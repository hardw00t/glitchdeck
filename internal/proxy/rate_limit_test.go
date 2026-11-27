package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
)

func TestRateLimitProviderWire(t *testing.T) {
	for _, tc := range []struct {
		name, provider string
		status         int
		explicit, body string
		headers        string
	}{
		{"legacy", "", 429, "legacy", "legacy", ""},
		{"openai", "openai", 429, "", `{"error":{"message":"Rate limit reached (glitchdeck)","type":"requests","param":null,"code":"rate_limit_exceeded"}}`, "X-Ratelimit-Limit-Requests: 2\nX-Ratelimit-Remaining-Requests: 0\nX-Ratelimit-Reset-Requests: 20s\nX-Ratelimit-Reset-Tokens: 20s\nX-Request-Id: req_glitchdeck_1\n"},
		{"anthropic 429", "anthropic", 429, "", `{"type":"error","error":{"type":"rate_limit_error","message":"Rate limit reached (glitchdeck)"}}`, "Anthropic-Ratelimit-Requests-Remaining: 0\nRequest-Id: req_glitchdeck_1\n"},
		{"anthropic 529", "anthropic", 529, "", `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`, "Anthropic-Ratelimit-Requests-Remaining: 0\nRequest-Id: req_glitchdeck_1\n"},
		{"gemini 429", "gemini", 429, "", `{"error":{"code":429,"message":"Resource has been exhausted (e.g. check quota).","status":"RESOURCE_EXHAUSTED"}}`, ""},
		{"gemini 503", "gemini", 503, "", `{"error":{"code":503,"message":"Resource has been exhausted (e.g. check quota).","status":"UNAVAILABLE"}}`, ""},
		{"body override", "gemini", 429, "overridden", "overridden", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := map[string]any{"status": tc.status, "retry_after_sec": 2, "body": tc.explicit}
			if tc.provider != "" {
				params["provider"], params["burst"], params["reset_sec"], params["retry_after_ms"] = tc.provider, 2, 20, 0
			}
			p := New(nil, rateLimitConfig(params), nil)
			defer p.Close()
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Host = "127.0.0.1"
			r.Header.Set("Authorization", "Bearer do-not-reflect")
			r.Header.Set("X-Api-Key", "do-not-reflect")
			before := time.Now().Truncate(time.Second)
			p.ServeHTTP(w, r)
			after := time.Now()
			if w.Code != tc.status || w.Body.String() != tc.body {
				t.Fatalf("got %d %q, want %d %q", w.Code, w.Body, tc.status, tc.body)
			}
			h := w.Result().Header.Clone()
			if tc.provider == "anthropic" {
				reset, err := time.Parse(time.RFC3339, h.Get("Anthropic-Ratelimit-Requests-Reset"))
				if err != nil || reset.Before(before.Add(20*time.Second)) || reset.After(after.Add(20*time.Second)) {
					t.Fatalf("bad reset: %v (%v)", reset, err)
				}
				h.Del("Anthropic-Ratelimit-Requests-Reset")
			}
			var got strings.Builder
			if err := h.Write(&got); err != nil {
				t.Fatal(err)
			}
			want := "Retry-After: 2\n"
			if tc.provider != "" {
				want += "Retry-After-Ms: 0\n"
			}
			want += tc.headers + "X-Glitchdeck-Fault: rate-limit\n"
			if tc.explicit == "" {
				want = "Content-Type: application/json\n" + want
			}
			lines := strings.Split(strings.TrimSuffix(want, "\n"), "\n")
			sort.Strings(lines)
			gotLines := strings.Split(strings.TrimSuffix(strings.ReplaceAll(got.String(), "\r\n", "\n"), "\n"), "\n")
			sort.Strings(gotLines)
			if strings.Join(gotLines, "\n") != strings.Join(lines, "\n") {
				t.Fatalf("headers:\n%s\nwant:\n%s", &got, lines)
			}
		})
	}
}

func rateLimitConfig(params map[string]any) fault.Config {
	return fault.Config{Rules: []fault.Rule{{ID: "limit", Enabled: true, Fault: fault.Fault{Type: "rate-limit", Params: params}}}}
}

func TestRateLimitBurstConcurrent(t *testing.T) {
	var passes atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		passes.Add(1)
		fmt.Fprint(w, r.URL.Query().Get("id"))
	}))
	defer up.Close()
	target, err := ParseTarget(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := New(target, rateLimitConfig(map[string]any{"burst": 2}), nil)
	defer p.Close()
	server := httptest.NewServer(p)
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	var limited atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 100 {
		wg.Go(func() {
			<-start
			id := strconv.Itoa(i)
			resp, err := client.Get(server.URL + "/?id=" + id)
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Error(err)
				return
			}
			switch resp.StatusCode {
			case 429:
				limited.Add(1)
			case 200:
				if string(body) != id || resp.Header.Get("X-Glitchdeck-Fault") != "" {
					t.Errorf("request %s not passed through: %q %v", id, body, resp.Header)
				}
			default:
				t.Errorf("unexpected response %d: %q", resp.StatusCode, body)
			}
		})
	}
	close(start)
	wg.Wait()
	stats := p.Stats()["limit"]
	if limited.Load() != 2 || passes.Load() != 98 || stats.Matched != 100 || stats.Applied != 2 {
		t.Fatalf("limited=%d passed=%d stats=%+v", limited.Load(), passes.Load(), stats)
	}
	p.Reset()
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatalf("first request after reset = %d", resp.StatusCode)
	}
}
