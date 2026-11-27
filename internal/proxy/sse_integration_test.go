package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
)

func TestSSEEarlyEOFThroughProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: one\n\ndata: [DONE]\n\n")
	}))
	defer upstream.Close()
	target, err := ParseTarget(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := fault.Config{Rules: []fault.Rule{{ID: "cut", Enabled: true, Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "eof_early"}}}}}
	p := New(target, cfg, nil)
	defer p.Close()
	server := httptest.NewServer(p)
	defer server.Close()
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || string(b) != "data: one\n\n" {
		t.Fatalf("body %q, err %v", b, err)
	}
}

func TestAbsoluteFormToSelfResetsSSEOnce(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.RequestURI() != "/stream?tokens=2" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: one\n\ndata: two\n\n")
	}))
	defer upstream.Close()
	target, err := ParseTarget(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := fault.Config{Rules: []fault.Rule{{ID: "cut", Enabled: true, Fault: fault.Fault{
		Type: "sse-glitch", Params: map[string]any{"action": "truncate", "after_events": 1},
	}}}}
	for _, host := range []string{"127.0.0.1", "localhost", "::1"} {
		t.Run(host, func(t *testing.T) {
			bus := telemetry.New()
			p := New(target, cfg, bus)
			defer p.Close()
			server := httptest.NewServer(p)
			defer server.Close()
			proxyURL, err := ParseTarget(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			resp, err := client.Post("http://"+net.JoinHostPort(host, proxyURL.Port())+"/stream?tokens=2", "application/json", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, readErr := io.ReadAll(resp.Body)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := p.Wait(ctx); err != nil {
				t.Fatal(err)
			}
			var ends []string
			for _, e := range bus.History(10) {
				if e.Type == "http_req" {
					var row struct{ End string }
					if err := json.Unmarshal(e.Data, &row); err != nil {
						t.Fatal(err)
					}
					ends = append(ends, row.End)
				}
			}
			if resp.StatusCode != http.StatusOK || !errors.Is(readErr, syscall.ECONNRESET) || len(ends) != 1 || ends[0] != "rst" {
				t.Fatalf("status %d, body %q, read error %v, http_req ends %v", resp.StatusCode, body, readErr, ends)
			}
		})
	}
}
