package demo

import (
	"bufio"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDemoStreamHasDone(t *testing.T) {
	r := httptest.NewRequest("POST", "http://127.0.0.1/api/chat/stream", strings.NewReader(`{"tokens":1,"token_ms":0}`))
	w := httptest.NewRecorder()
	New().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "data: [DONE]") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestProviderStreamsAndGzip(t *testing.T) {
	for _, tc := range []struct {
		path, body, want string
	}{
		{"/v1/responses", `{"tokens":1,"token_ms":0,"tools":true}`, "response.function_call_arguments.delta"},
		{"/v1beta/models/demo:streamGenerateContent?alt=sse", `{"tokens":1,"token_ms":0}`, `"finishReason":"STOP"`},
		{"/v1/messages", `{"tokens":1,"token_ms":0,"tools":true}`, `"partial_json"`},
		{"/v1/chat/completions", `{"tokens":1,"token_ms":0,"tools":true,"gzip":true}`, `"arguments"`},
		{"/v1/chat/completions", `{"tokens":1,"token_ms":0,"tools":[{"type":"function"}]}`, `[DONE]`},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			New().ServeHTTP(w, httptest.NewRequest("POST", "http://127.0.0.1"+tc.path, strings.NewReader(tc.body)))
			var body io.Reader = w.Body
			if strings.Contains(tc.body, `"gzip":true`) {
				if w.Header().Get("Content-Encoding") != "gzip" {
					t.Fatal("missing gzip encoding")
				}
				z, err := gzip.NewReader(body)
				if err != nil {
					t.Fatal(err)
				}
				defer z.Close()
				body = z
			}
			b, err := io.ReadAll(body)
			if err != nil || w.Code != 200 || !strings.Contains(string(b), tc.want) {
				t.Fatalf("status %d, body %s, error %v", w.Code, b, err)
			}
		})
	}
}

func TestGzipStreamFlushesEachEvent(t *testing.T) {
	server := httptest.NewServer(New())
	defer server.Close()
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest("POST", server.URL+"/v1/chat/completions", strings.NewReader(`{"tokens":5,"token_ms":1000,"gzip":true}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	z, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	line, err := bufio.NewReader(z).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "data: ") {
		t.Fatalf("first event: %q, %v", line, err)
	}
}
