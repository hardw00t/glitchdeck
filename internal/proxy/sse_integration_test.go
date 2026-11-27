package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/fault"
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
