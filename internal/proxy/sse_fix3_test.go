package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
)

type sseInjectionRecorder struct {
	*httptest.ResponseRecorder
	release func()
}

func (w sseInjectionRecorder) Write(body []byte) (int, error) {
	if bytes.Contains(body, []byte(`data: {"error":`)) {
		w.release()
	}
	return w.ResponseRecorder.Write(body)
}

func TestCompressedLookaheadCaptureJoinsBeforeDecoderClose(t *testing.T) {
	release := make(chan struct{})
	open := sync.OnceFunc(func() { close(release) })
	defer open()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Trailer", "X-Final")
		z := gzip.NewWriter(w)
		_, _ = io.WriteString(z, "data: first\n\n")
		_ = z.Flush()
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(z, "data: second\n\n")
		_ = z.Close()
		w.Header().Set("X-Final", "done")
	}))
	defer up.Close()
	target, _ := ParseExplicitTarget(up.URL)
	cfg := fault.Config{Rules: []fault.Rule{{ID: "inject", Enabled: true, Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "inject_error", "provider": "auto", "after_events": 1}}}}}
	p := New(target, cfg, nil)
	defer p.Close()
	p.ShouldCaptureResponse = func(uint64) bool { return true }
	recorded := make(chan ResponseRecord, 1)
	p.OnResponse = func(r ResponseRecord) { recorded <- r }
	done := make(chan struct{})
	go func() {
		p.ServeHTTP(sseInjectionRecorder{httptest.NewRecorder(), open}, localCassetteRequest("GET", "/"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		open()
		t.Fatal("handler blocked on lookahead")
	}
	select {
	case resp := <-recorded:
		if string(resp.Body) != "data: first\n\ndata: second\n\n" || !resp.Truncated {
			t.Fatalf("capture must retain both events and flag unrepresentable trailers: %+v", resp)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("capture did not finish")
	}
}
