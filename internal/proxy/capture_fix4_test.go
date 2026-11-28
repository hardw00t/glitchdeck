package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/fault"
)

type closeTrackingBody struct {
	io.Reader
	closed atomic.Int32
}

func (b *closeTrackingBody) Close() error { b.closed.Add(1); return nil }

func TestCompressedSSEFaultClosesTransportBody(t *testing.T) {
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	_, _ = io.WriteString(z, "data: first\n\ndata: second\n\n")
	_ = z.Close()
	for _, capture := range []bool{false, true} {
		t.Run(map[bool]string{false: "without capture", true: "with capture"}[capture], func(t *testing.T) {
			body := &closeTrackingBody{Reader: bytes.NewReader(compressed.Bytes())}
			p := New(nil, encodedSSEConfig(map[string]any{"action": "eof_early", "after_events": 1}), nil)
			defer p.Close()
			p.SetOptions(Options{CassetteUpstream: func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}, "Content-Encoding": {"gzip"}}, Body: body, ContentLength: -1}, nil
			}})
			if capture {
				p.ShouldCaptureResponse = func(uint64) bool { return true }
				p.OnResponse = func(ResponseRecord) {}
			}
			p.ServeHTTP(httptest.NewRecorder(), localCassetteRequest("GET", "/"))
			if err := p.Wait(t.Context()); err != nil {
				t.Fatal(err)
			}
			if got := body.closed.Load(); got != 1 {
				t.Fatalf("transport body closed %d times, want once", got)
			}
		})
	}
}

func TestEncodedPartialResponseCaptureIsIncomplete(t *testing.T) {
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	_, _ = io.WriteString(z, "partial")
	_ = z.Close()
	for _, timeout := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "timeout retry"}[timeout], func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Content-Range", "bytes 0-30/100")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(compressed.Bytes())
			}))
			defer up.Close()
			target, _ := ParseExplicitTarget(up.URL)
			cfg := fault.Config{}
			method := "GET"
			if timeout {
				method = "POST"
				cfg.Rules = []fault.Rule{{ID: "dup", Enabled: true, Fault: fault.Fault{Type: "dup-webhook", Params: map[string]any{"mode": "timeout_retry", "count": 2}}}}
			}
			p := New(target, cfg, nil)
			defer p.Close()
			p.ShouldCaptureResponse = func(uint64) bool { return true }
			records := make(chan ResponseRecord, 1)
			p.OnResponse = func(r ResponseRecord) { records <- r }
			req := localCassetteRequest(method, "/")
			req.Header.Set("Accept-Encoding", "gzip")
			p.ServeHTTP(httptest.NewRecorder(), req)
			got := <-records
			if !got.Truncated {
				t.Fatalf("encoded 206 capture must be incomplete: %+v", got)
			}
		})
	}
}
