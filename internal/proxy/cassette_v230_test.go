package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
)

func localCassetteRequest(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Host = "localhost"
	return r
}

func TestResponseCaptureDecodesCompressedBodies(t *testing.T) {
	var encoded bytes.Buffer
	z := gzip.NewWriter(&encoded)
	_, _ = z.Write([]byte("secret response"))
	_ = z.Close()
	for _, tc := range []struct {
		encoding  string
		body      []byte
		want      string
		truncated bool
	}{
		{"gzip", encoded.Bytes(), "secret response", false},
		{"gzip", []byte("bad gzip"), "", true},
		{"br", []byte("opaque"), "", true},
	} {
		t.Run(tc.encoding+tc.want, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Encoding", tc.encoding)
				_, _ = w.Write(tc.body)
			}))
			defer up.Close()
			target, _ := ParseExplicitTarget(up.URL)
			p := New(target, fault.Config{}, nil)
			defer p.Close()
			var got ResponseRecord
			p.ShouldCaptureResponse = func(uint64) bool { return true }
			p.OnResponse = func(r ResponseRecord) { got = r }
			func() {
				defer func() { _ = recover() }()
				p.ServeHTTP(httptest.NewRecorder(), localCassetteRequest("GET", "/"))
			}()
			if string(got.Body) != tc.want || got.Truncated != tc.truncated || got.Header.Get("Content-Encoding") != "" {
				t.Fatalf("body=%q truncated=%v headers=%v", got.Body, got.Truncated, got.Header)
			}
		})
	}
}

func TestCassetteMatchesClientVisibleAuthorityAndPath(t *testing.T) {
	for _, target := range []*url.URL{nil, {Scheme: "http", Host: "localhost:9999", Path: "/prefix"}} {
		p := New(target, fault.Config{}, nil)
		p.SetOptions(Options{CassetteUpstream: func(r *http.Request) (*http.Response, error) {
			if r.URL.EscapedPath() != "/a%2Fb" || r.URL.Host != "client.example" {
				t.Errorf("match URL = %s", r.URL.String())
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: http.NoBody}, nil
		}})
		r := localCassetteRequest("GET", "/a%2Fb")
		r.Host = "client.example"
		// Absolute form is trusted as proxy traffic, unlike an origin request with a remote Host.
		r.URL.Scheme = "http"
		r.URL.Host = "client.example"
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Errorf("status %d", w.Code)
		}
		p.Close()
	}
}

func TestCassetteOriginUsesClientPathInsteadOfTargetPrefix(t *testing.T) {
	target, _ := url.Parse("http://localhost:9999/prefix")
	p := New(target, fault.Config{}, nil)
	defer p.Close()
	p.SetOptions(Options{CassetteUpstream: func(r *http.Request) (*http.Response, error) {
		if r.URL.EscapedPath() != "/a%2Fb" || r.URL.Host != "localhost" {
			t.Errorf("match URL %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: http.NoBody}, nil
	}})
	w := httptest.NewRecorder()
	p.ServeHTTP(w, localCassetteRequest("GET", "/a%2Fb"))
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
}

func TestCaptureTimeoutRetryDecodesAndReserves(t *testing.T) {
	var encoded bytes.Buffer
	z := gzip.NewWriter(&encoded)
	_, _ = z.Write([]byte("secret"))
	_ = z.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(encoded.Bytes())
	}))
	defer up.Close()
	target, _ := ParseExplicitTarget(up.URL)
	cfg := fault.Config{Rules: []fault.Rule{{ID: "dup", Enabled: true, Fault: fault.Fault{Type: "dup-webhook", Params: map[string]any{"mode": "timeout_retry", "count": 2}}}}}
	p := New(target, cfg, nil)
	defer p.Close()
	p.ShouldCaptureResponse = func(uint64) bool { return true }
	p.ReserveResponseBytes = func(_ uint64, n int) int { return min(n, 3) }
	var got ResponseRecord
	p.OnResponse = func(r ResponseRecord) { got = r }
	w := httptest.NewRecorder()
	p.ServeHTTP(w, localCassetteRequest("POST", "/"))
	if w.Code != 504 || string(got.Body) != "sec" || !got.Truncated || got.Header.Get("Content-Encoding") != "" {
		t.Fatalf("status=%d capture=%+v", w.Code, got)
	}
}

func TestBeforeHeadersResetRecordsBodylessRequest(t *testing.T) {
	cfg := fault.Config{Rules: []fault.Rule{{ID: "rst", Enabled: true, Fault: fault.Fault{Type: "tcp-rst", Params: map[string]any{"before_headers": true}}}}}
	p := New(nil, cfg, nil)
	defer p.Close()
	var req Record
	var resp ResponseRecord
	p.OnRequest = func(r Record) { req = r }
	p.ShouldCaptureResponse = func(uint64) bool { return true }
	p.OnResponse = func(r ResponseRecord) { resp = r }
	r := localCassetteRequest("POST", "/")
	r.Body = io.NopCloser(strings.NewReader("unread"))
	r.ContentLength = 6
	p.ServeHTTP(httptest.NewRecorder(), r)
	if req.UnrecordableBody || len(req.Body) != 0 || resp.Status != 0 {
		t.Fatalf("request=%+v response=%+v", req, resp)
	}
}

func TestRecordingAutoProviderLookaheadIsBounded(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer up.Close()
	target, _ := ParseExplicitTarget(up.URL)
	cfg := fault.Config{Rules: []fault.Rule{{ID: "inject", Enabled: true, Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "inject_error", "provider": "auto", "after_events": 1}}}}}
	p := New(target, cfg, nil)
	defer p.Close()
	p.ShouldCaptureResponse = func(uint64) bool { return true }
	records := make(chan ResponseRecord, 1)
	p.OnResponse = func(r ResponseRecord) { records <- r }
	go p.ServeHTTP(httptest.NewRecorder(), localCassetteRequest("GET", "/"))
	select {
	case rec := <-records:
		if !rec.Truncated {
			t.Fatalf("cancelled capture must be incomplete: %+v", rec)
		}
	case <-time.After(time.Second):
		t.Fatal("provider lookahead blocked")
	}
}

func TestResponseCaptureHonorsReservation(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "123456") }))
	defer up.Close()
	target, _ := ParseExplicitTarget(up.URL)
	p := New(target, fault.Config{}, nil)
	defer p.Close()
	p.ShouldCaptureResponse = func(uint64) bool { return true }
	p.ReserveResponseBytes = func(_ uint64, n int) int { return min(n, 3) }
	var got ResponseRecord
	p.OnResponse = func(r ResponseRecord) { got = r }
	w := httptest.NewRecorder()
	p.ServeHTTP(w, localCassetteRequest("GET", "/"))
	if w.Body.String() != "123456" || string(got.Body) != "123" || !got.Truncated {
		t.Fatalf("client %q capture %q truncated %v", w.Body.String(), got.Body, got.Truncated)
	}
}

func TestCassetteConcurrentNoEgressAndStickyFailure(t *testing.T) {
	var live atomic.Int32
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	up.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			live.Add(1)
		}
	}
	up.Start()
	defer up.Close()
	target, _ := ParseExplicitTarget(up.URL)
	p := New(target, fault.Config{}, nil)
	defer p.Close()
	p.SetOptions(Options{CassetteUpstream: func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/miss" {
			return nil, &CassetteError{Kind: "cassette_miss"}
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("recorded"))}, nil
	}})
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			p.ServeHTTP(w, localCassetteRequest("GET", "/ok"))
			if w.Code != 200 || w.Body.String() != "recorded" {
				t.Errorf("response %d %q", w.Code, w.Body.String())
			}
		}()
	}
	wg.Wait()
	w := httptest.NewRecorder()
	p.ServeHTTP(w, localCassetteRequest("POST", "/miss?secret=hidden"))
	var ce *CassetteError
	if w.Code != 502 || !errors.As(p.CassetteFailure(), &ce) || ce.Kind != "cassette_miss" || !strings.Contains(w.Body.String(), "POST /miss") || strings.Contains(w.Body.String(), "hidden") {
		t.Fatalf("failure: %d %v", w.Code, p.CassetteFailure())
	}
	if live.Load() != 0 {
		t.Fatalf("live requests: %d", live.Load())
	}
}

func TestResponseCaptureIsBoundedAndPrefault(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, strings.Repeat("x", maxBody+1))
	}))
	defer up.Close()
	target, _ := ParseExplicitTarget(up.URL)
	p := New(target, fault.Config{}, nil)
	defer p.Close()
	var got ResponseRecord
	p.ShouldCaptureResponse = func(uint64) bool { return true }
	p.OnResponse = func(r ResponseRecord) { got = r }
	w := httptest.NewRecorder()
	p.ServeHTTP(w, localCassetteRequest("GET", "/"))
	if got.Status != 200 || len(got.Body) != maxBody || !got.Truncated {
		t.Fatalf("capture: status=%d bytes=%d truncated=%v", got.Status, len(got.Body), got.Truncated)
	}
}

func TestResponseCaptureDrainsAfterSSEFault(t *testing.T) {
	const original = "data: one\n\ndata: two\n\ndata: three\n\n"
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, original)
	}))
	defer up.Close()
	target, _ := ParseExplicitTarget(up.URL)
	cfg := fault.Config{Rules: []fault.Rule{{ID: "cut", Enabled: true, Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "eof_early", "after_events": 1, "http_clean": true}}}}}
	p := New(target, cfg, nil)
	defer p.Close()
	var got ResponseRecord
	p.ShouldCaptureResponse = func(uint64) bool { return true }
	p.OnResponse = func(r ResponseRecord) { got = r }
	w := httptest.NewRecorder()
	p.ServeHTTP(w, localCassetteRequest("GET", "/"))
	if w.Body.String() != "data: one\n\n" || string(got.Body) != original || got.Truncated {
		t.Fatalf("client=%q capture=%q truncated=%v", w.Body.String(), got.Body, got.Truncated)
	}
}

func TestCassetteBlocksTunnelAndWebSocketAndRedirect(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	p.SetOptions(Options{CassetteUpstream: func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://outside.example/"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	}})
	if c, err := p.DialContext(context.Background(), "tcp", "localhost:80"); err == nil {
		c.Close()
		t.Fatal("dial allowed")
	}
	connect := httptest.NewRequest("CONNECT", "http://outside.example:443", nil)
	connect.Host = "outside.example:443"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, connect)
	if w.Code != 502 {
		t.Fatalf("CONNECT: %d", w.Code)
	}
	ws := httptest.NewRequest("GET", "http://outside.example/ws", nil)
	ws.Header.Set("Connection", "Upgrade")
	ws.Header.Set("Upgrade", "websocket")
	w = httptest.NewRecorder()
	p.ServeHTTP(w, ws)
	if w.Code != 502 {
		t.Fatalf("websocket: %d", w.Code)
	}
	w = httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "http://outside.example/", nil))
	if w.Code != 302 || w.Header().Get("Location") != "" {
		t.Fatalf("redirect: %d %q", w.Code, w.Header().Get("Location"))
	}
}
