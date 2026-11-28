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
		encoding         string
		body             []byte
		want             string
		truncated        bool
		capturedEncoding string
		unscannable      bool
	}{
		{"gzip", encoded.Bytes(), "secret response", false, "", false},
		{"gzip", []byte("bad gzip"), "", false, "", true},
		{"br", []byte("opaque"), "", false, "", true},
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
			if string(got.Body) != tc.want || got.Truncated != tc.truncated || got.Header.Get("Content-Encoding") != tc.capturedEncoding || got.UnscannableEncoding != tc.unscannable || got.Status != 200 {
				t.Fatalf("body=%q truncated=%v unscannable=%v status=%d headers=%v", got.Body, got.Truncated, got.UnscannableEncoding, got.Status, got.Header)
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

func TestCaptureTimeoutRetryKeepsOriginalReadError(t *testing.T) {
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Content-Length", "20")
			_, _ = io.WriteString(w, "short")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer up.Close()
	target, _ := ParseExplicitTarget(up.URL)
	cfg := fault.Config{Rules: []fault.Rule{{ID: "dup", Enabled: true, Fault: fault.Fault{Type: "dup-webhook", Params: map[string]any{"mode": "timeout_retry", "count": 2, "delay_ms": 0}}}}}
	p := New(target, cfg, nil)
	defer p.Close()
	p.ShouldCaptureResponse = func(uint64) bool { return true }
	var got ResponseRecord
	p.OnResponse = func(r ResponseRecord) { got = r }
	w := httptest.NewRecorder()
	p.ServeHTTP(w, localCassetteRequest("POST", "/"))
	if err := p.Wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	stats := p.Stats()["dup"].Replays
	if w.Code != 504 || !got.Truncated || stats == nil || stats.OriginalOutcome != "transport_error" {
		t.Fatalf("status=%d truncated=%t replay=%+v", w.Code, got.Truncated, stats)
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
	if !req.UnrecordableBody || len(req.Body) != 0 || resp.Status != 0 {
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
	got := make(chan ResponseRecord, 1)
	p.ShouldCaptureResponse = func(uint64) bool { return true }
	p.OnResponse = func(r ResponseRecord) { got <- r }
	w := httptest.NewRecorder()
	p.ServeHTTP(w, localCassetteRequest("GET", "/"))
	captured := <-got
	if w.Body.String() != "data: one\n\n" || string(captured.Body) != original || captured.Truncated {
		t.Fatalf("client=%q capture=%q truncated=%v", w.Body.String(), captured.Body, captured.Truncated)
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

func TestCaptureStopsAtFirstReservationGap(t *testing.T) {
	c := &responseCapture{ReadCloser: io.NopCloser(strings.NewReader("abcdef"))}
	calls := 0
	c.reserve = func(n int) int {
		calls++
		if calls == 1 {
			return 1
		}
		return n
	}
	buf := make([]byte, 3)
	_, _ = c.Read(buf)
	_, _ = c.Read(buf)
	if string(c.body) != "a" || !c.truncated {
		t.Fatalf("capture is not a prefix: %q", c.body)
	}
}

func TestCapturePreservesLiveCompressedRepresentation(t *testing.T) {
	var encoded bytes.Buffer
	z := gzip.NewWriter(&encoded)
	_, _ = z.Write([]byte("payload"))
	_ = z.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Connection", "X-Private")
		w.Header().Set("X-Private", "hidden")
		_, _ = w.Write(encoded.Bytes())
	}))
	defer up.Close()
	target, _ := ParseExplicitTarget(up.URL)
	p := New(target, fault.Config{}, nil)
	defer p.Close()
	p.ShouldCaptureResponse = func(uint64) bool { return true }
	var requestRecord Record
	p.OnRequest = func(r Record) { requestRecord = r }
	var got ResponseRecord
	p.OnResponse = func(r ResponseRecord) { got = r }
	w := httptest.NewRecorder()
	req := localCassetteRequest("GET", "/")
	req.Header.Set("Connection", "X-Request-Private")
	req.Header.Set("X-Request-Private", "hidden")
	req.Header.Set("Accept-Encoding", "gzip")
	p.ServeHTTP(w, req)
	if !bytes.Equal(w.Body.Bytes(), encoded.Bytes()) || w.Header().Get("Content-Encoding") != "gzip" || string(got.Body) != "payload" || got.Header.Get("X-Private") != "" || requestRecord.Header.Get("X-Request-Private") != "" {
		t.Fatalf("live=%x headers=%v capture=%+v", w.Body.Bytes(), w.Header(), got)
	}
}

func TestEarlyEOFFinishesBeforeUpstreamCloses(t *testing.T) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: one\n\ndata: trigger\n\n")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "data: retained after downstream EOF\n\n")
	}))
	defer up.Close()
	target, _ := ParseExplicitTarget(up.URL)
	cfg := fault.Config{Rules: []fault.Rule{{ID: "cut", Enabled: true, Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "eof_early", "after_events": 1, "http_clean": true}}}}}
	p := New(target, cfg, nil)
	defer p.Close()
	captured := make(chan ResponseRecord, 1)
	p.ShouldCaptureResponse = func(uint64) bool { return true }
	p.OnResponse = func(r ResponseRecord) { captured <- r }
	server := httptest.NewServer(p)
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		resp, err := http.Get(server.URL)
		if err == nil {
			_, err = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		t.Error("downstream EOF waited for upstream")
	}
	close(release)
	got := <-captured
	if got.Truncated || !strings.Contains(string(got.Body), "retained after downstream EOF") {
		t.Fatalf("capture ended before upstream: %+v", got)
	}
}

func TestCaptureProbeBodylessAndTrailers(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Content-Encoding", "gzip")
			return
		}
		w.Header().Set("Trailer", "X-Trailer")
		_, _ = io.WriteString(w, "body")
		w.Header().Set("X-Trailer", "value")
	}))
	defer up.Close()
	target, _ := ParseExplicitTarget(up.URL)
	p := New(target, fault.Config{}, nil)
	defer p.Close()
	p.ShouldCaptureResponse = func(uint64) bool { return true }
	var req Record
	var res ResponseRecord
	p.OnRequest = func(r Record) { req = r }
	p.OnResponse = func(r ResponseRecord) { res = r }
	p.ServeProbeHTTP(httptest.NewRecorder(), localCassetteRequest("HEAD", "/"))
	if !req.AssertionProbe || res.Truncated || len(res.Body) != 0 {
		t.Fatalf("bodyless probe: request=%+v response=%+v", req, res)
	}
	p.ServeHTTP(httptest.NewRecorder(), localCassetteRequest("GET", "/"))
	if !res.Truncated {
		t.Fatalf("response trailers not marked incomplete: %+v", res)
	}
}

func TestCaptureUnscannableTransferAndRequestEncoding(t *testing.T) {
	for _, tc := range []struct {
		name     string
		transfer []string
		unsafe   bool
	}{
		{"chunked", []string{"chunked"}, false},
		{"unsupported", []string{"compress", "chunked"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := New(nil, fault.Config{}, nil)
			defer p.Close()
			p.SetOptions(Options{CassetteUpstream: func(r *http.Request) (*http.Response, error) {
				_, _ = io.Copy(io.Discard, r.Body)
				return &http.Response{StatusCode: 200, Header: make(http.Header), TransferEncoding: tc.transfer, Body: io.NopCloser(strings.NewReader("response")), ContentLength: -1}, nil
			}})
			p.ShouldCaptureResponse = func(uint64) bool { return true }
			var reqRecord Record
			var respRecord ResponseRecord
			p.OnRequest = func(r Record) { reqRecord = r }
			p.OnResponse = func(r ResponseRecord) { respRecord = r }
			req := localCassetteRequest("POST", "/")
			req.Body = io.NopCloser(strings.NewReader("request"))
			req.ContentLength = 7
			req.Header.Set("Connection", "Grpc-Encoding")
			req.Header.Set("Grpc-Encoding", "gzip")
			p.ServeHTTP(httptest.NewRecorder(), req)
			if !reqRecord.UnscannableEncoding || reqRecord.Header.Get("Grpc-Encoding") != "" {
				t.Fatalf("request capture: %+v", reqRecord)
			}
			if respRecord.UnscannableEncoding != tc.unsafe || respRecord.Truncated || string(respRecord.Body) != "response" {
				t.Fatalf("response capture: %+v", respRecord)
			}
		})
	}
}

func TestCaptureNominatedGzipRequestIsUnscannable(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	p.SetOptions(Options{CassetteUpstream: func(r *http.Request) (*http.Response, error) {
		_, _ = io.Copy(io.Discard, r.Body)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), ContentLength: 2}, nil
	}})
	var got Record
	p.OnRequest = func(r Record) { got = r }
	req := localCassetteRequest("POST", "/")
	req.Body = io.NopCloser(strings.NewReader("compressed"))
	req.ContentLength = 10
	req.Header.Set("Connection", "Content-Encoding, Content-Type")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Type", "application/octet-stream")
	p.ServeHTTP(httptest.NewRecorder(), req)
	if !got.UnscannableEncoding || got.Header.Get("Content-Encoding") != "" || got.Header.Get("Content-Type") != "" {
		t.Fatalf("request capture: %+v", got)
	}
}
