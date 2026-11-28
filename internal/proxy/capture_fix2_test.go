package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/fault"
)

func TestCaptureCompressedExactDecodedLimit(t *testing.T) {
	data := make([]byte, maxBody)
	rng := rand.NewPCG(1, 2)
	for i := range data {
		data[i] = byte(rng.Uint64())
	}
	var encoded bytes.Buffer
	z := gzip.NewWriter(&encoded)
	_, _ = z.Write(data)
	_ = z.Close()
	if encoded.Len() <= maxBody {
		t.Fatal("fixture must exceed wire limit")
	}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(encoded.Bytes())
	}))
	defer up.Close()
	target, _ := ParseExplicitTarget(up.URL)
	p := New(target, fault.Config{}, nil)
	defer p.Close()
	var got ResponseRecord
	p.ShouldCaptureResponse = func(uint64) bool { return true }
	p.OnResponse = func(r ResponseRecord) { got = r }
	req := localCassetteRequest("GET", "/")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if got.Truncated || !bytes.Equal(got.Body, data) || !bytes.Equal(w.Body.Bytes(), encoded.Bytes()) {
		t.Fatalf("truncated=%v decoded=%d wire=%d", got.Truncated, len(got.Body), w.Body.Len())
	}
}

func TestCaptureStreamedSingleDuplicateReservesOnce(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body) }))
	defer up.Close()
	target, _ := ParseExplicitTarget(up.URL)
	p := New(target, fault.Config{Rules: []fault.Rule{{ID: "dup", Enabled: true, Fault: fault.Fault{Type: "dup-webhook", Params: map[string]any{"count": 1}}}}}, nil)
	defer p.Close()
	var got Record
	reserved := 0
	p.ShouldCaptureBody = func(uint64) bool { return true }
	p.ReserveRequestBytes = func(_ uint64, n int) int { reserved += n; return n }
	p.OnRequest = func(r Record) { got = r }
	req := localCassetteRequest("POST", "/")
	req.Body = io.NopCloser(bytes.NewBufferString("payload"))
	req.ContentLength = 7
	p.ServeHTTP(httptest.NewRecorder(), req)
	if string(got.Body) != "payload" || got.BodyTruncated || reserved != 7 {
		t.Fatalf("record=%+v reserved=%d", got, reserved)
	}
}

func TestReplayNestedConnectSetsStickyFailure(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	p.options.CassetteUpstream = func(*http.Request) (*http.Response, error) { return nil, nil }
	req := localCassetteRequest("CONNECT", "/")
	req = req.WithContext(context.WithValue(req.Context(), connKey{}, ConnMeta{MITM: true, Authority: "example.com", Scheme: "https"}))
	p.ServeHTTP(httptest.NewRecorder(), req)
	if p.CassetteFailure() == nil {
		t.Fatal("nested CONNECT did not set replay failure")
	}
}

func TestCaptureAutoSSEContinuesAfterDownstreamEOF(t *testing.T) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "data: final\n\n")
	}))
	defer up.Close()
	target, _ := ParseExplicitTarget(up.URL)
	p := New(target, fault.Config{Rules: []fault.Rule{{ID: "inject", Enabled: true, Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "inject_error", "provider": "auto", "after_events": 1}}}}}, nil)
	defer p.Close()
	p.ShouldCaptureResponse = func(uint64) bool { return true }
	records := make(chan ResponseRecord, 1)
	p.OnResponse = func(r ResponseRecord) { records <- r }
	done := make(chan struct{})
	go func() { p.ServeHTTP(httptest.NewRecorder(), localCassetteRequest("GET", "/")); close(done) }()
	<-done
	close(release)
	got := <-records
	if got.Truncated || !bytes.Contains(got.Body, []byte("data: final\n\n")) {
		t.Fatalf("capture=%q truncated=%v", got.Body, got.Truncated)
	}
}

func TestCaptureRateLimitBudgetAndBurstFallback(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body) }))
	defer up.Close()
	target, _ := ParseExplicitTarget(up.URL)
	p := New(target, fault.Config{Rules: []fault.Rule{{ID: "rate", Enabled: true, Fault: fault.Fault{Type: "rate-limit", Params: map[string]any{"burst": 1}}}}}, nil)
	defer p.Close()
	var records []Record
	used := 0
	p.ShouldCaptureBody = func(uint64) bool { return true }
	p.ReserveRequestBytes = func(_ uint64, n int) int { used += n; return n }
	p.OnRequest = func(r Record) { records = append(records, r) }
	for range 2 {
		req := localCassetteRequest("POST", "/")
		req.Body = io.NopCloser(bytes.NewBufferString("payload"))
		req.ContentLength = 7
		p.ServeHTTP(httptest.NewRecorder(), req)
	}
	if len(records) != 2 || string(records[0].Body) != "payload" || string(records[1].Body) != "payload" || used != 14 {
		t.Fatalf("records=%+v reserved=%d", records, used)
	}
}

func TestResponseCaptureSyntheticAndFailure(t *testing.T) {
	for _, tc := range []struct {
		rate        bool
		intentional bool
	}{{true, true}, {false, false}} {
		cfg := fault.Config{}
		if tc.rate {
			cfg.Rules = []fault.Rule{{ID: "rate", Enabled: true, Fault: fault.Fault{Type: "rate-limit"}}}
		}
		p := New(nil, cfg, nil)
		var got ResponseRecord
		p.ShouldCaptureResponse = func(uint64) bool { return true }
		p.OnResponse = func(r ResponseRecord) { got = r }
		p.ServeHTTP(httptest.NewRecorder(), localCassetteRequest("GET", "/"))
		p.Close()
		if got.Intentional != tc.intentional || got.Status != 0 {
			t.Fatalf("rate=%v record=%+v", tc.rate, got)
		}
	}
}

func TestTimeoutRetryInvalidEncodingDoesNotChangeTransportOutcome(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Repr-Digest", "old")
		_, _ = io.WriteString(w, "not gzip")
	}))
	defer up.Close()
	target, _ := ParseExplicitTarget(up.URL)
	p := New(target, fault.Config{Rules: []fault.Rule{{ID: "dup", Enabled: true, Fault: fault.Fault{Type: "dup-webhook", Params: map[string]any{"mode": "timeout_retry", "count": 2}}}}}, nil)
	defer p.Close()
	p.ShouldCaptureResponse = func(uint64) bool { return true }
	var got ResponseRecord
	p.OnResponse = func(r ResponseRecord) { got = r }
	p.ServeHTTP(httptest.NewRecorder(), localCassetteRequest("POST", "/"))
	if err := p.Wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	stats := p.Stats()["dup"].Replays
	if !got.Truncated || got.Header.Get("Repr-Digest") != "" || stats == nil || stats.OriginalOutcome != "" {
		t.Fatalf("record=%+v replay=%+v", got, stats)
	}
}

func TestRateLimitZeroCaptureBudgetDrainsWithoutRetaining(t *testing.T) {
	p := New(nil, fault.Config{Rules: []fault.Rule{{ID: "rate", Enabled: true, Fault: fault.Fault{Type: "rate-limit"}}}}, nil)
	defer p.Close()
	p.ShouldCaptureBody = func(uint64) bool { return true }
	p.ReserveRequestBytes = func(uint64, int) int { return 0 }
	var got Record
	p.OnRequest = func(r Record) { got = r }
	payload := bytes.Repeat([]byte("x"), 128*1024)
	req := localCassetteRequest("POST", "/")
	req.Body = io.NopCloser(bytes.NewReader(payload))
	req.ContentLength = int64(len(payload))
	p.ServeHTTP(httptest.NewRecorder(), req)
	if len(got.Body) != 0 || !got.BodyTruncated || got.UnrecordableBody {
		t.Fatalf("record=%+v", got)
	}
}

func TestUnknownDuplicateReservesOnlyUploadedBytes(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body) }))
	defer up.Close()
	target, _ := ParseExplicitTarget(up.URL)
	p := New(target, fault.Config{Rules: []fault.Rule{{ID: "dup", Enabled: true, Fault: fault.Fault{Type: "dup-webhook", Params: map[string]any{"count": 2}}}}}, nil)
	defer p.Close()
	total := 0
	var got Record
	p.ShouldCaptureBody = func(uint64) bool { return true }
	p.ReserveRequestBytes = func(_ uint64, n int) int { total += n; return n }
	p.OnRequest = func(r Record) { got = r }
	req := localCassetteRequest("POST", "/")
	req.Body = io.NopCloser(bytes.NewBufferString("payload"))
	req.ContentLength = -1
	p.ServeHTTP(httptest.NewRecorder(), req)
	if total != 7 || string(got.Body) != "payload" || got.BodyTruncated {
		t.Fatalf("reserved=%d record=%+v", total, got)
	}
}

func TestHTTP2SyntheticResponseIsIntentional(t *testing.T) {
	p := New(nil, fault.Config{Rules: []fault.Rule{{ID: "rate", Enabled: true, Fault: fault.Fault{Type: "rate-limit"}}}}, nil)
	defer p.Close()
	var order []string
	p.OnRequest = func(Record) { order = append(order, "request") }
	var got ResponseRecord
	p.OnResponse = func(r ResponseRecord) { got = r; order = append(order, "response") }
	p.ShouldCaptureResponse = func(uint64) bool { return true }
	req := localCassetteRequest("GET", "/")
	req.ProtoMajor = 2
	p.ServeHTTP(httptest.NewRecorder(), req)
	if len(order) != 2 || order[0] != "request" || order[1] != "response" || !got.Intentional || got.Status != 0 {
		t.Fatalf("order=%v response=%+v", order, got)
	}
}
