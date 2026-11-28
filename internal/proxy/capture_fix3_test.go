package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
)

func TestTimeoutRetryCaptureDecodedBoundary(t *testing.T) {
	data := make([]byte, maxBody)
	rng := rand.NewPCG(3, 4)
	for i := range data {
		data[i] = byte(rng.Uint64())
	}
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	_, _ = z.Write(data)
	_ = z.Close()
	for _, tc := range []struct {
		name, encoding string
		wire           []byte
		truncated      bool
	}{
		{"identity-over", "", append(bytes.Clone(data), 'x'), true},
		{"gzip-exact", "gzip", compressed.Bytes(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Encoding", tc.encoding)
				_, _ = w.Write(tc.wire)
			}))
			defer up.Close()
			target, _ := ParseExplicitTarget(up.URL)
			p := New(target, fault.Config{Rules: []fault.Rule{{ID: "dup", Enabled: true, Fault: fault.Fault{Type: "dup-webhook", Params: map[string]any{"mode": "timeout_retry", "count": 2}}}}}, nil)
			defer p.Close()
			p.ShouldCaptureResponse = func(uint64) bool { return true }
			var got ResponseRecord
			p.OnResponse = func(r ResponseRecord) { got = r }
			req := localCassetteRequest("POST", "/")
			req.Header.Set("Accept-Encoding", "gzip")
			p.ServeHTTP(httptest.NewRecorder(), req)
			if got.Truncated != tc.truncated || !bytes.Equal(got.Body, data) {
				t.Fatalf("truncated=%v body length=%d", got.Truncated, len(got.Body))
			}
		})
	}
}

func TestKnownLengthDuplicateReservesOnlyReadBytes(t *testing.T) {
	p := New(nil, fault.Config{Rules: []fault.Rule{{ID: "dup", Enabled: true, Fault: fault.Fault{Type: "dup-webhook", Params: map[string]any{"count": 2}}}}}, nil)
	defer p.Close()
	reserved := 0
	p.ShouldCaptureBody = func(uint64) bool { return true }
	p.ReserveRequestBytes = func(_ uint64, n int) int { reserved += n; return n }
	p.OnRequest = func(Record) {}
	req := localCassetteRequest("POST", "/")
	req.Body = io.NopCloser(bytes.NewBufferString("short"))
	req.ContentLength = maxBody
	p.ServeHTTP(httptest.NewRecorder(), req)
	if reserved != 5 {
		t.Fatalf("reserved %d bytes for 5-byte upload", reserved)
	}
}

func TestRateLimitStopsReadingAtCaptureLimit(t *testing.T) {
	p := New(nil, fault.Config{Rules: []fault.Rule{{ID: "rate", Enabled: true, Fault: fault.Fault{Type: "rate-limit"}}}}, nil)
	defer p.Close()
	p.ShouldCaptureBody = func(uint64) bool { return true }
	p.OnRequest = func(Record) {}
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	req := localCassetteRequest("POST", "/")
	req.Body = reader
	done := make(chan int, 1)
	go func() { w := httptest.NewRecorder(); p.ServeHTTP(w, req); done <- w.Code }()
	go func() { _, _ = writer.Write(bytes.Repeat([]byte("x"), maxBody+1)) }()
	select {
	case status := <-done:
		if status != 429 {
			t.Fatalf("status=%d", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("rate limit waited for upload EOF")
	}
}
