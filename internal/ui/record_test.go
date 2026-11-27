package ui

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/tape"
)

func TestStoppedTapeFreezesConfigChangesAndSequenceGaps(t *testing.T) {
	var r recorder
	before := fault.Config{Seed: 17}
	after := fault.Config{Seed: 29, Rules: []fault.Rule{{ID: "replay", Enabled: true, Fault: fault.Fault{Type: "dup-webhook"}}}}
	r.start(5, 0, before)
	now := time.Now()
	r.request(proxy.Record{Seq: 6, Method: "POST", Path: "/checkout", At: now})
	r.changed(8, after)
	r.request(proxy.Record{Seq: 8, Method: "POST", Path: "/webhooks/payment", At: now.Add(time.Millisecond)})
	r.stop()
	r.changed(9, fault.Config{Seed: 43})
	r.request(proxy.Record{Seq: 9, Method: "GET", Path: "/unrecorded", At: now})
	doc := r.tape(fault.Config{Seed: 43})
	if doc.Seed != 17 || len(doc.Script) != 2 || doc.Script[0].Seq != 6 || doc.Script[1].Seq != 8 {
		t.Fatalf("frozen tape = %+v", doc)
	}
	if len(doc.ConfigChanges) != 1 || doc.ConfigChanges[0].BeforeSeq != 8 || doc.ConfigChanges[0].Seed != 29 || !doc.ConfigChanges[0].Rules[0].Enabled {
		t.Fatalf("config timeline = %+v", doc.ConfigChanges)
	}
}

func TestRecordingAfterBurstConsumptionIsIncomplete(t *testing.T) {
	cfg := fault.Config{Rules: []fault.Rule{{ID: "burst", Enabled: true, Fault: fault.Fault{
		Type: "rate-limit", Params: map[string]any{"burst": 1},
	}}}}
	p := proxy.New(nil, cfg, nil)
	defer p.Close()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "127.0.0.1"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("initial status %d", w.Code)
	}
	rec := NewRecorder()
	rec.Start(p)
	doc, err := rec.Export("after-burst")
	if err != nil || !doc.Incomplete || !strings.Contains(doc.IncompleteReason, "burst") {
		t.Fatalf("recording %+v, err %v", doc, err)
	}
}

func TestUnsupportedTrafficMarksTapeIncomplete(t *testing.T) {
	for _, tc := range []struct {
		name   string
		active int
		next   func(*recorder)
		want   string
	}{
		{"open at start", 1, func(*recorder) {}, "already open"},
		{"binary or fragmented", 0, func(r *recorder) {
			r.request(proxy.Record{Seq: 1, Path: "/ws/ticker", WebSocket: true, At: time.Now()})
			r.unsupportedFrame(1)
		}, "binary or fragmented"},
		{"streamed upload", 0, func(r *recorder) {
			r.request(proxy.Record{Seq: 1, Path: "/upload", UnrecordableBody: true, At: time.Now()})
		}, "streamed request body"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r recorder
			r.start(0, tc.active, fault.Config{Seed: 1})
			tc.next(&r)
			status := r.stop()
			doc := r.tape(fault.Config{Seed: 2})
			if !status.Incomplete || !doc.Incomplete || !strings.Contains(doc.IncompleteReason, tc.want) || doc.IncompleteReason != status.IncompleteReason {
				t.Fatalf("status %+v, tape %+v", status, doc)
			}
		})
	}
}

func TestRecordingDoesNotRetargetForwardedWebSocket(t *testing.T) {
	var r recorder
	r.start(0, 0, fault.Config{})
	r.request(proxy.Record{Seq: 1, URL: "https://127.0.0.1/ws", Path: "/ws", WebSocket: true, MITM: true, At: time.Now()})
	if doc := r.tape(fault.Config{}); !doc.Incomplete {
		t.Fatal("forwarded WebSocket could be replayed against the reverse target")
	}
}

func TestRecordedSSEKeepsProtocol(t *testing.T) {
	var r recorder
	r.start(0, 0, fault.Config{})
	r.request(proxy.Record{Seq: 1, Path: "/events", Proto: "h2c", At: time.Now()})
	r.markSSE(1)
	if doc := r.tape(fault.Config{}); len(doc.Script) != 1 || doc.Script[0].Stream == nil || doc.Script[0].Stream.Proto != "h2c" {
		t.Fatalf("protocol lost in SSE step: %+v", doc.Script)
	}
}

func TestRecordingBudgetIncludesConfigSnapshots(t *testing.T) {
	rule := func(seed uint64, size int) fault.Config {
		return fault.Config{Seed: seed, Rules: []fault.Rule{{
			ID: "limit", Fault: fault.Fault{Type: "rate-limit", Params: map[string]any{"body": strings.Repeat("a", size)}},
		}}}
	}
	t.Run("changes and traffic share budget", func(t *testing.T) {
		var r recorder
		r.start(0, 0, rule(1, 2<<20))
		now := time.Now()
		r.request(proxy.Record{Seq: 1, Method: "POST", Path: "/one", At: now, Body: make([]byte, 1<<20)})
		r.changed(2, rule(2, 2<<20))
		r.changed(2, rule(3, 2<<20))
		if status := r.status(); status.Incomplete {
			t.Fatalf("replacement did not release its byte allowance: %+v", status)
		}
		r.request(proxy.Record{Seq: 2, Method: "GET", Path: "/two", At: now})
		r.changed(3, rule(4, 3<<20))
		r.request(proxy.Record{Seq: 3, Method: "GET", Path: "/three", At: now})
		r.stop()
		doc := r.tape(fault.Config{})
		if !doc.Incomplete || !strings.Contains(doc.IncompleteReason, "budget") || len(doc.ConfigChanges) != 1 || doc.ConfigChanges[0].Seed != 3 || len(doc.Script) != 3 {
			t.Fatalf("incomplete=%t reason=%q changes=%d steps=%d", doc.Incomplete, doc.IncompleteReason, len(doc.ConfigChanges), len(doc.Script))
		}
	})
	t.Run("oversize initial snapshot is not retained", func(t *testing.T) {
		var r recorder
		status := r.start(0, 0, rule(1, maxRecordBytes))
		if !status.Incomplete || !strings.Contains(status.IncompleteReason, "budget") {
			t.Fatalf("recording status: %+v", status)
		}
		if doc := r.tape(fault.Config{}); len(doc.Rules) != 0 {
			t.Fatal("recording retained an oversized initial configuration")
		}
	})
}

func TestRecordingRedactsHeadersAndQueryValues(t *testing.T) {
	var r recorder
	r.start(0, 0, fault.Config{})
	h := make(http.Header)
	for _, k := range []string{"x-api-key", "x-goog-api-key", "Stripe-Signature", "x-my-token", "x-extra-apikey", "x-my-secret", "Authorization"} {
		h.Set(k, "fixture-secret")
	}
	h.Set("Content-Type", "application/json")
	h.Set("Referer", "http://localhost/previous?token=referer-secret")
	query := "?api_key=sk-123&keep=a%20b&ToKeN=other-secret;hidden-suffix&keep=c&%53ig=hidden&apikey=private&key=key-value&access_token=access-value&secret=secret-value&signature=sig-value"
	now := time.Now()
	r.request(proxy.Record{Seq: 1, Method: "GET", Path: "/reverse" + query, Header: h, At: now})
	r.request(proxy.Record{Seq: 2, Method: "GET", Path: "/forward" + query, URL: "http://127.0.0.1/forward" + query, Header: h, At: now})
	r.markSSE(2)
	r.request(proxy.Record{Seq: 3, Path: "/ws" + query, WebSocket: true, At: now})
	doc := r.tape(fault.Config{})
	var data bytes.Buffer
	if err := tape.Encode(&data, doc); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"fixture-secret", "referer-secret", "sk-123", "other-secret", "hidden", "private", "key-value", "access-value", "secret-value", "sig-value"} {
		if strings.Contains(data.String(), secret) {
			t.Errorf("tape contains %q: %s", secret, data.String())
		}
	}
	if !strings.Contains(data.String(), "Content-Type: application/json") ||
		strings.Count(data.String(), "keep=a%20b") != 3 || strings.Count(data.String(), "keep=c") != 3 {
		t.Fatalf("unrelated header or query values lost: %s", data.String())
	}
}

func TestRecordingRedactsSemicolonParametersAndSensitiveSuffixes(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"/?keep=a%20b;token=secret&x=%2f", "/?keep=a%20b;token=REDACTED&x=%2f"},
		{"/?token=prefix;suffix&keep=x", "/?token=REDACTED&keep=x"},
		{"/?token=prefix;keep=value&x=y", "/?token=REDACTED&x=y"},
		{"/?a=b;%53ig=private;other=z", "/?a=b;%53ig=REDACTED"},
	} {
		if got := redactQuery(tc.input); got != tc.want {
			t.Errorf("redactQuery(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestRecordingWithTrailersIsIncomplete(t *testing.T) {
	var r recorder
	r.start(0, 0, fault.Config{})
	r.request(proxy.Record{Seq: 1, Method: "POST", Path: "/", At: time.Now(), HasTrailers: true})
	doc := r.tape(fault.Config{})
	if !doc.Incomplete || !strings.Contains(doc.IncompleteReason, "trailer") {
		t.Fatalf("trailer-bearing recording marked complete: %+v", doc)
	}
}

func TestRecordingExportReportsEvictions(t *testing.T) {
	for _, tc := range []struct {
		name  string
		n     int
		body  []byte
		drops int
	}{
		{"entries", maxEntries + 2, nil, 2},
		{"bytes", 5, bytes.Repeat([]byte("a"), 2<<20), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r recorder
			r.start(0, 0, fault.Config{})
			now := time.Now()
			for i := 1; i <= tc.n; i++ {
				r.request(proxy.Record{Seq: uint64(i), At: now, Method: "POST", Path: "/", Body: tc.body})
			}
			r.stop()
			doc := r.tape(fault.Config{})
			var data bytes.Buffer
			if err := tape.Encode(&data, doc); err != nil {
				t.Fatal(err)
			}
			if want := tc.n - tc.drops; len(doc.Script) != want || doc.Script[0].Seq != uint64(tc.drops+1) {
				t.Fatalf("retained %d steps, want %d starting after %d", len(doc.Script), want, tc.drops)
			}
			if !bytes.Contains(data.Bytes(), []byte("truncated: true")) || !bytes.Contains(data.Bytes(), []byte("dropped_entries: 2")) {
				t.Fatal("tape omits truncation metadata")
			}
			if _, err := tape.Decode(&data); err != nil {
				t.Fatalf("truncated tape does not decode: %v", err)
			}
		})
	}
}

func TestRecordingMarksCappedRequestBody(t *testing.T) {
	var r recorder
	r.start(0, 0, fault.Config{})
	r.request(proxy.Record{Seq: 1, Method: "POST", Path: "/upload", At: time.Now(), Body: []byte("prefix"), BodyTruncated: true})
	status := r.stop()
	doc := r.tape(fault.Config{})
	if !status.Truncated || !doc.Truncated || !doc.Incomplete || doc.DroppedEntries != 0 ||
		!strings.Contains(doc.IncompleteReason, "body was truncated") || len(doc.Script) != 1 || doc.Script[0].HTTP.Body != "prefix" {
		t.Fatalf("status %+v, tape %+v", status, doc)
	}
	if next := r.start(1, 0, fault.Config{}); next.Truncated || next.Incomplete || next.DroppedEntries != 0 {
		t.Fatalf("new recording inherited truncation: %+v", next)
	}
}

func TestRecordingStopReportsPendingBody(t *testing.T) {
	var r recorder
	r.start(0, 0, fault.Config{})
	if !r.shouldCaptureBody(1) {
		t.Fatal("active recording did not capture the upload")
	}
	if doc := r.tape(fault.Config{}); !doc.Incomplete || !strings.Contains(doc.IncompleteReason, "in flight") {
		t.Fatalf("running export omitted pending upload: %+v", doc)
	}
	r.request(proxy.Record{Seq: 1, Method: "POST", Path: "/", At: time.Now(), BodyCaptureStarted: true})
	if status := r.stop(); status.Incomplete {
		t.Fatalf("completed upload was still pending: %+v", status)
	}
	r.start(1, 0, fault.Config{})
	r.shouldCaptureBody(2)
	if status := r.stop(); !status.Incomplete || !strings.Contains(status.IncompleteReason, "in flight") {
		t.Fatalf("stopped recording omitted pending upload: %+v", status)
	}
}
