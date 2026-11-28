package ui

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/tape"
)

func TestCassetteCaptureAndPendingResponse(t *testing.T) {
	var r recorder
	r.start(0, 0, fault.Config{})
	if !r.shouldCaptureResponse(1) {
		t.Fatal("response capture disabled")
	}
	r.request(proxy.Record{Seq: 1, At: time.Now(), Method: "POST", Path: "/chat?x=1", Body: []byte(`{"id":1}`)})
	if !r.tape(fault.Config{}).Incomplete {
		t.Fatal("pending response not marked incomplete")
	}
	r.response(proxy.ResponseRecord{Seq: 1, Status: 200, Header: http.Header{"Set-Cookie": {"secret"}, "Content-Type": {"text/plain"}}, Body: []byte("ok")})
	doc := r.tape(fault.Config{})
	if doc.Incomplete || doc.Version != 3 || len(doc.Cassettes) != 1 || doc.Cassettes[0].Response.Body != "ok" || doc.Cassettes[0].Request.Path != "/chat" || doc.Cassettes[0].Response.Headers["Set-Cookie"] != "" {
		t.Fatalf("bad cassette: %+v", doc)
	}
	r.stop()
	if r.shouldCaptureResponse(2) {
		t.Fatal("captured after stop")
	}
}

func TestCassetteTruncationAndMetadata(t *testing.T) {
	recording := NewRecorder()
	recording.SetCassetteMetadata("http://127.0.0.1:8080", []string{"id"})
	r := &recording.rec
	r.start(0, 0, fault.Config{})
	r.shouldCaptureResponse(1)
	r.request(proxy.Record{Seq: 1, At: time.Now(), Method: "POST", Path: "/", Body: []byte(`{"id":1,"value":2}`)})
	r.response(proxy.ResponseRecord{Seq: 1, Status: 200, Body: []byte("partial"), Truncated: true})
	doc, err := recording.Export("test")
	if err != nil || !doc.Incomplete || !doc.Truncated || !doc.Cassettes[0].Response.Truncated || doc.Target != "http://127.0.0.1:8080" || len(doc.IgnoreJSONPaths) != 1 {
		t.Fatalf("bad metadata: %+v, %v", doc, err)
	}
}

func TestForwardCassetteAvoidsLegacyWarningAndPreservesEscapedPath(t *testing.T) {
	var r recorder
	r.start(0, 0, fault.Config{})
	r.shouldCaptureResponse(1)
	r.request(proxy.Record{Seq: 1, At: time.Now(), Method: "GET", Path: "/a%2Fb", URL: "https://example.com/a%2Fb"})
	r.response(proxy.ResponseRecord{Seq: 1, Status: 200})
	doc := r.tape(fault.Config{})
	if doc.Incomplete || len(doc.Cassettes) != 1 || doc.Cassettes[0].Request.Path != "/a%2Fb" {
		t.Fatalf("forward cassette: %+v", doc)
	}
}

func TestResponseReservationsRespectRecordingBudget(t *testing.T) {
	var r recorder
	r.start(0, 0, fault.Config{})
	r.shouldCaptureResponse(1)
	r.shouldCaptureResponse(2)
	first := r.reserveResponseBytes(1, 6<<20)
	second := r.reserveResponseBytes(2, 6<<20)
	if first < 0 || second < 0 || first+second > maxRecordBytes-r.bytes {
		t.Fatalf("over-reserved: %d + %d", first, second)
	}
	r.response(proxy.ResponseRecord{Seq: 1})
	if r.reserveResponseBytes(2, 1<<20) == 0 {
		t.Fatal("completed response did not release reservation")
	}
	r.stop()
	if r.reserveResponseBytes(2, 1) != 0 {
		t.Fatal("reserved after stop")
	}
}

func TestMixedCassetteOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		intentional bool
		ineligible  bool
		incomplete  bool
	}{
		{"failure", false, false, true},
		{"synthetic", true, false, false},
		{"ineligible", false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r recorder
			r.start(0, 0, fault.Config{})
			r.shouldCaptureResponse(1)
			r.request(proxy.Record{Seq: 1, Method: "GET", Path: "/ok", At: time.Unix(1, 0)})
			r.response(proxy.ResponseRecord{Seq: 1, Status: 200})
			if !tc.ineligible {
				r.shouldCaptureResponse(2)
			}
			r.request(proxy.Record{Seq: 2, Method: "GET", Path: "/other", At: time.Unix(1, 0), WebSocket: tc.ineligible})
			if !tc.ineligible {
				r.response(proxy.ResponseRecord{Seq: 2, Intentional: tc.intentional})
			}
			doc := r.tape(fault.Config{})
			if doc.Version != 3 || doc.Incomplete != tc.incomplete {
				t.Fatalf("unexpected tape: %+v", doc)
			}
		})
	}
}

func TestCassetteDuplicateRequests(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		var r recorder
		r.start(0, 0, fault.Config{})
		for seq := uint64(1); seq <= 2; seq++ {
			r.shouldCaptureResponse(seq)
			method := "GET"
			if seq == 1 {
				method = "get"
			}
			r.request(proxy.Record{Seq: seq, Method: method, Path: "/same", At: time.Unix(1, 0), AssertionProbe: seq == 2})
			body := "same"
			if conflict && seq == 2 {
				body = "different"
			}
			r.response(proxy.ResponseRecord{Seq: seq, Status: 200, Body: []byte(body)})
		}
		doc := r.tape(fault.Config{})
		if len(doc.Cassettes) != 1 || doc.Incomplete != conflict || len(doc.Script) != 1 {
			t.Fatalf("conflict=%v: %+v", conflict, doc)
		}
	}
}

func TestDemoTLSCassetteAuthorityDoesNotChangeLegacyScript(t *testing.T) {
	recording := NewRecorder()
	recording.SetCassetteMetadata("demo", nil)
	recording.SetDemoTLSAuthority("127.0.0.1:45678")
	r := &recording.rec
	r.start(0, 0, fault.Config{})
	r.shouldCaptureResponse(1)
	r.request(proxy.Record{Seq: 1, Method: "GET", Path: "/demo", URL: "https://127.0.0.1:45678/demo", At: time.Unix(1, 0), MITM: true})
	r.response(proxy.ResponseRecord{Seq: 1, Status: 200})
	doc := r.tape(fault.Config{})
	if doc.Cassettes[0].Request.Host != "localhost" || doc.Script[0].HTTP.URL != "${DEMO_TLS}/demo" {
		t.Fatalf("demo identity: %+v", doc)
	}
	if _, report, err := tape.RunReplay(context.Background(), doc, "", "", false); err != nil || report.CassetteError != nil {
		t.Fatalf("demo TLS replay: report=%+v err=%v", report, err)
	}
}

func TestDemoHTTPCassetteAuthority(t *testing.T) {
	recording := NewRecorder()
	recording.SetCassetteMetadata("demo", nil)
	recording.SetDemoHTTPAuthority("127.0.0.1:12345")
	r := &recording.rec
	r.start(0, 0, fault.Config{})
	r.shouldCaptureResponse(1)
	r.request(proxy.Record{Seq: 1, Method: "GET", Path: "/demo", URL: "http://127.0.0.1:12345/demo", At: time.Unix(1, 0)})
	r.response(proxy.ResponseRecord{Seq: 1, Status: 200})
	doc := r.tape(fault.Config{})
	if doc.Cassettes[0].Request.Host != "" || doc.Script[0].HTTP.URL != "" || doc.Script[0].HTTP.Path != "/demo" {
		t.Fatalf("demo identity: %+v", doc)
	}
	if _, report, err := tape.RunReplay(context.Background(), doc, "", "", false); err != nil || report.CassetteError != nil {
		t.Fatalf("demo HTTP replay: report=%+v err=%v", report, err)
	}
}

func TestSyntheticIneligibleExchangeInMixedTape(t *testing.T) {
	var r recorder
	r.start(0, 0, fault.Config{})
	r.shouldCaptureResponse(1)
	r.request(proxy.Record{Seq: 1, Method: "GET", Path: "/ok", At: time.Unix(1, 0)})
	r.response(proxy.ResponseRecord{Seq: 1, Status: 200})
	r.request(proxy.Record{Seq: 2, Method: "GET", Path: "/limited", Proto: "h2c", At: time.Unix(1, 0)})
	r.response(proxy.ResponseRecord{Seq: 2, Intentional: true})
	if doc := r.tape(fault.Config{}); doc.Version != 3 || doc.Incomplete {
		t.Fatalf("synthetic HTTP/2: %+v", doc)
	}
}
