package ui

import (
	"net/http"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
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
