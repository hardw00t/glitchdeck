package ui

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
)

func TestFailedResponseCaptureIsIncomplete(t *testing.T) {
	var r recorder
	r.start(0, 0, fault.Config{})
	r.shouldCaptureResponse(1)
	r.request(proxy.Record{Seq: 1, At: time.Unix(1, 0), Method: "GET", Path: "/"})
	r.response(proxy.ResponseRecord{Seq: 1, Truncated: true})
	doc := r.tape(fault.Config{})
	if !doc.Incomplete || !doc.Truncated {
		t.Fatalf("failed capture was exported as complete: %+v", doc)
	}
}

func TestOnlyCassetteEvictedIsIncomplete(t *testing.T) {
	var r recorder
	r.start(0, 0, fault.Config{})
	r.shouldCaptureResponse(1)
	r.request(proxy.Record{Seq: 1, At: time.Unix(1, 0), Method: "GET", Path: "/"})
	r.response(proxy.ResponseRecord{Seq: 1, Status: http.StatusOK, Body: bytes.Repeat([]byte{0xff}, 7<<20)})
	doc := r.tape(fault.Config{})
	if !doc.Incomplete || !doc.Truncated || len(doc.Cassettes) != 0 {
		t.Fatalf("evicted cassette was exported as complete: %+v", doc)
	}
}

func TestPendingResponseDoesNotPreventRequestEviction(t *testing.T) {
	var r recorder
	r.start(0, 0, fault.Config{})
	r.shouldCaptureResponse(1)
	r.request(proxy.Record{Seq: 1, At: time.Unix(1, 0), Method: "POST", Path: "/", Body: bytes.Repeat([]byte("a"), 4<<20)})
	if n := r.reserveRequestBytes(2, 4<<20); n != 4<<20 {
		t.Fatalf("reserved %d bytes, want full upload", n)
	}
	r.response(proxy.ResponseRecord{Seq: 1})
	r.request(proxy.Record{Seq: 2, At: time.Unix(2, 0), Method: "POST", Path: "/", Body: bytes.Repeat([]byte("b"), 4<<20)})
	doc := r.tape(fault.Config{})
	if doc.Incomplete || len(doc.Script) != 1 || doc.Script[0].Seq != 2 {
		t.Fatalf("request-only recording changed: incomplete=%v script=%d", doc.Incomplete, len(doc.Script))
	}
}

func TestEvictedPendingExchangeWithResponseIsIncomplete(t *testing.T) {
	var r recorder
	r.start(0, 0, fault.Config{})
	r.shouldCaptureResponse(1)
	r.request(proxy.Record{Seq: 1, At: time.Unix(1, 0), Method: "POST", Path: "/", Body: bytes.Repeat([]byte("a"), 4<<20)})
	r.reserveRequestBytes(2, 4<<20)
	r.response(proxy.ResponseRecord{Seq: 1, Status: http.StatusOK})
	if doc := r.tape(fault.Config{}); !doc.Incomplete {
		t.Fatal("response for evicted request left recording complete")
	}
}

func TestDistinctExplicitPortsKeepSeparateCassettes(t *testing.T) {
	var r recorder
	r.start(0, 0, fault.Config{})
	for i, target := range []string{"http://example.com:80/", "http://example.com:443/"} {
		seq := uint64(i + 1)
		r.shouldCaptureResponse(seq)
		r.request(proxy.Record{Seq: seq, At: time.Unix(int64(seq), 0), Method: "GET", URL: target})
		r.response(proxy.ResponseRecord{Seq: seq, Status: http.StatusOK, Body: []byte("same")})
	}
	doc := r.tape(fault.Config{})
	if len(doc.Cassettes) != 2 {
		t.Fatalf("distinct ports coalesced: %+v", doc.Cassettes)
	}

	upstream := doc.CassetteUpstream()
	for _, target := range []string{"http://example.com:80/", "http://example.com:443/"} {
		req, err := http.NewRequestWithContext(context.Background(), "GET", target, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := upstream(req)
		if err != nil {
			t.Fatalf("replay %s: %v", target, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || string(body) != "same" {
			t.Fatalf("replay %s: body=%q err=%v", target, body, err)
		}
	}
}
