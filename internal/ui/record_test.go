package ui

import (
	"strings"
	"testing"
	"time"

	"glitchdeck/internal/fault"
	"glitchdeck/internal/proxy"
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
