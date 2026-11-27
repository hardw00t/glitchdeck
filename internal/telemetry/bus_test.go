package telemetry

import (
	"strings"
	"testing"
	"time"
)

func TestSlowSubscriberRetainsNewest(t *testing.T) {
	b := New()
	_, slow, unsub := b.Subscribe()
	defer unsub()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 1; i <= 300; i++ {
			b.Publish("http_req", i)
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("publisher blocked by idle subscriber")
	}
	if first := <-slow; first.ID != 45 || string(first.Data) != "45" {
		t.Fatalf("first retained event = %#v", first)
	}
	last := b.History(1)
	if len(last) != 1 || last[0].ID != 300 {
		t.Fatalf("history tail = %#v", last)
	}
	b.Clear()
	if len(b.History(0)) != 0 || len(slow) != 0 {
		t.Fatal("clear retained stale events")
	}
}

func TestHistoryRetainsNewestWithinByteBudget(t *testing.T) {
	b := New()
	payload := strings.Repeat("x", 32<<10)
	for range 300 {
		b.Publish("sse_event", payload)
	}
	events := b.History(0)
	var bytes int
	for _, event := range events {
		bytes += len(event.Data)
	}
	if bytes > 8<<20 || len(events) == 0 || events[len(events)-1].ID != 300 {
		t.Fatalf("retained %d events and %d bytes", len(events), bytes)
	}
	b.Publish("sse_event", strings.Repeat("x", 128<<10))
	if newest := b.History(1)[0]; newest.ID != 300 {
		t.Fatalf("oversized event retained: id=%d size=%d", newest.ID, len(newest.Data))
	}
}
