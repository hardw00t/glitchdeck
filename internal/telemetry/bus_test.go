package telemetry

import (
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
