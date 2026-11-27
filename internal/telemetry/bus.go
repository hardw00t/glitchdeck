package telemetry

import (
	"encoding/json"
	"sync"
)

const (
	historySize    = 4096
	subscriberSize = 256
	historyBytes   = 8 << 20
	maxEventBytes  = 64 << 10
)

// Event's ID continues across resets so a reconnect never mistakes fresh events for duplicates.
type Event struct {
	ID   uint64          `json:"id"`
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type Bus struct {
	mu           sync.Mutex
	id           uint64
	ring         [historySize]Event
	write, count int
	bytes        int
	subs         map[chan Event]struct{}
	observer     func(Event)
}

func New() *Bus { return &Bus{subs: make(map[chan Event]struct{})} }

func (b *Bus) SetObserver(observer func(Event)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.observer = observer
}

func (b *Bus) Publish(kind string, data any) {
	payload, err := json.Marshal(data)
	if err != nil || len(payload)+len(kind) > maxEventBytes {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.id++
	e := Event{ID: b.id, Type: kind, Data: payload}
	if b.observer != nil {
		b.observer(e)
	}
	if kind == "http_req" || kind == "ws_frame" || kind == "sse_event" || kind == "grpc_call" || kind == "tls_handshake_failed" {
		size := len(payload) + len(kind)
		for b.count == len(b.ring) || b.bytes+size > historyBytes {
			i := (b.write - b.count + len(b.ring)) % len(b.ring)
			old := b.ring[i]
			b.bytes -= len(old.Data) + len(old.Type)
			b.ring[i] = Event{}
			b.count--
		}
		b.ring[b.write] = e
		b.write = (b.write + 1) % len(b.ring)
		b.count++
		b.bytes += size
	}
	for ch := range b.subs {
		select {
		case ch <- e:
		default:
			select {
			case <-ch:
			default:
			}
			ch <- e // Only this publisher can fill the slot while mu is held.
		}
	}
}

func (b *Bus) History(limit int) []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.history(limit)
}

func (b *Bus) history(limit int) []Event {
	if limit <= 0 || limit > b.count {
		limit = b.count
	}
	events := make([]Event, limit)
	start := (b.write - limit + len(b.ring)) % len(b.ring)
	n := copy(events, b.ring[start:])
	copy(events[n:], b.ring[:limit-n])
	return events
}

func (b *Bus) Subscribe() ([]Event, <-chan Event, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan Event, subscriberSize)
	b.subs[ch] = struct{}{}
	return b.history(0), ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if _, ok := b.subs[ch]; ok {
			delete(b.subs, ch)
			close(ch)
		}
	}
}

func (b *Bus) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	clear(b.ring[:])
	b.write, b.count, b.bytes = 0, 0, 0
	for ch := range b.subs {
		for range len(ch) {
			select {
			case <-ch:
			default:
			}
		}
	}
}
