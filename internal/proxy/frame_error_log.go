package proxy

import (
	"slices"
	"sync"

	"github.com/hardw00t/glitchdeck/internal/wsframe"
)

// FrameErrorEntry contains protocol metadata, never frame payloads.
type FrameErrorEntry struct {
	Seq      uint64 `json:"seq"`
	Code     string `json:"error"`
	Detail   string `json:"detail"`
	Declared uint64 `json:"declared_bytes"`
	Limit    int    `json:"limit_bytes"`
	Dir      string `json:"dir"`
}

type FrameErrorLog struct {
	mu      sync.Mutex
	entries []FrameErrorEntry
	omitted uint64
}

func (l *FrameErrorLog) Observe(o Outcome) {
	frame, ok := o.Err.(*FrameError)
	if !ok {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) < 64 {
		l.entries = append(l.entries, FrameErrorEntry{o.Seq, frame.Code, frame.Detail, frame.Declared, wsframe.MaxPayload, frame.Direction})
	} else {
		l.omitted++
	}
}

func (l *FrameErrorLog) Snapshot() ([]FrameErrorEntry, uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.entries), l.omitted
}

func (l *FrameErrorLog) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = l.entries[:0]
	l.omitted = 0
}
