package ui

import (
	"slices"
	"strings"
	"sync"
	"time"

	"glitchdeck/internal/proxy"
	"glitchdeck/internal/tape"
)

const (
	maxEntries     = 256
	maxRecordBytes = 8 << 20
)

type recordingStatus struct {
	Recording bool  `json:"recording"`
	ElapsedMS int64 `json:"elapsed_ms"`
	Events    int   `json:"events"`
}

type recorded struct {
	seq           uint64
	at            time.Time
	http          *tape.HTTP
	ws            *tape.WS
	bytes, events int
	done          bool
}

type recorder struct {
	mu               sync.Mutex
	running          bool
	started, stopped time.Time
	startSeq         uint64
	entries          []*recorded
	streams          map[uint64]*recorded
	bytes, events    int
}

func (r *recorder) clear() {
	r.running = false
	r.started, r.stopped = time.Time{}, time.Time{}
	r.startSeq, r.bytes, r.events = 0, 0, 0
	r.entries, r.streams = nil, nil
}

func (r *recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clear()
}

func (r *recorder) start(seq func() uint64) recordingStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running {
		r.clear()
		r.running, r.started, r.startSeq = true, time.Now(), seq()
		r.streams = make(map[uint64]*recorded)
	}
	return r.snapshot()
}

func (r *recorder) stop() recordingStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		r.running, r.stopped = false, time.Now()
	}
	return r.snapshot()
}

func (r *recorder) status() recordingStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.snapshot()
}

func (r *recorder) snapshot() recordingStatus {
	end := r.stopped
	if r.running {
		end = time.Now()
	}
	return recordingStatus{Recording: r.running, ElapsedMS: end.Sub(r.started).Milliseconds(), Events: r.events}
}

func (r *recorder) request(req proxy.Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running || req.Seq <= r.startSeq {
		return
	}
	e := &recorded{seq: req.Seq, at: req.At, events: 1, bytes: len(req.Path)}
	if req.WebSocket {
		e.ws = &tape.WS{Path: req.Path}
		r.streams[req.Seq] = e
	} else {
		e.http = &tape.HTTP{Method: req.Method, Path: req.Path, Body: string(req.Body)}
		e.bytes += len(req.Body)
		for k, v := range req.Header {
			switch strings.ToLower(k) {
			case "authorization", "proxy-authorization", "cookie", "connection", "upgrade", "transfer-encoding", "content-length", "expect", "te", "trailer":
				continue
			}
			if e.http.Headers == nil {
				e.http.Headers = make(map[string]string)
			}
			e.http.Headers[k] = strings.Join(v, ", ")
			e.bytes += len(k) + len(e.http.Headers[k])
		}
	}
	r.entries = append(r.entries, e)
	r.bytes += e.bytes
	r.events++
	r.trim()
}

func (r *recorder) trim() {
	for len(r.entries) > maxEntries || r.bytes > maxRecordBytes {
		old := r.entries[0]
		r.entries[0] = nil
		r.entries = r.entries[1:]
		delete(r.streams, old.seq)
		r.bytes -= old.bytes
		r.events -= old.events
	}
}

func (r *recorder) clientFrame(seq uint64, payload []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.streams[seq]; r.running && e != nil {
		e.ws.Messages = append(e.ws.Messages, string(payload))
		e.bytes += len(payload) + 16
		r.bytes += len(payload) + 16
		e.events++
		r.events++
		r.trim()
	}
}

func (r *recorder) serverFrame(seq uint64, action string, opcode byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.streams[seq]; r.running && e != nil {
		e.events++
		r.events++
		switch {
		case e.done || action == "drop":
		case action == "close_1006" || action == "truncate" || opcode == 8:
			e.ws.Frames++
			e.done = true
		case opcode == 1 || opcode == 2:
			e.ws.Frames++
		}
	}
}

func (r *recorder) tickerStalled() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running {
		return
	}
	for i := len(r.entries) - 1; i >= 0; i-- {
		e := r.entries[i]
		if e.ws != nil && e.ws.Path == "/ws/ticker" {
			if !e.done {
				e.ws.Frames++
				e.done = true
			}
			return
		}
	}
}

func (r *recorder) script() ([]tape.Step, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entries := slices.Clone(r.entries)
	slices.SortFunc(entries, func(a, b *recorded) int {
		switch {
		case a.seq < b.seq:
			return -1
		case a.seq > b.seq:
			return 1
		default:
			return 0
		}
	})
	steps := make([]tape.Step, 0, len(entries))
	start := r.startSeq
	if len(entries) != 0 {
		start = entries[0].seq - 1
	}
	for _, e := range entries {
		at := max(e.at.Sub(entries[0].at).Milliseconds(), 0)
		if e.ws != nil {
			ws := *e.ws
			ws.Frames = max(ws.Frames, 1)
			ws.Messages = slices.Clone(ws.Messages)
			steps = append(steps, tape.Step{WS: &ws, AtMS: at})
		} else {
			steps = append(steps, tape.Step{HTTP: e.http, AtMS: at})
		}
	}
	return steps, start
}
