package ui

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/tape"
)

const (
	maxEntries     = 256
	maxRecordBytes = 8 << 20
)

type recordingStatus struct {
	Recording        bool   `json:"recording"`
	ElapsedMS        int64  `json:"elapsed_ms"`
	Events           int    `json:"events"`
	Incomplete       bool   `json:"incomplete"`
	IncompleteReason string `json:"incomplete_reason,omitempty"`
}

type recorded struct {
	seq           uint64
	at            time.Time
	http          *tape.HTTP
	ws            *tape.WS
	bytes, events int
	done          bool
	sse           bool
	mitm          bool
}

type recordedChange struct {
	tape.ConfigChange
	at    time.Time
	bytes int
}

type recorder struct {
	mu               sync.Mutex
	running          bool
	started, stopped time.Time
	startSeq         uint64
	entries          []*recorded
	streams          map[uint64]*recorded
	bytes, events    int
	config           fault.Config
	changes          []recordedChange
	incompleteReason string
	lastFrame        time.Time
}

// Recording captures traffic and configuration changes from a single proxy.
type Recording struct {
	rec recorder
	p   *proxy.Proxy
}

func NewRecorder() *Recording { return new(Recording) }

// Start attaches hooks before the proxy is served.
func (r *Recording) Start(p *proxy.Proxy) {
	r.p = p
	r.rec.attach(p)
	p.CaptureBoundary(func(next uint64, active int) {
		r.rec.start(next-1, active, p.Config())
	})
}

func (r *Recording) Stop() { r.rec.stop() }

func (r *Recording) ConfigChanged(before uint64, cfg fault.Config) { r.rec.changed(before, cfg) }

func (r *Recording) Export(name string) (tape.Tape, error) {
	var cfg fault.Config
	if r.p != nil {
		cfg = r.p.Config()
	}
	doc := r.rec.tape(cfg)
	doc.Name = name
	return doc, nil
}

func (r *recorder) attach(p *proxy.Proxy) {
	p.OnRequest = r.request
	p.OnClientFrame = r.clientFrame
	p.OnServerFrame = r.serverFrame
	p.OnUnsupportedFrame = r.unsupportedFrame
	p.OnSSE = r.markSSE
}

func (r *recorder) markSSE(seq uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running {
		return
	}
	for i := len(r.entries) - 1; i >= 0; i-- {
		if e := r.entries[i]; e.seq == seq {
			e.sse = true
			return
		}
	}
}

func (r *recorder) clear() {
	r.running = false
	r.started, r.stopped = time.Time{}, time.Time{}
	r.startSeq, r.bytes, r.events = 0, 0, 0
	r.entries, r.streams = nil, nil
	r.config = fault.Config{}
	r.changes = nil
	r.incompleteReason = ""
	r.lastFrame = time.Time{}
}

func (r *recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clear()
}

func (r *recorder) start(seq uint64, activeWS int, cfg fault.Config) recordingStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running {
		r.clear()
		r.running, r.started, r.startSeq = true, time.Now(), seq
		if size, ok := configSize(cfg); ok && size <= maxRecordBytes {
			r.config, r.bytes = cfg, size
		} else {
			r.markIncomplete("initial configuration exceeded the recording byte budget")
		}
		r.streams = make(map[uint64]*recorded)
		if activeWS != 0 {
			r.markIncomplete("WebSocket connection already open when recording started")
		}
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
	return recordingStatus{
		Recording: r.running, ElapsedMS: end.Sub(r.started).Milliseconds(), Events: r.events,
		Incomplete: r.incompleteReason != "", IncompleteReason: r.incompleteReason,
	}
}

func (r *recorder) changed(before uint64, cfg fault.Config) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running {
		return
	}
	change := recordedChange{ConfigChange: tape.ConfigChange{BeforeSeq: before, Seed: cfg.Seed, Rules: cfg.Rules}}
	previous := r.config
	if n := len(r.changes); n > 0 {
		previous = fault.Config{Seed: r.changes[n-1].Seed, Rules: r.changes[n-1].Rules}
	}
	for seq, stream := range r.streams {
		if stream.done {
			continue
		}
		path, _, _ := strings.Cut(stream.ws.Path, "?")
		oldRule := fault.MatchRule(previous, "GET", path, seq, true)
		newRule := fault.MatchRule(cfg, "GET", path, seq, true)
		if !reflect.DeepEqual(oldRule, newRule) || (newRule != nil && previous.Seed != cfg.Seed) {
			change.at = time.Now()
			break
		}
	}
	last := len(r.changes) - 1
	replace := last >= 0 && r.changes[last].BeforeSeq == before && change.at.IsZero() && r.changes[last].at.IsZero()
	if !replace && len(r.changes) == maxEntries {
		r.markIncomplete("configuration history exceeded the recording limit")
		return
	}
	var previousSize int
	if replace {
		previousSize = r.changes[last].bytes
	}
	size, ok := configSize(cfg)
	if !ok || size > maxRecordBytes-r.bytes+previousSize {
		r.markIncomplete("configuration change exceeded the recording byte budget")
		return
	}
	change.bytes = size
	r.bytes += size - previousSize
	if replace {
		r.changes[last] = change
	} else {
		r.changes = append(r.changes, change)
	}
}

func configSize(cfg fault.Config) (int, bool) {
	data, err := json.Marshal(cfg)
	return len(data), err == nil
}

func (r *recorder) markIncomplete(reason string) {
	if r.incompleteReason == "" {
		r.incompleteReason = reason
	}
}

func (r *recorder) unsupportedFrame(seq uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running && seq > r.startSeq {
		r.markIncomplete("binary or fragmented WebSocket frames cannot be replayed")
	}
}

func (r *recorder) request(req proxy.Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running || req.Seq <= r.startSeq {
		return
	}
	if req.UnrecordableBody {
		r.markIncomplete("streamed request body was not captured")
	}
	e := &recorded{seq: req.Seq, at: req.At, events: 1, bytes: len(req.Path), mitm: req.MITM}
	if req.WebSocket {
		if req.Header.Get("Sec-WebSocket-Protocol") != "" {
			r.markIncomplete("WebSocket subprotocol offers were not captured")
		}
		e.ws = &tape.WS{Path: req.Path}
		r.streams[req.Seq] = e
	} else {
		e.http = &tape.HTTP{Method: req.Method, Path: req.Path, URL: req.URL, Proto: req.Proto, Body: string(req.Body)}
		if req.URL != "" {
			e.http.Path = ""
		}
		e.bytes += len(req.Body) + len(req.URL) + len(req.Proto)
		for k, v := range req.Header {
			switch strings.ToLower(k) {
			case "authorization", "proxy-authorization", "cookie", "set-cookie", "connection", "upgrade", "transfer-encoding", "content-length", "expect", "te", "trailer", "x-glitchdeck-run", "x-glitchdeck-seq":
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
		r.lastFrame = time.Now()
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
		r.lastFrame = time.Now()
		e.events++
		r.events++
		switch {
		case e.done || action == "drop":
		case action == "close_1006" || action == "truncate":
			e.ws.Frames++
			e.done = true
		case opcode == 8:
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

func (r *recorder) tape(fallback fault.Config) tape.Tape {
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
	doc := tape.Tape{
		Version: 1,
		Seed:    fallback.Seed, Rules: fallback.Rules,
		Incomplete: r.incompleteReason != "", IncompleteReason: r.incompleteReason,
		Script: make([]tape.Step, 0, len(entries)),
	}
	if r.started.IsZero() {
		if v2Rules(doc.Rules) {
			doc.Version = 2
		}
		return doc
	}
	doc.Seed, doc.Rules, doc.StartSeq = r.config.Seed, r.config.Rules, r.startSeq
	if len(entries) != 0 {
		first, last := entries[0].seq, entries[len(entries)-1].seq
		doc.StartSeq = first - 1
		origin := entries[0].at
		for _, change := range r.changes {
			entry := change.ConfigChange
			switch {
			case change.BeforeSeq <= first:
				doc.Seed, doc.Rules = change.Seed, change.Rules
			case !change.at.IsZero() && change.at.Before(r.lastFrame):
				ms := max(change.at.Sub(origin).Milliseconds(), 0)
				entry.AtMS = &ms
				doc.ConfigChanges = append(doc.ConfigChanges, entry)
			case change.BeforeSeq <= last:
				doc.ConfigChanges = append(doc.ConfigChanges, entry)
			}
		}
	}
	if v2Rules(doc.Rules) {
		doc.Version = 2
	}
	for _, change := range doc.ConfigChanges {
		if v2Rules(change.Rules) {
			doc.Version = 2
			break
		}
	}
	for _, e := range entries {
		step := tape.Step{Seq: e.seq, AtMS: max(e.at.Sub(entries[0].at).Milliseconds(), 0), HTTP: e.http}
		if e.mitm {
			doc.Version, doc.TLSMITM = 2, true
		}
		if e.http != nil {
			if e.http.URL != "" || e.http.Proto != "" || e.sse {
				doc.Version = 2
			}
			if e.sse {
				h := e.http
				step.HTTP = nil
				step.Stream = &tape.Stream{Method: h.Method, Path: h.Path, URL: h.URL, Headers: h.Headers, Body: h.Body}
			}
		}
		if e.ws != nil {
			ws := *e.ws
			ws.Frames = max(ws.Frames, 1)
			ws.Messages = slices.Clone(ws.Messages)
			step.WS = &ws
		}
		doc.Script = append(doc.Script, step)
	}
	return doc
}

func v2Rules(rules []fault.Rule) bool {
	for _, r := range rules {
		switch r.Fault.Type {
		case "sse-glitch", "grpc-glitch", "h2-glitch":
			return true
		}
		if r.Match.Host != "" || r.Match.Scheme != "" || r.Match.Proto != "" {
			return true
		}
	}
	return false
}
