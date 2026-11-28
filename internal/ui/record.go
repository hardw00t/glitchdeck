package ui

import (
	"encoding/json"
	"net"
	"net/url"
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

const pendingBodyReason = "recording ended with request bodies still in flight"

type recordingStatus struct {
	Recording        bool   `json:"recording"`
	ElapsedMS        int64  `json:"elapsed_ms"`
	Events           int    `json:"events"`
	Incomplete       bool   `json:"incomplete"`
	IncompleteReason string `json:"incomplete_reason,omitempty"`
	Truncated        bool   `json:"truncated,omitempty"`
	DroppedEntries   int    `json:"dropped_entries,omitempty"`
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
	cassette      *tape.Cassette
	probe         bool
	demoScheme    string
	intentional   bool
}

type recordedChange struct {
	tape.ConfigChange
	at    time.Time
	bytes int
}

type recorder struct {
	mu                    sync.Mutex
	running               bool
	started, stopped      time.Time
	startSeq              uint64
	entries               []*recorded
	streams               map[uint64]*recorded
	bytes, events         int
	config                fault.Config
	changes               []recordedChange
	incompleteReason      string
	lastFrame             time.Time
	bodyTruncated         bool
	droppedEntries        int
	pendingBodies         int
	pendingResponses      map[uint64]bool
	responseReservations  map[uint64]int
	requestReservations   map[uint64]int
	reservedResponseBytes int
	forwardWarning        bool
	demoHTTPAuthority     string
	demoTLSAuthority      string
	target                string
	ignoreJSONPaths       []string
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
	p.CaptureRecordingBoundary(func(next uint64, active int, cfg fault.Config, usedBurst bool) {
		r.rec.start(next-1, active, cfg, usedBurst)
	})
}

func (r *Recording) Stop() { r.rec.stop() }

func (r *Recording) ConfigChanged(before uint64, cfg fault.Config) { r.rec.changed(before, cfg) }

func (r *Recording) SetCassetteMetadata(target string, ignoreJSONPaths []string) {
	r.rec.mu.Lock()
	defer r.rec.mu.Unlock()
	r.rec.target = target
	r.rec.ignoreJSONPaths = slices.Clone(ignoreJSONPaths)
}

func (r *Recording) SetDemoHTTPAuthority(authority string) {
	r.rec.mu.Lock()
	defer r.rec.mu.Unlock()
	r.rec.demoHTTPAuthority = authority
}

func (r *Recording) SetDemoTLSAuthority(authority string) {
	r.rec.mu.Lock()
	defer r.rec.mu.Unlock()
	r.rec.demoTLSAuthority = authority
}

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
	p.ShouldCaptureBody = r.shouldCaptureBody
	p.ShouldCaptureResponse = r.shouldCaptureResponse
	p.OnResponse = r.response
	p.ReserveResponseBytes = r.reserveResponseBytes
	p.ReserveRequestBytes = r.reserveRequestBytes
	p.OnClientFrame = r.clientFrame
	p.OnServerFrame = r.serverFrame
	p.OnUnsupportedFrame = r.unsupportedFrame
	p.OnSSE = r.markSSE
	p.OnBlindTunnel = r.blindTunnel
}

func (r *recorder) shouldCaptureBody(seq uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running || seq <= r.startSeq {
		return false
	}
	r.pendingBodies++
	return true
}

func (r *recorder) shouldCaptureResponse(seq uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running || seq <= r.startSeq {
		return false
	}
	r.pendingResponses[seq] = true
	return true
}

func (r *recorder) reserveResponseBytes(seq uint64, n int) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running || !r.pendingResponses[seq] || n <= 0 {
		return 0
	}
	allowed := min(n, max(0, maxRecordBytes-r.bytes-r.reservedResponseBytes))
	r.responseReservations[seq] += allowed
	r.reservedResponseBytes += allowed
	return allowed
}

func (r *recorder) reserveRequestBytes(seq uint64, n int) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running || seq <= r.startSeq || n <= 0 {
		return 0
	}
	for len(r.entries) > 0 && n > maxRecordBytes-r.bytes-r.reservedResponseBytes {
		if r.pendingResponses[r.entries[0].seq] {
			break
		}
		r.dropOldest()
	}
	allowed := min(n, max(0, maxRecordBytes-r.bytes-r.reservedResponseBytes))
	r.requestReservations[seq] += allowed
	r.reservedResponseBytes += allowed
	return allowed
}

func (r *recorder) response(res proxy.ResponseRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reservedResponseBytes -= r.responseReservations[res.Seq]
	delete(r.responseReservations, res.Seq)
	if !r.running || !r.pendingResponses[res.Seq] && !res.Intentional {
		return
	}
	delete(r.pendingResponses, res.Seq)
	if res.Status == 0 {
		if res.Intentional {
			for _, e := range r.entries {
				if e.seq == res.Seq {
					e.intentional = true
					break
				}
			}
		}
		return
	}
	for _, e := range r.entries {
		if e.seq != res.Seq || e.cassette == nil {
			continue
		}
		keySize := len(e.cassette.Request.Path) + len(e.cassette.Request.Host) + len(e.cassette.Request.Method) + len(e.cassette.Request.BodySHA256)
		e.bytes += keySize
		r.bytes += keySize
		headers := make(map[string]string)
		for k, v := range res.Header {
			name := strings.ToLower(k)
			switch name {
			case "authorization", "proxy-authorization", "cookie", "set-cookie", "referer", "connection", "upgrade", "transfer-encoding", "content-length", "expect", "te", "trailer", "x-glitchdeck-run", "x-glitchdeck-seq":
				continue
			}
			if strings.Contains(name, "secret") || strings.Contains(name, "token") || strings.Contains(name, "api-key") || strings.Contains(name, "apikey") || strings.Contains(name, "signature") {
				continue
			}
			headers[k] = strings.Join(v, ", ")
			e.bytes += len(k) + len(headers[k])
			r.bytes += len(k) + len(headers[k])
		}
		e.cassette.Response = tape.NewCassetteResponse(res.Status, headers, res.Body, res.Truncated)
		size := len(e.cassette.Response.Body)
		e.bytes += size
		r.bytes += size
		if res.Truncated {
			r.bodyTruncated = true
			r.markIncomplete("recorded response body was truncated")
		}
		r.trim()
		return
	}
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
	r.bodyTruncated, r.droppedEntries, r.pendingBodies = false, 0, 0
	r.pendingResponses = nil
	if r.responseReservations == nil {
		r.responseReservations = make(map[uint64]int)
	}
	if r.requestReservations == nil {
		r.requestReservations = make(map[uint64]int)
	}
	r.forwardWarning = false
}

func (r *recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clear()
}

func (r *recorder) start(seq uint64, activeStreams int, cfg fault.Config, usedBurst ...bool) recordingStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running {
		r.clear()
		r.running, r.started, r.startSeq = true, time.Now(), seq
		if size, ok := configSize(cfg); ok && size <= maxRecordBytes-r.reservedResponseBytes {
			r.config, r.bytes = cfg, size
		} else {
			r.markIncomplete("initial configuration exceeded the recording byte budget")
		}
		r.streams = make(map[uint64]*recorded)
		r.pendingResponses = make(map[uint64]bool)
		if activeStreams != 0 {
			r.markIncomplete("WebSocket, blind or passthrough CONNECT tunnel already open when recording started")
		}
		if len(usedBurst) != 0 && usedBurst[0] {
			r.markIncomplete("rate-limit burst was partially or fully consumed before recording started")
		}
	}
	return r.snapshot()
}

func (r *recorder) stop() recordingStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		r.running, r.stopped = false, time.Now()
		if r.pendingBodies != 0 {
			r.markIncomplete(pendingBodyReason)
		}
		if len(r.pendingResponses) != 0 {
			r.markIncomplete("recording ended with responses still in flight")
		}
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
		Incomplete: r.incompleteReason != "" || len(r.pendingResponses) != 0, IncompleteReason: r.incompleteReason,
		Truncated: r.bodyTruncated || r.droppedEntries != 0, DroppedEntries: r.droppedEntries,
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
	if !ok || size > maxRecordBytes-r.bytes-r.reservedResponseBytes+previousSize {
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

func (r *recorder) blindTunnel(seq uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running && seq > r.startSeq {
		r.markIncomplete("blind CONNECT traffic cannot be recorded")
	}
}

func (r *recorder) request(req proxy.Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reservedResponseBytes -= r.requestReservations[req.Seq]
	delete(r.requestReservations, req.Seq)
	if !r.running || req.Seq <= r.startSeq {
		return
	}
	if req.BodyCaptureStarted {
		r.pendingBodies--
	}
	if req.BodyTruncated {
		r.bodyTruncated = true
		r.markIncomplete("recorded request body was truncated")
	} else if req.UnrecordableBody {
		r.markIncomplete("streamed request body was not captured")
	}
	if req.HasTrailers {
		r.markIncomplete("request trailers were not captured")
	}
	if req.URL != "" {
		u, err := url.Parse(req.URL)
		if err != nil || !strings.EqualFold(u.Hostname(), "localhost") && !net.ParseIP(u.Hostname()).IsLoopback() {
			r.forwardWarning = true
		}
	}
	requestPath := req.Path
	host := ""
	demoScheme := ""
	if req.URL != "" {
		if u, err := url.Parse(req.URL); err == nil {
			requestPath, host = u.EscapedPath(), u.Host
			if host != "" && u.Scheme == "https" && host == r.demoTLSAuthority {
				host, demoScheme = "localhost", "https"
			} else if host != "" && u.Scheme == "http" && host == r.demoHTTPAuthority {
				host, demoScheme = "", "http"
			}
		}
	} else if u, err := url.ParseRequestURI(requestPath); err == nil {
		requestPath = u.EscapedPath()
	}
	req.Path, req.URL = redactQuery(req.Path), redactQuery(req.URL)
	e := &recorded{seq: req.Seq, at: req.At, events: 1, bytes: len(req.Path), mitm: req.MITM, sse: req.SSE, probe: req.AssertionProbe, demoScheme: demoScheme}
	if req.WebSocket {
		if req.MITM || req.URL != "" {
			r.markIncomplete("forwarded WebSocket authority cannot be replayed")
		}
		if req.Header.Get("Sec-WebSocket-Protocol") != "" {
			r.markIncomplete("WebSocket subprotocol offers were not captured")
		}
		e.ws = &tape.WS{Path: req.Path}
		r.streams[req.Seq] = e
	} else {
		e.http = &tape.HTTP{Method: req.Method, Path: req.Path, URL: req.URL, Proto: req.Proto, Body: string(req.Body)}
		e.cassette = &tape.Cassette{Request: tape.CassetteRequest{Method: req.Method, Path: requestPath, Host: host, BodySHA256: tape.BodySHA256(req.Body, r.ignoreJSONPaths)}}
		if req.URL != "" {
			e.http.Path = ""
		}
		e.bytes += len(req.Body) + len(req.URL) + len(req.Proto)
		for k, v := range req.Header {
			name := strings.ToLower(k)
			switch name {
			case "authorization", "proxy-authorization", "cookie", "set-cookie", "referer", "connection", "upgrade", "transfer-encoding", "content-length", "expect", "te", "trailer", "x-glitchdeck-run", "x-glitchdeck-seq":
				continue
			}
			if strings.Contains(name, "secret") || strings.Contains(name, "token") ||
				strings.Contains(name, "api-key") || strings.Contains(name, "apikey") || strings.Contains(name, "signature") {
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

func redactQuery(raw string) string {
	base, query, ok := strings.Cut(raw, "?")
	if !ok {
		return raw
	}
	var out strings.Builder
	for start := 0; start < len(query); {
		end := strings.IndexAny(query[start:], "&;")
		if end < 0 {
			end = len(query)
		} else {
			end += start
		}
		key, _, hasValue := strings.Cut(query[start:end], "=")
		decoded, _ := url.QueryUnescape(key)
		sensitive := false
		if hasValue {
			switch strings.ToLower(decoded) {
			case "api_key", "apikey", "key", "token", "access_token", "secret", "sig", "signature":
				sensitive = true
			}
		}
		if sensitive {
			if out.Len() == 0 {
				out.WriteString(base)
				out.WriteByte('?')
			}
			out.WriteString(query[:start])
			out.WriteString(key)
			out.WriteString("=REDACTED")
			if next := strings.IndexByte(query[end:], '&'); next >= 0 {
				end += next
			} else {
				end = len(query)
			}
			query, start = query[end:], 0
			continue
		}
		start = end + 1
	}
	if out.Len() == 0 {
		return raw
	}
	out.WriteString(query)
	return out.String()
}

func (r *recorder) trim() {
	for len(r.entries) > 0 && (len(r.entries) > maxEntries || r.bytes+r.reservedResponseBytes > maxRecordBytes) {
		r.dropOldest()
	}
}

func (r *recorder) dropOldest() {
	old := r.entries[0]
	r.entries[0] = nil
	r.entries = r.entries[1:]
	delete(r.streams, old.seq)
	r.bytes -= old.bytes
	r.events -= old.events
	r.droppedEntries++
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
	reason := r.incompleteReason
	if reason == "" && r.pendingBodies != 0 {
		reason = pendingBodyReason
	}
	if reason == "" && len(r.pendingResponses) != 0 {
		reason = "recording ended with responses still in flight"
	}
	doc := tape.Tape{
		Version: 1,
		Seed:    fallback.Seed, Rules: fallback.Rules,
		Incomplete: reason != "", IncompleteReason: reason,
		Truncated: r.bodyTruncated || r.droppedEntries != 0, DroppedEntries: r.droppedEntries,
		Script: make([]tape.Step, 0, len(entries)),
	}
	doc.Target = r.target
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
				step.Stream = &tape.Stream{Method: h.Method, Path: h.Path, URL: h.URL, Proto: h.Proto, Headers: h.Headers, Body: h.Body}
			}
		}
		if e.ws != nil {
			ws := *e.ws
			ws.Frames = max(ws.Frames, 1)
			ws.Messages = slices.Clone(ws.Messages)
			step.WS = &ws
		}
		if e.cassette != nil && e.cassette.Response.Status != 0 {
			found := false
			for _, c := range doc.Cassettes {
				if cassetteKeysOverlap(c.Request, e.cassette.Request) {
					found = true
					if (!reflect.DeepEqual(c.Response, e.cassette.Response) ||
						(c.Request.Host == "") != (e.cassette.Request.Host == "") ||
						(c.Request.BodySHA256 == "") != (e.cassette.Request.BodySHA256 == "")) && !doc.Incomplete {
						doc.Incomplete = true
						doc.IncompleteReason = "identical requests produced different responses"
					}
					break
				}
			}
			if !found {
				doc.Cassettes = append(doc.Cassettes, *e.cassette)
			}
		}
		if !e.probe {
			doc.Script = append(doc.Script, step)
		}
	}
	if len(doc.Cassettes) != 0 {
		doc.Version = 3
		doc.IgnoreJSONPaths = slices.Clone(r.ignoreJSONPaths)
		for i := range doc.Script {
			step := &doc.Script[i]
			for _, e := range entries {
				if step.Seq != e.seq || e.demoScheme == "" {
					continue
				}
				if step.HTTP != nil {
					h := *step.HTTP
					u, err := url.Parse(h.URL)
					if err == nil {
						h.Path, h.URL = u.RequestURI(), ""
						if e.demoScheme == "https" {
							h.Path, h.URL = "", "${DEMO_TLS}"+u.RequestURI()
						}
						step.HTTP = &h
					}
				}
				if step.Stream != nil {
					s := *step.Stream
					u, err := url.Parse(s.URL)
					if err == nil {
						s.Path, s.URL = u.RequestURI(), ""
						if e.demoScheme == "https" {
							s.Path, s.URL = "", "${DEMO_TLS}"+u.RequestURI()
						}
						step.Stream = &s
					}
				}
				break
			}
		}
		for _, e := range entries {
			if !e.intentional && (e.cassette == nil || e.cassette.Response.Status == 0) && !doc.Incomplete {
				doc.Incomplete = true
				doc.IncompleteReason = "recorded exchange has no replayable response"
			}
		}
		if r.droppedEntries != 0 && !doc.Incomplete {
			doc.Incomplete = true
			doc.IncompleteReason = "recorded entries were evicted"
		}
	} else if r.forwardWarning && !doc.Incomplete {
		doc.Incomplete = true
		doc.IncompleteReason = "forwarded traffic requires explicit upstream authorization for replay"
	}
	return doc
}

func cassetteKeysOverlap(a, b tape.CassetteRequest) bool {
	if !strings.EqualFold(a.Method, b.Method) || a.Path != b.Path ||
		a.BodySHA256 != "" && b.BodySHA256 != "" && !strings.EqualFold(a.BodySHA256, b.BodySHA256) {
		return false
	}
	if a.Host == "" || b.Host == "" || strings.EqualFold(a.Host, b.Host) {
		return true
	}
	normalize := func(authority string) string {
		host, port, err := net.SplitHostPort(authority)
		if err == nil && (port == "80" || port == "443") {
			return strings.ToLower(strings.Trim(host, "[]"))
		}
		return strings.ToLower(strings.Trim(authority, "[]"))
	}
	return normalize(a.Host) == normalize(b.Host)
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
