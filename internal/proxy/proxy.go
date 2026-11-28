package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/grpcwire"
	"github.com/hardw00t/glitchdeck/internal/h2tap"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
)

const maxBody = 4 << 20
const TransportErrorHeader = "X-Glitchdeck-Transport-Error"

type Outcome struct {
	Seq       uint64
	Reset     bool
	H2Fault   bool
	Err       error
	WSAction  string
	WSMessage uint64
	WSUntil   time.Time
}

type Record struct {
	Seq                uint64
	Method, Path       string
	Header             http.Header
	URL                string
	Proto              string
	Body               []byte
	WebSocket          bool
	SSE                bool
	At                 time.Time
	MITM               bool
	UnrecordableBody   bool
	BodyTruncated      bool
	HasTrailers        bool
	BodyCaptureStarted bool
	AssertionProbe     bool
}
type ResponseRecord struct {
	Seq         uint64
	Status      int
	Header      http.Header
	Body        []byte
	Truncated   bool
	Intentional bool
}

type CassetteError struct {
	Kind   string
	Method string
	Path   string
}

func (e *CassetteError) Error() string {
	if e.Method == "" && e.Path == "" {
		return e.Kind
	}
	return fmt.Sprintf("%s: %s %s", e.Kind, e.Method, e.Path)
}

func (p *Proxy) CassetteFailure() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cassetteFailure
}

func (p *Proxy) failCassette(kind, method, path string) *CassetteError {
	err := &CassetteError{Kind: kind, Method: method, Path: path}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cassetteFailure == nil {
		p.cassetteFailure = err
	}
	return err
}

func (p *Proxy) cassetteResponse(r *http.Request) (*http.Response, error) {
	resp, err := p.options.CassetteUpstream(r)
	if err == nil && resp != nil {
		return resp, nil
	}
	kind := "cassette_miss"
	var cassetteErr *CassetteError
	if errors.As(err, &cassetteErr) {
		switch cassetteErr.Kind {
		case "cassette_ambiguous", "cassette_match_limit":
			kind = cassetteErr.Kind
		}
	}
	return nil, p.failCassette(kind, r.Method, r.URL.EscapedPath())
}

type responseCapture struct {
	io.ReadCloser
	body      []byte
	truncated bool
	failed    bool
	err       error
	eof       bool
	reserve   func(int) int
	discard   bool
}

func (c *responseCapture) Read(b []byte) (int, error) {
	n, err := c.ReadCloser.Read(b)
	take := 0
	if !c.truncated && !c.discard {
		take = min(n, maxBody-len(c.body))
		if c.reserve != nil && take > 0 {
			take = max(0, min(take, c.reserve(take)))
		}
	}
	c.body = append(c.body, b[:take]...)
	if n > take && !c.discard {
		c.truncated = true
	}
	if err == io.EOF {
		c.eof = true
	}
	if err != nil && err != io.EOF {
		c.failed = true
		c.err = err
	}
	return n, err
}

func (c *responseCapture) finish() {
	if !c.eof && !c.truncated && !c.failed {
		var err error
		if c.discard {
			_, err = io.Copy(io.Discard, c)
		} else {
			_, err = io.Copy(io.Discard, io.LimitReader(c, int64(maxBody-len(c.body)+1)))
		}
		if err != nil {
			c.failed = true
		}
	}
}

type transportReader struct {
	io.Reader
	err       error
	remaining int64
}

func (r *transportReader) Read(p []byte) (int, error) {
	within := r.remaining > 0
	if within && int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.Reader.Read(p)
	if within {
		r.remaining -= int64(n)
		if err != nil && err != io.EOF {
			r.err = err
		}
	}
	return n, err
}

type reservationReader struct {
	io.Reader
	reserve  func(int) int
	reserved int
	full     bool
}

func (r *reservationReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 && !r.full {
		want := min(n, maxBody-r.reserved)
		got := max(0, min(want, r.reserve(want)))
		r.reserved += got
		r.full = got < want || r.reserved == maxBody
	}
	return n, err
}

type teeReadCloser struct {
	io.Reader
	io.Closer
}

type Proxy struct {
	target                *url.URL
	cfg                   atomic.Pointer[fault.Config]
	seq                   atomic.Uint64
	requests              atomic.Uint64
	connects              atomic.Int64
	interceptedOK         atomic.Int64
	tlsRejected           atomic.Int64
	passthroughOK         atomic.Int64
	blindOK               atomic.Int64
	connectEgressDenied   atomic.Int64
	innerEgressDenied     atomic.Int64
	replayDenied          int64
	deniedHosts           []string
	dialFailed            atomic.Int64
	reverseDialFailed     atomic.Int64
	innerUsable           atomic.Int64
	interceptedEmpty      atomic.Int64
	bus                   *telemetry.Bus
	transports            [8]*http.Transport
	gate                  sync.Mutex
	admission             sync.Mutex
	resetBarrier          sync.RWMutex
	generation            uint64
	activeWS              int
	activeTunnels         int
	mu                    sync.Mutex
	ctx                   context.Context
	cancel                context.CancelFunc
	pending               int
	active                int
	replayWorkers         sync.WaitGroup
	done                  chan struct{}
	closed                bool
	draining              bool
	options               Options
	cassetteFailure       error
	server                *http.Server
	front                 *front
	stats                 map[string]RuleStats
	applied               map[appliedKey]uint64
	replayCapacitySkips   map[appliedKey]uint64
	replayWarned          map[string]bool
	sseEncodingWarned     map[string]bool
	burstUsed             map[string]int
	sseAdmission          map[string]chan []string
	OnBlindTunnel         func(uint64)
	OnSSE                 func(uint64)
	OnRequest             func(Record)
	ShouldCaptureBody     func(uint64) bool
	ShouldCaptureResponse func(uint64) bool
	OnResponse            func(ResponseRecord)
	ReserveResponseBytes  func(uint64, int) int
	ReserveRequestBytes   func(uint64, int) int
	OnClientFrame         func(uint64, []byte)
	OnServerFrame         func(uint64, string, byte)
	OnUnsupportedFrame    func(uint64)
	OnOutcome             func(Outcome)
}

func ParseTarget(s string) (*url.URL, error) {
	u, err := ParseExplicitTarget(s)
	if err != nil {
		return nil, err
	}
	h := strings.ToLower(u.Hostname())
	if h != "localhost" && (net.ParseIP(h) == nil || !net.ParseIP(h).IsLoopback()) {
		return nil, errors.New("target must be loopback")
	}
	return u, nil
}

func ParseExplicitTarget(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Hostname() == "" || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("target must be an HTTP or HTTPS URL without credentials, query, or fragment")
	}
	if u.Port() != "" {
		p, e := strconv.Atoi(u.Port())
		if e != nil || p < 1 || p > 65535 {
			return nil, errors.New("invalid target port")
		}
	}
	return u, nil
}
func New(target *url.URL, cfg fault.Config, bus *telemetry.Bus) *Proxy {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Proxy{bus: bus, ctx: ctx, cancel: cancel, done: make(chan struct{}), stats: make(map[string]RuleStats)}
	if target != nil {
		u := *target
		p.target = &u
	}
	close(p.done)
	p.SetConfig(cfg)
	return p
}
func cloneConfig(c fault.Config) fault.Config {
	b, _ := json.Marshal(c)
	var out fault.Config
	_ = json.Unmarshal(b, &out)
	return out
}
func (p *Proxy) Config() fault.Config     { return cloneConfig(*p.cfg.Load()) }
func (p *Proxy) SetConfig(c fault.Config) { p.SetConfigAt(c) }
func (p *Proxy) SetConfigAt(c fault.Config) uint64 {
	c = cloneConfig(c)
	p.gate.Lock()
	defer p.gate.Unlock()
	if len(p.burstUsed) != 0 {
		previous := p.cfg.Load()
		for id := range p.burstUsed {
			var unchanged bool
			for _, old := range previous.Rules {
				if old.ID == id {
					for _, rule := range c.Rules {
						if rule.ID == id {
							unchanged = reflect.DeepEqual(old, rule)
							break
						}
					}
					break
				}
			}
			if !unchanged {
				delete(p.burstUsed, id)
			}
		}
	}
	p.cfg.Store(&c)
	return p.seq.Load() + 1
}
func (p *Proxy) Seq() uint64           { return p.seq.Load() }
func (p *Proxy) RequestsTotal() uint64 { return p.requests.Load() }

type TrafficStats struct {
	RequestsTotal     int64 `json:"-"`
	Connects          int64 `json:"connects"`
	InnerRequests     int64 `json:"inner_requests"`
	InnerUsable       int64 `json:"-"`
	InterceptedEmpty  int64 `json:"-"`
	InterceptedOK     int64 `json:"intercepted_ok"`
	TLSRejected       int64 `json:"tls_rejected"`
	PassthroughOK     int64 `json:"passthrough_ok"`
	BlindOK           int64 `json:"blind_ok"`
	EgressDenied      int64 `json:"egress_denied"`
	InnerEgressDenied int64 `json:"-"`
	DialFailed        int64 `json:"dial_failed"`
	ReverseDialFailed int64 `json:"-"`

	ReplayAdmissionDenied int64    `json:"-"`
	EgressDeniedHosts     []string `json:"egress_denied_hosts,omitempty"`
}

func (p *Proxy) TrafficStats() TrafficStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	connects, requests := p.connects.Load(), int64(p.requests.Load())
	innerDenied := p.innerEgressDenied.Load()
	reverseFailed := p.reverseDialFailed.Load()
	return TrafficStats{RequestsTotal: requests, Connects: connects, InnerRequests: requests - connects,
		InterceptedOK: p.interceptedOK.Load(), TLSRejected: p.tlsRejected.Load(),
		InnerUsable: p.innerUsable.Load(), InterceptedEmpty: p.interceptedEmpty.Load(),
		PassthroughOK: p.passthroughOK.Load(), BlindOK: p.blindOK.Load(),
		EgressDenied: p.connectEgressDenied.Load() + innerDenied + p.replayDenied, InnerEgressDenied: innerDenied,
		ReplayAdmissionDenied: p.replayDenied, EgressDeniedHosts: slices.Clone(p.deniedHosts),
		DialFailed: p.dialFailed.Load(), ReverseDialFailed: reverseFailed}
}
func (p *Proxy) SetSeq(n uint64)       { p.gate.Lock(); p.seq.Store(n); p.gate.Unlock() }
func (p *Proxy) ActiveWebSockets() int { p.gate.Lock(); defer p.gate.Unlock(); return p.activeWS }
func (p *Proxy) CaptureBoundary(fn func(uint64, int)) {
	p.admission.Lock()
	defer p.admission.Unlock()
	p.gate.Lock()
	defer p.gate.Unlock()
	fn(p.seq.Load()+1, p.activeWS+p.activeTunnels)
}

// CaptureRecordingBoundary takes the configuration and burst snapshot at one admission boundary.
func (p *Proxy) CaptureRecordingBoundary(fn func(uint64, int, fault.Config, bool)) {
	p.CaptureBoundary(func(next uint64, active int) {
		fn(next, active, p.Config(), len(p.burstUsed) != 0)
	})
}

// SSEAdmissionHeader correlates an internal request with its admission observer.
const SSEAdmissionHeader = "X-Glitchdeck-Sse-Admission"

// WatchSSEAdmission returns the custom terminals of the actual admitted request.
// Send the returned token as SSEAdmissionHeader and unregister after the response.
func (p *Proxy) WatchSSEAdmission() (string, <-chan []string, func()) {
	runID := rand.Text()
	ch := make(chan []string, 1)
	p.gate.Lock()
	if p.sseAdmission == nil {
		p.sseAdmission = make(map[string]chan []string)
	}
	p.sseAdmission[runID] = ch
	p.gate.Unlock()
	return runID, ch, func() {
		p.gate.Lock()
		if p.sseAdmission[runID] == ch {
			delete(p.sseAdmission, runID)
		}
		p.gate.Unlock()
	}
}
func (p *Proxy) Reset() { p.ResetWith(nil) }
func (p *Proxy) ResetWith(fn func()) {
	p.resetBarrier.Lock()
	defer p.resetBarrier.Unlock()
	p.gate.Lock()
	defer p.gate.Unlock()
	p.mu.Lock()
	p.cancel()
	p.generation++
	p.activeWS = 0
	p.activeTunnels = 0
	p.mu.Unlock()
	p.gate.Unlock()
	_ = p.Wait(context.Background())
	p.gate.Lock()
	p.mu.Lock()
	if !p.closed {
		p.ctx, p.cancel = context.WithCancel(context.Background())
	}
	p.seq.Store(0)
	p.requests.Store(0)
	p.connects.Store(0)
	p.interceptedOK.Store(0)
	p.tlsRejected.Store(0)
	p.passthroughOK.Store(0)
	p.blindOK.Store(0)
	p.connectEgressDenied.Store(0)
	p.innerEgressDenied.Store(0)
	p.replayDenied = 0
	p.deniedHosts = nil
	p.dialFailed.Store(0)
	p.reverseDialFailed.Store(0)
	p.innerUsable.Store(0)
	p.interceptedEmpty.Store(0)
	clear(p.stats)
	clear(p.applied)
	clear(p.replayCapacitySkips)
	clear(p.sseEncodingWarned)
	clear(p.replayWarned)
	clear(p.burstUsed)
	p.mu.Unlock()
	if p.options.OnReset != nil {
		p.options.OnReset()
	}
	if fn != nil {
		fn()
	}
}

// Close joins replica workers; synchronous replica callbacks must not call Close.
func (p *Proxy) Close() {
	p.mu.Lock()
	p.closed = true
	p.cancel()
	s := p.server
	transports := p.transports
	p.mu.Unlock()
	closeIdleTransports(transports)
	if s != nil {
		_ = s.Close()
	}
	p.replayWorkers.Wait()
}
func (p *Proxy) beginPendingLocked() {
	if p.active == 0 {
		p.done = make(chan struct{})
	}
	p.active++
}

func (p *Proxy) finishPending() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active--
	if p.active == 0 {
		close(p.done)
	}
}

func (p *Proxy) finishReplay() {
	p.mu.Lock()
	p.pending--
	p.active--
	if p.active == 0 {
		close(p.done)
	}
	p.mu.Unlock()
}

func (p *Proxy) Wait(ctx context.Context) error {
	p.mu.Lock()
	ch := p.done
	p.mu.Unlock()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (p *Proxy) Drain(ctx context.Context) error {
	p.gate.Lock()
	p.mu.Lock()
	p.draining = true
	ch := p.done
	p.mu.Unlock()
	p.gate.Unlock()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type reverseTargetKey struct{}

func (p *Proxy) skipUnsupportedSSE(gen uint64, rule *fault.Rule, encoding string) string {
	reason := "encoding_unsupported:" + encoding
	p.mu.Lock()
	if gen != p.generation {
		p.mu.Unlock()
		return reason
	}
	stats := p.stats[rule.ID]
	// Upstream-controlled encodings cannot grow a rule's stats indefinitely.
	if len(stats.SkipReasons) >= 16 && stats.SkipReasons[reason] == 0 {
		reason = "encoding_unsupported:other"
	}
	stats.skip(reason)
	p.stats[rule.ID] = stats
	first := !p.sseEncodingWarned[rule.ID]
	if first {
		if p.sseEncodingWarned == nil {
			p.sseEncodingWarned = make(map[string]bool)
		}
		p.sseEncodingWarned[rule.ID] = true
	}
	report := first && !p.options.SuppressStderr
	p.mu.Unlock()
	if report {
		fmt.Fprintf(os.Stderr, "rule %s: SSE fault skipped, upstream Content-Encoding %s is not decodable (stdlib supports gzip/deflate)\n", rule.ID, encoding)
	}
	return reason
}

func (p *Proxy) publish(gen uint64, kind string, v any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if gen == p.generation && p.bus != nil {
		p.bus.Publish(kind, v)
	}
}
func (p *Proxy) outcome(gen uint64, o Outcome) {
	p.mu.Lock()
	fn := p.OnOutcome
	valid := gen == p.generation
	p.mu.Unlock()
	if valid && fn != nil {
		fn(o)
	}
}
func (p *Proxy) callback(gen uint64, fn func()) {
	p.mu.Lock()
	valid := gen == p.generation
	p.mu.Unlock()
	if valid {
		fn()
	}
}
func (p *Proxy) upstream(r *http.Request, body []byte, ctx context.Context) *http.Request {
	var u url.URL
	if p.options.CassetteUpstream != nil {
		u = *r.URL
		if !u.IsAbs() {
			u.Scheme, u.Host = "http", r.Host
		}
	} else if r.URL.IsAbs() {
		u = *r.URL
	} else if p.target != nil {
		u = *p.target
		u.Path = strings.TrimRight(u.Path, "/") + r.URL.Path
		u.RawPath = ""
		if p.target.RawPath != "" || r.URL.RawPath != "" {
			u.RawPath = strings.TrimRight(p.target.EscapedPath(), "/") + r.URL.EscapedPath()
		}
		u.RawQuery, u.ForceQuery = r.URL.RawQuery, r.URL.ForceQuery
	} else {
		return nil
	}
	q := r.Clone(ctx)
	q.URL, q.RequestURI, q.Host = &u, "", u.Host
	if p.options.Demo {
		q.Header.Del("Origin")
	}
	trailers := headerToken(q.Header, "TE", "trailers")
	stripHop(q.Header)
	if trailers {
		q.Header.Set("TE", "trailers")
	}
	q.Body, q.ContentLength = http.NoBody, int64(len(body))
	q.TransferEncoding = nil
	if body != nil && len(q.Trailer) != 0 {
		q.ContentLength = -1
	} else {
		q.Trailer = nil
	}
	if len(body) != 0 || len(q.Trailer) != 0 {
		q.Body = io.NopCloser(bytes.NewReader(body))
	}
	return q
}

func normalizeSelfRequest(r *http.Request) bool {
	var host, port string
	switch {
	case r.Method == http.MethodConnect:
		var err error
		host, port, err = net.SplitHostPort(r.Host)
		if err != nil {
			return false
		}
	case (r.URL.Scheme == "http" || r.URL.Scheme == "https") && r.URL.User == nil:
		host, port = r.URL.Hostname(), upstreamPort(r.URL.Scheme, r.URL.Port())
	default:
		return false
	}
	if !listenerAuthority(r.Context(), host, port) {
		return false
	}
	*r.URL = url.URL{Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery, ForceQuery: r.URL.ForceQuery}
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}
	r.RequestURI = r.URL.RequestURI()
	return true
}

type probeKey struct{}

// ServeProbeHTTP serves a trusted in-process assertion after Drain.
func (p *Proxy) ServeProbeHTTP(w http.ResponseWriter, r *http.Request) {
	p.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), probeKey{}, true)))
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.resetBarrier.RLock()
	p.mu.Lock()
	if p.closed || p.draining && r.Context().Value(probeKey{}) != true {
		p.mu.Unlock()
		p.resetBarrier.RUnlock()
		http.Error(w, "proxy closed", http.StatusServiceUnavailable)
		return
	}
	p.beginPendingLocked()
	p.mu.Unlock()
	p.resetBarrier.RUnlock()
	defer p.finishPending()
	if !prepareProtocolRequest(r) {
		if r.Method == http.MethodConnect && p.options.CassetteUpstream != nil {
			p.failCassette("cassette_miss", r.Method, r.URL.Path)
		}
		http.Error(w, "request does not match CONNECT authority", http.StatusMisdirectedRequest)
		return
	}
	self := normalizeSelfRequest(r)
	tunnel := r.Method == http.MethodConnect && !self
	if !p.authorize(w, r, tunnel || r.URL.IsAbs()) {
		return
	}
	if seen := MetaFrom(r.Context()).innerSeen; seen != nil {
		seen.Store(true)
	}
	p.mu.Lock()
	p.requests.Add(1)
	if tunnel {
		p.connects.Add(1)
	}
	p.mu.Unlock()
	if tunnel {
		p.connect(w, r)
		return
	}
	if p.options.RewriteRequest != nil {
		p.options.RewriteRequest(r)
	}
	start := time.Now()
	scheme, host := r.URL.Scheme, r.URL.Host
	if r.URL.IsAbs() {
		if r.URL.User != nil || (scheme != "http" && scheme != "https") || !p.allowed(r.URL.Hostname(), upstreamPort(scheme, r.URL.Port())) {
			deniedHost := p.noteEgressDenial(r.URL.Host, false)
			http.Error(w, "egress denied", http.StatusForbidden)
			if seq, gen := p.tunnelSequence(); seq != 0 {
				p.publishDeniedRequest(gen, seq, 403, deniedHost, nil, 0, 0)
			}
			return
		}
	} else if p.target != nil {
		if p.options.RequireUpstreamAllow && !p.allowed(p.target.Hostname(), upstreamPort(p.target.Scheme, p.target.Port())) {
			p.noteEgressDenial(p.target.Host, false)
			http.Error(w, "egress denied", http.StatusForbidden)
			return
		}
		scheme, host = p.target.Scheme, p.target.Host
	} else {
		scheme, host = "http", r.Host
	}
	p.admission.Lock()
	p.gate.Lock()
	p.mu.Lock()
	session, gen, closed := p.ctx, p.generation, p.closed || p.draining && r.Context().Value(probeKey{}) != true
	p.mu.Unlock()
	if closed || session.Err() != nil {
		p.gate.Unlock()
		p.admission.Unlock()
		http.Error(w, "proxy closed", 503)
		return
	}
	seq := p.seq.Add(1)
	p.gate.Unlock()
	ws := r.Method == http.MethodGet && strings.EqualFold(r.Header.Get("Upgrade"), "websocket") && headerToken(r.Header, "Connection", "upgrade")
	captureResponse := !ws && r.ProtoMajor != 2 && p.OnResponse != nil && p.ShouldCaptureResponse != nil && p.ShouldCaptureResponse(seq)
	responseRecord := ResponseRecord{Seq: seq}
	responseAsync := false
	if captureResponse || !ws && r.ProtoMajor == 2 && p.OnResponse != nil {
		defer func() {
			if !responseAsync && (captureResponse || responseRecord.Intentional) {
				p.OnResponse(responseRecord)
			}
		}()
	}
	if p.options.BeforeRequest != nil {
		p.options.BeforeRequest(seq)
	}
	proto, recordProto := "h1", ""
	if r.ProtoMajor == 2 {
		proto, recordProto = "h2", "h2c"
		if r.TLS != nil {
			recordProto = "h2"
		}
	}
	ctype := r.Header.Get("Content-Type")
	match := fault.Query{Method: r.Method, Path: r.URL.Path, Host: host, Scheme: scheme, Proto: proto, ContentType: ctype, Seq: seq, WS: ws}
	p.gate.Lock()
	if gen != p.generation {
		p.gate.Unlock()
		p.admission.Unlock()
		http.Error(w, "proxy closed", http.StatusServiceUnavailable)
		return
	}
	cfg := *p.cfg.Load()
	rule := fault.MatchRequest(cfg, match)
	var kind, action, skip, h2Error string
	var params map[string]any
	if rule != nil {
		kind, params = rule.Fault.Type, rule.Fault.Params
		if !ws && kind == "rate-limit" {
			if burst := fault.Int(params, "burst", 0); burst > 0 {
				if p.burstUsed[rule.ID] >= burst {
					skip = "burst_exhausted"
				} else {
					if p.burstUsed == nil {
						p.burstUsed = make(map[string]int)
					}
					p.burstUsed[rule.ID]++
				}
			}
		}
	}
	if runID := r.Header.Get(SSEAdmissionHeader); runID != "" {
		r.Header.Del(SSEAdmissionHeader)
		if ch := p.sseAdmission[runID]; ch != nil {
			delete(p.sseAdmission, runID)
			var extra []string
			if kind == "sse-glitch" {
				extra = fault.Strings(params, "done_events")
			}
			ch <- extra
		}
	}
	if ws {
		p.activeWS++
	}
	p.gate.Unlock()
	if p.options.OnAdmission != nil {
		p.options.OnAdmission(seq, r.Method, r.URL.RequestURI(), host)
	}
	p.admission.Unlock()
	if rule != nil && !ws {
		p.countRule(gen, rule, "matched", "")
		if skip != "" {
			p.countRule(gen, rule, "skipped", skip)
		}
	}
	if ws {
		defer func() {
			p.gate.Lock()
			p.mu.Lock()
			if gen == p.generation {
				p.activeWS--
			}
			p.mu.Unlock()
			p.gate.Unlock()
		}()
	}
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(session, cancel)
	defer stop()
	defer cancel()
	incoming := r
	r = r.WithContext(ctx)
	usable := false
	markUsable := func() {
		if !usable {
			p.innerUsable.Add(1)
			usable = true
		}
	}
	meta := MetaFrom(ctx)
	streamID := streamFrom(ctx)
	isGRPC := r.ProtoMajor == 2 && fault.NativeGRPC(ctype)
	applied := false
	ruleID := ""
	if rule != nil {
		ruleID = rule.ID
	}
	markApplied := func() {
		if kind != "dup-webhook" {
			markUsable()
		}
		applied = true
		p.countRule(gen, rule, "applied", "")
	}
	status, n, end := 0, int64(0), "complete"
	var dialDenied bool
	var deniedHost string
	runID := r.Header.Get("X-Glitchdeck-Run")
	var body []byte
	var streamedBytes atomic.Int64
	var previewMu sync.Mutex
	var preview []byte
	var upstreamHeaders http.Header
	var grpcStatus *int
	grpcSource, grpcMessage := "proxy", ""
	var grpcIn, grpcOut grpcwire.MsgCounter
	var isSSE bool
	sseEvents := 0
	if !ws {
		defer func() {
			if dialDenied {
				if isGRPC {
					p.publishDeniedGRPC(gen, seq, status, grpcStatus, deniedHost, grpcIn.Count(), grpcOut.Count())
				}
				p.publishDeniedRequest(gen, seq, status, deniedHost, nil, streamedBytes.Load(), n)
				return
			}
			previewMu.Lock()
			snippet := string(preview)
			previewMu.Unlock()
			if isGRPC {
				p.grpcEvent(gen, seq, r, status, grpcStatus, grpcSource, grpcMessage, kind, action, h2Error, ruleID, applied, grpcIn.Count(), grpcOut.Count(), start)
			}
			var tunnel string
			if meta.MITM {
				tunnel = "mitm"
			}
			protocol := ""
			if proto == "h2" && !isGRPC {
				protocol = "h2"
			}
			p.publish(gen, "http_req", map[string]any{
				"seq": seq, "ts_ms": start.UnixMilli(), "method": r.Method, "path": r.URL.RequestURI(),
				"status": status, "latency_ms": time.Since(start).Milliseconds(), "req_bytes": streamedBytes.Load(), "resp_bytes": n,
				"fault": kind, "replay_index": 0, "request_headers": inspectorHeaders(r.Header),
				"applied": applied, "rule_id": ruleID,
				"response_headers": inspectorHeaders(upstreamHeaders), "body_snippet": snippet,
				"proto": r.Proto, "protocol": protocol, "scheme": scheme, "host": host, "stream_id": streamID, "sse": isSSE,
				"sse_events": sseEvents, "grpc_status": grpcStatus, "fault_action": action, "fault_skipped": skip, "end": end, "run_id": runID, "tunnel": tunnel,
			})
		}()
	}
	if runID != "" {
		w.Header().Set("X-Glitchdeck-Seq", strconv.FormatUint(seq, 10))
	}
	var capturing bool
	hasTrailers := len(r.Trailer) > 0
	var preReserved int
	record := func(captured []byte, missing, truncated bool) {
		if p.OnRequest == nil {
			return
		}
		if capturing && kind == "dup-webhook" && fault.Int(params, "count", 2) > 1 && p.ReserveRequestBytes != nil && len(captured) > preReserved {
			captured, truncated = captured[:preReserved], true
		}
		headers := r.Header.Clone()
		stripHop(headers)
		rec := Record{Seq: seq, Method: r.Method, Path: r.URL.RequestURI(), Header: headers, Body: captured,
			WebSocket: ws, SSE: isSSE, At: start, Proto: recordProto, UnrecordableBody: missing, BodyTruncated: truncated,
			BodyCaptureStarted: capturing, MITM: meta.MITM, HasTrailers: hasTrailers, AssertionProbe: r.Context().Value(probeKey{}) == true}
		if r.URL.IsAbs() {
			rec.URL = r.URL.String()
		} else if meta.MITM {
			rec.URL = scheme + "://" + host + r.URL.RequestURI()
		}
		if capturing {
			p.OnRequest(rec)
		} else {
			p.callback(gen, func() { p.OnRequest(rec) })
		}
	}
	var plan h2tap.Plan
	flushPlanned := false
	cutsStream := false
	if !ws && r.ProtoMajor == 2 && (kind == "h2-glitch" || kind == "tcp-rst") {
		if kind == "h2-glitch" {
			plan, action, end = h2Plan(params, streamID)
		} else {
			plan = h2tap.Plan{Kind: "rst", Code: 2, BeforeHdrs: fault.Bool(params, "before_headers", false), AfterBytes: int64(fault.Int(params, "after_bytes", 0))}
			action, end = "rst_stream", "h2_rst"
		}
		h2Error = h2Names[plan.Code]
		if meta.Tap == nil || streamID == 0 {
			record(nil, r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0, false)
			h2Error, end, skip = "INTERNAL_ERROR", "h2_rst", "untapped"
			p.countRule(gen, rule, "skipped", skip)
			panic(http.ErrAbortHandler)
		}
		cutsStream = plan.Kind == "rst"
		plan.Applied = new(atomic.Bool)
		p.mu.Lock()
		p.beginPendingLocked()
		p.mu.Unlock()
		defer p.finishPending()
		planDone := meta.Tap.ArmContext(ctx, streamID, plan)
		defer func() {
			if !plan.BeforeHdrs && plan.AfterBytes == 0 && status != 0 {
				flushPlanned = true
				_ = http.NewResponseController(w).Flush()
			}
			if flushPlanned && (plan.BeforeHdrs || n >= plan.AfterBytes) {
				// HTTP/2 Flush can return before the buffered frame reaches the tap.
				select {
				case <-planDone:
				case <-meta.Tap.Done():
				case <-ctx.Done():
				}
			}
			if plan.Applied.Load() {
				if plan.BeforeHdrs {
					responseRecord.Intentional = true
				}
				markApplied()
				p.outcome(gen, Outcome{Seq: seq, H2Fault: true})
				if cutsStream {
					n = min(n, plan.AfterBytes)
					grpcStatus, grpcSource, grpcMessage = nil, "proxy", ""
				}
			} else {
				h2Error, skip = "", "not_triggered"
				if end == "h2_rst" || end == "h2_goaway" {
					end = "complete"
				}
				p.countRule(gen, rule, "skipped", skip)
			}
		}()
		if plan.BeforeHdrs {
			record(nil, r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0, false)
			flushPlanned = true
			_ = http.NewResponseController(w).Flush()
			return
		}
	}
	if !ws && kind == "tcp-rst" && fault.Bool(params, "before_headers", false) {
		record(nil, r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0, false)
		resetWriter(w, func() {
			responseRecord.Intentional = true
			end = "rst"
			markApplied()
			p.outcome(gen, Outcome{Seq: seq, Reset: true})
		})
		return
	}
	grpcAfter := fault.Int(params, "after_messages", 0)
	injectGRPC := func(code int, message, source string) {
		status, grpcStatus, grpcSource, grpcMessage = 200, &code, source, message
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Grpc-Status", strconv.Itoa(code))
		w.Header().Set("Grpc-Message", grpcwire.EncodeMessage(message))
		w.WriteHeader(status)
	}
	if kind == "grpc-glitch" {
		action = "status"
		if !wait(ctx, time.Duration(fault.Int(params, "delay_ms", 0))*time.Millisecond) {
			end = "client_cancel"
			return
		}
		if grpcAfter == 0 {
			record(nil, r.ContentLength != 0, false)
			code, _ := fault.GRPCCode(params["code"])
			if _, ok := params["code"]; !ok {
				code = 14
			}
			injectGRPC(code, fault.String(params, "message", ""), "injected")
			responseRecord.Intentional = true
			markApplied()
			return
		}
	}
	hasBody := r.Body != nil && r.Body != http.NoBody
	capture := hasBody && p.OnRequest != nil && (p.ShouldCaptureBody == nil || p.ShouldCaptureBody(seq))
	capturing = capture && p.ShouldCaptureBody != nil
	buffered := kind == "dup-webhook" && fault.Int(params, "count", 2) > 1

	if buffered && hasBody {
		var err error
		var reader io.Reader = io.LimitReader(r.Body, maxBody+1)
		var reservation *reservationReader
		if capturing && p.ReserveRequestBytes != nil {
			reservation = &reservationReader{Reader: reader, reserve: func(n int) int { return p.ReserveRequestBytes(seq, n) }}
			reader = reservation
		}
		body, err = io.ReadAll(reader)
		if reservation != nil {
			preReserved = reservation.reserved
		}
		r.Trailer = incoming.Trailer
		hasTrailers = hasTrailers || len(r.Trailer) != 0
		streamedBytes.Add(int64(len(body)))
		preview = body[:min(len(body), 256)]
		if err != nil || len(body) > maxBody {
			if capturing {
				record(body[:min(len(body), maxBody)], err != nil, len(body) > maxBody)
			}
			body = nil
			status = http.StatusRequestEntityTooLarge
			message := "webhook replay body exceeds replay cap or is unreadable"
			p.outcome(gen, Outcome{Seq: seq, Err: errors.New(message)})
			http.Error(w, message, status)
			return
		}
		if isGRPC {
			_, _ = grpcIn.Write(body)
		}
	}
	if buffered || ws {
		record(body, !buffered && hasBody, false)
	}
	if ws {
		if p.options.CassetteUpstream != nil {
			p.failCassette("cassette_miss", r.Method, r.URL.Path)
			http.Error(w, "cassette unavailable", http.StatusBadGateway)
			return
		}
		p.serveWS(w, r, gen, match)
		return
	}
	if kind == "rate-limit" && skip == "" {
		var recorded []byte
		missing, truncated := hasBody, false
		if capture && !isGRPC {
			b := &countingBody{ReadCloser: r.Body, incoming: incoming, count: &streamedBytes, capture: true, previewMu: &previewMu, preview: &preview}
			if capturing && p.ReserveRequestBytes != nil {
				b.reserve = func(n int) int { return p.ReserveRequestBytes(seq, n) }
			}
			_, readErr := io.Copy(io.Discard, io.LimitReader(b, maxBody+1))
			recorded, missing, truncated = b.body, readErr != nil, b.truncated
			hasTrailers = hasTrailers || len(incoming.Trailer) != 0
		}
		record(recorded, missing, truncated)
		responseRecord.Intentional = true
		status = fault.Int(params, "status", 429)
		responseBody := rateLimitResponse(w.Header(), params, status, seq, time.Now())
		upstreamHeaders = w.Header()
		w.WriteHeader(status)
		count, _ := io.WriteString(w, responseBody)
		n = int64(count)
		markApplied()
		return
	}
	if !buffered && !hasBody {
		record(nil, false, false)
	}
	if kind == "latency-wave" && !wait(ctx, time.Duration(fault.Latency(cfg.Seed, seq, params))*time.Millisecond) {
		if capturing {
			record(nil, true, false)
		}
		end = "client_cancel"
		panic(http.ErrAbortHandler)
	}
	reverse := !r.URL.IsAbs() && !meta.MITM && p.target != nil
	if reverse {
		ctx = context.WithValue(ctx, reverseTargetKey{}, true)
	}
	if buffered {
		origin := &replayDialOrigin{client: incoming.Context(), reverse: reverse}
		r = r.WithContext(context.WithValue(r.Context(), replayDialOriginKey{}, origin))
		defer func() {
			if origin.client.Err() == nil {
				origin.completed.Store(true)
			}
		}()
	}
	mode := fault.String(params, "mode", "sequential")
	var releaseTimeout func(bool, string, int)
	if kind == "dup-webhook" && buffered && mode == "timeout_retry" {
		releaseTimeout = p.timeoutReplays(r, body, seq, gen, rule, params)
		if releaseTimeout != nil {
			defer releaseTimeout(false, "", 0)
			detached, stopDetached := context.WithTimeout(context.WithoutCancel(ctx), time.Duration(fault.Int(params, "replay_timeout_ms", 5000))*time.Millisecond)
			defer stopDetached()
			stopSession := context.AfterFunc(session, stopDetached)
			defer stopSession()
			ctx = detached
		}
	}
	var cancelLookahead context.CancelFunc
	var captureCancel context.CancelFunc
	var stopCaptureSession func() bool
	var stopCaptureClient func() bool
	upstreamContext := ctx
	lookahead := &sseLookahead{}
	if captureResponse && kind == "sse-glitch" {
		var detached context.Context
		detached, captureCancel = context.WithCancel(context.WithoutCancel(ctx))
		stopCaptureSession = context.AfterFunc(session, captureCancel)
		stopCaptureClient = context.AfterFunc(ctx, captureCancel)
		upstreamContext = detached
		defer func() {
			if !responseAsync {
				stopCaptureClient()
				stopCaptureSession()
				captureCancel()
			}
		}()
	}
	q := p.upstream(r, body, upstreamContext)
	if q != nil && kind == "dup-webhook" && fault.Bool(params, "replay_header", false) {
		q.Header.Del("X-Glitchdeck-Replay")
	}
	if q == nil {
		if !buffered && hasBody {
			record(nil, hasBody, false)
		}
		status, end = 502, "upstream_error"
		http.Error(w, "no upstream target", status)
		return
	}
	if kind == "sse-glitch" {
		q.Header.Del("Accept-Encoding")
		if fault.String(params, "action", "") == "inject_error" && fault.String(params, "provider", "auto") == "auto" {
			upstreamCtx, cancelUpstream := context.WithCancel(q.Context())
			cancelLookahead = cancelUpstream
			defer func() {
				if !responseAsync {
					cancelUpstream()
				}
			}()
			q = q.WithContext(upstreamCtx)
			if captureResponse {
				ctx = context.WithValue(ctx, sseLookaheadKey{}, lookahead)
			}
			ctx = context.WithValue(ctx, sseUpstreamCancelKey{}, cancelUpstream)
		}
	}
	var finishRecord func(bool)
	var recordMu sync.Mutex
	recorded, classified, sseNotified := buffered || !hasBody, false, false
	notifySSE := func() {
		if recorded && classified && isSSE && !sseNotified && p.OnSSE != nil {
			sseNotified = true
			p.callback(gen, func() { p.OnSSE(seq) })
		}
	}
	if !buffered && hasBody {
		b := &countingBody{ReadCloser: r.Body, incoming: incoming, count: &streamedBytes, capture: capture, previewMu: &previewMu, preview: &preview}
		if p.ReserveRequestBytes != nil {
			b.reserve = func(n int) int { return p.ReserveRequestBytes(seq, n) }
		}
		if isGRPC {
			b.grpc = &grpcIn
		}
		finishRecord = func(force bool) {
			recordMu.Lock()
			defer recordMu.Unlock()
			if recorded {
				return
			}
			b.mu.Lock()
			missing := !capture || b.failed || !b.eof && (r.ContentLength < 0 || b.count.Load() < r.ContentLength)
			if missing && capture && !force {
				b.mu.Unlock()
				return
			}
			captured, truncated := b.body, b.truncated
			b.body = nil
			hasTrailers = hasTrailers || b.hasTrailers
			b.capture = false
			b.mu.Unlock()
			record(captured, missing, truncated)
			recorded = true
			notifySSE()
		}
		b.done = func() { finishRecord(true) }
		q.Body, q.ContentLength, q.Trailer = b, r.ContentLength, r.Trailer
		defer finishRecord(true)
	}
	if !buffered && hasBody && r.ProtoMajor == 1 {
		_ = http.NewResponseController(w).EnableFullDuplex()
	}
	var transport *http.Transport
	if p.options.CassetteUpstream == nil {
		transport = p.transportFor(ctx, r.ProtoMajor == 2 && q.URL.Scheme == "http")
	}
	var releaseReplay func(bool)
	var replayClock *replayTiming
	if kind == "dup-webhook" && buffered && mode == "concurrent" {
		releaseReplay, replayClock = p.concurrentReplays(r, body, seq, gen, rule, params)
		if releaseReplay != nil {
			defer releaseReplay(false)
		}
	}
	if meta.Tap != nil && streamID != 0 && !meta.Tap.AdmitUpstream(streamID) {
		meta.Tap.Reset(streamID, 7)
		panic(http.ErrAbortHandler)
	}
	if releaseReplay != nil {
		// A concurrent group is counted by the first copy that clears egress.
		replayClock.start()
		releaseReplay(true)
	}
	var resp *http.Response
	var err error
	if p.options.CassetteUpstream != nil {
		resp, err = p.cassetteResponse(q)
		if err != nil {
			status, end = http.StatusBadGateway, "upstream_error"
			http.Error(w, err.Error(), status)
			return
		}
	} else {
		resp, err = transport.RoundTrip(q)
		p.noteRoundTripDial(incoming.Context(), gen, q.URL.Host, reverse, err)
	}
	if errors.Is(err, errEgressDenied) {
		dialDenied, deniedHost = true, p.deniedHost(q.URL.Host)
	}
	if releaseTimeout != nil {
		originalOutcome := ""
		committedStatus := 0
		if err != nil {
			originalOutcome = replayError(err)
		} else {
			committedStatus = resp.StatusCode
			var drainErr error
			if captureResponse {
				responseRecord.Status = resp.StatusCode
				responseRecord.Header = resp.Header.Clone()
				stripHop(responseRecord.Header)
				encoding := strings.ToLower(strings.TrimSpace(strings.Join(resp.Header.Values("Content-Encoding"), ", ")))
				if resp.StatusCode == http.StatusPartialContent && encoding != "" && encoding != "identity" {
					responseRecord.Truncated = true
				}
				responseRecord.Header.Del("Content-Length")
				if r.Method == http.MethodHead || resp.StatusCode == http.StatusNotModified || resp.StatusCode == http.StatusNoContent || resp.StatusCode < 200 {
					responseRecord.Header.Del("Content-Encoding")
					_, drainErr = io.Copy(io.Discard, resp.Body)
				} else if encoding != "" && encoding != "identity" && encoding != "gzip" && encoding != "x-gzip" && encoding != "deflate" {
					responseRecord.Truncated = true
					_, drainErr = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
				} else {
					responseRecord.Header.Del("Content-Encoding")
					raw := &transportReader{Reader: resp.Body, remaining: maxBody}
					var source io.ReadCloser = io.NopCloser(raw)
					if encoding != "" && encoding != "identity" {
						stripSSEIntegrity(responseRecord.Header)
						source = &sseDecoder{source: source, encoding: encoding}
					}
					capture := &responseCapture{ReadCloser: source}
					if p.ReserveResponseBytes != nil {
						capture.reserve = func(n int) int { return p.ReserveResponseBytes(seq, n) }
					}
					capture.finish()
					_, _ = io.Copy(io.Discard, io.LimitReader(raw, raw.remaining))
					drainErr = raw.err
					_ = source.Close()
					responseRecord.Body = capture.body
					responseRecord.Truncated = responseRecord.Truncated || capture.truncated || capture.failed
					if capture.failed {
						responseRecord.Status = 0
					}
				}
				responseRecord.Truncated = responseRecord.Truncated || len(resp.Trailer) != 0
			} else {
				_, drainErr = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
			}
			if drainErr != nil {
				originalOutcome = replayError(drainErr)
			}
			_ = resp.Body.Close()
			markUsable()
		}
		if originalOutcome != "" && originalOutcome != "timeout" {
			originalOutcome = "transport_error"
		}
		if !p.recordOriginal(gen, rule, mode, committedStatus, originalOutcome) {
			end = "client_cancel"
			return
		}
		defer releaseTimeout(true, originalOutcome, committedStatus)
		applied = true
		if fault.String(params, "client_result", "gateway_timeout") == "reset" {
			end = "rst"
			if r.ProtoMajor == 2 {
				p.outcome(gen, Outcome{Seq: seq, Reset: true})
				if meta.Tap != nil && streamID != 0 {
					meta.Tap.Reset(streamID, 2)
				}
				panic(http.ErrAbortHandler)
			}
			resetWriter(w, func() { p.outcome(gen, Outcome{Seq: seq, Reset: true}) })
			return
		}
		status = http.StatusGatewayTimeout
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		const timeoutBody = "glitchdeck: simulated sender timeout after upstream commit"
		w.Header().Set("Content-Length", strconv.Itoa(len(timeoutBody)))
		w.WriteHeader(status)
		count, _ := io.WriteString(w, timeoutBody)
		n = int64(count)
		_ = http.NewResponseController(w).Flush()
		return
	}
	if err != nil {
		p.outcome(gen, Outcome{Seq: seq, Err: err})
		status, end = 502, "upstream_error"
		if isGRPC && r.ProtoMajor == 2 {
			injectGRPC(14, "upstream unavailable", "proxy")
			return
		}
		w.Header().Set(TransportErrorHeader, "1")
		http.Error(w, "upstream unavailable", status)
		return
	}
	originalBody := resp.Body
	var decoder *sseDecoder
	defer func() {
		if !responseAsync {
			if decoder != nil {
				_ = decoder.Close()
			}
			_ = originalBody.Close()
		}
	}()
	if isGRPC && resp.ProtoMajor != 2 {
		injectGRPC(14, "upstream is not HTTP/2", "proxy")
		return
	}
	markUsable()
	resp.Header.Del(TransportErrorHeader)
	if p.options.CassetteUpstream != nil && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		filterReplayLocation(r, resp.Header)
	}
	status, upstreamHeaders = resp.StatusCode, resp.Header
	media, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	encoding := strings.ToLower(strings.TrimSpace(strings.Join(resp.Header.Values("Content-Encoding"), ", ")))
	if len(encoding) > 128 {
		encoding = "other"
	}
	recordMu.Lock()
	isSSE = media == "text/event-stream"
	classified = true
	notifySSE()
	recordMu.Unlock()
	if finishRecord != nil {
		finishRecord(false)
	}
	bodyless := r.Method == http.MethodHead || resp.StatusCode == http.StatusNotModified || resp.StatusCode == http.StatusNoContent || resp.StatusCode < 200
	decodedResponse := false
	if _, ok := resp.Body.(*sseDecoder); ok {
		decodedResponse = true
	}
	if captureResponse {
		responseRecord.Status = resp.StatusCode
		responseRecord.Header = resp.Header.Clone()
		stripHop(responseRecord.Header)
		if resp.StatusCode == http.StatusPartialContent && encoding != "" && encoding != "identity" {
			responseRecord.Truncated = true
		}
		if len(resp.Trailer) != 0 {
			responseRecord.Truncated = true
		}
		if !bodyless && encoding != "" && encoding != "identity" && encoding != "gzip" && encoding != "x-gzip" && encoding != "deflate" {
			responseRecord.Header.Del("Content-Length")
			responseRecord.Truncated = true
		} else if !bodyless {
			capture := &responseCapture{ReadCloser: resp.Body}
			var decoded *responseCapture
			var encodedWriter *io.PipeWriter
			var decodedDone chan struct{}
			reserve := func(n int) int {
				if p.ReserveResponseBytes != nil {
					return p.ReserveResponseBytes(seq, n)
				}
				return n
			}
			if encoding == "gzip" || encoding == "x-gzip" || encoding == "deflate" {
				reader, writer := io.Pipe()
				encodedWriter = writer
				decoded = &responseCapture{ReadCloser: &sseDecoder{source: reader, encoding: encoding}, reserve: reserve}
				decodedDone = make(chan struct{})
				go func() {
					decoded.finish()
					_, _ = io.Copy(io.Discard, reader)
					_ = decoded.Close()
					close(decodedDone)
				}()
				capture.ReadCloser = teeReadCloser{Reader: io.TeeReader(resp.Body, writer), Closer: resp.Body}
				capture.discard = true
			} else {
				capture.reserve = reserve
			}
			resp.Body = capture
			finishCapture := func() {
				cancelDrain := cancel
				if captureCancel != nil {
					cancelDrain = captureCancel
				}
				drainTimeout := 2 * time.Second
				if lookahead.wait != nil {
					drainTimeout = 500 * time.Millisecond
				}
				timer := time.AfterFunc(drainTimeout, cancelDrain)
				defer timer.Stop()
				if lookahead.wait != nil {
					lookahead.wait()
				}
				if responseAsync && decoder != nil {
					_ = decoder.Close()
				}
				capture.finish()
				responseRecord.Body = capture.body
				responseRecord.Truncated = responseRecord.Truncated || capture.truncated || capture.failed || len(resp.Trailer) != 0
				if capture.failed {
					responseRecord.Status = 0
				}
				if encoding == "gzip" || encoding == "x-gzip" || encoding == "deflate" {
					responseRecord.Header.Del("Content-Encoding")
					responseRecord.Header.Del("Content-Length")
					stripSSEIntegrity(responseRecord.Header)
					_ = encodedWriter.Close()
					<-decodedDone
					responseRecord.Body = decoded.body
					responseRecord.Truncated = responseRecord.Truncated || decoded.truncated || decoded.failed
					if decoded.failed {
						responseRecord.Status = 0
					}
				}
			}
			defer func() {
				if captureCancel != nil && (lookahead.wait != nil || !capture.eof && !capture.truncated && !capture.failed) {
					responseAsync = true
					stopCaptureClient()
					p.mu.Lock()
					p.beginPendingLocked()
					p.mu.Unlock()
					go func() {
						defer p.finishPending()
						defer stopCaptureSession()
						defer captureCancel()
						if cancelLookahead != nil {
							defer cancelLookahead()
						}
						defer capture.Close()
						finishCapture()
						p.OnResponse(responseRecord)
					}()
				} else {
					finishCapture()
				}
			}()
		}
	}
	switch kind {
	case "dup-webhook":
		if buffered && mode == "sequential" && p.sequentialReplays(r, body, seq, gen, rule, params) {
			markApplied()
		}
	case "tcp-rst":
		if r.ProtoMajor != 2 {
			n = resetResponse(w, resp, r.Method, fault.Int(params, "after_bytes", 0), cancel, func(err error) {
				if err == nil {
					end = "rst"
					markApplied()
				}
				p.outcome(gen, Outcome{Seq: seq, Reset: err == nil, Err: err})
			})
			return
		}
	case "byte-trickle", "latency-wave":
		markApplied()
	case "sse-glitch":
		action = fault.String(params, "action", "stall")
		if action == "early_eof" {
			action = "eof_early"
		}
		if !isSSE {
			skip = "not_sse"
			p.countRule(gen, rule, "skipped", skip)
		} else if encoding != "" && encoding != "identity" && !decodedResponse {
			switch encoding {
			case "gzip", "x-gzip", "deflate":
				// Keep upstream flushes visible to clients; io.ReadAll would buffer the stream.
				decoder = &sseDecoder{source: resp.Body, encoding: encoding}
				resp.Body = decoder
				decodedResponse = true
				resp.Header.Del("Content-Encoding")
				resp.Header.Del("Content-Length")
				stripSSEIntegrity(resp.Header)
				stripSSEIntegrity(resp.Trailer)
				decoded := encoding
				if decoded == "x-gzip" {
					decoded = "gzip"
				}
				resp.Header.Set("X-Glitchdeck-Decoded", decoded)
			default:
				skip = p.skipUnsupportedSSE(gen, rule, encoding)
				rule = nil
			}
		}
	}
	if isSSE && r.ProtoMajor == 1 && sseNeedsHijack(rule) {
		result := p.relayHijackedSSE(ctx, w, resp, rule, cfg.Seed, seq, gen, start, runID, encoding)
		n, sseEvents, end, skip = result.bytes, result.events, requestSSEEnd(result.end), result.skip
		applied = applied || result.applied
		if result.err != nil && result.end != "client_cancel" {
			p.outcome(gen, Outcome{Seq: seq, Err: result.err})
		}
		return
	}
	streaming := resp.ContentLength < 0 || isSSE || plan.Applied != nil || isGRPC
	stripHop(resp.Header)
	if isSSE && rule != nil && kind == "sse-glitch" || kind == "grpc-glitch" {
		resp.Header.Del("Content-Length")
	}
	copyHeaders(w.Header(), resp.Header)
	if isGRPC && resp.Header.Get("Grpc-Status") != "" && len(resp.Trailer) == 0 {
		grpcSource = "upstream"
		if g, err := strconv.Atoi(resp.Header.Get("Grpc-Status")); err == nil {
			grpcStatus = &g
		}
		grpcMessage = grpcwire.DecodeMessage(resp.Header.Get("Grpc-Message"))
		w.WriteHeader(status)
		return
	}
	for k := range resp.Trailer {
		w.Header().Add("Trailer", k)
	}
	w.WriteHeader(status)
	rc := http.NewResponseController(w)
	if streaming {
		flushPlanned = plan.Applied != nil
		_ = rc.Flush()
	}
	if cutsStream && plan.Applied != nil && plan.Applied.Load() {
		return
	}
	if isSSE && kind != "byte-trickle" && plan.Applied == nil {
		result := p.relaySSE(ctx, w, resp.Body, rule, cfg.Seed, seq, gen, start, runID, encoding)
		n, sseEvents, end = result.bytes, result.events, requestSSEEnd(result.end)
		if result.skip != "" {
			skip = result.skip
		}
		applied = applied || result.applied
		if r.ProtoMajor == 2 && (result.end == "rst" || result.end == "eof_early" && !fault.Bool(params, "http_clean", true)) {
			code := uint32(0)
			if result.end == "rst" {
				code = 2
				if !fault.Bool(params, "rst", true) {
					code = 8
				}
			}
			if !resetProtocolStreamAfterData(ctx, code, result.bytes) {
				panic(http.ErrAbortHandler)
			}
		}
		if result.err != nil && result.end != "client_cancel" {
			p.outcome(gen, Outcome{Seq: seq, Err: result.err})
			if result.end == "upstream_error" {
				if !decodedResponse {
					panic(http.ErrAbortHandler)
				}
				if r.ProtoMajor == 2 {
					if !resetProtocolStreamAfterData(ctx, 2, result.bytes) {
						_ = rc.SetWriteDeadline(time.Now())
					}
				} else if conn, _, err := rc.Hijack(); err == nil {
					// Close without writing the final chunk: decoding failed, not clean EOF.
					_ = conn.Close()
				}
			}
		}
		if lookahead.wait == nil && result.err == nil && (result.end == "eof" || result.end == "done") {
			if decodedResponse {
				stripSSEIntegrity(resp.Trailer)
			}
			for k, v := range resp.Trailer {
				w.Header()[http.TrailerPrefix+k] = v
			}
		}
		return
	}
	var responseBody io.Reader = resp.Body
	if isGRPC {
		var count io.Writer = &grpcOut
		if cutsStream && plan.Applied != nil {
			count = &limitedGRPCCount{counter: &grpcOut, left: plan.AfterBytes}
		}
		responseBody = io.TeeReader(responseBody, count)
	}
	if kind == "grpc-glitch" && grpcAfter > 0 {
		code, _ := fault.GRPCCode(params["code"])
		if _, ok := params["code"]; !ok {
			code = 14
		}
		message := fault.String(params, "message", "")
		var injected bool
		n, injected, err = relayGRPCMessages(flushWriter{w}, responseBody, grpcAfter, code, message)
		if injected {
			grpcStatus, grpcSource, grpcMessage = &code, "injected", message
			markApplied()
			return
		}
	} else if kind == "byte-trickle" {
		n, err = trickle(ctx, w, responseBody, params)
	} else if streaming {
		n, err = io.Copy(flushWriter{w}, responseBody)
	} else {
		n, err = io.Copy(w, responseBody)
	}
	for k, v := range resp.Trailer {
		w.Header()[http.TrailerPrefix+k] = v
	}
	if isGRPC {
		grpcSource = "upstream"
		if g, e := strconv.Atoi(grpcHeader(resp, "Grpc-Status")); e == nil {
			grpcStatus = &g
		}
		grpcMessage = grpcwire.DecodeMessage(grpcHeader(resp, "Grpc-Message"))
	}
	if plan.Applied != nil && plan.Applied.Load() {
		return
	}
	if err != nil {
		end = "upstream_error"
		p.outcome(gen, Outcome{Seq: seq, Err: err})
		panic(http.ErrAbortHandler)
	}
}

type countingBody struct {
	io.ReadCloser
	count       *atomic.Int64
	grpc        *grpcwire.MsgCounter
	mu          sync.Mutex
	previewMu   *sync.Mutex
	preview     *[]byte
	done        func()
	capture     bool
	body        []byte
	truncated   bool
	eof         bool
	reserve     func(int) int
	failed      bool
	incoming    *http.Request
	hasTrailers bool
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if b.grpc != nil {
		_, _ = b.grpc.Write(p[:n])
	}
	b.previewMu.Lock()
	remainingPreview := 256 - len(*b.preview)
	*b.preview = append(*b.preview, p[:min(n, remainingPreview)]...)
	b.previewMu.Unlock()
	b.mu.Lock()
	b.count.Add(int64(n))
	if b.capture && !b.truncated {
		take := min(n, maxBody-len(b.body))
		if b.reserve != nil && take > 0 {
			take = max(0, min(take, b.reserve(take)))
		}
		b.body = append(b.body, p[:take]...)
		b.truncated = n > take
	}
	if err == io.EOF {
		b.hasTrailers = len(b.incoming.Trailer) != 0
		b.eof = true
	} else if err != nil {
		b.failed = true
	}
	b.mu.Unlock()
	if err != nil && b.done != nil {
		b.done()
	}
	return n, err
}

// The downstream HTTP server owns the inbound body's lifetime.
func (b *countingBody) Close() error { return nil }

type flushWriter struct{ http.ResponseWriter }

func (w flushWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}

func inspectorHeaders(h http.Header) map[string]string {
	var out map[string]string
	for _, k := range [...]string{"Accept", "Content-Type", "Content-Length", "Content-Encoding", "Retry-After", "X-Glitchdeck-Fault"} {
		if v := h.Get(k); v != "" {
			if out == nil {
				out = make(map[string]string)
			}
			out[k] = v[:min(len(v), 256)]
		}
	}
	return out
}
func stripHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, k := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(k))
		}
	}
	for _, k := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(k)
	}
}
func copyHeaders(dst, src http.Header) {
	for k, v := range src {
		dst[k] = append([]string(nil), v...)
	}
}
func wait(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
func headerToken(h http.Header, key, token string) bool {
	for _, v := range h.Values(key) {
		for _, s := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(s), token) {
				return true
			}
		}
	}
	return false
}
func trickle(ctx context.Context, w http.ResponseWriter, body io.Reader, params map[string]any) (int64, error) {
	size := fault.Int(params, "chunk_bytes", 128)
	if size > 64<<10 {
		size = 64 << 10
	}
	rate := fault.Int(params, "bytes_per_sec", 128)
	buf := make([]byte, size)
	var total int64
	stalled := false
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if !wait(ctx, time.Duration(float64(time.Second)*float64(n)/float64(rate))) {
				return total, ctx.Err()
			}
			k, e := w.Write(buf[:n])
			total += int64(k)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			if e != nil {
				return total, e
			}
			if !stalled && fault.Int(params, "stall_after_bytes", 0) > 0 && total >= int64(fault.Int(params, "stall_after_bytes", 0)) {
				stalled = true
				if !wait(ctx, time.Duration(fault.Int(params, "stall_ms", 0))*time.Millisecond) {
					return total, ctx.Err()
				}
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}
func rst(c net.Conn) {
	raw := rawConn(c)
	if t, ok := raw.(interface{ SetLinger(int) error }); ok {
		_ = t.SetLinger(0)
	}
	_ = raw.Close()
}
func resetWriter(w http.ResponseWriter, injected func()) {
	h, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unavailable", 500)
		return
	}
	c, _, err := h.Hijack()
	if err == nil {
		injected()
		rst(c)
	}
}
func resetResponse(w http.ResponseWriter, resp *http.Response, method string, n int, cancel context.CancelFunc, result func(error)) int64 {
	h, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unavailable", 500)
		return 0
	}
	c, b, err := h.Hijack()
	if err != nil {
		return 0
	}
	defer rst(c)
	if method == http.MethodHead || resp.StatusCode < 200 || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		// These responses cannot be made incomplete by chunking.
		result(nil)
		return 0
	}
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	timer := time.AfterFunc(2*time.Second, cancel)
	defer timer.Stop()
	stripHop(resp.Header)
	var writer io.Writer = b
	if resp.ContentLength < 0 || int64(n) >= resp.ContentLength {
		resp.Header.Del("Content-Length")
		resp.Header.Set("Transfer-Encoding", "chunked")
		writer = httputil.NewChunkedWriter(b)
	}
	resp.Header.Set("Connection", "close")
	_, _ = fmt.Fprintf(b, "HTTP/1.1 %s\r\n", resp.Status)
	_ = resp.Header.Write(b)
	_, _ = b.WriteString("\r\n")
	count, copyErr := io.CopyN(writer, resp.Body, int64(n))
	if copyErr == io.EOF {
		copyErr = nil
	}
	if flushErr := b.Flush(); copyErr == nil {
		copyErr = flushErr
	}
	result(copyErr)
	return count
}
