package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
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
	Seq              uint64
	Method, Path     string
	Header           http.Header
	URL              string
	Proto            string
	Body             []byte
	WebSocket        bool
	At               time.Time
	MITM             bool
	UnrecordableBody bool
}
type Proxy struct {
	target             *url.URL
	cfg                atomic.Pointer[fault.Config]
	seq                atomic.Uint64
	requests           atomic.Uint64
	bus                *telemetry.Bus
	transport          *http.Transport
	h2c                *http.Transport
	gate               sync.Mutex
	admission          sync.Mutex
	generation         uint64
	activeWS           int
	activeTunnels      int
	mu                 sync.Mutex
	ctx                context.Context
	cancel             context.CancelFunc
	pending            int
	done               chan struct{}
	closed             bool
	draining           bool
	options            Options
	server             *http.Server
	front              *front
	stats              map[string]RuleStats
	applied            map[AppliedFault]uint64
	OnBlindTunnel      func(uint64)
	OnSSE              func(uint64)
	OnRequest          func(Record)
	OnClientFrame      func(uint64, []byte)
	OnServerFrame      func(uint64, string, byte)
	OnUnsupportedFrame func(uint64)
	OnOutcome          func(Outcome)
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
	p.transport, p.h2c = p.newTransport(false), p.newTransport(true)
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
	p.cfg.Store(&c)
	return p.seq.Load() + 1
}
func (p *Proxy) Seq() uint64           { return p.seq.Load() }
func (p *Proxy) RequestsTotal() uint64 { return p.requests.Load() }
func (p *Proxy) SetSeq(n uint64)       { p.gate.Lock(); p.seq.Store(n); p.gate.Unlock() }
func (p *Proxy) ActiveWebSockets() int { p.gate.Lock(); defer p.gate.Unlock(); return p.activeWS }
func (p *Proxy) CaptureBoundary(fn func(uint64, int)) {
	p.gate.Lock()
	defer p.gate.Unlock()
	fn(p.seq.Load()+1, p.activeWS+p.activeTunnels)
}
func (p *Proxy) Reset() { p.ResetWith(nil) }
func (p *Proxy) ResetWith(fn func()) {
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
	clear(p.stats)
	clear(p.applied)
	p.mu.Unlock()
	if fn != nil {
		fn()
	}
}
func (p *Proxy) Close() {
	p.mu.Lock()
	p.closed = true
	p.cancel()
	s := p.server
	p.mu.Unlock()
	p.transport.CloseIdleConnections()
	p.h2c.CloseIdleConnections()
	if s != nil {
		_ = s.Close()
	}
}
func (p *Proxy) beginPendingLocked() {
	if p.pending == 0 {
		p.done = make(chan struct{})
	}
	p.pending++
}

func (p *Proxy) finishPending() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pending--
	if p.pending == 0 {
		close(p.done)
	}
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
	if r.URL.IsAbs() {
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
	q.TransferEncoding, q.Trailer = nil, nil
	if len(body) != 0 {
		q.Body = io.NopCloser(bytes.NewReader(body))
	}
	return q
}
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	if p.closed || p.draining {
		p.mu.Unlock()
		http.Error(w, "proxy closed", http.StatusServiceUnavailable)
		return
	}
	p.beginPendingLocked()
	p.mu.Unlock()
	defer p.finishPending()
	if !prepareProtocolRequest(r) {
		http.Error(w, "request does not match CONNECT authority", http.StatusMisdirectedRequest)
		return
	}
	if !p.authorize(w, r) {
		return
	}
	p.requests.Add(1)
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	start := time.Now()
	scheme, host := r.URL.Scheme, r.URL.Host
	if r.URL.IsAbs() {
		if r.URL.User != nil || (scheme != "http" && scheme != "https") || !p.allowed(r.URL.Hostname(), upstreamPort(scheme, r.URL.Port())) {
			http.Error(w, "egress denied", http.StatusForbidden)
			if seq, gen := p.tunnelSequence(); seq != 0 {
				p.tunnelEvent(r, start, seq, gen, 403, "", "egress_denied", 0, 0)
			}
			return
		}
	} else if p.target != nil {
		if p.options.RequireUpstreamAllow && !p.allowed(p.target.Hostname(), upstreamPort(p.target.Scheme, p.target.Port())) {
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
	session, gen, closed := p.ctx, p.generation, p.closed || p.draining
	p.mu.Unlock()
	if closed || session.Err() != nil {
		p.gate.Unlock()
		p.admission.Unlock()
		http.Error(w, "proxy closed", 503)
		return
	}
	seq := p.seq.Add(1)
	p.gate.Unlock()
	if p.options.BeforeRequest != nil {
		p.options.BeforeRequest(seq)
	}
	cfg := *p.cfg.Load()
	if p.options.OnAdmission != nil {
		p.options.OnAdmission(seq, r.Method, r.URL.RequestURI(), host)
	}
	p.admission.Unlock()
	p.gate.Lock()
	ws := r.Method == http.MethodGet && strings.EqualFold(r.Header.Get("Upgrade"), "websocket") && headerToken(r.Header, "Connection", "upgrade")
	if ws {
		p.activeWS++
	}
	p.gate.Unlock()
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
	r = r.WithContext(ctx)
	proto := "h1"
	recordProto := ""
	if r.ProtoMajor == 2 {
		proto, recordProto = "h2", "h2c"
		if r.TLS != nil {
			recordProto = "h2"
		}
	}
	meta := MetaFrom(ctx)
	streamID := streamFrom(ctx)
	ctype := r.Header.Get("Content-Type")
	isGRPC := r.ProtoMajor == 2 && fault.NativeGRPC(ctype)
	match := fault.Query{Method: r.Method, Path: r.URL.Path, Host: host, Scheme: scheme, Proto: proto, ContentType: ctype, Seq: seq, WS: ws}
	rule := fault.MatchRequest(cfg, match)
	var kind, action, skip, h2Error string
	var params map[string]any
	if rule != nil {
		kind, params = rule.Fault.Type, rule.Fault.Params
		if !ws {
			p.countRule(gen, rule, "matched", "")
		}
	}
	applied := false
	ruleID := ""
	if rule != nil {
		ruleID = rule.ID
	}
	markApplied := func() {
		applied = true
		p.countRule(gen, rule, "applied", "")
	}
	status, n, end := 0, int64(0), "complete"
	runID := r.Header.Get("X-Glitchdeck-Run")
	var body []byte
	var streamedBytes atomic.Int64
	var upstreamHeaders http.Header
	var grpcStatus *int
	grpcSource, grpcMessage := "proxy", ""
	var grpcIn, grpcOut grpcwire.MsgCounter
	var isSSE bool
	sseEvents := 0
	if !ws {
		defer func() {
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
				"status": status, "latency_ms": time.Since(start).Milliseconds(), "req_bytes": int64(len(body)) + streamedBytes.Load(), "resp_bytes": n,
				"fault": kind, "replay_index": 0, "request_headers": inspectorHeaders(r.Header),
				"applied": applied, "rule_id": ruleID,
				"response_headers": inspectorHeaders(upstreamHeaders), "body_snippet": string(body[:min(len(body), 256)]),
				"proto": r.Proto, "protocol": protocol, "scheme": scheme, "host": host, "stream_id": streamID, "sse": isSSE,
				"sse_events": sseEvents, "grpc_status": grpcStatus, "fault_action": action, "fault_skipped": skip, "end": end, "run_id": runID, "tunnel": tunnel,
			})
		}()
	}
	if runID != "" {
		w.Header().Set("X-Glitchdeck-Seq", strconv.FormatUint(seq, 10))
	}
	record := func(captured []byte, missing bool) {
		if p.OnRequest == nil {
			return
		}
		rec := Record{Seq: seq, Method: r.Method, Path: r.URL.RequestURI(), Header: r.Header, Body: captured,
			WebSocket: ws, At: start, Proto: recordProto, UnrecordableBody: missing, MITM: meta.MITM}
		if r.URL.IsAbs() {
			rec.URL = r.URL.String()
		} else if meta.MITM {
			rec.URL = scheme + "://" + host + r.URL.RequestURI()
		}
		p.callback(gen, func() { p.OnRequest(rec) })
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
			record(nil, r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0)
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
			record(nil, r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0)
			flushPlanned = true
			_ = http.NewResponseController(w).Flush()
			return
		}
	}
	if !ws && kind == "tcp-rst" && fault.Bool(params, "before_headers", false) {
		record(nil, r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0)
		resetWriter(w, func() {
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
			record(nil, r.ContentLength != 0)
			code, _ := fault.GRPCCode(params["code"])
			if _, ok := params["code"]; !ok {
				code = 14
			}
			injectGRPC(code, fault.String(params, "message", ""), "injected")
			markApplied()
			return
		}
	}
	buffered := (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) &&
		(!isGRPC || kind == "dup-webhook" || p.OnRequest != nil && r.ContentLength >= 0 && r.ContentLength <= maxBody)
	if buffered {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil || len(body) > maxBody {
			body = nil
			status = http.StatusRequestEntityTooLarge
			p.outcome(gen, Outcome{Seq: seq, Err: errors.New("request body too large or unreadable")})
			http.Error(w, "request body too large or unreadable", status)
			return
		}
		if isGRPC {
			_, _ = grpcIn.Write(body)
		}
	}
	record(body, !buffered && r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0)
	if ws {
		p.serveWS(w, r, gen, match)
		return
	}
	if kind == "rate-limit" {
		status = fault.Int(params, "status", 429)
		w.Header().Set("Retry-After", strconv.Itoa(fault.Int(params, "retry_after_sec", 5)))
		w.Header().Set("X-Glitchdeck-Fault", kind)
		upstreamHeaders = w.Header()
		w.WriteHeader(status)
		count, _ := io.WriteString(w, fault.String(params, "body", ""))
		n = int64(count)
		markApplied()
		return
	}
	if kind == "latency-wave" && !wait(ctx, time.Duration(fault.Latency(cfg.Seed, seq, params))*time.Millisecond) {
		end = "client_cancel"
		panic(http.ErrAbortHandler)
	}
	if !r.URL.IsAbs() && !meta.MITM && !p.options.RequireUpstreamAllow {
		ctx = context.WithValue(ctx, reverseTargetKey{}, true)
	}
	q := p.upstream(r, body, ctx)
	if q == nil {
		status, end = 502, "upstream_error"
		http.Error(w, "no upstream target", status)
		return
	}
	if kind == "sse-glitch" {
		q.Header.Del("Accept-Encoding")
	}
	if !buffered && r.Body != nil && r.Body != http.NoBody {
		b := &countingBody{ReadCloser: r.Body, count: &streamedBytes}
		if isGRPC {
			b.grpc = &grpcIn
		}
		q.Body, q.ContentLength = b, r.ContentLength
	}
	transport := p.transport
	if r.ProtoMajor == 2 && q.URL.Scheme == "http" {
		transport = p.h2c
	}
	if meta.Tap != nil && streamID != 0 && !meta.Tap.AdmitUpstream(streamID) {
		meta.Tap.Reset(streamID, 7)
		panic(http.ErrAbortHandler)
	}
	resp, err := transport.RoundTrip(q)
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
	defer resp.Body.Close()
	if isGRPC && resp.ProtoMajor != 2 {
		injectGRPC(14, "upstream is not HTTP/2", "proxy")
		return
	}
	resp.Header.Del(TransportErrorHeader)
	status, upstreamHeaders = resp.StatusCode, resp.Header
	media, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	encoding := resp.Header.Get("Content-Encoding")
	isSSE = media == "text/event-stream" && (encoding == "" || strings.EqualFold(encoding, "identity"))
	if isSSE && p.OnSSE != nil {
		p.callback(gen, func() { p.OnSSE(seq) })
	}
	switch kind {
	case "dup-webhook":
		if fault.Int(params, "count", 2) > 1 {
			if buffered || r.Body == nil || r.Body == http.NoBody {
				if p.replays(r, body, seq, gen, rule, params, transport) {
					markApplied()
				}
			} else {
				err := errors.New("cannot replay streamed request body")
				p.outcome(gen, Outcome{Seq: seq, Err: err})
				p.publish(gen, "http_req", map[string]any{"seq": seq, "fault": kind, "rule_id": ruleID, "applied": false, "error": err.Error()})
			}
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
			if media == "text/event-stream" {
				skip = "encoded"
			}
			p.countRule(gen, rule, "skipped", skip)
		}
	}
	if isSSE && r.ProtoMajor == 1 && sseNeedsHijack(rule) {
		result := p.relayHijackedSSE(ctx, w, resp, rule, cfg.Seed, seq, gen, start, runID)
		n, sseEvents, end, skip = result.bytes, result.events, requestSSEEnd(result.end), result.skip
		applied = applied || result.applied
		if result.err != nil && result.end != "client_cancel" {
			p.outcome(gen, Outcome{Seq: seq, Err: result.err})
		}
		return
	}
	streaming := resp.ContentLength < 0 || isSSE || plan.Applied != nil || isGRPC
	stripHop(resp.Header)
	if isSSE && kind == "sse-glitch" || kind == "grpc-glitch" {
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
		result := p.relaySSE(ctx, w, resp.Body, rule, cfg.Seed, seq, gen, start, runID)
		n, sseEvents, end, skip = result.bytes, result.events, requestSSEEnd(result.end), result.skip
		applied = applied || result.applied
		if r.ProtoMajor == 2 && (result.end == "rst" || result.end == "eof_early" && !fault.Bool(params, "http_clean", true)) {
			code := uint32(0)
			if result.end == "rst" {
				code = 2
				if !fault.Bool(params, "rst", true) {
					code = 8
				}
			}
			if !resetProtocolStream(ctx, code) {
				panic(http.ErrAbortHandler)
			}
		}
		if result.err != nil && result.end != "client_cancel" {
			p.outcome(gen, Outcome{Seq: seq, Err: result.err})
			if result.end == "upstream_error" {
				panic(http.ErrAbortHandler)
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
	count *atomic.Int64
	grpc  *grpcwire.MsgCounter
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.count.Add(int64(n))
	if b.grpc != nil {
		_, _ = b.grpc.Write(p[:n])
	}
	return n, err
}

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
func (p *Proxy) replays(r *http.Request, body []byte, seq, gen uint64, rule *fault.Rule, params map[string]any, transport *http.Transport) bool {
	count := fault.Int(params, "count", 2)
	delay := fault.Int(params, "delay_ms", 150)
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil || gen != p.generation {
		p.mu.Unlock()
		return false
	}
	ctx := p.ctx
	started := false
	var replayErr error
	for i := 1; i < count; i++ {
		if p.pending >= 64 {
			replayErr = errors.New("webhook replay capacity exceeded")
			break
		}
		q := p.upstream(r, body, ctx)
		if q == nil || !p.allowed(q.URL.Hostname(), upstreamPort(q.URL.Scheme, q.URL.Port())) {
			replayErr = errors.New("webhook replay egress denied")
			break
		}
		p.beginPendingLocked()
		started = true
		if fault.Bool(params, "replay_header", false) {
			q.Header.Set("X-Glitchdeck-Replay", strconv.Itoa(i))
		}
		go func(index int) {
			defer p.finishPending()
			if !wait(ctx, time.Duration(index)*time.Duration(delay)*time.Millisecond) {
				return
			}
			replayCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			start := time.Now()
			resp, err := transport.RoundTrip(q.WithContext(replayCtx))
			status := 0
			var n int64
			if err == nil {
				status = resp.StatusCode
				n, err = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			if err != nil && ctx.Err() == nil {
				p.outcome(gen, Outcome{Seq: seq, Err: err})
			}
			p.publish(gen, "http_req", map[string]any{"seq": seq, "ts_ms": start.UnixMilli(), "method": q.Method, "path": q.URL.RequestURI(), "status": status, "latency_ms": time.Since(start).Milliseconds(), "req_bytes": len(body), "resp_bytes": n, "fault": "dup-webhook", "rule_id": rule.ID, "applied": true, "replay_index": index})
		}(i)
	}
	p.mu.Unlock()
	if replayErr != nil {
		p.outcome(gen, Outcome{Seq: seq, Err: replayErr})
		p.publish(gen, "http_req", map[string]any{"seq": seq, "fault": "dup-webhook", "rule_id": rule.ID, "applied": false, "error": replayErr.Error()})
	}
	return started
}
