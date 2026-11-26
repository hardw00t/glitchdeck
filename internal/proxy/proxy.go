package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"glitchdeck/internal/fault"
	"glitchdeck/internal/telemetry"
)

const maxBody = 4 << 20
const TransportErrorHeader = "X-Glitchdeck-Transport-Error"

type Outcome struct {
	Seq       uint64
	Reset     bool
	Err       error
	WSAction  string
	WSMessage uint64
	WSUntil   time.Time
}

type Record struct {
	Seq              uint64
	Method, Path     string
	Header           http.Header
	Body             []byte
	WebSocket        bool
	At               time.Time
	UnrecordableBody bool
}
type Proxy struct {
	target             *url.URL
	cfg                atomic.Pointer[fault.Config]
	seq                atomic.Uint64
	bus                *telemetry.Bus
	transport          *http.Transport
	gate               sync.Mutex
	generation         uint64
	activeWS           int
	mu                 sync.Mutex
	ctx                context.Context
	cancel             context.CancelFunc
	pending            int
	done               chan struct{}
	closed             bool
	OnRequest          func(Record)
	OnClientFrame      func(uint64, []byte)
	OnServerFrame      func(uint64, string, byte)
	OnUnsupportedFrame func(uint64)
	OnOutcome          func(Outcome)
}

func ParseTarget(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u == nil || u.Scheme != "http" || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("target must be a loopback HTTP URL")
	}
	h := strings.ToLower(u.Hostname())
	if h != "localhost" && (net.ParseIP(h) == nil || !net.ParseIP(h).IsLoopback()) {
		return nil, errors.New("target must be loopback")
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
	u := *target
	p := &Proxy{target: &u, bus: bus, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	close(p.done)
	p.transport = &http.Transport{DisableCompression: true, ForceAttemptHTTP2: false, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}}
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
func (p *Proxy) SetSeq(n uint64)       { p.gate.Lock(); p.seq.Store(n); p.gate.Unlock() }
func (p *Proxy) ActiveWebSockets() int { p.gate.Lock(); defer p.gate.Unlock(); return p.activeWS }
func (p *Proxy) CaptureBoundary(fn func(uint64, int)) {
	p.gate.Lock()
	defer p.gate.Unlock()
	fn(p.seq.Load()+1, p.activeWS)
}
func (p *Proxy) Reset() { p.ResetWith(nil) }
func (p *Proxy) ResetWith(fn func()) {
	p.gate.Lock()
	defer p.gate.Unlock()
	p.mu.Lock()
	p.cancel()
	p.generation++
	p.activeWS = 0
	p.mu.Unlock()
	_ = p.Wait(context.Background())
	p.mu.Lock()
	if !p.closed {
		p.ctx, p.cancel = context.WithCancel(context.Background())
	}
	p.seq.Store(0)
	p.mu.Unlock()
	if fn != nil {
		fn()
	}
}
func (p *Proxy) Close() {
	p.mu.Lock()
	p.closed = true
	p.cancel()
	p.mu.Unlock()
	p.transport.CloseIdleConnections()
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
func (p *Proxy) publish(gen uint64, kind string, v any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if gen == p.generation && p.bus != nil {
		p.bus.Publish(kind, v)
	}
}
func (p *Proxy) outcome(gen uint64, o Outcome) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if gen == p.generation && p.OnOutcome != nil {
		p.OnOutcome(o)
	}
}
func (p *Proxy) callback(gen uint64, fn func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if gen == p.generation {
		fn()
	}
}
func (p *Proxy) upstream(r *http.Request, body []byte, ctx context.Context) *http.Request {
	u := *p.target
	u.Path = strings.TrimRight(u.Path, "/") + r.URL.Path
	u.RawPath = ""
	if p.target.RawPath != "" || r.URL.RawPath != "" {
		u.RawPath = strings.TrimRight(p.target.EscapedPath(), "/") + r.URL.EscapedPath()
	}
	u.RawQuery, u.ForceQuery = r.URL.RawQuery, r.URL.ForceQuery
	q := r.Clone(ctx)
	q.URL, q.RequestURI, q.Host = &u, "", p.target.Host
	stripHop(q.Header)
	q.Body, q.ContentLength = http.NoBody, int64(len(body))
	q.TransferEncoding, q.Trailer = nil, nil
	if len(body) != 0 {
		q.Body = io.NopCloser(bytes.NewReader(body))
	}
	return q
}
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	p.gate.Lock()
	p.mu.Lock()
	ctx, gen, closed := p.ctx, p.generation, p.closed
	p.mu.Unlock()
	if closed || ctx.Err() != nil {
		p.gate.Unlock()
		http.Error(w, "proxy closed", 503)
		return
	}
	seq := p.seq.Add(1)
	cfg := *p.cfg.Load()
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
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(r.Context(), cancel)
	defer stop()
	defer cancel()
	r = r.WithContext(ctx)
	rule := fault.MatchRule(cfg, r.Method, r.URL.Path, seq, false)
	var kind string
	var params map[string]any
	if rule != nil {
		kind, params = rule.Fault.Type, rule.Fault.Params
	}
	status, n := 0, int64(0)
	var body []byte
	var streamedBytes atomic.Int64
	var upstreamHeaders http.Header
	if !ws {
		defer func() {
			p.publish(gen, "http_req", map[string]any{
				"seq": seq, "ts_ms": start.UnixMilli(), "method": r.Method, "path": r.URL.RequestURI(),
				"status": status, "latency_ms": time.Since(start).Milliseconds(), "req_bytes": int64(len(body)) + streamedBytes.Load(), "resp_bytes": n,
				"fault": kind, "replay_index": 0, "request_headers": inspectorHeaders(r.Header),
				"response_headers": inspectorHeaders(upstreamHeaders), "body_snippet": string(body[:min(len(body), 256)]),
			})
		}()
	}
	if !ws && kind == "tcp-rst" && fault.Bool(params, "before_headers", false) {
		if p.OnRequest != nil {
			p.callback(gen, func() {
				p.OnRequest(Record{Seq: seq, Method: r.Method, Path: r.URL.RequestURI(), Header: r.Header, At: start})
			})
		}
		resetWriter(w, func() { p.outcome(gen, Outcome{Seq: seq, Reset: true}) })
		return
	}
	buffered := r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch
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
	}
	if p.OnRequest != nil {
		p.callback(gen, func() {
			p.OnRequest(Record{Seq: seq, Method: r.Method, Path: r.URL.RequestURI(), Header: r.Header, Body: body, WebSocket: ws, At: start, UnrecordableBody: !buffered && r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0})
		})
	}
	if ws {
		p.serveWS(w, r, seq, gen)
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
		return
	}
	if kind == "latency-wave" && !wait(ctx, time.Duration(fault.Latency(cfg.Seed, seq, params))*time.Millisecond) {
		panic(http.ErrAbortHandler)
	}
	q := p.upstream(r, body, ctx)
	if !buffered && r.Body != nil && r.Body != http.NoBody {
		q.Body, q.ContentLength = &countingBody{ReadCloser: r.Body, count: &streamedBytes}, r.ContentLength
	}
	resp, err := p.transport.RoundTrip(q)
	if err != nil {
		p.outcome(gen, Outcome{Seq: seq, Err: err})
		status = 502
		w.Header().Set(TransportErrorHeader, "1")
		http.Error(w, "upstream unavailable", status)
		return
	}
	defer resp.Body.Close()
	resp.Header.Del(TransportErrorHeader)
	status, upstreamHeaders = resp.StatusCode, resp.Header
	if kind == "dup-webhook" && fault.Int(params, "count", 2) > 1 {
		if buffered || r.Body == nil || r.Body == http.NoBody {
			p.replays(r, body, seq, gen, params)
		} else {
			err := errors.New("cannot replay streamed request body")
			p.outcome(gen, Outcome{Seq: seq, Err: err})
			p.publish(gen, "http_req", map[string]any{"seq": seq, "fault": "dup-webhook", "error": err.Error()})
		}
	}
	if kind == "tcp-rst" {
		n = resetResponse(w, resp, r.Method, fault.Int(params, "after_bytes", 0), cancel, func(err error) {
			p.outcome(gen, Outcome{Seq: seq, Reset: err == nil, Err: err})
		})
		return
	}
	stream := resp.ContentLength < 0 || strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")
	stripHop(resp.Header)
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(status)
	if stream {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	if kind == "byte-trickle" {
		n, err = trickle(ctx, w, resp.Body, params)
	} else if stream {
		n, err = io.Copy(flushWriter{w}, resp.Body)
	} else {
		n, err = io.Copy(w, resp.Body)
	}
	if err != nil {
		p.outcome(gen, Outcome{Seq: seq, Err: err})
		panic(http.ErrAbortHandler)
	}
}

type countingBody struct {
	io.ReadCloser
	count *atomic.Int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.count.Add(int64(n))
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
	if t, ok := c.(interface{ SetLinger(int) error }); ok {
		_ = t.SetLinger(0)
	}
	_ = c.Close()
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
func (p *Proxy) replays(r *http.Request, body []byte, seq, gen uint64, params map[string]any) {
	count := fault.Int(params, "count", 2)
	delay := fault.Int(params, "delay_ms", 150)
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil || gen != p.generation {
		p.mu.Unlock()
		return
	}
	ctx := p.ctx
	overloaded := false
	for i := 1; i < count; i++ {
		if p.pending >= 64 {
			overloaded = true
			break
		}
		if p.pending == 0 {
			p.done = make(chan struct{})
		}
		p.pending++
		q := p.upstream(r, body, ctx)
		if fault.Bool(params, "replay_header", false) {
			q.Header.Set("X-Glitchdeck-Replay", strconv.Itoa(i))
		}
		go func(index int) {
			defer func() {
				p.mu.Lock()
				p.pending--
				if p.pending == 0 {
					close(p.done)
				}
				p.mu.Unlock()
			}()
			if !wait(ctx, time.Duration(index)*time.Duration(delay)*time.Millisecond) {
				return
			}
			replayCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			start := time.Now()
			resp, err := p.transport.RoundTrip(q.WithContext(replayCtx))
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
			p.publish(gen, "http_req", map[string]any{"seq": seq, "ts_ms": start.UnixMilli(), "method": q.Method, "path": q.URL.RequestURI(), "status": status, "latency_ms": time.Since(start).Milliseconds(), "req_bytes": len(body), "resp_bytes": n, "fault": "dup-webhook", "replay_index": index})
		}(i)
	}
	p.mu.Unlock()
	if overloaded {
		err := errors.New("webhook replay capacity exceeded")
		p.outcome(gen, Outcome{Seq: seq, Err: err})
		p.publish(gen, "http_req", map[string]any{"seq": seq, "fault": "dup-webhook", "error": err.Error()})
	}
}
