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

type Record struct {
	Seq          uint64
	Method, Path string
	Header       http.Header
	Body         []byte
	WebSocket    bool
	At           time.Time
}
type Proxy struct {
	target        *url.URL
	cfg           atomic.Pointer[fault.Config]
	seq           atomic.Uint64
	bus           *telemetry.Bus
	transport     *http.Transport
	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	pending       int
	done          chan struct{}
	closed        bool
	OnRequest     func(Record)
	OnClientFrame func(uint64, []byte)
	OnServerFrame func(uint64, string, byte)
}

func ParseTarget(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u == nil || u.Scheme != "http" || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("target must be a loopback HTTP URL")
	}
	h := strings.ToLower(u.Hostname())
	if h != "localhost" && h != "127.0.0.1" {
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
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", port))
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
func (p *Proxy) SetConfig(c fault.Config) { c = cloneConfig(c); p.cfg.Store(&c) }
func (p *Proxy) Seq() uint64              { return p.seq.Load() }
func (p *Proxy) SetSeq(n uint64)          { p.seq.Store(n) }
func (p *Proxy) Reset() {
	p.mu.Lock()
	p.cancel()
	p.mu.Unlock()
	_ = p.Wait(context.Background())
	p.mu.Lock()
	if !p.closed {
		p.ctx, p.cancel = context.WithCancel(context.Background())
	}
	p.seq.Store(0)
	p.mu.Unlock()
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
func (p *Proxy) publish(kind string, v any) {
	if p.bus != nil {
		p.bus.Publish(kind, v)
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
	seq := p.seq.Add(1)
	cfg := *p.cfg.Load()
	ws := strings.EqualFold(r.Header.Get("Upgrade"), "websocket") && headerToken(r.Header, "Connection", "upgrade")
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	if p.OnRequest != nil {
		p.OnRequest(Record{seq, r.Method, r.URL.RequestURI(), r.Header, body, ws, start})
	}
	if ws {
		p.serveWS(w, r, seq)
		return
	}
	rule := fault.MatchRule(cfg, r.Method, r.URL.Path, seq, false)
	var kind string
	var params map[string]any
	if rule != nil {
		kind, params = rule.Fault.Type, rule.Fault.Params
	}
	status, n := 0, int64(0)
	var upstreamHeaders http.Header
	defer func() {
		p.publish("http_req", map[string]any{
			"seq": seq, "ts_ms": start.UnixMilli(), "method": r.Method, "path": r.URL.RequestURI(),
			"status": status, "latency_ms": time.Since(start).Milliseconds(), "req_bytes": len(body), "resp_bytes": n,
			"fault": kind, "replay_index": 0, "request_headers": inspectorHeaders(r.Header),
			"response_headers": inspectorHeaders(upstreamHeaders), "body_snippet": string(body[:min(len(body), 256)]),
		})
	}()
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
	if kind == "latency-wave" && !wait(r.Context(), time.Duration(fault.Latency(cfg.Seed, seq, params))*time.Millisecond) {
		return
	}
	if kind == "tcp-rst" && fault.Bool(params, "before_headers", false) {
		resetWriter(w)
		return
	}
	resp, err := p.transport.RoundTrip(p.upstream(r, body, r.Context()))
	if err != nil {
		status = 502
		http.Error(w, "upstream unavailable", status)
		return
	}
	defer resp.Body.Close()
	status, upstreamHeaders = resp.StatusCode, resp.Header
	if kind == "dup-webhook" {
		p.replays(r, body, seq, params)
	}
	if kind == "tcp-rst" {
		n = p.resetResponse(w, resp, fault.Int(params, "after_bytes", 0))
		return
	}
	stripHop(resp.Header)
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(status)
	if kind == "byte-trickle" {
		n = trickle(r.Context(), w, resp.Body, params)
		return
	}
	n, _ = io.Copy(w, resp.Body)
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
func trickle(ctx context.Context, w http.ResponseWriter, body io.Reader, params map[string]any) int64 {
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
				break
			}
			k, e := w.Write(buf[:n])
			total += int64(k)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			if e != nil {
				break
			}
			if !stalled && fault.Int(params, "stall_after_bytes", 0) > 0 && total >= int64(fault.Int(params, "stall_after_bytes", 0)) {
				stalled = true
				if !wait(ctx, time.Duration(fault.Int(params, "stall_ms", 0))*time.Millisecond) {
					break
				}
			}
		}
		if err != nil {
			break
		}
	}
	return total
}
func rst(c net.Conn) {
	if t, ok := c.(interface{ SetLinger(int) error }); ok {
		_ = t.SetLinger(0)
	}
	_ = c.Close()
}
func resetWriter(w http.ResponseWriter) {
	h, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unavailable", 500)
		return
	}
	c, _, err := h.Hijack()
	if err == nil {
		rst(c)
	}
}
func (p *Proxy) resetResponse(w http.ResponseWriter, resp *http.Response, n int) int64 {
	h, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unavailable", 500)
		return 0
	}
	c, b, err := h.Hijack()
	if err != nil {
		return 0
	}
	stripHop(resp.Header)
	resp.Header.Set("Connection", "close")
	_, _ = fmt.Fprintf(b, "HTTP/1.1 %s\r\n", resp.Status)
	_ = resp.Header.Write(b)
	_, _ = b.WriteString("\r\n")
	count, _ := io.CopyN(b, resp.Body, int64(n))
	_ = b.Flush()
	rst(c)
	return count
}
func (p *Proxy) replays(r *http.Request, body []byte, seq uint64, params map[string]any) {
	count := fault.Int(params, "count", 2)
	delay := fault.Int(params, "delay_ms", 150)
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil {
		p.mu.Unlock()
		return
	}
	ctx := p.ctx
	if count > 1 && p.pending == 0 {
		p.done = make(chan struct{})
	}
	for i := 1; i < count; i++ {
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
			start := time.Now()
			resp, err := p.transport.RoundTrip(q)
			status := 0
			var n int64
			if err == nil {
				status = resp.StatusCode
				n, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			p.publish("http_req", map[string]any{"seq": seq, "ts_ms": start.UnixMilli(), "method": q.Method, "path": q.URL.RequestURI(), "status": status, "latency_ms": time.Since(start).Milliseconds(), "req_bytes": len(body), "resp_bytes": n, "fault": "dup-webhook", "replay_index": index})
		}(i)
	}
	p.mu.Unlock()
}
