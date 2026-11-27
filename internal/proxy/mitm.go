package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func (p *Proxy) admitTunnel(record, active bool) (context.Context, uint64, uint64) {
	p.gate.Lock()
	defer p.gate.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	var seq uint64
	if record && !p.closed {
		seq = p.seq.Add(1)
		if active {
			p.activeTunnels++
		}
	}
	return p.ctx, seq, p.generation
}

func (p *Proxy) tunnelSequence() (uint64, uint64) {
	_, seq, gen := p.admitTunnel(true, false)
	return seq, gen
}

func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host, port, err := net.SplitHostPort(r.Host)
	n, portErr := strconv.ParseUint(port, 10, 16)
	valid := r.ProtoMajor == 1 && err == nil && portErr == nil && n != 0 && p.allowed(host, port)
	pattern, passthrough := "", false
	if valid && p.options.CA != nil {
		pattern, passthrough = p.passthrough(host, port)
	}
	intercept := valid && p.options.CA != nil && !passthrough
	tunnel := "blind"
	if passthrough {
		tunnel = "passthrough"
	}
	ctx, seq, gen := p.admitTunnel(!intercept, valid && !intercept)
	if valid && !intercept && seq != 0 {
		defer func() {
			p.gate.Lock()
			if gen == p.generation {
				p.activeTunnels--
			}
			p.gate.Unlock()
		}()
	}
	if valid && !intercept && seq != 0 && p.OnBlindTunnel != nil {
		p.callback(gen, func() { p.OnBlindTunnel(seq) })
	}
	if !valid {
		deniedHost := p.noteEgressDenial(r.Host, true)
		http.Error(w, "egress denied", http.StatusForbidden)
		p.tunnelEvent(r, start, seq, gen, 403, "", "", "egress_denied", deniedHost, 0, 0)
		return
	}
	if ctx.Err() != nil {
		http.Error(w, "proxy closed", http.StatusServiceUnavailable)
		return
	}
	p.mu.Lock()
	f := p.front
	p.mu.Unlock()
	var upstream net.Conn
	if intercept {
		if f == nil || f.minter == nil {
			http.Error(w, "no tunnel listener", http.StatusBadGateway)
			return
		}
	} else {
		dialCtx, cancel := context.WithCancel(r.Context())
		stop := context.AfterFunc(ctx, cancel)
		upstream, err = p.dial(dialCtx, "tcp", r.Host)
		stop()
		failure, deniedHost := p.noteDialResult(dialCtx, gen, r.Host, false, true, err)
		cancel()
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			p.tunnelEvent(r, start, seq, gen, 502, tunnel, pattern, failure, deniedHost, 0, 0)
			return
		}
		defer upstream.Close()
	}
	c, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "hijacking unavailable", http.StatusBadGateway)
		return
	}
	handedOver := false
	defer func() {
		if !handedOver {
			_ = c.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || rw.Flush() != nil {
		return
	}
	if intercept {
		rejected := false
		if secured, spec, ok := f.intercept(c, rw.Reader, r.Host, host, p.options.MITMALPN, func(name string, err error) {
			p.tlsRejected.Add(1)
			rejected = true
			if !p.options.SuppressStderr {
				fmt.Fprintf(os.Stderr, "tls_handshake_failed: host=%q sni=%q: %q\n", r.Host, name, err)
			}
			p.publish(gen, "tls_handshake_failed", map[string]any{"host": r.Host, "sni": name, "error": err.Error(), "ts_ms": start.UnixMilli()})
		}); ok {
			seen := new(atomic.Bool)
			spec.innerSeen = seen
			secured = &countEmptyConn{Conn: secured, p: p, gen: gen, seen: seen}
			p.interceptedOK.Add(1)
			handedOver = true
			f.route(secured, spec)
		}
		if !handedOver && !rejected {
			p.interceptedEmpty.Add(1)
		}
		return
	}
	_ = c.SetDeadline(time.Time{})
	stopUp := context.AfterFunc(ctx, func() { _ = upstream.Close() })
	defer stopUp()
	toUp := make(chan int64, 1)
	go func() {
		n, err := io.Copy(upstream, rw.Reader)
		if err != nil {
			_ = c.Close()
			_ = upstream.Close()
		} else {
			closeWrite(upstream)
		}
		toUp <- n
	}()
	fromUp, err := io.Copy(c, upstream)
	if err != nil {
		_ = c.Close()
		_ = upstream.Close()
	} else {
		closeWrite(c)
	}
	sent := <-toUp
	if passthrough {
		p.passthroughOK.Add(1)
	} else {
		p.blindOK.Add(1)
	}
	p.tunnelEvent(r, start, seq, gen, 200, tunnel, pattern, "", "", sent, fromUp)
}

func (f *front) intercept(c net.Conn, br *bufio.Reader, authority, host, alpn string, failed func(string, error)) (net.Conn, ConnMeta, bool) {
	first, err := br.Peek(1)
	if err != nil {
		return nil, ConnMeta{}, false
	}
	var conn net.Conn = &bufferedConn{Conn: c, r: br}
	meta := ConnMeta{Scheme: "http", Authority: authority, MITM: true}
	if first[0] == 0x16 {
		protocols := []string{"h2", "http/1.1"}
		if alpn == "h1" {
			protocols = protocols[1:]
		}
		serverName := ""
		tc := tls.Server(conn, &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: protocols,
			GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
				serverName = info.ServerName
				return nil, nil
			},
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				name := info.ServerName
				if name == "" {
					name = host
				}
				return f.minter.For(strings.ToLower(name))
			},
		})
		if err := tc.Handshake(); err != nil {
			failed(serverName, err)
			return nil, ConnMeta{}, false
		}
		firstApp := bufio.NewReader(tc)
		if _, err := firstApp.Peek(1); err != nil {
			if certificateAlert(err) {
				failed(serverName, err)
			}
			return nil, ConnMeta{}, false
		}
		state := tc.ConnectionState()
		meta.Scheme, meta.SNI, meta.ALPN, meta.tls = "https", state.ServerName, state.NegotiatedProtocol, &state
		conn = &bufferedConn{Conn: &interceptedTLS{Conn: tc, raw: c}, r: firstApp}
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, meta, true
}

func certificateAlert(err error) bool {
	var op *net.OpError
	if !errors.As(err, &op) || op.Op != "remote error" {
		return false
	}
	switch op.Err.Error() {
	case "tls: bad certificate", "tls: unsupported certificate", "tls: revoked certificate",
		"tls: expired certificate", "tls: unknown certificate", "tls: unknown certificate authority",
		"tls: certificate unobtainable", "tls: bad certificate status response", "tls: bad certificate hash value":
		return true
	}
	return false
}

type countEmptyConn struct {
	net.Conn
	p    *Proxy
	gen  uint64
	seen *atomic.Bool
	once sync.Once
}

func (c *countEmptyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.p.gate.Lock()
		defer c.p.gate.Unlock()
		if c.gen == c.p.generation && !c.seen.Load() {
			c.p.interceptedEmpty.Add(1)
		}
	})
	return err
}

func (c *countEmptyConn) Unwrap() net.Conn { return c.Conn }

type interceptedTLS struct {
	*tls.Conn
	raw net.Conn
}

func (c *interceptedTLS) Unwrap() net.Conn { return c.raw }

func rawConn(c net.Conn) net.Conn {
	for {
		u, ok := c.(interface{ Unwrap() net.Conn })
		if !ok {
			return c
		}
		c = u.Unwrap()
	}
}

func closeWrite(c net.Conn) {
	if tcp, ok := rawConn(c).(interface{ CloseWrite() error }); ok {
		_ = tcp.CloseWrite()
	} else {
		_ = c.Close()
	}
}

func (p *Proxy) tunnelEvent(r *http.Request, t time.Time, seq, gen uint64, status int, tunnel, pattern, failure, deniedHost string, in, out int64) {
	if seq == 0 {
		return
	}
	event := map[string]any{
		"seq": seq, "ts_ms": t.UnixMilli(), "method": r.Method, "path": r.Host, "host": r.Host, "proto": r.Proto,
		"status": status, "tunnel": tunnel, "req_bytes": in, "resp_bytes": out, "latency_ms": time.Since(t).Milliseconds(),
		"fault": "", "error": failure, "replay_index": 0,
	}
	if failure == "egress_denied" {
		delete(event, "path")
		delete(event, "host")
		if deniedHost != "" {
			event["host"] = deniedHost
		}
	}
	if pattern != "" {
		event["passthrough"] = pattern
	}
	p.publish(gen, "http_req", event)
}
