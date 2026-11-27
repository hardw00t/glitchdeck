package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/wsframe"
)

func (p *Proxy) serveWS(w http.ResponseWriter, r *http.Request, gen uint64, match fault.Query) {
	seq := match.Seq
	key := r.Header.Get("Sec-WebSocket-Key")
	decoded, err := base64.StdEncoding.DecodeString(key)
	if r.Method != "GET" || r.Header.Get("Sec-WebSocket-Version") != "13" || err != nil || len(decoded) != 16 {
		http.Error(w, "invalid websocket handshake", 400)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	q := p.upstream(r, nil, ctx)
	if q == nil {
		http.Error(w, "no upstream target", http.StatusBadGateway)
		return
	}
	dialCtx, stopDial := context.WithTimeout(ctx, 5*time.Second)
	defer stopDial()
	addr := net.JoinHostPort(q.URL.Hostname(), upstreamPort(q.URL.Scheme, q.URL.Port()))
	if !r.URL.IsAbs() && !MetaFrom(r.Context()).MITM && !p.options.RequireUpstreamAllow {
		dialCtx = context.WithValue(dialCtx, reverseTargetKey{}, true)
	}
	up, err := p.dial(dialCtx, "tcp", addr)
	if err != nil {
		p.outcome(gen, Outcome{Seq: seq, Err: err})
		w.Header().Set(TransportErrorHeader, "1")
		http.Error(w, "upstream unavailable", 502)
		return
	}
	defer up.Close()
	rawUp := up
	stop := context.AfterFunc(ctx, func() { _ = rawUp.Close() })
	defer stop()
	_ = up.SetDeadline(time.Now().Add(5 * time.Second))
	if q.URL.Scheme == "https" {
		cfg := &tls.Config{RootCAs: p.options.UpstreamCA, InsecureSkipVerify: p.options.InsecureUpstream, MinVersion: tls.VersionTLS12, ServerName: q.URL.Hostname(), NextProtos: []string{"http/1.1"}}
		secure := tls.Client(up, cfg)
		if err := secure.HandshakeContext(dialCtx); err != nil {
			http.Error(w, "upstream handshake failed", http.StatusBadGateway)
			return
		}
		up = secure
	}
	q.Header.Set("Connection", "Upgrade")
	q.Header.Set("Upgrade", "websocket")
	q.Header.Del("Sec-WebSocket-Extensions")
	if err = q.Write(up); err != nil {
		p.outcome(gen, Outcome{Seq: seq, Err: err})
		w.Header().Set(TransportErrorHeader, "1")
		http.Error(w, "upstream handshake failed", 502)
		return
	}
	reader := bufio.NewReader(up)
	var resp *http.Response
	for {
		resp, err = http.ReadResponse(reader, q)
		if err != nil {
			p.outcome(gen, Outcome{Seq: seq, Err: err})
			w.Header().Set(TransportErrorHeader, "1")
			http.Error(w, "upstream handshake failed", 502)
			return
		}
		if resp.StatusCode < 100 || resp.StatusCode >= 200 || resp.StatusCode == 101 {
			break
		}
		resp.Body.Close()
	}
	resp.Header.Del(TransportErrorHeader)
	if resp.StatusCode != 101 {
		defer resp.Body.Close()
		stripHop(resp.Header)
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}
	selections := resp.Header.Values("Sec-WebSocket-Protocol")
	selected := ""
	validSelection := len(selections) <= 1
	if len(selections) == 1 {
		selected = strings.TrimSpace(selections[0])
		validSelection = selected != "" && !strings.Contains(selected, ",")
	}
	offered := selected == ""
	for _, offer := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, item := range strings.Split(offer, ",") {
			if strings.TrimSpace(item) == selected {
				offered = true
			}
		}
	}
	if !headerToken(resp.Header, "Connection", "upgrade") || !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") || resp.Header.Get("Sec-WebSocket-Accept") != wsframe.AcceptKey(key) || resp.Header.Get("Sec-WebSocket-Extensions") != "" || !validSelection || !offered {
		err := fmt.Errorf("unsupported upstream websocket handshake")
		p.outcome(gen, Outcome{Seq: seq, Err: err})
		w.Header().Set(TransportErrorHeader, "1")
		http.Error(w, err.Error(), 502)
		return
	}
	_ = up.SetDeadline(time.Time{})
	h, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unavailable", 500)
		return
	}
	client, buf, err := h.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	_ = client.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err = fmt.Fprintf(buf, "HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		return
	}
	if err = resp.Header.Write(buf); err != nil {
		return
	}
	if _, err = buf.WriteString("\r\n"); err != nil {
		return
	}
	if err = buf.Flush(); err != nil {
		return
	}
	_ = client.SetWriteDeadline(time.Time{})
	stop()
	done := make(chan struct{})
	var once sync.Once
	closeBoth := func(action string) {
		once.Do(func() {
			if action != "" {
				p.outcome(gen, Outcome{Seq: seq, WSAction: action})
				rst(client)
				rst(up)
			} else {
				client.Close()
				up.Close()
			}
			cancel()
			close(done)
		})
	}
	go func() {
		select {
		case <-ctx.Done():
			closeBoth("")
		case <-done:
		}
	}()
	var wg sync.WaitGroup
	var closing sync.Once
	beginClose := func() {
		closing.Do(func() {
			_ = client.SetDeadline(time.Now().Add(time.Second))
			_ = up.SetDeadline(time.Now().Add(time.Second))
			timer := time.AfterFunc(time.Second, func() { closeBoth("") })
			context.AfterFunc(ctx, func() { timer.Stop() })
		})
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		p.pump(ctx, buf.Reader, up, true, "c2s", gen, match, closeBoth, beginClose)
	}()
	go func() {
		defer wg.Done()
		p.pump(ctx, reader, client, false, "s2c", gen, match, closeBoth, beginClose)
	}()
	wg.Wait()
	closeBoth("")
}
func (p *Proxy) pump(ctx context.Context, src io.Reader, dst net.Conn, masked bool, dir string, gen uint64, match fault.Query, closeBoth func(string), beginClose func()) {
	seq := match.Seq
	normalClose := false
	defer func() {
		if !normalClose {
			closeBoth("")
		}
	}()
	var frameSeq uint64
	var messageSeq uint64
	fragmented := false
	for {
		f, err := wsframe.Read(src, masked)
		if err != nil {
			return
		}
		if (f.Opcode == 2 || f.Opcode == 0 || !f.Fin) && p.OnUnsupportedFrame != nil {
			p.callback(gen, func() { p.OnUnsupportedFrame(seq) })
		}
		if f.Opcode == 0 {
			if !fragmented {
				return
			}
			if f.Fin {
				fragmented = false
			}
		} else if f.Opcode == 1 || f.Opcode == 2 {
			if fragmented {
				return
			}
			fragmented = !f.Fin
		}
		frameSeq++
		if dir == "c2s" && f.Opcode == 1 && f.Fin && p.OnClientFrame != nil {
			p.callback(gen, func() { p.OnClientFrame(seq, f.Payload) })
		}
		action, ruleID := "", ""
		var params map[string]any
		cfg := *p.cfg.Load()
		rule := fault.MatchRequest(cfg, match)
		if rule != nil {
			params = rule.Fault.Params
			direction := fault.String(params, "dir", "both")
			after := fault.Int(params, "after_frames", 1)
			if after < 1 {
				after = 1
			}
			every := fault.Int(params, "every", 1)
			if (direction == "both" || direction == dir) && frameSeq >= uint64(after) && (frameSeq-uint64(after))%uint64(every) == 0 {
				action = fault.String(params, "action", "drop")
				ruleID = rule.ID
				p.countRule(gen, rule, "matched", "")
				p.countRule(gen, rule, "applied", "")
			}
		}
		if dir == "s2c" && p.OnServerFrame != nil {
			p.callback(gen, func() { p.OnServerFrame(seq, action, f.Opcode) })
		}
		preview := ""
		if f.Opcode == 1 {
			snippet := f.Payload[:min(len(f.Payload), 80)]
			if utf8.Valid(snippet) {
				preview = string(snippet)
			}
		}
		p.publish(gen, "ws_frame", map[string]any{"conn_id": seq, "frame_seq": frameSeq, "ts_ms": time.Now().UnixMilli(), "dir": dir, "opcode": f.Opcode, "bytes": len(f.Payload), "fault": action, "fault_type": "ws-glitch", "rule_id": ruleID, "applied": action != "", "action": action, "preview": preview})
		data := f.Opcode == 0 || f.Opcode == 1 || f.Opcode == 2
		switch action {
		case "drop":
			if dir == "s2c" && data {
				p.outcome(gen, Outcome{Seq: seq, WSAction: action, WSMessage: messageSeq + 1})
			}
			continue
		case "delay":
			delay := time.Duration(fault.Int(params, "delay_ms", 0)) * time.Millisecond
			if dir == "s2c" && data && delay > 0 {
				p.outcome(gen, Outcome{Seq: seq, WSAction: action, WSMessage: messageSeq + 1, WSUntil: time.Now().Add(delay)})
			}
			if !wait(ctx, delay) {
				return
			}
		case "corrupt":
			if len(f.Payload) > 0 {
				f.Payload[0] ^= byte((cfg.Seed+frameSeq)%255 + 1)
				if dir == "s2c" && data {
					p.outcome(gen, Outcome{Seq: seq, WSAction: action, WSMessage: messageSeq + 1})
				}
			}
		case "close_1006":
			closeBoth(action)
			return
		case "truncate":
			var b bytes.Buffer
			if wsframe.Write(&b, f, masked) != nil {
				return
			}
			wire := b.Bytes()
			header := len(wire) - len(f.Payload)
			count := fault.Int(params, "truncate_bytes", 0)
			if count > len(f.Payload) {
				count = len(f.Payload)
			}
			_, _ = dst.Write(wire[:header+count])
			closeBoth(action)
			return
		}
		if f.Opcode == 8 {
			beginClose()
		}
		if wsframe.Write(dst, f, masked) != nil {
			closeBoth("")
			return
		}
		if dir == "s2c" && data && f.Fin {
			messageSeq++
		}
		if f.Opcode == 8 {
			normalClose = true
			return
		}
	}
}
