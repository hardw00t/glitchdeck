package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"glitchdeck/internal/fault"
	"glitchdeck/internal/wsframe"
)

func (p *Proxy) serveWS(w http.ResponseWriter, r *http.Request, seq uint64) {
	key := r.Header.Get("Sec-WebSocket-Key")
	decoded, err := base64.StdEncoding.DecodeString(key)
	if r.Method != "GET" || r.Header.Get("Sec-WebSocket-Version") != "13" || err != nil || len(decoded) != 16 {
		http.Error(w, "invalid websocket handshake", 400)
		return
	}
	p.mu.Lock()
	ctx := p.ctx
	closed := p.closed
	p.mu.Unlock()
	if closed || ctx.Err() != nil {
		http.Error(w, "proxy closed", 503)
		return
	}
	port := p.target.Port()
	if port == "" {
		port = "80"
	}
	up, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		http.Error(w, "upstream unavailable", 502)
		return
	}
	defer up.Close()
	stop := context.AfterFunc(ctx, func() { up.Close() })
	defer stop()
	_ = up.SetDeadline(time.Now().Add(5 * time.Second))
	q := p.upstream(r, nil, ctx)
	q.Header.Set("Connection", "Upgrade")
	q.Header.Set("Upgrade", "websocket")
	q.Header.Del("Sec-WebSocket-Extensions")
	if err = q.Write(up); err != nil {
		http.Error(w, "upstream handshake failed", 502)
		return
	}
	reader := bufio.NewReader(up)
	resp, err := http.ReadResponse(reader, q)
	if err != nil {
		http.Error(w, "upstream handshake failed", 502)
		return
	}
	if resp.StatusCode != 101 {
		defer resp.Body.Close()
		stripHop(resp.Header)
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}
	if !headerToken(resp.Header, "Connection", "upgrade") || !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") || resp.Header.Get("Sec-WebSocket-Accept") != wsframe.AcceptKey(key) || resp.Header.Get("Sec-WebSocket-Extensions") != "" {
		http.Error(w, "unsupported upstream websocket handshake", 502)
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
	done := make(chan struct{})
	var once sync.Once
	closeBoth := func(abnormal bool) {
		once.Do(func() {
			if abnormal {
				rst(client)
				rst(up)
			} else {
				client.Close()
				up.Close()
			}
			close(done)
		})
	}
	go func() {
		select {
		case <-ctx.Done():
			closeBoth(false)
		case <-done:
		}
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); p.pump(ctx, buf.Reader, up, true, "c2s", seq, r.URL.Path, closeBoth) }()
	go func() { defer wg.Done(); p.pump(ctx, reader, client, false, "s2c", seq, r.URL.Path, closeBoth) }()
	wg.Wait()
	closeBoth(false)
}
func (p *Proxy) pump(ctx context.Context, src io.Reader, dst net.Conn, masked bool, dir string, seq uint64, path string, closeBoth func(bool)) {
	defer closeBoth(false)
	var frameSeq uint64
	fragmented := false
	for {
		f, err := wsframe.Read(src, masked)
		if err != nil {
			return
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
			p.OnClientFrame(seq, f.Payload)
		}
		action := ""
		var params map[string]any
		cfg := *p.cfg.Load()
		rule := fault.MatchRule(cfg, http.MethodGet, path, seq, true)
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
			}
		}
		if dir == "s2c" && p.OnServerFrame != nil {
			p.OnServerFrame(seq, action, f.Opcode)
		}
		preview := ""
		if f.Opcode == 1 {
			snippet := f.Payload[:min(len(f.Payload), 80)]
			if utf8.Valid(snippet) {
				preview = string(snippet)
			}
		}
		p.publish("ws_frame", map[string]any{"conn_id": seq, "frame_seq": frameSeq, "ts_ms": time.Now().UnixMilli(), "dir": dir, "opcode": f.Opcode, "bytes": len(f.Payload), "fault": action, "preview": preview})
		switch action {
		case "drop":
			continue
		case "delay":
			if !wait(ctx, time.Duration(fault.Int(params, "delay_ms", 0))*time.Millisecond) {
				return
			}
		case "corrupt":
			if len(f.Payload) > 0 {
				f.Payload[0] ^= byte((cfg.Seed+frameSeq)%255 + 1)
			}
		case "close_1006":
			closeBoth(true)
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
			closeBoth(true)
			return
		}
		if wsframe.Write(dst, f, masked) != nil {
			return
		}
		if f.Opcode == 8 {
			return
		}
	}
}
