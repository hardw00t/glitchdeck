package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/wsframe"
)

type FrameError struct {
	Code      string
	Detail    string
	Declared  uint64
	Direction string
}

func (e *FrameError) Error() string { return e.Detail }

var errWSRead = errors.New("websocket read failed")
var errWSReadTimeout = errors.New("websocket read failed")

type wsWriter struct {
	mu     sync.Mutex
	conn   net.Conn
	masked bool
	closed bool
}

func (w *wsWriter) write(f wsframe.Frame) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return net.ErrClosed
	}
	err := wsframe.Write(w.conn, f, w.masked)
	if f.Opcode == 8 {
		var protocol *wsframe.ErrProtocol
		if !errors.As(err, &protocol) {
			w.closed = true
		}
	}
	return err
}

func (w *wsWriter) truncate(b []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed {
		_, _ = w.conn.Write(b)
	}
}

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
	reverse := !r.URL.IsAbs() && !MetaFrom(r.Context()).MITM && p.target != nil
	if reverse {
		dialCtx = context.WithValue(dialCtx, reverseTargetKey{}, true)
	}
	up, err := p.dial(dialCtx, "tcp", addr)
	if err != nil {
		p.noteDialResult(ctx, gen, q.URL.Host, reverse, false, err)
		if errors.Is(err, errEgressDenied) {
			p.publishDeniedRequest(gen, seq, 502, p.deniedHost(q.URL.Host), 0, 0, 0)
		}
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
		p.innerUsable.Add(1)
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
	p.innerUsable.Add(1)
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
	p.coordinateWS(ctx, cancel, client, up, buf.Reader, reader, gen, match)
}

func (p *Proxy) coordinateWS(ctx context.Context, cancel context.CancelFunc, client, up net.Conn, clientReader, upReader io.Reader, gen uint64, match fault.Query) {
	seq := match.Seq
	done := make(chan struct{})
	var once sync.Once
	var terminal sync.Mutex
	var failing atomic.Bool
	var closingState atomic.Bool
	closeNow := func(action string) {
		once.Do(func() {
			cancel()
			if action != "" {
				p.outcome(gen, Outcome{Seq: seq, WSAction: action})
				rst(client)
				rst(up)
			} else {
				client.Close()
				up.Close()
			}
			close(done)
		})
	}
	closeBoth := func(action string) {
		terminal.Lock()
		defer terminal.Unlock()
		if failing.Load() {
			return
		}
		closeNow(action)
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
			closingState.Store(true)
			_ = client.SetDeadline(time.Now().Add(time.Second))
			_ = up.SetDeadline(time.Now().Add(time.Second))
			timer := time.AfterFunc(time.Second, func() { closeBoth("") })
			context.AfterFunc(ctx, func() { timer.Stop() })
		})
	}
	clientWriter := &wsWriter{conn: client}
	upWriter := &wsWriter{conn: up, masked: true}
	var failed sync.Once
	fail := func(dir, code string, err error) {
		if closingState.Load() && err == errWSReadTimeout {
			return
		}
		failing.Store(true)
		terminal.Lock()
		defer terminal.Unlock()
		if ctx.Err() != nil {
			closeNow("")
			return
		}
		failed.Do(func() {
			deadline := time.Now().Add(time.Second)
			_ = client.SetWriteDeadline(deadline)
			_ = up.SetWriteDeadline(deadline)
			frameErr := &FrameError{Code: code, Detail: err.Error(), Direction: dir}
			closeCode, reason := uint16(1002), "glitchdeck: protocol error"
			var large *wsframe.ErrFrameTooLarge
			if errors.As(err, &large) {
				frameErr.Code, frameErr.Declared = "frame_too_large", large.Declared
				closeCode, reason = 1009, "glitchdeck: frame exceeds 4 MiB proxy limit"
			}
			var protocol *wsframe.ErrProtocol
			if errors.As(err, &protocol) {
				frameErr.Declared = protocol.Declared
			}
			p.publish(gen, "ws_frame", map[string]any{"conn_id": seq, "dir": dir, "error": frameErr.Code, "detail": frameErr.Detail, "declared_bytes": frameErr.Declared, "limit_bytes": wsframe.MaxPayload, "ts_ms": time.Now().UnixMilli()})
			p.outcome(gen, Outcome{Seq: seq, Err: frameErr})
			payload := make([]byte, 2, 2+len(reason))
			binary.BigEndian.PutUint16(payload, closeCode)
			payload = append(payload, reason...)
			frame := wsframe.Frame{Fin: true, Opcode: 8, Payload: payload}
			var closes sync.WaitGroup
			closes.Add(2)
			go func() { defer closes.Done(); _ = clientWriter.write(frame) }()
			go func() { defer closes.Done(); _ = upWriter.write(frame) }()
			closes.Wait()
			closeNow("")
		})
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		p.pump(ctx, clientReader, upWriter, true, "c2s", gen, match, closeBoth, beginClose, fail)
	}()
	go func() {
		defer wg.Done()
		p.pump(ctx, upReader, clientWriter, false, "s2c", gen, match, closeBoth, beginClose, fail)
	}()
	wg.Wait()
	closeBoth("")
}
func (p *Proxy) pump(ctx context.Context, src io.Reader, dst *wsWriter, masked bool, dir string, gen uint64, match fault.Query, closeBoth func(string), beginClose func(), fail func(string, string, error)) {
	seq := match.Seq
	normalClose := false
	defer func() {
		if !normalClose {
			closeBoth("")
		}
	}()
	var frameSeq, dataSeq, controlSeq uint64
	var messageSeq uint64
	fragmented := false
	for {
		f, err := wsframe.Read(src, masked)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				var protocol *wsframe.ErrProtocol
				var large *wsframe.ErrFrameTooLarge
				if !errors.As(err, &protocol) && !errors.As(err, &large) {
					var timeout net.Error
					if errors.As(err, &timeout) && timeout.Timeout() {
						err = errWSReadTimeout
					} else {
						err = errWSRead
					}
				}
				fail(dir, "protocol_error", err)
			}
			return
		}
		if (f.Opcode == 2 || f.Opcode == 0 || !f.Fin) && p.OnUnsupportedFrame != nil {
			p.callback(gen, func() { p.OnUnsupportedFrame(seq) })
		}
		if f.Opcode == 0 {
			if !fragmented {
				fail(dir, "protocol_error", &wsframe.ErrProtocol{Reason: "unexpected continuation frame", Declared: uint64(len(f.Payload))})
				return
			}
			if f.Fin {
				fragmented = false
			}
		} else if f.Opcode == 1 || f.Opcode == 2 {
			if fragmented {
				fail(dir, "protocol_error", &wsframe.ErrProtocol{Reason: "unexpected data frame", Declared: uint64(len(f.Payload))})
				return
			}
			fragmented = !f.Fin
		}
		frameSeq++
		data := f.Opcode == 0 || f.Opcode == 1 || f.Opcode == 2
		class := "control"
		if data {
			class = "data"
			dataSeq++
		} else {
			controlSeq++
		}
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
			selected := fault.String(params, "frames", "all")
			selectedSeq := frameSeq
			if selected == "data" {
				selectedSeq = dataSeq
			}
			if selected == "control" {
				selectedSeq = controlSeq
			}
			after := fault.Int(params, "after_frames", 1)
			if after < 1 {
				after = 1
			}
			every := fault.Int(params, "every", 1)
			if (selected == "all" || selected == class) && (direction == "both" || direction == dir) && selectedSeq >= uint64(after) && (selectedSeq-uint64(after))%uint64(every) == 0 {
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
		p.publish(gen, "ws_frame", map[string]any{"conn_id": seq, "frame_seq": frameSeq, "data_seq": dataSeq, "control_seq": controlSeq, "class": class, "ts_ms": time.Now().UnixMilli(), "dir": dir, "opcode": f.Opcode, "bytes": len(f.Payload), "fault": action, "fault_type": "ws-glitch", "rule_id": ruleID, "applied": action != "", "action": action, "preview": preview})
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
			dst.truncate(wire[:header+count])
			closeBoth(action)
			return
		}
		if f.Opcode == 8 {
			beginClose()
		}
		if err := dst.write(f); err != nil {
			var protocol *wsframe.ErrProtocol
			if action == "corrupt" && errors.As(err, &protocol) {
				fail(dir, "invalid_after_fault", err)
			}
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
