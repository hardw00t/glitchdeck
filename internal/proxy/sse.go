package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/sse"
)

func selected(params map[string]any, seed uint64, id string, seq uint64, idx int) bool {
	if every := fault.Int(params, "every", 0); every > 0 && idx%every == 0 {
		return true
	}
	switch events := params["events"].(type) {
	case []any:
		for _, v := range events {
			switch n := v.(type) {
			case float64:
				if n == float64(idx) {
					return true
				}
			case int:
				if n == idx {
					return true
				}
			}
		}
	case []int:
		for _, n := range events {
			if n == idx {
				return true
			}
		}
	}
	_, ok := params["probability"]
	return ok && fault.Pick(seed, id, seq, uint64(idx), fault.Int(params, "probability", 0))
}

func requestSSEEnd(end string) string {
	switch end {
	case "done":
		return "complete"
	case "eof_early":
		return "eof"
	default:
		return end
	}
}

type sseResult struct {
	bytes     int64
	events    int
	end, skip string
	applied   bool
	err       error
}

func (p *Proxy) relaySSE(ctx context.Context, w http.ResponseWriter, body io.Reader, rule *fault.Rule, seed, seq, gen uint64, start time.Time, run string) (res sseResult) {
	res.end = "eof"
	kind, action := "", "none"
	faultID := ""
	var params map[string]any
	if rule != nil && rule.Fault.Type == "sse-glitch" {
		faultID = rule.ID
		kind, params = rule.Fault.Type, rule.Fault.Params
		action = fault.String(params, "action", "stall")
		if action == "early_eof" {
			action = "eof_early"
		}
	}
	limit := p.options.SSETelemetryMax
	if limit <= 0 {
		limit = 512
	}
	markApplied := func() {
		if !res.applied {
			res.applied = true
			p.countRule(gen, rule, "applied", "")
		}
	}
	captured := 0
	delivered, maxGap, lastDelivered := 0, int64(0), int64(0)
	deliveredValid, deliveredDone := true, false
	stream := streamFrom(ctx)
	rc := http.NewResponseController(w)
	defer rc.SetWriteDeadline(time.Time{})
	defer func() {
		if kind != "" && !res.applied {
			reason := res.skip
			if reason == "" {
				reason = "not_triggered"
			}
			p.countRule(gen, rule, "skipped", reason)
		}
		p.publish(gen, "sse_event", map[string]any{
			"seq": seq, "stream_id": stream, "run_id": run, "kind": "end", "event_index": 0,
			"ts_ms": time.Now().UnixMilli(), "t_rel_ms": time.Since(start).Milliseconds(),
			"end": res.end, "events": res.events, "duration_ms": time.Since(start).Milliseconds(),
			"event": "", "id": nil, "data_bytes": 0, "raw_bytes": 0, "is_done": res.end == "done",
			"delivered_events": delivered, "delivered_valid_json": deliveredValid, "delivered_done": deliveredDone, "delivered_max_gap_ms": maxGap,
			"applied": res.applied, "fault_id": faultID,
			"fault": kind, "action": "none", "stall_ms": 0, "preview": "",
		})
	}()
	write := func(data []byte) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
		n, err := w.Write(data)
		res.bytes += int64(n)
		if err == nil {
			err = rc.Flush()
		}
		_ = rc.SetWriteDeadline(time.Time{})
		if err != nil && !errors.Is(err, http.ErrNotSupported) {
			res.end, res.err = "client_cancel", err
			return false
		}
		return true
	}
	passThrough := kind == ""
	if passThrough {
		body = io.TeeReader(body, sseWriterFunc(func(data []byte) (int, error) {
			if !write(data) {
				return 0, res.err
			}
			return len(data), nil
		}))
	}
	r := sse.NewReader(body, 0)
	after := fault.Int(params, "after_events", 1)
	every := fault.Int(params, "every", 0)
	eventType := fault.String(params, "event_type", "")
	stallMS := fault.Int(params, "stall_ms", 30000)
	if fault.Bool(params, "forever", false) {
		stallMS = 600000
	}
	stall := func() bool {
		markApplied()
		_ = rc.SetWriteDeadline(time.Time{})
		if !wait(ctx, time.Duration(stallMS)*time.Millisecond) {
			res.end, res.err = "client_cancel", ctx.Err()
			return false
		}
		return true
	}
	if action == "stall" && after == 0 && !stall() {
		return res
	}
	matching := 0
	for {
		f, err := r.Next()
		if err != nil {
			if tail := r.Tail(); !passThrough && len(tail) != 0 && !write(tail) {
				return res
			}
			switch {
			case errors.Is(err, sse.ErrLineTooLong):
				res.skip = "line_too_long"
				if passThrough {
					_, res.err = io.Copy(io.Discard, r)
				} else {
					n, err := io.Copy(flushWriter{w}, r)
					res.bytes, res.err = res.bytes+n, err
				}
			case ctx.Err() != nil:
				res.end, res.err = "client_cancel", ctx.Err()
			case err != io.EOF:
				res.end, res.err = "upstream_error", err
			}
			return res
		}
		eventName := f.Event
		if eventName == "" {
			eventName = "message"
		}
		if f.Dispatch {
			res.events++
		}
		current := "none"
		if f.Dispatch && (eventType == "" || eventType == eventName) {
			matching++
			switch action {
			case "drop", "corrupt_json":
				if !f.IsDone() && selected(params, seed, rule.ID, seq, matching) {
					current = action
				}
			case "truncate":
				if res.events > after {
					current = action
				}
			case "eof_early":
				before := fault.String(params, "before_event", "")
				_, explicit := params["after_events"]
				if before == eventName || before == "" && (explicit && res.events > after || !explicit && f.IsDone()) {
					current = action
				}
			case "stall":
				if matching == after || matching > after && every > 0 && (matching-after)%every == 0 {
					current = action
				}
			}
		}
		raw := f.Raw
		switch current {
		case "corrupt_json":
			rnd := rand.NewPCG(seed^fault.RuleHash(rule.ID), seq<<32|uint64(res.events)).Uint64()
			if v, ok := sse.CorruptJSON(f.Data, fault.String(params, "mode", "cut"), rnd); ok {
				f.Data = v
				raw = sse.Encode(f)
			} else {
				current = "none"
			}
		case "truncate":
			raw = raw[:min(len(raw), fault.Int(params, "cut_bytes", len(raw)/2))]
		}
		if !passThrough && current != "drop" && current != "eof_early" && !write(raw) {
			return res
		}
		if f.Dispatch && current != "drop" && current != "eof_early" && current != "truncate" {
			delivered++
			now := time.Since(start).Milliseconds()
			maxGap = max(maxGap, now-lastDelivered)
			lastDelivered = now
			deliveredDone = deliveredDone || f.IsDone()
			if !f.IsDone() && f.Data != "" && !json.Valid([]byte(f.Data)) {
				deliveredValid = false
			}
		}
		if current != "none" {
			markApplied()
		}
		if captured < limit || current != "none" {
			captured++
			preview := f.Data[:min(len(f.Data), 120)]
			for len(preview) != 0 && !utf8.ValidString(preview) {
				preview = preview[:len(preview)-1]
			}
			frameKind := "event"
			if !f.Dispatch {
				frameKind = "comment"
				if f.Retry != nil {
					frameKind = "retry"
				}
			}
			delay := 0
			if current == "stall" {
				delay = stallMS
			}
			p.publish(gen, "sse_event", map[string]any{
				"seq": seq, "stream_id": stream, "run_id": run, "kind": frameKind,
				"event_index": res.events, "ts_ms": time.Now().UnixMilli(), "t_rel_ms": time.Since(start).Milliseconds(),
				"event": eventName, "id": f.ID, "data_bytes": len(f.Data), "raw_bytes": len(f.Raw), "is_done": f.IsDone(),
				"applied": current != "none", "fault_id": faultID,
				"fault": kind, "action": current, "stall_ms": delay, "preview": preview,
			})
		}
		switch current {
		case "truncate":
			res.end = "rst"
			return res
		case "eof_early":
			res.end = current
			return res
		case "stall":
			if !stall() {
				return res
			}
		}
		if f.IsDone() || f.Event == "message_stop" {
			res.end = "done"
		}
	}
}

type sseWriterFunc func([]byte) (int, error)

func (fn sseWriterFunc) Write(data []byte) (int, error) { return fn(data) }

type hijackedSSEWriter struct {
	out     *bufio.Writer
	conn    net.Conn
	chunked bool
}

func (w *hijackedSSEWriter) Header() http.Header { return nil }
func (w *hijackedSSEWriter) WriteHeader(int)     {}
func (w *hijackedSSEWriter) Write(b []byte) (int, error) {
	if w.chunked {
		if _, err := fmt.Fprintf(w.out, "%x\r\n", len(b)); err != nil {
			return 0, err
		}
	}
	n, err := w.out.Write(b)
	if err == nil && w.chunked {
		_, err = w.out.WriteString("\r\n")
	}
	return n, err
}

func (w *hijackedSSEWriter) Flush()                             { _ = w.out.Flush() }
func (w *hijackedSSEWriter) FlushError() error                  { return w.out.Flush() }
func (w *hijackedSSEWriter) SetWriteDeadline(t time.Time) error { return w.conn.SetWriteDeadline(t) }

func sseNeedsHijack(rule *fault.Rule) bool {
	if rule == nil || rule.Fault.Type != "sse-glitch" {
		return false
	}
	a := fault.String(rule.Fault.Params, "action", "stall")
	return a == "truncate" || (a == "eof_early" || a == "early_eof") && !fault.Bool(rule.Fault.Params, "http_clean", true)
}

func (p *Proxy) relayHijackedSSE(ctx context.Context, w http.ResponseWriter, resp *http.Response, rule *fault.Rule, seed, seq, gen uint64, start time.Time, run string) sseResult {
	conn, b, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return sseResult{end: "upstream_error", err: err}
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	headers := resp.Header.Clone()
	stripHop(headers)
	headers.Del("Content-Length")
	headers.Set("Connection", "close")
	chunked := fault.String(rule.Fault.Params, "action", "stall") != "truncate"
	if chunked {
		headers.Set("Transfer-Encoding", "chunked")
	}
	if run != "" {
		headers.Set("X-Glitchdeck-Seq", strconv.FormatUint(seq, 10))
	}
	if _, err = fmt.Fprintf(b, "HTTP/1.1 %s\r\n", resp.Status); err == nil {
		err = headers.Write(b)
	}
	if err == nil {
		_, err = b.WriteString("\r\n")
	}
	if err == nil {
		err = b.Flush()
	}
	if err != nil {
		return sseResult{end: "client_cancel", err: err}
	}
	out := &hijackedSSEWriter{out: b.Writer, conn: conn, chunked: chunked}
	result := p.relaySSE(ctx, out, resp.Body, rule, seed, seq, gen, start, run)
	if result.end == "rst" && fault.Bool(rule.Fault.Params, "rst", true) {
		rst(conn)
	} else if chunked && result.end != "eof_early" && result.err == nil {
		_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		_, _ = b.WriteString("0\r\n\r\n")
		result.err = b.Flush()
		if result.err != nil {
			result.end = "client_cancel"
		}
	}
	return result
}
