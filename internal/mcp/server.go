package mcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/hardw00t/glitchdeck/internal/demo"
	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/tape"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
	"github.com/hardw00t/glitchdeck/internal/ui"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type Options struct {
	Workdir             string
	Version             string
	CloseOutputOnCancel bool
}
type Server struct {
	in               io.Reader
	out              io.Writer
	opts             Options
	p                *proxy.Proxy
	bus              *telemetry.Bus
	listener         net.Listener
	app              *http.Server
	appListener      net.Listener
	target, proxyURL string
	recording        *ui.Recording
	isDemo           bool
	ctx              context.Context
}

func NewServer(in io.Reader, out io.Writer, opts Options) *Server {
	return &Server{in: in, out: out, opts: opts}
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func (s *Server) Serve() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	s.ctx = ctx
	defer s.stop()
	if s.opts.CloseOutputOnCancel {
		if closer, ok := s.out.(io.Closer); ok {
			done := make(chan struct{})
			exited := make(chan struct{})
			go func() {
				defer close(exited)
				select {
				case <-ctx.Done():
					_ = closer.Close()
				case <-done:
				}
			}()
			defer func() { close(done); <-exited; _ = closer.Close() }()
		}
	}
	type line struct {
		data []byte
		err  error
	}
	lines := make(chan line)
	go func() {
		scanner := bufio.NewScanner(s.in)
		scanner.Buffer(make([]byte, 64<<10), 4<<20)
		for scanner.Scan() {
			b := append([]byte{}, scanner.Bytes()...)
			select {
			case lines <- line{data: b}:
			case <-ctx.Done():
				return
			}
		}
		select {
		case lines <- line{err: scanner.Err()}:
		case <-ctx.Done():
		}
	}()
	enc := json.NewEncoder(s.out)
	for {
		var l line
		select {
		case <-ctx.Done():
			return nil
		case l = <-lines:
		}
		if l.data == nil {
			return l.err
		}
		handle := func(data []byte) map[string]any {
			var r request
			var result any
			var code int
			message := ""
			if !json.Valid(data) {
				code = -32700
				message = "Parse error"
			} else if json.Unmarshal(data, &r) != nil || r.JSONRPC != "2.0" || r.Method == "" || !validID(r.ID) {
				code = -32600
				message = "Invalid Request"
			} else if strings.HasPrefix(r.Method, "notifications/") && len(r.ID) == 0 {
				return nil
			} else {
				func() {
					defer func() {
						if recover() != nil {
							code = -32603
							message = "Internal error"
						}
					}()
					switch r.Method {
					case "initialize":
						var p struct {
							ProtocolVersion string `json:"protocolVersion"`
						}
						if len(r.Params) > 0 && (json.Unmarshal(r.Params, &p) != nil || string(r.Params) == "null") {
							code = -32602
							message = "Invalid params"
							break
						}
						v := p.ProtocolVersion
						if v != "2024-11-05" && v != "2025-03-26" {
							v = "2025-03-26"
						}
						result = map[string]any{"protocolVersion": v, "capabilities": map[string]any{"tools": map[string]any{"listChanged": false}}, "serverInfo": map[string]string{"name": "glitchdeck", "version": s.opts.Version}, "instructions": "Use local tapes and fault rules to reproduce network failures."}
					case "ping":
						result = map[string]any{}
					case "tools/list":
						result = map[string]any{"tools": tools()}
					case "tools/call":
						var p struct {
							Name      string          `json:"name"`
							Arguments json.RawMessage `json:"arguments"`
							Meta      json.RawMessage `json:"_meta"`
						}
						dec := json.NewDecoder(strings.NewReader(string(r.Params)))
						dec.DisallowUnknownFields()
						if dec.Decode(&p) != nil || p.Name == "" {
							code = -32602
							message = "Invalid params"
							break
						}
						var obj map[string]json.RawMessage
						if len(p.Arguments) == 0 {
							p.Arguments = []byte("{}")
						}
						if json.Unmarshal(p.Arguments, &obj) != nil || obj == nil || !validArgs(p.Name, obj) {
							code = -32602
							message = "Invalid params"
							break
						}
						value, invalid := s.call(p.Name, p.Arguments)
						if invalid {
							code = -32602
							message = "Invalid params"
							if p.Name == "tape_validate" {
								message = "Invalid params: supply exactly one of tape_path or tape_yaml"
							}
							break
						}
						b, e := json.Marshal(value)
						if e != nil {
							code = -32603
							message = "Internal error"
							break
						}
						_, isErr := value["error"].(map[string]string)
						result = map[string]any{"content": []any{map[string]string{"type": "text", "text": string(b)}}, "structuredContent": value, "isError": isErr}
					default:
						code = -32601
						message = "Method not found"
					}
				}()
			}
			if len(r.ID) == 0 && code != -32700 && code != -32600 {
				return nil
			}
			id := r.ID
			if len(id) == 0 || !validID(id) {
				id = []byte("null")
			}
			response := map[string]any{"jsonrpc": "2.0", "id": id}
			if code != 0 {
				response["error"] = map[string]any{"code": code, "message": message}
			} else {
				response["result"] = result
			}
			return response
		}
		var response any
		trimmed := strings.TrimSpace(string(l.data))
		if strings.HasPrefix(trimmed, "[") && json.Valid(l.data) {
			var batch []json.RawMessage
			_ = json.Unmarshal(l.data, &batch)
			if len(batch) == 0 {
				response = map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32600, "message": "Invalid Request"}}
			} else {
				replies := make([]map[string]any, 0, len(batch))
				for _, item := range batch {
					if reply := handle(item); reply != nil {
						replies = append(replies, reply)
					}
				}
				if len(replies) > 0 {
					response = replies
				}
			}
		} else if reply := handle(l.data); reply != nil {
			response = reply
		}
		if response != nil {
			if err := enc.Encode(response); err != nil {
				return err
			}
		}
	}
}
func validID(id json.RawMessage) bool {
	if len(id) == 0 {
		return true
	}
	var x any
	d := json.NewDecoder(strings.NewReader(string(id)))
	d.UseNumber()
	if d.Decode(&x) != nil {
		return false
	}
	switch v := x.(type) {
	case string:
		return true
	case json.Number:
		_, err := v.Int64()
		return err == nil
	}
	return false
}
func fail(code, msg string) map[string]any {
	return map[string]any{"error": map[string]string{"code": code, "message": msg}}
}
func (s *Server) stop() {
	if s.listener != nil {
		_ = s.listener.Close()
		s.listener = nil
	}
	if s.p != nil {
		s.p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = s.p.Wait(ctx)
		cancel()
		s.p = nil
	}
	if s.recording != nil {
		s.recording.Stop()
		s.recording = nil
	}
	if s.app != nil {
		if closer, ok := s.app.Handler.(io.Closer); ok {
			_ = closer.Close()
		}
		_ = s.app.Close()
		s.app = nil
	}
	if s.appListener != nil {
		_ = s.appListener.Close()
		s.appListener = nil
	}
	s.isDemo = false
}
func (s *Server) call(name string, raw []byte) (map[string]any, bool) {
	switch name {
	case "proxy_start":
		var a struct {
			Target   string  `json:"target"`
			Listen   string  `json:"listen"`
			Seed     *uint64 `json:"seed"`
			TapePath string  `json:"tape_path"`
			Record   bool    `json:"record"`
		}
		if json.Unmarshal(raw, &a) != nil || a.Target == "" {
			return nil, true
		}
		if s.p != nil {
			return fail("PROXY_ALREADY_RUNNING", s.proxyURL), false
		}
		if a.Listen == "" {
			a.Listen = "127.0.0.1:0"
		}
		host, _, err := net.SplitHostPort(a.Listen)
		if err != nil || (host != "localhost" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback())) {
			return fail("INVALID_TARGET", "listener must be loopback"), false
		}
		cfg := fault.Config{Seed: 1}
		if a.Seed != nil {
			cfg.Seed = *a.Seed
		}
		if a.TapePath != "" {
			t, e := s.readTape(a.TapePath)
			if e != nil {
				return fail("INVALID_TAPE", e.Error()), false
			}
			cfg = fault.Config{Seed: t.Seed, Rules: t.Rules}
		}
		target := a.Target
		s.isDemo = target == "demo"
		if s.isDemo {
			l, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				return fail("INVALID_TARGET", e.Error()), false
			}
			s.appListener = l
			s.app = &http.Server{Handler: demo.New(), Protocols: demo.Protocols()}
			go s.app.Serve(l)
			target = "http://" + l.Addr().String()
		}
		u, e := proxy.ParseTarget(target)
		if e != nil {
			s.stop()
			return fail("INVALID_TARGET", e.Error()), false
		}
		l, e := net.Listen("tcp", a.Listen)
		if e != nil {
			s.stop()
			return fail("INVALID_TARGET", e.Error()), false
		}
		s.listener = l
		s.bus = telemetry.New()
		s.p = proxy.New(u, cfg, s.bus)
		s.p.SetOptions(proxy.Options{Demo: s.isDemo})
		s.target = target
		s.proxyURL = "http://" + l.Addr().String()
		if a.Record {
			s.recording = ui.NewRecorder()
			s.recording.Start(s.p)
		}
		go s.p.Serve(l)
		return map[string]any{"running": true, "proxy_url": s.proxyURL, "target_url": target, "demo": s.isDemo, "seed": cfg.Seed, "seq": 0, "rules_count": len(cfg.Rules), "recording": a.Record}, false
	case "proxy_stop":
		was := s.p != nil
		seq := uint64(0)
		events, steps := 0, 0
		if was {
			seq = s.p.Seq()
			events = len(s.bus.History(4096))
			if s.recording != nil {
				if t, e := s.recording.Export("session"); e == nil {
					steps = len(t.Script)
				}
			}
		}
		s.stop()
		return map[string]any{"was_running": was, "seq_count": seq, "events_captured": events, "recorded_steps": steps}, false
	case "fault_set":
		var a struct {
			Mode  string       `json:"mode"`
			Seed  *uint64      `json:"seed"`
			Rules []fault.Rule `json:"rules"`
		}
		if json.Unmarshal(raw, &a) != nil || len(a.Rules) == 0 || (a.Mode != "" && a.Mode != "upsert" && a.Mode != "replace") {
			return nil, true
		}
		if s.p == nil {
			return fail("PROXY_NOT_RUNNING", "start a proxy first"), false
		}
		cfg := s.p.Config()
		if a.Seed != nil {
			cfg.Seed = *a.Seed
		}
		if a.Mode == "replace" {
			cfg.Rules = a.Rules
		} else {
			for _, r := range a.Rules {
				found := false
				for i := range cfg.Rules {
					if cfg.Rules[i].ID == r.ID {
						cfg.Rules[i] = r
						found = true
						break
					}
				}
				if !found {
					cfg.Rules = append(cfg.Rules, r)
				}
			}
		}
		if len(cfg.Rules) > 64 {
			return fail("INVALID_RULE", "at most 64 rules are allowed"), false
		}
		if e := fault.Validate(cfg); e != nil {
			return fail("INVALID_RULE", e.Error()), false
		}
		seq := s.p.SetConfigAt(cfg)
		if s.recording != nil {
			s.recording.ConfigChanged(seq, cfg)
		}
		return faultSummary(cfg, seq), false
	case "fault_clear":
		var a struct {
			RuleIDs  []string `json:"rule_ids"`
			ResetBus bool     `json:"reset_bus"`
		}
		if json.Unmarshal(raw, &a) != nil {
			return nil, true
		}
		if s.p == nil {
			return fail("PROXY_NOT_RUNNING", "start a proxy first"), false
		}
		cfg := s.p.Config()
		kept := cfg.Rules[:0]
		for _, r := range cfg.Rules {
			keep := a.RuleIDs != nil
			for _, id := range a.RuleIDs {
				if id == r.ID {
					keep = false
				}
			}
			if keep {
				kept = append(kept, r)
			}
		}
		cfg.Rules = kept
		seq := s.p.SetConfigAt(cfg)
		if a.ResetBus {
			s.bus.Clear()
		}
		if s.recording != nil {
			s.recording.ConfigChanged(seq, cfg)
		}
		return faultSummary(cfg, seq), false
	case "wire_events":
		var a struct {
			SinceID     uint64 `json:"since_id"`
			Limit       int    `json:"limit"`
			Type        string `json:"type"`
			FaultedOnly bool   `json:"faulted_only"`
		}
		if json.Unmarshal(raw, &a) != nil || a.Limit < 0 || a.Limit > 100 {
			return nil, true
		}
		if s.p == nil {
			return fail("PROXY_NOT_RUNNING", "start a proxy first"), false
		}
		if a.Limit == 0 {
			a.Limit = 25
		}
		events := []any{}
		next := a.SinceID
		truncated := false
		for _, event := range s.bus.History(4096) {
			if event.ID <= a.SinceID || (a.Type != "" && a.Type != "all" && event.Type != a.Type) {
				continue
			}
			var d map[string]any
			_ = json.Unmarshal(event.Data, &d)
			faultName, _ := d["fault"].(string)
			applied, known := d["applied"].(bool)
			if a.FaultedOnly && ((known && !applied) || (!known && faultName == "" && d["fault_id"] == nil)) {
				continue
			}
			if len(events) == a.Limit {
				truncated = true
				break
			}
			item := map[string]any{"id": event.ID, "type": event.Type}
			for _, k := range []string{"seq", "conn_id", "frame_seq", "method", "path", "status", "http_status", "grpc_status", "grpc_status_name", "latency_ms", "fault_id", "rule_id", "fault_type", "error", "action", "fault_action", "dir", "applied"} {
				if v, ok := d[k]; ok {
					if str, ok := v.(string); ok && len(str) > 256 {
						v = str[:256]
					}
					item[k] = v
				}
			}
			if id, ok := d["rule_id"]; ok {
				item["fault_id"] = id
			}
			if faultName != "" && item["fault_type"] == nil {
				item["fault_type"] = faultName
			}
			events = append(events, item)
			next = event.ID
		}
		return map[string]any{"events": events, "count": len(events), "next_since_id": next, "truncated": truncated}, false
	case "tape_validate":
		var a struct {
			Path *string `json:"tape_path"`
			YAML *string `json:"tape_yaml"`
		}
		if json.Unmarshal(raw, &a) != nil || (a.Path == nil) == (a.YAML == nil) {
			return nil, true
		}
		var t tape.Tape
		var err error
		if a.Path != nil {
			t, err = s.readTape(*a.Path)
		} else {
			t, err = tape.Decode(strings.NewReader(*a.YAML))
		}
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}, false
		}
		return map[string]any{"ok": true, "version": t.Version, "name": t.Name, "rules": len(t.Rules)}, false
	case "tape_run":
		var a struct {
			TapePath  string `json:"tape_path"`
			TapeYAML  string `json:"tape_yaml"`
			Target    string `json:"target"`
			TimeoutMS int    `json:"timeout_ms"`
		}
		if json.Unmarshal(raw, &a) != nil || (a.TapePath == "") == (a.TapeYAML == "") || len(a.TapeYAML) > 1<<20 {
			return nil, true
		}
		var t tape.Tape
		var e error
		if a.TapePath != "" {
			t, e = s.readTape(a.TapePath)
		} else {
			t, e = tape.Decode(strings.NewReader(a.TapeYAML))
		}
		if e != nil {
			return fail("INVALID_TAPE", e.Error()), false
		}
		if len(t.UpstreamAllow) > 0 {
			return fail("INVALID_TAPE", "MCP tapes cannot expand the loopback egress policy"), false
		}
		if a.TimeoutMS == 0 {
			a.TimeoutMS = 30000
		}
		ctx, cancel := context.WithTimeout(s.ctx, time.Duration(a.TimeoutMS)*time.Millisecond)
		defer cancel()
		start := time.Now()
		results, report, e := tape.RunWithReport(ctx, t, a.Target)
		if ctx.Err() != nil {
			return fail("TIMEOUT", ctx.Err().Error()), false
		}
		if e != nil {
			return fail("INVALID_TAPE", e.Error()), false
		}
		assertions := []any{}
		failed := 0
		for _, r := range results {
			ok := len(r.Failures) == 0
			if !ok {
				failed++
			}
			failures := r.Failures
			if failures == nil {
				failures = []string{}
			}
			assertions = append(assertions, map[string]any{"name": r.Name, "passed": ok, "failures": failures})
		}
		code := 0
		if failed > 0 {
			code = 1
		}
		target := t.Target
		if a.Target != "" {
			target = a.Target
		}
		name := a.TapePath
		if name == "" {
			name = t.Name
		}
		triggered := []any{}
		var total uint64
		for _, applied := range report.AppliedFaults {
			triggered = append(triggered, map[string]any{"rule_id": applied.RuleID, "type": applied.Type, "count": applied.Count})
			total += applied.Count
		}
		return map[string]any{"schema_version": 2, "command": "test", "ok": code == 0, "exit_code": code, "tape": name, "target": target, "duration_ms": time.Since(start).Milliseconds(), "summary": map[string]any{"assertions_total": len(results), "assertions_failed": failed, "assertions_passed": len(results) - failed, "requests_total": report.RequestsTotal, "faults_triggered": total}, "faults_triggered": triggered, "assertions": assertions, "error": nil}, false
	case "tape_export":
		var a struct {
			Name    string `json:"name"`
			OutPath string `json:"out_path"`
		}
		if json.Unmarshal(raw, &a) != nil || a.Name == "" {
			return nil, true
		}
		if s.p == nil || s.recording == nil {
			return fail("PROXY_NOT_RUNNING", "start recording first"), false
		}
		t, e := s.recording.Export(a.Name)
		if e != nil {
			return fail("INVALID_TAPE", e.Error()), false
		}
		if s.isDemo {
			t.Target = "demo"
		} else {
			t.Target = s.target
		}
		var b strings.Builder
		if e = tape.Encode(&b, t); e != nil {
			return fail("INVALID_TAPE", e.Error()), false
		}
		res := map[string]any{"name": a.Name, "steps": len(t.Script), "rules": len(t.Rules), "incomplete": t.Incomplete}
		if a.OutPath == "" {
			if b.Len() > 64<<10 {
				return fail("INVALID_PATH", "use out_path for large tapes"), false
			}
			res["yaml"] = b.String()
		} else {
			path, e := s.outputPath(a.OutPath)
			if b.Len() > 1<<20 {
				return fail("INVALID_TAPE", "tape exceeds 1 MiB"), false
			}
			if e != nil {
				return fail("INVALID_PATH", e.Error()), false
			}
			if e = s.writeTape(path, []byte(b.String())); e != nil {
				return fail("INVALID_PATH", e.Error()), false
			}
			res["out_path"] = path
		}
		return res, false
	case "demo_trigger":
		var a struct {
			Action  string `json:"action"`
			OrderID string `json:"order_id"`
			Amount  *int   `json:"amount_cents"`
			Frames  int    `json:"frames"`
		}
		if json.Unmarshal(raw, &a) != nil || a.Action == "" || a.Frames < 0 || a.Frames > 50 {
			return nil, true
		}
		if s.p == nil || !s.isDemo {
			return fail("DEMO_NOT_ACTIVE", "start demo proxy first"), false
		}
		if a.OrderID == "" {
			a.OrderID = "ord-1"
		}
		amount := 9900
		if a.Amount != nil {
			amount = *a.Amount
		}
		status := 200
		errorText := ""
		if a.Action == "ticker" {
			if a.Frames == 0 {
				a.Frames = 3
			}
			if e := s.ticker(a.Frames); e != nil {
				errorText = e.Error()
			}
		} else {
			path := "/api/state"
			method := "GET"
			body := ""
			switch a.Action {
			case "checkout":
				path = "/checkout"
				method = "POST"
			case "webhook":
				path = "/webhooks/payment"
				method = "POST"
			case "reset":
				path = "/api/reset"
				method = "POST"
			case "state":
			default:
				return nil, true
			}
			if method == "POST" {
				b, _ := json.Marshal(map[string]any{"order_id": a.OrderID, "amount_cents": amount})
				body = string(b)
			}
			req, _ := http.NewRequestWithContext(s.ctx, method, s.proxyURL+path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			client := http.Client{Timeout: 5 * time.Second}
			resp, e := client.Do(req)
			if e != nil {
				status = 0
				errorText = e.Error()
			} else {
				status = resp.StatusCode
				if _, e := io.Copy(io.Discard, resp.Body); e != nil {
					errorText = e.Error()
				}
				resp.Body.Close()
			}
		}
		if a.Action == "webhook" {
			ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
			defer cancel()
			if err := s.p.Wait(ctx); err != nil {
				return fail("TIMEOUT", err.Error()), false
			}
		}
		client := http.Client{Timeout: 5 * time.Second}
		stateReq, _ := http.NewRequestWithContext(s.ctx, http.MethodGet, s.target+"/api/summary", nil)
		stateResp, e := client.Do(stateReq)
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				return fail("TIMEOUT", e.Error()), false
			}
			return fail("DEMO_ERROR", e.Error()), false
		}
		defer stateResp.Body.Close()
		var state any
		if e := json.NewDecoder(stateResp.Body).Decode(&state); e != nil {
			return fail("DEMO_ERROR", e.Error()), false
		}
		return map[string]any{"action": a.Action, "status": status, "error": errorText, "state": state}, false
	default:
		return nil, true
	}
}
func faultSummary(c fault.Config, seq uint64) map[string]any {
	ids := []string{}
	for _, r := range c.Rules {
		if r.Enabled {
			ids = append(ids, r.ID)
		}
	}
	return map[string]any{"seed": c.Seed, "rules_count": len(c.Rules), "active_rule_ids": ids, "effective_from_seq": seq}
}
func (s *Server) path(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(s.opts.Workdir, p)
}

func (s *Server) readTape(path string) (tape.Tape, error) {
	base := s.opts.Workdir
	if base == "" {
		base = "."
	}
	if filepath.IsAbs(path) {
		abs, err := filepath.Abs(base)
		if err != nil {
			return tape.Tape{}, err
		}
		path, err = filepath.Rel(abs, path)
		if err != nil {
			return tape.Tape{}, err
		}
	}
	if !filepath.IsLocal(path) {
		return tape.Tape{}, fmt.Errorf("tape path is empty or escapes workdir")
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return tape.Tape{}, err
	}
	defer root.Close()
	f, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return tape.Tape{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return tape.Tape{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return tape.Tape{}, fmt.Errorf("tape must be a regular file of at most 1 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return tape.Tape{}, err
	}
	if len(data) > 1<<20 {
		return tape.Tape{}, fmt.Errorf("tape exceeds 1 MiB")
	}
	return tape.Decode(strings.NewReader(string(data)))
}

func (s *Server) writeTape(path string, data []byte) error {
	base := s.opts.Workdir
	if base == "" {
		base = "."
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return err
	}
	defer root.Close()
	base, err = filepath.Abs(base)
	if err != nil {
		return err
	}
	base, err = filepath.EvalSymlinks(base)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(rel), ".glitchdeck-"+rand.Text())
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(tmp)
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return root.Rename(tmp, rel)
}
func (s *Server) outputPath(p string) (string, error) {
	if strings.ContainsRune(p, 0) || (filepath.Ext(p) != ".yaml" && filepath.Ext(p) != ".yml") {
		return "", fmt.Errorf("output must be YAML")
	}
	base := s.opts.Workdir
	if base == "" {
		base = "."
	}
	base, e := filepath.Abs(base)
	if e != nil {
		return "", e
	}
	base, e = filepath.EvalSymlinks(base)
	if e != nil {
		return "", e
	}
	target := s.path(p)
	parent, e := filepath.EvalSymlinks(filepath.Dir(target))
	if e != nil {
		return "", e
	}
	parent, e = filepath.Abs(parent)
	if e != nil {
		return "", e
	}
	rel, e := filepath.Rel(base, parent)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("output outside workdir")
	}
	dest := filepath.Join(parent, filepath.Base(target))
	if info, e := os.Lstat(dest); e == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("output is symlink")
	}
	return dest, nil
}
