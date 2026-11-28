package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
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
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Options struct {
	Workdir             string
	Version             string
	CloseOutputOnCancel bool
	AllowExec           bool
	UpstreamAllow       []string
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
	mu               sync.Mutex
	job              *job
	writeMu          sync.Mutex
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
	write := func(response any) error {
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
		return enc.Encode(response)
	}
	writeErrors := make(chan error, 1)
	writeAsync := func(response any) {
		if err := write(response); err != nil {
			select {
			case writeErrors <- err:
			default:
			}
		}
	}
	defer s.shutdownJob()
	for {
		var l line
		select {
		case <-ctx.Done():
			return nil
		case err := <-writeErrors:
			return err
		case l = <-lines:
		}
		if l.data == nil {
			if l.err != nil {
				return l.err
			}
			if j := s.runningJob(); j != nil {
				select {
				case <-ctx.Done():
					return nil
				case <-j.done:
				}
			}
			select {
			case err := <-writeErrors:
				return err
			default:
			}
			return l.err
		}
		handle := func(data []byte, batch bool) map[string]any {
			var r request
			var result any
			var code int
			message := ""
			var params *paramError
			dispatched := false
			if !json.Valid(data) {
				code = -32700
				message = "Parse error"
			} else if json.Unmarshal(data, &r) != nil || r.JSONRPC != "2.0" || r.Method == "" || !validID(r.ID) {
				code = -32600
				message = "Invalid Request"
			} else if strings.HasPrefix(r.Method, "notifications/") && len(r.ID) == 0 {
				if r.Method == "notifications/cancelled" {
					s.cancelJob(r.Params)
				}
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
							params = &paramError{Field: "params", Reason: "malformed"}
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
						catalog := tools()
						for _, tool := range catalog {
							switch tool["name"] {
							case "fault_set":
								tool["_meta"] = map[string]any{"faultCatalog": fault.Registry}
							case "exec_run":
								tool["_meta"] = map[string]any{"execEnabled": s.opts.AllowExec}
							}
						}
						result = map[string]any{"tools": catalog}
					case "tools/call":
						var p struct {
							Name      string          `json:"name"`
							Arguments json.RawMessage `json:"arguments"`
							Meta      json.RawMessage `json:"_meta"`
						}
						dec := json.NewDecoder(bytes.NewReader(r.Params))
						dec.DisallowUnknownFields()
						if dec.Decode(&p) != nil || p.Name == "" {
							params = &paramError{Field: "params", Reason: "malformed"}
							break
						}
						if len(p.Arguments) == 0 {
							p.Arguments = []byte("{}")
						}
						params = validArgs(p.Name, p.Arguments)
						if params != nil {
							break
						}
						var value map[string]any
						switch p.Name {
						case "exec_run", "tape_run":
							var run jobRun
							switch {
							case batch && p.Name == "exec_run":
								params = &paramError{Field: "arguments", Reason: "not_batchable"}
							case p.Name == "exec_run" && !s.opts.AllowExec:
								value = fail("EXEC_DISABLED", "exec_run is disabled; restart the server as `glitchdeck mcp --allow-exec` to let this client run commands")
							default:
								if id, busy := s.busyJob(); busy {
									value = fail("BUSY", "request "+id+" is still running")
								} else if p.Name == "exec_run" {
									run, value, params = s.prepareExec(p.Arguments)
								} else {
									run, value, params = s.prepareTapeRun(p.Arguments)
								}
							}
							if run != nil {
								if batch {
									value = run(ctx)
								} else {
									s.startJob(r.ID, p.Name, run, writeAsync)
									dispatched = true
									return
								}
							}
						default:
							value, params = s.call(p.Name, p.Arguments)
						}
						if params != nil {
							params.Tool = p.Name
							break
						}
						result = toolResult(p.Name, value)
					default:
						code = -32601
						message = "Method not found"
					}
				}()
			}
			if dispatched || len(r.ID) == 0 && code != -32700 && code != -32600 {
				return nil
			}
			id := r.ID
			if len(id) == 0 || !validID(id) {
				id = []byte("null")
			}
			if params != nil && code == 0 {
				return rpcError(id, -32602, params.message(), params)
			}
			if code != 0 {
				return rpcError(id, code, message, nil)
			}
			return map[string]any{"jsonrpc": "2.0", "id": id, "result": result}
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
					if reply := handle(item, true); reply != nil {
						replies = append(replies, reply)
					}
				}
				if len(replies) > 0 {
					response = replies
				}
			}
		} else if reply := handle(l.data, false); reply != nil {
			response = reply
		}
		if ctx.Err() != nil {
			return nil
		}
		if response != nil {
			if err := write(response); err != nil {
				return err
			}
		}
	}
}

func rpcError(id json.RawMessage, code int, message string, data *paramError) map[string]any {
	e := map[string]any{"code": code, "message": message}
	if data != nil {
		e["data"] = data
	}
	return map[string]any{"jsonrpc": "2.0", "id": id, "error": e}
}

func toolResult(name string, value map[string]any) map[string]any {
	b, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	_, isErr := value["error"].(map[string]string)
	if name == "tape_validate" && value["ok"] == false {
		isErr = true
	}
	return map[string]any{"content": []any{map[string]string{"type": "text", "text": string(b)}}, "structuredContent": value, "isError": isErr}
}

func toolResponse(id json.RawMessage, name string, value map[string]any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "result": toolResult(name, value)}
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
func (s *Server) call(name string, raw []byte) (map[string]any, *paramError) {
	switch name {
	case "proxy_start":
		var a struct {
			Target   string  `json:"target"`
			Listen   string  `json:"listen"`
			Seed     *uint64 `json:"seed"`
			TapePath string  `json:"tape_path"`
			Record   bool    `json:"record"`
		}
		if json.Unmarshal(raw, &a) != nil {
			return nil, malformedArgs()
		}
		if a.Target == "" {
			return nil, &paramError{Field: "arguments.target", Reason: "invalid_value"}
		}
		if s.p != nil {
			return fail("PROXY_ALREADY_RUNNING", s.proxyURL), nil
		}
		if a.Listen == "" {
			a.Listen = "127.0.0.1:0"
		}
		host, _, err := net.SplitHostPort(a.Listen)
		if err != nil || (host != "localhost" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback())) {
			return fail("INVALID_TARGET", "listener must be loopback"), nil
		}
		cfg := fault.Config{Seed: 1}
		if a.Seed != nil {
			cfg.Seed = *a.Seed
		}
		var ignoreJSONPaths []string
		if a.TapePath != "" {
			t, e := s.readTape(a.TapePath)
			if e != nil {
				return fail("INVALID_TAPE", e.Error()), nil
			}
			cfg = fault.Config{Seed: t.Seed, Rules: t.Rules}
			ignoreJSONPaths = t.IgnoreJSONPaths
		}
		target := a.Target
		s.isDemo = target == "demo"
		if s.isDemo {
			l, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				return fail("INVALID_TARGET", e.Error()), nil
			}
			s.appListener = l
			s.app = &http.Server{Handler: demo.New(), Protocols: demo.Protocols()}
			go s.app.Serve(l)
			target = "http://" + l.Addr().String()
		}
		u, e := proxy.ParseTarget(target)
		if e != nil {
			s.stop()
			return fail("INVALID_TARGET", e.Error()), nil
		}
		l, e := net.Listen("tcp", a.Listen)
		if e != nil {
			s.stop()
			return fail("INVALID_TARGET", e.Error()), nil
		}
		s.listener = l
		s.bus = telemetry.New()
		s.p = proxy.New(u, cfg, s.bus)
		s.p.SetOptions(proxy.Options{Demo: s.isDemo})
		s.target = target
		s.proxyURL = "http://" + l.Addr().String()
		if a.Record {
			s.recording = ui.NewRecorder()
			s.recording.SetCassetteMetadata(target, ignoreJSONPaths)
			if s.isDemo {
				s.recording.SetDemoHTTPAuthority(u.Host)
			}
			s.recording.Start(s.p)
		}
		go s.p.Serve(l)
		return map[string]any{"running": true, "proxy_url": s.proxyURL, "target_url": target, "demo": s.isDemo, "seed": cfg.Seed, "seq": 0, "rules_count": len(cfg.Rules), "recording": a.Record}, nil
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
		return map[string]any{"was_running": was, "seq_count": seq, "events_captured": events, "recorded_steps": steps}, nil
	case "fault_set":
		var a struct {
			Mode  string       `json:"mode"`
			Seed  *uint64      `json:"seed"`
			Rules []fault.Rule `json:"rules"`
		}
		if json.Unmarshal(raw, &a) != nil {
			return nil, malformedArgs()
		}
		if s.p == nil {
			return fail("PROXY_NOT_RUNNING", "start a proxy first"), nil
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
			return fail("INVALID_RULE", "at most 64 rules are allowed"), nil
		}
		if e := fault.Validate(cfg); e != nil {
			return fail("INVALID_RULE", e.Error()), nil
		}
		seq := s.p.SetConfigAt(cfg)
		if s.recording != nil {
			s.recording.ConfigChanged(seq, cfg)
		}
		return faultSummary(cfg, seq), nil
	case "fault_clear":
		var a struct {
			RuleIDs  []string `json:"rule_ids"`
			ResetBus bool     `json:"reset_bus"`
		}
		if json.Unmarshal(raw, &a) != nil {
			return nil, malformedArgs()
		}
		if s.p == nil {
			return fail("PROXY_NOT_RUNNING", "start a proxy first"), nil
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
		return faultSummary(cfg, seq), nil
	case "wire_events":
		var a struct {
			SinceID     uint64 `json:"since_id"`
			Limit       int    `json:"limit"`
			Type        string `json:"type"`
			FaultedOnly bool   `json:"faulted_only"`
		}
		if json.Unmarshal(raw, &a) != nil {
			return nil, malformedArgs()
		}
		if s.p == nil {
			return fail("PROXY_NOT_RUNNING", "start a proxy first"), nil
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
			for _, k := range []string{"data_seq", "control_seq", "limit_bytes", "ts_ms", "replay_index", "committed_status"} {
				if v, ok := d[k].(float64); ok && v >= 0 {
					item[k] = v
				}
			}
			if _, ok := d["declared_bytes"]; ok {
				var declared struct {
					Bytes json.Number `json:"declared_bytes"`
				}
				if json.Unmarshal(event.Data, &declared) == nil && declared.Bytes != "" {
					if n, err := strconv.ParseUint(string(declared.Bytes), 10, 64); err == nil {
						item["declared_bytes"] = n
					}
				}
			}
			for k, allowed := range map[string][]string{
				"class":            {"data", "control"},
				"replay_mode":      {"sequential", "concurrent", "timeout_retry"},
				"outcome":          {"ok", "conflict", "client_error", "server_error", "timeout", "transport_error", "canceled", "capacity_exceeded", "egress_denied"},
				"original_outcome": {"timeout", "transport_error"},
			} {
				if v, ok := d[k].(string); ok {
					for _, candidate := range allowed {
						if v == candidate {
							item[k] = v
							break
						}
					}
				}
			}
			if event.Type == "tls_handshake_failed" {
				item["host"], item["sni"] = d["host"], d["sni"]
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
		return map[string]any{"events": events, "count": len(events), "next_since_id": next, "truncated": truncated}, nil
	case "tape_validate":
		var a struct {
			Path *string `json:"tape_path"`
			YAML *string `json:"tape_yaml"`
		}
		if json.Unmarshal(raw, &a) != nil {
			return nil, malformedArgs()
		}
		if (a.Path == nil) == (a.YAML == nil) {
			return nil, tapeChoiceError()
		}
		var t tape.Tape
		var err error
		if a.Path != nil {
			t, err = s.readTape(*a.Path)
		} else {
			t, err = tape.Decode(strings.NewReader(*a.YAML))
		}
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}, nil
		}
		return map[string]any{"ok": true, "version": t.Version, "name": t.Name, "rules": len(t.Rules)}, nil
	case "tape_export":
		var a struct {
			Name          string `json:"name"`
			OutPath       string `json:"out_path"`
			RedactSecrets bool   `json:"redact_secrets"`
			Format        string `json:"format"`
		}
		if json.Unmarshal(raw, &a) != nil {
			return nil, malformedArgs()
		}
		if s.p == nil || s.recording == nil {
			return fail("PROXY_NOT_RUNNING", "start recording first"), nil
		}
		t, e := s.recording.Export(a.Name)
		if e != nil {
			var blocked *tape.ExportBlockedError
			if errors.As(e, &blocked) {
				return fail("EXPORT_BLOCKED", e.Error()), nil
			}
			return fail("INVALID_TAPE", e.Error()), nil
		}
		hasCassettes := len(t.Cassettes) != 0
		if s.isDemo {
			t.Target = "demo"
		} else {
			t.Target = s.target
		}
		t, e = tape.PrepareExport(t, a.RedactSecrets)
		if e != nil {
			var blocked *tape.ExportBlockedError
			if errors.As(e, &blocked) {
				return fail("EXPORT_BLOCKED", e.Error()), nil
			}
			return fail("INVALID_TAPE", e.Error()), nil
		}
		if a.OutPath != "" && hasCassettes {
			return fail("INVALID_PATH", "cassette exports are inline only"), nil
		}
		if a.Format == "v1" || a.Format == "v2" {
			if a.Format == "v1" && usesV2(t) {
				return fail("VERSION_CONFLICT", `recording uses v2-only features; export with format "v2"`), nil
			}
			markLegacyForwardIncomplete(&t)
			t.Cassettes, t.IgnoreJSONPaths = nil, nil
			if a.Format == "v1" {
				t.Version = 1
			} else {
				t.Version = 2
			}
		} else if len(t.Cassettes) != 0 {
			t.Version = 3
		} else {
			t.Version = 2
		}
		limit := 64 << 10
		if a.OutPath != "" {
			limit = 1 << 20
		}
		b, e := encodeExport(&t, limit)
		if e != nil {
			if e == errExportSize {
				if a.OutPath == "" {
					return fail("INVALID_PATH", "use out_path for large tapes"), nil
				}
				return fail("INVALID_TAPE", "tape exceeds 1 MiB"), nil
			}
			return fail("INVALID_TAPE", e.Error()), nil
		}
		_, decodeErr := tape.Decode(strings.NewReader(b))
		if a.Format != "v1" && decodeErr != nil && !t.Incomplete {
			return fail("INVALID_TAPE", "recording did not encode a valid tape"), nil
		}
		res := map[string]any{"name": t.Name, "steps": len(t.Script), "rules": len(t.Rules), "incomplete": t.Incomplete, "version": t.Version, "replayable": !t.Incomplete && decodeErr == nil}
		if t.Truncated {
			res["truncated"], res["dropped_entries"] = true, t.DroppedEntries
		}
		if t.OmittedBodyBytes > 0 {
			res["omitted_body_bytes"] = t.OmittedBodyBytes
		}
		if a.OutPath == "" {
			res["yaml"] = b
		} else {
			path, e := s.outputPath(a.OutPath)
			if e != nil {
				return fail("INVALID_PATH", e.Error()), nil
			}
			base := s.opts.Workdir
			if base == "" {
				base = "."
			}
			base, e = filepath.Abs(base)
			if e == nil {
				base, e = filepath.EvalSymlinks(base)
			}
			var relative string
			if e == nil {
				relative, e = filepath.Rel(base, path)
			}
			if e != nil {
				return fail("INVALID_PATH", e.Error()), nil
			}
			if e = s.writeTape(path, []byte(b)); e != nil {
				return fail("INVALID_PATH", e.Error()), nil
			}
			res["out_path"] = path
			res["tape_path"] = relative
		}
		if t.Truncated {
			LogDiagnostic(fmt.Sprintf("tape export truncated: dropped_entries=%d", t.DroppedEntries))
		}
		return res, nil
	case "demo_trigger":
		var a struct {
			Action  string `json:"action"`
			OrderID string `json:"order_id"`
			Amount  *int   `json:"amount_cents"`
			Frames  int    `json:"frames"`
		}
		if json.Unmarshal(raw, &a) != nil {
			return nil, malformedArgs()
		}
		if s.p == nil || !s.isDemo {
			return fail("DEMO_NOT_ACTIVE", "start demo proxy first"), nil
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
				return nil, &paramError{Field: "arguments.action", Reason: "invalid_value"}
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
				return fail("TIMEOUT", err.Error()), nil
			}
		}
		client := http.Client{Timeout: 5 * time.Second}
		stateReq, _ := http.NewRequestWithContext(s.ctx, http.MethodGet, s.target+"/api/summary", nil)
		stateResp, e := client.Do(stateReq)
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				return fail("TIMEOUT", e.Error()), nil
			}
			return fail("DEMO_ERROR", e.Error()), nil
		}
		defer stateResp.Body.Close()
		var state any
		if e := json.NewDecoder(stateResp.Body).Decode(&state); e != nil {
			return fail("DEMO_ERROR", e.Error()), nil
		}
		return map[string]any{"action": a.Action, "status": status, "error": errorText, "state": state}, nil
	default:
		return nil, &paramError{Field: "name", Reason: "unknown_tool"}
	}
}

func markLegacyForwardIncomplete(t *tape.Tape) {
	if t.Incomplete {
		return
	}
	for _, step := range t.Script {
		raw := ""
		if step.HTTP != nil {
			raw = step.HTTP.URL
		} else if step.Stream != nil {
			raw = step.Stream.URL
		}
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || !strings.EqualFold(u.Hostname(), "localhost") && !net.ParseIP(u.Hostname()).IsLoopback() {
			t.Incomplete = true
			t.IncompleteReason = "forwarded traffic requires explicit upstream authorization for replay"
			return
		}
	}
}

func usesV2(t tape.Tape) bool {
	if t.TLSMITM {
		return true
	}
	for _, step := range t.Script {
		if step.Stream != nil || step.GRPC != nil || step.HTTP != nil && (step.HTTP.URL != "" || step.HTTP.Proto != "") {
			return true
		}
	}
	check := func(rules []fault.Rule) bool {
		for _, r := range rules {
			if r.Fault.Type == "sse-glitch" || r.Fault.Type == "grpc-glitch" || r.Fault.Type == "h2-glitch" || r.Match.Host != "" || r.Match.Scheme != "" || r.Match.Proto != "" {
				return true
			}
		}
		return false
	}
	if check(t.Rules) {
		return true
	}
	for _, change := range t.ConfigChanges {
		if check(change.Rules) {
			return true
		}
	}
	return false
}

func compressedBody(headers map[string]string) bool {
	for k, v := range headers {
		if strings.EqualFold(k, "Content-Encoding") {
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "gzip", "x-gzip", "deflate":
				return true
			}
		}
	}
	return false
}

var errExportSize = errors.New("tape exceeds export size limit without request bodies")

func encodeExport(t *tape.Tape, limit int) (string, error) {
	encode := func() (string, error) {
		var b strings.Builder
		err := tape.Encode(&b, *t)
		return b.String(), err
	}
	data, err := encode()
	if err != nil || len(data) <= limit {
		return data, err
	}
	t.Script = append([]tape.Step(nil), t.Script...)
	type capturedBody struct {
		target       *string
		value        string
		truncated    *bool
		wasTruncated bool
		base64       bool
		compressed   bool
		cassette     int
	}
	var bodies []capturedBody
	total := 0
	for i := range t.Script {
		step := &t.Script[i]
		var body *string
		var headers map[string]string
		if step.HTTP != nil {
			h := *step.HTTP
			step.HTTP = &h
			body = &h.Body
			headers = h.Headers
		} else if step.Stream != nil {
			stream := *step.Stream
			step.Stream = &stream
			body = &stream.Body
			headers = stream.Headers
		}
		if body != nil && *body != "" {
			bodies = append(bodies, capturedBody{target: body, value: *body, compressed: compressedBody(headers)})
			total += len(*body)
		}
	}
	t.Cassettes = append([]tape.Cassette(nil), t.Cassettes...)
	for i := range t.Cassettes {
		response := &t.Cassettes[i].Response
		if response.Body != "" {
			bodies = append(bodies, capturedBody{target: &response.Body, value: response.Body, truncated: &response.Truncated, wasTruncated: response.Truncated, base64: response.BodyEncoding == "base64", compressed: compressedBody(response.Headers), cassette: i + 1})
			total += len(response.Body)
		}
	}
	if total == 0 && len(t.Cassettes) == 0 {
		return "", errExportSize
	}
	previousOmitted := t.OmittedBodyBytes
	t.Truncated, t.Incomplete = true, true
	if t.IncompleteReason == "" {
		if len(t.Cassettes) == 0 {
			t.IncompleteReason = "recorded request body was truncated for export"
		} else {
			t.IncompleteReason = "recording exceeded export size limit"
		}
	}
	retain := func(n int) {
		omitted := 0
		for i := len(bodies) - 1; i >= 0; i-- {
			keep := min(n, len(bodies[i].value))
			if bodies[i].compressed && keep < len(bodies[i].value) {
				keep = 0
			}
			if bodies[i].base64 && keep < len(bodies[i].value) {
				keep -= keep % 4
			}
			*bodies[i].target = bodies[i].value[:keep]
			if bodies[i].truncated != nil {
				*bodies[i].truncated = bodies[i].wasTruncated || keep < len(bodies[i].value)
			}
			omitted += len(bodies[i].value) - keep
			n -= keep
		}
		t.OmittedBodyBytes = previousOmitted + omitted
	}
	retain(0)
	data, err = encode()
	if err != nil {
		return "", err
	}
	if len(data) > limit && len(t.Cassettes) != 0 {
		cassettes := t.Cassettes
		low, high, removed := 1, len(cassettes), len(cassettes)+1
		for low <= high {
			mid := low + (high-low)/2
			t.Cassettes = cassettes[mid:]
			candidate, encodeErr := encode()
			if encodeErr != nil {
				return "", encodeErr
			}
			if len(candidate) <= limit {
				removed = mid
				high = mid - 1
			} else {
				low = mid + 1
			}
		}
		if removed > len(cassettes) {
			return "", errExportSize
		}
		t.Cassettes = cassettes[removed:]
		if len(t.Cassettes) == 0 {
			t.Version = 2
			t.IgnoreJSONPaths = nil
		}
		kept := bodies[:0]
		total = 0
		for _, body := range bodies {
			if body.cassette != 0 && body.cassette <= removed {
				previousOmitted += len(body.value)
				continue
			}
			kept = append(kept, body)
			total += len(body.value)
		}
		bodies = kept
		retain(0)
		data, err = encode()
		if err != nil {
			return "", err
		}
	}
	if len(data) > limit {
		return "", errExportSize
	}
	best, low, high := data, 0, total-1
	bestRetained := 0
	for low <= high {
		mid := low + (high-low)/2
		retain(mid)
		candidate, encodeErr := encode()
		if encodeErr == nil && len(candidate) <= limit {
			best, bestRetained = candidate, mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	retain(bestRetained)
	return best, nil
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
	data, err := s.readTapeBytes(path)
	if err != nil {
		return tape.Tape{}, err
	}
	return tape.Decode(bytes.NewReader(data))
}

func (s *Server) readTapeBytes(path string) ([]byte, error) {
	base := s.opts.Workdir
	if base == "" {
		base = "."
	}
	if filepath.IsAbs(path) {
		abs, err := filepath.Abs(base)
		if err != nil {
			return nil, err
		}
		path, err = filepath.Rel(abs, path)
		if err != nil {
			return nil, err
		}
	}
	if !filepath.IsLocal(path) {
		return nil, errors.New("tape path is empty or escapes workdir")
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("tape must be a regular file of at most 1 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, errors.New("tape exceeds 1 MiB")
	}
	return data, nil
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
