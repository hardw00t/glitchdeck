package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/execrun"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/tape"
	"gopkg.in/yaml.v3"
)

func TestHandshakeAndList(t *testing.T) {
	var out bytes.Buffer
	s := NewServer(strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\"}}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n"), &out, Options{})
	if err := s.Serve(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatal(out.String())
	}
	var result struct {
		Result struct {
			Tools []struct {
				Name  string `json:"name"`
				Input struct {
					Type                 string `json:"type"`
					AdditionalProperties *bool  `json:"additionalProperties"`
					Properties           map[string]struct {
						Type      string `json:"type"`
						MaxLength int    `json:"maxLength"`
					} `json:"properties"`
					Required []string `json:"required"`
				} `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &result); err != nil || len(result.Result.Tools) != 10 {
		t.Fatal(out.String())
	}
	for _, tool := range result.Result.Tools {
		if tool.Name != "tape_validate" {
			continue
		}
		s := tool.Input
		if s.Type != "object" || s.AdditionalProperties == nil || *s.AdditionalProperties ||
			len(s.Required) != 0 || len(s.Properties) != 2 || s.Properties["tape_path"].Type != "string" ||
			s.Properties["tape_yaml"].Type != "string" || s.Properties["tape_yaml"].MaxLength != 1048576 {
			t.Fatalf("unexpected tape_validate schema: %+v", s)
		}
		return
	}
	t.Fatal("tape_validate missing from tools/list")
}
func TestRejectsUnknownToolAndParameters(t *testing.T) {
	var out bytes.Buffer
	input := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"shell_exec\",\"arguments\":{}}}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"proxy_stop\",\"arguments\":{\"unexpected\":true}}}\n"
	if err := NewServer(strings.NewReader(input), &out, Options{}).Serve(); err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var reply struct {
			Error struct {
				Code int `json:"code"`
				Data struct {
					Reason string `json:"reason"`
				} `json:"data"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(line), &reply); err != nil || reply.Error.Code != -32602 ||
			reply.Error.Data.Reason != []string{"unknown_tool", "unknown_field"}[i] {
			t.Fatalf("bad response %s", line)
		}
	}
}

func TestTapeFilesAreRegularAndBounded(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(nil, nil, Options{Workdir: dir})
	if err := os.WriteFile(filepath.Join(dir, "large"), make([]byte, 1<<20+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readTape("large"); err == nil {
		t.Fatal("accepted oversized tape")
	}
}

func TestTapeExportStaysInRoot(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(nil, nil, Options{Workdir: dir})
	path := filepath.Join(dir, "tape.yaml")
	if err := s.writeTape(path, []byte("version: 1\n")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "version: 1\n" {
		t.Fatalf("output %q: %v", b, err)
	}
	if err := s.writeTape(filepath.Join(filepath.Dir(dir), "outside.yaml"), []byte("bad")); err == nil {
		t.Fatal("wrote outside root")
	}
}

func TestTapeExportReportsDroppedEntries(t *testing.T) {
	s := NewServer(nil, nil, Options{Workdir: t.TempDir()})
	s.ctx = context.Background()
	start, _ := s.call("proxy_start", []byte(`{"target":"demo","record":true}`))
	if start["error"] != nil {
		t.Fatal(start)
	}
	t.Cleanup(s.stop)
	for range 258 {
		resp, err := http.Get(start["proxy_url"].(string) + "/api/state")
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("request failed: %s: %v", resp.Status, err)
		}
	}
	got, _ := s.call("tape_export", []byte(`{"name":"capped"}`))
	if data, _ := got["yaml"].(string); got["truncated"] != true || got["dropped_entries"] != 2 ||
		!strings.Contains(data, "truncated: true") || !strings.Contains(data, "dropped_entries: 2") {
		t.Fatalf("tape export omitted truncation: %v", got)
	}
}

func TestTapeExportFitsBodyBudgets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		path   string
		budget int
	}{
		{"inline", "", 64 << 10},
		{"file", "capture.yaml", 1 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer(nil, nil, Options{Workdir: t.TempDir()})
			s.ctx = context.Background()
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					http.Error(w, "upload incomplete", http.StatusBadRequest)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(upstream.Close)
			start, _ := s.call("proxy_start", fmt.Appendf(nil, `{"target":%q,"record":true}`, upstream.URL))
			if start["error"] != nil {
				t.Fatal(start)
			}
			t.Cleanup(s.stop)
			if tc.path != "" {
				s.p.ShouldCaptureResponse = func(uint64) bool { return false }
			}
			body := strings.Repeat("a", tc.budget+10000)
			for _, payload := range []string{body, "last"} {
				resp, err := http.Post(start["proxy_url"].(string)+"/upload", "text/plain", strings.NewReader(payload))
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusNoContent {
					t.Fatalf("upload status: %d", resp.StatusCode)
				}
			}
			args, _ := json.Marshal(map[string]string{"name": "budget", "out_path": tc.path})
			got, _ := s.call("tape_export", args)
			if got["error"] != nil {
				t.Fatal(got)
			}
			data, _ := got["yaml"].(string)
			if tc.path != "" {
				b, err := os.ReadFile(got["out_path"].(string))
				if err != nil {
					t.Fatal(err)
				}
				data = string(b)
			}
			if len(data) > tc.budget {
				t.Fatalf("export size %d exceeds %d", len(data), tc.budget)
			}
			var doc tape.Tape
			err := yaml.Unmarshal([]byte(data), &doc)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tape.Decode(strings.NewReader(data)); err == nil {
				t.Fatal("incomplete tape accepted for replay")
			}
			if len(doc.Script) != 2 || doc.Script[0].Seq >= doc.Script[1].Seq || doc.Script[1].HTTP.Body != "last" {
				t.Fatalf("script order or later body changed: %+v", doc.Script)
			}
			omitted := len(body) - len(doc.Script[0].HTTP.Body)
			if omitted <= 0 || !doc.Incomplete || !doc.Truncated || doc.OmittedBodyBytes != omitted || got["omitted_body_bytes"] != omitted {
				t.Fatalf("missing truncation metadata: result=%v tape=%+v omitted=%d", got, doc, omitted)
			}
		})
	}
}

func TestEncodeExportBoundsBinaryAndUTF8Bodies(t *testing.T) {
	for _, body := range []string{
		strings.Repeat("界", 30000),
		strings.Repeat("\x00\xff\"", 30000),
	} {
		original := &tape.HTTP{Method: "POST", Path: "/", Body: body}
		doc := tape.Tape{Version: 1, Script: []tape.Step{{HTTP: original}}}
		data, err := encodeExport(&doc, 64<<10)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > 64<<10 {
			t.Fatalf("export exceeds budget: %d", len(data))
		}
		var decoded tape.Tape
		if err := yaml.Unmarshal([]byte(data), &decoded); err != nil {
			t.Fatal(err)
		}
		retained := decoded.Script[0].HTTP.Body
		if !strings.HasPrefix(body, retained) || decoded.OmittedBodyBytes != len(body)-len(retained) || !decoded.Incomplete || !decoded.Truncated {
			t.Fatalf("incorrect body or metadata: retained=%d omitted=%d", len(retained), decoded.OmittedBodyBytes)
		}
		if original.Body != body {
			t.Fatal("export mutated recording")
		}
	}
}

func TestInvalidIDsBlankLineAndMetadata(t *testing.T) {
	input := "\n" +
		`{"jsonrpc":"2.0","id":null,"method":"ping"}` + "\n" +
		`{"jsonrpc":"2.0","id":1.5,"method":"ping"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"proxy_stop","arguments":{},"_meta":{"progressToken":"p"}}}` + "\n"
	var out bytes.Buffer
	if err := NewServer(strings.NewReader(input), &out, Options{}).Serve(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatal(out.String())
	}
	for i, code := range []int{-32700, -32600, -32600} {
		var reply struct {
			Error struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal([]byte(lines[i]), &reply) != nil || reply.Error.Code != code {
			t.Fatalf("unexpected response %s", lines[i])
		}
	}
	if strings.Contains(lines[3], `"error"`) {
		t.Fatal(lines[3])
	}
}

func TestFaultClearEmptySelectionAndRuleLimit(t *testing.T) {
	s := NewServer(nil, nil, Options{})
	s.ctx = context.Background()
	if result, _ := s.call("proxy_start", []byte(`{"target":"demo"}`)); result["error"] != nil {
		t.Fatal(result)
	}
	defer s.stop()
	for i := range 64 {
		raw := fmt.Sprintf(`{"rules":[{"id":"r%d","enabled":true,"fault":{"type":"tcp-rst","params":{}}}]}`, i)
		if result, _ := s.call("fault_set", []byte(raw)); result["error"] != nil {
			t.Fatal(result)
		}
	}
	if result, _ := s.call("fault_clear", []byte(`{"rule_ids":[]}`)); result["rules_count"] != 64 {
		t.Fatal(result)
	}
	if result, _ := s.call("fault_set", []byte(`{"rules":[{"id":"extra","enabled":true,"fault":{"type":"tcp-rst","params":{}}}]}`)); result["error"] == nil {
		t.Fatal(result)
	}
	if len(s.p.Config().Rules) != 64 {
		t.Fatal("oversized configuration published")
	}
}

func TestBatchRequestsAndNotifications(t *testing.T) {
	input := `[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":2,"method":"ping"}]` + "\n" +
		`[{"jsonrpc":"2.0","method":"notifications/initialized"}]` + "\n" +
		`[]` + "\n"
	var out bytes.Buffer
	if err := NewServer(strings.NewReader(input), &out, Options{}).Serve(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatal(out.String())
	}
	var replies []map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &replies); err != nil || len(replies) != 2 {
		t.Fatal(lines[0], err)
	}
	var empty map[string]any
	if json.Unmarshal([]byte(lines[1]), &empty) != nil || empty["error"] == nil {
		t.Fatal(lines[1])
	}
}

func TestWireEventsAppliedAndProtocolFields(t *testing.T) {
	s := NewServer(nil, nil, Options{})
	s.ctx = context.Background()
	if result, _ := s.call("proxy_start", []byte(`{"target":"demo"}`)); result["error"] != nil {
		t.Fatal(result)
	}
	defer s.stop()
	s.bus.Publish("sse_event", map[string]any{"fault": "sse-glitch", "fault_id": "rule", "applied": false})
	s.bus.Publish("sse_event", map[string]any{"fault": "sse-glitch", "rule_id": "rule", "applied": true})
	s.bus.Publish("grpc_call", map[string]any{"grpc_status": 14, "http_status": 200})
	s.bus.Publish("ws_frame", map[string]any{"dir": "s2c", "action": "drop"})
	filtered, _ := s.call("wire_events", []byte(`{"faulted_only":true}`))
	if filtered["count"] != 1 {
		t.Fatal(filtered)
	}
	if filtered["events"].([]any)[0].(map[string]any)["fault_id"] != "rule" {
		t.Fatal(filtered)
	}
	all, _ := s.call("wire_events", []byte(`{}`))
	events := all["events"].([]any)
	if events[2].(map[string]any)["grpc_status"] != float64(14) || events[3].(map[string]any)["dir"] != "s2c" {
		t.Fatal(events)
	}
}

func TestWireEventsDiagnosticAllowlist(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wire_events","arguments":{}}}` + "\n"
	var output bytes.Buffer
	s := NewServer(strings.NewReader(input), &output, Options{})
	s.ctx = context.Background()
	if result, _ := s.call("proxy_start", []byte(`{"target":"demo"}`)); result["error"] != nil {
		t.Fatal(result)
	}
	s.bus.Publish("ws_frame", map[string]any{"class": "data", "data_seq": 3, "control_seq": 2, "declared_bytes": 4194305, "limit_bytes": 4194304, "ts_ms": 123, "detail": "secret", "body": "secret"})
	s.bus.Publish("http_req", map[string]any{"replay_mode": "timeout_retry", "replay_index": 1, "committed_status": 200, "outcome": "conflict", "original_outcome": "timeout"})
	s.bus.Publish("ws_frame", map[string]any{"declared_bytes": uint64(9007199254740993)})
	if err := s.Serve(); err != nil {
		t.Fatal(err)
	}
	var reply struct {
		Result struct {
			Content struct {
				Events []map[string]any `json:"events"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(output.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if len(reply.Result.Content.Events) != 3 {
		t.Fatal(output.String())
	}
	ws := reply.Result.Content.Events[0]
	if ws["class"] != "data" || ws["data_seq"] != float64(3) || ws["control_seq"] != float64(2) || ws["declared_bytes"] != float64(4194305) || ws["limit_bytes"] != float64(4194304) || ws["ts_ms"] != float64(123) || ws["detail"] != nil || ws["body"] != nil {
		t.Fatal(ws)
	}
	http := reply.Result.Content.Events[1]
	if http["replay_mode"] != "timeout_retry" || http["replay_index"] != float64(1) || http["committed_status"] != float64(200) || http["outcome"] != "conflict" || http["original_outcome"] != "timeout" {
		t.Fatal(http)
	}
	if !strings.Contains(output.String(), `"declared_bytes":9007199254740993`) {
		t.Fatal(output.String())
	}
}

func TestReportFaultProjectionOnlyExportsReplayCapacity(t *testing.T) {
	var report execrun.Envelope
	report.SetAppliedFaults([]proxy.AppliedFault{
		{RuleID: "same", Type: "sse-glitch", SkipReasons: map[string]uint64{"replay_capacity_exceeded": 3, "encoding_unsupported:secret": 1}},
		{RuleID: "same", Type: "dup-webhook", SkipReasons: map[string]uint64{"replay_capacity_exceeded": 2, "encoding_unsupported:secret": 1}},
	})
	first := report.FaultsTriggered[0].(map[string]any)
	second := report.FaultsTriggered[1].(map[string]any)
	if first["skip_reasons"] != nil {
		t.Fatal(first)
	}
	reasons, ok := second["skip_reasons"].(map[string]uint64)
	if !ok || len(reasons) != 1 || reasons["replay_capacity_exceeded"] != 2 {
		t.Fatal(second)
	}
}

func TestDemoTriggerReportsTransportFailure(t *testing.T) {
	s := NewServer(nil, nil, Options{})
	s.ctx = context.Background()
	if result, _ := s.call("proxy_start", []byte(`{"target":"demo"}`)); result["error"] != nil {
		t.Fatal(result)
	}
	defer s.stop()
	if result, _ := s.call("fault_set", []byte(`{"rules":[{"id":"reset","enabled":true,"fault":{"type":"tcp-rst","params":{}}}]}`)); result["error"] != nil {
		t.Fatal(result)
	}
	result, _ := s.call("demo_trigger", []byte(`{"action":"checkout"}`))
	if result["error"] == "" || result["error"] == nil {
		t.Fatal(result)
	}
}
