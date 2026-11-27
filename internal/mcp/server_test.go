package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
			Tools []any `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &result); err != nil || len(result.Result.Tools) != 8 {
		t.Fatal(out.String())
	}
}
func TestRejectsUnknownToolAndParameters(t *testing.T) {
	var out bytes.Buffer
	input := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"shell_exec\",\"arguments\":{}}}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"proxy_stop\",\"arguments\":{\"unexpected\":true}}}\n"
	if err := NewServer(strings.NewReader(input), &out, Options{}).Serve(); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var reply struct {
			Error struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(line), &reply); err != nil || reply.Error.Code != -32602 {
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
