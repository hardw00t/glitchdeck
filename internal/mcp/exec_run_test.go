package mcp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const execTape = "version: 2\ntarget: demo\n"

type execReply struct {
	ID    json.RawMessage `json:"id"`
	Error *struct {
		Code int            `json:"code"`
		Data map[string]any `json:"data"`
	} `json:"error"`
	Result struct {
		IsError bool           `json:"isError"`
		Content map[string]any `json:"structuredContent"`
	} `json:"result"`
}

func execRequest(id int, args map[string]any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": "exec_run", "arguments": args}}
}

func execSingle(t *testing.T, opts Options, args map[string]any) execReply {
	t.Helper()
	input, err := json.Marshal(execRequest(1, args))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := NewServer(bytes.NewReader(append(input, '\n')), &out, opts).Serve(); err != nil {
		t.Fatal(err)
	}
	var reply execReply
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &reply); err != nil {
		t.Fatalf("invalid response %q: %v", out.String(), err)
	}
	return reply
}

func execErrorCode(r execReply) any {
	err, _ := r.Result.Content["error"].(map[string]any)
	return err["code"]
}

func TestExecDisabledDoesNotRun(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "created")
	for _, args := range []map[string]any{
		{"command": []string{"sh", "-c", "touch created"}, "tape_yaml": execTape},
		{"command": []string{"sh", "-c", "touch created"}, "tape_path": "missing.yaml"},
	} {
		r := execSingle(t, Options{Workdir: dir}, args)
		if !r.Result.IsError || execErrorCode(r) != "EXEC_DISABLED" || r.Result.Content["exec"] != nil {
			t.Fatalf("response: %+v", r)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("command created marker or stat failed: %v", err)
	}
}

func TestExecCommandValidation(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		command                 any
		field, reason, expected string
	}{
		{"string", "echo hi", "arguments.command", "type_mismatch", "array"},
		{"empty", []string{}, "arguments.command", "too_short", ""},
		{"empty_arg", []string{""}, "arguments.command[0]", "too_short", ""},
		{"nul", []string{"a\x00"}, "arguments.command[0]", "invalid_value", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := execSingle(t, Options{Workdir: t.TempDir(), AllowExec: true}, map[string]any{"command": tc.command, "tape_yaml": execTape})
			if r.Error == nil || r.Error.Code != -32602 || r.Error.Data["field"] != tc.field || r.Error.Data["reason"] != tc.reason {
				t.Fatalf("response: %+v", r)
			}
			if tc.expected != "" && r.Error.Data["expected"] != tc.expected {
				t.Fatalf("response: %+v", r)
			}
		})
	}
}

func TestExecCwdConfinement(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	for _, cwd := range []string{"../", outside, "escape"} {
		t.Run(cwd, func(t *testing.T) {
			r := execSingle(t, Options{Workdir: dir, AllowExec: true}, map[string]any{"command": []string{"unused"}, "tape_yaml": execTape, "cwd": cwd})
			b, _ := json.Marshal(r)
			if !r.Result.IsError || execErrorCode(r) != "INVALID_PATH" || strings.Contains(string(b), dir) || strings.Contains(string(b), outside) {
				t.Fatalf("response: %s", b)
			}
		})
	}
}

func TestExecEgressPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, tape, target string
		allow              []string
	}{
		{"target", execTape, "https://example.com", nil},
		{"tape", "version: 2\ntarget: demo\nupstream_allow:\n  - evil.test\n", "", []string{"api.openai.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := execSingle(t, Options{Workdir: t.TempDir(), AllowExec: true, UpstreamAllow: tc.allow}, map[string]any{"command": []string{"unused"}, "tape_yaml": tc.tape, "target": tc.target})
			if !r.Result.IsError || execErrorCode(r) != "EGRESS_POLICY" {
				t.Fatalf("response: %+v", r)
			}
		})
	}
}

func TestExecDiscoveryAndBatchRejection(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		input := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
		var out bytes.Buffer
		if err := NewServer(strings.NewReader(input), &out, Options{Workdir: t.TempDir(), AllowExec: enabled}).Serve(); err != nil {
			t.Fatal(err)
		}
		var reply struct {
			Result struct {
				Tools []struct {
					Name string         `json:"name"`
					Meta map[string]any `json:"_meta"`
				} `json:"tools"`
			} `json:"result"`
		}
		if err := json.Unmarshal(out.Bytes(), &reply); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, tool := range reply.Result.Tools {
			if tool.Name == "exec_run" {
				found = true
				if tool.Meta["execEnabled"] != enabled {
					t.Fatalf("metadata: %v", tool.Meta)
				}
			}
		}
		if !found {
			t.Fatal("exec_run missing from tools/list")
		}
	}
	batch, err := json.Marshal([]any{execRequest(2, map[string]any{"command": []string{"unused"}, "tape_yaml": execTape})})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := NewServer(bytes.NewReader(append(batch, '\n')), &out, Options{Workdir: t.TempDir(), AllowExec: true}).Serve(); err != nil {
		t.Fatal(err)
	}
	var replies []execReply
	if err := json.Unmarshal(out.Bytes(), &replies); err != nil {
		t.Fatal(err)
	}
	if len(replies) != 1 || replies[0].Error == nil || replies[0].Error.Code != -32602 || replies[0].Error.Data["reason"] != "not_batchable" {
		t.Fatalf("batch response: %s", out.String())
	}
}
