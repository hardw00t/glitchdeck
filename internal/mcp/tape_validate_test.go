package mcp

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTapeValidateStdio(t *testing.T) {
	base := t.TempDir()
	workdir := filepath.Join(base, "work")
	if err := os.Mkdir(workdir, 0700); err != nil {
		t.Fatal(err)
	}
	const v1 = "version: 1\nname: first\ntarget: demo\n"
	const v2 = "version: 2\nname: second\ntarget: demo\nrules:\n  - id: limit\n    enabled: true\n    fault: {type: rate-limit, params: {status: 429}}\n"
	const badYAML = "version: [\n"
	const badSchema = v1 + "unknown_field: true\n"
	const badTarget = "version: 2\ntarget: ftp://localhost\n"
	for path, text := range map[string]string{"work/valid.tape.yaml": v2, "work/invalid.tape.yaml": badSchema, "x.tape.yaml": v1} {
		if err := os.WriteFile(filepath.Join(base, path), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../x.tape.yaml", filepath.Join(workdir, "link.tape.yaml")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		args    map[string]string
		want    map[string]any
		errText string
	}{
		{name: "inline v1", args: map[string]string{"tape_yaml": v1}, want: map[string]any{"ok": true, "version": float64(1), "name": "first", "rules": float64(0)}},
		{name: "inline v2", args: map[string]string{"tape_yaml": v2}, want: map[string]any{"ok": true, "version": float64(2), "name": "second", "rules": float64(1)}},
		{name: "invalid YAML", args: map[string]string{"tape_yaml": badYAML}, errText: "yaml:"},
		{name: "invalid schema", args: map[string]string{"tape_yaml": badSchema}, errText: "unknown_field"},
		{name: "invalid target", args: map[string]string{"tape_yaml": badTarget}, errText: "HTTP or HTTPS"},
		{name: "unknown expected rule", args: map[string]string{"tape_yaml": v2 + "expect: {faults: [{rule: missing, max_applied: 0}]}\n"}, errText: "missing"},
		{name: "inverted bounds", args: map[string]string{"tape_yaml": v2 + "expect: {faults: [{rule: limit, min_applied: 1, max_applied: 0}]}\n"}, errText: "min_applied"},
		{name: "fractional bound", args: map[string]string{"tape_yaml": v2 + "expect: {faults: [{rule: limit, max_applied: 1.5}]}\n"}, errText: "max_applied"},
		{name: "raw missing data", args: map[string]string{"tape_yaml": "version: 2\ntarget: demo\nrules: [{id: r, fault: {type: sse-glitch, params: {action: inject_error, provider: raw}}}]\n"}, errText: "data"},
		{name: "non-raw data", args: map[string]string{"tape_yaml": "version: 2\ntarget: demo\nrules: [{id: r, fault: {type: sse-glitch, params: {action: inject_error, provider: openai, data: x}}}]\n"}, errText: "data"},
		{name: "wrong fragments", args: map[string]string{"tape_yaml": "version: 2\ntarget: demo\nrules: [{id: r, fault: {type: sse-glitch, params: {action: drop, every: 1, after_fragments: 1}}}]\n"}, errText: "after_fragments"},
		{name: "wrong mode", args: map[string]string{"tape_yaml": "version: 2\ntarget: demo\nrules: [{id: r, fault: {type: sse-glitch, params: {action: corrupt_json, every: 1, mode: truncate}}}]\n"}, errText: "mode"},
		{name: "zero burst", args: map[string]string{"tape_yaml": "version: 2\ntarget: demo\nrules: [{id: r, fault: {type: rate-limit, params: {burst: 0}}}]\n"}, errText: "burst"},
		{name: "fractional retry", args: map[string]string{"tape_yaml": "version: 2\ntarget: demo\nrules: [{id: r, fault: {type: rate-limit, params: {retry_after_ms: 1.5}}}]\n"}, errText: "retry_after_ms"},
		{name: "invalid provider", args: map[string]string{"tape_yaml": "version: 2\ntarget: demo\nrules: [{id: r, fault: {type: rate-limit, params: {provider: azure}}}]\n"}, errText: "provider"},
		{name: "empty done events", args: map[string]string{"tape_yaml": "version: 2\nrules: [{id: r, fault: {type: sse-glitch, params: {done_events: []}}}]\n"}, errText: "done_events"},
		{name: "too many done events", args: map[string]string{"tape_yaml": "version: 2\nrules: [{id: r, fault: {type: sse-glitch, params: {done_events: [" + strings.Repeat("x,", 16) + "x]}}}]\n"}, errText: "done_events"},
		{name: "empty done event", args: map[string]string{"tape_yaml": "version: 2\nrules: [{id: r, fault: {type: sse-glitch, params: {done_events: ['']}}}]\n"}, errText: "done_events"},
		{name: "long done event", args: map[string]string{"tape_yaml": "version: 2\nrules: [{id: r, fault: {type: sse-glitch, params: {done_events: ['" + strings.Repeat("é", 65) + "']}}}]\n"}, errText: "done_events"},
		{name: "long message", args: map[string]string{"tape_yaml": "version: 2\nrules: [{id: r, fault: {type: sse-glitch, params: {action: inject_error, message: '" + strings.Repeat("é", 257) + "'}}}]\n"}, errText: "message"},
		{name: "long raw data", args: map[string]string{"tape_yaml": "version: 2\nrules: [{id: r, fault: {type: sse-glitch, params: {action: inject_error, provider: raw, data: '" + strings.Repeat("é", 32769) + "'}}}]\n"}, errText: "data"},
		{name: "long error type", args: map[string]string{"tape_yaml": "version: 2\nrules: [{id: r, fault: {type: sse-glitch, params: {action: inject_error, error_type: '" + strings.Repeat("x", 65) + "'}}}]\n"}, errText: "error_type"},
		{name: "unicode error type", args: map[string]string{"tape_yaml": "version: 2\nrules: [{id: r, fault: {type: sse-glitch, params: {action: inject_error, error_type: 'é'}}}]\n"}, errText: "error_type"},
		{name: "terminal on http", args: map[string]string{"tape_yaml": "version: 2\nassertions: [{http_get: /, expect_sse: {terminal: error}}]\n"}, errText: "terminal"},
		{name: "terminal on grpc", args: map[string]string{"tape_yaml": "version: 2\nscript: [{name: g, grpc: {path: /}}]\nassertions: [{grpc_step: g, expect_sse: {terminal: error}}]\n"}, errText: "terminal"},
		{name: "empty terminal", args: map[string]string{"tape_yaml": "version: 2\nscript: [{name: s, stream: {path: /}}]\nassertions: [{stream_step: s, expect_sse: {terminal: ''}}]\n"}, errText: "terminal"},
		{name: "null terminal", args: map[string]string{"tape_yaml": "version: 2\nscript: [{name: s, stream: {path: /}}]\nassertions: [{stream_step: s, expect_sse: {terminal: null}}]\n"}, errText: "terminal"},
		{name: "valid done events boundary", args: map[string]string{"tape_yaml": "version: 2\nrules: [{id: r, fault: {type: sse-glitch, params: {done_events: [" + strings.Repeat("x,", 15) + "'" + strings.Repeat("é", 64) + "']}}}]\n"}, want: map[string]any{"ok": true, "version": float64(2), "name": "", "rules": float64(1)}},
		{name: "valid message boundary", args: map[string]string{"tape_yaml": "version: 2\nrules: [{id: r, fault: {type: sse-glitch, params: {action: inject_error, message: '" + strings.Repeat("é", 256) + "'}}}]\n"}, want: map[string]any{"ok": true, "version": float64(2), "name": "", "rules": float64(1)}},
		{name: "valid raw boundary", args: map[string]string{"tape_yaml": "version: 2\nrules: [{id: r, fault: {type: sse-glitch, params: {action: inject_error, provider: raw, data: '" + strings.Repeat("é", 32768) + "'}}}]\n"}, want: map[string]any{"ok": true, "version": float64(2), "name": "", "rules": float64(1)}},
		{name: "valid type boundary", args: map[string]string{"tape_yaml": "version: 2\nrules: [{id: r, fault: {type: sse-glitch, params: {action: inject_error, error_type: '" + strings.Repeat("x", 64) + "'}}}]\n"}, want: map[string]any{"ok": true, "version": float64(2), "name": "", "rules": float64(1)}},
		{name: "valid path", args: map[string]string{"tape_path": "valid.tape.yaml"}, want: map[string]any{"ok": true, "version": float64(2), "name": "second", "rules": float64(1)}},
		{name: "absolute path in workdir", args: map[string]string{"tape_path": filepath.Join(workdir, "valid.tape.yaml")}, want: map[string]any{"ok": true, "version": float64(2), "name": "second", "rules": float64(1)}},
		{name: "invalid tape at path", args: map[string]string{"tape_path": "invalid.tape.yaml"}, errText: "unknown_field"},
		// Unreadable paths are validation results, not protocol errors.
		{name: "missing path", args: map[string]string{"tape_path": "missing.tape.yaml"}, errText: "missing.tape.yaml"},
		{name: "relative escape", args: map[string]string{"tape_path": "../x.tape.yaml"}, errText: "escapes"},
		{name: "absolute escape", args: map[string]string{"tape_path": filepath.Join(base, "x.tape.yaml")}, errText: "escapes"},
		{name: "symlink escape", args: map[string]string{"tape_path": "link.tape.yaml"}, errText: "escapes"},
		{name: "both", args: map[string]string{"tape_path": "valid.tape.yaml", "tape_yaml": v1}},
		{name: "neither", args: map[string]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, err := json.Marshal(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			input := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tape_validate","arguments":%s}}`+"\n", args)
			var output strings.Builder
			if err := NewServer(strings.NewReader(input), &output, Options{Workdir: workdir}).Serve(); err != nil {
				t.Fatal(err)
			}
			var reply struct {
				Error struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
				Result *struct {
					IsError bool `json:"isError"`
					Content []struct {
						Text string `json:"text"`
					} `json:"content"`
					Structured map[string]any `json:"structuredContent"`
				} `json:"result"`
			}
			if err := json.Unmarshal([]byte(output.String()), &reply); err != nil {
				t.Fatal(err)
			}
			if tc.want == nil && tc.errText == "" {
				if reply.Error.Code != -32602 || !strings.Contains(reply.Error.Message, "tape_path or tape_yaml") || reply.Result != nil {
					t.Fatal(output.String())
				}
				return
			}
			if reply.Error.Code != 0 || reply.Result == nil || reply.Result.IsError != (tc.errText != "") || len(reply.Result.Content) != 1 {
				t.Fatal(output.String())
			}
			got := reply.Result.Structured
			var text map[string]any
			if err := json.Unmarshal([]byte(reply.Result.Content[0].Text), &text); err != nil || !maps.Equal(text, got) {
				t.Fatal(output.String())
			}
			if tc.want != nil {
				if !maps.Equal(got, tc.want) {
					t.Fatal(output.String())
				}
			} else if message, _ := got["error"].(string); len(got) != 2 || got["ok"] != false || !strings.Contains(message, tc.errText) {
				t.Fatal(output.String())
			}
		})
	}
}
