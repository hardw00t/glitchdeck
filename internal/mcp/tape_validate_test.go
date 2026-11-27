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
			if reply.Error.Code != 0 || reply.Result == nil || reply.Result.IsError || len(reply.Result.Content) != 1 {
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
