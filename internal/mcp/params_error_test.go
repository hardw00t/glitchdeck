package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestInvalidParamsDetails(t *testing.T) {
	const secret = "sk-test-SECRET"
	workdir := t.TempDir()
	for _, tc := range []struct {
		name, arguments, reason, field string
		batch                          bool
	}{
		{"shell_exec", `{"command":"` + secret + `"}`, "unknown_tool", "shell_exec", false},
		{"proxy_stop", `{"unexpected":"` + secret + `"}`, "unknown_field", "arguments.unexpected", false},
		{"fault_set", `{}`, "required", "arguments.rules", false},
		{"exec_run", `{"command":"` + secret + `"}`, "type_mismatch", "arguments.command", false},
		{"tape_run", `{"timeout_ms":5}`, "out_of_range", "arguments.timeout_ms", false},
		{"fault_set", `{"mode":"` + secret + `","rules":[{}]}`, "not_in_enum", "arguments.mode", false},
		{"exec_run", `{"command":["` + strings.Repeat(secret, 400) + `"]}`, "too_long", "arguments.command[0]", false},
		{"exec_run", `{"command":[""]}`, "too_short", "arguments.command[0]", false},
		{"proxy_start", `{"target":"demo","seed":1.5}`, "not_integer", "arguments.seed", false},
		{"tape_validate", `{"tape_yaml":"` + secret + `","tape_path":` + quoteParam(workdir) + `}`, "mutually_exclusive", "arguments", false},
		{"exec_run", `{"command":["a\u0000` + secret + `"],"tape_yaml":"unused"}`, "invalid_value", "arguments.command[0]", false},
		{"exec_run", `{"command":["` + secret + `"]}`, "not_batchable", "arguments", true},
		{"proxy_stop", `"` + secret + `"`, "malformed", "arguments", false},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			input := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":` + quoteParam(tc.name) + `,"arguments":` + tc.arguments + `}}`
			if tc.batch {
				input = "[" + input + "]"
			}
			var out bytes.Buffer
			if err := NewServer(strings.NewReader(input+"\n"), &out, Options{Workdir: workdir, AllowExec: true}).Serve(); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), secret) || strings.Contains(out.String(), workdir) {
				t.Fatal("invalid-params response echoed input")
			}
			var reply struct {
				Error struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
					Data    struct {
						Field   string `json:"field"`
						Reason  string `json:"reason"`
						Minimum int    `json:"minimum"`
						Maximum int    `json:"maximum"`
					} `json:"data"`
				} `json:"error"`
			}
			data := bytes.TrimSpace(out.Bytes())
			if tc.batch {
				data = bytes.TrimSuffix(bytes.TrimPrefix(data, []byte("[")), []byte("]"))
			}
			if err := json.Unmarshal(data, &reply); err != nil {
				t.Fatal(err)
			}
			e := reply.Error
			if e.Code != -32602 || e.Data.Reason != tc.reason || e.Data.Field != tc.field || len(e.Message) > 256 {
				t.Fatalf("unexpected response: %s", data)
			}
			if tc.reason == "out_of_range" && (e.Data.Minimum != 100 || e.Data.Maximum != 120000) {
				t.Fatalf("missing range bounds: %s", data)
			}
		})
	}
}

func quoteParam(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
