package mcp

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func FuzzValidateSchema(f *testing.F) {
	for _, seed := range []string{`null`, `{}`, `{"command":"sk-test-SECRET"}`, `{"\u0000unknown":123}`, `{"timeout_ms":5}`, `{"rules":[null]}`} {
		f.Add(seed)
	}
	catalog := tools()
	f.Fuzz(func(t *testing.T, raw string) {
		// Put the same hostile JSON against every advertised tool schema.
		for _, tool := range catalog {
			name := tool["name"].(string)
			err := validArgs(name, json.RawMessage(raw))
			if err == nil {
				continue
			}
			switch err.Reason {
			case "unknown_tool", "unknown_field", "required", "type_mismatch", "out_of_range", "not_in_enum", "too_long", "too_short", "not_integer", "mutually_exclusive", "invalid_value", "not_batchable", "malformed":
			default:
				t.Fatalf("unexpected reason %q", err.Reason)
			}
			if len(err.message()) > 256 || err.Tool != name || !utf8.ValidString(err.Field) || strings.ContainsFunc(err.Field, unicode.IsControl) {
				t.Fatalf("unsafe diagnostics: %+v", err)
			}
			if err.Reason == "unknown_field" {
				const longestParent = len("arguments.rules[63].fault.")
				if len(err.Field) > longestParent+64 || err.message() != "Invalid params: unknown field" {
					t.Fatalf("unbounded unknown field: %q", err.Field)
				}
			} else if strings.Contains(err.message(), "sk-test-SECRET") || strings.Contains(err.Field, "sk-test-SECRET") {
				t.Fatal("echoed a secret value")
			}
		}
	})
}

func TestSchemaErrorDetails(t *testing.T) {
	cases := []struct{ name, args, field, reason string }{
		{"exec_run", `{"command":"secret"}`, "arguments.command", "type_mismatch"},
		{"exec_run", `{"command":[""]}`, "arguments.command[0]", "too_short"},
		{"exec_run", `{"command":["ok"],"timeout_sec":301}`, "arguments.timeout_sec", "out_of_range"},
		{"exec_run", `{"command":["ok"],"seed":1.5}`, "arguments.seed", "not_integer"},
		{"tape_export", `{"name":"n","format":"v3"}`, "arguments.format", "not_in_enum"},
		{"proxy_stop", `{"z":1,"a":2}`, "arguments.a", "unknown_field"},
		{"fault_set", `{}`, "arguments.rules", "required"},
	}
	for _, tc := range cases {
		err := validArgs(tc.name, json.RawMessage(tc.args))
		if err == nil || err.Field != tc.field || err.Reason != tc.reason {
			t.Errorf("%s %s: %#v", tc.name, tc.args, err)
		}
	}
}
