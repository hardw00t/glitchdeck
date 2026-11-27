package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	dir := t.TempDir()
	fixtures := []struct {
		file, yaml, name string
		version, rules   int
		ok               bool
	}{
		{"v1.yaml", "version: 1\nname: legacy\ntarget: demo\n", "legacy", 1, 0, true},
		{"v2.yaml", "version: 2\nname: current\ntarget: demo\nrules:\n  - id: limit\n    enabled: true\n    match: {path_prefix: /}\n    fault: {type: rate-limit, params: {status: 429}}\n", "current", 2, 1, true},
		{"malformed.yaml", "version: [\n", "", 0, 0, false},
		{"schema.yaml", "version: 2\nunknown_field: true\n", "", 0, 0, false},
		{"missing.yaml", "", "", 0, 0, false},
	}
	var paths []string
	for _, f := range fixtures {
		path := filepath.Join(dir, f.file)
		if f.yaml != "" {
			if err := os.WriteFile(path, []byte(f.yaml), 0600); err != nil {
				t.Fatal(err)
			}
		}
		paths = append(paths, path)
	}
	if code, out := launchOutput(t, append([]string{"validate"}, paths[:2]...)...); code != 0 || out != "OK "+paths[0]+"\nOK "+paths[1]+"\n" {
		t.Fatalf("valid tapes: exit %d, stdout %q", code, out)
	}
	if code, out := launchOutput(t, "validate", paths[2]); code != 2 || !strings.HasPrefix(out, "INVALID "+paths[2]+": ") {
		t.Fatalf("malformed tape: exit %d, stdout %q", code, out)
	}
	code, out := launchOutput(t, append([]string{"validate", "--json"}, paths...)...)
	var got struct {
		Schema  string                       `json:"schema"`
		Command string                       `json:"command"`
		OK      *bool                        `json:"ok"`
		Results []map[string]json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || code != 2 || got.OK == nil || *got.OK || got.Schema != "glitchdeck.v2" || got.Command != "validate" || len(got.Results) != len(fixtures) {
		t.Fatalf("mixed tapes: exit %d, stdout %q, decode error %v", code, out, err)
	}
	for i, f := range fixtures {
		result := got.Results[i]
		want := map[string]any{"file": paths[i], "ok": f.ok}
		if f.ok {
			want["name"], want["version"], want["rules"] = f.name, f.version, f.rules
			if _, exists := result["error"]; exists {
				t.Errorf("%s: unexpected error field: %s", f.file, result["error"])
			}
		} else {
			var message string
			if err := json.Unmarshal(result["error"], &message); err != nil || message == "" {
				t.Errorf("%s: missing error message: %v", f.file, err)
			}
		}
		for key, value := range want {
			encoded, err := json.Marshal(value)
			if err != nil || string(result[key]) != string(encoded) {
				t.Errorf("%s: %s = %s, want %s", f.file, key, result[key], encoded)
			}
		}
	}
}

func TestValidateRequiresFiles(t *testing.T) {
	if code, _ := launchOutput(t, "validate"); code != 2 {
		t.Fatalf("validate with no files: exit %d, want 2", code)
	}
}

func TestValidateStdin(t *testing.T) {
	old := validateStdin
	t.Cleanup(func() { validateStdin = old })
	const v2 = "version: 2\nname: current\ntarget: demo\n"
	const limit = 1 << 20
	const sizeError = "stdin exceeds 1 MiB limit"
	for _, tc := range []struct {
		name, input, wantName, wantError string
		version                          int
	}{
		{"v1", "version: 1\nname: legacy\ntarget: demo\n", "legacy", "", 1},
		{"v2", v2, "current", "", 2},
		{"invalid YAML", "version: [\n", "", "yaml:", 0},
		{"invalid schema", "version: 2\nunknown_field: true\n", "", "unknown_field", 0},
		{"exact limit", v2 + strings.Repeat(" ", limit-len(v2)), "current", "", 2},
		{"target scheme", "version: 2\ntarget: ftp://localhost\n", "", "HTTP or HTTPS", 0},
		{"inverted bounds", "version: 2\nrules: [{id: known, fault: {type: tcp-rst}}]\nexpect: {faults: [{rule: known, min_applied: 1, max_applied: 0}]}\n", "", "min_applied", 0},
		{"unknown rule", "version: 2\nexpect: {faults: [{rule: missing, max_applied: 0}]}\n", "", "missing", 0},
		{"negative bounds", "version: 2\nrules: [{id: known, fault: {type: tcp-rst}}]\nexpect: {faults: [{rule: known, max_applied: -1}]}\n", "", "uint64", 0},
		{"fractional bounds", "version: 2\nrules: [{id: known, fault: {type: tcp-rst}}]\nexpect: {faults: [{rule: known, min_applied: -0.5}]}\n", "", "min_applied", 0},
		{"signal exit", "version: 2\nname: signal\nexpect: {child_exit: -1}\n", "signal", "", 2},
		{"invalid child exit", "version: 2\nexpect: {child_exit: -2}\n", "", "child_exit", 0},
		{"negative SSE count", "version: 2\nassertions: [{stream_step: s, expect_sse: {min_events: -1}}]\n", "", "min_events", 0},
		{"inverted SSE bounds", "version: 2\nassertions: [{stream_step: s, expect_sse: {min_events: 5, max_events: 4}}]\n", "", "min_events", 0},
		{"over limit", v2 + strings.Repeat(" ", limit+1-len(v2)), "", sizeError, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok := tc.wantError == ""
			wantExit := 0
			if !ok {
				wantExit = 2
			}
			validateStdin = strings.NewReader(tc.input)
			code, out := launchOutput(t, "validate", "-")
			if code != wantExit || ok && out != "OK -\n" ||
				!ok && (!strings.HasPrefix(out, "INVALID -: ") || !strings.Contains(out, tc.wantError)) {
				t.Errorf("human output: exit %d, stdout %q", code, out)
			}

			validateStdin = strings.NewReader(tc.input)
			code, out = launchOutput(t, "validate", "-", "--json")
			var got struct {
				OK      *bool              `json:"ok"`
				Results []validationResult `json:"results"`
			}
			if err := json.Unmarshal([]byte(out), &got); err != nil || code != wantExit || got.OK == nil || *got.OK != ok || len(got.Results) != 1 {
				t.Fatalf("JSON output: exit %d, stdout %q, decode error %v", code, out, err)
			}
			r := got.Results[0]
			if r.File != "-" || r.OK != ok || ok && (r.Name != tc.wantName || r.Version != tc.version || r.Error != "") ||
				!ok && !strings.Contains(r.Error, tc.wantError) {
				t.Errorf("wrong stdin result: %+v", r)
			}
		})
	}
}

func TestValidateStdinDuplicate(t *testing.T) {
	old := validateStdin
	t.Cleanup(func() { validateStdin = old })
	const input = "version: 2\nname: current\ntarget: demo\n"
	reader := strings.NewReader(input)
	validateStdin = reader
	if code, out := launchOutput(t, "validate", "-", "-"); code != 2 || out != "" || reader.Len() != len(input) {
		t.Fatalf("exit %d, stdout %q, unread bytes %d; want usage error before reading", code, out, reader.Len())
	}
	code, out, stderr := runHelpProcess(t, "validate", "-", "--json", "-")
	var usage struct {
		Code     string `json:"code"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(stderr), &usage); err != nil || code != 2 || usage.Code != "usage" ||
		usage.ExitCode != 2 || !strings.Contains(out, `"ok":false,"results":[]`) {
		t.Fatalf("exit %d, stdout %q, stderr %q, decode error %v", code, out, stderr, err)
	}
}

func TestValidateStdinMixedWithFile(t *testing.T) {
	old := validateStdin
	t.Cleanup(func() { validateStdin = old })
	validateStdin = strings.NewReader("version: 2\nname: piped\ntarget: demo\n")
	path := filepath.Join(t.TempDir(), "file.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nname: disk\ntarget: demo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	code, out := launchOutput(t, "validate", path, "-", "--json")
	var got struct {
		OK      bool               `json:"ok"`
		Results []validationResult `json:"results"`
	}
	want := []validationResult{
		{File: path, OK: true, Version: 1, Name: "disk"},
		{File: "-", OK: true, Version: 2, Name: "piped"},
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || code != 0 || !got.OK || len(got.Results) != 2 ||
		got.Results[0] != want[0] || got.Results[1] != want[1] {
		t.Fatalf("exit %d, stdout %q, decode error %v", code, out, err)
	}
}

func TestValidateV220Parameters(t *testing.T) {
	for _, fault := range []string{
		`{type: sse-glitch, params: {action: inject_error, provider: raw}}`,
		`{type: sse-glitch, params: {action: inject_error, provider: openai, data: x}}`,
		`{type: sse-glitch, params: {action: drop, every: 1, after_fragments: 1}}`,
		`{type: sse-glitch, params: {action: corrupt_json, every: 1, mode: truncate}}`,
		`{type: sse-glitch, params: {action: corrupt_tool_args, mode: cut}}`,
		`{type: rate-limit, params: {burst: 0}}`,
		`{type: rate-limit, params: {retry_after_ms: 1.5}}`,
		`{type: rate-limit, params: {provider: azure}}`,
		`{type: sse-glitch, params: {done_events: []}}`,
		`{type: sse-glitch, params: {done_events: [` + strings.Repeat("x,", 16) + `x]}}`,
		`{type: sse-glitch, params: {done_events: [""]}}`,
		`{type: sse-glitch, params: {done_events: ["` + strings.Repeat("é", 65) + `"]}}`,
		`{type: sse-glitch, params: {action: inject_error, message: "` + strings.Repeat("é", 257) + `"}}`,
		`{type: sse-glitch, params: {action: inject_error, provider: raw, data: "` + strings.Repeat("é", 32769) + `"}}`,
		`{type: sse-glitch, params: {action: inject_error, error_type: "` + strings.Repeat("x", 65) + `"}}`,
		`{type: sse-glitch, params: {action: inject_error, error_type: "é"}}`,
	} {
		path := filepath.Join(t.TempDir(), "bad.yaml")
		doc := "version: 2\ntarget: demo\nrules:\n  - id: r\n    fault: " + fault + "\n"
		if err := os.WriteFile(path, []byte(doc), 0600); err != nil {
			t.Fatal(err)
		}
		if code, _ := launchOutput(t, "validate", path); code != 2 {
			t.Errorf("accepted %s", fault)
		}
	}
}

func TestValidateV220ParameterBoundaries(t *testing.T) {
	for _, params := range []string{
		`{done_events: [x]}`,
		`{done_events: [` + strings.Repeat("x,", 15) + `x]}`,
		`{done_events: ["` + strings.Repeat("é", 64) + `"]}`,
		`{action: inject_error, message: "` + strings.Repeat("é", 256) + `"}`,
		`{action: inject_error, provider: raw, data: "` + strings.Repeat("é", 32768) + `"}`,
		`{action: inject_error, error_type: "` + strings.Repeat("x", 64) + `"}`,
	} {
		path := filepath.Join(t.TempDir(), "good.yaml")
		doc := "version: 2\ntarget: demo\nrules: [{id: r, fault: {type: sse-glitch, params: " + params + "}}]\n"
		if err := os.WriteFile(path, []byte(doc), 0600); err != nil {
			t.Fatal(err)
		}
		if code, _ := launchOutput(t, "validate", path); code != 0 {
			t.Errorf("rejected %s", params[:min(len(params), 100)])
		}
	}
}

func TestValidateTerminalAssertionPresence(t *testing.T) {
	for _, assertion := range []string{`{http_get: /, expect_sse: {terminal: error}}`, `{grpc_step: g, expect_sse: {terminal: error}}`, `{stream_step: s, expect_sse: {terminal: ""}}`, `{stream_step: s, expect_sse: {terminal: null}}`} {
		path := filepath.Join(t.TempDir(), "bad.yaml")
		doc := "version: 2\ntarget: demo\nscript: [{name: s, stream: {path: /}}, {name: g, grpc: {path: /}}]\nassertions: [" + assertion + "]\n"
		if err := os.WriteFile(path, []byte(doc), 0600); err != nil {
			t.Fatal(err)
		}
		if code, _ := launchOutput(t, "validate", path); code != 2 {
			t.Errorf("accepted %s", assertion)
		}
	}
}

func TestValidateAnthropicStatusWarning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warning.yaml")
	doc := "version: 2\ntarget: demo\nrules: [{id: r, fault: {type: rate-limit, params: {provider: anthropic, status: 418}}}]\n"
	if err := os.WriteFile(path, []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	old := os.Stderr
	defer func() { os.Stderr = old }()
	os.Stderr = writer
	code, _ := launchOutput(t, "validate", path)
	writer.Close()
	message, err := io.ReadAll(reader)
	if err != nil || code != 0 || !strings.Contains(string(message), "warning") || !strings.Contains(string(message), "418") {
		t.Fatalf("code=%d stderr=%q error=%v", code, message, err)
	}
}

func TestValidateTLSPassthrough(t *testing.T) {
	old := validateStdin
	t.Cleanup(func() { validateStdin = old })
	patterns := []string{"", "*", "any", "*.", "*.com", "api.*.com", "a*.example.com", "https://example.com", "example.com/path", "example.com?x", "user@example.com", "192.0.2.0/24", "example.com:0", "example.com:65536", strings.Repeat("a", 64) + ".test", strings.Repeat("a.", 126) + "aa", "[not-ip]:443"}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			input := "version: 2\ntls_passthrough: [" + strconv.Quote(pattern) + "]\n"
			validateStdin = strings.NewReader(input)
			if code, out := launchOutput(t, "validate", "-"); code != 2 || !strings.Contains(out, "tls_passthrough[0]") {
				t.Fatalf("exit %d: %s", code, out)
			}
			path := filepath.Join(t.TempDir(), "invalid.tape.yaml")
			if err := os.WriteFile(path, []byte(input), 0600); err != nil {
				t.Fatal(err)
			}
			if code, out := launchOutput(t, "validate", path); code != 2 || !strings.Contains(out, "tls_passthrough[0]") {
				t.Fatalf("file exit %d: %s", code, out)
			}
		})
	}
	for _, input := range []string{"version: 1\ntls_passthrough: []\n", "version: 1\ntls_passthrough: [example.com]\n"} {
		validateStdin = strings.NewReader(input)
		if code, out := launchOutput(t, "validate", "-"); code != 2 || !strings.Contains(out, "new keys require version: 2") {
			t.Fatalf("exit %d: %s", code, out)
		}
	}
}
