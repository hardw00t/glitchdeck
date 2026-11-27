package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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
