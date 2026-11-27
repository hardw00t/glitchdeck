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
