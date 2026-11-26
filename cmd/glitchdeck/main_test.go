package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTapeExitCodes(t *testing.T) {
	malformed := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(malformed, []byte("version: [\n"), 0600); err != nil {
		t.Fatal(err)
	}
	multiple := filepath.Join(t.TempDir(), "multiple.yaml")
	if err := os.WriteFile(multiple, []byte("version: 1\ntarget: demo\nassertions:\n  - name: both\n    http_get: /api/state\n    json_eq:\n      duplicate_charges: 99\n      total_charged_cents: 99\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		file string
		code int
		text string
	}{
		{"../../examples/checkout-dup-webhook.tape.yaml", 1, "FAIL "},
		{"../../examples/clean.tape.yaml", 0, "PASS "},
		{multiple, 1, "FAIL both:"},
		{malformed, 2, ""},
	} {
		t.Run(filepath.Base(tc.file), func(t *testing.T) {
			old := os.Stdout
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			os.Stdout = writer
			code := run([]string{"test", tc.file, "--timeout", "5s"})
			os.Stdout = old
			writer.Close()
			output, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				t.Fatal(err)
			}
			if code != tc.code || (tc.text != "" && !strings.Contains(string(output), tc.text)) || (tc.text == "" && len(output) != 0) {
				t.Fatalf("exit %d, stdout %q", code, output)
			}
			if tc.file == multiple && (strings.Count(string(output), "FAIL ") != 1 || !strings.Contains(string(output), "duplicate_charges") || !strings.Contains(string(output), "total_charged_cents")) {
				t.Fatalf("unexpected verdict %q", output)
			}
		})
	}
}
