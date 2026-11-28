package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTapeTestReportCannotReplaceInput(t *testing.T) {
	file := filepath.Join(t.TempDir(), "tape.yaml")
	const original = "version: 2\ntarget: demo\n"
	if err := os.WriteFile(file, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	code, out := launchOutput(t, "test", "--json", "--report", file, file)
	if code != 2 || !strings.Contains(out, "USAGE") {
		t.Fatalf("status=%d, report=%s", code, out)
	}
	data, err := os.ReadFile(file)
	if err != nil || string(data) != original {
		t.Fatalf("input tape replaced: %q, %v", data, err)
	}
}
