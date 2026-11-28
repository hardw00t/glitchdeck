package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExecRejectsAliasedRecordAndReportBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	tapePath := filepath.Join(dir, "input.yaml")
	dest := filepath.Join(dir, "destination")
	if err := os.WriteFile(tapePath, []byte("version: 2\ntarget: demo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "alias")
	if err := os.Symlink(dest, link); err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{dest, filepath.Join(dir, ".", "destination"), link} {
		code, _ := launchOutput(t, "exec", "--tape", tapePath, "--json", "--mode", "record", "--tape-out", dest, "--report", alias, "--", "true")
		data, err := os.ReadFile(dest)
		if code != 2 || err != nil || string(data) != "keep" {
			t.Fatalf("alias %s: exit %d, data %q, err %v", alias, code, data, err)
		}
	}
}
