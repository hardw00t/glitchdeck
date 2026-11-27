package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecHelp(t *testing.T) {
	for _, flag := range []string{"-h", "--help"} {
		code, out := launchOutput(t, "exec", flag)
		if code != 0 || !strings.HasPrefix(out, "usage: glitchdeck exec --tape <file>") || !strings.Contains(out, "-upstream-allow") || !strings.Contains(out, "-allow-zero-traffic") {
			t.Fatalf("exec %s: code=%d out=%q", flag, code, out)
		}
	}
}

func TestExecZeroTrafficFlag(t *testing.T) {
	path := execTapeWithoutExpectations(t)
	for _, tc := range []struct {
		flags []string
		want  int
	}{
		{nil, 1},
		{[]string{"--allow-zero-traffic"}, 0},
	} {
		args := append([]string{"exec", "--tape", path, "--json"}, tc.flags...)
		args = append(args, "--", "sh", "-c", "exit 0")
		code, out := launchOutput(t, args...)
		if code != tc.want || (tc.want == 1 && !strings.Contains(out, "zero_traffic")) {
			t.Fatalf("exit %d, output %s", code, out)
		}
	}
}

func execTapeWithoutExpectations(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "exec.tape.yaml")
	if err := os.WriteFile(path, []byte("version: 2\ntarget: http://127.0.0.1:1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
