package main

import (
	"io"
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

func TestTLSPassthroughFlags(t *testing.T) {
	path := execTapeWithoutExpectations(t)
	for _, command := range []string{"exec", "proxy", "demo"} {
		args := []string{command, "--tls-passthrough", "valid.test,api.*.com"}
		if command == "exec" {
			args = append(args, "--tape", path, "--", "true")
		}
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		old := os.Stderr
		os.Stderr = w
		code, _ := launchOutput(t, args...)
		os.Stderr = old
		w.Close()
		output, err := io.ReadAll(r)
		r.Close()
		if err != nil || code != 2 || !strings.Contains(string(output), "tls_passthrough[1]") {
			t.Errorf("%s: exit %d, stderr %q, error %v", command, code, output, err)
		}
	}
}

func TestTLSPassthroughWithoutTLSNote(t *testing.T) {
	path := execTapeWithoutExpectations(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	code, _ := launchOutput(t, "exec", "--tape", path, "--allow-zero-traffic", "--tls-passthrough", " example.com ", "--tls-passthrough", "*.example.com", "--", "true")
	os.Stderr = old
	w.Close()
	output, err := io.ReadAll(r)
	r.Close()
	if err != nil || code != 0 || strings.Count(string(output), "tls-passthrough has no effect without --tls") != 1 {
		t.Fatalf("exit %d, stderr %q, error %v", code, output, err)
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
