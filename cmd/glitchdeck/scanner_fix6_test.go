package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFix6RecordEscapedAuthenticationChallenge(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("q", 24)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="\s`+secret[1:]+`"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	for _, redact := range []bool{false, true} {
		dir := t.TempDir()
		input, report, output := filepath.Join(dir, "in.yaml"), filepath.Join(dir, "report.json"), filepath.Join(dir, "out.yaml")
		if err := os.WriteFile(input, []byte("version: 2\ntarget: "+server.URL+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		args := []string{"-test.run=^TestFix3CLIHelper$", "--", "exec", "--json", "--mode", "record", "--tape", input, "--report", report, "--tape-out", output}
		if redact {
			args = append(args, "--redact-secrets")
		}
		args = append(args, "--", os.Args[0], "-test.run=^TestExecHybridCassette$")
		cmd := exec.Command(os.Args[0], args...)
		cmd.Env = append(os.Environ(), "GD_CASSETTE_TEST_PATH=/challenge")
		stdout, err := cmd.Output()
		if err == nil || !bytes.Contains(stdout, []byte("EXPORT_BLOCKED")) {
			t.Fatalf("redact=%v did not block: %v %s", redact, err, stdout)
		}
	}
}
