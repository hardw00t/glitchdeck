package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordHeaderNameIsNotInScannerDiagnostics(t *testing.T) {
	secret := "sk-" + "ant-" + strings.Repeat("p", 32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "multipart/mixed; boundary=mime")
		fmt.Fprintf(w, "--mime\r\n%s: =?UTF-8?B?cGxhaW4=?=\r\n\r\ncontent\r\n--mime--\r\n", secret)
	}))
	defer server.Close()
	dir := t.TempDir()
	input, report, output := filepath.Join(dir, "in.yaml"), filepath.Join(dir, "report.json"), filepath.Join(dir, "out.yaml")
	if err := os.WriteFile(input, []byte("version: 2\ntarget: "+server.URL+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GD_CASSETTE_TEST_PATH", "/name")
	cmd := exec.Command(os.Args[0], "-test.run=^TestFix3CLIHelper$", "--", "exec", "--json", "--mode", "record", "--tape", input, "--report", report, "--tape-out", output, "--", os.Args[0], "-test.run=^TestExecHybridCassette$")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	exit, ok := err.(*exec.ExitError)
	data, readErr := os.ReadFile(report)
	if !ok || exit.ExitCode() != 2 || readErr != nil || !bytes.Equal(data, stdout) || !bytes.Contains(data, []byte("EXPORT_BLOCKED")) || !bytes.Contains(data, []byte("field=$.")) {
		t.Fatalf("blocked result missing: %v, %v, %s", err, readErr, stdout)
	}
	for _, sink := range [][]byte{stdout, stderr.Bytes(), data} {
		if bytes.Contains(bytes.ToLower(sink), []byte(secret)) || bytes.Contains(sink, []byte(dir)) {
			t.Fatalf("unsafe diagnostic: %s", sink)
		}
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("blocked export left an output: %v", err)
	}
}
