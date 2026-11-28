package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecNeverWritesReportOverTapeOnUsageErrors(t *testing.T) {
	for _, extra := range [][]string{{"--timeout", "0"}, {"--mode", "bad"}, {"--unknown"}} {
		t.Run(extra[0], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.yaml")
			if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"exec", "--json", "--tape", path, "--tape-out", filepath.Join(filepath.Dir(path), "out"), "--report", path}
			args = append(args, extra...)
			args = append(args, "--", "true")
			launchOutput(t, args...)
			got, err := os.ReadFile(path)
			if err != nil || string(got) != "original" {
				t.Fatalf("input overwritten: %q %v", got, err)
			}
		})
	}
}

func TestExecRejectsSymlinkDotDotReportAlias(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "real/child"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "real/child"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "real/input")
	if err := os.WriteFile(input, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	code, _ := launchOutput(t, "exec", "--json", "--mode", "replay", "--tape", input, "--report", filepath.Join(dir, "link")+"/../input", "--", "true")
	got, err := os.ReadFile(input)
	if code != 2 || err != nil || string(got) != "original" {
		t.Fatalf("exit %d input %q: %v", code, got, err)
	}
}

func TestBlockedExportRemainsPrimaryWhenReportWriteFails(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("Z", 32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"api_key":%q}`, secret)
	}))
	defer server.Close()
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	if err := os.WriteFile(input, []byte("version: 2\ntarget: "+server.URL+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(dir, "report")
	if err := os.Mkdir(report, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GD_CASSETTE_TEST_PATH", "/secret")
	code, out := launchOutput(t, "exec", "--json", "--tape", input, "--mode", "record", "--tape-out", filepath.Join(dir, "out"), "--report", report, "--", os.Args[0], "-test.run=^TestExecHybridCassette$")
	if code != 2 || !strings.Contains(out, "EXPORT_BLOCKED") || strings.Contains(out, secret) || strings.Contains(out, dir) {
		t.Fatalf("exit %d output %q", code, out)
	}
}

func TestExecPinsOutputDirectoriesAcrossChild(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	if err := os.WriteFile(input, []byte("version: 2\ntarget: http://127.0.0.1:1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tapes", "reports"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	code, out := launchOutput(t, "exec", "--json", "--tape", input, "--mode", "record", "--allow-zero-traffic",
		"--tape-out", filepath.Join(dir, "tapes/out"), "--report", filepath.Join(dir, "reports/out"),
		"--", "sh", "-c", `mv "$1/tapes" "$1/tapes-old"; mv "$1/reports" "$1/reports-old"; mkdir "$1/decoy"; ln -s decoy "$1/tapes"; ln -s decoy "$1/reports"`, "sh", dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	for _, name := range []string{"tapes-old/out", "reports-old/out"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("missing pinned output %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "decoy/out")); !os.IsNotExist(err) {
		t.Fatalf("decoy modified: %v", err)
	}
}

func TestExecRecordPreflightDoesNotExposePaths(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	if err := os.WriteFile(input, []byte("version: 2\ntarget: demo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.CreateTemp(dir, "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	stderr := os.Stderr
	os.Stderr = log
	defer func() { os.Stderr = stderr }()
	report := filepath.Join(dir, "report")
	code, out := launchOutput(t, "exec", "--json", "--mode", "record", "--tape", input,
		"--tape-out", filepath.Join(dir, "missing", "out"), "--report", report, "--", "true")
	data, err := os.ReadFile(log.Name())
	if err != nil || code != 3 || !strings.Contains(out, "TAPE_IO") || strings.Contains(out, dir) || strings.Contains(string(data), dir) {
		t.Fatalf("exit %d stdout %q stderr %q: %v", code, out, data, err)
	}
	if _, err := os.Stat(report); !os.IsNotExist(err) {
		t.Fatalf("preflight wrote a report: %v", err)
	}
}
