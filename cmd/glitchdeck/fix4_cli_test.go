package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestLegacyUsageFailureRefreshesReport(t *testing.T) {
	dir := t.TempDir()
	input, report := filepath.Join(dir, "input.yaml"), filepath.Join(dir, "report.json")
	if err := os.WriteFile(input, []byte("version: 2\ntarget: demo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, code, message string
		args                []string
	}{
		{"test-timeout", "USAGE", "usage: glitchdeck test [flags] tape.yaml", []string{"test", input, "--report", report, "--json", "--timeout", "0"}},
		{"test-parse", "USAGE", "flag provided but not defined: -unknown", []string{"test", input, "--report", report, "--json", "--unknown"}},
		{"test-missing-tape", "USAGE", "usage: glitchdeck test [flags] tape.yaml", []string{"test", "--report", report, "--json"}},
		{"exec-timeout", "USAGE_ERROR", "expected --tape, positive timeout and grace, and -- <command>", []string{"exec", "--tape", input, "--report", report, "--json", "--timeout", "0", "--", "unused"}},
		{"exec-parse", "USAGE_ERROR", "flag provided but not defined: -unknown", []string{"exec", "--tape", input, "--report", report, "--json", "--unknown", "--", "unused"}},
		{"exec-missing-tape", "USAGE_ERROR", "expected --tape, positive timeout and grace, and -- <command>", []string{"exec", "--report", report, "--json", "--", "unused"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeStale := func() {
				t.Helper()
				if err := os.WriteFile(report, []byte(`{"ok":true}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			writeStale()
			code, stdout := launchOutput(t, tc.args...)
			data, err := os.ReadFile(report)
			var got struct {
				OK       bool
				ExitCode int `json:"exit_code"`
				Error    map[string]string
			}
			if err != nil || json.Unmarshal(data, &got) != nil || code != 2 || got.OK || got.ExitCode != 2 || got.Error["code"] != tc.code || got.Error["message"] != tc.message || !bytes.Equal(data, []byte(stdout)) {
				t.Fatalf("exit %d, report=%s stdout=%s err=%v", code, data, stdout, err)
			}
			if baseline := os.Getenv("GD_V224_BINARY"); baseline != "" {
				writeStale()
				baselineOut, err := exec.Command(baseline, tc.args...).Output()
				exit, ok := err.(*exec.ExitError)
				baselineReport, readErr := os.ReadFile(report)
				if !ok || exit.ExitCode() != code || readErr != nil || !bytes.Equal(data, baselineReport) || !bytes.Equal([]byte(stdout), baselineOut) {
					t.Fatalf("baseline differs: err=%v read=%v stdout=%s report=%s", err, readErr, baselineOut, baselineReport)
				}
			}
		})
	}
}
