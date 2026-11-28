package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestMissingInputParentRefreshesReport(t *testing.T) {
	dir := t.TempDir()
	input, report := filepath.Join(dir, "missing", "input.yaml"), filepath.Join(dir, "report.json")
	for _, command := range []string{"exec", "test"} {
		t.Run(command, func(t *testing.T) {
			args := []string{"test", input, "--report", report, "--json"}
			if command == "exec" {
				args = []string{"exec", "--tape", input, "--report", report, "--json", "--", "unused"}
			}
			stale := []byte(`{"ok":true}`)
			if err := os.WriteFile(report, stale, 0600); err != nil {
				t.Fatal(err)
			}
			code, stdout := launchOutput(t, args...)
			data, err := os.ReadFile(report)
			var got struct{ Error map[string]string }
			if err != nil || json.Unmarshal(data, &got) != nil || code != 2 || got.Error["code"] != "TAPE_IO" || !bytes.Equal(data, []byte(stdout)) {
				t.Fatalf("exit %d report=%s stdout=%s err=%v", code, data, stdout, err)
			}
			if baseline := os.Getenv("GD_V224_BINARY"); baseline != "" {
				if err := os.WriteFile(report, stale, 0600); err != nil {
					t.Fatal(err)
				}
				out, err := exec.Command(baseline, args...).Output()
				exit, ok := err.(*exec.ExitError)
				oldReport, readErr := os.ReadFile(report)
				if !ok || exit.ExitCode() != code || readErr != nil || !bytes.Equal(data, oldReport) || !bytes.Equal([]byte(stdout), out) {
					t.Fatalf("baseline differs: err=%v read=%v stdout=%s report=%s", err, readErr, out, oldReport)
				}
			}
		})
	}
}

func TestRelativeInputSymlinkRepeatedReport(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"tapes", "fixtures"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "fixtures", "current.yaml"), []byte("version: 2\ntarget: demo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	input, report := filepath.Join(dir, "tapes", "current.yaml"), filepath.Join(dir, "report.json")
	if err := os.Symlink("../fixtures/current.yaml", input); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"exec", "test"} {
		t.Run(command, func(t *testing.T) {
			args := []string{"test", input, "--report", report, "--json"}
			if command == "exec" {
				args = []string{"exec", "--tape", input, "--report", report, "--json", "--allow-zero-traffic", "--", "true"}
			}
			for i := range 2 {
				if err := os.WriteFile(report, []byte(`{"ok":true}`), 0600); err != nil {
					t.Fatal(err)
				}
				code, stdout := launchOutput(t, args...)
				data, err := os.ReadFile(report)
				var got struct{ OK bool }
				if err != nil || json.Unmarshal(data, &got) != nil || code != 0 || !got.OK || !bytes.Equal(data, []byte(stdout)) {
					t.Fatalf("run %d exit %d report=%s stdout=%s err=%v", i, code, data, stdout, err)
				}
			}
		})
	}
}
