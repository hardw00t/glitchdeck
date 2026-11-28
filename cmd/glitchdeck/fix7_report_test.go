package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPassthroughReportRefreshesInvalidInputParents(t *testing.T) {
	for _, command := range []string{"exec", "test"} {
		for _, parent := range []string{"missing", "file"} {
			for _, usage := range []bool{false, true} {
				t.Run(command+"/"+parent+"/"+map[bool]string{false: "open", true: "usage"}[usage], func(t *testing.T) {
					dir := t.TempDir()
					if parent == "file" {
						if err := os.WriteFile(filepath.Join(dir, parent), []byte("file"), 0600); err != nil {
							t.Fatal(err)
						}
					}
					input, report := filepath.Join(dir, parent, "input"), filepath.Join(dir, "report")
					if err := os.WriteFile(report, []byte(`{"ok":true}`), 0600); err != nil {
						t.Fatal(err)
					}
					args := []string{"test", "--json", "--report", report}
					if usage {
						args = append(args, "--timeout", "0")
					}
					args = append(args, input)
					if command == "exec" {
						args = []string{"exec", "--json", "--tape", input, "--report", report}
						if usage {
							args = append(args, "--timeout", "0")
						}
						args = append(args, "--", "true")
					}
					code, _ := launchOutput(t, args...)
					data, err := os.ReadFile(report)
					var got struct {
						OK    bool `json:"ok"`
						Error struct {
							Code string `json:"code"`
						} `json:"error"`
					}
					if err != nil || json.Unmarshal(data, &got) != nil || code != 2 || got.OK || got.Error.Code == "" {
						t.Fatalf("exit=%d report=%s err=%v", code, data, err)
					}
					want := "TAPE_IO"
					if usage {
						want = map[string]string{"exec": "USAGE_ERROR", "test": "USAGE"}[command]
					}
					if got.Error.Code != want {
						t.Fatalf("wrong error: %s", data)
					}
				})
			}
		}
	}
}

func TestPassthroughReportReplacesAbsoluteSymlink(t *testing.T) {
	for _, command := range []string{"exec", "test"} {
		t.Run(command, func(t *testing.T) {
			dir := t.TempDir()
			input, target, report := filepath.Join(dir, "input"), filepath.Join(dir, "target"), filepath.Join(dir, "report")
			if err := os.WriteFile(input, []byte("invalid tape"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, report); err != nil {
				t.Fatal(err)
			}
			args := []string{"test", "--json", "--report", report, input}
			if command == "exec" {
				args = []string{"exec", "--json", "--tape", input, "--report", report, "--", "true"}
			}
			code, _ := launchOutput(t, args...)
			info, err := os.Lstat(report)
			data, readErr := os.ReadFile(target)
			if code != 2 || err != nil || info.Mode()&os.ModeSymlink != 0 || readErr != nil || string(data) != "untouched" {
				t.Fatalf("exit=%d info=%v err=%v target=%q read=%v", code, info, err, data, readErr)
			}
		})
	}
}

func TestPassthroughExecChildCreatesReportDirectory(t *testing.T) {
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input"), filepath.Join(dir, "child")
	if err := os.WriteFile(input, []byte("version: 2\ntarget: demo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(output, "report")
	code, out := launchOutput(t, "exec", "--json", "--tape", input, "--report", report, "--allow-zero-traffic", "--", "mkdir", output)
	data, err := os.ReadFile(report)
	var got struct {
		OK bool `json:"ok"`
	}
	if code != 0 || err != nil || json.Unmarshal(data, &got) != nil || !got.OK {
		t.Fatalf("exit=%d output=%s report=%s err=%v", code, out, data, err)
	}
}
