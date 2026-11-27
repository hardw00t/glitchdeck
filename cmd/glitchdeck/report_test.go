package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestGitHubSummaryForTestAndExecReports(t *testing.T) {
	for _, tc := range []struct {
		name           string
		args           func(string) []string
		wantExit       int
		wantAnnotation string
	}{
		{"test", func(report string) []string {
			return []string{"test", "../../examples/clean.tape.yaml", "--json", "--report", report}
		}, 0, ""},
		{"exec", func(report string) []string {
			return []string{"exec", "--tape", "../../examples/tapes/your-app-openai-sse-cut.tape.yaml", "--json", "--report", report, "--", "sh", "-c", "exit 0"}
		}, 0, ""},
		{"exec failure", func(report string) []string {
			return []string{"exec", "--tape", "../../examples/tapes/your-app-openai-sse-cut.tape.yaml", "--json", "--report", report, "--", "sh", "-c", "exit 1"}
		}, 1, "child_exit:"},
		{"exec timeout", func(report string) []string {
			return []string{"exec", "--tape", "../../examples/tapes/your-app-openai-sse-cut.tape.yaml", "--json", "--report", report, "--timeout", "100ms", "--", "sh", "-c", "sleep 2"}
		}, 124, "TIMEOUT: context deadline exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			report := filepath.Join(dir, "report.json")
			summary := filepath.Join(dir, "summary")
			t.Setenv("GITHUB_STEP_SUMMARY", summary)
			if code, out := launchOutput(t, tc.args(report)...); code != tc.wantExit {
				t.Fatalf("run exit %d, want %d: %s", code, tc.wantExit, out)
			}
			code, out := launchOutput(t, "report", "--github", report)
			if code != 0 {
				t.Fatalf("report exit %d: %s", code, out)
			}
			if tc.wantAnnotation != "" && !strings.Contains(out, "::error::"+tc.wantAnnotation) {
				t.Fatalf("missing failure annotation: %q", out)
			}
			data, err := os.ReadFile(summary)
			if err != nil || !strings.Contains(string(data), "## Glitchdeck") || !strings.Contains(string(data), "| "+strconv.Itoa(tc.wantExit)+" |") {
				t.Fatalf("summary %q, error %v", data, err)
			}
		})
	}
}
