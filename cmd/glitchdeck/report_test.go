package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitHubSummaryForTestAndExecReports(t *testing.T) {
	for _, tc := range []struct {
		name           string
		args           func(string) []string
		wantExit       int
		wantAnnotation string
		wantSummary    []string
	}{
		{"test", func(report string) []string {
			return []string{"test", "../../examples/clean.tape.yaml", "--json", "--report", report}
		}, 0, "", []string{"| Exit code | Requests total | Faults triggered | Assertions passed | Assertions failed |", "| --- | --- | --- | --- | --- |", "| 0 | 2 | 0 | 1 | 0 |"}},
		{"test failure", func(report string) []string {
			return []string{"test", "../../examples/checkout-dup-webhook.tape.yaml", "--json", "--report", report}
		}, 1, "no-duplicate-charges:", []string{"| 1 | 2 | 1 | 0 | 1 |", "- dup-pay (dup-webhook): 1", "- no-duplicate-charges: duplicate\\_charges: expected 0, got 1"}},
		{"exec", func(report string) []string {
			return []string{"exec", "--tape", "../../examples/tapes/your-app-openai-sse-cut.tape.yaml", "--json", "--report", report, "--", "sh", "-c", "exit 0"}
		}, 0, "", []string{"| Exit code | Child exit code | Requests total | Faults triggered | Assertions passed | Assertions failed |", "| --- | --- | --- | --- | --- | --- |", "| 0 | 0 | 0 | 0 | 0 | 0 |"}},
		{"exec failure", func(report string) []string {
			return []string{"exec", "--tape", "../../examples/tapes/your-app-openai-sse-cut.tape.yaml", "--json", "--report", report, "--", "sh", "-c", "exit 7"}
		}, 1, "child_exit: expected 0, got 7", []string{"| 1 | 7 | 0 | 0 | 0 | 0 |", "- child\\_exit: expected 0, got 7"}},
		{"exec timeout", func(report string) []string {
			return []string{"exec", "--tape", "../../examples/tapes/your-app-openai-sse-cut.tape.yaml", "--json", "--report", report, "--timeout", "100ms", "--", "sh", "-c", "sleep 2"}
		}, 124, "TIMEOUT: context deadline exceeded", []string{"- TIMEOUT: context deadline exceeded"}},
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
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			for _, want := range tc.wantSummary {
				if !strings.Contains(text, want) {
					t.Errorf("summary missing %q:\n%s", want, text)
				}
			}
			if strings.HasPrefix(tc.name, "test") && strings.Contains(text, "Child exit code") {
				t.Errorf("test summary shows a child exit:\n%s", text)
			}
		})
	}
}

func TestGitHubSummaryEscapesReportText(t *testing.T) {
	dir := t.TempDir()
	report, summary := filepath.Join(dir, "report.json"), filepath.Join(dir, "summary.md")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	const data = `{"command":"exec","exit_code":1,"exec":{"exit_code":7},"summary":{"requests_total":9,"faults_triggered":5,"assertions_passed":2,"assertions_failed":1},"faults_triggered":[{"rule_id":"cut|early","type":"sse-glitch","count":2},{"rule_id":"limit\nnext","type":"rate-limit","count":3}],"diff":["expected a|b\r\n- injected"],"error":{"code":"FAIL","message":"<b>error</b>\nnext"}}`
	if err := os.WriteFile(report, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if code, out := launchOutput(t, "report", "--github", report); code != 0 {
		t.Fatalf("report exit %d: %s", code, out)
	}
	text, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"| 1 | 7 | 9 | 5 | 2 | 1 |", "- cut\\|early (sse-glitch): 2\n", "- limit next (rate-limit): 3\n", "- expected a\\|b - injected\n", "- FAIL: &lt;b&gt;error&lt;/b&gt; next\n"} {
		if !strings.Contains(string(text), want) {
			t.Errorf("summary missing %q:\n%s", want, text)
		}
	}
}
