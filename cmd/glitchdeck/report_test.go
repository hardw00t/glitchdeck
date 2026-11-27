package main

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitHubSummaryForTestAndExecReports(t *testing.T) {
	execTape := execTapeWithoutExpectations(t)
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
			return []string{"exec", "--tape", execTape, "--json", "--report", report, "--allow-zero-traffic", "--", "sh", "-c", "exit 0"}
		}, 0, "", []string{"| Exit code | Child exit code | Requests total | Faults triggered | Assertions passed | Assertions failed |", "| --- | --- | --- | --- | --- | --- |", "| 0 | 0 | 0 | 0 | 0 | 0 |"}},
		{"exec failure", func(report string) []string {
			return []string{"exec", "--tape", execTape, "--json", "--report", report, "--allow-zero-traffic", "--", "sh", "-c", "exit 7"}
		}, 1, "child_exit: expected 0, got 7", []string{"| 1 | 7 | 0 | 0 | 0 | 0 |", "- child\\_exit: expected 0, got 7"}},
		{"exec timeout", func(report string) []string {
			return []string{"exec", "--tape", execTape, "--json", "--report", report, "--timeout", "100ms", "--", "sh", "-c", "sleep 2"}
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

func TestReportJUnit(t *testing.T) {
	type problem struct {
		Message string `xml:"message,attr"`
		Text    string `xml:",chardata"`
	}
	for _, tc := range []struct {
		name, report, suite, firstCase, failureMessage, failureText, errorMessage string
		tests, failures, errors                                                   int
	}{
		{name: "passing assertion", report: `{"schema_version":2,"command":"test","tape":"clean","ok":true,"assertions":[{"name":"no faults","passed":true,"failures":[]}]}`, suite: "clean", firstCase: "no faults", tests: 1},
		{name: "passing expectations", report: `{"schema_version":2,"command":"exec","ok":true,"assertions":[]}`, suite: "glitchdeck", firstCase: "expectations", tests: 1},
		{
			name:   "assertion diff and error",
			report: `{"schema_version":2,"command":"test","tape":"tape <>&\"\u0001","exit_code":3,"assertions":[{"name":"check <>&\"","passed":false,"failures":["bad <>&\"\u0000","another failure"]},{"name":"passing","passed":true}],"diff":["check <>&\": bad <>&\"\u0000","check <>&\": another failure","other: mismatch"],"error":{"code":"FAIL","message":"error <>&\"\ufffe"}}`,
			suite:  "tape <>&\"�", firstCase: `check <>&"`, failureMessage: "bad <>&\"�", failureText: "bad <>&\"�\nanother failure",
			errorMessage: "FAIL: error <>&\"�", tests: 4, failures: 2, errors: 1,
		},
		{name: "exec diff only", report: `{"schema_version":2,"command":"exec","exit_code":1,"diff":["child_exit: expected 0, got 7"]}`, suite: "glitchdeck", failureMessage: "child_exit: expected 0, got 7", tests: 1, failures: 1},
		{name: "failed without details", report: `{"schema_version":2,"exit_code":3}`, suite: "glitchdeck", firstCase: "glitchdeck", failureMessage: "exit code 3", tests: 1, failures: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report.json")
			if err := os.WriteFile(path, []byte(tc.report), 0600); err != nil {
				t.Fatal(err)
			}
			code, out := launchOutput(t, "report", "--junit", path)
			var got struct {
				XMLName xml.Name `xml:"testsuites"`
				Suites  []struct {
					Name     string `xml:"name,attr"`
					Tests    *int   `xml:"tests,attr"`
					Failures *int   `xml:"failures,attr"`
					Errors   *int   `xml:"errors,attr"`
					Cases    []struct {
						Name      string   `xml:"name,attr"`
						Classname string   `xml:"classname,attr"`
						Failure   *problem `xml:"failure"`
						Error     *problem `xml:"error"`
					} `xml:"testcase"`
				} `xml:"testsuite"`
			}
			if err := xml.Unmarshal([]byte(out), &got); code != 0 || err != nil || !strings.HasPrefix(out, xml.Header) || len(got.Suites) != 1 {
				t.Fatalf("exit %d, XML decode error %v, stdout %q", code, err, out)
			}
			s := got.Suites[0]
			if s.Name != tc.suite || s.Tests == nil || *s.Tests != tc.tests || s.Failures == nil || *s.Failures != tc.failures ||
				s.Errors == nil || *s.Errors != tc.errors || len(s.Cases) != tc.tests {
				t.Fatalf("wrong suite or totals:\n%s", out)
			}
			if tc.firstCase != "" && s.Cases[0].Name != tc.firstCase {
				t.Errorf("first testcase name = %q, want %q", s.Cases[0].Name, tc.firstCase)
			}
			var failures, errors int
			for _, c := range s.Cases {
				if c.Classname != tc.suite {
					t.Errorf("classname = %q, want %q", c.Classname, tc.suite)
				}
				if c.Failure != nil {
					failures++
				}
				if c.Error != nil {
					errors++
					if c.Error.Message != tc.errorMessage {
						t.Errorf("error message = %q, want %q", c.Error.Message, tc.errorMessage)
					}
				}
			}
			if failures != tc.failures || errors != tc.errors {
				t.Errorf("testcases contain %d failures and %d errors:\n%s", failures, errors, out)
			}
			if tc.failureMessage != "" {
				f := s.Cases[0].Failure
				if f == nil || f.Message != tc.failureMessage || tc.failureText != "" && f.Text != tc.failureText {
					t.Errorf("wrong first failure:\n%s", out)
				}
			}
		})
	}
}

func TestReportJUnitConflictingFormats(t *testing.T) {
	for _, other := range []string{"--github", "--json"} {
		t.Run(other, func(t *testing.T) {
			if code, out := launchOutput(t, "report", "--junit", other, "missing.json"); code != 2 || out != "" {
				t.Fatalf("exit %d, stdout %q; want exit 2 before reading the report", code, out)
			}
		})
	}
}

func TestReportJUnitHelp(t *testing.T) {
	code, out, stderr := runHelpProcess(t, "report", "--help")
	if code != 0 || stderr != "" || !strings.Contains(out, "usage: glitchdeck report [--github|--json|--junit] report.json\n") ||
		!strings.Contains(out, "\n  -junit\n") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, stderr)
	}
}
