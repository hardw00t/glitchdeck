package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestProxyTapePassthroughDoesNotChangeEgressOrTLS(t *testing.T) {
	if path := os.Getenv("GLITCHDECK_TEST_PROXY_TAPE"); path != "" {
		args := []string{"proxy", "--tape", path, "--target", "http://127.0.0.1:1", "--listen", "0.0.0.0:0", "--allow-remote", "--ui", "127.0.0.1:0", "--json"}
		if os.Getenv("GLITCHDECK_TEST_PROXY_TLS") == "1" {
			args = append(args, "--tls")
		}
		os.Exit(run(args))
	}
	for _, tc := range []struct {
		extra string
		tls   bool
	}{
		{"", false}, {"tls_passthrough: [pinned.test]\n", false},
		{"", true}, {"tls_passthrough: [pinned.test]\n", true},
	} {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		if err := os.WriteFile(path, []byte("version: 2\ntls_mitm: true\nupstream_allow: [0.0.0.0]\n"+tc.extra), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProxyTapePassthroughDoesNotChangeEgressOrTLS$")
		var stderr strings.Builder
		cmd.Stderr = &stderr
		cmd.Env = append(os.Environ(), "GLITCHDECK_TEST_PROXY_TAPE="+path)
		if tc.tls {
			cmd.Env = append(cmd.Env, "GLITCHDECK_TEST_PROXY_TLS=1")
		}
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		var ready struct {
			Proxy string `json:"proxy"`
			TLS   struct {
				Enabled bool `json:"enabled"`
			} `json:"tls"`
		}
		err = json.NewDecoder(out).Decode(&ready)
		if err != nil {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatalf("missing proxy readiness: %v; stderr=%s", err, stderr.String())
		}
		proxyURL, err := url.Parse(ready.Proxy)
		if err != nil {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatal(err)
		}
		proxyURL.Host = strings.Replace(proxyURL.Host, "0.0.0.0", "127.0.0.1", 1)
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 3 * time.Second}
		resp, err := client.Get("http://0.0.0.0:1/")
		if err == nil {
			resp.Body.Close()
		}
		cmd.Process.Kill()
		cmd.Wait()
		if err != nil || resp.StatusCode != http.StatusForbidden || ready.TLS.Enabled != tc.tls {
			t.Fatalf("passthrough=%q response=%v err=%v tls=%v", tc.extra, resp, err, ready.TLS.Enabled)
		}
	}
}
func TestTopLevelHelp(t *testing.T) {
	for _, alias := range []string{"-h", "--help", "help"} {
		t.Run(alias, func(t *testing.T) {
			code, out := launchOutput(t, alias)
			if code != 0 || !strings.Contains(out, "validate") || !strings.Contains(out, "version") {
				t.Fatalf("exit %d, stdout %q", code, out)
			}
		})
	}
	if code, _ := launchOutput(t, "not-a-command"); code != 2 {
		t.Fatalf("unknown command: exit %d, want 2", code)
	}
}

func TestBrowserCommand(t *testing.T) {
	const ui = "http://127.0.0.1:8081"
	for _, tc := range []struct {
		goos, name string
		args       []string
	}{
		{"darwin", "open", []string{ui}},
		{"windows", "rundll32", []string{"url.dll,FileProtocolHandler", ui}},
		{"linux", "xdg-open", []string{ui}},
	} {
		name, args := browserCommand(tc.goos, ui)
		if name != tc.name || !slices.Equal(args, tc.args) {
			t.Errorf("%s: got %q %q, want %q %q", tc.goos, name, args, tc.name, tc.args)
		}
	}
	for _, url := range []string{"http://localhost:8081", "http://[::1]:8081"} {
		if name, _ := browserCommand("linux", url); name == "" {
			t.Errorf("refused loopback URL %q", url)
		}
	}
	for _, url := range []string{"http://0.0.0.0:8081", "http://localhost.example:8081", "http://localhost@example.com:8081", "file://localhost/tmp", "--help"} {
		if name, args := browserCommand("linux", url); name != "" || len(args) != 0 {
			t.Errorf("accepted %q: %q %q", url, name, args)
		}
	}
}

func TestTapeExitCodes(t *testing.T) {
	malformed := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(malformed, []byte("version: [\n"), 0600); err != nil {
		t.Fatal(err)
	}
	multiple := filepath.Join(t.TempDir(), "multiple.yaml")
	if err := os.WriteFile(multiple, []byte("version: 1\ntarget: demo\nassertions:\n  - name: both\n    http_get: /api/state\n    json_eq:\n      duplicate_charges: 99\n      total_charged_cents: 99\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		file string
		code int
		text string
	}{
		{"../../examples/checkout-dup-webhook.tape.yaml", 1, "FAIL "},
		{"../../examples/clean.tape.yaml", 0, "PASS "},
		{multiple, 1, "FAIL both:"},
		{malformed, 2, ""},
	} {
		t.Run(filepath.Base(tc.file), func(t *testing.T) {
			old := os.Stdout
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			os.Stdout = writer
			code := run([]string{"test", tc.file, "--timeout", "5s"})
			os.Stdout = old
			writer.Close()
			output, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				t.Fatal(err)
			}
			if code != tc.code || (tc.text != "" && !strings.Contains(string(output), tc.text)) || (tc.text == "" && len(output) != 0) {
				t.Fatalf("exit %d, stdout %q", code, output)
			}
			if tc.file == multiple && (strings.Count(string(output), "FAIL ") != 1 || !strings.Contains(string(output), "duplicate_charges") || !strings.Contains(string(output), "total_charged_cents")) {
				t.Fatalf("unexpected verdict %q", output)
			}
		})
	}
}

func TestTapeErrorReplacesStaleReport(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "report.json")
	if err := os.WriteFile(report, []byte(`{"ok":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"test", filepath.Join(dir, "missing"), "--report", report}); code != 2 {
		t.Fatalf("exit %d", code)
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		OK       bool `json:"ok"`
		ExitCode int  `json:"exit_code"`
	}
	if err := json.Unmarshal(data, &got); err != nil || got.OK || got.ExitCode != 2 {
		t.Fatalf("stale or invalid report %q: %v", data, err)
	}
}

func TestTapeReportIncludesChangedRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tape.yaml")
	report := filepath.Join(dir, "report.json")
	data := `version: 2
target: demo
rules:
  - {id: changed, enabled: false, fault: {type: rate-limit}}
config_changes:
  - before_seq: 1
    rules:
      - id: changed
        enabled: true
        match: {method: POST, path_prefix: /webhooks/payment}
        fault: {type: dup-webhook, params: {count: 2, delay_ms: 0}}
script:
  - name: payment
    http:
      method: POST
      path: /webhooks/payment
      body: '{"order_id":"ord-101","amount_cents":4900}'
`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"test", path, "--report", report}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Summary struct {
			FaultsTriggered uint64 `json:"faults_triggered"`
		} `json:"summary"`
		Faults []struct {
			RuleID string `json:"rule_id"`
			Type   string `json:"type"`
		} `json:"faults_triggered"`
	}
	if err := json.Unmarshal(raw, &got); err != nil || got.Summary.FaultsTriggered != 1 || len(got.Faults) != 1 || got.Faults[0].RuleID != "changed" || got.Faults[0].Type != "dup-webhook" {
		t.Fatalf("report %s: %v", raw, err)
	}
}

func TestV1RuntimeErrorKeepsJSONStdoutEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tape.yaml")
	report := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, []byte("version: 1\ntarget: \"\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	old := os.Stdout
	os.Stdout = writer
	code := run([]string{"test", "--json", "--report", report, path})
	os.Stdout = old
	writer.Close()
	out, err := io.ReadAll(reader)
	if err != nil || len(out) != 0 || code != 2 {
		t.Fatalf("exit %d, stdout %q, read error %v", code, out, err)
	}
	if data, err := os.ReadFile(report); err != nil || !json.Valid(data) {
		t.Fatalf("missing JSON report: %s (%v)", data, err)
	}
}

func TestDemoMissingCAExplainsInitialization(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "new-ca")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	old := os.Stderr
	os.Stderr = writer
	code := run([]string{"demo", "--ca-dir", dir, "--listen", "127.0.0.1:0", "--ui", "127.0.0.1:0", "--app", "127.0.0.1:0"})
	os.Stderr = old
	writer.Close()
	out, err := io.ReadAll(reader)
	if err != nil || code != 2 || !strings.Contains(string(out), "glitchdeck ca init --ca-dir") || !strings.Contains(string(out), dir) {
		t.Fatalf("exit %d, stderr %q, read error %v", code, out, err)
	}
}
