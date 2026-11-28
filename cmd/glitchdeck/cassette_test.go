package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/execrun"
	"github.com/hardw00t/glitchdeck/internal/tape"
)

func TestExecHybridCassette(t *testing.T) {
	if os.Getenv("GD_CASSETTE_DEMO_TLS") != "" {
		proxyURL, _ := url.Parse(os.Getenv("GLITCHDECK_PROXY_URL"))
		client := http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}, Timeout: 5 * time.Second}
		if os.Getenv("GD_CASSETTE_DEFAULT_CLIENT") != "" {
			client.Transport = http.DefaultTransport
		}
		response, err := client.Get(os.Getenv("GLITCHDECK_DEMO_TLS") + "/")
		if err != nil {
			os.Exit(9)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		os.Exit(0)
	}
	if route := os.Getenv("GD_CASSETTE_TEST_PATH"); route != "" {
		client := http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second}
		base := os.Getenv("GLITCHDECK_PROXY_URL")
		if os.Getenv("GD_CASSETTE_TEST_USE_TARGET") != "" {
			base = os.Getenv("GLITCHDECK_TARGET")
			proxyURL, _ := url.Parse(os.Getenv("GLITCHDECK_PROXY_URL"))
			client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			if os.Getenv("GD_CASSETTE_DEFAULT_CLIENT") != "" {
				client.Transport = http.DefaultTransport
			}
		}
		for path := range strings.SplitSeq(route, ",") {
			response, err := client.Get(base + path)
			if err != nil {
				os.Exit(9)
			}
			if response.Header.Get("Content-Type") == "text/event-stream" || route == "/secret" {
				_, err = io.Copy(os.Stdout, response.Body)
			} else {
				_, err = io.Copy(io.Discard, response.Body)
			}
			response.Body.Close()
			if err != nil {
				os.Exit(9)
			}
		}
		os.Exit(0)
	}

	const events = "data: {\"choices\":[{\"delta\":{\"content\":\"one\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"two\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"three\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"four\"}}]}\n\ndata: [DONE]\n\n"
	secret := "sk-" + "ant-" + strings.Repeat("Z", 32)
	var accepts atomic.Int64
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/completions":
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Set-Cookie", "session=local")
			w.Header().Set("Authorization", "not-for-export")
			z := gzip.NewWriter(w)
			_, _ = io.WriteString(z, events)
			_ = z.Close()
		case "/large":
			_, _ = io.WriteString(w, strings.Repeat("x", 5<<20))
		case "/secret":
			w.Header().Set("Content-Encoding", "gzip")
			z := gzip.NewWriter(w)
			_, _ = fmt.Fprintf(z, `{"api_key":%q}`, secret)
			_ = z.Close()
		case "/diagnostics":
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Content-Encoding", secret)
			_, _ = io.WriteString(w, events)
		default:
			_, _ = io.WriteString(w, "ordinary response")
		}
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepts.Add(1)
		}
	}
	upstream.Start()
	defer upstream.Close()
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input.yaml"), filepath.Join(dir, "output.yaml")
	const rule = `rules:
  - id: cut
    enabled: true
    match: {path_prefix: /v1/chat/completions}
    fault: {type: sse-glitch, params: {action: eof_early, after_events: 3, http_clean: true}}
expect: {faults: [{rule: cut, min_applied: 1}]}
`
	writeInput := func(extra string) []byte {
		t.Helper()
		raw := []byte("version: 2\nname: local cassette smoke\ntarget: " + upstream.URL + "\n" + extra)
		if err := os.WriteFile(input, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	invoke := func(path string, flags ...string) (int, execrun.Envelope) {
		t.Helper()
		args := append([]string{"exec", "--tape", path, "--json", "--grace", "3s"}, flags...)
		args = append(args, "--", os.Args[0], "-test.run=^TestExecHybridCassette$")
		code, raw := launchOutput(t, args...)
		var report execrun.Envelope
		if err := json.Unmarshal([]byte(raw), &report); err != nil {
			t.Fatalf("invalid report: %v", err)
		}
		return code, report
	}
	readOutput := func() []byte {
		t.Helper()
		raw, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	checkCut := func(code int, report execrun.Envelope) {
		t.Helper()
		if code != 0 || report.Exec == nil || report.Summary.FaultsTriggered != 1 {
			t.Fatalf("exit %d, report %+v", code, report)
		}
	}
	checkDeliveredCut := func(code int, report execrun.Envelope) {
		t.Helper()
		checkCut(code, report)
		if strings.Count(report.Exec.StdoutTail, "data: ") != 3 || strings.Contains(report.Exec.StdoutTail, "four") || strings.Contains(report.Exec.StdoutTail, "[DONE]") {
			t.Fatalf("unexpected child stream %q", report.Exec.StdoutTail)
		}
	}
	t.Setenv("GD_CASSETTE_TEST_PATH", "/plain,/v1/chat/completions")
	original := writeInput(rule)
	if code, report := invoke(input, "--mode", "record"); code != 2 || !strings.Contains(fmt.Sprint(report.Error), "USAGE_ERROR") || !strings.Contains(fmt.Sprint(report.Error), "--mode record requires --tape-out") {
		t.Fatalf("missing --tape-out: exit %d, error %v", code, report.Error)
	}
	checkCut(invoke(input, "--mode", "record", "--tape-out", output))
	if current, err := os.ReadFile(input); err != nil || !bytes.Equal(current, original) {
		t.Fatal("the input tape changed")
	}
	doc, err := tape.Decode(bytes.NewReader(readOutput()))
	if err != nil || doc.Version != 3 || len(doc.Cassettes) != 2 {
		t.Fatalf("invalid recorded cassettes: version %d, count %d, error %v", doc.Version, len(doc.Cassettes), err)
	}
	plain, sse := doc.Cassettes[0].Response, doc.Cassettes[1].Response
	if plain.Status != 200 || plain.Body != "ordinary response" || sse.Status != 200 || sse.Body != events {
		t.Fatal("recording did not retain the unfaulted bodies")
	}
	for name := range sse.Headers {
		if strings.EqualFold(name, "Content-Encoding") || strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "Authorization") {
			t.Fatalf("unsafe or stale response header %s", name)
		}
	}
	before := accepts.Load()
	doc.Cassettes = append(doc.Cassettes, doc.Cassettes[0])
	var ambiguous bytes.Buffer
	if err := tape.Encode(&ambiguous, doc); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, ambiguous.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GD_CASSETTE_TEST_PATH", "/plain")
	if code, report := invoke(input, "--mode", "replay", "--allow-zero-traffic"); code != 1 || !strings.Contains(fmt.Sprint(report.Error), "cassette_ambiguous") {
		t.Fatalf("ambiguous replay: exit %d, error %v", code, report.Error)
	}
	t.Setenv("GD_CASSETTE_TEST_PATH", "/plain,/v1/chat/completions")
	checkDeliveredCut(invoke(output, "--mode", "replay"))
	if delta := accepts.Load() - before; delta != 0 {
		t.Fatalf("replay reached the upstream: %d accepts", delta)
	}
	if code, _ := launchOutput(t, "test", "--mode", "replay", "--json", output); code != 0 || accepts.Load() != before {
		t.Fatalf("test replay: exit %d, upstream accepts %d", code, accepts.Load()-before)
	}
	checkDeliveredCut(invoke(output))
	if accepts.Load() <= before {
		t.Fatal("default mode did not reach the upstream")
	}
	t.Setenv("GD_CASSETTE_TEST_PATH", "/missing")
	if code, report := invoke(output, "--mode", "replay", "--allow-zero-traffic"); code != 1 || !strings.Contains(fmt.Sprint(report.Error), "cassette_miss") {
		t.Fatalf("replay miss: exit %d, error %v", code, report.Error)
	}
	if err := os.WriteFile(input, []byte("version: 3\ntarget: demo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if code, report := invoke(input, "--mode", "replay", "--allow-zero-traffic"); code == 0 || !strings.Contains(fmt.Sprint(report.Error), "cassette_miss") {
		t.Fatalf("cassette-less replay: exit %d, error %v", code, report.Error)
	}
	writeInput("")
	t.Setenv("GD_CASSETTE_TEST_PATH", "/large")
	if code, report := invoke(input, "--mode", "record", "--tape-out", output); code != 0 {
		t.Fatalf("large recording: exit %d, error %v", code, report.Error)
	}
	raw := readOutput()
	if !bytes.Contains(raw, []byte("incomplete: true")) || bytes.Count(raw, []byte("truncated: true")) < 2 {
		t.Fatal("large recording lacks truncation and incomplete markers")
	}
	if _, err := tape.Decode(bytes.NewReader(raw)); err == nil {
		t.Fatal("accepted incomplete recording")
	}
	if err := os.Remove(output); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GD_CASSETTE_TEST_PATH", "/secret")
	reportPath := filepath.Join(dir, "report.json")
	code, stdout := launchOutput(t, "exec", "--tape", input, "--json", "--report", reportPath, "--mode", "record", "--tape-out", output, "--", os.Args[0], "-test.run=^TestExecHybridCassette$")
	reportBytes, err := os.ReadFile(reportPath)
	if err != nil || code != 2 || !strings.Contains(stdout, "EXPORT_BLOCKED") || strings.Contains(stdout, secret) || bytes.Contains(reportBytes, []byte(secret)) || strings.Contains(stdout, dir) || bytes.Contains(reportBytes, []byte(dir)) ||
		!strings.Contains(stdout, "secret_kind=anthropic") || !strings.Contains(stdout, "field=$.") || !bytes.Contains(reportBytes, []byte("secret_kind=anthropic")) || !bytes.Contains(reportBytes, []byte("field=$.")) {
		t.Fatalf("blocked output leaked or failed: exit %d, stdout %q, report %q, err %v", code, stdout, reportBytes, err)
	}
	code, stdout = launchOutput(t, "exec", "--tape", input, "--mode", "record", "--tape-out", output, "--", os.Args[0], "-test.run=^TestExecHybridCassette$")
	if code != 2 || strings.Count(stdout, secret) != 1 {
		t.Fatalf("record did not pass through the child output: exit %d, stdout %q", code, stdout)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("blocked export wrote a file")
	}
	if code, report := invoke(input, "--mode", "record", "--tape-out", output, "--redact-secrets"); code != 0 || report.Exec == nil || report.Exec.StdoutTail != "" || report.Exec.StderrTail != "" {
		t.Fatalf("redacted recording: exit %d, report %+v", code, report)
	}
	errReader, errWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = errWriter
	code, stdout = launchOutput(t, "exec", "--tape", input, "--json", "--report", reportPath, "--mode", "record", "--redact-secrets", "--tape-out", output, "--", os.Args[0], "-test.run=^TestExecHybridCassette$")
	os.Stderr = oldStderr
	errWriter.Close()
	stderr, err := io.ReadAll(errReader)
	errReader.Close()
	if err != nil {
		t.Fatal(err)
	}
	reportBytes, err = os.ReadFile(reportPath)
	if err != nil || code != 0 || strings.Contains(stdout, secret) || bytes.Contains(stderr, []byte(secret)) || bytes.Contains(reportBytes, []byte(secret)) || strings.Contains(stdout, dir) || bytes.Contains(stderr, []byte(dir)) || bytes.Contains(reportBytes, []byte(dir)) {
		t.Fatalf("redacted diagnostics leaked: exit %d stdout %q stderr %q report %q err %v", code, stdout, stderr, reportBytes, err)
	}
	raw = readOutput()
	if bytes.Contains(raw, []byte(secret)) || !bytes.Contains(raw, []byte("redacted: true")) || !bytes.Contains(raw, []byte("REDACTED")) {
		t.Fatal("redacted export still contains the original secret or lacks its markers")
	}

	writeInput("rules:\n  - id: diagnostic\n    enabled: true\n    match: {path_prefix: /diagnostics}\n    fault: {type: sse-glitch, params: {action: eof_early, after_events: 1}}\n")
	t.Setenv("GD_CASSETTE_TEST_PATH", "/diagnostics,/secret")
	log, err := os.CreateTemp(dir, "record-stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	os.Stderr = log
	defer func() { os.Stderr = oldStderr }()
	code, stdout = launchOutput(t, "exec", "--tape", input, "--json", "--report", reportPath, "--mode", "record", "--tape-out", output, "--", os.Args[0], "-test.run=^TestExecHybridCassette$")
	logBytes, err := os.ReadFile(log.Name())
	if err != nil {
		t.Fatal(err)
	}
	reportBytes, err = os.ReadFile(reportPath)
	if err != nil || code != 2 || !strings.Contains(stdout, "EXPORT_BLOCKED") {
		t.Fatalf("blocked diagnostic run: exit %d, report %q, err %v", code, stdout, err)
	}
	for _, sink := range []string{stdout, string(logBytes), string(reportBytes)} {
		if strings.Contains(sink, secret) || strings.Contains(sink, dir) {
			t.Fatalf("blocked run disclosed a diagnostic: %q", sink)
		}
	}
}

func TestRecordReplayPreservesLogicalTargetPrefix(t *testing.T) {
	var requests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/prefix/item" {
			t.Errorf("unexpected logical path: %s", r.URL.Path)
		}
		requests.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	dir := t.TempDir()
	input, output := filepath.Join(dir, "in.yaml"), filepath.Join(dir, "out.yaml")
	if err := os.WriteFile(input, []byte("version: 2\ntarget: "+upstream.URL+"/prefix\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GD_CASSETTE_TEST_PATH", "/item")
	t.Setenv("GD_CASSETTE_TEST_USE_TARGET", "1")
	child := []string{"--", os.Args[0], "-test.run=^TestExecHybridCassette$"}
	args := append([]string{"exec", "--json", "--tape", input, "--mode", "record", "--tape-out", output}, child...)
	if code, out := launchOutput(t, args...); code != 0 {
		t.Fatalf("record exit %d: %s", code, out)
	}
	t.Setenv("GD_CASSETTE_DEFAULT_CLIENT", "1")
	args = append([]string{"exec", "--json", "--tape", output, "--mode", "replay"}, child...)
	if code, out := launchOutput(t, args...); code != 0 {
		t.Fatalf("replay exit %d: %s", code, out)
	}
	if requests.Load() != 1 {
		t.Fatalf("replay reached upstream or record missed it: %d requests", requests.Load())
	}
}

func TestReplayDemoTLSDefaultClient(t *testing.T) {
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input.yaml"), filepath.Join(dir, "output.yaml")
	if err := os.WriteFile(input, []byte("version: 2\ntarget: demo\ntls_mitm: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GD_CASSETTE_DEMO_TLS", "1")
	child := []string{"--", os.Args[0], "-test.run=^TestExecHybridCassette$"}
	args := append([]string{"exec", "--json", "--tape", input, "--mode", "record", "--tape-out", output}, child...)
	if code, out := launchOutput(t, args...); code != 0 {
		t.Fatalf("record exit %d: %s", code, out)
	}
	t.Setenv("GD_CASSETTE_DEFAULT_CLIENT", "1")
	args = append([]string{"exec", "--json", "--tape", output, "--mode", "replay"}, child...)
	if code, out := launchOutput(t, args...); code != 0 {
		raw, _ := os.ReadFile(output)
		t.Fatalf("replay exit %d: %s\nrecorded tape: %s", code, out, raw)
	}
}
