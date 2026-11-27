package execrun

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/tape"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
	"github.com/hardw00t/glitchdeck/internal/tlsmitm"
)

func TestExecInjectsProxy(t *testing.T) {
	if os.Getenv("GD_HELPER") == "1" {
		if os.Getenv("GLITCHDECK_PROXY_URL") == "" {
			os.Exit(9)
		}
		os.Exit(0)
	}
	t.Setenv("GD_HELPER", "1")
	r := Run(context.Background(), tape.Tape{Version: 2, Target: "demo"}, Options{Command: []string{os.Args[0], "-test.run=TestExecInjectsProxy"}, AllowZeroTraffic: true})
	if r.ExitCode != 0 {
		t.Fatalf("exit %d: %+v", r.ExitCode, r)
	}
}

func TestExecTLSExportsUsableBundle(t *testing.T) {
	if os.Getenv("GD_TLS_HELPER") == "1" {
		bundle := os.Getenv("SSL_CERT_FILE")
		for _, name := range []string{"REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH", "AWS_CA_BUNDLE", "DENO_CERT", "GIT_SSL_CAINFO", "PIP_CERT", "NPM_CONFIG_CAFILE", "CARGO_HTTP_CAINFO"} {
			if bundle == "" || os.Getenv(name) != bundle {
				t.Fatalf("%s does not point to SSL_CERT_FILE", name)
			}
		}
		if os.Getenv("NODE_EXTRA_CA_CERTS") == os.Getenv("GLITCHDECK_CA_CERT") {
			t.Fatal("NODE_EXTRA_CA_CERTS must use the merged Node bundle")
		}
		data, err := os.ReadFile(bundle)
		if err != nil {
			t.Fatal(err)
		}
		ca, err := os.ReadFile(os.Getenv("GLITCHDECK_CA_CERT"))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(ca)
		pool := x509.NewCertPool()
		if block == nil || !pool.AppendCertsFromPEM(data) {
			t.Fatal("invalid CA or bundle")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
			t.Fatalf("bundle does not trust proxy CA: %v", err)
		}
		for _, name := range []string{"GD_GIT_TEST_CERT", "GD_PUBLIC_TEST_CERT"} {
			path := os.Getenv(name)
			if path == "" {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(data)
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
				t.Fatalf("bundle discarded %s: %v", name, err)
			}
		}
		return
	}
	t.Setenv("GD_TLS_HELPER", "1")
	dir := t.TempDir()
	private, err := tlsmitm.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	gitRoot := filepath.Join(dir, "git.pem")
	if err := os.WriteFile(gitRoot, private.PEM, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_SSL_CAINFO", gitRoot)
	t.Setenv("GD_GIT_TEST_CERT", gitRoot)
	for data := systemPEM(); len(data) != 0; {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		cert, err := x509.ParseCertificate(block.Bytes)
		if block.Type != "CERTIFICATE" || err != nil || cert.Subject.CommonName != "ISRG Root X1" {
			continue
		}
		path := filepath.Join(dir, "public.pem")
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("GD_PUBLIC_TEST_CERT", path)
		break
	}
	r := Run(context.Background(), tape.Tape{Version: 2, Target: "demo"}, Options{TLS: true, Command: []string{os.Args[0], "-test.run=^TestExecTLSExportsUsableBundle$"}, JSON: true, AllowZeroTraffic: true})
	if r.ExitCode != 0 {
		t.Fatalf("exit %d: %+v", r.ExitCode, r)
	}
}

func TestExecExitCodesAndSecretRedaction(t *testing.T) {
	dir := t.TempDir()
	denied := filepath.Join(dir, "denied")
	if err := os.WriteFile(denied, []byte("not executable"), 0600); err != nil {
		t.Fatal(err)
	}
	invalid := filepath.Join(dir, "invalid")
	if err := os.WriteFile(invalid, []byte("not an executable"), 0700); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		cmd      []string
		timeout  time.Duration
		want     int
		wantDiff string
	}{
		{"success", []string{"sh", "-c", "exit 0"}, 0, 0, ""},
		{"mismatch", []string{"sh", "-c", "exit 7"}, 0, 1, "child_exit: expected 0, got 7"},
		{"usage", nil, 0, 2, ""},
		{"timeout", []string{"sh", "-c", "sleep 5"}, 50 * time.Millisecond, 124, ""},
		{"start failure", []string{invalid}, 0, 125, ""},
		{"permission", []string{denied}, 0, 126, ""},
		{"not found", []string{filepath.Join(dir, "missing")}, 0, 127, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Run(context.Background(), tape.Tape{Version: 2, Target: "demo"}, Options{Command: tc.cmd, Timeout: tc.timeout, Grace: 50 * time.Millisecond, JSON: true, AllowZeroTraffic: true})
			if r.ExitCode != tc.want {
				t.Fatalf("exit %d, want %d: %+v", r.ExitCode, tc.want, r)
			}
			if diff := strings.Join(r.Diff, "\n"); diff != tc.wantDiff {
				t.Fatalf("diff %q, want %q", diff, tc.wantDiff)
			}
		})
	}
	r := Run(context.Background(), tape.Tape{Version: 2, Target: "demo"}, Options{Command: []string{"sh", "-c", "printf '%s' \"$HTTP_PROXY\""}, ProxyAuth: true, JSON: true})
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "glitchdeck:") {
		t.Fatalf("credentials in report: %s", b)
	}
}

func TestObservedGRPCAssertion(t *testing.T) {
	bus := telemetry.New()
	bus.Publish("grpc_call", map[string]any{"seq": 1, "grpc_status": 14})
	bus.Publish("http_req", map[string]any{"seq": 1, "path": "/service/method"})
	want := 14
	tp := tape.Tape{Script: []tape.Step{{Name: "call", GRPC: &tape.GRPC{Path: "/service/method"}}}}
	a := tape.Assertion{Name: "status", GRPCStep: "call", ExpectGRPCStatus: &want}
	if r := observedAssertion(a, tp, bus.History(10)); len(r.Failures) != 0 {
		t.Fatal(r.Failures)
	}
	want = 4
	if r := observedAssertion(a, tp, bus.History(10)); len(r.Failures) == 0 {
		t.Fatal("expected mismatch")
	}
}

func TestObservedGRPCDistinctSteps(t *testing.T) {
	bus := telemetry.New()
	bus.Publish("http_req", map[string]any{"seq": 1, "path": "/service/method"})
	bus.Publish("grpc_call", map[string]any{"seq": 1, "grpc_status": 0})
	bus.Publish("http_req", map[string]any{"seq": 2, "path": "/service/method"})
	bus.Publish("grpc_call", map[string]any{"seq": 2, "grpc_status": 14})
	tp := tape.Tape{Script: []tape.Step{
		{Name: "first", GRPC: &tape.GRPC{Path: "/service/method"}},
		{Name: "second", GRPC: &tape.GRPC{Path: "/service/method"}},
	}}
	want := 14
	a := tape.Assertion{Name: "second status", GRPCStep: "second", ExpectGRPCStatus: &want}
	if r := observedAssertion(a, tp, bus.History(10)); len(r.Failures) != 0 {
		t.Fatal(r.Failures)
	}
	tp.Script[1].Seq = 1
	if r := observedAssertion(a, tp, bus.History(10)); len(r.Failures) == 0 {
		t.Fatal("explicit sequence was ignored")
	}
}

func TestHTTPAssertionRejectsMissingNullAndLargeNumberMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"number":9007199254740993}`))
	}))
	defer server.Close()
	tp := tape.Tape{Assertions: []tape.Assertion{{
		Name: "json", HTTPGet: "/", Direct: true,
		JSONEq: map[string]any{"missing": nil, "number": json.Number("9007199254740992")},
	}}}
	result := assertions(context.Background(), tp, "", server.URL, "", nil)
	if len(result) != 1 || len(result[0].Failures) != 2 {
		t.Fatalf("expected both mismatches: %+v", result)
	}
}

func TestExecReportsChildRequests(t *testing.T) {
	if os.Getenv("GD_COUNT_HELPER") == "1" {
		resp, err := http.Get(os.Getenv("GLITCHDECK_PROXY_URL") + "/api/state")
		if err != nil {
			os.Exit(9)
		}
		resp.Body.Close()
		os.Exit(0)
	}
	t.Setenv("GD_COUNT_HELPER", "1")
	r := Run(context.Background(), tape.Tape{Version: 2, Target: "demo"}, Options{
		Command: []string{os.Args[0], "-test.run=TestExecReportsChildRequests"},
		JSON:    true,
	})
	if r.ExitCode != 0 || r.Summary.RequestsTotal != 1 {
		t.Fatalf("unexpected child report: %+v", r)
	}
}

func TestExecAbsoluteFormToSelfAssertsSSEReset(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl unavailable")
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	f, err := os.Open("../../examples/tapes/openai-sse-truncate-rst.tape.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tp, err := tape.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	r := Run(context.Background(), tp, Options{
		Command: []string{"sh", "-c", `
			test "$NO_PROXY" = "example.invalid,${GLITCHDECK_PROXY_URL#http://}" && \
				test "$no_proxy" = "$NO_PROXY" || exit 9
			unset NO_PROXY no_proxy
			curl -q -sS -N --max-time 5 -X POST -H 'Content-Type: application/json' \
				-d '{"tokens":8,"token_ms":1}' "$GLITCHDECK_PROXY_URL/api/chat/stream"
			test "$?" -eq 56
		`},
		NoProxy: "example.invalid",
		JSON:    true,
	})
	if r.ExitCode != 0 || r.Summary.RequestsTotal != 1 || r.Summary.AssertionsPassed != 1 {
		t.Fatalf("unexpected child report: %+v, exec: %+v", r, r.Exec)
	}
}

func TestHTTPAssertionDoesNotFollowRedirect(t *testing.T) {
	followed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			followed = true
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer server.Close()
	tp := tape.Tape{Assertions: []tape.Assertion{{HTTPGet: "/", Direct: true, ExpectStatus: http.StatusFound}}}
	result := assertions(context.Background(), tp, "", server.URL, "", nil)
	if followed || len(result) != 1 || len(result[0].Failures) != 0 {
		t.Fatalf("redirect followed or assertion failed: %+v", result)
	}
}

func TestObservedGRPCUsesAdmissionOrder(t *testing.T) {
	bus := telemetry.New()
	bus.Publish("grpc_call", map[string]any{"seq": 2, "grpc_status": 14})
	bus.Publish("http_req", map[string]any{"seq": 2, "path": "/call", "method": "POST"})
	bus.Publish("grpc_call", map[string]any{"seq": 1, "grpc_status": 0})
	bus.Publish("http_req", map[string]any{"seq": 1, "path": "/call", "method": "POST"})
	tp := tape.Tape{Script: []tape.Step{{Name: "first", GRPC: &tape.GRPC{Path: "/call"}}, {Name: "second", GRPC: &tape.GRPC{Path: "/call"}}}}
	want := 14
	result := observedAssertion(tape.Assertion{GRPCStep: "second", ExpectGRPCStatus: &want}, tp, bus.History(10))
	if len(result.Failures) != 0 {
		t.Fatal(result.Failures)
	}
}

func TestAssertionEvidenceSurvivesHistoryEviction(t *testing.T) {
	want := 14
	tp := tape.Tape{Script: []tape.Step{{Name: "call", GRPC: &tape.GRPC{Path: "/call"}}}, Assertions: []tape.Assertion{{GRPCStep: "call", ExpectGRPCStatus: &want}}}
	evidence := newAssertionEvidence(tp)
	bus := telemetry.New()
	bus.SetObserver(evidence.observe)
	evidence.admit(1, "POST", "/call", "127.0.0.1")
	bus.Publish("grpc_call", map[string]any{"seq": 1, "grpc_status": 14})
	bus.Publish("http_req", map[string]any{"seq": 1, "path": "/call", "method": "POST"})
	for i := range 5000 {
		bus.Publish("http_req", map[string]any{"seq": i + 2, "path": "/other"})
	}
	if r := observedAssertion(tp.Assertions[0], tp, evidence.history()); len(r.Failures) != 0 {
		t.Fatal(r.Failures)
	}
}

func TestPassingFaultExpectationIsCounted(t *testing.T) {
	min := uint64(0)
	tp := tape.Tape{Version: 2, Target: "demo", Expect: tape.Expect{Faults: []tape.FaultExpect{{Rule: "unused", MinApplied: &min}}}}
	r := Run(context.Background(), tp, Options{Command: []string{os.Args[0], "-test.run=^$"}, JSON: true, AllowZeroTraffic: true})
	if r.Summary.AssertionsTotal != 1 || r.Summary.AssertionsPassed != 1 {
		t.Fatalf("unexpected summary: %+v", r.Summary)
	}
}

func TestExecAppliesSequenceConfigChange(t *testing.T) {
	if os.Getenv("GD_CONFIG_HELPER") == "1" {
		for _, status := range []int{200, 429} {
			resp, err := http.Get(os.Getenv("GLITCHDECK_PROXY_URL") + "/api/state")
			if err != nil {
				os.Exit(8)
			}
			resp.Body.Close()
			if resp.StatusCode != status {
				os.Exit(9)
			}
		}
		os.Exit(0)
	}
	t.Setenv("GD_CONFIG_HELPER", "1")
	rule := fault.Rule{ID: "late", Enabled: true, Fault: fault.Fault{Type: "rate-limit", Params: map[string]any{"status": 429}}}
	tp := tape.Tape{Version: 2, Target: "demo", ConfigChanges: []tape.ConfigChange{{BeforeSeq: 2, Rules: []fault.Rule{rule}}}}
	r := Run(context.Background(), tp, Options{Command: []string{os.Args[0], "-test.run=TestExecAppliesSequenceConfigChange"}, JSON: true})
	if r.ExitCode != 0 {
		t.Fatalf("configuration was not applied: %+v", r)
	}
}

func TestObservedSSEUsesDeliveredSummary(t *testing.T) {
	bus := telemetry.New()
	bus.Publish("sse_event", map[string]any{"seq": 1, "kind": "event", "preview": "{", "data_bytes": 100})
	bus.Publish("sse_event", map[string]any{"seq": 1, "kind": "end", "end": "eof", "events": 2, "delivered_events": 1, "delivered_valid_json": true, "delivered_done": false, "delivered_max_gap_ms": 0, "terminal": "error"})
	bus.Publish("http_req", map[string]any{"seq": 1, "path": "/stream", "method": "GET", "status": 200})
	one, yes := 1, true
	tp := tape.Tape{Script: []tape.Step{{Name: "stream", Stream: &tape.Stream{Path: "/stream"}}}}
	a := tape.Assertion{StreamStep: "stream", ExpectStatus: 200, ExpectSSE: &tape.SSEExpect{MinEvents: &one, MaxEvents: &one, ValidJSON: &yes, Terminal: "error"}}
	if r := observedAssertion(a, tp, bus.History(10)); len(r.Failures) != 0 {
		t.Fatal(r.Failures)
	}
}

func TestObservedSSEDoesNotAssertOnOpaquePassThrough(t *testing.T) {
	bus := telemetry.New()
	bus.Publish("http_req", map[string]any{"seq": 1, "path": "/stream", "method": "GET", "status": 200})
	bus.Publish("sse_event", map[string]any{"seq": 1, "kind": "end", "terminal": "none", "encoding": "gzip", "inspected": false})
	tp := tape.Tape{Script: []tape.Step{{Name: "stream", Stream: &tape.Stream{Path: "/stream"}}}}
	a := tape.Assertion{StreamStep: "stream", ExpectSSE: &tape.SSEExpect{Terminal: "none"}}
	if got := observedAssertion(a, tp, bus.History(10)); len(got.Failures) != 1 || !strings.Contains(got.Failures[0], "not inspected") {
		t.Fatalf("expected an inconclusive assertion, got %+v", got)
	}
}

func TestExecLegacyTerminalEvidence(t *testing.T) {
	if os.Getenv("GD_TERMINAL_HELPER") == "1" {
		for _, path := range []string{"/stop", "/completed"} {
			resp, err := http.Get(os.Getenv("GLITCHDECK_PROXY_URL") + path)
			if err != nil {
				os.Exit(9)
			}
			_, err = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if err != nil {
				os.Exit(9)
			}
		}
		os.Exit(0)
	}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if r.URL.Path == "/stop" {
			fmt.Fprint(w, "event: message_stop\ndata: {}\n\n")
			return
		}
		fmt.Fprint(w, "event: response.completed\ndata: {}\n\ndata: [DONE]\n\n")
	}))
	defer up.Close()
	t.Setenv("GD_TERMINAL_HELPER", "1")
	one, two, yes := 1, 2, true
	tp := tape.Tape{Version: 2, Target: up.URL, Script: []tape.Step{
		{Name: "stop", Stream: &tape.Stream{Path: "/stop"}},
		{Name: "completed", Stream: &tape.Stream{Path: "/completed"}},
	}, Assertions: []tape.Assertion{
		{StreamStep: "stop", ExpectSSE: &tape.SSEExpect{End: "eof", Terminal: "message_stop", Done: &yes, MinEvents: &one, MaxEvents: &one}},
		{StreamStep: "completed", ExpectSSE: &tape.SSEExpect{End: "done", Terminal: "response.completed", Done: &yes, MinEvents: &two, MaxEvents: &two}},
	}}
	r := Run(context.Background(), tp, Options{Command: []string{os.Args[0], "-test.run=^TestExecLegacyTerminalEvidence$"}, JSON: true})
	if r.ExitCode != 0 {
		t.Fatalf("exec evidence: %+v", r)
	}
}

func TestExecRejectsUnobservedTrafficAndFaults(t *testing.T) {
	if os.Getenv("GD_ZERO_HELPER") == "1" {
		resp, err := http.Get(os.Getenv("GLITCHDECK_PROXY_URL") + "/api/state")
		if err != nil {
			os.Exit(9)
		}
		resp.Body.Close()
		os.Exit(0)
	}
	zero := uint64(0)
	rule := fault.Rule{ID: "miss", Enabled: true, Match: fault.Match{PathPrefix: "/never"}, Fault: fault.Fault{Type: "rate-limit"}}
	for _, tc := range []struct {
		name           string
		traffic, allow bool
		assertions     []tape.Assertion
		rules          []fault.Rule
		expect         []tape.FaultExpect
		want           int
		diff           string
	}{
		{name: "no traffic", want: 1, diff: "zero_traffic"},
		{name: "assertion traffic is not child traffic", assertions: []tape.Assertion{{Name: "state", HTTPGet: "/api/state", ExpectStatus: 200}}, want: 1, diff: "zero_traffic"},
		{name: "opt out", allow: true, want: 0},
		{name: "no matched fault", traffic: true, rules: []fault.Rule{rule}, want: 1, diff: "zero_faults"},
		{name: "assertion fault is not a child fault", traffic: true, rules: []fault.Rule{rule}, assertions: []tape.Assertion{{Name: "limited probe", HTTPGet: "/never", ExpectStatus: 429}}, want: 1, diff: "zero_faults"},
		{name: "opt out of no matched fault", traffic: true, allow: true, rules: []fault.Rule{rule}, want: 0},
		{name: "explicit zero", traffic: true, rules: []fault.Rule{rule}, expect: []tape.FaultExpect{{Rule: "miss", MaxApplied: &zero}}, want: 0},
		{name: "unrelated zero expectation", traffic: true, rules: []fault.Rule{rule}, expect: []tape.FaultExpect{{Rule: "other", MaxApplied: &zero}}, want: 1, diff: "zero_faults"},
		{name: "minimum zero", traffic: true, rules: []fault.Rule{rule}, expect: []tape.FaultExpect{{Rule: "miss", MinApplied: &zero}}, want: 0},
		{name: "zero is not explicit", traffic: true, rules: []fault.Rule{rule}, expect: []tape.FaultExpect{{Rule: "miss"}}, want: 1, diff: "zero_faults"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := []string{os.Args[0], "-test.run=^$"}
			if tc.traffic {
				t.Setenv("GD_ZERO_HELPER", "1")
				cmd = []string{os.Args[0], "-test.run=^TestExecRejectsUnobservedTrafficAndFaults$"}
			}
			tp := tape.Tape{Version: 2, Target: "demo", Rules: tc.rules, Assertions: tc.assertions, Expect: tape.Expect{Faults: tc.expect}}
			r := Run(context.Background(), tp, Options{Command: cmd, JSON: true, AllowZeroTraffic: tc.allow})
			if r.ExitCode != tc.want || (tc.diff != "" && !strings.Contains(strings.Join(r.Diff, "\n"), tc.diff)) {
				t.Fatalf("unexpected result: %+v", r)
			}
		})
	}
}

func TestExecReportsTLSHandshakeFailure(t *testing.T) {
	if os.Getenv("GD_TLS_REJECT_HELPER") == "1" {
		proxyURL, err := url.Parse(os.Getenv("GLITCHDECK_PROXY_URL"))
		if err != nil {
			os.Exit(9)
		}
		client := &http.Client{Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12},
		}, Timeout: 3 * time.Second}
		_, err = client.Get("https://127.0.0.1:443/")
		if err == nil {
			os.Exit(9)
		}
		return
	}
	t.Setenv("GD_TLS_REJECT_HELPER", "1")
	r := Run(context.Background(), tape.Tape{Version: 2, Target: "demo"}, Options{
		TLS: true, JSON: true, Command: []string{os.Args[0], "-test.run=^TestExecReportsTLSHandshakeFailure$"},
	})
	if r.ExitCode != 1 || !strings.Contains(strings.Join(r.Diff, "\n"), "tls_rejected_only") || len(r.Exec.TLSHandshakeFailures) != 1 ||
		r.Exec.TLSHandshakeFailureCount != 1 || r.Exec.TLSHandshakeFailuresOmitted != 0 ||
		!strings.Contains(string(r.Exec.TLSHandshakeFailures[0]), "bad certificate") {
		t.Fatalf("missing TLS failure in report: %+v", r)
	}
}

func TestExecFaultExpectationsUseChildTrafficOnly(t *testing.T) {
	if os.Getenv("GD_FAULT_CHILD") == "1" {
		resp, err := http.Get(os.Getenv("GLITCHDECK_PROXY_URL") + "/api/state")
		if err != nil {
			os.Exit(9)
		}
		resp.Body.Close()
		return
	}
	t.Setenv("GD_FAULT_CHILD", "1")
	zero, one := uint64(0), uint64(1)
	rules := []fault.Rule{
		{ID: "optional", Enabled: true, Match: fault.Match{PathPrefix: "/optional"}, Fault: fault.Fault{Type: "rate-limit"}},
		{ID: "required", Enabled: true, Match: fault.Match{PathPrefix: "/required"}, Fault: fault.Fault{Type: "rate-limit"}},
	}
	for _, tc := range []struct {
		name     string
		min, max *uint64
		want     int
	}{
		{"minimum", &one, nil, 1}, {"maximum", nil, &zero, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tp := tape.Tape{Version: 2, Target: "demo", Rules: rules,
				Assertions: []tape.Assertion{{Name: "probe", HTTPGet: "/required", ExpectStatus: 429}},
				Expect:     tape.Expect{Faults: []tape.FaultExpect{{Rule: "optional", MinApplied: &zero}, {Rule: "required", MinApplied: tc.min, MaxApplied: tc.max}}}}
			r := Run(context.Background(), tp, Options{Command: []string{os.Args[0], "-test.run=^TestExecFaultExpectationsUseChildTrafficOnly$"}, JSON: true})
			if r.ExitCode != tc.want || r.Summary.FaultsTriggered != 1 {
				t.Fatalf("unexpected result: %+v", r)
			}
		})
	}
}

func TestTLSFailureEvidenceSurvivesHistoryEvictionAndIsBounded(t *testing.T) {
	bus := telemetry.New()
	var failures tlsFailureEvidence
	bus.SetObserver(failures.observe)
	for range 110 {
		bus.Publish("tls_handshake_failed", map[string]string{"error": "rejected"})
	}
	bus.Publish("tls_handshake_failed", map[string]string{"error": strings.Repeat("x", 5000)})
	for range 4100 {
		bus.Publish("http_req", nil)
	}
	count, details := failures.snapshot()
	if count != 111 || len(details) != 100 {
		t.Fatalf("count=%d details=%d", count, len(details))
	}
}

func TestExecWaitTimeoutSkipsAssertions(t *testing.T) {
	if os.Getenv("GD_WAIT_CHILD") == "1" {
		resp, err := http.Get(os.Getenv("GLITCHDECK_PROXY_URL") + "/slow")
		if err != nil {
			os.Exit(9)
		}
		resp.Body.Close()
		return
	}
	var slow atomic.Int32
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			slow.Add(1)
		} else {
			probes.Add(1)
		}
	}))
	defer srv.Close()
	t.Setenv("GD_WAIT_CHILD", "1")
	t.Setenv("GORACE", strings.TrimSpace(os.Getenv("GORACE")+" atexit_sleep_ms=0"))
	tp := tape.Tape{Version: 2, Target: srv.URL, Rules: []fault.Rule{{ID: "dup", Enabled: true, Match: fault.Match{PathPrefix: "/slow"}, Fault: fault.Fault{Type: "dup-webhook", Params: map[string]any{"delay_ms": 500}}}}, Assertions: []tape.Assertion{{Name: "probe", HTTPGet: "/probe", ExpectStatus: 200}}}
	r := Run(context.Background(), tp, Options{Command: []string{os.Args[0], "-test.run=^TestExecWaitTimeoutSkipsAssertions$"}, JSON: true, Grace: 50 * time.Millisecond, AllowLoopbackEgress: true})
	if slow.Load() != 1 {
		t.Fatalf("slow requests = %d", slow.Load())
	}
	if r.ExitCode != 3 || probes.Load() != 0 {
		t.Fatalf("exit=%d probes=%d result=%+v", r.ExitCode, probes.Load(), r)
	}
}

func TestMergeNoProxy(t *testing.T) {
	target, _ := url.Parse("http://localhost:3000")
	got, dropped := mergeNoProxy("internal.example.test,localhost", ".svc.test", "", "127.0.0.1:1234", target)
	if got != "internal.example.test,.svc.test,127.0.0.1:1234" || strings.Join(dropped, ",") != "localhost" {
		t.Fatalf("merge = %q, dropped %v", got, dropped)
	}
	got, dropped = mergeNoProxy("localhost", "", " LOCALHOST ", "127.0.0.1:1234", target)
	if got != " LOCALHOST ,127.0.0.1:1234" || len(dropped) != 0 {
		t.Fatalf("explicit merge = %q, dropped %v", got, dropped)
	}
	target, _ = url.Parse("http://example.com")
	got, _ = mergeNoProxy("localhost", "", "", "127.0.0.1:1234", target)
	if !strings.HasPrefix(got, "localhost,") {
		t.Fatal(got)
	}
	target, _ = url.Parse("https://api.example.com")
	got, dropped = mergeNoProxy("example.com,*.example.com,*.com,example.com:443", "api.EXAMPLE.com:443,.example.com:8443,*.other.test", "", "127.0.0.1:1234", target)
	if got != ".example.com:8443,*.other.test,127.0.0.1:1234" || strings.Join(dropped, ",") != "example.com,*.example.com,*.com,example.com:443,api.EXAMPLE.com:443" {
		t.Fatalf("domain merge = %q, dropped %v", got, dropped)
	}
}

func TestExecTrafficChecks(t *testing.T) {
	if mode := os.Getenv("GD_TRAFFIC_HELPER"); mode != "" {
		p, _ := url.Parse(os.Getenv("GLITCHDECK_PROXY_URL"))
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(p), TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}}}
		if mode == "denied" || mode == "mixed" || mode == "oversized denial" {
			target := "http://example.com/?token=do-not-print"
			if mode == "mixed" {
				target = "https://example.com/"
			}
			if mode == "oversized denial" {
				target = "http://" + strings.Repeat("a", 64<<10) + ".test/"
			}
			resp, _ := client.Get(target)
			if resp != nil {
				resp.Body.Close()
			}
		}
		if mode == "mixed" {
			tr := &http.Transport{Proxy: http.ProxyURL(p), TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS11}}
			defer tr.CloseIdleConnections()
			if _, err := (&http.Client{Transport: tr, Timeout: 3 * time.Second}).Get("https://127.0.0.1:443/"); err == nil {
				t.Fatal("unsupported TLS version unexpectedly negotiated")
			}
		}
		if mode == "rejected" || mode == "rejected_nonzero" || mode == "broken upstream" {
			_, _ = client.Get("https://127.0.0.1:443/")
		}
		if mode == "mixed" {
			ca, err := os.ReadFile(os.Getenv("GLITCHDECK_CA_CERT"))
			roots := x509.NewCertPool()
			if err != nil || !roots.AppendCertsFromPEM(ca) {
				t.Fatalf("load interception CA: %v", err)
			}
			tr := &http.Transport{Proxy: http.ProxyURL(p), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
			defer tr.CloseIdleConnections()
			target := strings.Replace(os.Getenv("GLITCHDECK_DEMO_TLS"), "127.0.0.1", "localhost", 1)
			resp, err := (&http.Client{Transport: tr, Timeout: 3 * time.Second}).Get(target + "/api/state")
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("successful HTTPS leg: %v, %v", resp, err)
			}
			resp.Body.Close()
		}
		if mode == "broken upstream" {
			resp, err := http.Get(os.Getenv("GLITCHDECK_PROXY_URL") + "/bad")
			if err != nil || resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("broken upstream: %v, %v", resp, err)
			}
			resp.Body.Close()
		}
		if mode == "rejected_nonzero" {
			os.Exit(7)
		}
		return
	}
	for _, tc := range []struct {
		mode, diff string
		allow      bool
		childExit  any
		want       int
		rejected   int64
		denied     int64
	}{
		{mode: "denied", diff: "egress_denied_only: 1 request(s) blocked by the upstream allowlist (hosts: example.com)", want: 1, denied: 1},
		{mode: "oversized denial", diff: "egress_denied_only:", want: 1, denied: 1},
		{mode: "rejected", diff: "tls_rejected_only:", want: 1, rejected: 1},
		{mode: "rejected_nonzero", allow: true, childExit: "nonzero", rejected: 1},
		{mode: "mixed", rejected: 1, denied: 1},
		{mode: "broken upstream", diff: "tls_rejected_only:", want: 1, rejected: 1},
		{mode: "idle", diff: "Go net/http (and some other clients) never proxy localhost/127.0.0.1", want: 1},
		{mode: "java", diff: "JVM ignores HTTP(S)_PROXY; set -Dhttps.proxyHost/-Dhttps.proxyPort via JAVA_TOOL_OPTIONS", want: 1},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			t.Setenv("GD_TRAFFIC_HELPER", tc.mode)
			tp := tape.Tape{Version: 2, Target: "demo", Expect: tape.Expect{ChildExit: tc.childExit}}
			command := []string{os.Args[0], "-test.run=^TestExecTrafficChecks$"}
			if tc.mode == "java" {
				if _, err := exec.LookPath("sh"); err != nil {
					t.Skip("shell unavailable for java stub")
				}
				path := filepath.Join(t.TempDir(), "java")
				if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
					t.Fatal(err)
				}
				command = []string{path}
			}
			if tc.mode == "broken upstream" {
				up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					conn, _, err := http.NewResponseController(w).Hijack()
					if err == nil {
						conn.Close()
					}
				}))
				defer up.Close()
				tp.Target = up.URL
			}
			var logs *os.File
			if tc.mode == "mixed" {
				var err error
				logs, err = os.Create(filepath.Join(t.TempDir(), "stderr"))
				if err != nil {
					t.Fatal(err)
				}
				defer logs.Close()
				old := os.Stderr
				os.Stderr = logs
				defer func() { os.Stderr = old }()
			}
			r := Run(context.Background(), tp, Options{TLS: true, JSON: true, AllowZeroTraffic: tc.allow, Command: command})
			if logs != nil {
				data, err := os.ReadFile(logs.Name())
				const warning = "warning: tls_rejected: 1 handshake(s) failed for hosts 127.0.0.1\n"
				if err != nil || strings.Count(string(data), warning) != 1 || strings.Count(string(data), "tls_handshake_failed:") != 1 ||
					r.Exec.Traffic.InterceptedOK != 1 || r.Exec.TLSHandshakeFailureCount != 1 {
					t.Fatalf("mixed HTTPS traffic: %+v, stderr=%q, err=%v", r.Exec.Traffic, data, err)
				}
			}
			diff := strings.Join(r.Diff, " ")
			if r.ExitCode != tc.want || !strings.Contains(diff, tc.diff) || strings.Contains(diff, "do-not-print") || tc.diff == "" && diff != "" || r.Exec.Traffic.TLSRejected != tc.rejected || r.Exec.Traffic.EgressDenied != tc.denied {
				t.Fatalf("%+v; traffic %+v", r, r.Exec.Traffic)
			}
		})
	}
}

func TestExecDrainsBeforeDirectAssertions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy")
	var status atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/probe" {
			addr, err := os.ReadFile(path)
			if err != nil {
				t.Error(err)
				return
			}
			resp, err := http.Get(string(addr) + "/late")
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
			status.Store(int32(resp.StatusCode))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	result := Run(context.Background(), tape.Tape{Version: 2, Assertions: []tape.Assertion{
		{Name: "probe", HTTPGet: "/probe", Direct: true, ExpectStatus: http.StatusNoContent},
	}}, Options{Target: upstream.URL, Command: []string{"sh", "-c", `printf %s "$GLITCHDECK_PROXY_URL" > "$1"`, "sh", path}, JSON: true})
	if result.ExitCode != 1 || !strings.Contains(strings.Join(result.Diff, "\n"), "zero_traffic:") || result.Summary.RequestsTotal != 0 || status.Load() != http.StatusServiceUnavailable {
		t.Fatalf("late HTTP status %d, exec report %+v", status.Load(), result)
	}
}

type halfCloseAfterClientHello struct{ *net.TCPConn }

func (c halfCloseAfterClientHello) Write(b []byte) (int, error) {
	n, err := c.TCPConn.Write(b)
	if err == nil {
		err = c.CloseWrite()
	}
	return n, err
}

func TestExecTLSWithoutApplicationTraffic(t *testing.T) {
	if mode := os.Getenv("GD_TLS_EMPTY_HELPER"); mode != "" {
		p, err := url.Parse(os.Getenv("GLITCHDECK_PROXY_URL"))
		if err != nil {
			t.Fatal(err)
		}
		conn, err := net.DialTimeout("tcp", p.Host, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.WriteString(conn, "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT: %v, %v", resp, err)
		}
		roots := x509.NewCertPool()
		version := uint16(tls.VersionTLS13)
		if mode == "12" {
			version = tls.VersionTLS12
		}
		if mode == "protocol" {
			version = tls.VersionTLS11
		}
		if mode == "hello EOF" {
			conn = halfCloseAfterClientHello{conn.(*net.TCPConn)}
		}
		if mode == "quiet" || mode == "hello EOF" {
			data, err := os.ReadFile(os.Getenv("GLITCHDECK_CA_CERT"))
			if err != nil || !roots.AppendCertsFromPEM(data) {
				t.Fatalf("load CA: %v", err)
			}
		} else {
			other, err := tlsmitm.Ephemeral()
			if err != nil {
				t.Fatal(err)
			}
			roots.AddCert(other.Cert)
		}
		client := tls.Client(conn, &tls.Config{ServerName: "localhost", RootCAs: roots, MinVersion: version, MaxVersion: version})
		err = client.Handshake()
		if (err == nil) != (mode == "quiet") {
			t.Fatalf("TLS handshake: %v", err)
		}
		if mode == "quiet" {
			_ = client.Close()
		}
		return
	}
	t.Setenv("GORACE", strings.TrimSpace(os.Getenv("GORACE")+" atexit_sleep_ms=0"))
	for _, tc := range []struct {
		name, mode, diff string
		override         bool
		rejected         int64
	}{
		{"TLS 1.2 rejection", "12", "tls_rejected_only:", false, 1},
		{"TLS 1.3 rejection", "13", "tls_rejected_only:", false, 1},
		{"ClientHello then EOF", "hello EOF", "tls_rejected_only:", false, 1},
		{"Unsupported TLS version", "protocol", "tls_rejected_only:", false, 1},
		{"Silent close", "quiet", "no_usable_traffic:", false, 0},
		{"Silent close override", "quiet", "", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GD_TLS_EMPTY_HELPER", tc.mode)
			r := Run(context.Background(), tape.Tape{Version: 2}, Options{TLS: true, AllowZeroTraffic: tc.override, JSON: true,
				Command: []string{os.Args[0], "-test.run=^TestExecTLSWithoutApplicationTraffic$"}})
			wantExit := 1
			if tc.override {
				wantExit = 0
			}
			diff := strings.Join(r.Diff, "\n")
			if r.ExitCode != wantExit || r.Exec.ExitCode != 0 || r.Exec.Traffic.InterceptedOK != 0 || r.Exec.Traffic.TLSRejected != tc.rejected ||
				r.Exec.TLSHandshakeFailureCount != uint64(tc.rejected) || !strings.HasPrefix(diff, tc.diff) || tc.override && diff != "" {
				t.Fatalf("exec=%+v traffic=%+v child=%+v", r, r.Exec.Traffic, r.Exec)
			}
			if tc.mode == "hello EOF" || tc.mode == "protocol" {
				var failure struct{ Error string }
				if len(r.Exec.TLSHandshakeFailures) != 1 || json.Unmarshal(r.Exec.TLSHandshakeFailures[0], &failure) != nil {
					t.Fatalf("expected one recorded handshake error, got %s", r.Exec.TLSHandshakeFailures)
				}
				if tc.mode == "hello EOF" && failure.Error != "EOF" || tc.mode == "protocol" && !strings.Contains(failure.Error, "unsupported versions") {
					t.Fatalf("unexpected handshake error: %q", failure.Error)
				}
			}
		})
	}
}
