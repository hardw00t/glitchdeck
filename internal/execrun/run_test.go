package execrun

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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

func TestWriteCABundleSeparatesCertificates(t *testing.T) {
	systemCA, err := tlsmitm.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	proxyCA, err := tlsmitm.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"with newline", systemCA.PEM},
		{"without newline", []byte(strings.TrimSuffix(string(systemCA.PEM), "\n"))},
		{"empty", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bundle.pem")
			if err := writeCABundle(path, tc.data, proxyCA.PEM); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			wantData := append([]byte(nil), tc.data...)
			if len(wantData) > 0 && wantData[len(wantData)-1] != '\n' {
				wantData = append(wantData, '\n')
			}
			wantData = append(wantData, proxyCA.PEM...)
			if !bytes.Equal(data, wantData) {
				t.Fatal("bundle does not preserve and separate the certificates")
			}
			if strings.Contains(string(data), "-----END CERTIFICATE----------BEGIN CERTIFICATE-----") {
				t.Fatal("certificates are glued together")
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(data) {
				t.Fatal("bundle contains no valid certificates")
			}
			want := 2
			if len(tc.data) == 0 {
				want = 1
			}
			if len(pool.Subjects()) != want {
				t.Fatalf("bundle contains %d certificates, want %d", len(pool.Subjects()), want)
			}
		})
	}
}

func TestExecTLSExportsUsableBundle(t *testing.T) {
	if os.Getenv("GD_TLS_HELPER") == "1" {
		bundle := os.Getenv("SSL_CERT_FILE")
		for _, name := range []string{"REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH", "AWS_CA_BUNDLE"} {
			if bundle == "" || os.Getenv(name) != bundle {
				t.Fatalf("%s does not point to SSL_CERT_FILE", name)
			}
		}
		if os.Getenv("NODE_EXTRA_CA_CERTS") != os.Getenv("GLITCHDECK_CA_CERT") {
			t.Fatal("NODE_EXTRA_CA_CERTS does not point to the proxy CA")
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
		return
	}
	t.Setenv("GD_TLS_HELPER", "1")
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
	bus.Publish("sse_event", map[string]any{"seq": 1, "kind": "end", "end": "eof", "events": 2, "delivered_events": 1, "delivered_valid_json": true, "delivered_done": false, "delivered_max_gap_ms": 0})
	bus.Publish("http_req", map[string]any{"seq": 1, "path": "/stream", "method": "GET"})
	one, yes := 1, true
	tp := tape.Tape{Script: []tape.Step{{Name: "stream", Stream: &tape.Stream{Path: "/stream"}}}}
	a := tape.Assertion{StreamStep: "stream", ExpectSSE: &tape.SSEExpect{MinEvents: &one, MaxEvents: &one, ValidJSON: &yes}}
	if r := observedAssertion(a, tp, bus.History(10)); len(r.Failures) != 0 {
		t.Fatal(r.Failures)
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
	if r.ExitCode != 0 || len(r.Diff) != 0 || len(r.Exec.TLSHandshakeFailures) != 1 ||
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
