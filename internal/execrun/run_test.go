package execrun

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/tape"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
)

func TestExecInjectsProxy(t *testing.T) {
	if os.Getenv("GD_HELPER") == "1" {
		if os.Getenv("GLITCHDECK_PROXY_URL") == "" {
			os.Exit(9)
		}
		os.Exit(0)
	}
	t.Setenv("GD_HELPER", "1")
	r := Run(context.Background(), tape.Tape{Version: 2, Target: "demo"}, Options{Command: []string{os.Args[0], "-test.run=TestExecInjectsProxy"}})
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
		name    string
		cmd     []string
		timeout time.Duration
		want    int
	}{
		{"success", []string{"sh", "-c", "exit 0"}, 0, 0},
		{"mismatch", []string{"sh", "-c", "exit 1"}, 0, 1},
		{"usage", nil, 0, 2},
		{"timeout", []string{"sh", "-c", "sleep 5"}, 50 * time.Millisecond, 124},
		{"start failure", []string{invalid}, 0, 125},
		{"permission", []string{denied}, 0, 126},
		{"not found", []string{filepath.Join(dir, "missing")}, 0, 127},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Run(context.Background(), tape.Tape{Version: 2, Target: "demo"}, Options{Command: tc.cmd, Timeout: tc.timeout, Grace: 50 * time.Millisecond, JSON: true})
			if r.ExitCode != tc.want {
				t.Fatalf("exit %d, want %d: %+v", r.ExitCode, tc.want, r)
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
	r := Run(context.Background(), tp, Options{Command: []string{os.Args[0], "-test.run=^$"}, JSON: true})
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
