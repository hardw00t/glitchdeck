package tape

import (
	"bytes"
	"context"
	"glitchdeck/internal/fault"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	original := Tape{Version: 1, Name: "checkout", Seed: 42, Target: "demo", Script: []Step{{Name: "send", HTTP: &HTTP{Method: "POST", Path: "/checkout", Body: `{}`}}}, Assertions: []Assertion{{Name: "state", HTTPGet: "/api/state", JSONEq: map[string]any{"duplicate_charges": 0}}}}
	var b bytes.Buffer
	if err := Encode(&b, original); err != nil {
		t.Fatal(err)
	}
	got, err := Decode(&b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != original.Name || got.Seed != 42 || got.Script[0].HTTP.Path != "/checkout" || got.Assertions[0].JSONEq["duplicate_charges"] != 0 {
		t.Fatalf("unexpected tape: %#v", got)
	}
}

func TestRunnerAssertionDiff(t *testing.T) {
	tp := Tape{Version: 1, Target: "demo", Assertions: []Assertion{{Name: "ledger", HTTPGet: "/api/state", ExpectStatus: 200, JSONEq: map[string]any{"duplicate_charges": 1}}}}
	results, err := Run(context.Background(), tp, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || len(results[0].Failures) != 1 || !strings.Contains(results[0].Failures[0], "duplicate_charges: expected 1, got 0") {
		t.Fatalf("unexpected results: %#v", results)
	}
}

func TestRejectRemoteTarget(t *testing.T) {
	_, err := Run(context.Background(), Tape{Version: 1, Target: "http://0:80"}, "")
	if err == nil {
		t.Fatal("remote target accepted")
	}
}

func TestWebSocketFailureOverlaysDemoState(t *testing.T) {
	tp := Tape{Version: 1, Target: "demo", Rules: []fault.Rule{{ID: "close", Enabled: true, Match: fault.Match{PathPrefix: "/ws/ticker"}, Fault: fault.Fault{Type: "ws-glitch", Params: map[string]any{"dir": "s2c", "action": "close_1006", "after_frames": 1}}}}, Script: []Step{{Name: "ticker", WS: &WS{Path: "/ws/ticker", Frames: 2, TimeoutMS: 3000}}}, Assertions: []Assertion{{Name: "healthy", HTTPGet: "/api/state", JSONEq: map[string]any{"ws_broken": false}}}}
	results, err := Run(context.Background(), tp, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || len(results[0].Failures) != 1 || !strings.Contains(results[0].Failures[0], "ws_broken: expected false, got true") {
		t.Fatalf("unexpected results: %#v", results)
	}
}

func TestDirectDemoStateBypassesFault(t *testing.T) {
	tp := Tape{Version: 1, Target: "demo", Rules: []fault.Rule{{ID: "rst", Enabled: true, Fault: fault.Fault{Type: "tcp-rst", Params: map[string]any{"before_headers": true}}}}, Assertions: []Assertion{{Name: "ledger", HTTPGet: "/api/state", Direct: true, JSONEq: map[string]any{"duplicate_charges": 0}}}}
	got, err := Run(context.Background(), tp, "")
	if err != nil || len(got) != 1 || len(got[0].Failures) != 0 {
		t.Fatalf("results %v, error %v", got, err)
	}
}
func TestWebSocketSetupFailureIsRuntimeError(t *testing.T) {
	_, err := Run(context.Background(), Tape{Version: 1, Target: "demo", Script: []Step{{WS: &WS{Path: "/missing"}}}}, "")
	if err == nil {
		t.Fatal("expected handshake error")
	}
}
func TestPreciseJSONNumbers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"id":9007199254740992}`)) }))
	defer server.Close()
	tp := Tape{Version: 1, Target: server.URL, Assertions: []Assertion{{HTTPGet: "/state", JSONEq: map[string]any{"id": int64(9007199254740993)}}}}
	got, err := Run(context.Background(), tp, "")
	if err != nil || len(got[0].Failures) != 1 {
		t.Fatalf("results %v, error %v", got, err)
	}
}
func TestRejectDirectNonDemo(t *testing.T) {
	_, err := Run(context.Background(), Tape{Version: 1, Target: "http://127.0.0.1:1", Assertions: []Assertion{{HTTPGet: "/api/state", Direct: true}}}, "")
	if err == nil {
		t.Fatal("accepted direct non-demo assertion")
	}
}
