package tape

import (
	"bytes"
	"context"
	"fmt"
	"glitchdeck/internal/fault"
	"glitchdeck/internal/wsframe"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	_, err := Run(context.Background(), Tape{Version: 1, Target: "http://" + "0" + ":80"}, "")
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

func TestJSONPresenceNumbersAndTrailingData(t *testing.T) {
	for _, tc := range []struct {
		body     string
		expected map[string]any
		failures int
	}{
		{`{"n":1.0}`, map[string]any{"n": 1}, 0},
		{`{}`, map[string]any{"missing": nil}, 1},
		{`{"n":1} garbage`, map[string]any{"n": 1}, 1},
	} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(tc.body)) }))
		results, err := Run(context.Background(), Tape{Version: 1, Target: s.URL, Assertions: []Assertion{{HTTPGet: "/", JSONEq: tc.expected}}}, "")
		s.Close()
		if err != nil || len(results) != 1 || len(results[0].Failures) != tc.failures {
			t.Fatalf("body %s: %v %v", tc.body, results, err)
		}
	}
}

func TestIncompleteAndBadSequenceRejected(t *testing.T) {
	for _, tp := range []Tape{
		{Version: 1, Target: "demo", Incomplete: true},
		{Version: 1, Target: "demo", StartSeq: 2, Script: []Step{{Seq: 2, HTTP: &HTTP{Path: "/"}}}},
	} {
		if _, err := Run(context.Background(), tp, ""); err == nil {
			t.Fatal("accepted invalid tape")
		}
	}
}

func TestUnreachableUpstreamIsError(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	target := s.URL
	s.Close()
	_, err := Run(context.Background(), Tape{Version: 1, Target: target, Script: []Step{{HTTP: &HTTP{Path: "/"}}}}, "")
	if err == nil {
		t.Fatal("unreachable upstream accepted")
	}
}

func TestFragmentedTickerJSON(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsframe.AcceptKey(r.Header.Get("Sec-WebSocket-Key")))
		_ = rw.Flush()
		_ = wsframe.Write(c, wsframe.Frame{Opcode: 1, Payload: []byte(`{"seq":`)}, false)
		_ = wsframe.Write(c, wsframe.Frame{Fin: true, Opcode: 0, Payload: []byte(`1}`)}, false)
	}))
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ch, err := startWS(ctx, s.URL, WS{Path: "/ws/ticker", Frames: 1}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-ch; err != nil {
		t.Fatal(err)
	}
}

func TestUnexpectedWebSocketEndIsError(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsframe.AcceptKey(r.Header.Get("Sec-WebSocket-Key")))
		_ = rw.Flush()
	}))
	defer s.Close()
	_, err := Run(context.Background(), Tape{Version: 1, Target: s.URL, Script: []Step{{WS: &WS{Path: "/", Frames: 1}}}}, "")
	if err == nil {
		t.Fatal("unexpected websocket close accepted")
	}
}
