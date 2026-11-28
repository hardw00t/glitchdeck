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

	"github.com/hardw00t/glitchdeck/internal/tape"
)

func TestRecordPreservesHTTPAssertionAndRejectsUnsupported(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":false}`))
	}))
	defer server.Close()
	out := filepath.Join(t.TempDir(), "record.yaml")
	doc := tape.Tape{Version: 2, Target: server.URL, Assertions: []tape.Assertion{{Name: "state", HTTPGet: "/state", JSONEq: map[string]any{"ok": true}}}}
	options := Options{Mode: "record", TapeOut: out, Command: []string{"true"}, AllowZeroTraffic: true, JSON: true}
	result := Run(context.Background(), doc, options)
	if result.Summary.AssertionsFailed != 1 {
		t.Fatalf("record assertion not evaluated: %+v", result)
	}
	file, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := tape.Decode(file)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(recorded.Assertions) != 1 || len(recorded.Cassettes) != 1 || len(recorded.Script) != 0 {
		t.Fatalf("assertion recording lost data: %+v", recorded)
	}
	options.Mode = "replay"
	options.TapeOut = ""
	replay := Run(context.Background(), recorded, options)
	if replay.Summary.AssertionsFailed != 1 {
		t.Fatalf("replay lost assertion failure: %+v", replay)
	}
	for _, assertion := range []tape.Assertion{{HTTPGet: "/state", Direct: true}, {StreamStep: "s"}, {HTTPGet: "/state", MaxLatencyMS: 1}} {
		doc.Assertions = []tape.Assertion{assertion}
		options.Mode = "record"
		options.TapeOut = out
		if err := os.WriteFile(out, []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
		result = Run(context.Background(), doc, options)
		b, _ := os.ReadFile(out)
		if result.ExitCode != 2 || string(b) != "keep" {
			t.Fatalf("unsupported assertion accepted: %+v, %q", result, b)
		}
	}
}

func TestBlockedEnvelopeContainsNoUserData(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("Q", 30)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(secret)) }))
	defer server.Close()
	doc := tape.Tape{Version: 2, Target: server.URL, Assertions: []tape.Assertion{{HTTPGet: "/", ExpectStatus: 200}}}
	result := Run(context.Background(), doc, Options{Mode: "record", TapeOut: filepath.Join(t.TempDir(), secret), TapePath: secret, Command: []string{"true", secret}, JSON: true, AllowZeroTraffic: true})
	data, _ := json.Marshal(result)
	if result.ExitCode != 2 || strings.Contains(string(data), secret) {
		t.Fatalf("unsafe blocked envelope: %s", data)
	}
}

func TestRecordRejectsInvalidOutputBeforeReplacingDestination(t *testing.T) {
	out := filepath.Join(t.TempDir(), "record.yaml")
	if err := os.WriteFile(out, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	doc := tape.Tape{Version: 2, Target: "demo", Expect: tape.Expect{Faults: []tape.FaultExpect{{Rule: "missing"}}}}
	result := Run(context.Background(), doc, Options{Mode: "record", TapeOut: out, Command: []string{"true"}, JSON: true, AllowZeroTraffic: true})
	data, err := os.ReadFile(out)
	if err != nil || result.ExitCode != 3 || string(data) != "keep" {
		t.Fatalf("invalid output replaced destination: %+v, %q, %v", result, data, err)
	}
}
