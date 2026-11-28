package tape

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
)

func TestDecodeResourceLimitsAndLegacyEviction(t *testing.T) {
	for _, doc := range []string{
		"version: 3\nname: " + strings.Repeat("x", 16<<20),
		"version: 3\ncassettes:\n" + strings.Repeat("- request: {method: GET, path: /}\n  response: {status: 200}\n", 257),
		"version: 3\ncassettes:\n" + strings.Repeat("- request: {method: GET, path: /}\n  response: {status: 200, body: "+strings.Repeat("x", 3<<20)+"}\n", 3),
		"version: 3\ncassettes: [{request: {method: GET, path: /}, response: {status: 200, body_encoding: base64, body: " + base64.StdEncoding.EncodeToString(make([]byte, (4<<20)+1)) + "}}]",
	} {
		if _, err := Decode(strings.NewReader(doc)); err == nil {
			t.Fatal("accepted oversized tape")
		}
	}
	for _, version := range []string{"1", "2"} {
		if _, err := Decode(strings.NewReader("version: " + version + "\ntruncated: true\ndropped_entries: 1\n")); err != nil {
			t.Fatalf("legacy v%s eviction: %v", version, err)
		}
		if _, err := Decode(strings.NewReader("version: " + version + "\nincomplete: true\n")); err == nil {
			t.Fatalf("accepted incomplete legacy v%s", version)
		}
	}
	if _, err := Decode(strings.NewReader("version: 3\nincomplete: true\n")); err == nil {
		t.Fatal("accepted incomplete v3")
	}
	if _, err := Decode(strings.NewReader("version: 3\ntruncated: true\n")); err == nil {
		t.Fatal("accepted truncated v3")
	}
}

func TestMatcherDefaultPortsAndHashlessAmbiguity(t *testing.T) {
	c := Cassette{Request: CassetteRequest{Method: "GET", Path: "/", Host: "example.com"}, Response: CassetteResponse{Status: 200}}
	for _, target := range []string{"https://example.com:443/", "http://example.com:80/"} {
		if _, err := (Tape{Cassettes: []Cassette{c}}).CassetteUpstream()(httptest.NewRequest("GET", target, nil)); err != nil {
			t.Fatalf("%s: %v", target, err)
		}
	}
	if _, err := (Tape{Cassettes: []Cassette{c}}).CassetteUpstream()(httptest.NewRequest("GET", "https://example.com:444/", nil)); err == nil {
		t.Fatal("matched nondefault port")
	}
	_, err := (Tape{Cassettes: []Cassette{c, c}}).CassetteUpstream()(httptest.NewRequest("GET", "https://example.com/", nil))
	var ce *proxy.CassetteError
	if !errors.As(err, &ce) || ce.Kind != "cassette_ambiguous" {
		t.Fatalf("got %v", err)
	}
	known := c
	known.Request.BodySHA256 = BodySHA256(nil, nil)
	_, err = (Tape{Cassettes: []Cassette{c, known}}).CassetteUpstream()(httptest.NewRequest("GET", "https://example.com/", nil))
	if !errors.As(err, &ce) || ce.Kind != "cassette_ambiguous" {
		t.Fatalf("hashless candidate: %v", err)
	}
}

func TestCanonicalHashRejectsLossyJSON(t *testing.T) {
	for _, pair := range [][2]string{{`{"a":1,"a":2}`, `{"a":2}`}, {`{"x":"\ud800"}`, `{"x":"�"}`}, {"{\"x\":\"\xff\"}", `{"x":"�"}`}} {
		if BodySHA256([]byte(pair[0]), nil) == BodySHA256([]byte(pair[1]), nil) {
			t.Fatalf("lossy canonicalization of %q", pair[0])
		}
	}
	if BodySHA256([]byte(`{"x":"\ud83d\ude00"}`), nil) != BodySHA256([]byte(`{"x":"😀"}`), nil) {
		t.Fatal("valid surrogate pair was not canonicalized")
	}
	for _, doc := range []string{
		"version: 3\nignore_json_paths: ['']",
		"version: 3\nignore_json_paths: ['a..b']",
		"version: 3\ncassettes: [{request: {method: GET, path: /, body_sha256: nope}, response: {status: 200}}]",
	} {
		if _, err := Decode(strings.NewReader(doc)); err == nil {
			t.Fatalf("accepted %s", doc)
		}
	}
}

func TestReplayHTTPStepFollowsOnlyLocalRecordedRedirect(t *testing.T) {
	first := Cassette{Request: CassetteRequest{Method: "GET", Path: "/one"}, Response: CassetteResponse{Status: 302, Headers: map[string]string{"Location": "/two"}}}
	second := Cassette{Request: CassetteRequest{Method: "GET", Path: "/two"}, Response: CassetteResponse{Status: 200}}
	tp := Tape{Version: 3, Target: "demo", Cassettes: []Cassette{first, second}, Script: []Step{{Name: "redirect", HTTP: &HTTP{Path: "/one"}}}}
	_, report, err := RunReplay(context.Background(), tp, "", "", false)
	if err != nil || report.RequestsTotal != 2 {
		t.Fatalf("requests=%d err=%v", report.RequestsTotal, err)
	}
	tp.Cassettes = tp.Cassettes[:1]
	_, _, err = RunReplay(context.Background(), tp, "", "", false)
	var ce *proxy.CassetteError
	if !errors.As(err, &ce) || ce.Kind != "cassette_miss" {
		t.Fatalf("missing redirect target: %v", err)
	}
}

func TestReplayDemoTLSStreamPassthroughIsIntercepted(t *testing.T) {
	tp := Tape{Version: 3, Target: "demo", TLSMITM: true, TLSPassthrough: []string{"localhost"},
		Cassettes: []Cassette{{Request: CassetteRequest{Method: "GET", Path: "/stream"}, Response: CassetteResponse{Status: 200, Headers: map[string]string{"Content-Type": "text/event-stream"}, Body: "event: custom_end\ndata: {}\n\n"}}},
		Rules:     []fault.Rule{{ID: "r", Enabled: true, Match: fault.Match{PathPrefix: "/stream"}, Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "drop", "every": 100, "done_events": []string{"custom_end"}}}}},
		Script:    []Step{{Name: "s", Stream: &Stream{URL: "${DEMO_TLS}/stream"}}}, Assertions: []Assertion{{StreamStep: "s", ExpectSSE: &SSEExpect{Terminal: "custom_end"}}}}
	results, _, err := RunReplay(context.Background(), tp, "", "", false)
	if err != nil || len(results) != 1 || len(results[0].Failures) != 0 {
		t.Fatalf("results=%v err=%v", results, err)
	}
}
