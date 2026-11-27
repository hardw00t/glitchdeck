package tape

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/demo"
	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
)

func TestV1RejectsV2KeysInConfigurationChanges(t *testing.T) {
	for _, rule := range []string{
		`{id: late, match: {host: ""}, fault: {type: rate-limit}}`,
		`{id: late, fault: {type: h2-glitch}}`,
	} {
		doc := "version: 1\ntarget: demo\nconfig_changes:\n  - before_seq: 1\n    rules: [" + rule + "]\n"
		if _, err := Decode(strings.NewReader(doc)); err == nil || !strings.Contains(err.Error(), "version: 2") {
			t.Fatalf("v1 accepted v2 rule %s: %v", rule, err)
		}
	}
}

func TestDecodeRejectsInvalidChildExit(t *testing.T) {
	for _, value := range []string{"true", "1.5", "non-zero"} {
		doc := "version: 2\ntarget: demo\nexpect: {child_exit: " + value + "}\n"
		if _, err := Decode(strings.NewReader(doc)); err == nil || !strings.Contains(err.Error(), "child_exit") {
			t.Fatalf("invalid child exit %s: %v", value, err)
		}
	}
}

func TestDecodeFaultBoundsRequireIntegerScalars(t *testing.T) {
	const base = "version: 2\nrules: [{id: r, fault: {type: tcp-rst}}]\n"
	for _, tc := range []struct {
		name, doc, field string
	}{
		{"negative fraction", "expect: {faults: [{rule: r, min_applied: -0.5}]}\n", "min_applied"},
		{"positive fraction", "expect: {faults: [{rule: r, max_applied: 2.5}]}\n", "max_applied"},
		{"float zero", "expect: {faults: [{rule: r, min_applied: 0.0}]}\n", "min_applied"},
		{"alias", "expect: {faults: [{rule: r, min_applied: &zero 0, max_applied: *zero}]}\n", ""},
		{"float alias", "expect: {faults: [{rule: r, max_applied: &float 0.0, min_applied: *float}]}\n", "min_applied"},
		{"alias key", "name: &key min_applied\nexpect: {faults: [{rule: r, ? *key : 0.5}]}\n", "min_applied"},
		{"merged fraction", "expect: {faults: [{<<: &base {rule: r, max_applied: 0.5}}]}\n", "max_applied"},
		{"overridden fraction", "expect: {faults: [{<<: &base {rule: r, max_applied: 0.5}, max_applied: 0}]}\n", ""},
		{"unknown field", "expect: {faults: [{rule: r, min_applied: 0, unexpected: 0}]}\n", "unexpected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(base + tc.doc))
			if tc.field == "" && err != nil || tc.field != "" && (err == nil || !strings.Contains(err.Error(), tc.field)) {
				t.Fatalf("expected validation of %q: %v", tc.field, err)
			}
		})
	}
}

func TestAssertionDiagnosticsAreBounded(t *testing.T) {
	data := `{"large":"` + strings.Repeat("x", 1<<20) + `"}`
	got := CheckAssertionJSON([]byte(data), map[string]any{"large": "small"}, nil)
	if len(got) != 1 || len(got[0]) > 1024 || !strings.Contains(got[0], "truncated") {
		t.Fatalf("unbounded assertion diagnostic: %d entries", len(got))
	}
}

func TestRejectPathOnlyTLSProtocol(t *testing.T) {
	for _, step := range []string{"http: {path: /, proto: h2}", "grpc: {path: /, proto: h2}", "stream: {path: /, proto: h2}"} {
		doc := "version: 2\ntarget: demo\nscript:\n  - " + step + "\n"
		if _, err := Decode(strings.NewReader(doc)); err == nil || !strings.Contains(err.Error(), "requires an HTTPS URL") {
			t.Fatalf("invalid protocol declaration %s: %v", step, err)
		}
	}
}

func TestGRPCMixedCaseHTTPSUsesProxy(t *testing.T) {
	proxyHit := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHit <- r.Method + " " + r.Host
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	// Route selection must use the scheme parsed by net/url, not its original spelling.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := runGRPC(ctx, server.URL, GRPC{URL: "HTTPS://127.0.0.1:1/service/Call"})
	if err == nil {
		t.Fatal("proxy rejection did not fail gRPC request")
	}
	select {
	case got := <-proxyHit:
		if got != "CONNECT 127.0.0.1:1" {
			t.Fatalf("proxy received %q", got)
		}
	default:
		t.Fatal("request did not use the local proxy")
	}
}

func TestStreamParserAndReport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "\ufeffdata: {\"x\":1}\r\rdata: [DONE]\r\r")
	}))
	defer server.Close()
	e := runStream(context.Background(), server.URL, Stream{Path: "/"})
	if e.End != "done" || e.Events != 2 || !e.ValidJSON {
		t.Fatalf("stream: %+v", e)
	}
	_, stats, err := RunWithReport(context.Background(), Tape{Version: 2, Target: "demo", Rules: []fault.Rule{{ID: "limit", Enabled: true, Fault: fault.Fault{Type: "rate-limit", Params: map[string]any{"status": 429}}}}, Script: []Step{{HTTP: &HTTP{Path: "/api/state"}}}}, "")
	if err != nil || stats.Rules["limit"].Applied != 1 || stats.RequestsTotal != 1 {
		t.Fatalf("stats %v, error %v", stats, err)
	}
}

func TestStreamTerminalEvidence(t *testing.T) {
	for _, tc := range []struct {
		body, terminal, end string
		done, valid         bool
	}{
		{"data: hello\n\nevent: end\ndata: done\n\n", "end", "eof", true, true},
		{"data: {broken\n\n", "none", "eof_early", false, false},
		{"event: error\ndata: {\"error\":{}}\n\n", "error", "eof", false, true},
		{"event: message_stop\ndata: {}\n\n", "message_stop", "eof", true, true},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, tc.body)
		}))
		e := runStreamWithTerminals(context.Background(), server.URL, Stream{Path: "/"}, []string{"end"})
		server.Close()
		if e.Terminal != tc.terminal || e.End != tc.end || e.Done != tc.done || e.ValidJSON != tc.valid {
			t.Errorf("%q: %+v", tc.body, e)
		}
		if failures := checkStream(Assertion{ExpectStatus: 200, ExpectSSE: &SSEExpect{Terminal: tc.terminal}}, e); len(failures) != 0 {
			t.Error(failures)
		}
	}
}

func TestInjectedErrorTapeEvidenceDistinguishesEOFAndReset(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"delta\":\"first\"}\n\ndata: [DONE]\n\n")
	}))
	defer up.Close()
	target, err := proxy.ParseTarget(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ close, end string }{{"clean", "eof"}, {"rst", "rst"}} {
		t.Run(tc.close, func(t *testing.T) {
			cfg := fault.Config{Rules: []fault.Rule{{ID: "error", Enabled: true, Fault: fault.Fault{
				Type: "sse-glitch", Params: map[string]any{"action": "inject_error", "provider": "openai", "close": tc.close},
			}}}}
			p := proxy.New(target, cfg, nil)
			defer p.Close()
			server := httptest.NewServer(p)
			defer server.Close()
			got := runStream(context.Background(), server.URL, Stream{Path: "/"})
			if got.End != tc.end || got.Terminal != "error" || got.Done || got.Events != 2 {
				t.Fatalf("stream: %+v", got)
			}
		})
	}
}

func TestTerminalRuleScopeAndValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: end\ndata: text\n\ndata: [DONE]\n\n")
	}))
	defer server.Close()
	tp := Tape{Version: 2, Target: server.URL, Rules: []fault.Rule{
		{ID: "unrelated", Enabled: true, Match: fault.Match{PathPrefix: "/other"}, Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "eof_early", "done_events": []string{"end"}}}},
	}, Script: []Step{{Name: "stream", Stream: &Stream{Path: "/stream"}}}, Assertions: []Assertion{{Name: "complete", StreamStep: "stream", ExpectSSE: &SSEExpect{Terminal: "done_marker"}}}}
	results, err := Run(context.Background(), tp, "")
	if err != nil || len(results) != 1 || len(results[0].Failures) != 0 {
		t.Fatalf("results=%v error=%v", results, err)
	}
	doc := "version: 2\ntarget: demo\nrules: [{id: r, fault: {type: sse-glitch, params: {done_events: [end]}}}]\nscript: [{name: s, stream: {path: /}}]\nassertions: [{stream_step: s, expect_sse: {terminal: end}}]\n"
	if _, err := Decode(strings.NewReader(doc)); err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(strings.NewReader(strings.Replace(doc, "terminal: end", "terminal: other", 1))); err == nil {
		t.Fatal("unknown terminal accepted")
	}
}

func TestReplayTerminalMarkerAfterSemanticTerminal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: response.completed\ndata: {}\n\ndata: [DONE]\n\n")
	}))
	defer server.Close()
	e := runStream(context.Background(), server.URL, Stream{Path: "/"})
	if e.Terminal != "response.completed" || e.End != "done" || e.Events != 2 || !e.Done {
		t.Fatalf("evidence: %+v", e)
	}
}

func TestTapeRunLegacyTerminalEvidence(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if r.URL.Path == "/stop" {
			fmt.Fprint(w, "event: message_stop\ndata: {}\n\n")
			return
		}
		fmt.Fprint(w, "event: response.completed\ndata: {}\n\ndata: [DONE]\n\n")
	}))
	defer up.Close()
	one, two, yes := 1, 2, true
	tp := Tape{Version: 2, Target: up.URL, Script: []Step{
		{Name: "stop", Stream: &Stream{Path: "/stop"}},
		{Name: "completed", Stream: &Stream{Path: "/completed"}},
	}, Assertions: []Assertion{
		{StreamStep: "stop", ExpectSSE: &SSEExpect{End: "eof", Terminal: "message_stop", Done: &yes, MinEvents: &one, MaxEvents: &one}},
		{StreamStep: "completed", ExpectSSE: &SSEExpect{End: "done", Terminal: "response.completed", Done: &yes, MinEvents: &two, MaxEvents: &two}},
	}}
	results, err := Run(context.Background(), tp, "")
	if err != nil || len(results) != 2 || len(results[0].Failures) != 0 || len(results[1].Failures) != 0 {
		t.Fatalf("results=%v err=%v", results, err)
	}
}

func TestReplayRejectsOpaqueFrameAssertions(t *testing.T) {
	for _, content := range []string{"application/json", "text/event-stream"} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", content)
			if content == "text/event-stream" {
				w.Header().Set("Content-Encoding", "br")
			}
			fmt.Fprint(w, "opaque")
		}))
		e := runStream(context.Background(), server.URL, Stream{Path: "/"})
		server.Close()
		if got := checkStream(Assertion{ExpectSSE: &SSEExpect{Terminal: "none"}}, e); len(got) == 0 {
			t.Fatalf("certified opaque response: %+v", e)
		}
		if got := checkStream(Assertion{ExpectStatus: 200}, e); len(got) != 0 {
			t.Fatal(got)
		}
	}
}

func TestReplayLimitsDecodedFrameLines(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		z := gzip.NewWriter(w)
		fmt.Fprint(z, strings.Repeat(":x\n", 65537)+"data: {}\n\n")
		z.Close()
	}))
	defer up.Close()
	tp := Tape{Version: 2, Target: up.URL, Script: []Step{{Name: "stream", Stream: &Stream{Path: "/"}}}, Assertions: []Assertion{{StreamStep: "stream", ExpectSSE: &SSEExpect{Terminal: "none"}}}}
	results, err := Run(context.Background(), tp, "")
	if err != nil || len(results) != 1 || len(results[0].Failures) == 0 {
		t.Fatalf("oversized decoded frame certified: %v %v", results, err)
	}
}

func TestTerminalAssertionPresenceAndStepType(t *testing.T) {
	for _, assertion := range []string{
		`{http_get: /, expect_sse: {terminal: error}}`,
		`{grpc_step: g, expect_sse: {terminal: error}}`,
		`{stream_step: s, expect_sse: {terminal: ""}}`,
		`{stream_step: s, expect_sse: {terminal: null}}`,
	} {
		doc := "version: 2\ntarget: demo\nscript: [{name: s, stream: {path: /}}, {name: g, grpc: {path: /}}]\nassertions: [" + assertion + "]\n"
		if _, err := Decode(strings.NewReader(doc)); err == nil {
			t.Errorf("accepted %s", assertion)
		}
	}
}

func TestReplayUsesAdmittedRuleForEscapedURL(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("X-Glitchdeck-Sse-Admission") != "" {
			t.Error("admission token forwarded upstream")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: custom_end\ndata: {}\n\n")
	}))
	defer up.Close()
	tp := Tape{Version: 2, Target: up.URL, Rules: []fault.Rule{{ID: "r", Enabled: true, Match: fault.Match{PathPrefix: "/a?b"}, Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "drop", "every": 100, "done_events": []string{"custom_end"}}}}}, Script: []Step{{Name: "s", Stream: &Stream{URL: up.URL + "/a%3Fb"}}}, Assertions: []Assertion{{StreamStep: "s", ExpectSSE: &SSEExpect{Terminal: "custom_end"}}}}
	results, err := Run(context.Background(), tp, "")
	if err != nil || len(results) != 1 || len(results[0].Failures) != 0 {
		t.Fatalf("results=%v err=%v", results, err)
	}
}

func TestPublishedSSEModeDefaults(t *testing.T) {
	data, err := json.Marshal(fault.Registry["sse-glitch"].Params["mode"])
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Default         any               `json:"default"`
		DefaultByAction map[string]string `json:"default_by_action"`
	}
	if err := json.Unmarshal(data, &spec); err != nil || spec.Default != nil || spec.DefaultByAction["corrupt_json"] != "cut" || spec.DefaultByAction["corrupt_tool_args"] != "truncate" {
		t.Fatalf("incorrect published mode defaults: %s (%v)", data, err)
	}
}

func TestGRPCDeadlineAndTLS(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		tp := Tape{Version: 2, Target: "demo", Rules: []fault.Rule{{ID: "deadline", Enabled: true, Fault: fault.Fault{Type: "grpc-glitch", Params: map[string]any{"code": "DEADLINE_EXCEEDED", "delay_ms": 100}}}}, Script: []Step{{Name: "call", GRPC: &GRPC{Path: "/glitchdeck.demo.v1.Quotes/Get", TimeoutMS: 20}}}, Assertions: []Assertion{{Name: "deadline", GRPCStep: "call", ExpectGRPCStatus: func() *int { v := 4; return &v }()}}}
		results, err := Run(context.Background(), tp, "")
		if err != nil || len(results) != 1 || len(results[0].Failures) != 0 {
			t.Fatalf("results %v error %v", results, err)
		}
	})
	t.Run("paired TLS", func(t *testing.T) {
		tp := Tape{Version: 2, Target: "demo", TLSMITM: true, Script: []Step{{HTTP: &HTTP{URL: "${DEMO_TLS}/api/state"}}}}
		if _, err := Run(context.Background(), tp, ""); err != nil {
			t.Fatal(err)
		}
	})
}

func TestV2SchemaAndVersionGate(t *testing.T) {
	doc := "version: 2\ntarget: demo\nscript:\n  - name: chat\n    stream: {path: /api/chat/stream}\nassertions:\n  - name: done\n    stream_step: chat\n    expect_sse: {end: done}\n"
	if _, err := Decode(strings.NewReader(doc)); err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(strings.NewReader(strings.Replace(doc, "version: 2", "version: 1", 1))); err == nil {
		t.Fatal("v1 accepted v2 fields")
	}
}

func TestRejectAnyUpstreamAndValidateBeforeTLSOverride(t *testing.T) {
	for _, allow := range []string{"any", "localhost, AnY ,::1"} {
		if _, err := Decode(strings.NewReader("version: 2\ntarget: demo\nupstream_allow: [\"" + allow + "\"]\n")); err == nil {
			t.Fatalf("accepted %q", allow)
		}
	}
	if _, _, err := RunWithTLS(context.Background(), Tape{Version: 1, Target: "demo", TLSMITM: true}, "", "", true); err == nil {
		t.Fatal("accepted invalid original tape")
	}
	if _, _, err := RunWithTLS(context.Background(), Tape{Version: 1, Target: "demo"}, "", "", true); err != nil {
		t.Fatal(err)
	}
}

func TestAssertionJSONComparison(t *testing.T) {
	if failures := CheckAssertionJSON([]byte(`{"n":9007199254740993,"nested":{"x":null}}`), map[string]any{"n": int64(9007199254740993), "nested.x": nil}, nil); len(failures) != 0 {
		t.Fatal(failures)
	}
	if failures := CheckAssertionJSON([]byte(`{"n":1} {}`), map[string]any{"n": 1}, nil); len(failures) == 0 {
		t.Fatal("accepted trailing JSON")
	}
}

func TestProtocolClientsDoNotFollowRedirects(t *testing.T) {
	hits := 0
	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer dst.Close()
	src := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dst.URL, http.StatusTemporaryRedirect)
	}))
	src.Config.Protocols = new(http.Protocols)
	src.Config.Protocols.SetHTTP1(true)
	src.Config.Protocols.SetUnencryptedHTTP2(true)
	src.Start()
	defer src.Close()
	runStream(context.Background(), src.URL, Stream{Path: "/"})
	_, _ = runGRPC(context.Background(), src.URL, GRPC{Path: "/"})
	if hits != 0 {
		t.Fatalf("redirect followed %d times", hits)
	}
}

func TestForwardH2CAbsoluteURLKeepsFaultsActive(t *testing.T) {
	upstream := httptest.NewUnstartedServer(demo.New())
	upstream.Config.Protocols = demo.Protocols()
	upstream.Start()
	defer upstream.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	code := 14
	doc := Tape{
		Version: 2, Target: "demo",
		Rules:      []fault.Rule{{ID: "upstream", Enabled: true, Match: fault.Match{Host: strings.TrimPrefix(upstream.URL, "http://"), Proto: "h2"}, Fault: fault.Fault{Type: "grpc-glitch"}}},
		Script:     []Step{{Name: "rpc", GRPC: &GRPC{URL: upstream.URL + "/glitchdeck.demo.v1.Quotes/Get", Proto: "h2c", MessageB64: "CgRBQ01F"}}},
		Assertions: []Assertion{{Name: "injected", GRPCStep: "rpc", ExpectGRPCStatus: &code}},
	}
	results, report, err := RunWithReport(ctx, doc, "")
	if err != nil || len(results) != 1 || len(results[0].Failures) != 0 || report.Rules["upstream"].Applied != 1 {
		t.Fatalf("forwarded call did not detonate in the proxy: %v %+v %v", results, report, err)
	}
}

func TestH2TapeCountsWireFault(t *testing.T) {
	for _, action := range []string{"rst_stream", "goaway"} {
		t.Run(action, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			scenario := Tape{
				Version: 2, Target: "demo",
				Rules: []fault.Rule{{ID: "refuse", Enabled: true, Match: fault.Match{Proto: "h2", Seq: []uint64{1}},
					Fault: fault.Fault{Type: "h2-glitch", Params: map[string]any{"action": action, "code": "REFUSED_STREAM"}}}},
				Script: []Step{{HTTP: &HTTP{Path: "/api/state", Proto: "h2c"}}},
			}
			_, stats, err := RunWithReport(ctx, scenario, "")
			if err != nil || stats.Rules["refuse"].Applied != 1 || stats.Rules["refuse"].Skipped != 0 {
				t.Fatalf("fault report: %+v, error %v", stats, err)
			}
		})
	}
}

func TestH2TapeRecognizesTimelineTCPReset(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	doc := Tape{
		Version: 2, Target: "demo",
		Script: []Step{{HTTP: &HTTP{Path: "/api/state", Proto: "h2c"}}},
		ConfigChanges: []ConfigChange{{BeforeSeq: 1, Rules: []fault.Rule{{
			ID: "cut", Enabled: true, Match: fault.Match{Proto: "h2"},
			Fault: fault.Fault{Type: "tcp-rst", Params: map[string]any{"before_headers": true}},
		}}}},
	}
	_, report, err := RunWithReport(ctx, doc, "")
	if err != nil || report.Rules["cut"].Applied != 1 {
		t.Fatalf("timeline reset was not recognized: %+v, %v", report, err)
	}
}
