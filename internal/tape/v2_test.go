package tape

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/demo"
	"github.com/hardw00t/glitchdeck/internal/fault"
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
