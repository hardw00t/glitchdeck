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
