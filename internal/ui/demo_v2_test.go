package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/demo"
	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/tape"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
)

func TestDemoV2TrafficGoesThroughProxy(t *testing.T) {
	upstream := httptest.NewUnstartedServer(demo.New())
	upstream.Config.Protocols = demo.Protocols()
	upstream.Start()
	defer upstream.Close()
	target, err := proxy.ParseTarget(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	bus := telemetry.New()
	p := proxy.New(target, fault.Config{Seed: 1, Rules: []fault.Rule{
		{ID: "end", Enabled: true, Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "eof_early"}}, Match: fault.Match{PathPrefix: "/api/chat/stream"}},
		{ID: "unavailable", Enabled: true, Fault: fault.Fault{Type: "grpc-glitch", Params: map[string]any{"code": 14}}},
	}}, bus)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(New(p, bus, Options{Listen: ln.Addr().String(), DemoURL: upstream.URL}))
	defer h.Close()
	defer p.Close()
	go p.Serve(ln)
	client := h.Client()
	client.Timeout = 4 * time.Second
	post := func(path, body string, dst any) {
		t.Helper()
		res, err := client.Post(h.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if err := json.NewDecoder(res.Body).Decode(dst); res.StatusCode != http.StatusOK || err != nil {
			t.Fatalf("%s: got %s (%v)", path, res.Status, err)
		}
	}
	var stream struct {
		Outcome string `json:"outcome"`
		Tokens  int    `json:"tokens"`
		Seq     int    `json:"seq"`
	}
	post("/api/demo/stream", `{"tokens":2,"token_ms":0,"wait":true}`, &stream)
	if stream.Outcome != "silent_truncation" || stream.Tokens != 2 || stream.Seq != 1 {
		t.Fatalf("unexpected demo stream result: %+v", stream)
	}
	var grpc struct {
		Status int `json:"grpc_status"`
	}
	post("/api/demo/grpc", "", &grpc)
	if grpc.Status != 14 {
		t.Fatalf("RPC did not receive injected gRPC status: %+v", grpc)
	}
}

type blockingTransport struct {
	base    http.RoundTripper
	entered chan struct{}
	release chan struct{}
}

func (b *blockingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Header.Get("X-Glitchdeck-Run") == "first" {
		close(b.entered)
		<-b.release
	}
	return b.base.RoundTrip(r)
}

func TestDemoStreamUsesAdmittedRule(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: custom_end\ndata: {}\n\n")
	}))
	defer up.Close()
	target, _ := proxy.ParseTarget(up.URL)
	p := proxy.New(target, fault.Config{Rules: []fault.Rule{{ID: "r", Enabled: true, Match: fault.Match{Seq: []uint64{1}}, Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "drop", "every": 100, "done_events": []string{"custom_end"}}}}}}, nil)
	defer p.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve(ln)
	transport := &blockingTransport{base: http.DefaultTransport, entered: make(chan struct{}), release: make(chan struct{})}
	c := &control{Options: Options{Listen: ln.Addr().String(), DemoURL: up.URL}, p: p, client: &http.Client{Transport: transport}}
	in := streamInput{Flavor: "openai", MaxMS: 5000, WedgeAfterMS: 1000}
	first := make(chan streamResult, 1)
	go func() { first <- c.readDemoStream(context.Background(), "first", in) }()
	<-transport.entered
	second := c.readDemoStream(context.Background(), "second", in)
	close(transport.release)
	gotFirst := <-first
	if second.Outcome != "complete" || gotFirst.Outcome != "silent_truncation" {
		t.Fatalf("second=%+v first=%+v", second, gotFirst)
	}
}

func TestDemoStreamDoesNotExposeProviderError(t *testing.T) {
	secret := strings.Repeat("secret-credential", 1000)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "event: error\ndata: {\"error\":{\"message\":%q}}\n\n", secret)
	}))
	defer up.Close()
	target, _ := proxy.ParseTarget(up.URL)
	p := proxy.New(target, fault.Config{}, nil)
	defer p.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve(ln)
	c := &control{Options: Options{Listen: ln.Addr().String(), DemoURL: up.URL}, p: p, client: &http.Client{}}
	got := c.readDemoStream(context.Background(), "error", streamInput{Flavor: "openai", MaxMS: 5000, WedgeAfterMS: 1000})
	if got.Outcome != "error" || got.ClientError == "" || len(got.ClientError) > 256 || strings.Contains(got.ClientError, "secret-credential") {
		t.Fatalf("unsafe error: %+v", got)
	}
}

func TestDemoConsoleRecordsAbsoluteTargetForReplay(t *testing.T) {
	upstream := httptest.NewServer(demo.New())
	defer upstream.Close()
	target, err := proxy.ParseTarget(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	bus := telemetry.New()
	p := proxy.New(target, fault.Config{Seed: 1}, bus)
	defer p.Close()
	p.SetOptions(proxy.Options{Demo: true})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	handler := New(p, bus, Options{Target: upstream.URL, DemoURL: upstream.URL})
	start := httptest.NewRequest("POST", "/api/tape/record", nil)
	start.RemoteAddr = "127.0.0.1:1234"
	start.Host = "localhost"
	handler.ServeHTTP(httptest.NewRecorder(), start)
	go p.Serve(ln)
	proxyURL := "http://" + ln.Addr().String()
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(parsed)}}
	resp, err := client.Get(upstream.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if err := p.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	export := httptest.NewRequest("GET", "/api/tape/export", nil)
	export.RemoteAddr = "127.0.0.1:1234"
	export.Host = "localhost"
	handler.ServeHTTP(w, export)
	doc, err := tape.Decode(strings.NewReader(w.Body.String()))
	if err != nil {
		t.Fatalf("export: %v: %s", err, w.Body.String())
	}
	if len(doc.Cassettes) != 1 || doc.Cassettes[0].Request.Host != "" {
		t.Fatalf("demo cassette: %+v", doc.Cassettes)
	}
	if _, report, err := tape.RunReplay(context.Background(), doc, "", "", false); err != nil || report.CassetteError != nil {
		t.Fatalf("replay: %+v, %v", report, err)
	}
}
