package ui

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/demo"
	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
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
