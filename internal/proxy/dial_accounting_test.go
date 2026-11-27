package proxy

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
	"github.com/hardw00t/glitchdeck/internal/testutil"
)

func TestDeniedRequestEventUsesPublicHost(t *testing.T) {
	const token = "fixture-marker"
	for _, tc := range []struct {
		method, authority, want string
	}{
		{http.MethodConnect, "Denied.Example.test:443", "denied.example.test"},
		{http.MethodConnect, token + ".example.test:443", ""},
		{http.MethodGet, "denied.example.test:" + strings.Repeat("0", 1024) + "80", ""},
	} {
		bus := telemetry.New()
		p := New(nil, fault.Config{}, bus)
		var hosts []string
		p.SetOptions(Options{ProxyAuth: token, OnEgressDenied: func(host string) { hosts = append(hosts, host) }})
		address := tc.authority
		if tc.method == http.MethodGet {
			address = "http://" + address + "/unreported?fixture=value"
		}
		r := httptest.NewRequest(tc.method, address, nil)
		r.SetBasicAuth("proxy", token)
		r.Header.Set("Proxy-Authorization", r.Header.Get("Authorization"))
		r.Header.Del("Authorization")
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		p.Close()
		var event map[string]json.RawMessage
		history := bus.History(1)
		if w.Code != http.StatusForbidden || len(history) != 1 || json.Unmarshal(history[0].Data, &event) != nil {
			t.Fatalf("status=%d events=%v", w.Code, history)
		}
		var host string
		_ = json.Unmarshal(event["host"], &host)
		if host != tc.want || event["path"] != nil || strings.Contains(string(history[0].Data), token) ||
			tc.want == "" && len(hosts) != 0 || tc.want != "" && !slices.Equal(hosts, []string{tc.want}) {
			t.Errorf("method=%s event=%s hosts=%q", tc.method, history[0].Data, hosts)
		}
	}
}

func TestRestrictedConfiguredReverseDialCountsAsDenial(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("restricted request reached upstream")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	for _, upgrade := range []bool{false, true} {
		p := New(target, fault.Config{}, nil)
		var hosts []string
		p.SetOptions(Options{RequireUpstreamAllow: true, OnEgressDenied: func(host string) { hosts = append(hosts, host) }})
		r := dialAccountingRequest(http.MethodGet)
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 8080}))
		if upgrade {
			r.Header.Set("Connection", "Upgrade")
			r.Header.Set("Upgrade", "websocket")
			r.Header.Set("Sec-WebSocket-Version", "13")
			r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		}
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		stats := p.TrafficStats()
		p.Close()
		if w.Code != http.StatusBadGateway || stats.EgressDenied != 1 || stats.DialFailed != 0 || stats.ReverseDialFailed != 0 || !slices.Equal(hosts, []string{"127.0.0.1"}) {
			t.Errorf("websocket=%v status=%d stats=%+v hosts=%q", upgrade, w.Code, stats, hosts)
		}
	}
}

func dialAccountingRequest(method string) *http.Request {
	r := httptest.NewRequest(method, "/webhook", strings.NewReader("{}"))
	r.Host = "127.0.0.1:8080"
	return r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}))
}

func TestCanceledReverseDialDoesNotCountAfterDrainOrReset(t *testing.T) {
	for _, reset := range []bool{false, true} {
		target, _ := url.Parse("http://" + testutil.RefusedTCPAddr(t))
		p := New(target, fault.Config{}, nil)
		defer p.Close()
		r := dialAccountingRequest(http.MethodGet)
		ctx, cancel := context.WithCancel(r.Context())
		tr := p.transportFor(context.WithValue(ctx, reverseTargetKey{}, true), false)
		dial := tr.DialContext
		entered, release, complete := make(chan struct{}), make(chan struct{}), make(chan struct{})
		tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			close(entered)
			<-release
			defer close(complete)
			return dial(context.WithoutCancel(ctx), network, address)
		}
		returned := make(chan struct{})
		go func() {
			defer close(returned)
			p.ServeHTTP(httptest.NewRecorder(), r.WithContext(ctx))
		}()
		awaitDialSignal(t, entered)
		cancel()
		awaitDialSignal(t, returned)
		if reset {
			p.Reset()
		} else if err := p.Drain(t.Context()); err != nil {
			t.Fatal(err)
		}
		close(release)
		awaitDialSignal(t, complete)
		stats := p.TrafficStats()
		if stats.DialFailed != 0 || stats.EgressDenied != 0 {
			t.Errorf("reset=%v stats=%+v", reset, stats)
		}
	}
}

func awaitDialSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("dial gate did not advance")
	}
}

func TestReverseReplayRefusalIsCountedBeforeDrainReturns(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	refused := testutil.RefusedTCPAddr(t)
	cfg := fault.Config{Rules: []fault.Rule{{ID: "replay", Enabled: true, Fault: fault.Fault{
		Type: "dup-webhook", Params: map[string]any{"mode": "timeout_retry", "count": 2, "delay_ms": 0},
	}}}}
	p := New(target, cfg, nil)
	defer p.Close()
	r := dialAccountingRequest(http.MethodPost)
	tr := p.transportFor(r.Context(), false)
	dial := tr.DialContext
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dial(ctx, network, refused)
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if err := p.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	stats, replay := p.TrafficStats(), p.Stats()["replay"].Replays
	if w.Code != http.StatusGatewayTimeout || replay == nil || replay.CommittedStatus != 204 || replay.Outcomes["transport_error"] != 1 || stats.DialFailed != 1 || stats.ReverseDialFailed != 1 {
		t.Fatalf("status=%d replay=%+v stats=%+v", w.Code, replay, stats)
	}
}

func TestCanceledBlindConnectDoesNotCountAsDialFailure(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	r := httptest.NewRequest(http.MethodConnect, "127.0.0.1:8080", nil)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	p.OnBlindTunnel = func(uint64) { cancel() }
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r.WithContext(ctx))
	if stats := p.TrafficStats(); w.Code != http.StatusBadGateway || stats.Connects != 1 || stats.DialFailed != 0 || stats.EgressDenied != 0 {
		t.Fatalf("status=%d stats=%+v", w.Code, stats)
	}
}
