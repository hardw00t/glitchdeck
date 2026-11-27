package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
	"github.com/hardw00t/glitchdeck/internal/tlsmitm"
)

func TestPassthroughMatching(t *testing.T) {
	tests := []struct {
		pattern, host, port string
		want                bool
	}{
		{"api.example.com", "API.Example.Com.", "443", true},
		{"api.example.com:8443", "api.example.com", "443", false},
		{"api.example.com:8443", "api.example.com.", "8443", true},
		{"api.example.com:08443", "api.example.com", "8443", true},
		{"api.example.com:8443", "api.example.com", "08443", true},
		{"*.example.com", "example.com", "443", false},
		{"*.example.com", ".example.com", "443", false},
		{"*.example.com", "badexample.com", "443", false},
		{"*.example.com", "a.b.example.com", "443", true},
		{"[::1]:8443", "::1", "8443", true},
		{"::1", "::1", "443", true},
	}
	for _, tt := range tests {
		p := New(nil, fault.Config{}, nil)
		p.SetOptions(Options{TLSPassthrough: []string{tt.pattern}})
		_, got := p.passthrough(tt.host, tt.port)
		p.Close()
		if got != tt.want {
			t.Errorf("%q %q:%s: got %v", tt.pattern, tt.host, tt.port, got)
		}
	}
}

func TestValidatePassthrough(t *testing.T) {
	for _, s := range []string{"example.com", " *.example.com:443 ", "127.0.0.1", "::1", "[::1]:8443"} {
		if err := ValidatePassthrough(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "*", "any", "*.", "*.com", "*.127.0.0.1", "api.*.com", "a*.example.com", "https://example.com", "example.com/path", "example.com?q=x", "a@example.com", "127.0.0.0/8", "example.com:0", "example.com:65536", "[bad]:443", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 127) + "com"} {
		if err := ValidatePassthrough(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func FuzzValidatePassthrough(f *testing.F) {
	for _, seed := range []string{"*.example.com", "[::1]:443", "", "api.*.com"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, pattern string) {
		if ValidatePassthrough(pattern) == nil && ValidatePassthrough(strings.TrimSpace(pattern)) != nil {
			t.Fatalf("trimming changed validation of %q", pattern)
		}
	})
}

func FuzzPassthrough(f *testing.F) {
	for _, s := range []string{"*.example.com", "[::1]:443", "", "api.*.com"} {
		f.Add(s, "a.example.com", "443")
	}
	f.Fuzz(func(t *testing.T, pattern, host, port string) {
		p := &Proxy{options: Options{TLSPassthrough: []string{pattern}}}
		if got, ok := p.passthrough(host, port); ok && (ValidatePassthrough(got) != nil || got != strings.TrimSpace(pattern)) {
			t.Fatalf("matched invalid or unexpected pattern %q", got)
		}
	})
}

func TestPassthroughDoesNotGrantEgress(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	p.SetOptions(Options{TLSPassthrough: []string{"evil.test"}})
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodConnect, "http://evil.test:443", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("got status %d", w.Code)
	}
	if s := p.TrafficStats(); s.Connects != 1 || s.EgressDenied != 1 || s.DialFailed != 0 {
		t.Fatalf("stats: %+v", s)
	}
}

func TestPassthroughDeniedBeforeDNS(t *testing.T) {
	old := net.DefaultResolver
	var calls atomic.Int64
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, fmt.Errorf("unexpected DNS dial")
	}}
	defer func() { net.DefaultResolver = old }()
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	p.SetOptions(Options{TLSPassthrough: []string{"evil.test"}})
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodConnect, "http://evil.test:443", nil))
	if w.Code != http.StatusForbidden || calls.Load() != 0 {
		t.Fatalf("status %d, DNS dials %d", w.Code, calls.Load())
	}
}

func TestPassthroughExposedListenerBlocksRestrictedIPs(t *testing.T) {
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := tlsmitm.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	p := New(nil, fault.Config{}, nil)
	p.SetOptions(Options{CA: ca, UpstreamAllow: []string{"169.254.169.254"}, TLSPassthrough: []string{"localhost", "127.0.0.1", "169.254.169.254"}})
	go p.Serve(l)
	defer p.Close()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	for _, host := range []string{"localhost", "127.0.0.1", "169.254.169.254"} {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		authority := net.JoinHostPort(host, "443")
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
		resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
		c.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("%s: status %d", host, resp.StatusCode)
		}
	}
}

func TestPassthroughUsesUpstreamCertificateAndRecordsEvent(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	ca, err := tlsmitm.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	bus := telemetry.New()
	p := New(nil, fault.Config{}, bus)
	p.SetOptions(Options{CA: ca, TLSPassthrough: []string{"127.0.0.1"}})
	server := httptest.NewServer(p)
	defer server.Close()
	defer p.Close()
	proxyURL, _ := url.Parse(server.URL)
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNoContent || !resp.TLS.PeerCertificates[0].Equal(upstream.Certificate()) {
		t.Fatal("upstream certificate or response not preserved")
	}
	resp.Body.Close()
	tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := p.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if s := p.TrafficStats(); s.PassthroughOK != 1 || s.TLSRejected != 0 {
		t.Fatalf("stats: %+v", s)
	}
	found := false
	for _, event := range bus.History(20) {
		var data map[string]any
		if event.Type == "http_req" && json.Unmarshal(event.Data, &data) == nil && data["tunnel"] == "passthrough" && data["passthrough"] == "127.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing passthrough event")
	}
}
