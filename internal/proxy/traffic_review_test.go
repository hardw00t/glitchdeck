package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
	"github.com/hardw00t/glitchdeck/internal/tlsmitm"
)

func TestInterceptTLSClientAlertsAndQuietClose(t *testing.T) {
	ca, err := tlsmitm.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, trust := range []bool{false, true} {
			t.Run(fmtTrafficCase(version, trust), func(t *testing.T) {
				bus := telemetry.New()
				p := New(nil, fault.Config{}, bus)
				p.SetOptions(Options{CA: ca, UpstreamAllow: []string{"example.test"}})
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				go p.Serve(l)
				defer p.Close()
				c, err := net.Dial("tcp", l.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err = c.Write([]byte("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")); err != nil {
					t.Fatal(err)
				}
				br := bufio.NewReader(c)
				resp, err := http.ReadResponse(br, nil)
				if err != nil || resp.StatusCode != 200 {
					t.Fatalf("CONNECT: %v %v", resp, err)
				}
				roots := x509.NewCertPool()
				if trust {
					roots.AddCert(ca.Cert)
				}
				tc := tls.Client(&bufferedConn{Conn: c, r: br}, &tls.Config{ServerName: "example.test", RootCAs: roots, MinVersion: version, MaxVersion: version})
				err = tc.Handshake()
				if (err == nil) != trust {
					t.Fatalf("handshake: %v", err)
				}
				c.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := p.Wait(ctx); err != nil {
					t.Fatal(err)
				}
				s := p.TrafficStats()
				if trust {
					if s.TLSRejected != 0 || s.InterceptedOK != 0 || s.InterceptedEmpty != 1 {
						t.Fatalf("quiet close: %+v", s)
					}
				} else if s.TLSRejected != 1 || s.InterceptedOK != 0 {
					t.Fatalf("certificate alert: %+v", s)
				}
				failures := 0
				for _, event := range bus.History(20) {
					if event.Type == "tls_handshake_failed" {
						failures++
					}
				}
				if trust && failures != 0 || !trust && failures != 1 {
					t.Fatalf("TLS failure events: %d", failures)
				}
			})
		}
	}
}

func fmtTrafficCase(v uint16, trusted bool) string { return fmt.Sprintf("%x/trusted=%v", v, trusted) }

func TestTransportFailureIsNotUsableTraffic(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	p.SetOptions(Options{AllowLoopbackEgress: true})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "http://"+addr+"/", nil))
	if w.Code != 502 || p.TrafficStats().InnerUsable != 0 {
		t.Fatalf("status %d stats %+v", w.Code, p.TrafficStats())
	}
}

func TestProbeAfterDrain(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer up.Close()
	target, _ := url.Parse(up.URL)
	p := New(target, fault.Config{}, nil)
	defer p.Close()
	if err := p.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "localhost"
	w := httptest.NewRecorder()
	p.ServeProbeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("probe status %d", w.Code)
	}
	if p.TrafficStats().InnerUsable != 1 {
		t.Fatalf("probe stats %+v", p.TrafficStats())
	}
	w = httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatalf("ordinary status %d", w.Code)
	}
}

func TestResetInvokesObserverAndClearsTraffic(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	called := 0
	p.SetOptions(Options{OnReset: func() { called++ }})
	p.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("CONNECT", "denied.test:443", nil))
	p.ResetWith(func() { called++ })
	if called != 2 || p.TrafficStats().RequestsTotal != 0 {
		t.Fatalf("callbacks %d stats %+v", called, p.TrafficStats())
	}
}
