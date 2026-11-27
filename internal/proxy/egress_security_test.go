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
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/tlsmitm"
	"golang.org/x/net/dns/dnsmessage"
)

func TestRestrictedEgressAddresses(t *testing.T) {
	for _, tc := range []struct {
		ip      string
		blocked bool
	}{
		{"127.0.0.2", true}, {"::1", true}, {"::ffff:127.0.0.1", true},
		{"169.254.1.1", true}, {"fe80::1", true}, {"0.0.0.0", true}, {"::", true},
		{"192.0.2.1", false}, {"2001:db8::1", false},
	} {
		if got := restrictedEgress(netip.MustParseAddr(tc.ip)); got != tc.blocked {
			t.Errorf("%s: got %v", tc.ip, got)
		}
	}
}

func TestForwardEgressListenerPolicy(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer up.Close()
	_, port, _ := net.SplitHostPort(up.Listener.Addr().String())
	for _, tc := range []struct {
		name, bind string
		allow      bool
		want       int
	}{
		{"exposed", "0.0.0.0:0", false, 502}, {"exposed opt in", "0.0.0.0:0", true, 204}, {"local", "127.0.0.1:0", false, 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := net.Listen("tcp", tc.bind)
			if err != nil {
				t.Fatal(err)
			}
			p := New(nil, fault.Config{}, nil)
			p.SetOptions(Options{UpstreamAllow: []string{"any"}, AllowLoopbackEgress: tc.allow})
			go p.Serve(l)
			defer p.Close()
			_, proxyPort, _ := net.SplitHostPort(l.Addr().String())
			for _, host := range []string{"127.0.0.1", "localhost", "[::ffff:127.0.0.1]"} {
				for _, method := range []string{"GET", "CONNECT", "websocket"} {
					c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", proxyPort), time.Second)
					if err != nil {
						t.Fatal(err)
					}
					_ = c.SetDeadline(time.Now().Add(2 * time.Second))
					authority := host + ":" + port
					switch method {
					case "CONNECT":
						fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
					case "websocket":
						fmt.Fprintf(c, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", authority, authority)
					default:
						fmt.Fprintf(c, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
					}
					resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: method})
					if err != nil {
						c.Close()
						t.Fatal(err)
					}
					want := tc.want
					if method == "CONNECT" && want == 204 {
						want = 200
					}
					if resp.StatusCode != want {
						t.Errorf("%s %s: got %d want %d", host, method, resp.StatusCode, want)
					}
					c.Close()
				}
			}
		})
	}
}

func TestDialRejectsResolvedLoopbackOnExposedListener(t *testing.T) {
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	p := New(nil, fault.Config{}, nil)
	p.SetOptions(Options{UpstreamAllow: []string{"any"}})
	go p.Serve(l)
	defer p.Close()
	// Wait until Serve has installed its listener before exercising the dial path.
	deadline := time.Now().Add(time.Second)
	for {
		p.mu.Lock()
		ready := p.front != nil
		p.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listener not ready")
		}
		time.Sleep(time.Millisecond)
	}
	_, err = p.dial(context.Background(), "tcp", "localhost:1")
	if err == nil || !strings.Contains(err.Error(), "egress denied") {
		t.Fatalf("dial error = %v", err)
	}
}

func TestDialRejectsDNSResolvedLoopback(t *testing.T) {
	dns, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := dns.ReadFrom(buf)
			if err != nil {
				return
			}
			var msg dnsmessage.Message
			if msg.Unpack(buf[:n]) != nil || len(msg.Questions) != 1 {
				continue
			}
			q := msg.Questions[0]
			reply := dnsmessage.Message{Header: dnsmessage.Header{ID: msg.Header.ID, Response: true, Authoritative: true}, Questions: msg.Questions}
			if q.Type == dnsmessage.TypeA {
				reply.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}}}
			}
			wire, err := reply.Pack()
			if err == nil {
				_, _ = dns.WriteTo(wire, addr)
			}
		}
	}()
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", dns.LocalAddr().String())
	}}
	defer func() { net.DefaultResolver = old }()
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	p := New(nil, fault.Config{}, nil)
	p.SetOptions(Options{UpstreamAllow: []string{"synthetic.test"}})
	go p.Serve(l)
	defer p.Close()
	deadline := time.Now().Add(time.Second)
	for {
		p.mu.Lock()
		ready := p.front != nil
		p.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listener not ready")
		}
		time.Sleep(time.Millisecond)
	}
	_, err = p.dial(context.Background(), "tcp", "synthetic.test:1")
	if err == nil || !strings.Contains(err.Error(), "egress denied") {
		t.Fatalf("dial error = %v", err)
	}
}

func TestInterceptedEgressHonorsListenerPolicy(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer up.Close()
	ca, err := tlsmitm.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	upRoots := x509.NewCertPool()
	upRoots.AddCert(up.Certificate())
	for _, tc := range []struct {
		allow bool
		want  int
	}{{false, 502}, {true, 204}} {
		l, err := net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			t.Fatal(err)
		}
		p := New(nil, fault.Config{}, nil)
		p.SetOptions(Options{CA: ca, UpstreamCA: upRoots, AllowLoopbackEgress: tc.allow})
		go p.Serve(l)
		_, port, _ := net.SplitHostPort(l.Addr().String())
		proxyURL, _ := url.Parse("http://" + net.JoinHostPort("127.0.0.1", port))
		tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
		client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
		resp, err := client.Get(up.URL)
		if err != nil {
			t.Errorf("allow=%v: %v", tc.allow, err)
		} else {
			if resp.StatusCode != tc.want {
				t.Errorf("allow=%v: got %d want %d", tc.allow, resp.StatusCode, tc.want)
			}
			resp.Body.Close()
		}
		tr.CloseIdleConnections()
		p.Close()
	}
}
