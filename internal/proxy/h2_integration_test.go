package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/h2tap"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
	"github.com/hardw00t/glitchdeck/internal/tlsmitm"
	"golang.org/x/net/http2/hpack"
)

func listenProxy(t *testing.T, p *Proxy) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close(); _ = l.Close() })
	go p.Serve(l)
	return l.Addr().String()
}

func TestH2PriorKnowledgeFaultFrames(t *testing.T) {
	for _, tc := range []struct {
		action string
		frame  byte
		code   uint32
	}{
		{"rst_stream", 3, 11},
		{"goaway", 7, 11},
	} {
		t.Run(tc.action, func(t *testing.T) {
			p := New(nil, fault.Config{Rules: []fault.Rule{{ID: "test", Enabled: true, Fault: fault.Fault{Type: "h2-glitch", Params: map[string]any{"action": tc.action, "code": "ENHANCE_YOUR_CALM"}}}}}, nil)
			addr := listenProxy(t, p)
			c, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			var block bytes.Buffer
			enc := hpack.NewEncoder(&block)
			for _, f := range []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: addr}, {Name: ":path", Value: "/"}} {
				if err := enc.WriteField(f); err != nil {
					t.Fatal(err)
				}
			}
			wire := append([]byte(h2tap.Preface), 0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 1, 0, 0, 16, 0)
			wire = append(wire, 0, 0, byte(block.Len()), 1, 4, 0, 0, 0, 1)
			wire = append(wire, block.Bytes()...)
			if _, err := c.Write(wire); err != nil {
				t.Fatal(err)
			}
			for {
				h, b, err := h2tap.ReadFrame(c)
				if err != nil {
					t.Fatal(err)
				}
				if h.Type != tc.frame {
					continue
				}
				if tc.frame == 7 {
					if h.Stream != 0 || len(b) < 8 || binary.BigEndian.Uint32(b) != 0 {
						t.Fatalf("bad GOAWAY: %+v %x", h, b)
					}
					b = b[4:]
				} else if h.Stream != 1 {
					t.Fatalf("bad RST_STREAM: %+v", h)
				}
				if len(b) < 4 || binary.BigEndian.Uint32(b) != tc.code {
					t.Fatalf("wrong error code: %x", b)
				}
				return
			}
		})
	}
}

func TestTLSInterceptNegotiatesHTTP2(t *testing.T) {
	u := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.Proto)
	}))
	u.EnableHTTP2 = true
	u.StartTLS()
	defer u.Close()
	upTrust := x509.NewCertPool()
	upTrust.AddCert(u.Certificate())
	ca, err := tlsmitm.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	clientTrust := x509.NewCertPool()
	clientTrust.AddCert(ca.Cert)
	p := New(nil, fault.Config{}, nil)
	p.SetOptions(Options{CA: ca, UpstreamCA: upTrust})
	addr := listenProxy(t, p)
	proxyURL, _ := url.Parse("http://" + addr)
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: clientTrust, MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 4 * time.Second}
	res, err := client.Get(u.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil || res.StatusCode != 200 || res.ProtoMajor != 2 || string(body) != "HTTP/2.0" {
		t.Fatalf("downstream %s %s, upstream %s: %v", res.Status, res.Proto, body, err)
	}
	if res.TLS == nil || res.TLS.NegotiatedProtocol != "h2" || res.TLS.PeerCertificates[0].VerifyHostname("127.0.0.1") != nil {
		t.Fatalf("wrong intercepted TLS identity: %+v", res.TLS)
	}
}

func TestTLSHandshakeFailureIsReported(t *testing.T) {
	ca, err := tlsmitm.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	bus := telemetry.New()
	_, events, unsubscribe := bus.Subscribe()
	defer unsubscribe()
	p := New(nil, fault.Config{}, bus)
	p.SetOptions(Options{CA: ca})
	addr := listenProxy(t, p)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = writer
	defer func() { os.Stderr = old; reader.Close(); writer.Close() }()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(c, "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
	if _, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect}); err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(c, &tls.Config{ServerName: "example.test", RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err == nil {
		t.Fatal("expected untrusted certificate failure")
	}
	select {
	case event := <-events:
		if event.Type != "tls_handshake_failed" || !strings.Contains(string(event.Data), "example.test") || !strings.Contains(string(event.Data), "error") {
			t.Fatalf("unexpected wire event: %+v", event)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("missing TLS failure event")
	}
	writer.Close()
	logged, err := io.ReadAll(reader)
	if err != nil || !strings.Contains(string(logged), "example.test") || !strings.Contains(string(logged), "tls_handshake_failed") {
		t.Fatalf("missing TLS diagnostic: %q, %v", logged, err)
	}
}

func TestDenyNonLoopbackCONNECT(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	addr := listenProxy(t, p)
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	blocked := net.IPv4(192, 0, 2, 1).String() + ":443"
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", blocked, blocked); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP/1.1 403 ") {
		t.Fatalf("CONNECT response %q: %v", line, err)
	}
}
