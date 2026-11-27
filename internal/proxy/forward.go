package proxy

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/hardw00t/glitchdeck/internal/localweb"
	"github.com/hardw00t/glitchdeck/internal/tlsmitm"
)

type Options struct {
	CA               *tlsmitm.CA
	Demo             bool
	UpstreamAllow    []string
	UpstreamCA       *x509.CertPool
	InsecureUpstream bool
	MITMALPN         string
	H2TapOff         bool
	SSETelemetryMax  int
	ProxyAuth        string
}

type RuleStats struct {
	Matched, Applied, Skipped uint64
	SkipReasons               map[string]uint64
}

// SetOptions configures the proxy before serving any requests.
func (p *Proxy) SetOptions(o Options) {
	p.mu.Lock()
	defer p.mu.Unlock()
	o.UpstreamAllow = slices.Clone(o.UpstreamAllow)
	p.options = o
	p.transport.CloseIdleConnections()
	p.h2c.CloseIdleConnections()
	p.transport, p.h2c = p.newTransport(false), p.newTransport(true)
}

func (p *Proxy) TLSInfo() (bool, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.options.CA == nil {
		return false, ""
	}
	return true, p.options.CA.Fingerprint()
}

func (p *Proxy) Stats() map[string]RuleStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]RuleStats, len(p.stats))
	for k, v := range p.stats {
		v.SkipReasons = cloneReasons(v.SkipReasons)
		out[k] = v
	}
	return out
}

func cloneReasons(in map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (p *Proxy) countRule(gen uint64, id, kind, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if gen != p.generation {
		return
	}
	v := p.stats[id]
	switch kind {
	case "matched":
		v.Matched++
	case "applied":
		v.Applied++
	case "skipped":
		v.Skipped++
		if v.SkipReasons == nil {
			v.SkipReasons = make(map[string]uint64)
		}
		v.SkipReasons[reason]++
	}
	p.stats[id] = v
}

func (p *Proxy) authorize(w http.ResponseWriter, r *http.Request) bool {
	absolute := r.Method == http.MethodConnect || r.URL.IsAbs()
	bind, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	bound := ""
	if bind != nil {
		bound = bind.String()
	}
	if absolute && r.Header.Get("Origin") != "" || !absolute && !localweb.Allowed(r, bound) {
		http.Error(w, "untrusted proxy host or origin", http.StatusForbidden)
		return false
	}
	if pass := p.options.ProxyAuth; pass != "" && !MetaFrom(r.Context()).MITM {
		auth := r.Header.Get("Proxy-Authorization")
		probe := &http.Request{Header: http.Header{"Authorization": {auth}}}
		_, got, ok := probe.BasicAuth()
		if !ok && !absolute {
			_, got, ok = r.BasicAuth()
			if ok && subtle.ConstantTimeCompare([]byte(got), []byte(pass)) == 1 {
				r.Header.Del("Authorization")
			}
		}
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(pass)) != 1 {
			w.Header().Set("Proxy-Authenticate", `Basic realm="glitchdeck"`)
			http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
			return false
		}
	}
	r.Header.Del("Proxy-Authorization")
	return true
}

func H2CProtocols() *http.Protocols {
	protos := new(http.Protocols)
	protos.SetUnencryptedHTTP2(true)
	return protos
}

func (p *Proxy) allowed(host, port string) bool {
	if host == "" {
		return false
	}
	if p.explicit(host, port) || strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip.IsLoopback() {
		return true
	}
	for _, a := range p.options.UpstreamAllow {
		for raw := range strings.SplitSeq(a, ",") {
			item := strings.ToLower(strings.TrimSpace(raw))
			h := strings.ToLower(host)
			if item == "any" || item == h || item == net.JoinHostPort(h, port) || strings.HasPrefix(item, "*.") && strings.HasSuffix(h, item[1:]) {
				return true
			}
			if _, cidr, err := net.ParseCIDR(item); err == nil && cidr.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func (p *Proxy) explicit(host, port string) bool {
	return p.target != nil && strings.EqualFold(host, p.target.Hostname()) && port == upstreamPort(p.target.Scheme, p.target.Port())
}

func upstreamPort(scheme, port string) string {
	if port != "" {
		return port
	}
	if scheme == "https" {
		return "443"
	}
	return "80"
}

func (p *Proxy) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if !p.allowed(host, port) {
		return nil, errors.New("egress denied")
	}
	d := &net.Dialer{}
	if strings.EqualFold(host, "localhost") {
		c, err := d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		if err != nil && ctx.Err() == nil {
			return d.DialContext(ctx, network, net.JoinHostPort("::1", port))
		}
		return c, err
	}
	return d.DialContext(ctx, network, addr)
}

func (p *Proxy) newTransport(h2c bool) *http.Transport {
	t := &http.Transport{
		DisableCompression: true,
		DialContext:        p.dial,
		ForceAttemptHTTP2:  true,
		TLSClientConfig: &tls.Config{
			RootCAs: p.options.UpstreamCA, InsecureSkipVerify: p.options.InsecureUpstream, MinVersion: tls.VersionTLS12,
		},
	}
	if h2c {
		t.Protocols = H2CProtocols()
	}
	return t
}
