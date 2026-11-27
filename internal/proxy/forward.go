package proxy

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/localweb"
	"github.com/hardw00t/glitchdeck/internal/tlsmitm"
)

type Options struct {
	CA                   *tlsmitm.CA
	Demo                 bool
	UpstreamAllow        []string
	TLSPassthrough       []string
	UpstreamCA           *x509.CertPool
	InsecureUpstream     bool
	MITMALPN             string
	H2TapOff             bool
	SSETelemetryMax      int
	ProxyAuth            string
	BeforeRequest        func(uint64)
	OnAdmission          func(seq uint64, method, path, host string)
	OnReset              func()
	RequireUpstreamAllow bool
	AllowLoopbackEgress  bool
}

type RuleStats struct {
	Matched, Applied, Skipped uint64
	SkipReasons               map[string]uint64
}

func (s *RuleStats) skip(reason string) {
	s.Skipped++
	if s.SkipReasons == nil {
		s.SkipReasons = make(map[string]uint64)
	}
	s.SkipReasons[reason]++
}

type AppliedFault struct {
	RuleID, Type string
	Count        uint64
}

func (p *Proxy) AppliedFaults() []AppliedFault {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]AppliedFault, 0, len(p.applied))
	for key, count := range p.applied {
		out = append(out, AppliedFault{RuleID: key.RuleID, Type: key.Type, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RuleID < out[j].RuleID || out[i].RuleID == out[j].RuleID && out[i].Type < out[j].Type
	})
	return out
}

// SetOptions configures the proxy before serving any requests.
func (p *Proxy) SetOptions(o Options) {
	p.mu.Lock()
	defer p.mu.Unlock()
	o.UpstreamAllow = slices.Clone(o.UpstreamAllow)
	o.TLSPassthrough = slices.Clone(o.TLSPassthrough)
	p.options = o
	closeIdleTransports(p.transports)
	p.transports = [8]*http.Transport{}
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

func (p *Proxy) countRule(gen uint64, rule *fault.Rule, kind, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if gen != p.generation {
		return
	}
	id := rule.ID
	v := p.stats[id]
	switch kind {
	case "matched":
		v.Matched++
	case "applied":
		if p.applied == nil {
			p.applied = make(map[AppliedFault]uint64)
		}
		p.applied[AppliedFault{RuleID: rule.ID, Type: rule.Fault.Type}]++
		v.Applied++
	case "skipped":
		v.skip(reason)
	}
	p.stats[id] = v
}

func (p *Proxy) authorize(w http.ResponseWriter, r *http.Request, absolute bool) bool {
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
	if strings.EqualFold(host, "localhost") {
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

func upstreamPort(scheme, port string) string {
	if port != "" {
		return port
	}
	if scheme == "https" {
		return "443"
	}
	return "80"
}

func restrictedEgress(ip netip.Addr) bool {
	ip = ip.Unmap()
	return !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func (p *Proxy) restrictEgressLocked(ctx context.Context) bool {
	if p.options.AllowLoopbackEgress {
		return false
	}
	bind, _ := ctx.Value(http.LocalAddrContextKey).(net.Addr)
	if p.front != nil {
		bind = p.front.Listener.Addr()
	}
	if bind == nil {
		return true
	}
	host, _, err := net.SplitHostPort(bind.String())
	if err != nil {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err != nil || !ip.Unmap().IsLoopback()
}

func (p *Proxy) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	p.mu.Lock()
	restrict := p.restrictEgressLocked(ctx)
	p.mu.Unlock()
	return p.dialWithPolicy(ctx, network, addr, restrict)
}

func (p *Proxy) dialWithPolicy(ctx context.Context, network, addr string, restrict bool) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	reverseTarget := ctx.Value(reverseTargetKey{}) == true && p.target != nil && !p.options.RequireUpstreamAllow && strings.EqualFold(host, p.target.Hostname()) && port == upstreamPort(p.target.Scheme, p.target.Port())
	if !p.allowed(host, port) && !reverseTarget {
		return nil, errors.New("egress denied")
	}
	// The operator-configured reverse target is reachable on any listener; clients
	// cannot choose it, so exposing the proxy does not turn it into an open relay.
	if reverseTarget {
		restrict = false
	}
	d := &net.Dialer{}
	if restrict {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil || restrictedEgress(ip) {
				return errors.New("egress denied")
			}
			return nil
		}
	}
	if strings.EqualFold(host, "localhost") {
		c, err := d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		if err != nil && ctx.Err() == nil {
			return d.DialContext(ctx, network, net.JoinHostPort("::1", port))
		}
		return c, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var last error
	for _, ip := range ips {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("no upstream addresses")
	}
	return nil, last
}

func closeIdleTransports(transports [8]*http.Transport) {
	for _, t := range transports {
		if t != nil {
			t.CloseIdleConnections()
		}
	}
}

func (p *Proxy) transportFor(ctx context.Context, h2c bool) *http.Transport {
	p.mu.Lock()
	defer p.mu.Unlock()
	restrict := p.restrictEgressLocked(ctx)
	// A restricted request must not borrow an already-dialed loopback connection.
	i := 0
	if restrict {
		i += 2
	}
	if ctx.Value(reverseTargetKey{}) == true {
		i += 4
	}
	if h2c {
		i++
	}
	if p.transports[i] == nil {
		p.transports[i] = p.newTransport(h2c, restrict)
	}
	return p.transports[i]
}

func (p *Proxy) newTransport(h2c, restrict bool) *http.Transport {
	t := &http.Transport{
		DisableCompression: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return p.dialWithPolicy(ctx, network, address, restrict)
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			RootCAs: p.options.UpstreamCA, InsecureSkipVerify: p.options.InsecureUpstream, MinVersion: tls.VersionTLS12,
		},
	}
	if h2c {
		t.Protocols = H2CProtocols()
	}
	return t
}
