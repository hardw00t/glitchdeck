package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardw00t/glitchdeck/internal/h2tap"
	"github.com/hardw00t/glitchdeck/internal/tlsmitm"
)

type ConnMeta struct {
	Scheme, Authority string
	SNI, ALPN         string
	MITM              bool
	Tap               *h2tap.Conn
	tls               *tls.ConnectionState
}

// ForwardH2CHeader marks a prior-knowledge proxy request whose authority is the upstream.
const ForwardH2CHeader = "X-Glitchdeck-H2c-Forward"

type connKey struct{}
type streamKey struct{}

func MetaFrom(ctx context.Context) ConnMeta {
	v, _ := ctx.Value(connKey{}).(ConnMeta)
	return v
}

func streamFrom(ctx context.Context) uint32 {
	v, _ := ctx.Value(streamKey{}).(uint32)
	return v
}

func resetProtocolStreamAfterData(ctx context.Context, code uint32, bytes int64) bool {
	tap, stream := MetaFrom(ctx).Tap, streamFrom(ctx)
	if tap == nil || stream == 0 {
		return false
	}
	select {
	case <-tap.ResetAfterData(stream, code, bytes):
	case <-tap.Done():
	case <-ctx.Done():
	}
	return true
}

// prepareProtocolRequest removes the private stream header even on untapped
// connections and pins intercepted requests to the CONNECT authority.
func prepareProtocolRequest(r *http.Request) bool {
	meta := MetaFrom(r.Context())
	h := r.Header.Get(h2tap.StreamHeader)
	r.Header.Del(h2tap.StreamHeader)
	forward := r.Header.Get(ForwardH2CHeader) == "1"
	r.Header.Del(ForwardH2CHeader)
	if meta.Tap != nil && h != "" {
		if id, err := strconv.ParseUint(h, 10, 31); err == nil {
			*r = *r.WithContext(context.WithValue(r.Context(), streamKey{}, uint32(id)))
		}
	}
	if !meta.MITM {
		if forward && r.ProtoMajor == 2 && r.Method != http.MethodConnect && r.URL.Host == "" {
			r.URL.Scheme, r.URL.Host = "http", r.Host
		}
		return true
	}
	if r.Method == http.MethodConnect || !authorityMatches(r.Host, meta.Authority, meta.Scheme) || r.URL.Host != "" && !authorityMatches(r.URL.Host, meta.Authority, meta.Scheme) {
		return false
	}
	r.URL.Scheme, r.URL.Host = meta.Scheme, meta.Authority
	r.Host, r.TLS = meta.Authority, meta.tls
	return true
}

func authorityMatches(got, want, scheme string) bool {
	if strings.EqualFold(got, want) {
		return true
	}
	h, p, _ := net.SplitHostPort(want)
	return ((p == "443" && scheme == "https") || (p == "80" && scheme == "http")) && strings.EqualFold(strings.Trim(got, "[]"), h)
}

func listenerAuthority(ctx context.Context, host, port string) bool {
	local, ok := ctx.Value(http.LocalAddrContextKey).(*net.TCPAddr)
	n, err := strconv.ParseUint(port, 10, 16)
	if !ok || err != nil || uint64(local.Port) != n {
		return false
	}
	ip, _ := netip.ParseAddr(host)
	ip = ip.Unmap()
	localIP := local.AddrPort().Addr().Unmap()
	if ip.IsValid() && ip == localIP {
		return true
	}
	var boundIP netip.Addr
	if s, ok := ctx.Value(http.ServerContextKey).(*http.Server); ok && s.Addr != "" {
		bound, _ := netip.ParseAddrPort(s.Addr)
		boundIP = bound.Addr().Unmap()
		if ip.IsValid() && ip == boundIP {
			return true
		}
	}
	return (localIP.IsLoopback() || boundIP.IsUnspecified()) && (ip.IsLoopback() || strings.EqualFold(host, "localhost"))
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }
func (c *bufferedConn) Unwrap() net.Conn           { return c.Conn }

type connWithMeta struct {
	net.Conn
	meta ConnMeta
}

func (c *connWithMeta) Unwrap() net.Conn { return c.Conn }

type front struct {
	net.Listener
	accepted  chan *connWithMeta
	stopped   chan struct{}
	closeOnce sync.Once
	acceptErr error
	off       bool
	minter    *tlsmitm.Minter
	mu        sync.Mutex
	routing   map[net.Conn]struct{}
	workers   sync.WaitGroup
	closing   bool
}

func (p *Proxy) Serve(listener net.Listener) error {
	p.mu.Lock()
	if p.closed || p.server != nil {
		p.mu.Unlock()
		_ = listener.Close()
		return errors.New("proxy already served or closed")
	}
	f := &front{Listener: listener, accepted: make(chan *connWithMeta), stopped: make(chan struct{}), off: p.options.H2TapOff, routing: make(map[net.Conn]struct{})}
	if p.options.CA != nil {
		f.minter = tlsmitm.NewMinter(p.options.CA, 0, 0)
	}
	protocols := H2CProtocols()
	protocols.SetHTTP1(true)
	s := &http.Server{
		Addr:              listener.Addr().String(),
		Handler:           p,
		Protocols:         protocols,
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, c.(*connWithMeta).meta)
		},
	}
	p.server, p.front = s, f
	p.mu.Unlock()
	go f.accept()
	return s.Serve(f)
}

func (f *front) accept() {
	slots := make(chan struct{}, 128)
	for {
		select {
		case <-f.stopped:
			return
		case slots <- struct{}{}:
		}
		c, err := f.Listener.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Temporary() {
				time.Sleep(5 * time.Millisecond)
				<-slots
				continue
			}
			f.closeOnce.Do(func() {
				f.acceptErr = err
				close(f.stopped)
				_ = f.Listener.Close()
			})
			return
		}
		f.mu.Lock()
		if f.closing {
			f.mu.Unlock()
			_ = c.Close()
			<-slots
			return
		}
		f.routing[c] = struct{}{}
		f.workers.Add(1)
		f.mu.Unlock()
		go func() {
			defer f.workers.Done()
			defer func() { f.mu.Lock(); delete(f.routing, c); f.mu.Unlock() }()
			defer func() { <-slots }()
			f.route(c, ConnMeta{})
		}()
	}
}

func (f *front) Accept() (net.Conn, error) {
	select {
	case c := <-f.accepted:
		return c, nil
	case <-f.stopped:
		return nil, f.acceptErr
	}
}

func (f *front) Close() error {
	var err error
	f.mu.Lock()
	f.closing = true
	for c := range f.routing {
		_ = c.Close()
	}
	f.mu.Unlock()
	f.closeOnce.Do(func() {
		f.acceptErr = net.ErrClosed
		close(f.stopped)
		err = f.Listener.Close()
	})
	f.workers.Wait()
	return err
}

func (f *front) route(c net.Conn, meta ConnMeta) {
	h2 := meta.ALPN == "h2"
	if meta.ALPN == "" && meta.tls == nil && !f.off {
		br := bufio.NewReader(c)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if start, _ := br.Peek(3); string(start) == "PRI" {
			if start, _ := br.Peek(len(h2tap.Preface)); string(start) == h2tap.Preface {
				h2 = true
			}
		}
		_ = c.SetReadDeadline(time.Time{})
		c = &bufferedConn{Conn: c, r: br}
	}
	if h2 && !f.off {
		meta.Tap = h2tap.New(c)
		c = meta.Tap
	}
	select {
	case f.accepted <- &connWithMeta{Conn: c, meta: meta}:
	case <-f.stopped:
		_ = c.Close()
	}
}
