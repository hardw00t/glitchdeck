package proxy

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type replayListenerOriginKey struct{}

// WithReplayListenerOrigin marks a request received directly by a replay target listener.
func WithReplayListenerOrigin(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), replayListenerOriginKey{}, true))
}

func filterReplayLocation(r *http.Request, header http.Header) {
	locations := header.Values("Location")
	header.Del("Location")
	local, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
	if len(locations) != 1 || !ok || local.IP.IsUnspecified() {
		return
	}
	raw := locations[0]
	if strings.ContainsAny(raw, "\\\r\n\t") || strings.TrimSpace(raw) != raw {
		return
	}
	dest, err := url.Parse(raw)
	if err != nil || raw == "" || dest.User != nil || dest.Opaque != "" || strings.HasPrefix(raw, "///") {
		return
	}
	direct := r.Context().Value(replayListenerOriginKey{}) == true
	scheme := "http"
	if direct && r.TLS != nil {
		scheme = "https"
	}
	if !dest.IsAbs() {
		if !direct && (r.URL.IsAbs() || r.TLS != nil) {
			return
		}
		base := *r.URL
		base.Scheme, base.Host = scheme, local.String()
		dest = base.ResolveReference(dest)
	}
	if dest.Scheme != scheme || !local.IP.Equal(net.ParseIP(dest.Hostname())) || upstreamPort(dest.Scheme, dest.Port()) != strconv.Itoa(local.Port) {
		return
	}
	// Advertise the checked numeric listener, not the original authority or reference.
	dest.Host = local.String()
	header.Set("Location", dest.String())
}
