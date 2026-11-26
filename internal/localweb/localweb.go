package localweb

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Allowed admits local hosts (or an explicitly configured listener host) and
// rejects cross-origin browser writes and upgrades. Native clients need no Origin.
func Allowed(r *http.Request, bind string) bool {
	host := hostname(r.Host)
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); !strings.EqualFold(host, "localhost") && !ip.IsLoopback() {
		bound := hostname(bind)
		if bound == "" || net.ParseIP(bound).IsUnspecified() || !strings.EqualFold(host, bound) {
			return false
		}
	}
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.Header.Get("Upgrade") == "" {
		return true
	}
	origins := r.Header.Values("Origin")
	if len(origins) == 0 {
		return true
	}
	if len(origins) != 1 {
		return false
	}
	u, err := url.Parse(origins[0])
	return err == nil && u.Scheme == "http" && u.User == nil && u.Path == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && strings.EqualFold(u.Host, r.Host)
}

func hostname(addr string) string {
	if host, port, err := net.SplitHostPort(addr); err == nil {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return ""
		}
		addr = host
	} else if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		addr = addr[1 : len(addr)-1]
	}
	if net.ParseIP(addr) != nil {
		return addr
	}
	for _, ch := range addr {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '.' || ch == '-') {
			return ""
		}
	}
	return addr
}
