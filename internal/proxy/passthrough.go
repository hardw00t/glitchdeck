package proxy

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

func passthroughParts(pattern string) (string, string, error) {
	s := strings.TrimSpace(pattern)
	if s == "" {
		return "", "", fmt.Errorf("empty pattern")
	}
	if strings.ContainsAny(s, "/?#@") {
		return "", "", fmt.Errorf("host must not contain scheme, path, query, userinfo or CIDR")
	}
	host, port := s, ""
	if strings.HasPrefix(s, "[") {
		if strings.HasSuffix(s, "]") {
			host = s[1 : len(s)-1]
		} else {
			var err error
			host, port, err = net.SplitHostPort(s)
			if err != nil {
				return "", "", fmt.Errorf("invalid bracketed IPv6")
			}
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return "", "", fmt.Errorf("invalid bracketed IPv6")
		}
	} else if ip, err := netip.ParseAddr(s); err == nil && ip.Is6() && ip.Zone() == "" {
		host = s
	} else if strings.Contains(s, ":") {
		var err error
		host, port, err = net.SplitHostPort(s)
		if err != nil {
			return "", "", fmt.Errorf("invalid host or port")
		}
	}
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return "", "", fmt.Errorf("port must be between 1 and 65535")
		}
		port = strings.TrimLeft(port, "0")
	} else if strings.HasSuffix(s, ":") {
		return "", "", fmt.Errorf("port must be between 1 and 65535")
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || host == "any" || host == "*" {
		return "", "", fmt.Errorf("invalid host")
	}
	if strings.Contains(host, "*") {
		if !strings.HasPrefix(host, "*.") || strings.Contains(host[2:], "*") {
			return "", "", fmt.Errorf("wildcard must be leading \"*.\" label")
		}
		if !strings.Contains(host[2:], ".") {
			return "", "", fmt.Errorf("wildcard requires at least two host labels")
		}
		if _, err := netip.ParseAddr(host[2:]); err == nil {
			return "", "", fmt.Errorf("wildcard cannot match an IP literal")
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() == "" {
		return ip.String(), port, nil
	}
	if len(host) > 253 {
		return "", "", fmt.Errorf("host exceeds 253 characters")
	}
	name := strings.TrimPrefix(host, "*.")
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", "", fmt.Errorf("invalid host label length")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", "", fmt.Errorf("invalid host label")
			}
		}
	}
	return host, port, nil
}

// ValidatePassthrough validates a CONNECT passthrough pattern.
func ValidatePassthrough(pattern string) error {
	_, _, err := passthroughParts(pattern)
	return err
}

func (p *Proxy) passthrough(host, port string) (string, bool) {
	return MatchPassthrough(p.options.TLSPassthrough, host, port)
}

// MatchPassthrough matches a CONNECT authority against passthrough patterns.
func MatchPassthrough(patterns []string, host, port string) (string, bool) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	ip, ipErr := netip.ParseAddr(host)
	if ipErr == nil {
		host = ip.String()
	}
	port = strings.TrimLeft(port, "0")
	for _, raw := range patterns {
		pattern, matchPort, err := passthroughParts(raw)
		if err != nil || matchPort != "" && matchPort != port {
			continue
		}
		if host == pattern || ipErr != nil && strings.HasPrefix(pattern, "*.") && len(host) > len(pattern)-1 && strings.HasSuffix(host, pattern[1:]) {
			return strings.TrimSpace(raw), true
		}
	}
	return "", false
}
