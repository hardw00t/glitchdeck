package proxy

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"unicode"
)

// DiagnosticHostname extracts a bounded hostname without URL credentials, paths or ports.
func DiagnosticHostname(authority string) string {
	if len(authority) > 260 {
		return ""
	}
	authority = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, authority)
	if net.ParseIP(authority) != nil {
		return strings.ToLower(authority)
	}
	u, err := url.Parse("//" + authority)
	if err != nil {
		return ""
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if len(host) > 253 {
		return ""
	}
	if net.ParseIP(host) == nil {
		for _, r := range host {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsMark(r) && r != '-' && r != '.' && r != '_' {
				return ""
			}
		}
	}
	return host
}

func (p *Proxy) deniedHost(authority string) string {
	host := DiagnosticHostname(authority)
	if token := strings.ToLower(p.options.ProxyAuth); token != "" && strings.Contains(host, token) {
		return ""
	}
	return host
}

func (p *Proxy) countEgressDenial(connect bool) {
	if connect {
		p.connectEgressDenied.Add(1)
	} else {
		p.innerEgressDenied.Add(1)
	}
}

func (p *Proxy) publishDeniedHost(host string) {
	if host != "" && p.options.OnEgressDenied != nil {
		p.options.OnEgressDenied(host)
	}
}

func (p *Proxy) noteEgressDenial(authority string, connect bool) string {
	p.countEgressDenial(connect)
	host := p.deniedHost(authority)
	p.publishDeniedHost(host)
	return host
}

type transportDialError struct{ error }

func (e *transportDialError) Unwrap() error { return e.error }

func (p *Proxy) noteRoundTripDial(client context.Context, gen uint64, authority string, reverse bool, err error) (failure, host string) {
	if err == nil {
		return "", ""
	}
	var dial *transportDialError
	if !errors.As(err, &dial) {
		return "", ""
	}
	return p.noteDialResult(client, gen, authority, reverse, false, dial.error)
}

// Only the handler or replay worker consumes a terminal dial result. Transport
// dials may outlive a canceled request; they never write counters themselves.
func (p *Proxy) noteDialResult(client context.Context, gen uint64, authority string, reverse, connect bool, err error) (failure, host string) {
	if err == nil {
		return "", ""
	}
	p.mu.Lock()
	if gen != p.generation || p.ctx.Err() != nil || client.Err() != nil || errors.Is(err, context.Canceled) {
		p.mu.Unlock()
		return "client_cancel", ""
	}
	if errors.Is(err, errEgressDenied) {
		p.countEgressDenial(connect)
		p.mu.Unlock()
		host = p.deniedHost(authority)
		p.publishDeniedHost(host)
		return "egress_denied", host
	}
	p.dialFailed.Add(1)
	if reverse {
		p.reverseDialFailed.Add(1)
	}
	p.mu.Unlock()
	return "dial_failed", ""
}
