package proxy

import (
	"context"
	"errors"
	"net"
	"net/url"
	"sort"
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

// Retention and its corresponding counter are updated under p.mu.
func (p *Proxy) retainDeniedHost(host string) {
	const limit = 10
	i := sort.SearchStrings(p.deniedHosts, host)
	if host == "" || i == limit || i < len(p.deniedHosts) && p.deniedHosts[i] == host {
		return
	}
	if len(p.deniedHosts) < limit {
		p.deniedHosts = append(p.deniedHosts, "")
	}
	copy(p.deniedHosts[i+1:], p.deniedHosts[i:])
	p.deniedHosts[i] = strings.Clone(host)
}

type deniedReplay struct {
	index, committedStatus int
	mode, originalOutcome  string
}

func (p *Proxy) publishDeniedRequest(gen, seq uint64, status int, host string, replay *deniedReplay, in, out int64) {
	event := map[string]any{"seq": seq, "status": status, "error": "egress_denied", "req_bytes": in, "resp_bytes": out}
	if host != "" {
		event["host"] = host
	}
	if replay != nil {
		event["replay_index"], event["outcome"] = replay.index, "egress_denied"
		switch replay.mode {
		case "sequential", "concurrent", "timeout_retry":
			event["replay_mode"] = replay.mode
		}
		if replay.mode == "timeout_retry" {
			event["committed_status"] = replay.committedStatus
			switch replay.originalOutcome {
			case "", "timeout", "transport_error":
				event["original_outcome"] = replay.originalOutcome
			}
		}
	}
	p.publish(gen, "http_req", event)
}

func (p *Proxy) publishDeniedGRPC(gen, seq uint64, status int, code *int, host string, in, out int) {
	event := map[string]any{"seq": seq, "http_status": status, "grpc_status": code, "error": "egress_denied", "req_messages": in, "resp_messages": out}
	if host != "" {
		event["host"] = host
	}
	p.publish(gen, "grpc_call", event)
}

func (p *Proxy) noteReplayAdmissionDenial(gen uint64, authority string, count int) string {
	host := p.deniedHost(authority)
	p.mu.Lock()
	defer p.mu.Unlock()
	if gen == p.generation && count > 0 {
		p.replayDenied += int64(count)
		p.retainDeniedHost(host)
	}
	return host
}

func (p *Proxy) noteEgressDenial(authority string, connect bool) string {
	host := p.deniedHost(authority)
	p.mu.Lock()
	p.countEgressDenial(connect)
	p.retainDeniedHost(host)
	p.mu.Unlock()
	return host
}

type transportDialError struct{ error }

func (e *transportDialError) Unwrap() error { return e.error }

func (p *Proxy) noteRoundTripDial(client context.Context, gen uint64, authority string, reverse bool, err error) {
	if err == nil {
		return
	}
	var dial *transportDialError
	if !errors.As(err, &dial) {
		return
	}
	p.noteDialResult(client, gen, authority, reverse, false, dial.error)
}

// dial_failed counts only request- or replay-visible failures. Background
// attempts abandoned by the transport never write counters themselves.
func (p *Proxy) noteDialResult(client context.Context, gen uint64, authority string, reverse, connect bool, err error) string {
	if err == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if gen != p.generation || p.ctx.Err() != nil || client.Err() != nil || errors.Is(err, context.Canceled) {
		return "client_cancel"
	}
	if errors.Is(err, errEgressDenied) {
		p.countEgressDenial(connect)
		p.retainDeniedHost(p.deniedHost(authority))
		return "egress_denied"
	}
	p.dialFailed.Add(1)
	if reverse {
		p.reverseDialFailed.Add(1)
	}
	return "dial_failed"
}
