package fault

import (
	"fmt"
	"hash/fnv"
	"math"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
)

type Config struct {
	Seed  uint64 `json:"seed" yaml:"seed"`
	Rules []Rule `json:"rules" yaml:"rules"`
}
type Rule struct {
	ID      string `json:"id" yaml:"id"`
	Enabled bool   `json:"enabled" yaml:"enabled"`
	Match   Match  `json:"match" yaml:"match"`
	Fault   Fault  `json:"fault" yaml:"fault"`
}
type Match struct {
	Method      string   `json:"method,omitempty" yaml:"method,omitempty"`
	PathPrefix  string   `json:"path_prefix,omitempty" yaml:"path_prefix,omitempty"`
	Seq         []uint64 `json:"seq,omitempty" yaml:"seq,omitempty"`
	Probability *int     `json:"probability,omitempty" yaml:"probability,omitempty"`
	Host        string   `json:"host,omitempty" yaml:"host,omitempty"`
	Scheme      string   `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	Proto       string   `json:"proto,omitempty" yaml:"proto,omitempty"`
}
type Fault struct {
	Type   string         `json:"type" yaml:"type"`
	Params map[string]any `json:"params,omitempty" yaml:"params,omitempty"`
}

func Int(p map[string]any, k string, def int) int {
	switch v := p[k].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case uint64:
		return int(v)
	case float64:
		return int(v)
	case float32:
		return int(v)
	default:
		return def
	}
}
func String(p map[string]any, k, def string) string {
	if v, ok := p[k].(string); ok {
		return v
	}
	return def
}
func Bool(p map[string]any, k string, def bool) bool {
	if v, ok := p[k].(bool); ok {
		return v
	}
	return def
}

func Validate(c Config) error {
	ids := make(map[string]struct{}, len(c.Rules))
	for _, r := range c.Rules {
		if _, exists := ids[r.ID]; r.ID == "" || exists {
			return &ValidationError{"invalid_rule", r.ID, "", fmt.Sprintf("missing or duplicate rule id %q", r.ID)}
		}
		ids[r.ID] = struct{}{}
		if r.Match.Proto != "" && r.Match.Proto != "h1" && r.Match.Proto != "h2" {
			return invalidRule(r.ID, "proto", "invalid protocol")
		}
		if r.Match.Scheme != "" && r.Match.Scheme != "http" && r.Match.Scheme != "https" {
			return invalidRule(r.ID, "scheme", "invalid scheme")
		}
		if p := r.Match.Probability; p != nil && (*p < 0 || *p > 100) {
			return invalidRule(r.ID, "probability", "invalid probability")
		}
		for _, seq := range r.Match.Seq {
			if seq == 0 {
				return invalidRule(r.ID, "seq", "sequence starts at 1")
			}
		}
		var schema map[string]paramRange
		switch r.Fault.Type {
		case "tcp-rst":
			schema = rstParams
		case "dup-webhook":
			schema = replayParams
		case "rate-limit":
			schema = limitParams
		case "byte-trickle":
			schema = trickleParams
		case "latency-wave":
			schema = latencyParams
			switch String(r.Fault.Params, "shape", "sine") {
			case "sine", "spike", "jitter":
			default:
				return invalidRule(r.ID, "shape", "invalid latency shape")
			}
		case "ws-glitch":
			schema = wsParams
			switch String(r.Fault.Params, "dir", "both") {
			case "both", "c2s", "s2c":
			default:
				return invalidRule(r.ID, "dir", "invalid WebSocket direction")
			}
			switch String(r.Fault.Params, "action", "drop") {
			case "drop", "delay", "corrupt", "truncate", "close_1006":
			default:
				return invalidRule(r.ID, "action", "invalid WebSocket action")
			}
		case "sse-glitch", "h2-glitch", "grpc-glitch":
			if err := validateV2(r); err != nil {
				return err
			}
			continue
		default:
			return &ValidationError{"unknown_type", r.ID, "", fmt.Sprintf("unknown fault %q", r.Fault.Type)}
		}
		for k, v := range r.Fault.Params {
			spec, ok := schema[k]
			if !ok || !spec.valid(v) {
				return invalidParam(r.ID, k)
			}
		}
	}
	return nil
}

type paramRange struct {
	min, max int
	kind     byte
}

func (p paramRange) valid(v any) bool {
	switch p.kind {
	case 's':
		_, ok := v.(string)
		return ok
	case 'b':
		_, ok := v.(bool)
		return ok
	}
	var n float64
	switch v := v.(type) {
	case int:
		n = float64(v)
	case int64:
		n = float64(v)
	case uint64:
		n = float64(v)
	case float64:
		n = v
	case float32:
		n = float64(v)
	default:
		return false
	}
	return n >= float64(p.min) && n <= float64(p.max) && n == math.Trunc(n)
}

const maxValue = 1 << 30

var (
	rstParams     = map[string]paramRange{"after_bytes": {max: maxValue}, "before_headers": {kind: 'b'}}
	replayParams  = map[string]paramRange{"count": {min: 1, max: 100}, "delay_ms": {max: maxValue}, "replay_header": {kind: 'b'}}
	limitParams   = map[string]paramRange{"status": {min: 200, max: 599}, "retry_after_sec": {max: maxValue}, "body": {kind: 's'}}
	trickleParams = map[string]paramRange{"bytes_per_sec": {min: 1, max: maxValue}, "chunk_bytes": {min: 1, max: 64 << 10}, "stall_after_bytes": {max: maxValue}, "stall_ms": {max: maxValue}}
	latencyParams = map[string]paramRange{"shape": {kind: 's'}, "base_ms": {max: maxValue / 2}, "amp_ms": {max: maxValue / 2}, "period_seq": {min: 1, max: maxValue}, "every": {min: 1, max: maxValue}}
	wsParams      = map[string]paramRange{"dir": {kind: 's'}, "action": {kind: 's'}, "delay_ms": {max: maxValue}, "after_frames": {max: maxValue}, "every": {min: 1, max: maxValue}, "truncate_bytes": {max: maxValue}}
)

type Query struct {
	Method, Path, Host, Scheme, Proto, ContentType string
	Seq                                            uint64
	WS                                             bool
}

func MatchRule(c Config, method, path string, seq uint64, ws bool) *Rule {
	return MatchRequest(c, Query{Method: method, Path: path, Seq: seq, WS: ws, Proto: "h1"})
}
func MatchRequest(c Config, q Query) *Rule {
	for i := range c.Rules {
		r := &c.Rules[i]
		if !r.Enabled || (r.Fault.Type == "ws-glitch") != q.WS || (r.Match.Method != "" && !strings.EqualFold(r.Match.Method, q.Method)) || !strings.HasPrefix(q.Path, r.Match.PathPrefix) {
			continue
		}
		if r.Fault.Type == "h2-glitch" && q.Proto != "h2" || r.Fault.Type == "grpc-glitch" && (q.Proto != "h2" || !strings.HasPrefix(strings.ToLower(q.ContentType), "application/grpc")) {
			continue
		}
		if r.Match.Proto != "" && r.Match.Proto != q.Proto || r.Match.Scheme != "" && r.Match.Scheme != q.Scheme {
			continue
		}
		host := q.Host
		if !strings.Contains(r.Match.Host, ":") {
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
		}
		if r.Match.Host != "" && !strings.EqualFold(r.Match.Host, host) && !(strings.HasPrefix(r.Match.Host, "*.") && strings.HasSuffix(strings.ToLower(host), strings.ToLower(r.Match.Host[1:]))) {
			continue
		}
		if len(r.Match.Seq) > 0 {
			found := false
			for _, n := range r.Match.Seq {
				if n == q.Seq {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if r.Match.Probability != nil && rand.New(rand.NewPCG(c.Seed, q.Seq)).IntN(100) >= *r.Match.Probability {
			continue
		}
		return r
	}
	return nil
}
func RuleHash(id string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(id))
	return h.Sum64()
}

func Pick(seed uint64, id string, seq, idx uint64, pct int) bool {
	return rand.New(rand.NewPCG(seed^RuleHash(id), seq<<32|idx)).IntN(100) < pct
}
func H2Code(v any) (uint32, error) {
	names := []string{"NO_ERROR", "PROTOCOL_ERROR", "INTERNAL_ERROR", "FLOW_CONTROL_ERROR", "SETTINGS_TIMEOUT", "STREAM_CLOSED", "FRAME_SIZE_ERROR", "REFUSED_STREAM", "CANCEL", "COMPRESSION_ERROR", "CONNECT_ERROR", "ENHANCE_YOUR_CALM", "INADEQUATE_SECURITY", "HTTP_1_1_REQUIRED"}
	if s, ok := v.(string); ok {
		for i, n := range names {
			if s == n {
				return uint32(i), nil
			}
		}
		x, e := strconv.Atoi(s)
		if e == nil && x >= 0 && x < len(names) {
			return uint32(x), nil
		}
	} else {
		n := Int(map[string]any{"v": v}, "v", -1)
		if n >= 0 && n < len(names) {
			return uint32(n), nil
		}
	}
	return 0, fmt.Errorf("invalid h2 code")
}
func GRPCCode(v any) (int, error) {
	names := []string{"OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED", "NOT_FOUND", "ALREADY_EXISTS", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION", "ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED", "INTERNAL", "UNAVAILABLE", "DATA_LOSS", "UNAUTHENTICATED"}
	if s, ok := v.(string); ok {
		for i, n := range names {
			if s == n {
				return i, nil
			}
		}
		n, e := strconv.Atoi(s)
		if e == nil && n >= 0 && n <= 16 {
			return n, nil
		}
	} else {
		n := Int(map[string]any{"v": v}, "v", -1)
		if n >= 0 && n <= 16 {
			return n, nil
		}
	}
	return 0, fmt.Errorf("invalid grpc code")
}
func Latency(seed, seq uint64, p map[string]any) int {
	base, amp := Int(p, "base_ms", 0), Int(p, "amp_ms", 0)
	switch String(p, "shape", "sine") {
	case "spike":
		if seq%uint64(Int(p, "every", 4)) == 0 {
			return base + amp
		}
		return base
	case "jitter":
		return base + rand.New(rand.NewPCG(seed, seq)).IntN(amp+1)
	default:
		return base + int(float64(amp)*(0.5+0.5*math.Sin(2*math.Pi*float64(seq)/float64(Int(p, "period_seq", 10)))))
	}
}
