package fault

import (
	"fmt"
	"math"
	"math/rand/v2"
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
			return fmt.Errorf("missing or duplicate rule id %q", r.ID)
		}
		ids[r.ID] = struct{}{}
		if p := r.Match.Probability; p != nil && (*p < 0 || *p > 100) {
			return fmt.Errorf("rule %q: invalid probability", r.ID)
		}
		for _, seq := range r.Match.Seq {
			if seq == 0 {
				return fmt.Errorf("rule %q: sequence starts at 1", r.ID)
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
				return fmt.Errorf("rule %q: invalid latency shape", r.ID)
			}
		case "ws-glitch":
			schema = wsParams
			switch String(r.Fault.Params, "dir", "both") {
			case "both", "c2s", "s2c":
			default:
				return fmt.Errorf("rule %q: invalid WebSocket direction", r.ID)
			}
			switch String(r.Fault.Params, "action", "drop") {
			case "drop", "delay", "corrupt", "truncate", "close_1006":
			default:
				return fmt.Errorf("rule %q: invalid WebSocket action", r.ID)
			}
		default:
			return fmt.Errorf("unknown fault %q", r.Fault.Type)
		}
		for k, v := range r.Fault.Params {
			spec, ok := schema[k]
			if !ok || !spec.valid(v) {
				return fmt.Errorf("rule %q: invalid parameter %q", r.ID, k)
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

func MatchRule(c Config, method, path string, seq uint64, ws bool) *Rule {
	for i := range c.Rules {
		r := &c.Rules[i]
		if !r.Enabled || (r.Fault.Type == "ws-glitch") != ws || (r.Match.Method != "" && !strings.EqualFold(r.Match.Method, method)) || !strings.HasPrefix(path, r.Match.PathPrefix) {
			continue
		}
		if len(r.Match.Seq) > 0 {
			found := false
			for _, n := range r.Match.Seq {
				if n == seq {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if r.Match.Probability != nil && rand.New(rand.NewPCG(c.Seed, seq)).IntN(100) >= *r.Match.Probability {
			continue
		}
		return r
	}
	return nil
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
