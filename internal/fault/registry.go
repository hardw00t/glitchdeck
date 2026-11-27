package fault

import (
	"fmt"
	"slices"
	"strings"
)

type ParamKind string

type ParamSpec struct {
	Kind            ParamKind           `json:"kind"`
	Min             int                 `json:"min,omitempty"`
	Max             int                 `json:"max,omitempty"`
	Default         any                 `json:"default,omitempty"`
	DefaultByAction map[string]any      `json:"default_by_action,omitempty"`
	Enum            []string            `json:"enum,omitempty"`
	EnumByAction    map[string][]string `json:"enum_by_action,omitempty"`
	Actions         []string            `json:"actions,omitempty"`
}

type TypeSpec struct {
	Actions []string             `json:"actions,omitempty"`
	Params  map[string]ParamSpec `json:"params"`
	Proto   string               `json:"proto"`
}

type ValidationError struct {
	Code, RuleID, Param string
	Message             string
}

func (e *ValidationError) Error() string { return e.Message }

func invalidRule(id, param, message string) error {
	code := "invalid_rule"
	if param != "" {
		code = "invalid_param"
	}
	return &ValidationError{code, id, param, fmt.Sprintf("rule %q: %s", id, message)}
}

func invalidParam(id, param string) error {
	return invalidRule(id, param, fmt.Sprintf("invalid parameter %q", param))
}

var Registry = map[string]TypeSpec{
	"sse-glitch": {
		Proto: "sse", Actions: []string{"stall", "drop", "truncate", "corrupt_json", "eof_early", "inject_error", "corrupt_tool_args"},
		Params: map[string]ParamSpec{
			"action":          {Kind: "string", Default: "stall", Enum: []string{"stall", "drop", "truncate", "corrupt_json", "eof_early", "inject_error", "corrupt_tool_args"}},
			"after_events":    {Kind: "int", Max: 1000000, Default: 1, Actions: []string{"stall", "truncate", "eof_early", "inject_error"}},
			"every":           {Kind: "int", Min: 1, Max: 1000000, Actions: []string{"stall", "drop", "corrupt_json"}},
			"stall_ms":        {Kind: "int", Max: 600000, Default: 30000, Actions: []string{"stall"}},
			"forever":         {Kind: "bool", Default: false, Actions: []string{"stall"}},
			"events":          {Kind: "int_list", Min: 1, Max: 1000000, Actions: []string{"drop", "corrupt_json"}},
			"probability":     {Kind: "int", Max: 100, Actions: []string{"drop", "corrupt_json"}},
			"event_type":      {Kind: "string", Actions: []string{"stall", "drop", "corrupt_json"}},
			"cut_bytes":       {Kind: "int", Min: 1, Max: 1 << 20, Actions: []string{"truncate"}},
			"rst":             {Kind: "bool", Default: true, Actions: []string{"truncate"}},
			"mode":            {Kind: "string", DefaultByAction: map[string]any{"corrupt_json": "cut", "corrupt_tool_args": "truncate"}, EnumByAction: map[string][]string{"corrupt_json": {"cut", "brace", "quote"}, "corrupt_tool_args": {"truncate", "invalid", "drop"}}, Actions: []string{"corrupt_json", "corrupt_tool_args"}},
			"before_event":    {Kind: "string", Actions: []string{"eof_early"}},
			"http_clean":      {Kind: "bool", Default: true, Actions: []string{"eof_early"}},
			"done_events":     {Kind: "string_list"},
			"provider":        {Kind: "string", Enum: []string{"auto", "openai", "openai_responses", "anthropic", "gemini", "raw"}, Actions: []string{"inject_error"}},
			"error_type":      {Kind: "string", Min: 1, Max: 64, Actions: []string{"inject_error"}},
			"message":         {Kind: "string", Max: 512, Actions: []string{"inject_error"}},
			"close":           {Kind: "string", Enum: []string{"clean", "rst"}, Actions: []string{"inject_error"}},
			"data":            {Kind: "string", Max: 64 << 10, Actions: []string{"inject_error"}},
			"event":           {Kind: "string", Actions: []string{"inject_error"}},
			"after_fragments": {Kind: "int", Min: 1, Max: 1000000, Actions: []string{"corrupt_tool_args"}},
			"then":            {Kind: "string", Enum: []string{"continue", "eof", "rst"}, Actions: []string{"corrupt_tool_args"}},
		},
	},
	"h2-glitch": {
		Proto: "h2", Actions: []string{"rst_stream", "goaway"},
		Params: map[string]ParamSpec{
			"action":         {Kind: "string", Default: "rst_stream", Enum: []string{"rst_stream", "goaway"}},
			"code":           {Kind: "h2_code"},
			"before_headers": {Kind: "bool", Default: true},
			"after_bytes":    {Kind: "int", Max: 1 << 30, Default: 0},
			"refuse_current": {Kind: "bool", Default: true, Actions: []string{"goaway"}},
			"close_after_ms": {Kind: "int", Max: 60000, Default: 100, Actions: []string{"goaway"}},
			"debug":          {Kind: "string", Max: 128, Actions: []string{"goaway"}},
		},
	},
	"grpc-glitch": {
		Proto: "grpc", Actions: []string{"status"},
		Params: map[string]ParamSpec{
			"action":         {Kind: "string", Default: "status", Enum: []string{"status"}},
			"code":           {Kind: "grpc_code", Default: "UNAVAILABLE"},
			"message":        {Kind: "string", Max: 1024},
			"after_messages": {Kind: "int", Max: 1000000, Default: 0},
			"delay_ms":       {Kind: "int", Max: 600000, Default: 0},
		},
	},
}

func init() {
	for name, params := range map[string]map[string]paramRange{
		"tcp-rst": rstParams, "dup-webhook": replayParams, "rate-limit": limitParams,
		"byte-trickle": trickleParams, "latency-wave": latencyParams, "ws-glitch": wsParams,
	} {
		p := make(map[string]ParamSpec, len(params))
		for k, v := range params {
			kind := ParamKind("int")
			switch v.kind {
			case 's':
				kind = "string"
			case 'b':
				kind = "bool"
			}
			p[k] = ParamSpec{Kind: kind, Min: v.min, Max: v.max}
		}
		spec := TypeSpec{Params: p, Proto: "any"}
		if name == "ws-glitch" {
			spec.Proto = "ws"
			spec.Actions = []string{"drop", "delay", "corrupt", "truncate", "close_1006"}
		}
		if name == "rate-limit" {
			provider := p["provider"]
			provider.Enum = []string{"none", "openai", "anthropic", "gemini"}
			p["provider"] = provider
		}
		Registry[name] = spec
	}
}

func validateV2(r Rule) error {
	s := Registry[r.Fault.Type]
	p := r.Fault.Params
	action := String(p, "action", s.Actions[0])
	if action == "early_eof" {
		action = "eof_early"
	}
	for k, v := range p {
		spec, ok := s.Params[k]
		if !ok || len(spec.Actions) != 0 && !slices.Contains(spec.Actions, action) || !spec.valid(v) && !(r.Fault.Type == "sse-glitch" && k == "action" && v == "early_eof") {
			return invalidParam(r.ID, k)
		}
		if options := spec.EnumByAction[action]; len(options) > 0 && !slices.Contains(options, String(p, k, "")) {
			return invalidParam(r.ID, k)
		}
	}
	if action := String(p, "action", s.Actions[0]); r.Fault.Type == "sse-glitch" && (action == "drop" || action == "corrupt_json") {
		if p["events"] == nil && p["every"] == nil && p["probability"] == nil {
			return invalidRule(r.ID, "events", "select events using events, every, or probability")
		}
	}
	if r.Fault.Type == "sse-glitch" && action == "inject_error" {
		provider := String(p, "provider", "auto")
		if provider == "raw" && p["data"] == nil || provider != "raw" && (p["data"] != nil || p["event"] != nil) {
			return invalidParam(r.ID, "data")
		}
		if strings.ContainsAny(String(p, "event", ""), "\r\n") {
			return invalidParam(r.ID, "event")
		}
		if value, ok := p["error_type"].(string); ok {
			for _, ch := range value {
				if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '.' || ch == '-') {
					return invalidParam(r.ID, "error_type")
				}
			}
		}
	}
	return nil
}

func (s ParamSpec) valid(v any) bool {
	inRange := paramRange{min: s.Min, max: s.Max}
	switch s.Kind {
	case "int":
		return inRange.valid(v)
	case "bool":
		_, ok := v.(bool)
		return ok
	case "string":
		text, ok := v.(string)
		return ok && len(text) >= s.Min && (s.Max == 0 || len(text) <= s.Max) && (len(s.Enum) == 0 || slices.Contains(s.Enum, text))
	case "h2_code":
		_, err := H2Code(v)
		return err == nil
	case "grpc_code":
		_, err := GRPCCode(v)
		return err == nil
	case "string_list":
		var entries []string
		switch values := v.(type) {
		case []string:
			entries = values
		case []any:
			for _, value := range values {
				text, ok := value.(string)
				if !ok {
					return false
				}
				entries = append(entries, text)
			}
		default:
			return false
		}
		if len(entries) < 1 || len(entries) > 16 {
			return false
		}
		for _, entry := range entries {
			if len(entry) < 1 || len(entry) > 128 {
				return false
			}
		}
		return true
	case "int_list":
		switch entries := v.(type) {
		case []int:
			for _, n := range entries {
				if n < s.Min || n > s.Max {
					return false
				}
			}
			return len(entries) > 0
		case []any:
			for _, n := range entries {
				if !inRange.valid(n) {
					return false
				}
			}
			return len(entries) > 0
		}
	}
	return false
}
