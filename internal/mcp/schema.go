package mcp

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
)

type schema = map[string]any

func scalar(t string) schema                { return schema{"type": t} }
func bounded(t string, min, max int) schema { return schema{"type": t, "minimum": min, "maximum": max} }
func choice(values ...string) schema        { return schema{"type": "string", "enum": values} }
func object(properties schema, required ...string) schema {
	s := schema{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}
func array(items schema) schema { return schema{"type": "array", "items": items} }
func tools() []map[string]any {
	str := scalar("string")
	boolean := scalar("boolean")
	uint := schema{"type": "integer", "minimum": 0}
	match := object(schema{"method": str, "path_prefix": str, "seq": array(schema{"type": "integer", "minimum": 1}), "probability": bounded("integer", 0, 100), "host": str, "scheme": str, "proto": str})
	rule := object(schema{"id": schema{"type": "string", "minLength": 1}, "enabled": boolean, "match": match, "fault": object(schema{"type": choice("tcp-rst", "dup-webhook", "rate-limit", "byte-trickle", "latency-wave", "ws-glitch", "sse-glitch", "h2-glitch", "grpc-glitch"), "params": schema{"type": "object"}}, "type")}, "id", "enabled", "fault")
	rules := array(rule)
	rules["minItems"] = 1
	rules["maxItems"] = 64
	specs := []struct {
		name, desc string
		s          schema
	}{
		{"proxy_start", "Start a loopback proxy", object(schema{"target": str, "listen": str, "seed": uint, "tape_path": str, "record": boolean}, "target")},
		{"proxy_stop", "Stop the active proxy", object(schema{})},
		{"fault_set", "Set fault rules", object(schema{"mode": choice("upsert", "replace"), "seed": uint, "rules": rules}, "rules")},
		{"fault_clear", "Clear fault rules", object(schema{"rule_ids": array(str), "reset_bus": boolean})},
		{"wire_events", "Read bounded wire events", object(schema{"since_id": uint, "limit": bounded("integer", 1, 100), "type": choice("all", "http_req", "ws_frame", "sse_event", "grpc_call"), "faulted_only": boolean})},
		{"tape_run", "Run a tape", object(schema{"tape_path": str, "tape_yaml": schema{"type": "string", "maxLength": 1048576}, "target": str, "timeout_ms": bounded("integer", 100, 120000)})},
		{"tape_export", "Export recorded traffic", object(schema{"name": schema{"type": "string", "minLength": 1}, "out_path": str}, "name")},
		{"demo_trigger", "Drive the demo", object(schema{"action": choice("checkout", "webhook", "ticker", "state", "reset"), "order_id": str, "amount_cents": uint, "frames": bounded("integer", 1, 50)}, "action")},
	}
	out := make([]map[string]any, 0, len(specs))
	for _, v := range specs {
		out = append(out, map[string]any{"name": v.name, "description": v.desc, "inputSchema": v.s})
	}
	return out
}
func validArgs(name string, args map[string]json.RawMessage) bool {
	for _, tool := range tools() {
		if tool["name"] == name {
			b, e := json.Marshal(args)
			if e != nil {
				return false
			}
			var v any
			d := json.NewDecoder(bytes.NewReader(b))
			d.UseNumber()
			if d.Decode(&v) != nil {
				return false
			}
			return validateSchema(tool["inputSchema"].(schema), v)
		}
	}
	return false
}
func validateSchema(s schema, v any) bool {
	switch s["type"] {
	case "object":
		m, ok := v.(map[string]any)
		if !ok {
			return false
		}
		props, _ := s["properties"].(schema)
		if required, ok := s["required"].([]string); ok {
			for _, k := range required {
				if _, ok := m[k]; !ok {
					return false
				}
			}
		}
		for k, val := range m {
			p, ok := props[k]
			if !ok {
				if s["additionalProperties"] == false {
					return false
				}
				continue
			}
			if !validateSchema(p.(schema), val) {
				return false
			}
		}
		return true
	case "array":
		a, ok := v.([]any)
		if !ok {
			return false
		}
		if n, ok := s["minItems"].(int); ok && len(a) < n {
			return false
		}
		if n, ok := s["maxItems"].(int); ok && len(a) > n {
			return false
		}
		for _, x := range a {
			if !validateSchema(s["items"].(schema), x) {
				return false
			}
		}
		return true
	case "string":
		x, ok := v.(string)
		if !ok {
			return false
		}
		if n, ok := s["minLength"].(int); ok && len(x) < n {
			return false
		}
		if n, ok := s["maxLength"].(int); ok && len(x) > n {
			return false
		}
		if choices, ok := s["enum"].([]string); ok {
			for _, c := range choices {
				if x == c {
					return true
				}
			}
			return false
		}
		return true
	case "integer":
		n, ok := v.(json.Number)
		if !ok || strings.ContainsAny(n.String(), ".eE") {
			return false
		}
		f, e := n.Float64()
		if e != nil || math.IsInf(f, 0) {
			return false
		}
		if min, ok := s["minimum"].(int); ok && f < float64(min) {
			return false
		}
		if max, ok := s["maximum"].(int); ok && f > float64(max) {
			return false
		}
		return true
	case "boolean":
		_, ok := v.(bool)
		return ok
	}
	return false
}
