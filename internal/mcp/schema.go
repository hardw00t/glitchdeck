package mcp

import (
	"bytes"
	"encoding/json"
	"math"
	"sort"
	"strconv"
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
		{"wire_events", "Read bounded wire events", object(schema{"since_id": uint, "limit": bounded("integer", 1, 100), "type": choice("all", "http_req", "ws_frame", "sse_event", "grpc_call", "tls_handshake_failed"), "faulted_only": boolean})},
		{"tape_run", "Run a tape", object(schema{"tape_path": str, "tape_yaml": schema{"type": "string", "maxLength": 1048576}, "target": str, "timeout_ms": bounded("integer", 100, 120000)})},
		{"tape_validate", "Validate a tape without running it; supply exactly one of tape_path or tape_yaml", object(schema{"tape_path": str, "tape_yaml": schema{"type": "string", "maxLength": 1048576}})},
		{"tape_export", "Export recorded traffic", object(schema{"name": schema{"type": "string", "minLength": 1}, "out_path": str, "format": choice("v2", "v1")}, "name")},
		{"demo_trigger", "Drive the demo", object(schema{"action": choice("checkout", "webhook", "ticker", "state", "reset"), "order_id": str, "amount_cents": uint, "frames": bounded("integer", 1, 50)}, "action")},
		{"exec_run", "Run a test command through a fault tape (requires --allow-exec); check ok. Maximum wall time is under 320 seconds. This grants arbitrary command execution, not a sandbox.", object(schema{"command": schema{"type": "array", "minItems": 1, "maxItems": 256, "items": schema{"type": "string", "minLength": 1, "maxLength": 4096}}, "tape_path": str, "tape_yaml": schema{"type": "string", "maxLength": 1048576}, "cwd": str, "target": str, "tls": boolean, "tls_passthrough": schema{"type": "array", "items": str, "maxItems": 32}, "allow_zero_traffic": boolean, "seed": uint, "timeout_sec": bounded("integer", 1, 300)}, "command")},
	}
	out := make([]map[string]any, 0, len(specs))
	for _, v := range specs {
		out = append(out, map[string]any{"name": v.name, "description": v.desc, "inputSchema": v.s})
	}
	return out
}
func validArgs(name string, raw json.RawMessage) *paramError {
	all := tools()
	for _, tool := range all {
		if tool["name"] == name {
			var v map[string]any
			d := json.NewDecoder(bytes.NewReader(raw))
			d.UseNumber()
			if !json.Valid(raw) || d.Decode(&v) != nil || v == nil {
				return &paramError{Tool: name, Field: "arguments", Reason: "malformed"}
			}
			errParam := validateSchema(tool["inputSchema"].(schema), v, "arguments")
			if errParam != nil {
				errParam.Tool = name
			}
			return errParam
		}
	}
	names := make([]string, 0, len(all))
	for _, tool := range all {
		names = append(names, tool["name"].(string))
	}
	sort.Strings(names)
	return &paramError{Field: safeName(name), Reason: "unknown_tool", Allowed: names}
}

func validateSchema(s schema, v any, path string) *paramError {
	fail := func(reason string) *paramError { return &paramError{Field: path, Reason: reason} }
	typ, _ := s["type"].(string)
	mismatch := func() *paramError { e := fail("type_mismatch"); e.Expected = typ; return e }
	switch typ {
	case "object":
		m, ok := v.(map[string]any)
		if !ok {
			return mismatch()
		}
		props, _ := s["properties"].(schema)
		if required, ok := s["required"].([]string); ok {
			keys := append([]string(nil), required...)
			sort.Strings(keys)
			for _, k := range keys {
				if _, ok := m[k]; !ok {
					return &paramError{Field: path + "." + k, Reason: "required"}
				}
			}
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p, ok := props[k]
			if !ok {
				if s["additionalProperties"] == false {
					allowed := make([]string, 0, len(props))
					for k := range props {
						allowed = append(allowed, k)
					}
					sort.Strings(allowed)
					return &paramError{Field: path + "." + safeName(k), Reason: "unknown_field", Allowed: allowed}
				}
				continue
			}
			if err := validateSchema(p.(schema), m[k], path+"."+k); err != nil {
				return err
			}
		}
	case "array":
		a, ok := v.([]any)
		if !ok {
			return mismatch()
		}
		if n, ok := s["minItems"].(int); ok && len(a) < n {
			e := fail("too_short")
			e.MinItems = &n
			return e
		}
		if n, ok := s["maxItems"].(int); ok && len(a) > n {
			e := fail("too_long")
			e.MaxItems = &n
			return e
		}
		for i, x := range a {
			if err := validateSchema(s["items"].(schema), x, path+"["+strconv.Itoa(i)+"]"); err != nil {
				return err
			}
		}
	case "string":
		x, ok := v.(string)
		if !ok {
			return mismatch()
		}
		if n, ok := s["minLength"].(int); ok && len(x) < n {
			e := fail("too_short")
			e.MinLength = &n
			return e
		}
		if n, ok := s["maxLength"].(int); ok && len(x) > n {
			e := fail("too_long")
			e.MaxLength = &n
			return e
		}
		if choices, ok := s["enum"].([]string); ok {
			for _, c := range choices {
				if x == c {
					return nil
				}
			}
			e := fail("not_in_enum")
			e.Allowed = choices
			return e
		}
	case "integer":
		n, ok := v.(json.Number)
		if !ok {
			return mismatch()
		}
		if strings.ContainsAny(n.String(), ".eE") {
			return fail("not_integer")
		}
		f, err := n.Float64()
		min, hasMin := s["minimum"].(int)
		max, hasMax := s["maximum"].(int)
		if err != nil || math.IsInf(f, 0) || hasMin && f < float64(min) || hasMax && f > float64(max) {
			e := fail("out_of_range")
			e.Expected = "integer"
			if hasMin {
				e.Minimum = &min
			}
			if hasMax {
				e.Maximum = &max
			}
			return e
		}
		if path == "arguments.seed" || path == "arguments.since_id" {
			if _, err := strconv.ParseUint(n.String(), 10, 64); err != nil {
				e := fail("out_of_range")
				e.Expected = "integer"
				return e
			}
		}
		if path == "arguments.amount_cents" {
			if _, err := strconv.ParseInt(n.String(), 10, strconv.IntSize); err != nil {
				e := fail("out_of_range")
				e.Expected = "integer"
				return e
			}
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return mismatch()
		}
	default:
		return mismatch()
	}
	return nil
}
