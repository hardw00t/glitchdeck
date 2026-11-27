package proxy

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/sse"
)

type sseDecoder struct {
	source   io.Reader
	encoding string
	reader   io.ReadCloser
	err      error
}

func (d *sseDecoder) Read(p []byte) (int, error) {
	if d.reader == nil && d.err == nil {
		if d.encoding == "deflate" {
			b := bufio.NewReader(d.source)
			h, err := b.Peek(2)
			// RFC 1950 checks the method, window size and header checksum.
			if err == nil && h[0]&15 == 8 && h[0]>>4 <= 7 && (int(h[0])*256+int(h[1]))%31 == 0 {
				d.reader, d.err = zlib.NewReader(b)
			} else {
				d.reader = flate.NewReader(b)
			}
		} else {
			reader, err := gzip.NewReader(d.source)
			d.err = err
			if err == nil {
				d.reader = reader
			}
		}
	}
	if d.err != nil {
		return 0, d.err
	}
	return d.reader.Read(p)
}

func (d *sseDecoder) Close() error {
	if d.reader != nil {
		return d.reader.Close()
	}
	return nil
}

func injectSSE(params map[string]any, provider string, sequence int) []byte {
	if provider == "raw" {
		event := fault.String(params, "event", "error")
		data := rawSSEData(params)
		return sse.Encode(sse.Frame{Data: data, Lines: []sse.Line{{Field: "event", Value: event}, {Field: "data"}}})
	}
	defaultMessage, defaultType := "Overloaded", "server_error"
	switch provider {
	case "anthropic":
		defaultType = "overloaded_error"
	case "gemini":
		defaultMessage, defaultType = "The model is overloaded.", "UNAVAILABLE"
	}
	quote := func(text string) string {
		b, _ := json.Marshal(text)
		return string(b)
	}
	msg := quote(fault.String(params, "message", defaultMessage))
	typ := quote(fault.String(params, "error_type", defaultType))
	switch provider {
	case "anthropic":
		return []byte("event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":" + typ + ",\"message\":" + msg + "}}\n\n")
	case "gemini":
		return []byte("data: {\"error\":{\"code\":503,\"message\":" + msg + ",\"status\":" + typ + "}}\n\n")
	case "openai_responses":
		return []byte(fmt.Sprintf("event: error\ndata: {\"type\":\"error\",\"code\":%s,\"message\":%s,\"param\":null,\"sequence_number\":%d}\n\n", typ, msg, sequence))
	default:
		return []byte("data: {\"error\":{\"message\":" + msg + ",\"type\":" + typ + ",\"param\":null,\"code\":null}}\n\n")
	}
}

func rawSSEData(params map[string]any) string {
	data := fault.String(params, "data", "")
	return strings.ReplaceAll(strings.ReplaceAll(data, "\r\n", "\n"), "\r", "\n")
}

func detectSSEProvider(f sse.Frame) string {
	switch {
	case f.Event == "message_start":
		return "anthropic"
	case strings.HasPrefix(f.Event, "response."):
		return "openai_responses"
	}
	data := strings.TrimSpace(f.Data)
	if len(data) <= 64<<10 && strings.HasPrefix(data, "{") {
		var v struct{ Candidates json.RawMessage }
		if json.Unmarshal([]byte(data), &v) == nil && v.Candidates != nil {
			return "gemini"
		}
	}
	return ""
}

type toolKey struct {
	shape, choice, call string
}

type toolFragment struct {
	obj   map[string]any
	field string
	key   toolKey
}

// toolFragments returns mutable argument fields and stable per-call identities.
func toolFragments(f sse.Frame) ([]toolFragment, map[string]any) {
	data := strings.TrimSpace(f.Data)
	if data == "" || data[0] != '{' {
		return nil, nil
	}
	dec := json.NewDecoder(strings.NewReader(data))
	dec.UseNumber()
	var v map[string]any
	if dec.Decode(&v) != nil || dec.InputOffset() != int64(len(data)) {
		return nil, nil
	}
	var out []toolFragment
	add := func(m map[string]any, field string, key toolKey) {
		if _, ok := m[field].(string); ok {
			out = append(out, toolFragment{m, field, key})
		}
	}
	for ci, c := range array(v["choices"]) {
		choice := object(c)
		delta := object(choice["delta"])
		choiceID := toolIndex(choice["index"], ci)
		add(object(delta["function_call"]), "arguments", toolKey{shape: "legacy", choice: choiceID})
		for i, x := range array(delta["tool_calls"]) {
			call := object(x)
			add(object(call["function"]), "arguments", toolKey{shape: "chat", choice: choiceID, call: toolIndex(call["index"], i)})
		}
	}
	if v["type"] == "content_block_delta" || f.Event == "content_block_delta" {
		delta := object(v["delta"])
		if delta["type"] == "input_json_delta" {
			add(delta, "partial_json", toolKey{shape: "anthropic", call: toolIndex(v["index"], 0)})
		}
	}
	typ, _ := v["type"].(string)
	if typ == "" {
		typ = f.Event
	}
	if typ == "response.function_call_arguments.delta" || typ == "response.function_call_arguments.done" {
		key := toolKey{shape: "responses"}
		if item, _ := v["item_id"].(string); item != "" {
			key.call = item
		} else {
			key.choice = toolIndex(v["output_index"], 0)
		}
		if typ == "response.function_call_arguments.delta" {
			add(v, "delta", key)
		} else {
			add(v, "arguments", key)
		}
	}
	return out, v
}

func toolIndex(v any, fallback int) string {
	if n, ok := v.(json.Number); ok {
		return string(n)
	}
	return strconv.Itoa(fallback)
}

func object(v any) map[string]any { m, _ := v.(map[string]any); return m }
func array(v any) []any           { a, _ := v.([]any); return a }
