package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"

	"github.com/hardw00t/glitchdeck/internal/sse"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
)

func TestSSETerminalCuts(t *testing.T) {
	for _, tc := range []struct {
		name, terminal string
		extra          any
	}{
		{"responses", "event: response.completed\ndata: {}\n\n", nil},
		{"gemini", "data: {\"candidates\":[{\"finishReason\":\"STOP\"}]}\n\n", nil},
		{"custom", "event: end\ndata: bye\n\n", []string{"end"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, "data: hello\n\n"+tc.terminal)
			}))
			defer upstream.Close()
			target, _ := ParseTarget(upstream.URL)
			params := map[string]any{"action": "eof_early"}
			if tc.extra != nil {
				params["done_events"] = tc.extra
			}
			p := New(target, fault.Config{Rules: []fault.Rule{{ID: "cut", Enabled: true, Fault: fault.Fault{Type: "sse-glitch", Params: params}}}}, nil)
			defer p.Close()
			server := httptest.NewServer(p)
			defer server.Close()
			resp, err := http.Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			b, err := io.ReadAll(resp.Body)
			if err != nil || string(b) != "data: hello\n\n" {
				t.Fatalf("body %q: %v", b, err)
			}
			if p.Stats()["cut"].Applied != 1 {
				t.Fatal(p.Stats())
			}
		})
	}
}

func TestSSEPlainTextCorruptionSkipped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: hello\n\n")
	}))
	defer upstream.Close()
	target, _ := ParseTarget(upstream.URL)
	p := New(target, fault.Config{Rules: []fault.Rule{{ID: "cut", Enabled: true, Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "corrupt_json", "events": []int{1}}}}}}, nil)
	defer p.Close()
	server := httptest.NewServer(p)
	defer server.Close()
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || !strings.Contains(string(b), "hello") || p.Stats()["cut"].SkipReasons["not_json"] != 1 {
		t.Fatalf("body %q, stats %v, err %v", b, p.Stats(), err)
	}
}

func TestInjectSSEGolden(t *testing.T) {
	for _, tc := range []struct{ provider, want string }{
		{"openai", "data: {\"error\":{\"message\":\"Overloaded\",\"type\":\"server_error\",\"param\":null,\"code\":null}}\n\n"},
		{"openai_responses", "event: error\ndata: {\"type\":\"error\",\"code\":\"server_error\",\"message\":\"Overloaded\",\"param\":null,\"sequence_number\":3}\n\n"},
		{"anthropic", "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}\n\n"},
		{"gemini", "data: {\"error\":{\"code\":503,\"message\":\"The model is overloaded.\",\"status\":\"UNAVAILABLE\"}}\n\n"},
		{"raw", "event: error\ndata: raw payload\n\n"},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			if got := string(injectSSE(map[string]any{"data": "raw payload"}, tc.provider, 3)); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
	raw := map[string]any{"event": "end", "data": "first\r\n\r\nlast"}
	if got := string(injectSSE(raw, "raw", 1)); got != "event: end\ndata: first\ndata: \ndata: last\n\n" {
		t.Fatalf("multiline raw event: %q", got)
	}
}

func TestInjectErrorStopsUpstreamImmediately(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"n\":1}\n\ndata: {\"n\":2}\n\n")
	}))
	defer upstream.Close()
	target, _ := ParseTarget(upstream.URL)
	p := New(target, fault.Config{Rules: []fault.Rule{{ID: "inject", Enabled: true, Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "inject_error", "provider": "anthropic"}}}}}, nil)
	defer p.Close()
	server := httptest.NewServer(p)
	defer server.Close()
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer do-not-reflect")
	req.Header.Set("X-Api-Key", "do-not-reflect")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || strings.Contains(string(b), `"n":2`) || strings.Contains(string(b), "do-not-reflect") || !strings.Contains(string(b), `"overloaded_error"`) || p.Stats()["inject"].Applied != 1 {
		t.Fatalf("body %q stats %v err %v", b, p.Stats(), err)
	}
}

func TestToolArgumentsModesAndClosures(t *testing.T) {
	for _, fixture := range []struct{ name, first, second string }{
		{"chat", `{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"a\":"}},{"index":1,"function":{"arguments":"safe"}}]}}]}`, `{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"1}"}}]}}]}`},
		{"legacy", `{"choices":[{"index":0,"delta":{"function_call":{"arguments":"{\"a\":"}}}]}`, `{"choices":[{"index":0,"delta":{"function_call":{"arguments":"1}"}}}]}`},
		{"anthropic", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"a\":"}}`, `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"1}"}}`},
		{"responses", `{"type":"response.function_call_arguments.delta","item_id":"x","delta":"{\"a\":"}`, `{"type":"response.function_call_arguments.delta","item_id":"x","delta":"1}"}`},
	} {
		for _, mode := range []string{"truncate", "invalid", "drop"} {
			for _, then := range []string{"continue", "eof", "rst"} {
				t.Run(fixture.name+"/"+mode+"/"+then, func(t *testing.T) {
					rule := &fault.Rule{ID: "tools", Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "corrupt_tool_args", "mode": mode, "then": then}}}
					p := New(nil, fault.Config{}, nil)
					defer p.Close()
					w := httptest.NewRecorder()
					result := p.relaySSE(context.Background(), w, strings.NewReader("data: "+fixture.first+"\n\ndata: "+fixture.second+"\n\n"), rule, 1, 1, 0, time.Now(), "")
					wantEnd := "eof"
					if then == "eof" {
						wantEnd = "eof_early"
					}
					if then == "rst" {
						wantEnd = "rst"
					}
					if !result.applied || result.end != wantEnd {
						t.Fatalf("result %#v", result)
					}
					reader := sse.NewReader(strings.NewReader(w.Body.String()), 0)
					args := ""
					for {
						frame, err := reader.Next()
						if err == io.EOF {
							break
						}
						if err != nil {
							t.Fatal(err)
						}
						if !json.Valid([]byte(frame.Data)) {
							t.Fatalf("invalid outer JSON %q", frame.Data)
						}
						parts, _ := toolFragments(frame)
						if len(parts) > 0 {
							args += parts[0].obj[parts[0].field].(string)
						}
						if fixture.name == "chat" && len(parts) > 1 && parts[1].obj[parts[1].field] != "safe" {
							t.Fatalf("other tool changed: %s", frame.Data)
						}
					}
					if json.Valid([]byte(args)) {
						t.Fatalf("arguments unexpectedly valid: %q", args)
					}
				})
			}
		}
	}
}

func TestSSEJSONValidityIgnoresPlainText(t *testing.T) {
	for _, tc := range []struct {
		data  string
		valid bool
	}{
		{"hello", true}, {"{broken", false},
	} {
		bus := telemetry.New()
		p := New(nil, fault.Config{}, bus)
		p.relaySSE(context.Background(), httptest.NewRecorder(), strings.NewReader("data: "+tc.data+"\n\n"), nil, 1, 1, 0, time.Now(), "")
		p.Close()
		var end map[string]any
		for _, event := range bus.History(20) {
			if event.Type == "sse_event" {
				var data map[string]any
				if err := json.Unmarshal(event.Data, &data); err != nil {
					t.Fatal(err)
				}
				if data["kind"] == "end" {
					end = data
				}
			}
		}
		if end["delivered_valid_json"] != tc.valid {
			t.Fatalf("%q: end %v", tc.data, end)
		}
	}
}

func TestInjectErrorAutoUsesFirstThreeEvents(t *testing.T) {
	for _, tc := range []struct{ event, data, provider, match string }{
		{"message_start", `{}`, "anthropic", `"overloaded_error"`},
		{"response.created", `{}`, "openai_responses", `"sequence_number":1`},
		{"", `{"candidates":[]}`, "gemini", `"UNAVAILABLE"`},
		{"", `{"choices":[]}`, "openai", `"server_error"`},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			bus := telemetry.New()
			p := New(nil, fault.Config{}, bus)
			defer p.Close()
			rule := &fault.Rule{ID: "auto", Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "inject_error"}}}
			in := "data: first\n\ndata: second\n\n"
			if tc.event != "" {
				in += "event: " + tc.event + "\n"
			}
			in += "data: " + tc.data + "\n\n"
			w := httptest.NewRecorder()
			res := p.relaySSE(context.Background(), w, strings.NewReader(in), rule, 1, 1, 0, time.Now(), "")
			if !res.applied || !strings.HasPrefix(w.Body.String(), "data: first\n\n") || strings.Contains(w.Body.String(), "data: second") || !strings.Contains(w.Body.String(), tc.match) {
				t.Fatalf("result %+v, output %q", res, w.Body)
			}
			if end := encodedSSEEnd(t, p, bus); end["terminal"] != "error" {
				t.Fatalf("end: %v", end)
			}
		})
	}
}

func TestToolArgumentsPreserveLargeIntegers(t *testing.T) {
	const input = `{"type":"response.function_call_arguments.done","item_id":"call","sequence_number":9007199254740993,"arguments":"{\"é\":1}"}`
	rule := &fault.Rule{ID: "tools", Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "corrupt_tool_args"}}}
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	for _, fixture := range []string{input + "{}", input} {
		t.Run(fixture[len(input):], func(t *testing.T) {
			w := httptest.NewRecorder()
			res := p.relaySSE(context.Background(), w, strings.NewReader("data: "+fixture+"\n\n"), rule, 1, 1, 0, time.Now(), "")
			f, err := sse.NewReader(w.Body, 0).Next()
			if err != nil {
				t.Fatal(err)
			}
			if fixture != input {
				if res.applied || f.Data != fixture || res.skip != "no_tool_args" {
					t.Fatalf("malformed data changed: %+v, %q", res, f.Data)
				}
				return
			}
			var decoded struct {
				Arguments string `json:"arguments"`
				Sequence  uint64 `json:"sequence_number"`
			}
			if err := json.Unmarshal([]byte(f.Data), &decoded); err != nil || decoded.Arguments != `{"é` || decoded.Sequence != 9007199254740993 || !res.applied {
				t.Fatalf("result %+v, data: %s (%v)", res, f.Data, err)
			}
		})
	}
}
