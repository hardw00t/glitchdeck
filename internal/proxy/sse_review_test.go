package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
)

func TestEmptyGzipDecoderIsTruncated(t *testing.T) {
	d := &sseDecoder{source: strings.NewReader(""), encoding: "gzip"}
	if _, err := io.ReadAll(d); err != io.ErrUnexpectedEOF {
		t.Fatalf("empty gzip: %v", err)
	}
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	d = &sseDecoder{source: &b, encoding: "gzip"}
	if data, err := io.ReadAll(d); err != nil || len(data) != 0 {
		t.Fatalf("valid empty gzip: %q %v", data, err)
	}
}

func TestRelayTerminalInjectionAndLegacyEnd(t *testing.T) {
	for _, tc := range []struct {
		input, end, terminal string
		after                int
	}{
		{"data: {}\n\ndata: [DONE]\n\n", "done", "done_marker", 2},
		{"event: message_stop\ndata: {}\n\n", "eof", "message_stop", 1},
		{"event: response.completed\ndata: {}\n\ndata: [DONE]\n\n", "done", "response.completed", 1},
	} {
		bus := telemetry.New()
		p := New(nil, fault.Config{}, bus)
		rule := &fault.Rule{ID: "inject", Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "inject_error", "provider": "openai", "after_events": tc.after}}}
		w := httptest.NewRecorder()
		res := p.relaySSE(context.Background(), w, strings.NewReader(tc.input), rule, 1, 1, 0, time.Now(), "")
		end := encodedSSEEnd(t, p, bus)
		p.Close()
		if res.applied || res.end != tc.end || end["terminal"] != tc.terminal || strings.Contains(w.Body.String(), "server_error") {
			t.Fatalf("result %+v end %v body %q", res, end, w.Body.String())
		}
	}
}

func TestRelayTelemetryBoundsAndSyntheticEvent(t *testing.T) {
	bus := telemetry.New()
	p := New(nil, fault.Config{}, bus)
	defer p.Close()
	name := strings.Repeat("x", 20000)
	rule := &fault.Rule{ID: "inject", Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "inject_error", "provider": "raw", "event": "custom", "data": "safe"}}}
	p.relaySSE(context.Background(), httptest.NewRecorder(), strings.NewReader("event: "+name+"\nid: "+name+"\ndata: {}\n\n"), rule, 1, 1, 0, time.Now(), "")
	found := false
	for _, e := range bus.History(20) {
		if e.Type != "sse_event" {
			continue
		}
		if len(e.Data) > 4096 {
			t.Fatalf("unbounded telemetry: %d", len(e.Data))
		}
		var d map[string]any
		if err := json.Unmarshal(e.Data, &d); err != nil {
			t.Fatal(err)
		}
		if d["action"] == "inject_error" {
			found = true
			if d["event"] != "custom" || d["ts_ms"] == nil || d["data_bytes"] != float64(4) {
				t.Fatalf("synthetic event: %v", d)
			}
		}
	}
	if !found {
		t.Fatal("missing synthetic telemetry")
	}
}

func TestCorruptionSkipNotReportedAfterSuccess(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	rule := &fault.Rule{ID: "corrupt", Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "corrupt_json", "every": 1}}}
	res := p.relaySSE(context.Background(), httptest.NewRecorder(), strings.NewReader("data: {\"a\":1}\n\ndata: [DONE]\n\n"), rule, 1, 1, 0, time.Now(), "")
	if !res.applied || res.skip != "" {
		t.Fatalf("result %+v", res)
	}
}

func TestLargeGeminiProviderDetection(t *testing.T) {
	data := `{"padding":"` + strings.Repeat("x", 70000) + `","candidates":[]}`
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	rule := &fault.Rule{ID: "inject", Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "inject_error"}}}
	w := httptest.NewRecorder()
	p.relaySSE(context.Background(), w, strings.NewReader("data: "+data+"\n\n"), rule, 1, 1, 0, time.Now(), "")
	if !strings.Contains(w.Body.String(), `"UNAVAILABLE"`) {
		t.Fatal("Gemini provider not detected")
	}
}

func TestTruncatedToolFragmentsAreOmitted(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	rule := &fault.Rule{ID: "tools", Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "corrupt_tool_args"}}}
	input := "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"abcdef\"}},{\"index\":1,\"function\":{\"arguments\":\"safe\"}}]}}]}\n\n" +
		"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"later\"}},{\"index\":1,\"function\":{\"arguments\":\"sibling\"}}]}}]}\n\n"
	w := httptest.NewRecorder()
	p.relaySSE(context.Background(), w, strings.NewReader(input), rule, 1, 1, 0, time.Now(), "")
	out := w.Body.String()
	if !strings.Contains(out, `"arguments":"safe"`) || !strings.Contains(out, `"arguments":"sibling"`) || strings.Contains(out, `"arguments":""`) || strings.Contains(out, "later") {
		t.Fatalf("output %s", out)
	}
	input += "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"later\"}},{\"index\":1,\"function\":{\"name\":\"sibling_name\"}}]}}]}\n\n"
	w = httptest.NewRecorder()
	p.relaySSE(context.Background(), w, strings.NewReader(input), rule, 1, 2, 0, time.Now(), "")
	if out := w.Body.String(); !strings.Contains(out, `"name":"sibling_name"`) || strings.Contains(out, "later") {
		t.Fatalf("sibling call without arguments lost: %s", out)
	}
}

func TestAutoInjectionDoesNotWaitForHeartbeatStream(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n: heartbeat\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer up.Close()
	p, _ := newEncodedSSEProxy(t, up.URL, encodedSSEConfig(map[string]any{"action": "inject_error"}))
	server := httptest.NewServer(p)
	defer server.Close()
	client := server.Client()
	client.Timeout = 2 * time.Second
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || !bytes.Contains(b, []byte(`"server_error"`)) {
		t.Fatalf("injection did not finish: %q (%v)", b, err)
	}
}

func TestTruncatedResponsesDoneIsOmitted(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	rule := &fault.Rule{ID: "tools", Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "corrupt_tool_args"}}}
	input := "data: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"x\",\"delta\":\"abcdef\"}\n\n" +
		"data: {\"type\":\"response.function_call_arguments.done\",\"item_id\":\"x\",\"arguments\":\"abcdef\"}\n\n"
	w := httptest.NewRecorder()
	p.relaySSE(context.Background(), w, strings.NewReader(input), rule, 1, 1, 0, time.Now(), "")
	if strings.Contains(w.Body.String(), "arguments.done") {
		t.Fatalf("suppressed done forwarded: %s", w.Body.String())
	}
}

func TestDecodedSSETelemetryBoundsManyFields(t *testing.T) {
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	field := strings.Repeat("x", 30000)
	for range 80 {
		if _, err := io.WriteString(z, "event: "+field+"\nid: "+field+"\ndata: {}\n\n"); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	bus := telemetry.New()
	p := New(nil, fault.Config{}, bus)
	defer p.Close()
	rule := &fault.Rule{ID: "corrupt", Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "corrupt_json", "events": []int{999}}}}
	d := &sseDecoder{source: &compressed, encoding: "gzip"}
	p.relaySSE(context.Background(), httptest.NewRecorder(), d, rule, 1, 1, 0, time.Now(), "")
	total := 0
	for _, e := range bus.History(100) {
		total += len(e.Data)
	}
	if total > 100000 {
		t.Fatalf("retained telemetry: %d bytes", total)
	}
}

func TestEmptyGzipRelayReportsDecodeError(t *testing.T) {
	bus := telemetry.New()
	p := New(nil, fault.Config{}, bus)
	defer p.Close()
	rule := &fault.Rule{ID: "corrupt", Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "corrupt_json"}}}
	d := &sseDecoder{source: strings.NewReader(""), encoding: "gzip"}
	res := p.relaySSE(context.Background(), httptest.NewRecorder(), d, rule, 1, 1, 0, time.Now(), "gzip")
	end := encodedSSEEnd(t, p, bus)
	if res.end != "upstream_error" || res.skip != "decode_error" || end["reason"] != "decode_error" {
		t.Fatalf("result %+v, end %v", res, end)
	}
}
