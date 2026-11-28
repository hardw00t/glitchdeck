package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/wsframe"
)

func TestSessionLoopAndEOF(t *testing.T) {
	in, w := io.Pipe()
	out, r := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- NewServer(in, r, Options{Workdir: t.TempDir()}).Serve(); r.Close() }()
	scan := bufio.NewScanner(out)
	call := func(id int, name, args string) map[string]any {
		t.Helper()
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`+"\n", id, name, args)
		if !scan.Scan() {
			t.Fatal("missing response", scan.Err())
		}
		var reply map[string]any
		if err := json.Unmarshal(scan.Bytes(), &reply); err != nil {
			t.Fatal(err)
		}
		result, ok := reply["result"].(map[string]any)
		if !ok {
			t.Fatalf("response: %v", reply)
		}
		if result["isError"] == true {
			t.Fatalf("tool: %v", result)
		}
		return result["structuredContent"].(map[string]any)
	}
	start := call(1, "proxy_start", `{"target":"demo","record":true}`)
	address := start["proxy_url"].(string)
	call(2, "fault_set", `{"rules":[{"id":"dup","enabled":true,"match":{"method":"POST","path_prefix":"/webhooks/payment"},"fault":{"type":"dup-webhook","params":{"count":2,"delay_ms":20}}}]}`)
	trigger := call(3, "demo_trigger", `{"action":"webhook","order_id":"ord-9","amount_cents":4900}`)
	state := trigger["state"].(map[string]any)
	if state["duplicate_charges"] != float64(1) {
		t.Fatal(state)
	}
	events := call(4, "wire_events", `{"limit":10}`)
	if events["count"].(float64) < 1 {
		t.Fatal(events)
	}
	call(5, "demo_trigger", `{"action":"ticker","frames":1}`)
	exported := call(6, "tape_export", `{"name":"session"}`)
	if !strings.Contains(exported["yaml"].(string), "webhooks/payment") {
		t.Fatal(exported)
	}
	w.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("EOF did not stop server")
	}
	u, _ := url.Parse(address)
	c, err := net.DialTimeout("tcp", u.Host, 200*time.Millisecond)
	if err == nil {
		c.Close()
		t.Fatal("listener still open")
	}
}

func TestStrictArgumentBounds(t *testing.T) {
	for _, args := range []string{`{"limit":0}`, `{"type":"other"}`, `{"limit":101}`, `{"since_id":-1}`} {
		if validArgs("wire_events", json.RawMessage(args)) == nil {
			t.Fatalf("accepted %s", args)
		}
	}
}

func TestProtocolErrorsAndNotifications(t *testing.T) {
	input := "{bad\n" +
		"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n" +
		"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n" +
		"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"demo_trigger\",\"arguments\":{\"action\":\"bad\"}}}\n"
	var output strings.Builder
	if err := NewServer(strings.NewReader(input), &output, Options{}).Serve(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 3 {
		t.Fatal(output.String())
	}
	var first, last struct {
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	json.Unmarshal([]byte(lines[0]), &first)
	json.Unmarshal([]byte(lines[2]), &last)
	if first.Error.Code != -32700 || last.Error.Code != -32602 {
		t.Fatal(output.String())
	}
}

func TestExportPathGuard(t *testing.T) {
	s := NewServer(strings.NewReader(""), io.Discard, Options{Workdir: t.TempDir()})
	for _, p := range []string{"../escape.yaml", "file.sh", "bad\x00.yaml"} {
		if _, err := s.outputPath(p); err == nil {
			t.Fatalf("accepted %q", p)
		}
	}
	if _, err := s.outputPath("safe.yaml"); err != nil {
		t.Fatal(err)
	}
}

func TestTapeRunReportsAssertions(t *testing.T) {
	for i, path := range []string{"clean.tape.yaml", "checkout-dup-webhook.tape.yaml"} {
		input := fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"tape_run\",\"arguments\":{\"tape_path\":%q}}}\n", path)
		var output strings.Builder
		if err := NewServer(strings.NewReader(input), &output, Options{Workdir: "../../examples"}).Serve(); err != nil {
			t.Fatal(err)
		}
		line := output.String()
		var reply struct {
			Result struct {
				IsError bool `json:"isError"`
				Content struct {
					Exit    int `json:"exit_code"`
					Summary struct {
						Requests uint64 `json:"requests_total"`
					} `json:"summary"`
				} `json:"structuredContent"`
			} `json:"result"`
		}
		if err := json.Unmarshal([]byte(line), &reply); err != nil {
			t.Fatal(err)
		}
		if reply.Result.IsError || reply.Result.Content.Exit != i || reply.Result.Content.Summary.Requests == 0 {
			t.Fatal(line)
		}
	}
}

func TestDiscoveryShowsFaultCatalog(t *testing.T) {
	var out strings.Builder
	if err := NewServer(strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n"), &out, Options{}).Serve(); err != nil {
		t.Fatal(err)
	}
	var reply struct {
		Result struct {
			Tools []map[string]any `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(out.String()), &reply); err != nil {
		t.Fatal(err)
	}
	for _, tool := range reply.Result.Tools {
		if tool["name"] != "fault_set" {
			continue
		}
		inputSchema := tool["inputSchema"].(map[string]any)
		rules := inputSchema["properties"].(map[string]any)["rules"].(map[string]any)
		fault := rules["items"].(map[string]any)["properties"].(map[string]any)["fault"].(map[string]any)
		params := fault["properties"].(map[string]any)["params"].(map[string]any)
		if params["additionalProperties"] == false || params["properties"] != nil {
			t.Fatal(params)
		}
		meta, ok := tool["_meta"].(map[string]any)
		if !ok {
			t.Fatalf("missing catalog: %v", tool)
		}
		catalog := meta["faultCatalog"].(map[string]any)
		for _, tc := range []struct{ typ, param, def, values string }{
			{"dup-webhook", "mode", "sequential", "sequential,concurrent,timeout_retry"},
			{"dup-webhook", "client_result", "gateway_timeout", "gateway_timeout,reset"},
			{"ws-glitch", "frames", "all", "all,data,control"},
		} {
			p := catalog[tc.typ].(map[string]any)["params"].(map[string]any)[tc.param].(map[string]any)
			b, _ := json.Marshal(p["enum"])
			var values []string
			_ = json.Unmarshal(b, &values)
			if p["default"] != tc.def || strings.Join(values, ",") != tc.values {
				t.Fatal(p)
			}
		}
		return
	}
	t.Fatal("fault_set absent")
}

func TestTapeRunIncludesReplayDiagnostics(t *testing.T) {
	input := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"tape_run\",\"arguments\":{\"tape_path\":\"checkout-dup-webhook.tape.yaml\"}}}\n"
	var out strings.Builder
	if err := NewServer(strings.NewReader(input), &out, Options{Workdir: "../../examples"}).Serve(); err != nil {
		t.Fatal(err)
	}
	var reply struct {
		Result struct {
			Content struct {
				Faults []map[string]any `json:"faults_triggered"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(out.String()), &reply); err != nil {
		t.Fatal(err)
	}
	if len(reply.Result.Content.Faults) == 0 || reply.Result.Content.Faults[0]["replays"] == nil {
		t.Fatal(out.String())
	}
}

func TestTapeRunErrorRetainsFrameDiagnostics(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/webhook" {
			w.WriteHeader(http.StatusOK)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsframe.AcceptKey(r.Header.Get("Sec-WebSocket-Key")))
		_ = rw.Flush()
		_, _ = conn.Write([]byte{0x82, 127, 0, 0, 0, 0, 0, 0x40, 0, 1})
		_, _ = wsframe.Read(rw.Reader, true)
	}))
	defer upstream.Close()
	doc := fmt.Sprintf("version: 2\ntarget: %s\nrules:\n  - id: dup\n    enabled: true\n    match: {method: POST, path_prefix: /webhook}\n    fault: {type: dup-webhook, params: {count: 2, delay_ms: 0}}\nscript:\n  - http: {method: POST, path: /webhook}\n  - ws: {path: /ws, frames: 1, timeout_ms: 1000}\n", upstream.URL)
	args, _ := json.Marshal(map[string]any{"tape_yaml": doc, "timeout_ms": 3000})
	input := fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"tape_run\",\"arguments\":%s}}\n", args)
	var out strings.Builder
	if err := NewServer(strings.NewReader(input), &out, Options{}).Serve(); err != nil {
		t.Fatal(err)
	}
	var reply struct {
		Result struct {
			IsError bool `json:"isError"`
			Content struct {
				Faults []struct {
					RuleID  string         `json:"rule_id"`
					Count   int            `json:"count"`
					Replays map[string]any `json:"replays"`
				} `json:"faults_triggered"`
				Frames []struct {
					Error    string `json:"error"`
					Declared int    `json:"declared_bytes"`
				} `json:"frame_errors"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(out.String()), &reply); err != nil {
		t.Fatal(err)
	}
	if !reply.Result.IsError || len(reply.Result.Content.Frames) != 1 || reply.Result.Content.Frames[0].Error != "frame_too_large" || reply.Result.Content.Frames[0].Declared != 4194305 {
		t.Fatal(out.String())
	}
	if len(reply.Result.Content.Faults) != 1 || reply.Result.Content.Faults[0].RuleID != "dup" || reply.Result.Content.Faults[0].Count != 1 || reply.Result.Content.Faults[0].Replays == nil {
		t.Fatal(out.String())
	}
}
