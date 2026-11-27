package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
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
		var obj map[string]json.RawMessage
		json.Unmarshal([]byte(args), &obj)
		if validArgs("wire_events", obj) {
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
	input := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"tape_run\",\"arguments\":{\"tape_path\":\"clean.tape.yaml\"}}}\n" +
		"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"tape_run\",\"arguments\":{\"tape_path\":\"checkout-dup-webhook.tape.yaml\"}}}\n"
	var output strings.Builder
	if err := NewServer(strings.NewReader(input), &output, Options{Workdir: "../../examples"}).Serve(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatal(output.String())
	}
	for i, line := range lines {
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
