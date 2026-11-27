package mcp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestHandshakeAndList(t *testing.T) {
	var out bytes.Buffer
	s := NewServer(strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\"}}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n"), &out, Options{})
	if err := s.Serve(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatal(out.String())
	}
	var result struct {
		Result struct {
			Tools []any `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &result); err != nil || len(result.Result.Tools) != 8 {
		t.Fatal(out.String())
	}
}
func TestRejectsUnknownToolAndParameters(t *testing.T) {
	var out bytes.Buffer
	input := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"shell_exec\",\"arguments\":{}}}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"proxy_stop\",\"arguments\":{\"unexpected\":true}}}\n"
	if err := NewServer(strings.NewReader(input), &out, Options{}).Serve(); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var reply struct {
			Error struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(line), &reply); err != nil || reply.Error.Code != -32602 {
			t.Fatalf("bad response %s", line)
		}
	}
}

func TestTapeFilesAreRegularAndBounded(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(nil, nil, Options{Workdir: dir})
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readTape("pipe"); err == nil {
		t.Fatal("accepted FIFO")
	}
	if err := os.WriteFile(filepath.Join(dir, "large"), make([]byte, 1<<20+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readTape("large"); err == nil {
		t.Fatal("accepted oversized tape")
	}
}

func TestTapeExportStaysInRoot(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(nil, nil, Options{Workdir: dir})
	path := filepath.Join(dir, "tape.yaml")
	if err := s.writeTape(path, []byte("version: 1\n")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "version: 1\n" {
		t.Fatalf("output %q: %v", b, err)
	}
	if err := s.writeTape(filepath.Join(filepath.Dir(dir), "outside.yaml"), []byte("bad")); err == nil {
		t.Fatal("wrote outside root")
	}
}
