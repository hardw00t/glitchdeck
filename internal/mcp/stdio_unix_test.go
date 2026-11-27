//go:build unix

package mcp

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestBlockedStdioStopsOnSignal(t *testing.T) {
	if os.Getenv("MCP_BLOCKED_STDIO_TEST") == "1" {
		out, err := OwnedStdioOutput()
		if err != nil {
			os.Exit(2)
		}
		_ = NewServer(strings.NewReader(strings.Repeat("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n", 10000)), out, Options{CloseOutputOnCancel: true}).Serve()
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestBlockedStdioStopsOnSignal$")
	cmd.Env = append(os.Environ(), "MCP_BLOCKED_STDIO_TEST=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	buf := make([]byte, 1)
	if _, err := io.ReadFull(stdout, buf); err != nil {
		t.Fatal(err)
	}
	// Let the child fill the pipe before requesting shutdown.
	time.Sleep(100 * time.Millisecond)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal(fmt.Errorf("server did not stop with a full stdout pipe"))
	}
}
