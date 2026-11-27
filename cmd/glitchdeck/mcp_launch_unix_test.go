//go:build unix

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestMCPLaunchHelper(t *testing.T) {
	if os.Getenv("GLITCHDECK_MCP_LAUNCH_HELPER") != "1" {
		return
	}
	os.Exit(mcpCommand([]string{"--allow-exec"}))
}

func TestMCPLaunchStdioIsolation(t *testing.T) {
	for _, tc := range []struct {
		name, script, want string
	}{
		{"stdin", "cat; echo stdin-eof", "stdin-eof"},
		{"inherited-fd", "if (echo leaked >&7) 2>/dev/null; then echo fd-leaked; else echo fd-closed; fi", "fd-closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sentinel, err := os.CreateTemp(t.TempDir(), "sentinel")
			if err != nil {
				t.Fatal(err)
			}
			defer sentinel.Close()
			cmd := exec.Command(os.Args[0], "-test.run=^TestMCPLaunchHelper$")
			cmd.Env = append(os.Environ(), "GLITCHDECK_MCP_LAUNCH_HELPER=1")
			cmd.ExtraFiles = []*os.File{nil, nil, nil, nil, sentinel}
			in, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { in.Close(); cmd.Process.Kill(); cmd.Wait() }()
			replies := make(chan map[string]any, 2)
			go func() {
				scan := bufio.NewScanner(out)
				scan.Buffer(make([]byte, 65536), 4<<20)
				for scan.Scan() {
					var reply map[string]any
					if json.Unmarshal(scan.Bytes(), &reply) == nil {
						replies <- reply
					}
				}
				close(replies)
			}()
			request := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "exec_run", "arguments": map[string]any{"command": []string{"sh", "-c", tc.script}, "tape_yaml": "version: 2\ntarget: demo\n", "allow_zero_traffic": true}}}
			if err := json.NewEncoder(in).Encode(request); err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintln(in, `{"jsonrpc":"2.0","id":2,"method":"ping"}`); err != nil {
				t.Fatal(err)
			}
			gotExec, gotPing := false, false
			for !gotExec || !gotPing {
				select {
				case reply, ok := <-replies:
					if !ok {
						t.Fatal("MCP response stream closed")
					}
					switch reply["id"] {
					case float64(1):
						result, _ := reply["result"].(map[string]any)
						content, _ := result["structuredContent"].(map[string]any)
						if result["isError"] == true || !strings.Contains(fmt.Sprint(content["stdout"]), tc.want) {
							t.Fatalf("exec response: %+v", reply)
						}
						gotExec = true
					case float64(2):
						if reply["error"] != nil {
							t.Fatalf("ping response: %+v", reply)
						}
						gotPing = true
					default:
						t.Fatalf("unexpected response: %+v", reply)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("timed out waiting for exec and ping while protocol stdin remains open")
				}
			}
		})
	}
}

func fullStderrPipe(t *testing.T) *os.File {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close(); writer.Close() })
	fd := int(writer.Fd())
	if err := syscall.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	block := make([]byte, 4096)
	for {
		_, err := syscall.Write(fd, block)
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.SetNonblock(fd, false); err != nil {
		t.Fatal(err)
	}
	return writer
}

func TestMCPLaunchServeErrorDoesNotBlockOnStderr(t *testing.T) {
	writer := fullStderrPipe(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestMCPLaunchHelper$")
	cmd.Env = append(os.Environ(), "GLITCHDECK_MCP_LAUNCH_HELPER=1")
	cmd.Stderr = writer
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	go func() {
		in.Write(bytes.Repeat([]byte("x"), 4<<20+1))
		in.Close()
	}()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 3 {
			t.Fatalf("expected exit 3 after scanner error, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("MCP shutdown blocked on stderr after scanner error")
	}
}

func TestMCPLaunchCancellationDoesNotBlockOnStderr(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestMCPLaunchHelper$")
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "GLITCHDECK_MCP_LAUNCH_HELPER=1")
	cmd.Stdout, cmd.Stderr = io.Discard, fullStderrPipe(t)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer cmd.Process.Kill()
	if _, err := fmt.Fprintln(in, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec_run","arguments":{"command":["sh","-c","echo $$ > ready; sleep 300"],"tape_yaml":"version: 2\n","allow_zero_traffic":true}}}`); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		pid, err := os.ReadFile(filepath.Join(cmd.Dir, "ready"))
		var pgid int
		if err == nil {
			_, err = fmt.Sscan(string(pid), &pgid)
			if err == nil && pgid > 0 {
				defer syscall.Kill(-pgid, syscall.SIGKILL)
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("waiting for child: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := fmt.Fprintln(in, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`); err != nil {
		t.Fatal(err)
	}
	in.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled job blocked server EOF on stderr")
	}
}
