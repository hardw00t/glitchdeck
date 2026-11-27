//go:build unix

package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

func TestExecExitAndOutput(t *testing.T) {
	for _, tc := range []struct {
		name, tape string
		ok         bool
		exit       float64
	}{
		{"expected", execTape + "expect:\n  child_exit: any\n", true, 0},
		{"unexpected", execTape, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := execSingle(t, Options{Workdir: t.TempDir(), AllowExec: true}, map[string]any{"command": []string{"sh", "-c", "exit 7"}, "tape_yaml": tc.tape, "allow_zero_traffic": true})
			if r.Error != nil || r.Result.IsError || r.Result.Content["child_exit"] != float64(7) || r.Result.Content["ok"] != tc.ok || r.Result.Content["exit_code"] != tc.exit {
				t.Fatalf("response: %+v", r)
			}
		})
	}
	r := execSingle(t, Options{Workdir: t.TempDir(), AllowExec: true}, map[string]any{"command": []string{"sh", "-c", "head -c 1048576 /dev/zero | tr '\\000' x"}, "tape_yaml": execTape, "allow_zero_traffic": true})
	s, _ := r.Result.Content["stdout"].(string)
	if r.Result.IsError || r.Result.Content["stdout_bytes"] != float64(1048576) || r.Result.Content["stdout_truncated"] != true || len(s) > 65536 || !utf8.ValidString(s) {
		t.Fatalf("bad output report: bytes=%v truncated=%v len=%d", r.Result.Content["stdout_bytes"], r.Result.Content["stdout_truncated"], len(s))
	}
}

func TestExecLoopbackTargetThroughProxy(t *testing.T) {
	if os.Getenv("MCP_EXEC_HTTP_HELPER") == "1" {
		resp, err := http.Get(os.Getenv("GLITCHDECK_PROXY_URL") + "/probe")
		if err != nil {
			os.Exit(2)
		}
		resp.Body.Close()
		if resp.StatusCode != 204 {
			os.Exit(3)
		}
		os.Exit(0)
	}
	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("127.0.0.2 unavailable: %v", err)
	}
	seen := make(chan string, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.URL.Path; w.WriteHeader(204) })}
	go srv.Serve(ln)
	defer srv.Close()
	t.Setenv("MCP_EXEC_HTTP_HELPER", "1")
	r := execSingle(t, Options{Workdir: t.TempDir(), AllowExec: true, UpstreamAllow: []string{"127.0.0.2"}}, map[string]any{"command": []string{os.Args[0], "-test.run=^TestExecLoopbackTargetThroughProxy$"}, "tape_yaml": execTape, "target": "http://" + ln.Addr().String()})
	if r.Result.IsError || r.Result.Content["ok"] != true {
		t.Fatalf("response: %+v", r)
	}
	select {
	case path := <-seen:
		if path != "/probe" {
			t.Fatal(path)
		}
	default:
		t.Fatal("proxy did not reach upstream")
	}
}

func execWaitFile(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			n, err := strconv.Atoi(strings.TrimSpace(string(b)))
			if err == nil {
				return n
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("child did not create %s", path)
	return 0
}

func execGroupGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if syscall.Kill(-pid, 0) == syscall.ESRCH {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process group %d still exists", pid)
}

func TestExecTimeoutKillsProcessGroup(t *testing.T) {
	dir := t.TempDir()
	pidfile := filepath.Join(dir, "pid")
	r := execSingle(t, Options{Workdir: dir, AllowExec: true}, map[string]any{"command": []string{"sh", "-c", "echo $$ > pid; sleep 300 & sleep 300"}, "tape_yaml": execTape, "timeout_sec": 1, "allow_zero_traffic": true})
	pid := execWaitFile(t, pidfile)
	defer syscall.Kill(-pid, syscall.SIGKILL)
	if r.Result.Content["timed_out"] != true || r.Result.Content["exit_code"] != float64(124) {
		t.Fatalf("response: %+v", r)
	}
	if pids, ok := r.Result.Content["leaked_pids"].([]any); !ok || len(pids) != 0 {
		t.Fatalf("leaked_pids must be an empty array: %v", r.Result.Content["leaked_pids"])
	}
	execGroupGone(t, pid)
}

func TestExecAsyncCancellationBusyAndEOF(t *testing.T) {
	dir := t.TempDir()
	in, writer := io.Pipe()
	reader, out := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- NewServer(in, out, Options{Workdir: dir, AllowExec: true}).Serve(); out.Close() }()
	defer writer.Close()
	defer reader.Close()
	responses := make(chan execReply, 16)
	go func() {
		scan := bufio.NewScanner(reader)
		scan.Buffer(make([]byte, 65536), 4<<20)
		for scan.Scan() {
			var r execReply
			if json.Unmarshal(scan.Bytes(), &r) == nil {
				responses <- r
			}
		}
		close(responses)
	}()
	send := func(v any) {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(writer, "%s\n", b); err != nil {
			t.Fatal(err)
		}
	}
	receive := func() execReply {
		t.Helper()
		select {
		case r, ok := <-responses:
			if !ok {
				t.Fatal("response stream closed")
			}
			return r
		case <-time.After(10 * time.Second):
			t.Fatal("response timeout")
			return execReply{}
		}
	}
	send(execRequest(7, map[string]any{"command": []string{"sh", "-c", "echo $$ > pid; sleep 300"}, "tape_yaml": execTape, "allow_zero_traffic": true}))
	pid := execWaitFile(t, filepath.Join(dir, "pid"))
	defer syscall.Kill(-pid, syscall.SIGKILL)
	send(execRequest(9, map[string]any{"command": []string{"true"}, "tape_yaml": execTape, "allow_zero_traffic": true}))
	r := receive()
	if string(r.ID) != "9" || !r.Result.IsError || execErrorCode(r) != "BUSY" {
		t.Fatalf("busy response: %+v", r)
	}
	send(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": 7}})
	start := time.Now()
	send(map[string]any{"jsonrpc": "2.0", "id": 8, "method": "ping"})
	r = receive()
	if string(r.ID) != "8" || time.Since(start) >= time.Second {
		t.Fatalf("ping response: %+v in %v", r, time.Since(start))
	}
	execGroupGone(t, pid)
	// The slot is released only once cleanup has returned.
	deadline := time.Now().Add(5 * time.Second)
	for {
		send(execRequest(10, map[string]any{"command": []string{"sh", "-c", "cat; echo done"}, "tape_yaml": execTape, "allow_zero_traffic": true}))
		r = receive()
		if string(r.ID) != "10" {
			t.Fatalf("unexpected response, including cancelled job: %+v", r)
		}
		if execErrorCode(r) != "BUSY" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("job slot not released")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r.Result.IsError || !strings.Contains(fmt.Sprint(r.Result.Content["stdout"]), "done") {
		t.Fatalf("stdin isolation: %+v", r)
	}
	writer.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not stop on EOF")
	}
	for r := range responses {
		t.Fatalf("unexpected response after cancellation: %+v", r)
	}
}

func TestExecEOFWaitsForJob(t *testing.T) {
	r := execSingle(t, Options{Workdir: t.TempDir(), AllowExec: true}, map[string]any{"command": []string{"sh", "-c", "sleep 0.1; echo finished"}, "tape_yaml": execTape, "allow_zero_traffic": true})
	if r.Result.IsError || !strings.Contains(fmt.Sprint(r.Result.Content["stdout"]), "finished") {
		t.Fatalf("response: %+v", r)
	}
}

func TestExecSignalStopsJob(t *testing.T) {
	if os.Getenv("MCP_EXEC_SIGNAL_HELPER") == "1" {
		out, err := OwnedStdioOutput()
		if err != nil {
			t.Fatal(err)
		}
		if err := NewServer(os.Stdin, out, Options{AllowExec: true, CloseOutputOnCancel: true}).Serve(); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExecSignalStopsJob$")
	dir := t.TempDir()
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "MCP_EXEC_SIGNAL_HELPER=1")
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	var out strings.Builder
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	if err := json.NewEncoder(in).Encode(execRequest(7, map[string]any{
		"command":   []string{"sh", "-c", "echo $$ > pid; sleep 300"},
		"tape_yaml": execTape, "allow_zero_traffic": true,
	})); err != nil {
		t.Fatal(err)
	}
	pid := execWaitFile(t, filepath.Join(dir, "pid"))
	defer syscall.Kill(-pid, syscall.SIGKILL)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	waited = true
	if err != nil || out.Len() != 0 {
		t.Fatalf("signal shutdown: %v, output %q", err, out.String())
	}
	execGroupGone(t, pid)
}

func TestExecRelativeCommandAndTapePaths(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "scenario.yaml"), []byte(execTape), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "scenario.yaml"), []byte(execTape), 0600); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(dir, "sub")
	if err := os.Mkdir(subdir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "script"), []byte("#!/bin/sh\nprintf 'run in sub'"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(outside, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo.yaml"), 0600); err != nil {
		t.Fatal(err)
	}
	opts := Options{Workdir: dir, AllowExec: true}
	args := map[string]any{"command": []string{"./script"}, "cwd": "sub", "tape_path": "scenario.yaml", "allow_zero_traffic": true}
	r := execSingle(t, opts, args)
	if r.Result.Content["stdout"] != "run in sub" || r.Result.Content["tape"] != "scenario.yaml" || r.Result.Content["ok"] != true {
		t.Fatalf("relative command failed: %+v", r)
	}
	args["cwd"] = "escape/sub"
	if r := execSingle(t, opts, args); execErrorCode(r) != "INVALID_PATH" {
		t.Fatalf("cwd traversed a symlink: %+v", r)
	}
	args["cwd"] = "sub"
	for _, path := range []string{"fifo.yaml", "escape/scenario.yaml", filepath.Join(dir, "scenario.yaml")} {
		args["tape_path"] = path
		if r := execSingle(t, opts, args); execErrorCode(r) != "INVALID_PATH" {
			t.Fatalf("accepted tape_path %s: %+v", path, r)
		}
	}
}

func TestExecPassthroughDoesNotGrantEgress(t *testing.T) {
	if os.Getenv("MCP_EXEC_CONNECT_HELPER") == "1" {
		conn, err := net.DialTimeout("tcp", strings.TrimPrefix(os.Getenv("GLITCHDECK_PROXY_URL"), "http://"), time.Second)
		if err != nil {
			os.Exit(2)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.WriteString(conn, "CONNECT 192.0.2.10:443 HTTP/1.1\r\nHost: 192.0.2.10:443\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil || resp.StatusCode != http.StatusForbidden {
			os.Exit(3)
		}
		resp.Body.Close()
		os.Exit(0)
	}
	t.Setenv("MCP_EXEC_CONNECT_HELPER", "1")
	r := execSingle(t, Options{Workdir: t.TempDir(), AllowExec: true}, map[string]any{
		"command":   []string{os.Args[0], "-test.run=^TestExecPassthroughDoesNotGrantEgress$"},
		"tape_yaml": execTape, "tls": true, "tls_passthrough": []string{"192.0.2.10"}, "allow_zero_traffic": true,
	})
	traffic, _ := r.Result.Content["traffic"].(map[string]any)
	if r.Result.Content["ok"] != true || traffic["egress_denied"] != float64(1) || traffic["dial_failed"] != float64(0) {
		t.Fatalf("passthrough bypassed egress: %+v", r)
	}
}

func TestExecSequentialJobsDoNotLeakGoroutines(t *testing.T) {
	t.Setenv("GORACE", os.Getenv("GORACE")+" atexit_sleep_ms=0")
	opts := Options{Workdir: t.TempDir(), AllowExec: true}
	args := map[string]any{"command": []string{"true"}, "tape_yaml": execTape, "allow_zero_traffic": true}
	run := func() {
		t.Helper()
		r := execSingle(t, opts, args)
		if r.Error != nil || r.Result.IsError || r.Result.Content["ok"] != true {
			t.Fatalf("response: %+v", r)
		}
	}
	run()
	baseline := runtime.NumGoroutine()
	for range 100 {
		run()
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > baseline+5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > baseline+5 {
		t.Fatalf("goroutines: baseline %d, after 100 jobs %d", baseline, n)
	}
}
