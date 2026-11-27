//go:build linux

package execrun

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/tape"
)

func TestInheritedCARejectsNamedPipeWithoutWaitingForWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roots.pem")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", path)
	done := make(chan []byte, 1)
	go func() { done <- inheritedCerts("SSL_CERT_FILE") }()
	select {
	case data := <-done:
		if len(data) != 0 {
			t.Fatal("accepted named pipe as a certificate file")
		}
	case <-time.After(time.Second):
		// Release a blocked open so the test cannot leave a reader behind.
		w, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			w.Close()
			<-done
		}
		t.Fatal("opening an inherited CA file blocked on the named pipe")
	}
}

func TestExecStartupRejectsInheritedCAWithoutBlocking(t *testing.T) {
	if os.Getenv("GD_FIFO_STARTUP") == "1" {
		r := Run(context.Background(), tape.Tape{Version: 2, Target: "demo"}, Options{TLS: true, JSON: true, AllowZeroTraffic: true, Command: []string{"true"}})
		if r.ExitCode != 0 {
			t.Fatalf("run failed: %+v", r)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "roots.pem")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExecStartupRejectsInheritedCAWithoutBlocking$")
	cmd.Env = append(os.Environ(), "GD_FIFO_STARTUP=1", "SSL_CERT_FILE="+path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("startup blocked or failed: %v: %s", err, out)
	}
}

func TestExecReapsDetachedChild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pid")
	r := Run(context.Background(), tape.Tape{Version: 2, Target: "demo"}, Options{Command: []string{"sh", "-c", `setsid sleep 300 & echo $! > "$1"; exec sleep 300`, "sh", path}, Timeout: 300 * time.Millisecond, Grace: 100 * time.Millisecond})
	if r.ExitCode != 124 {
		t.Fatalf("got exit %d", r.ExitCode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Kill(pid, 0); err != syscall.ESRCH {
		t.Fatalf("detached process %d remains: %v", pid, err)
	}
}

func TestExecDoesNotKillUnrelatedChild(t *testing.T) {
	unrelated := exec.Command("sleep", "30")
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unrelated.Process.Kill(); _ = unrelated.Wait() }()
	r := Run(context.Background(), tape.Tape{Version: 2, Target: "demo"}, Options{Command: []string{"sh", "-c", "exit 0"}, Grace: 100 * time.Millisecond, JSON: true, AllowZeroTraffic: true})
	if r.ExitCode != 0 {
		t.Fatalf("unexpected exit: %+v", r)
	}
	if err := syscall.Kill(unrelated.Process.Pid, 0); err != nil {
		t.Fatalf("unrelated child was killed: %v", err)
	}
}

func TestExecNonExecutableOnPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "not-executable"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	r := Run(context.Background(), tape.Tape{Version: 2, Target: "demo"}, Options{Command: []string{"not-executable"}, JSON: true})
	if r.ExitCode != 126 {
		t.Fatalf("expected 126, got %d", r.ExitCode)
	}
}
