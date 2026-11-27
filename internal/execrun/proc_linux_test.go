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

var _ = func() bool {
	if marker := os.Getenv("GD_TEST_STALLED_HELPER"); marker != "" && os.Getenv(helperEnv) != "" {
		_ = os.WriteFile(marker, []byte(strconv.Itoa(os.Getpid())), 0600)
		_ = syscall.Kill(os.Getpid(), syscall.SIGSTOP)
	}
	return true
}()

func TestInheritedCARejectsNamedPipeWithoutWaitingForWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roots.pem")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", path)
	done := make(chan []byte, 1)
	go func() { done <- inheritedCerts("SSL_CERT_FILE", nil) }()
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

func TestExecDetachedPreservesLargeArgumentVector(t *testing.T) {
	args := []string{"sh", "-c", `printf '%s:%s' "$#" "${64}"`, "sh"}
	for range 64 {
		args = append(args, strings.Repeat("x", 4095))
	}
	r := Run(context.Background(), tape.Tape{Version: 2, Target: "demo"}, Options{
		Command: args, DetachStdio: true, AllowZeroTraffic: true, TailBytes: 8192,
		Timeout: 10 * time.Second,
	})
	if r.Error != nil || r.Exec.ExitCode != 0 || r.Exec.StdoutTail != "64:"+strings.Repeat("x", 4095) {
		t.Fatalf("large argv failed: error=%v exit=%d output=%q", r.Error, r.Exec.ExitCode, r.Exec.StdoutTail)
	}
}

func TestExecDetachedStalledHelperIsKilledAndReaped(t *testing.T) {
	if marker := os.Getenv("GD_TEST_STALLED_HELPER"); marker != "" {
		target := marker + ".target"
		r := Run(context.Background(), tape.Tape{Version: 2, Target: "demo"}, Options{
			Command:     []string{"sh", "-c", `touch "$1"`, "sh", target},
			DetachStdio: true, AllowZeroTraffic: true, Timeout: 200 * time.Millisecond,
		})
		data, err := os.ReadFile(marker)
		if err != nil {
			t.Fatalf("helper never reached pre-ready stall: %v", err)
		}
		pid, err := strconv.Atoi(string(data))
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
			t.Fatalf("helper %d not reaped: %v", pid, err)
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatalf("target started: stat error %v", err)
		}
		if !r.Exec.TimedOut && r.ExitCode != 124 {
			t.Fatalf("expected timeout, got exit=%d error=%v", r.ExitCode, r.Error)
		}
		return
	}
	marker := filepath.Join(t.TempDir(), "helper-pid")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExecDetachedStalledHelperIsKilledAndReaped$")
	cmd.Env = append(os.Environ(), "GD_TEST_STALLED_HELPER="+marker)
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if data, readErr := os.ReadFile(marker); readErr == nil {
		if pid, parseErr := strconv.Atoi(string(data)); parseErr == nil {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	} else {
		t.Fatalf("helper did not start: %v; output: %s", readErr, out)
	}
	if err != nil {
		t.Fatalf("stalled helper was not handled: %v; output: %s", err, out)
	}
}
