//go:build unix

package execrun

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/tape"
)

func TestDetachedRunLetsCallerOwnSignals(t *testing.T) {
	if os.Getenv("GD_TEST_SIGNAL_OWNER") == "1" {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM)
		defer signal.Stop(signals)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan Envelope, 1)
		go func() {
			done <- Run(ctx, tape.Tape{Version: 2}, Options{
				Command:     []string{"sh", "-c", `trap 'exit 0' TERM; echo ready > ready; while :; do sleep 0.02; done`},
				DetachStdio: true, AllowZeroTraffic: true, Timeout: 10 * time.Second,
			})
		}()
		select {
		case <-signals:
		case <-time.After(5 * time.Second):
			t.Fatal("parent did not deliver the signal")
		}
		select {
		case <-done:
			t.Fatal("executor relayed the signal before its caller cancelled")
		case <-time.After(400 * time.Millisecond):
		}
		cancel()
		select {
		case r := <-done:
			if len(r.Exec.LeakedPIDs) != 0 {
				t.Fatal(r.Exec.LeakedPIDs)
			}
		case <-time.After(4 * time.Second):
			t.Fatal("caller cancellation did not stop detached execution")
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDetachedRunLetsCallerOwnSignals$")
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "GD_TEST_SIGNAL_OWNER=1", "GORACE=atexit_sleep_ms=0")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	ready := filepath.Join(cmd.Dir, "ready")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) || time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatalf("waiting for detached execution: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}
