//go:build !windows

package execrun

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

func setupProcess(cmd *exec.Cmd, grace time.Duration) error {
	if err := subreaper(); err != nil {
		return err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = grace
	return nil
}
func cleanupProcess(cmd *exec.Cmd, grace time.Duration) []int {
	if cmd.Process == nil {
		return nil
	}
	pgid := cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	deadline := time.Now().Add(grace)
	for syscall.Kill(-pgid, 0) == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	leaked := reapChildren()
	if syscall.Kill(-pgid, 0) == nil {
		leaked = append(leaked, pgid)
	}
	return leaked
}
func forwardSignals(cmd *exec.Cmd) func() {
	signals := make(chan os.Signal, 2)
	done := make(chan struct{})
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		count := 0
		for {
			select {
			case s := <-signals:
				count++
				sig := s.(syscall.Signal)
				if count > 1 {
					sig = syscall.SIGKILL
				}
				_ = syscall.Kill(-cmd.Process.Pid, sig)
			case <-done:
				return
			}
		}
	}()
	return func() { signal.Stop(signals); close(done) }
}
