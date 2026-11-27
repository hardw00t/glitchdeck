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
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = grace
	return nil
}
func cleanupProcess(cmd *exec.Cmd, grace time.Duration) []int {
	if !ownsChildren() {
		return nil
	}
	return cleanupOwnedProcess(cmd, grace)
}
func cleanupOwnedProcess(cmd *exec.Cmd, grace time.Duration) []int {
	if cmd.Process == nil {
		return nil
	}
	pgid := cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	deadline := time.Now().Add(grace)
	for syscall.Kill(-pgid, 0) == nil && time.Now().Before(deadline) {
		for {
			var status syscall.WaitStatus
			pid, _ := syscall.Wait4(-pgid, &status, syscall.WNOHANG, nil)
			if pid <= 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	leaked := reapChildren()
	deadline = time.Now().Add(2 * time.Second)
	for syscall.Kill(-pgid, 0) == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if syscall.Kill(-pgid, 0) == nil {
		leaked = append(leaked, pgid)
	}
	return leaked
}
func forwardSignals(grace time.Duration) (func(*exec.Cmd), func()) {
	signals := make(chan os.Signal, 2)
	done := make(chan struct{})
	ready := make(chan *exec.Cmd, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		var cmd *exec.Cmd
		var pending []os.Signal
		count := 0
		forward := func(s os.Signal) {
			count++
			sig := s.(syscall.Signal)
			if count > 1 {
				if grace > 0 {
					sig = syscall.SIGKILL
				} else {
					sig = syscall.SIGTERM
				}
			}
			_ = syscall.Kill(-cmd.Process.Pid, sig)
			if count == 1 && grace > 0 {
				pgid := cmd.Process.Pid
				go func() {
					timer := time.NewTimer(grace)
					defer timer.Stop()
					select {
					case <-timer.C:
						_ = syscall.Kill(-pgid, syscall.SIGKILL)
					case <-done:
					}
				}()
			}
		}
		for {
			select {
			case cmd = <-ready:
				for _, s := range pending {
					forward(s)
				}
				pending = nil
			case s := <-signals:
				if cmd == nil {
					pending = append(pending, s)
					continue
				}
				forward(s)
			case <-done:
				return
			}
		}
	}()
	return func(cmd *exec.Cmd) { ready <- cmd }, func() { signal.Stop(signals); close(done) }
}
