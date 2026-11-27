//go:build windows

package execrun

import (
	"os/exec"
	"syscall"
	"time"
)

func setupProcess(cmd *exec.Cmd, grace time.Duration) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
	cmd.WaitDelay = grace
	return nil
}
func cleanupProcess(cmd *exec.Cmd, grace time.Duration) []int { return nil }
func forwardSignals(cmd *exec.Cmd) func()                     { return func() {} }
