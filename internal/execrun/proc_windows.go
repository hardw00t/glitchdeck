//go:build windows

package execrun

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

const caReadFlags = os.O_RDONLY

func setupProcess(cmd *exec.Cmd, grace time.Duration) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
	cmd.WaitDelay = grace
	return nil
}
func cleanupProcess(cmd *exec.Cmd, grace time.Duration) []int { return nil }
func forwardSignals(grace time.Duration) (func(*exec.Cmd), func()) {
	return func(*exec.Cmd) {}, func() {}
}
func isolateProcess(cmd *exec.Cmd, grace time.Duration) (*os.File, *os.File, error) {
	return nil, nil, nil
}
