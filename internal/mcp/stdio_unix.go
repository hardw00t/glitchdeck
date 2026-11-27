//go:build unix

package mcp

import (
	"os"
	"syscall"
)

// OwnedStdioOutput returns a pollable duplicate that can be closed on cancellation.
func OwnedStdioOutput() (*os.File, error) {
	fd, err := syscall.Dup(int(os.Stdout.Fd()))
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(fd)
	if err = syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "mcp-stdout"), nil
}
