//go:build unix

package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

func closeInheritedOnExec() error {
	if closeInheritedRange() {
		return nil
	}
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			fd, err := strconv.Atoi(entry.Name())
			if err == nil && fd > 2 {
				_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, syscall.FD_CLOEXEC)
				if errno != 0 && errno != syscall.EBADF {
					return fmt.Errorf("mark inherited file descriptor close-on-exec: %w", errno)
				}
			}
		}
		return nil
	}
	return fmt.Errorf("cannot inspect inherited file descriptors")
}
