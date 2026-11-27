//go:build linux && (amd64 || arm64)

package main

import "syscall"

func closeInheritedRange() bool {
	const sysCloseRange, closeRangeCloexec = 436, 1 << 2
	_, _, errno := syscall.Syscall(sysCloseRange, 3, uintptr(^uint32(0)), closeRangeCloexec)
	return errno == 0
}
