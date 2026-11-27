package mcp

import (
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
)

var cancelSynchronousIO = syscall.NewLazyDLL("kernel32.dll").NewProc("CancelSynchronousIo")

type ownedStdioOutput struct {
	file   *os.File
	mu     sync.Mutex
	thread syscall.Handle
	closed bool
}

// OwnedStdioOutput returns a cancellable duplicate of stdout.
func OwnedStdioOutput() (*ownedStdioOutput, error) {
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return nil, err
	}
	var handle syscall.Handle
	if err := syscall.DuplicateHandle(process, syscall.Handle(os.Stdout.Fd()), process, &handle, 0, false, syscall.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, err
	}
	return &ownedStdioOutput{file: os.NewFile(uintptr(handle), "mcp-stdout")}, nil
}

func (o *ownedStdioOutput) Write(p []byte) (int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return 0, os.ErrClosed
	}
	process, err := syscall.GetCurrentProcess()
	if err == nil {
		err = syscall.DuplicateHandle(process, syscall.Handle(^uintptr(1)), process, &o.thread, 0, false, syscall.DUPLICATE_SAME_ACCESS)
	}
	if err != nil {
		o.mu.Unlock()
		return 0, err
	}
	o.mu.Unlock()
	n, err := o.file.Write(p)
	o.mu.Lock()
	syscall.CloseHandle(o.thread)
	o.thread = 0
	o.mu.Unlock()
	return n, err
}

func (o *ownedStdioOutput) Close() error {
	for {
		o.mu.Lock()
		o.closed = true
		if o.thread == 0 {
			o.mu.Unlock()
			return o.file.Close()
		}
		cancelSynchronousIO.Call(uintptr(o.thread))
		o.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
}
