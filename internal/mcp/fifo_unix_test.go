//go:build unix

package mcp

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestTapeRejectsFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(nil, nil, Options{Workdir: dir}).readTape("pipe"); err == nil {
		t.Fatal("accepted FIFO")
	}
}
