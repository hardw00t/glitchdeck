package mcp

import (
	"bytes"
	"os"
	"testing"
	"time"
)

func TestWindowsBlockedStdioClose(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	stdout := os.Stdout
	os.Stdout = w
	out, err := OwnedStdioOutput()
	os.Stdout = stdout
	if err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() { _, err := out.Write(bytes.Repeat([]byte("x"), 1<<20)); written <- err }()
	select {
	case err := <-written:
		t.Fatalf("pipe write did not block: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	closed := make(chan error, 1)
	go func() { closed <- out.Close() }()
	select {
	case <-written:
	case <-time.After(3 * time.Second):
		t.Fatal("write was not canceled")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close did not finish")
	}
}
