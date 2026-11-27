package h2tap

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestResetAfterPendingData(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	c := New(server)
	defer c.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	frame := appendFrame(nil, frameData, 0, 1, []byte("final"))
	if _, err := c.Write(frame[:frameHead+2]); err != nil {
		t.Fatal(err)
	}
	done := c.ResetAfterData(1, 2, 5)
	select {
	case <-done:
		t.Fatal("reset before final DATA")
	default:
	}
	errch := make(chan error, 1)
	go func() { _, err := c.Write(frame[frameHead+2:]); errch <- err }()
	h, b, err := ReadFrame(client)
	if err != nil || h.Type != frameData || string(b) != "final" {
		t.Fatalf("DATA: %+v %q %v", h, b, err)
	}
	h, b, err = ReadFrame(client)
	if err != nil || h.Type != frameRST || h.Stream != 1 || len(b) != 4 || binary.BigEndian.Uint32(b) != 2 {
		t.Fatalf("RST: %+v %x %v", h, b, err)
	}
	if err := <-errch; err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reset did not complete")
	}
}

func TestResetAfterAlreadyForwardedAndPendingData(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	c := New(server)
	defer c.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	first := appendFrame(nil, frameData, 0, 1, []byte("first"))
	written := make(chan error, 1)
	go func() { _, err := c.Write(first); written <- err }()
	if _, _, err := ReadFrame(client); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	done := c.ResetAfterData(1, 2, 10)
	select {
	case <-done:
		t.Fatal("reset before remaining DATA")
	default:
	}
	last := appendFrame(nil, frameData, 0, 1, []byte("final"))
	go func() { _, err := c.Write(last); written <- err }()
	h, b, err := ReadFrame(client)
	if err != nil || h.Type != frameData || string(b) != "final" {
		t.Fatalf("DATA: %+v %q %v", h, b, err)
	}
	h, b, err = ReadFrame(client)
	if err != nil || h.Type != frameRST || len(b) != 4 || binary.BigEndian.Uint32(b) != 2 {
		t.Fatalf("RST: %+v %x %v", h, b, err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reset did not complete")
	}
}
