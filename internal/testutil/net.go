package testutil

import (
	"net"
	"testing"
	"time"
)

// RefusedTCPAddr reserves a loopback port with an outgoing connection, not a listener.
func RefusedTCPAddr(t testing.TB) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	conn, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn.LocalAddr().String()
}
