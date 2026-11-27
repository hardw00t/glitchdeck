package proxy

import (
	"bufio"
	"crypto/tls"
	"net"
	"testing"
)

func TestInterceptReportsSNIBeforeVersionNegotiation(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	name := make(chan string, 1)
	go func() {
		f := &front{}
		f.intercept(server, bufio.NewReader(server), "example.test:443", "example.test", "", func(s string, _ error) { name <- s })
	}()
	c := tls.Client(client, &tls.Config{ServerName: "named.example", MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11})
	_ = c.Handshake()
	if got := <-name; got != "named.example" {
		t.Fatalf("SNI = %q", got)
	}
}
