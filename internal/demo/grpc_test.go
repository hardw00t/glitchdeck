package demo

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestQuoteGRPCOverH2C(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: New(), Protocols: Protocols()}
	go srv.Serve(ln)
	defer srv.Close()
	proto := new(http.Protocols)
	proto.SetUnencryptedHTTP2(true)
	client := &http.Client{Transport: &http.Transport{Protocols: proto}, Timeout: 2 * time.Second}
	resp, err := client.Post("http://"+ln.Addr().String()+"/glitchdeck.demo.v1.Quotes/Get", "application/grpc", bytes.NewReader([]byte{0, 0, 0, 0, 6, 10, 4, 'A', 'C', 'M', 'E'}))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || resp.ProtoMajor != 2 || resp.Trailer.Get("Grpc-Status") != "0" || !bytes.Contains(b, []byte("ACME")) {
		t.Fatalf("body %x proto %s trailers %v err %v", b, resp.Proto, resp.Trailer, err)
	}
}
