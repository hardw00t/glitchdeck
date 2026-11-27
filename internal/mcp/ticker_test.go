package mcp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/wsframe"
)

func TestTickerValidatesCompleteMessages(t *testing.T) {
	for _, tc := range []struct {
		name      string
		frames    []wsframe.Frame
		wantError bool
	}{
		{"invalid", []wsframe.Frame{{Fin: true, Opcode: 1, Payload: []byte("not json")}}, true},
		{"fragmented", []wsframe.Frame{{Opcode: 1, Payload: []byte(`{"seq":`)}, {Fin: true, Opcode: 9}, {Fin: true, Opcode: 0, Payload: []byte(`1}`)}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := l.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				r := bufio.NewReader(c)
				if _, err := http.ReadRequest(r); err != nil {
					return
				}
				fmt.Fprint(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
				for _, frame := range tc.frames {
					if wsframe.Write(c, frame, false) != nil {
						return
					}
				}
				for {
					frame, err := wsframe.Read(r, true)
					if err != nil || frame.Opcode == 8 {
						return
					}
				}
			}()
			s := &Server{ctx: context.Background(), proxyURL: "http://" + l.Addr().String()}
			err = s.ticker(1)
			if (err != nil) != tc.wantError {
				t.Fatalf("ticker: %v", err)
			}
			<-done
		})
	}
}
