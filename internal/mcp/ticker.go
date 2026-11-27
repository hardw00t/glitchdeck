package mcp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/hardw00t/glitchdeck/internal/wsframe"
)

func (s *Server) ticker(frames int) error {
	u, err := url.Parse(s.proxyURL)
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", u.Host, 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(frames)*400*time.Millisecond + 5*time.Second))
	stop := context.AfterFunc(s.ctx, func() { _ = conn.Close() })
	defer stop()
	_, err = fmt.Fprintf(conn, "GET /ws/ticker HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", u.Host)
	if err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil {
		return err
	}
	if resp.StatusCode != 101 {
		return fmt.Errorf("websocket status %d", resp.StatusCode)
	}
	for range frames {
		frame, err := wsframe.Read(reader, false)
		if err != nil {
			return err
		}
		if frame.Opcode == 8 {
			return fmt.Errorf("websocket closed")
		}
	}
	return wsframe.Write(conn, wsframe.Frame{Fin: true, Opcode: 8, Payload: []byte{3, 232}}, true)
}
