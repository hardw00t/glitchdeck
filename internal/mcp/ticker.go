package mcp

import (
	"bufio"
	"context"
	"encoding/json"
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
	var message []byte
	fragmented := false
	for received := 0; received < frames; {
		frame, err := wsframe.Read(reader, false)
		if err != nil {
			return err
		}
		switch frame.Opcode {
		case 8:
			return fmt.Errorf("websocket closed")
		case 9:
			if err := wsframe.Write(conn, wsframe.Frame{Fin: true, Opcode: 10, Payload: frame.Payload}, true); err != nil {
				return err
			}
			continue
		case 10:
			continue
		case 1:
			if fragmented {
				return fmt.Errorf("unexpected websocket message")
			}
			message = message[:0]
		case 0:
			if !fragmented {
				return fmt.Errorf("unexpected websocket continuation")
			}
		default:
			return fmt.Errorf("unexpected websocket message type")
		}
		if len(message)+len(frame.Payload) > wsframe.MaxPayload {
			return fmt.Errorf("websocket message too large")
		}
		message = append(message, frame.Payload...)
		fragmented = !frame.Fin
		if frame.Fin {
			if !json.Valid(message) {
				return fmt.Errorf("invalid ticker JSON")
			}
			received++
		}
	}
	return wsframe.Write(conn, wsframe.Frame{Fin: true, Opcode: 8, Payload: []byte{3, 232}}, true)
}
