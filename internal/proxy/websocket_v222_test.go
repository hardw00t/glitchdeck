package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
	"github.com/hardw00t/glitchdeck/internal/wsframe"
)

func TestPumpFrameClasses(t *testing.T) {
	for _, tc := range []struct {
		class       string
		input, want []byte
	}{
		{"data", []byte{9, 1, 9, 1, 9, 1}, []byte{9, 1, 9, 9, 1}},
		{"control", []byte{9, 1, 9, 1, 9, 1}, []byte{9, 1, 1, 9, 1}},
		{"all", []byte{9, 9, 1}, []byte{9, 1}},
	} {
		t.Run(tc.class, func(t *testing.T) {
			cfg := fault.Config{Rules: []fault.Rule{{ID: "ws", Enabled: true, Fault: fault.Fault{Type: "ws-glitch", Params: map[string]any{"dir": "s2c", "action": "drop", "frames": tc.class, "after_frames": 2, "every": 1000}}}}}
			p := New(nil, cfg, nil)
			defer p.Close()
			var input bytes.Buffer
			for _, op := range tc.input {
				if err := wsframe.Write(&input, wsframe.Frame{Fin: true, Opcode: op, Payload: []byte("a")}, false); err != nil {
					t.Fatal(err)
				}
			}
			a, b := net.Pipe()
			defer b.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				p.pump(context.Background(), &input, &wsWriter{conn: a}, false, "s2c", 0, fault.Query{Seq: 1, WS: true}, func(string) { a.Close() }, func() {}, func(string, string, error) {})
			}()
			var got []byte
			for {
				f, err := wsframe.Read(b, false)
				if err != nil {
					break
				}
				got = append(got, f.Opcode)
			}
			<-done
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestPumpDataLeavesCloseUntouched(t *testing.T) {
	for _, action := range []string{"drop", "corrupt"} {
		t.Run(action, func(t *testing.T) {
			cfg := fault.Config{Rules: []fault.Rule{{ID: "ws", Enabled: true, Fault: fault.Fault{Type: "ws-glitch", Params: map[string]any{"action": action, "frames": "data"}}}}}
			p := New(nil, cfg, nil)
			defer p.Close()
			var input bytes.Buffer
			_ = wsframe.Write(&input, wsframe.Frame{Fin: true, Opcode: 8, Payload: []byte{0x0f, 0xa0}}, false)
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				p.pump(context.Background(), &input, &wsWriter{conn: a}, false, "s2c", 0, fault.Query{Seq: 1, WS: true}, func(string) { a.Close() }, func() {}, func(string, string, error) {})
			}()
			f, err := wsframe.Read(b, false)
			if err != nil || f.Opcode != 8 || binary.BigEndian.Uint16(f.Payload) != 4000 {
				t.Fatalf("close %#v, %v", f, err)
			}
			<-done
		})
	}
}

func TestCorruptInvalidCloseReportsFault(t *testing.T) {
	cfg := fault.Config{Seed: 13, Rules: []fault.Rule{{ID: "ws", Enabled: true, Fault: fault.Fault{Type: "ws-glitch", Params: map[string]any{"action": "corrupt"}}}}}
	p := New(nil, cfg, nil)
	defer p.Close()
	var input bytes.Buffer
	_ = wsframe.Write(&input, wsframe.Frame{Fin: true, Opcode: 8, Payload: []byte{0x0f, 0xa0}}, false)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	errors := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.pump(context.Background(), &input, &wsWriter{conn: a}, false, "s2c", 0, fault.Query{Seq: 1, WS: true}, func(string) {}, func() {}, func(_ string, code string, _ error) { errors <- code })
	}()
	select {
	case code := <-errors:
		if code != "invalid_after_fault" {
			t.Fatalf("error %q", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no invalid-after-fault error")
	}
	<-done
}

type cancelOnErrorContext struct {
	context.Context
	cancel context.CancelFunc
}

func (c cancelOnErrorContext) Err() error {
	c.cancel()
	return c.Context.Err()
}

func TestWebSocketCancellationDuringFailureClosesBothPumps(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	client, clientPeer := net.Pipe()
	up, upPeer := net.Pipe()
	defer client.Close()
	defer clientPeer.Close()
	defer up.Close()
	defer upPeer.Close()
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := cancelOnErrorContext{Context: base, cancel: cancel}
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.coordinateWS(ctx, cancel, client, up, client, bytes.NewReader([]byte{0xc1, 0}), 0, fault.Query{Seq: 1})
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("coordinator did not exit after cancellation during error handling")
	}
}

func FuzzPumpFrames(f *testing.F) {
	f.Add([]byte{0x81, 0x01, 'a'}, false)
	f.Add([]byte{0x81, 126, 0, 1}, false)
	f.Add([]byte{0x88, 2, 3, 232}, false)
	f.Add([]byte{0xc1, 0}, true)
	f.Fuzz(func(t *testing.T, data []byte, cancelEarly bool) {
		if len(data) > 65536 {
			t.Skip()
		}
		p := New(nil, fault.Config{}, nil)
		defer p.Close()
		client, clientPeer := net.Pipe()
		up, upPeer := net.Pipe()
		defer client.Close()
		defer clientPeer.Close()
		defer up.Close()
		defer upPeer.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		clientDrained := make(chan struct{})
		upDrained := make(chan struct{})
		go func() {
			defer close(done)
			p.coordinateWS(ctx, cancel, client, up, client, bytes.NewReader(data), 0, fault.Query{Seq: 1})
		}()
		go func() { defer close(clientDrained); _, _ = io.Copy(io.Discard, clientPeer) }()
		go func() { defer close(upDrained); _, _ = io.Copy(io.Discard, upPeer) }()
		if cancelEarly {
			cancel()
		}
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		for _, ch := range []<-chan struct{}{done, clientDrained, upDrained} {
			select {
			case <-ch:
			case <-timer.C:
				t.Fatal("websocket coordinator or peer did not exit")
			}
		}
	})
}

func TestWebSocketMalformedFrameClosesBothPeers(t *testing.T) {
	cases := []struct {
		name       string
		wire       []byte
		fromClient bool
		code       uint16
		event      string
		declared   uint64
	}{
		{"oversized", []byte{0x82, 127, 0, 0, 0, 0, 0, 0x40, 0, 1}, false, 1009, "frame_too_large", 4194305},
		{"rsv", []byte{0xc1, 0}, false, 1002, "protocol_error", 0},
		{"unmasked client", []byte{0x81, 0}, true, 1002, "protocol_error", 0},
		{"noncanonical", []byte{0x81, 126, 0, 1}, false, 1002, "protocol_error", 1},
		{"length", []byte{0x81, 127, 0x80, 0, 0, 0, 0, 0, 0, 0}, false, 1002, "protocol_error", 0},
		{"opcode", []byte{0x83, 1}, false, 1002, "protocol_error", 1},
		{"fragmented ping", []byte{0x09, 1}, false, 1002, "protocol_error", 1},
		{"masked opcode before mask", []byte{0x83, 0x81}, true, 1002, "protocol_error", 1},
		{"opcode before extended length", []byte{0x83, 126}, false, 1002, "protocol_error", 0},
		{"fragmented ping before extended length", []byte{0x09, 127}, false, 1002, "protocol_error", 0},
		{"large ping", []byte{0x89, 126, 0, 126}, false, 1002, "protocol_error", 126},
		{"close code", []byte{0x88, 2, 3, 0xed}, false, 1002, "protocol_error", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := make(chan struct{})
			upstreamClose := make(chan wsframe.Frame, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer c.Close()
				_, _ = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsframe.AcceptKey(r.Header.Get("Sec-WebSocket-Key")))
				if rw.Flush() != nil {
					return
				}
				<-start
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				if !tc.fromClient {
					_, _ = c.Write(tc.wire)
				}
				f, _ := wsframe.Read(rw.Reader, true)
				upstreamClose <- f
			}))
			defer upstream.Close()
			target, _ := url.Parse(upstream.URL)
			bus := telemetry.New()
			p := New(target, fault.Config{}, bus)
			defer p.Close()
			outcomes := make(chan Outcome, 1)
			p.OnOutcome = func(o Outcome) {
				if o.Err != nil {
					outcomes <- o
				}
			}
			server := httptest.NewServer(p)
			defer server.Close()
			c, err := net.Dial("tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = fmt.Fprint(c, "GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\n\r\n")
			reader := bufio.NewReader(c)
			resp, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
			if err != nil || resp.StatusCode != 101 {
				t.Fatalf("handshake: %v %v", resp, err)
			}
			close(start)
			if tc.fromClient {
				_, _ = c.Write(tc.wire)
			}
			got, err := wsframe.Read(reader, false)
			if err != nil || got.Opcode != 8 || len(got.Payload) < 2 || binary.BigEndian.Uint16(got.Payload) != tc.code {
				t.Fatalf("client close: %#v %v", got, err)
			}
			up := <-upstreamClose
			if up.Opcode != 8 || len(up.Payload) < 2 || binary.BigEndian.Uint16(up.Payload) != tc.code {
				t.Fatalf("upstream close: %#v", up)
			}
			outcome := <-outcomes
			frameErr, ok := outcome.Err.(*FrameError)
			if !ok || frameErr.Code != tc.event || frameErr.Declared != tc.declared {
				t.Fatalf("outcome: %#v", outcome.Err)
			}
			found := false
			for _, e := range bus.History(100) {
				if e.Type != "ws_frame" {
					continue
				}
				var v map[string]any
				_ = json.Unmarshal(e.Data, &v)
				if v["error"] == tc.event {
					found = true
					if v["declared_bytes"] != float64(tc.declared) || v["ts_ms"] == nil || v["ts_ms"].(float64) <= 0 {
						t.Fatalf("event: %s", e.Data)
					}
				}
			}
			if !found {
				t.Fatal("missing error event")
			}
		})
	}
}

func TestWSWriterAllowsSlowPeer(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() {
		done <- (&wsWriter{conn: a}).write(wsframe.Frame{Fin: true, Opcode: 1, Payload: []byte("slow")})
	}()
	time.Sleep(1100 * time.Millisecond)
	if _, err := wsframe.Read(b, false); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("slow peer disconnected: %v", err)
	}
}

func TestWSWriterPreservesCloseDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	deadline := time.Now().Add(100 * time.Millisecond)
	if err := a.SetWriteDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	w := &wsWriter{conn: a}
	done := make(chan error, 1)
	go func() { done <- w.write(wsframe.Frame{Fin: true, Opcode: 1, Payload: []byte("one")}) }()
	if _, err := wsframe.Read(b, false); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := w.write(wsframe.Frame{Fin: true, Opcode: 1, Payload: []byte("two")})
	if err == nil || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("close deadline lost: %v", err)
	}
}

func TestWSWriterRejectsFramesAfterClose(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	w := &wsWriter{conn: a}
	done := make(chan error, 1)
	go func() { done <- w.write(wsframe.Frame{Fin: true, Opcode: 8}) }()
	if f, err := wsframe.Read(b, false); err != nil || f.Opcode != 8 {
		t.Fatalf("close: %#v %v", f, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = a.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	if err := w.write(wsframe.Frame{Fin: true, Opcode: 1}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
}

func TestWSWriterTruncateAllowsSlowPeer(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	done := make(chan struct{})
	go func() { (&wsWriter{conn: a}).truncate([]byte("x")); close(done) }()
	time.Sleep(1100 * time.Millisecond)
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := io.ReadFull(b, buf); err != nil || string(buf) != "x" {
		t.Fatalf("truncated write: %q %v", buf, err)
	}
	<-done
}

func TestWebSocketCloseDeadlineIsNotProtocolError(t *testing.T) {
	received := make(chan error, 1)
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			received <- err
			return
		}
		defer c.Close()
		_, _ = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsframe.AcceptKey(r.Header.Get("Sec-WebSocket-Key")))
		_ = rw.Flush()
		f, err := wsframe.Read(rw.Reader, true)
		if err == nil && f.Opcode != 8 {
			err = fmt.Errorf("got opcode %d", f.Opcode)
		}
		received <- err
		<-release
	}))
	defer upstream.Close()
	defer close(release)
	target, _ := url.Parse(upstream.URL)
	p := New(target, fault.Config{}, nil)
	defer p.Close()
	outcomes := make(chan Outcome, 1)
	p.OnOutcome = func(o Outcome) {
		if o.Err != nil {
			outcomes <- o
		}
	}
	server := httptest.NewServer(p)
	defer server.Close()
	c, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprint(c, "GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\n\r\n")
	reader := bufio.NewReader(c)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("handshake: %v %v", resp, err)
	}
	if err := wsframe.Write(c, wsframe.Frame{Fin: true, Opcode: 8}, true); err != nil {
		t.Fatal(err)
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
	if frame, err := wsframe.Read(reader, false); err != io.EOF {
		t.Fatalf("expected close deadline EOF, got %#v %v", frame, err)
	}
	select {
	case o := <-outcomes:
		t.Fatalf("normal close reported error: %v", o.Err)
	default:
	}
}

func TestPumpSanitizesReadErrors(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	reported := make(chan error, 1)
	p.pump(context.Background(), errorReader{}, &wsWriter{conn: a}, false, "s2c", 0, fault.Query{Seq: 1}, func(string) {}, func() {}, func(_ string, _ string, err error) { reported <- err })
	if err := <-reported; err.Error() != "websocket read failed" {
		t.Fatalf("unsafe error: %v", err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, fmt.Errorf("read tcp 192.0.2.1:1234: private socket error")
}
