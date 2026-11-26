package demo

import (
	"bufio"
	"encoding/json"
	"fmt"
	"glitchdeck/internal/wsframe"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCheckoutChargesOnlyWhenRequested(t *testing.T) {
	h := New()
	for _, body := range []string{`{"order_id":"a","amount_cents":100}`, `{"order_id":"a","amount_cents":100,"charge":true}`, `{"order_id":"a","amount_cents":100,"charge":true}`} {
		r := httptest.NewRequest("POST", "/checkout", strings.NewReader(body))
		r.Host = "127.0.0.1"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("checkout: %d", w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/state", nil))
	var state struct {
		Orders     []json.RawMessage `json:"orders"`
		Charges    []json.RawMessage `json:"charges"`
		Duplicates int               `json:"duplicate_charges"`
		Total      int               `json:"total_charged_cents"`
		Broken     bool              `json:"ws_broken"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Orders) != 3 || len(state.Charges) != 2 || state.Duplicates != 1 || state.Total != 200 || state.Broken {
		t.Fatalf("state: %+v", state)
	}
}

func TestRejectCrossOriginMutations(t *testing.T) {
	h := New()
	for _, path := range []string{"/checkout", "/webhooks/payment", "/api/reset"} {
		r := httptest.NewRequest("POST", "http://127.0.0.1"+path, strings.NewReader(`{}`))
		r.Header.Set("Origin", "http://localhost:9")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
}

func TestRejectInvalidWebSocketHandshake(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws/ticker", nil)
	r.Host = "localhost"
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Sec-WebSocket-Key", "invalid")
	w := httptest.NewRecorder()
	New().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("status %d", w.Code)
	}
}

func TestTickerRejectsUntrustedUpgrade(t *testing.T) {
	h := New()
	for _, tc := range []struct{ host, origin string }{
		{"127.0.0.1:3000", "http://localhost:8081"},
		{net.JoinHostPort(strings.Repeat("x", 7), "3000"), ""},
	} {
		req := httptest.NewRequest(http.MethodGet, "/ws/ticker", nil)
		req.Host = tc.host
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", "MDEyMzQ1Njc4OWFiY2RlZg==")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("host %q origin %q: status %d, want 403", tc.host, tc.origin, rec.Code)
		}
	}
}

func TestTickerPingAndClose(t *testing.T) {
	s := httptest.NewServer(New())
	defer s.Close()
	c, err := net.Dial("tcp", s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	fmt.Fprintf(c, "GET /ws/ticker HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\n\r\n", s.Listener.Addr())
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, &http.Request{Method: "GET"})
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("handshake: %v %v", resp, err)
	}
	if err := wsframe.Write(c, wsframe.Frame{Fin: true, Opcode: 9, Payload: []byte("ping")}, true); err != nil {
		t.Fatal(err)
	}
	frame, err := wsframe.Read(r, false)
	if err != nil || frame.Opcode != 10 || string(frame.Payload) != "ping" {
		t.Fatalf("pong: %v %v", frame, err)
	}
	if err := wsframe.Write(c, wsframe.Frame{Fin: true, Opcode: 8}, true); err != nil {
		t.Fatal(err)
	}
	frame, err = wsframe.Read(r, false)
	if err != nil || frame.Opcode != 8 {
		t.Fatalf("close: %v %v", frame, err)
	}
}
