package demo

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"glitchdeck/internal/wsframe"
)

type entry struct {
	OrderID     string `json:"order_id"`
	AmountCents int    `json:"amount_cents"`
	Duplicate   bool   `json:"duplicate"`
}
type service struct {
	mu      sync.Mutex
	orders  []entry
	charges []entry
	ticks   int
}

func New() http.Handler {
	s := &service{orders: []entry{}, charges: []entry{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/checkout", s.checkout)
	mux.HandleFunc("/webhooks/payment", s.payment)
	mux.HandleFunc("/api/state", s.state)
	mux.HandleFunc("/api/reset", s.reset)
	mux.HandleFunc("/ws/ticker", s.ticker)
	return mux
}
func (s *service) charge(e entry) {
	for _, old := range s.charges {
		if old.OrderID == e.OrderID {
			e.Duplicate = true
			break
		}
	}
	s.charges = append(s.charges, e)
}
func (s *service) checkout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var v struct {
		OrderID     string `json:"order_id"`
		AmountCents int    `json:"amount_cents"`
		Charge      bool   `json:"charge"`
	}
	if json.NewDecoder(r.Body).Decode(&v) != nil || v.OrderID == "" || v.AmountCents < 0 {
		http.Error(w, "invalid order", 400)
		return
	}
	e := entry{OrderID: v.OrderID, AmountCents: v.AmountCents}
	s.mu.Lock()
	for _, old := range s.orders {
		if old.OrderID == e.OrderID {
			e.Duplicate = true
			break
		}
	}
	s.orders = append(s.orders, e)
	if v.Charge {
		s.charge(entry{OrderID: v.OrderID, AmountCents: v.AmountCents})
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"order_id": v.OrderID, "receipt": strings.Repeat(" ", 2048)})
}
func (s *service) payment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var e entry
	if json.NewDecoder(r.Body).Decode(&e) != nil || e.OrderID == "" || e.AmountCents < 0 {
		http.Error(w, "invalid payment", 400)
		return
	}
	e.Duplicate = false
	s.mu.Lock()
	s.charge(e)
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}
func (s *service) state(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	total, duplicates := 0, 0
	for _, c := range s.charges {
		total += c.AmountCents
		if c.Duplicate {
			duplicates++
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"orders": s.orders, "charges": s.charges, "duplicate_charges": duplicates, "total_charged_cents": total, "ws_ticks_sent": s.ticks, "ws_broken": false})
}
func (s *service) reset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	s.mu.Lock()
	s.orders = []entry{}
	s.charges = []entry{}
	s.ticks = 0
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}
func (s *service) ticker(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || r.Header.Get("Sec-WebSocket-Key") == "" {
		http.Error(w, "websocket required", 400)
		return
	}
	h, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "upgrade unavailable", 500)
		return
	}
	conn, rw, err := h.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsframe.AcceptKey(r.Header.Get("Sec-WebSocket-Key")))
	if rw.Flush() != nil {
		return
	}
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		s.ticks++
		seq, orders := s.ticks, len(s.orders)
		s.mu.Unlock()
		payload, _ := json.Marshal(map[string]any{"seq": seq, "price": 10000 + seq, "orders": orders})
		if err := wsframe.Write(conn, wsframe.Frame{Fin: true, Opcode: 1, Payload: payload}, false); err != nil {
			return
		}
	}
}
