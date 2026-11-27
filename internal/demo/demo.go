package demo

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hardw00t/glitchdeck/internal/localweb"
	"github.com/hardw00t/glitchdeck/internal/wsframe"
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
	llm     map[string]int
	mux     *http.ServeMux
	sockets map[net.Conn]struct{}
	closed  bool
}

func New() http.Handler {
	s := &service{orders: []entry{}, charges: []entry{}, llm: map[string]int{}, sockets: map[net.Conn]struct{}{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/checkout", s.checkout)
	mux.HandleFunc("/webhooks/payment", s.payment)
	mux.HandleFunc("/api/state", s.state)
	mux.HandleFunc("/api/summary", s.summary)
	mux.HandleFunc("/api/reset", s.reset)
	mux.HandleFunc("/ws/ticker", s.ticker)
	mux.HandleFunc("/api/chat/stream", s.stream)
	mux.HandleFunc("/v1/chat/completions", s.stream)
	mux.HandleFunc("/v1/messages", s.stream)
	mux.HandleFunc("/v1/responses", s.stream)
	mux.HandleFunc("/v1beta/models/", s.stream)
	mux.HandleFunc("/api/stream-result", s.streamResult)
	mux.HandleFunc("/glitchdeck.demo.v1.Quotes/Get", s.quote)
	s.mux = mux
	return s
}

func (s *service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if (r.URL.Path == "/ws/ticker" || (r.Method != http.MethodGet && r.Method != http.MethodHead)) && !localweb.Allowed(r, "") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for conn := range s.sockets {
		conn.Close()
	}
	return nil
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
	json.NewEncoder(w).Encode(map[string]any{"orders": s.orders, "charges": s.charges, "duplicate_charges": duplicates, "total_charged_cents": total, "ws_ticks_sent": s.ticks, "ws_broken": false, "llm_runs": s.llm["runs"], "llm_completed": s.llm["complete"], "llm_wedged": s.llm["wedged"], "llm_truncated": s.llm["truncated"], "llm_parse_errors": s.llm["parse_error"], "llm_silent_truncations": s.llm["silent_truncation"]})
}

func (s *service) summary(w http.ResponseWriter, r *http.Request) {
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
	json.NewEncoder(w).Encode(map[string]any{"orders_count": len(s.orders), "charges_count": len(s.charges), "duplicate_charges": duplicates, "total_charged_cents": total, "ws_ticks_sent": s.ticks})
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
	s.llm = map[string]int{}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}
func (s *service) ticker(w http.ResponseWriter, r *http.Request) {
	key, err := base64.StdEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Key"))
	connectionUpgrade := false
	for _, value := range r.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				connectionUpgrade = true
			}
		}
	}
	if r.Method != http.MethodGet || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || !connectionUpgrade || r.Header.Get("Sec-WebSocket-Version") != "13" || err != nil || len(key) != 16 {
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
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		conn.Close()
		return
	}
	s.sockets[conn] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.sockets, conn)
		s.mu.Unlock()
	}()
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsframe.AcceptKey(r.Header.Get("Sec-WebSocket-Key")))
	if rw.Flush() != nil {
		return
	}
	frames := make(chan wsframe.Frame, 1)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		defer close(frames)
		for {
			frame, err := wsframe.Read(rw.Reader, true)
			if err != nil {
				return
			}
			if frame.Opcode == 8 || frame.Opcode == 9 {
				select {
				case frames <- frame:
				case <-stop:
					return
				}
				if frame.Opcode == 8 {
					return
				}
			}
		}
	}()
	write := func(frame wsframe.Frame) bool {
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		return wsframe.Write(conn, frame, false) == nil
	}
	control := func(frame wsframe.Frame, ok bool) bool {
		if !ok {
			return false
		}
		if frame.Opcode == 8 {
			_ = write(frame)
			return false
		}
		frame.Opcode = 10
		return write(frame)
	}
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case frame, ok := <-frames:
			if !control(frame, ok) {
				return
			}
			continue
		default:
		}
		select {
		case frame, ok := <-frames:
			if !control(frame, ok) {
				return
			}
		case <-ticker.C:
			s.mu.Lock()
			s.ticks++
			seq, orders := s.ticks, len(s.orders)
			s.mu.Unlock()
			payload, _ := json.Marshal(map[string]any{"seq": seq, "price": 10000 + seq, "orders": orders})
			if r.URL.Query().Get("heartbeat") == "1" && !write(wsframe.Frame{Fin: true, Opcode: 9}) {
				return
			}
			if !write(wsframe.Frame{Fin: true, Opcode: 1, Payload: payload}) {
				return
			}
		}
	}
}
