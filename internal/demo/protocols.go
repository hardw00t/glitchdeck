package demo

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

var streamID atomic.Uint64

func Protocols() *http.Protocols {
	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	return p
}
func (s *service) stream(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	var v struct {
		Tokens  int  `json:"tokens"`
		TokenMS *int `json:"token_ms"`
		Stream  bool `json:"stream"`
	}
	if e := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&v); e != nil && e != io.EOF {
		http.Error(w, "invalid request", 400)
		return
	}
	if v.Tokens == 0 {
		v.Tokens = 24
	}
	if v.Tokens < 1 || v.Tokens > 256 {
		http.Error(w, "invalid tokens", 400)
		return
	}
	ms := 40
	if v.TokenMS != nil {
		ms = *v.TokenMS
	}
	if ms < 0 || ms > 1000 {
		http.Error(w, "invalid delay", 400)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	id := streamID.Add(1)
	anthropic := r.URL.Path == "/v1/messages"
	emit := func(event string, data any) bool {
		b, _ := json.Marshal(data)
		if event != "" {
			fmt.Fprintf(w, "event: %s\n", event)
		}
		fmt.Fprintf(w, "data: %s\n\n", b)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if ms == 0 {
			return r.Context().Err() == nil
		}
		timer := time.NewTimer(time.Duration(ms) * time.Millisecond)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return false
		case <-timer.C:
			return true
		}
	}
	if anthropic {
		if !emit("message_start", map[string]any{"type": "message_start"}) {
			return
		}
		if !emit("content_block_start", map[string]any{"type": "content_block_start"}) {
			return
		}
	} else {
		if !emit("", map[string]any{"id": fmt.Sprintf("chatcmpl-demo-%d", id), "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": "demo-1", "choices": []any{map[string]any{"index": 0, "delta": map[string]any{"role": "assistant"}, "finish_reason": nil}}}) {
			return
		}
	}
	words := strings.Fields("The quick brown fox jumps over the lazy dog while systems recover from transient failures with care and patience")
	for i := 0; i < v.Tokens; i++ {
		word := words[i%len(words)] + " "
		if anthropic {
			if !emit("content_block_delta", map[string]any{"type": "content_block_delta", "delta": map[string]any{"text": word}}) {
				return
			}
		} else {
			if !emit("", map[string]any{"id": fmt.Sprintf("chatcmpl-demo-%d", id), "choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": word}, "finish_reason": nil}}}) {
				return
			}
		}
	}
	if anthropic {
		emit("content_block_stop", map[string]any{"type": "content_block_stop"})
		emit("message_delta", map[string]any{"type": "message_delta"})
		emit("message_stop", map[string]any{"type": "message_stop"})
	} else {
		emit("", map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}}})
		fmt.Fprint(w, "data: [DONE]\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
}
func (s *service) streamResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	var v struct {
		Outcome string `json:"outcome"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&v) != nil {
		http.Error(w, "invalid result", 400)
		return
	}
	switch v.Outcome {
	case "complete", "wedged", "parse_error", "truncated", "silent_truncation", "error":
	default:
		http.Error(w, "invalid outcome", 400)
		return
	}
	s.mu.Lock()
	s.llm["runs"]++
	s.llm[v.Outcome]++
	s.mu.Unlock()
	w.WriteHeader(204)
}
func (s *service) quote(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.ProtoMajor != 2 {
		http.Error(w, "gRPC requires HTTP/2", 400)
		return
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if e != nil || len(b) < 7 || b[0] != 0 || int(binary.BigEndian.Uint32(b[1:5])) != len(b)-5 || b[5] != 10 || int(b[6]) != len(b)-7 {
		http.Error(w, "invalid gRPC request", 400)
		return
	}
	symbol := b[7:]
	if len(symbol) > 127 {
		http.Error(w, "invalid symbol", 400)
		return
	}
	msg := append([]byte{10, byte(len(symbol))}, symbol...)
	msg = append(msg, 16, 0x90, 0x4e)
	frame := make([]byte, 5)
	binary.BigEndian.PutUint32(frame[1:], uint32(len(msg)))
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Add("Trailer", "Grpc-Status")
	w.Write(append(frame, msg...))
	w.Header().Set("Grpc-Status", "0")
}
