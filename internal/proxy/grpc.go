package proxy

import (
	"encoding/binary"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hardw00t/glitchdeck/internal/grpcwire"
)

func relayGRPCMessages(w http.ResponseWriter, body io.Reader, count int, code int, message string) (int64, bool, error) {
	var total int64
	for range count {
		var header [5]byte
		if _, err := io.ReadFull(body, header[:]); err != nil {
			if err == io.EOF {
				return total, false, nil
			}
			return total, false, err
		}
		size := binary.BigEndian.Uint32(header[1:])
		if size > 4<<20 {
			return total, false, io.ErrShortBuffer
		}
		n, err := w.Write(header[:])
		total += int64(n)
		if err != nil {
			return total, false, err
		}
		copied, err := io.CopyN(w, body, int64(size))
		total += copied
		if err != nil {
			return total, false, err
		}
	}
	w.Header()[http.TrailerPrefix+"Grpc-Status"] = []string{strconv.Itoa(code)}
	w.Header()[http.TrailerPrefix+"Grpc-Message"] = []string{grpcwire.EncodeMessage(message)}
	return total, true, nil
}

type limitedGRPCCount struct {
	counter *grpcwire.MsgCounter
	left    int64
}

func (c *limitedGRPCCount) Write(data []byte) (int, error) {
	n := min(c.left, int64(len(data)))
	c.left -= n
	_, _ = c.counter.Write(data[:n])
	return len(data), nil
}

func grpcHeader(resp *http.Response, key string) string {
	if v := resp.Trailer.Get(key); v != "" {
		return v
	}
	return resp.Header.Get(key)
}

func (p *Proxy) grpcEvent(gen, seq uint64, r *http.Request, httpStatus int, code *int, source, message, kind, action, h2Error string, reqCount, respCount int, start time.Time) {
	service, method, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	deadline, _ := grpcwire.ParseTimeout(r.Header.Get("Grpc-Timeout"))
	name := ""
	if code != nil {
		name = grpcwire.Code(*code).String()
	}
	p.publish(gen, "grpc_call", map[string]any{
		"seq": seq, "stream_id": streamFrom(r.Context()), "ts_ms": start.UnixMilli(), "service": service, "method": method,
		"http_status": httpStatus, "grpc_status": code, "grpc_status_name": name, "grpc_message": message,
		"source": source, "req_messages": reqCount, "resp_messages": respCount, "deadline_ms": deadline.Milliseconds(),
		"latency_ms": time.Since(start).Milliseconds(), "fault": kind, "action": action, "h2_error": h2Error,
	})
}
