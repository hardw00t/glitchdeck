package grpcwire

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type Code int

var names = []string{"OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED", "NOT_FOUND", "ALREADY_EXISTS", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION", "ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED", "INTERNAL", "UNAVAILABLE", "DATA_LOSS", "UNAUTHENTICATED"}

func (c Code) String() string {
	if c < 0 || int(c) >= len(names) {
		return "UNKNOWN"
	}
	return names[c]
}
func ParseCode(s string) (Code, error) {
	for i, n := range names {
		if s == n {
			return Code(i), nil
		}
	}
	n, e := strconv.Atoi(s)
	if e != nil || n < 0 || n > 16 {
		return 0, fmt.Errorf("invalid grpc code")
	}
	return Code(n), nil
}
func EncodeMessage(s string) string {
	var b strings.Builder
	for _, v := range []byte(s) {
		if v < 32 || v > 126 || v == '%' {
			fmt.Fprintf(&b, "%%%02X", v)
		} else {
			b.WriteByte(v)
		}
	}
	return b.String()
}
func DecodeMessage(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, e := strconv.ParseUint(s[i+1:i+3], 16, 8); e == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

type MsgCounter struct {
	head      [5]byte
	n         int
	remaining uint32
	count     atomic.Int64
	invalid   bool
}

func (m *MsgCounter) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) != 0 && !m.invalid {
		if m.remaining != 0 {
			n := min(uint32(len(p)), m.remaining)
			m.remaining -= n
			p = p[n:]
			if m.remaining == 0 {
				m.count.Add(1)
			}
			continue
		}
		n := copy(m.head[m.n:], p)
		m.n += n
		p = p[n:]
		if m.n == len(m.head) {
			m.remaining = binary.BigEndian.Uint32(m.head[1:])
			m.n = 0
			if m.head[0] > 1 || m.remaining > 4<<20 {
				m.invalid = true
			} else if m.remaining == 0 {
				m.count.Add(1)
			}
		}
	}
	return total, nil
}
func (m *MsgCounter) Count() int { return int(m.count.Load()) }
func ParseTimeout(s string) (time.Duration, bool) {
	if len(s) < 2 || len(s) > 9 {
		return 0, false
	}
	n, e := strconv.ParseUint(s[:len(s)-1], 10, 64)
	if e != nil {
		return 0, false
	}
	var u time.Duration
	switch s[len(s)-1] {
	case 'H':
		u = time.Hour
	case 'M':
		u = time.Minute
	case 'S':
		u = time.Second
	case 'm':
		u = time.Millisecond
	case 'u':
		u = time.Microsecond
	case 'n':
		u = time.Nanosecond
	default:
		return 0, false
	}
	if n > uint64((1<<63-1)/u) {
		return 0, false
	}
	return time.Duration(n) * u, true
}
