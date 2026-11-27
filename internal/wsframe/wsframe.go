package wsframe

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"io"
	"unicode/utf8"
)

const MaxPayload = 4 << 20

type ErrFrameTooLarge struct {
	Declared uint64
	Opcode   byte
	Limit    int
}

func (e *ErrFrameTooLarge) Error() string { return "frame too large" }

type ErrProtocol struct {
	Reason   string
	Declared uint64
}

func (e *ErrProtocol) Error() string { return e.Reason }

type Frame struct {
	Fin     bool
	Opcode  byte
	Payload []byte
}

func AcceptKey(key string) string {
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h[:])
}
func valid(f Frame) bool {
	switch f.Opcode {
	case 0, 1, 2:
		return true
	case 8, 9, 10:
		if !f.Fin || len(f.Payload) > 125 {
			return false
		}
		if f.Opcode == 8 {
			if len(f.Payload) == 1 {
				return false
			}
			if len(f.Payload) >= 2 {
				code := binary.BigEndian.Uint16(f.Payload)
				if code < 1000 || code >= 5000 || code == 1004 || code == 1005 || code == 1006 || code == 1015 || (code >= 1016 && code < 3000) || !utf8.Valid(f.Payload[2:]) {
					return false
				}
			}
		}
		return true
	default:
		return false
	}
}
func Read(r io.Reader, masked bool) (Frame, error) {
	var f Frame
	var h [8]byte
	if _, err := io.ReadFull(r, h[:2]); err != nil {
		return f, err
	}
	readRest := func(b []byte) error {
		_, err := io.ReadFull(r, b)
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	f.Fin = h[0]&0x80 != 0
	f.Opcode = h[0] & 15
	if h[0]&0x70 != 0 || (h[1]&0x80 != 0) != masked {
		var declared uint64
		if h[1]&127 < 126 {
			declared = uint64(h[1] & 127)
		}
		return f, &ErrProtocol{Reason: "invalid frame flags", Declared: declared}
	}
	n := uint64(h[1] & 127)
	if f.Opcode != 0 && f.Opcode != 1 && f.Opcode != 2 && f.Opcode != 8 && f.Opcode != 9 && f.Opcode != 10 || f.Opcode >= 8 && !f.Fin {
		declared := n
		if n >= 126 {
			declared = 0
		}
		return f, &ErrProtocol{Reason: "invalid opcode or control frame", Declared: declared}
	}
	if n == 126 {
		if err := readRest(h[:2]); err != nil {
			return f, err
		}
		n = uint64(binary.BigEndian.Uint16(h[:2]))
		if n < 126 {
			return f, &ErrProtocol{Reason: "noncanonical length", Declared: n}
		}
	} else if n == 127 {
		if err := readRest(h[:8]); err != nil {
			return f, err
		}
		n = binary.BigEndian.Uint64(h[:])
		if n < 65536 || n>>63 != 0 {
			if n>>63 != 0 {
				return f, &ErrProtocol{Reason: "invalid length"}
			}
			return f, &ErrProtocol{Reason: "invalid length", Declared: n}
		}
	}
	if n > MaxPayload {
		return f, &ErrFrameTooLarge{Declared: n, Opcode: f.Opcode, Limit: MaxPayload}
	}
	if f.Opcode == 8 && n == 1 {
		return f, &ErrProtocol{Reason: "invalid opcode or control frame", Declared: n}
	}
	if f.Opcode >= 8 && n > 125 {
		return f, &ErrProtocol{Reason: "frame too large", Declared: n}
	}
	var key [4]byte
	if masked {
		if err := readRest(key[:]); err != nil {
			return f, err
		}
	}
	f.Payload = make([]byte, int(n))
	if err := readRest(f.Payload); err != nil {
		return f, err
	}
	if masked {
		for i := range f.Payload {
			f.Payload[i] ^= key[i%4]
		}
	}
	if !valid(f) {
		return Frame{}, &ErrProtocol{Reason: "invalid opcode or control frame", Declared: n}
	}
	return f, nil
}
func Write(w io.Writer, f Frame, masked bool) error {
	if len(f.Payload) > MaxPayload || !valid(f) {
		return &ErrProtocol{Reason: "invalid frame", Declared: uint64(len(f.Payload))}
	}
	var h [14]byte
	if f.Fin {
		h[0] = 0x80
	}
	h[0] |= f.Opcode
	n := len(f.Payload)
	pos := 2
	switch {
	case n < 126:
		h[1] = byte(n)
	case n <= 65535:
		h[1] = 126
		binary.BigEndian.PutUint16(h[2:4], uint16(n))
		pos = 4
	default:
		h[1] = 127
		binary.BigEndian.PutUint64(h[2:10], uint64(n))
		pos = 10
	}
	var key [4]byte
	if masked {
		h[1] |= 0x80
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		copy(h[pos:], key[:])
		pos += 4
	}
	if err := writeAll(w, h[:pos]); err != nil {
		return err
	}
	if !masked {
		return writeAll(w, f.Payload)
	}
	var buf [4096]byte
	for i := 0; i < n; {
		end := i + len(buf)
		if end > n {
			end = n
		}
		for j := i; j < end; j++ {
			buf[j-i] = f.Payload[j] ^ key[j%4]
		}
		if err := writeAll(w, buf[:end-i]); err != nil {
			return err
		}
		i = end
	}
	return nil
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
