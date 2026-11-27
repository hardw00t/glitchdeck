// Package h2tap injects transport faults at HTTP/2 frame boundaries.
package h2tap

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	Preface      = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	StreamHeader = "glitchdeck-stream-id"
	frameHead    = 9
	frameDefault = 16384
	frameMax     = 1<<24 - 1

	frameData    = 0
	frameHeaders = 1
	frameRST     = 3
	frameSetting = 4
	frameGoAway  = 7
	frameWindow  = 8
	frameCont    = 9

	flagEndStream  = 1
	flagAck        = 1
	flagEndHeaders = 4
	flagPadded     = 8
	flagPriority   = 32
)

type FrameHeader struct {
	Length int
	Type   byte
	Flags  byte
	Stream uint32
}

func frameHeader(b []byte) FrameHeader {
	return FrameHeader{
		Length: int(b[0])<<16 | int(b[1])<<8 | int(b[2]),
		Type:   b[3], Flags: b[4], Stream: binary.BigEndian.Uint32(b[5:]) & 0x7fffffff,
	}
}

func ReadFrame(r io.Reader) (FrameHeader, []byte, error) { return readFrame(r, frameMax) }

func readFrame(r io.Reader, max int) (FrameHeader, []byte, error) {
	var header [frameHead]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return FrameHeader{}, nil, err
	}
	h := frameHeader(header[:])
	if h.Length > max {
		return h, nil, errors.New("HTTP/2 frame exceeds advertised size")
	}
	payload := make([]byte, h.Length)
	_, err := io.ReadFull(r, payload)
	return h, payload, err
}

func appendFrame(dst []byte, kind, flags byte, stream uint32, payload []byte) []byte {
	n := len(payload)
	dst = append(dst, byte(n>>16), byte(n>>8), byte(n), kind, flags)
	dst = binary.BigEndian.AppendUint32(dst, stream&0x7fffffff)
	return append(dst, payload...)
}

func wordFrame(kind byte, stream, value uint32) []byte {
	return binary.BigEndian.AppendUint32(append([]byte{0, 0, 4, kind, 0}, byte(stream>>24)&0x7f, byte(stream>>16), byte(stream>>8), byte(stream)), value)
}

func headerPayload(h FrameHeader, payload []byte) ([]byte, error) {
	if h.Flags&flagPadded != 0 {
		if len(payload) == 0 || int(payload[0]) >= len(payload) {
			return nil, errors.New("invalid HTTP/2 padding")
		}
		payload = payload[1 : len(payload)-int(payload[0])]
	}
	if h.Type == frameHeaders && h.Flags&flagPriority != 0 {
		if len(payload) < 5 {
			return nil, errors.New("invalid HTTP/2 priority field")
		}
		payload = payload[5:]
	}
	return payload, nil
}
