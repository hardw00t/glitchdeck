package h2tap

import (
	"bytes"
	"errors"
	"testing"
)

func TestReadRSTStreamCode(t *testing.T) {
	wire := []byte{0, 0, 4, 3, 0, 0, 0, 0, 5, 0, 0, 0, 11}
	h, data, err := ReadFrame(bytes.NewReader(wire))
	if err != nil || h.Type != 3 || h.Stream != 5 || !bytes.Equal(data, []byte{0, 0, 0, 11}) {
		t.Fatalf("RST_STREAM was not decoded: %+v %x %v", h, data, err)
	}
}

func TestContinuationIgnoresPaddingFlag(t *testing.T) {
	payload := []byte{0xff, 1, 2}
	got, err := headerPayload(FrameHeader{Type: frameCont, Flags: flagPadded}, payload)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("continuation payload %x: %v", got, err)
	}
}

func TestFrameSizeError(t *testing.T) {
	_, _, err := readFrame(bytes.NewReader([]byte{0, 0, 2, 0, 0, 0, 0, 0, 1}), 1)
	if !errors.Is(err, errFrameSize) {
		t.Fatalf("expected frame size error, got %v", err)
	}
}

func FuzzFrameCodec(f *testing.F) {
	f.Add([]byte{0, 0, 4, 3, 0, 0, 0, 0, 1, 0, 0, 0, 8})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) < 9 || int(b[0])<<16|int(b[1])<<8|int(b[2]) > len(b)-9 {
			return
		}
		h, payload, err := ReadFrame(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		got := appendFrame(nil, h.Type, h.Flags, h.Stream, payload)
		if !bytes.Equal(got[:5], b[:5]) || !bytes.Equal(got[6:], b[6:len(got)]) || got[5] != b[5]&0x7f {
			t.Fatalf("bad round trip: got %x want %x", got, b[:len(got)])
		}
	})
}
