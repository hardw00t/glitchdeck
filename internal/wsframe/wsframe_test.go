package wsframe

import (
	"bytes"
	"testing"
)

func TestRoundTripLengthsAndMasks(t *testing.T) {
	for _, n := range []int{0, 125, 126, 65536} {
		for _, masked := range []bool{false, true} {
			input := Frame{Fin: true, Opcode: 2, Payload: bytes.Repeat([]byte{42}, n)}
			var b bytes.Buffer
			if err := Write(&b, input, masked); err != nil {
				t.Fatal(err)
			}
			got, err := Read(&b, masked)
			if err != nil || !got.Fin || got.Opcode != 2 || !bytes.Equal(got.Payload, input.Payload) {
				t.Fatalf("length %d masked %v: %v", n, masked, err)
			}
		}
	}
}
func TestRejectInvalidFrame(t *testing.T) {
	for _, wire := range [][]byte{{0xc1, 0}, {0x89, 126, 0, 126}, {0x81, 0x80, 0, 0, 0, 0}} {
		if _, err := Read(bytes.NewReader(wire), false); err == nil {
			t.Fatalf("accepted %x", wire)
		}
	}
}
func TestAcceptKey(t *testing.T) {
	if AcceptKey("dGhlIHNhbXBsZSBub25jZQ==") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatal("bad accept key")
	}
}
