package wsframe

import (
	"bytes"
	"errors"
	"testing"
)

func TestReadTypedErrors(t *testing.T) {
	tests := []struct {
		name  string
		wire  []byte
		large bool
	}{
		{"large", []byte{0x82, 127, 0, 0, 0, 0, 0, 0x40, 0, 1}, true},
		{"rsv", []byte{0xc1, 0}, false},
		{"noncanonical", []byte{0x81, 126, 0, 1}, false},
		{"length", []byte{0x81, 127, 0x80, 0, 0, 0, 0, 0, 0, 0}, false},
		{"opcode", []byte{0x83, 0}, false},
		{"fragmented ping", []byte{0x09, 0}, false},
		{"large ping", []byte{0x89, 126, 0, 126}, false},
		{"close code", []byte{0x88, 2, 3, 0xed}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Read(bytes.NewReader(tt.wire), false)
			if tt.large {
				var e *ErrFrameTooLarge
				if !errors.As(err, &e) || e.Declared != MaxPayload+1 || e.Opcode != 2 || e.Limit != MaxPayload {
					t.Fatalf("large error: %#v", err)
				}
				return
			}
			var e *ErrProtocol
			if !errors.As(err, &e) {
				t.Fatalf("protocol error: %v", err)
			}
		})
	}
}
