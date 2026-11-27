package grpcwire

import "testing"

func TestMessageCounterFragmented(t *testing.T) {
	var c MsgCounter
	c.Write([]byte{0, 0, 0})
	c.Write([]byte{0, 3, 'a', 'b'})
	if c.Count() != 0 {
		t.Fatal(c.Count())
	}
	c.Write([]byte{'c'})
	if c.Count() != 1 {
		t.Fatal(c.Count())
	}
	if DecodeMessage(EncodeMessage("a%\nb")) != "a%\nb" {
		t.Fatal("message roundtrip")
	}
}
