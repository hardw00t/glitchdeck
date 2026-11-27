package sse

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func TestReaderPreservesFrames(t *testing.T) {
	r := NewReader(strings.NewReader("data: one\r\ndata: two\r\n\r\npartial"), 0)
	f, err := r.Next()
	if err != nil || f.Data != "one\ntwo" || string(f.Raw) != "data: one\r\ndata: two\r\n\r\n" {
		t.Fatalf("frame=%+v err=%v", f, err)
	}
	_, _ = r.Next()
	if string(r.Tail()) != "partial" {
		t.Fatalf("tail %q", r.Tail())
	}
}

func TestReaderLineEndings(t *testing.T) {
	const input = "\ufeff: warmup\rretry: +3\r\rid: 77\r\nevent: delta\ndata: one\rdata:  two\n\runtouched-tail"
	r := NewReader(strings.NewReader(input), 0)
	comment, err := r.Next()
	if err != nil || comment.Dispatch || comment.Retry != nil || !comment.Lines[0].Comment || string(comment.Raw) != "\ufeff: warmup\rretry: +3\r\r" {
		t.Fatalf("invalid comment frame: %#v %v", comment, err)
	}
	event, err := r.Next()
	if err != nil || !event.Dispatch || event.ID == nil || *event.ID != "77" || event.Event != "delta" || event.Data != "one\n two" {
		t.Fatalf("invalid event frame: %#v %v", event, err)
	}
	if _, err := r.Next(); err != io.EOF || string(r.Tail()) != "untouched-tail" {
		t.Fatalf("trailing data lost: %q %v", r.Tail(), err)
	}
}

func TestReaderDispatchesCRWithoutNextByte(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	done := make(chan Frame, 1)
	go func() { f, _ := NewReader(r, 0).Next(); done <- f }()
	go func() { _, _ = io.WriteString(w, "data: one\r\r") }()
	select {
	case f := <-done:
		if f.Data != "one" {
			t.Fatalf("frame=%+v", f)
		}
	case <-time.After(time.Second):
		t.Fatal("CR-delimited event blocked")
	}
}

func TestCorruptJSONIsInvalidAndPreservesFraming(t *testing.T) {
	for _, mode := range []string{"cut", "brace", "quote"} {
		const valid = `{"nested":[{"hello":"世界"}]}`
		data, ok := CorruptJSON(valid, mode, 10)
		if !ok || json.Valid([]byte(data)) || strings.ContainsRune(data, '\r') {
			t.Fatalf("%s left a valid JSON payload or broke framing: %q", mode, data)
		}
	}
}

func TestTerminalAndJSON(t *testing.T) {
	for _, tc := range []struct{ event, data, want string }{
		{"", " [DONE] ", "done_marker"}, {"message_stop", "", "message_stop"},
		{"", `{"type":"message_stop"}`, "message_stop"},
		{"response.completed", "", "response.completed"}, {"", `{"type":"response.incomplete"}`, "response.incomplete"},
		{"response.failed", "", "response.failed"}, {"error", "", "error"},
		{"", `{"error":{"message":"bad"}}`, "error"},
		{"", `{"candidates":[{"finishReason":"STOP"}]}`, "finish_reason"},
		{"end", "", "end"}, {"response.output_text.delta", "hello", ""},
		{"", `{"candidates":[{"finishReason":""}]}`, ""},
		{"", `{"type":"message_stop","padding":"` + strings.Repeat("x", 70<<10) + `"}`, ""},
	} {
		kind, ok := (Frame{Event: tc.event, Data: tc.data}).Terminal([]string{"end"})
		if kind != tc.want || ok != (tc.want != "") {
			t.Errorf("%q %q: got %q %v", tc.event, tc.data[:min(len(tc.data), 80)], kind, ok)
		}
	}
	for _, tc := range []struct {
		data string
		want bool
	}{
		{"hello", false}, {" [DONE] ", false}, {" {broken", true}, {"[1]", true}, {"", false},
	} {
		if got := (Frame{Data: tc.data}).IsJSON(); got != tc.want {
			t.Errorf("IsJSON(%q) = %v", tc.data, got)
		}
	}
}

func FuzzReader(f *testing.F) {
	f.Add([]byte("\ufeffdata: é\r\n\r\n: comment\r\rpartial"))
	f.Add([]byte("data\n\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		r := NewReader(bytes.NewReader(input), 256)
		var out bytes.Buffer
		for {
			frame, err := r.Next()
			if err != nil {
				out.Write(r.Tail())
				_, _ = io.Copy(&out, r)
				break
			}
			out.Write(frame.Raw)
		}
		if !bytes.Equal(input, out.Bytes()) {
			t.Fatalf("lost bytes while scanning frames")
		}
	})
}
