package sse

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ErrLineTooLong = errors.New("SSE line or frame too long")

type Line struct {
	Field, Value string
	Comment      bool
}

type Frame struct {
	Raw      []byte
	Lines    []Line
	Event    string
	ID       *string
	Data     string
	Retry    *int
	Dispatch bool
}

func (f Frame) IsDone() bool { return strings.TrimSpace(f.Data) == "[DONE]" }

type Reader struct {
	r     *bufio.Reader
	max   int
	tail  []byte
	first bool
}

func NewReader(r io.Reader, maxLine int) *Reader {
	if maxLine <= 0 {
		maxLine = 1 << 20
	}
	return &Reader{r: bufio.NewReaderSize(r, 64<<10), max: maxLine, first: true}
}

func (r *Reader) Tail() []byte               { return r.tail }
func (r *Reader) Read(p []byte) (int, error) { return r.r.Read(p) }

func (r *Reader) Next() (Frame, error) {
	const maxFrame = 4 << 20
	var f Frame
	var data []string
	r.tail = nil
	for {
		start := len(f.Raw)
		var end int
		for {
			b, err := r.r.ReadByte()
			if err != nil {
				r.tail = f.Raw
				return Frame{}, err
			}
			f.Raw = append(f.Raw, b)
			if len(f.Raw)-start > r.max || len(f.Raw) > max(maxFrame, r.max) {
				r.tail = f.Raw
				return Frame{}, ErrLineTooLong
			}
			if b == '\r' || b == '\n' {
				end = len(f.Raw) - 1
				if b == '\r' {
					if next, err := r.r.Peek(1); err == nil && next[0] == '\n' {
						_, _ = r.r.Discard(1)
						f.Raw = append(f.Raw, '\n')
					}
				}
				break
			}
		}
		text := string(f.Raw[start:end])
		if r.first {
			text = strings.TrimPrefix(text, "\ufeff")
			r.first = false
		}
		if text == "" {
			f.Data = strings.Join(data, "\n")
			return f, nil
		}
		line := Line{}
		if value, comment := strings.CutPrefix(text, ":"); comment {
			line.Comment, line.Value = true, value
		} else {
			line.Field, line.Value, _ = strings.Cut(text, ":")
			line.Value = strings.TrimPrefix(line.Value, " ")
			switch line.Field {
			case "data":
				data = append(data, line.Value)
				f.Dispatch = true
			case "event":
				f.Event, f.Dispatch = line.Value, true
			case "id":
				if !strings.ContainsRune(line.Value, 0) {
					f.ID = new(line.Value)
				}
			case "retry":
				if n, ok := retryValue(line.Value); ok {
					f.Retry = &n
				}
			}
		}
		f.Lines = append(f.Lines, line)
	}
}

func retryValue(s string) (int, bool) {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

func Encode(f Frame) []byte {
	var b bytes.Buffer
	wrote := false
	for _, line := range f.Lines {
		if line.Comment {
			b.WriteByte(':')
			b.WriteString(line.Value)
			b.WriteByte('\n')
		} else if line.Field == "data" {
			if !wrote {
				for value := range strings.SplitSeq(f.Data, "\n") {
					b.WriteString("data: ")
					b.WriteString(value)
					b.WriteByte('\n')
				}
				wrote = true
			}
		} else {
			b.WriteString(line.Field)
			b.WriteString(": ")
			b.WriteString(line.Value)
			b.WriteByte('\n')
		}
	}
	b.WriteByte('\n')
	return b.Bytes()
}

func CorruptJSON(data, mode string, rnd uint64) (string, bool) {
	if !json.Valid([]byte(data)) {
		return data, false
	}
	if mode == "cut" && len(data) > 2 {
		for i := range uint64(8) {
			offset := 1 + int((rnd+i)%uint64(len(data)-2))
			for offset > 0 && !utf8.RuneStart(data[offset]) {
				offset--
			}
			if !json.Valid([]byte(data[:offset])) {
				return data[:offset], true
			}
		}
	}
	if mode == "quote" {
		if count := strings.Count(data, `"`); count > 0 {
			for attempt := range min(8, count) {
				want := (rnd + uint64(attempt)) % uint64(count)
				for i := range len(data) {
					if data[i] == '"' {
						if want == 0 {
							candidate := data[:i] + data[i+1:]
							if !json.Valid([]byte(candidate)) {
								return candidate, true
							}
							break
						}
						want--
					}
				}
			}
		}
	}
	if i := strings.LastIndexAny(data, "}]"); i >= 0 {
		candidate := data[:i] + data[i+1:]
		if !json.Valid([]byte(candidate)) {
			return candidate, true
		}
	}
	return "", true
}
