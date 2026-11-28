package tape

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/sse"
)

func TestScannerRepresentations(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("z", 24)
	cases := []struct{ name, contentType, encoding, body string }{
		{"multipart", "multipart/form-data; boundary=x", "", "--x\r\nContent-Disposition: form-data; name=\"x\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte(secret)) + "\r\n--x--\r\n"},
		{"form", "application/x-www-form-urlencoded", "", "v=Bearer+eyJ" + strings.Repeat("x", 20)},
		{"composed", "application/x-www-form-urlencoded", "", "v=%22sk%5Cu002dant%5Cu002d" + strings.Repeat("z", 24) + "%22"},
		{"mixed percent", "application/x-www-form-urlencoded", "", "ordinary=%oops&v=%22sk%5Cu002dant%5Cu002d" + strings.Repeat("z", 24) + "%22"},
		{"quoted-printable", "multipart/form-data; boundary=x", "", "--x\r\nContent-Disposition: form-data; name=\"x\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nsk=2Dant=2D" + strings.Repeat("z", 24) + "\r\n--x--\r\n"},
		{"sse", "text/event-stream", "", ": \"\ndata: {\"key\":\"sk-ant-\\u007a" + strings.Repeat("z", 23) + "\"}\n\n"},
		{"charset", "text/plain; charset=utf-16", "", "ordinary"},
		{"grpc", "application/grpc", "", "ordinary"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := Tape{Cassettes: []Cassette{{Response: CassetteResponse{Headers: map[string]string{"Content-Type": tc.contentType}, Body: tc.body}}}}
			_, err := PrepareExport(in, false)
			var blocked *ExportBlockedError
			if !errors.As(err, &blocked) || strings.Contains(err.Error(), secret) {
				t.Fatalf("expected safe block: %v", err)
			}
			out, err := PrepareExport(in, true)
			if err == nil {
				if _, err = PrepareExport(out, false); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(out.Cassettes[0].Response.Body, secret) {
					t.Fatal("secret retained")
				}
			}
		})
	}
}

func TestScannerRedactsAnSSEEventWithoutChangingItsFraming(t *testing.T) {
	body := ": \"\r\ndata: {\"key\":\"sk-ant-\\u007a" + strings.Repeat("z", 23) + "\"}\r\n\r\ndata: [DONE]\r\n\r\n"
	in := Tape{Cassettes: []Cassette{{Response: CassetteResponse{Headers: map[string]string{"Content-Type": "text/event-stream"}, Body: body}}}}
	out, err := PrepareExport(in, true)
	if err != nil {
		t.Fatal(err)
	}
	reader := sse.NewReader(strings.NewReader(out.Cassettes[0].Response.Body), 4096)
	frame, err := reader.Next()
	if err != nil || frame.Data != `{"key":"REDACTED"}` {
		t.Fatalf("redacted event: %q, %v", frame.Data, err)
	}
	next, err := reader.Next()
	if err != nil || !next.IsDone() {
		t.Fatalf("terminal event: %q, %v", next.Data, err)
	}
}

func TestScannerCompressedBoundaries(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("q", 24)
	var gz bytes.Buffer
	g := gzip.NewWriter(&gz)
	g.Name = secret
	_, _ = g.Write([]byte("clean"))
	_ = g.Close()
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	_, _ = zw.Write([]byte("clean"))
	_ = zw.Close()
	z.WriteString(secret)
	for _, tc := range []struct {
		enc string
		b   []byte
	}{{"gzip", gz.Bytes()}, {"deflate", z.Bytes()}} {
		in := Tape{Cassettes: []Cassette{{Response: CassetteResponse{Headers: map[string]string{"Content-Encoding": tc.enc}, BodyEncoding: "base64", Body: base64.StdEncoding.EncodeToString(tc.b)}}}}
		if _, err := PrepareExport(in, false); err == nil {
			t.Fatal("uninspected compressed bytes accepted")
		}
	}
	var raw bytes.Buffer
	fw, _ := flate.NewWriter(&raw, flate.DefaultCompression)
	_, _ = fw.Write([]byte(secret))
	_ = fw.Close()
	in := Tape{Cassettes: []Cassette{{Response: CassetteResponse{Headers: map[string]string{"Content-Encoding": "deflate"}, BodyEncoding: "base64", Body: base64.StdEncoding.EncodeToString(raw.Bytes())}}}}
	out, err := PrepareExport(in, true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := base64.StdEncoding.DecodeString(out.Cassettes[0].Response.Body)
	if err != nil {
		t.Fatal(err)
	}
	r := flate.NewReader(bytes.NewReader(b))
	decoded, err := io.ReadAll(r)
	if err != nil || string(decoded) != "REDACTED" {
		t.Fatalf("decoded %q: %v", decoded, err)
	}
}

func TestScannerInvalidatesValidators(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("q", 24)
	in := Tape{Cassettes: []Cassette{{Response: CassetteResponse{Headers: map[string]string{"Content-Length": "1", "Content-MD5": "old", "Content-Digest": "old", "ETag": "\"old\""}, Body: secret}}}}
	out, err := PrepareExport(in, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Cassettes[0].Response.Headers) != 0 {
		t.Fatal("stale validators retained")
	}
}
