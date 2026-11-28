package tape

import (
	"bytes"
	"compress/gzip"
	"errors"
	"strings"
	"testing"
)

func TestExportWritesOnlyDecodedGzipPayload(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("Z", 24)
	for _, tc := range []struct {
		name, payload, want string
		blocked             bool
	}{
		{"clean", "ordinary payload", "ordinary payload", false},
		{"contains secret", secret, "REDACTED", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var compressed bytes.Buffer
			g := gzip.NewWriter(&compressed)
			g.Name = "opaque-filename"
			g.Comment = "opaque-comment"
			g.Extra = []byte{'B', 'Y', 2, 0, 0xff, 0}
			if _, err := g.Write([]byte(tc.payload)); err != nil {
				t.Fatal(err)
			}
			if err := g.Close(); err != nil {
				t.Fatal(err)
			}
			in := Tape{Name: "gzip", Version: 2, Target: "demo", Script: []Step{{HTTP: &HTTP{Method: "POST", Path: "/", Body: compressed.String(), Headers: map[string]string{"Content-Encoding": "gzip", "Content-Type": "text/plain"}}}}}
			var unredacted bytes.Buffer
			err := Encode(&unredacted, in)
			if tc.blocked {
				var blocked *ExportBlockedError
				if !errors.As(err, &blocked) || blocked.Kind != "anthropic" || unredacted.Len() != 0 || strings.Contains(err.Error(), secret) {
					t.Fatalf("ordinary export did not block safely: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			for _, redact := range []bool{false, true} {
				if tc.blocked && !redact {
					continue
				}
				out, err := PrepareExport(in, redact)
				if err != nil || out.Redacted != tc.blocked || out.Script[0].HTTP.Body != tc.want {
					t.Fatalf("expected decoded body %q, got %v", tc.want, err)
				}
				if _, present := out.Script[0].HTTP.Headers["Content-Encoding"]; present || in.Script[0].HTTP.Headers["Content-Encoding"] != "gzip" {
					t.Fatal("export retained encoding or mutated input")
				}
				var encoded bytes.Buffer
				if err := Encode(&encoded, out); err != nil {
					t.Fatal(err)
				}
				if !tc.blocked && unredacted.String() != encoded.String() {
					t.Fatal("direct Encode retained compressed data")
				}
				if decoded, err := Decode(&encoded); err != nil || decoded.Script[0].HTTP.Body != tc.want {
					t.Fatalf("decoded export was not usable: %v", err)
				}
			}
		})
	}
}

func TestExportNormalizesCompressedMIMEPart(t *testing.T) {
	var compressed bytes.Buffer
	g := gzip.NewWriter(&compressed)
	g.Name = "discarded-inner-name"
	if _, err := g.Write([]byte("ordinary part")); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	body := "--x\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\n\r\n" + compressed.String() + "\r\n--x--\r\n"
	in := Tape{Script: []Step{{HTTP: &HTTP{Body: body, Headers: map[string]string{"Content-Type": "multipart/mixed; boundary=x"}}}}}
	out, err := PrepareExport(in, false)
	if err != nil {
		t.Fatal(err)
	}
	want := "--x\r\nContent-Type: text/plain\r\n\r\nordinary part\r\n--x--\r\n"
	if out.Script[0].HTTP.Body != want || in.Script[0].HTTP.Body != body {
		t.Fatal("normalized MIME part did not retain only decoded text")
	}
}
