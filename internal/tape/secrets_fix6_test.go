package tape

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestFix6QuotedPairHeaders(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("x", 24)
	for _, name := range []string{"WWW-Authenticate", "X-Mime"} {
		for _, redact := range []bool{false, true} {
			input := Tape{Cassettes: []Cassette{{Response: CassetteResponse{Status: 401, Headers: map[string]string{name: `Basic realm="` + `\s` + secret[1:] + `"`}}}}}
			_, err := PrepareExport(input, redact)
			if err == nil {
				t.Fatalf("%s redact=%v accepted an escaped credential", name, redact)
			}
		}
	}
	value := `/path?auth=Bearer\+eyJabc`
	body := "--part\r\nX-Target: \"" + value + "\"\r\n\r\nok\r\n--part--\r\n"
	input := Tape{Cassettes: []Cassette{{Response: CassetteResponse{
		Body: body, Headers: map[string]string{"Content-Type": "multipart/mixed; boundary=part"},
	}}}}
	for _, redact := range []bool{false, true} {
		if _, err := PrepareExport(input, redact); err == nil {
			t.Fatalf("redact=%v accepted an escaped MIME header query", redact)
		}
	}
}

func TestFix6NULStrippedBodies(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("x", 24)
	for _, bigEndian := range []bool{false, true} {
		var body strings.Builder
		for _, b := range []byte(`<?xml version="1.0" encoding="UTF-16"?><x>` + secret + `</x>`) {
			if bigEndian {
				body.WriteByte(0)
			}
			body.WriteByte(b)
			if !bigEndian {
				body.WriteByte(0)
			}
		}
		for _, encoded := range []bool{false, true} {
			response := CassetteResponse{Body: body.String(), Headers: map[string]string{"Content-Type": "application/xml"}}
			if encoded {
				response.BodyEncoding = "base64"
				response.Body = base64.StdEncoding.EncodeToString([]byte(response.Body))
			}
			in := Tape{Cassettes: []Cassette{{Response: response}}}
			if _, err := PrepareExport(in, false); err == nil {
				t.Fatal("exported BOM-less UTF-16 with a hidden credential")
			}
			out, err := PrepareExport(in, true)
			if err != nil || !out.Redacted || out.Cassettes[0].Response.Body != "REDACTED" {
				t.Fatalf("BOM-less UTF-16 was not replaced: %v", err)
			}
		}
	}
}

func TestFix6DeclaredJSONCompressionGuess(t *testing.T) {
	for _, media := range []string{"application/json", "application/problem+json"} {
		for _, redact := range []bool{false, true} {
			input := Tape{Cassettes: []Cassette{{Response: CassetteResponse{Body: "80", Headers: map[string]string{"Content-Type": media}}}}}
			if _, err := PrepareExport(input, redact); err != nil {
				t.Fatalf("%s: %v", media, err)
			}
			input.Cassettes[0].Response.Headers["Content-Encoding"] = "deflate"
			out, err := PrepareExport(input, redact)
			if redact {
				if err != nil || !out.Redacted || out.Cassettes[0].Response.Body != "REDACTED" {
					t.Fatalf("%s: expected invalid declared compression to be replaced: %v", media, err)
				}
			} else if blocked, ok := err.(*ExportBlockedError); !ok || blocked.Kind != "unscannable_encoding" {
				t.Fatalf("%s: expected invalid declared compression to block: %v", media, err)
			}
		}
	}
}
