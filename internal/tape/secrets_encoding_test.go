package tape

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestExportTextEncodingAllowlist(t *testing.T) {
	secret := "sk-" + "ant-" + strings.Repeat("Z", 24)
	// IBM037 XML with an internal entity substituted into a credential-bearing attribute.
	const ibm037 = "TFrE1sPj6NfFQKdAukxaxdXjyePoQIiol4iFlUB/UHv09V5/brtuTKdAkoWofn+iklCIqJeIhZVegZWjYOnp6enp6enp6enp6enp6enp6enp6enp6X9hbg=="
	for _, tc := range []struct {
		name, body, media, encoding, path string
		ws                                bool
	}{
		{"IBM037 XML", ibm037, "application/xml", "base64", "$.cassettes[0].response.body", false},
		{"IBM037 external XML entity", ibm037, "application/xml-external-parsed-entity", "base64", "$.cassettes[0].response.body", false},
		{"UTF-7 frame", `<?xml version="1.0" encoding="UTF-7"?><x key="sk+AC0-ant-` + secret[7:] + `"/>`, "", "", "$.script[0].ws.messages[0]", true},
		{"UTF-7 BOM", "+/v8-<x/>", "", "", "$.script[0].ws.messages[0]", true},
		{"JSON charset", `{"key":"` + secret + `"}`, `application/json; charset=" IBM037 "`, "", "$.cassettes[0].response.body", false},
		{"invalid UTF-8", "plain\x80" + secret, "text/plain", "", "$.cassettes[0].response.body", false},
		{"malformed UTF-16", "\xff\xfe\x00\xd8", "text/plain", "", "$.cassettes[0].response.body", false},
		{"unsupported XML declaration after BOM", "\xef\xbb\xbf" + `<?xml version="1.0" encoding="windows-1252"?><x/>`, "application/xml", "", "$.cassettes[0].response.body", false},
		{"multipart text epilogue", "--x\r\n\r\nok\r\n--x--\r\n\x80", "multipart/mixed; boundary=x", "", "$.cassettes[0].response.body", false},
		{"multipart base64 defaults to text", "--x\r\nContent-Transfer-Encoding: base64\r\n\r\ngA==\r\n--x--\r\n", "multipart/mixed; boundary=x", "", "$.cassettes[0].response.body", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := Tape{Version: 3, Target: "demo"}
			if tc.ws {
				in.Version = 2
				in.Script = []Step{{WS: &WS{Path: "/ws", Messages: []string{tc.body}}}}
			} else {
				in.Cassettes = []Cassette{{Request: CassetteRequest{Method: "GET", Path: "/"}, Response: CassetteResponse{
					Status: 200, Body: tc.body, BodyEncoding: tc.encoding, Headers: map[string]string{"Content-Type": tc.media},
				}}}
			}
			var encoded bytes.Buffer
			var blocked *ExportBlockedError
			if err := Encode(&encoded, in); !errors.As(err, &blocked) || blocked.Kind != "unscannable_encoding" || blocked.Field != tc.path || encoded.Len() != 0 || strings.Contains(err.Error(), secret) {
				t.Errorf("expected safe encoding block, got %v", err)
			}
			clean, err := PrepareExport(in, true)
			if err != nil {
				t.Fatal(err)
			}
			encoded.Reset()
			if err := Encode(&encoded, clean); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encoded.Bytes(), []byte(secret)) || bytes.Contains(encoded.Bytes(), []byte(tc.body)) {
				t.Fatal("redacted export contains original data")
			}
			decoded, err := Decode(&encoded)
			if err != nil || !decoded.Redacted {
				t.Fatalf("redacted tape did not validate: %v", err)
			}
			if tc.ws {
				if got := decoded.Script[0].WS.Messages[0]; got != "REDACTED" {
					t.Fatal("WebSocket marker missing")
				}
			} else if got := decoded.Cassettes[0].Response; got.Body != "REDACTED" || got.BodyEncoding != "" {
				t.Fatal("plain body marker missing")
			}
		})
	}
}

func TestExportAllowedTextEncodings(t *testing.T) {
	secret := "sk-" + "ant-" + strings.Repeat("Z", 24)
	for _, tc := range []struct {
		name, media, format string
		order               binary.AppendByteOrder
	}{
		{"UTF-8 JSON", `application/json; charset=" UTF8 "`, `{"value":"%s"}`, nil},
		{"XML example in UTF-8 JSON", "application/json", `{"xml":"<?xml version='1.0' encoding='windows-1252'?>","value":"%s"}`, nil},
		{"UTF-8 XML", "application/xml; charset=ascii", `<?xml version="1.0" encoding="utf-8"?><x>%s</x>`, nil},
		{"UTF-8 SSE", "text/event-stream", "data: %s\n\n", nil},
		{"UTF-16LE JSON", "application/json; charset=utf-16le", `{"value":"%s"}`, binary.LittleEndian},
		{"UTF-16BE JSON", "application/json", `{"value":"%s"}`, binary.BigEndian},
	} {
		t.Run(tc.name, func(t *testing.T) {
			makeTape := func(value string) Tape {
				raw := []byte(strings.Replace(tc.format, "%s", value, 1))
				encoding := ""
				if tc.order != nil {
					data := tc.order.AppendUint16(nil, 0xfeff)
					for _, u := range utf16.Encode([]rune(string(raw))) {
						data = tc.order.AppendUint16(data, u)
					}
					raw, encoding = []byte(base64.StdEncoding.EncodeToString(data)), "base64"
				}
				return Tape{Cassettes: []Cassette{{Response: CassetteResponse{Status: 200, Body: string(raw), BodyEncoding: encoding, Headers: map[string]string{"Content-Type": tc.media}}}}}
			}
			in := makeTape("ordinary")
			out, err := PrepareExport(in, false)
			if err != nil || out.Cassettes[0].Response.Body != in.Cassettes[0].Response.Body || out.Redacted {
				t.Errorf("clean allowed text rejected or changed: %v", err)
			}
			var blocked *ExportBlockedError
			if _, err := PrepareExport(makeTape(secret), false); !errors.As(err, &blocked) || blocked.Kind != "anthropic" {
				t.Errorf("allowed text did not reveal its credential: %v", err)
			}
			redacted, err := PrepareExport(makeTape(secret), true)
			if err != nil || !redacted.Redacted || redacted.Cassettes[0].Response.Body != makeTape("REDACTED").Cassettes[0].Response.Body {
				t.Errorf("redaction did not preserve the allowed representation: %v", err)
			}
		})
	}
}

func TestExportPreservesBinaryBase64(t *testing.T) {
	const binaryBody = "iVBORw0KGgo="
	input := Tape{Cassettes: []Cassette{{Response: CassetteResponse{
		Status: 200, Body: binaryBody, BodyEncoding: "base64", Headers: map[string]string{"Content-Type": "application/octet-stream"},
	}}}}
	out, err := PrepareExport(input, false)
	if err != nil || out.Cassettes[0].Response.Body != binaryBody || out.Cassettes[0].Response.BodyEncoding != "base64" {
		t.Fatalf("binary body was rejected or changed: %v", err)
	}
}

func TestExportEncodingContainerBoundaries(t *testing.T) {
	secret := "sk-" + "ant-" + strings.Repeat("Z", 24)
	t.Run("binary BOM cannot hide decoded octets", func(t *testing.T) {
		in := Tape{Cassettes: []Cassette{{Response: NewCassetteResponse(200, map[string]string{"Content-Type": "application/octet-stream"}, []byte("\xff\xfe"+secret+"!"), false)}}}
		if _, err := PrepareExport(in, false); err == nil {
			t.Fatal("exported credential in binary data")
		}
		out, err := PrepareExport(in, true)
		if err != nil || out.Cassettes[0].Response.Body != "REDACTED" {
			t.Fatalf("unrecognised binary body was not replaced: %v", err)
		}
	})
	t.Run("multipart binary part preserved", func(t *testing.T) {
		raw := []byte("--x\r\nContent-Type: application/octet-stream\r\n\r\n\x89PNG\r\n\x1a\n\r\n--x--\r\n")
		in := Tape{Cassettes: []Cassette{{Response: NewCassetteResponse(200, map[string]string{"Content-Type": "multipart/mixed; boundary=x"}, raw, false)}}}
		out, err := PrepareExport(in, false)
		if err != nil || out.Cassettes[0].Response.Body != in.Cassettes[0].Response.Body {
			t.Fatalf("binary part was rejected or changed: %v", err)
		}
	})
	t.Run("declared compression does not clear charset", func(t *testing.T) {
		var compressed bytes.Buffer
		w := gzip.NewWriter(&compressed)
		_, _ = w.Write([]byte("ordinary"))
		_ = w.Close()
		in := Tape{Cassettes: []Cassette{{Response: NewCassetteResponse(200, map[string]string{"Content-Type": "application/gzip; charset=ibm037"}, compressed.Bytes(), false)}}}
		var blocked *ExportBlockedError
		if _, err := PrepareExport(in, false); !errors.As(err, &blocked) || blocked.Kind != "unscannable_encoding" {
			t.Errorf("disallowed charset accepted inside gzip: %v", err)
		}
		out, err := PrepareExport(in, true)
		if err != nil || !out.Redacted || out.Cassettes[0].Response.Body != "REDACTED" {
			t.Fatalf("gzip body with a disallowed charset was not replaced: %v", err)
		}
	})
}
