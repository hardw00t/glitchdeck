package tape

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestExportClassifierRejectsBinaryAndOversizeBodies(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("Z", 24)
	var archive bytes.Buffer
	z := zip.NewWriter(&archive)
	member, err := z.Create("text.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Write([]byte(secret)); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	g := gzip.NewWriter(&compressed)
	if _, err := g.Write(bytes.Repeat([]byte("a"), maxCassetteBody+1)); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	var binaryGzip bytes.Buffer
	g = gzip.NewWriter(&binaryGzip)
	if _, err := g.Write([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, body, media, storage string }{
		{"MP4 spoof", "+/v8ftyp-sk+AC0-ant-" + strings.Repeat("Z", 24), "video/mp4", ""},
		{"PNG", "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", "image/png", ""},
		{"ZIP member", archive.String(), "application/octet-stream", ""},
		{"base64 text", "b3JkaW5hcnk=", "text/plain", "base64"},
		{"oversize decoded gzip", compressed.String(), "application/gzip", ""},
		{"gzip of binary", binaryGzip.String(), "application/gzip", ""},
		{"oversize text", strings.Repeat("a", maxCassetteBody+1), "text/plain", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := Tape{Cassettes: []Cassette{{Response: CassetteResponse{
				Body: tc.body, BodyEncoding: tc.storage, Headers: map[string]string{"Content-Type": tc.media},
			}}}}
			var blocked *ExportBlockedError
			if _, err := PrepareExport(in, false); !errors.As(err, &blocked) || blocked.Kind != "unscannable_encoding" || blocked.Field != "$.cassettes[0].response.body" {
				t.Errorf("expected a safe encoding block, got %v", err)
			}
			out, err := PrepareExport(in, true)
			if err != nil || !out.Redacted || out.Cassettes[0].Response.Body != "REDACTED" || out.Cassettes[0].Response.BodyEncoding != "" {
				t.Fatalf("expected whole-body replacement, got %v", err)
			}
		})
	}
}

func TestExportClassifierScansForeignHTTPAssertion(t *testing.T) {
	type HTTP struct{ Value string }
	secret := "sk-ant-" + strings.Repeat("Z", 24)
	in := Tape{Assertions: []Assertion{{JSONEq: map[string]any{"example": HTTP{Value: secret}}}}}
	var blocked *ExportBlockedError
	if _, err := PrepareExport(in, false); !errors.As(err, &blocked) || blocked.Kind != "anthropic" {
		t.Fatalf("expected generic assertion scan to block, got %v", err)
	}
	out, err := PrepareExport(in, true)
	if err != nil || !out.Redacted || out.Assertions[0].JSONEq["example"].(HTTP).Value != "REDACTED" {
		t.Fatalf("expected generic assertion scan to redact, got %v", err)
	}
}

func TestExportClassifierRejectsUnscannableBodies(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("Z", 24)
	cases := []struct {
		name, body, media, encoding string
		ws                          bool
	}{
		{"IBM037 SQL", "TFrE1sPj6NfFQKdAukxaxdXjyePoQIiol4iFlUB/UHv09V5/brtuTKdAkoWofn+iklCIqJeIhZVegZWjYOnp6enp6enp6enp6enp6enp6enp6enp6X9hbg==", "application/sql", "base64", false},
		{"octet stream UTF-7", "+/v8-" + secret, "application/octet-stream", "", false},
		{"BOM-less UTF-16 body", "h\x00e\x00l\x00l\x00o\x00", "text/plain", "", false},
		{"unproved base64 text", "b3JkaW5hcnk=", "application/octet-stream", "base64", false},
		{"BOM-less UTF-16 WebSocket", "h\x00e\x00l\x00l\x00o\x00", "", "", true},
		{"multipart charset", "--x\r\nContent-Disposition: form-data; name=\"_charset_\"\r\n\r\nutf-7\r\n--x\r\nContent-Disposition: form-data; name=\"value\"\r\nContent-Type: text/plain\r\n\r\nsk+AC0-ant-" + strings.Repeat("Z", 24) + "\r\n--x--\r\n", "multipart/form-data; boundary=x", "", false},
		{"malformed content type", secret, "text/plain; charset=", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := Tape{Version: 3, Target: "demo"}
			path := "$.cassettes[0].response.body"
			if tc.ws {
				in.Version = 2
				in.Script = []Step{{WS: &WS{Path: "/ws", Messages: []string{tc.body}}}}
				path = "$.script[0].ws.messages[0]"
			} else {
				in.Cassettes = []Cassette{{Request: CassetteRequest{Method: "GET", Path: "/"}, Response: CassetteResponse{Status: 200, Body: tc.body, BodyEncoding: tc.encoding, Headers: map[string]string{"Content-Type": tc.media}}}}
			}
			var blocked *ExportBlockedError
			var output bytes.Buffer
			err := Encode(&output, in)
			if !errors.As(err, &blocked) || blocked.Kind != "unscannable_encoding" || blocked.Field != path || output.Len() != 0 || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), tc.body) {
				t.Fatalf("expected safe block at %s, got %v and %d bytes", path, err, output.Len())
			}
			clean, err := PrepareExport(in, true)
			if err != nil || !clean.Redacted {
				t.Fatalf("redaction failed: %v", err)
			}
			if tc.ws {
				if clean.Script[0].WS.Messages[0] != "REDACTED" {
					t.Fatal("missing WebSocket marker")
				}
			} else if response := clean.Cassettes[0].Response; response.Body != "REDACTED" || response.BodyEncoding != "" {
				t.Fatal("missing body marker")
			}
			output.Reset()
			if err := Encode(&output, clean); err != nil {
				t.Fatalf("encoding redacted tape: %v", err)
			}
			decoded, err := Decode(&output)
			if err != nil || !decoded.Redacted {
				t.Fatalf("redacted tape does not validate: %v", err)
			}
		})
	}
}

func TestExportClassifierAcceptsKnownRepresentations(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("Z", 24)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write([]byte(`{"value":"ordinary"}`))
	_ = writer.Close()
	utf16Body := []byte{0xff, 0xfe}
	for _, r := range utf16.Encode([]rune(`{"value":"ordinary"}`)) {
		utf16Body = binary.LittleEndian.AppendUint16(utf16Body, r)
	}
	cases := []struct{ name, body, media string }{
		{"JSON", `{"value":"ordinary"}`, "application/json"},
		{"XML", `<?xml version="1.0" encoding="utf-8"?><x>ordinary</x>`, "application/xml"},
		{"SSE", "data: ordinary\n\n", "text/event-stream"},
		{"UTF-16 JSON", string(utf16Body), "application/json"},
		{"gzip JSON", compressed.String(), "application/gzip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := Tape{Version: 2, Target: "demo", Script: []Step{{HTTP: &HTTP{Method: "POST", Path: "/", Body: tc.body, Headers: map[string]string{"Content-Type": tc.media}}}}}
			out, err := PrepareExport(in, false)
			if err != nil || out.Redacted || out.Script[0].HTTP.Body != tc.body {
				t.Fatalf("clean representation changed or rejected: %v", err)
			}
			var output bytes.Buffer
			if err := Encode(&output, out); err != nil {
				t.Fatalf("encoding clean tape: %v", err)
			}
			if _, err := Decode(&output); err != nil {
				t.Fatalf("clean tape does not validate: %v", err)
			}
		})
	}
	for _, tc := range []struct{ media, body string }{
		{"application/json", `{"value":"` + secret + `"}`},
		{"application/xml", `<?xml version="1.0" encoding="utf-8"?><x>` + secret + `</x>`},
		{"text/event-stream", "data: " + secret + "\n\n"},
	} {
		in := Tape{Cassettes: []Cassette{{Response: CassetteResponse{Body: tc.body, Headers: map[string]string{"Content-Type": tc.media}}}}}
		var blocked *ExportBlockedError
		if _, err := PrepareExport(in, false); !errors.As(err, &blocked) || blocked.Kind != "anthropic" {
			t.Errorf("%s credential not detected: %v", tc.media, err)
		}
	}
}

func TestExportClassifierDetectsEncodedTextSecrets(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("Z", 24)
	text := `{"value":"` + secret + `"}`
	utf16Body := []byte{0xff, 0xfe}
	for _, r := range utf16.Encode([]rune(text)) {
		utf16Body = binary.LittleEndian.AppendUint16(utf16Body, r)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write([]byte(text))
	_ = writer.Close()
	for _, tc := range []struct{ name, media, body string }{
		{"UTF-16 JSON", "application/json", string(utf16Body)},
		{"gzip JSON", "application/gzip", compressed.String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := Tape{Script: []Step{{HTTP: &HTTP{Body: tc.body, Headers: map[string]string{"Content-Type": tc.media}}}}}
			var blocked *ExportBlockedError
			if _, err := PrepareExport(in, false); !errors.As(err, &blocked) || blocked.Kind != "anthropic" {
				t.Fatalf("credential not detected: %v", err)
			}
		})
	}
}

func FuzzExportClassifierInvariant(f *testing.F) {
	secret := "sk-ant-" + strings.Repeat("Z", 24)
	f.Add([]byte("+/v8ftyp-sk+AC0-ant-secret"), "video/mp4", "", "", uint8(0), false)
	f.Add([]byte("PK\x03\x04"+strings.Repeat("\x00", 36)), "application/octet-stream", "", "", uint8(0), false)
	f.Add([]byte("ordinary"), "text/plain", "", "", uint8(1), false)
	f.Add([]byte("ordinary"), "application/json", "", "", uint8(0), false)
	f.Add([]byte("+/v8-"+secret), "application/octet-stream", "", "", uint8(0), false)
	f.Add([]byte("h\x00e\x00l\x00l\x00o\x00"), "text/plain", "", "", uint8(0), false)
	f.Add([]byte("h\x00e\x00l\x00l\x00o\x00"), "text/plain", "", "", uint8(2), false)
	f.Add([]byte("h\x00e\x00l\x00l\x00o\x00"), "", "", "", uint8(0), true)
	f.Add([]byte("--x\r\nContent-Disposition: form-data; name=\"_charset_\"\r\n\r\nutf-7\r\n--x\r\nContent-Type: text/plain\r\n\r\nsk+AC0-ant-secret\r\n--x--\r\n"), "multipart/form-data; boundary=x", "", "", uint8(0), false)
	f.Add([]byte(secret), "text/plain; charset=", "", "", uint8(0), false)
	f.Add([]byte(`<!DOCTYPE x [<!ENTITY x "&#45;">]><x>sk&x;ant-synthetic</x>`), "application/xml", "", "", uint8(0), false)
	f.Add([]byte(`<x key="sk&#45;ant-synthetic"/>`), "", "", "", uint8(0), true)
	f.Add([]byte(`<?xml version="1.0" encoding="UTF-7"?><x>sk+AC0-ant-secret</x>`), "", "", "", uint8(0), true)
	f.Add([]byte(`{"key":"`+secret+`"}`), "application/json; charset=ibm037", "", "", uint8(0), false)
	f.Add([]byte("plain\x80"+secret), "text/plain", "", "", uint8(0), false)
	f.Add([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"), "image/png", "", "", uint8(0), false)
	f.Add([]byte("\x01\x00\x00\x00\x03abc"), "application/grpc", "gzip", "", uint8(0), false)
	f.Add([]byte{0x4c, 0x5a, 0xc4, 0xd6, 0xc3, 0xe3, 0xe8, 0xd7, 0xc5}, "application/sql", "", "", uint8(1), false)
	ibm037, _ := base64.StdEncoding.DecodeString("TFrE1sPj6NfFQKdAukxaxdXjyePoQIiol4iFlUB/UHv09V5/brtuTKdAkoWofn+iklCIqJeIhZVegZWjYOnp6enp6enp6enp6enp6enp6enp6enp6X9hbg==")
	f.Add(ibm037, "application/xml", "", "", uint8(1), false)
	f.Add([]byte{0xff, 0xfe, '{', 0, '}', 0}, "application/json", "", "", uint8(1), false)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write([]byte(`{"value":"` + secret + `"}`))
	_ = writer.Close()
	f.Add(compressed.Bytes(), "application/json", "gzip", "", uint8(1), false)
	f.Fuzz(func(t *testing.T, raw []byte, media, encoding, charset string, storage uint8, ws bool) {
		if len(raw) == 0 || len(raw) > 4096 || len(media) > 256 || len(encoding) > 64 || len(charset) > 64 {
			return
		}
		body := string(raw)
		http := !ws && storage%3 == 2
		storedBase64 := !ws && !http && storage%3 == 1
		if storedBase64 {
			body = base64.StdEncoding.EncodeToString(raw)
		}
		contentType := media
		if charset != "" {
			contentType += "; charset=" + charset
		}
		headers := map[string]string{}
		if contentType != "" {
			headers["Content-Type"] = contentType
		}
		if encoding != "" {
			headers["Content-Encoding"] = encoding
		}
		contentType = strings.TrimSpace(contentType)
		encoding = strings.ToLower(strings.TrimSpace(encoding))
		in := Tape{Version: 2, Target: "demo"}
		field := "$.cassettes[0].response.body"
		if ws {
			in.Script = []Step{{WS: &WS{Path: "/ws", Messages: []string{body}}}}
			contentType, encoding = "", ""
			field = "$.script[0].ws.messages[0]"
		} else if http {
			in.Script = []Step{{HTTP: &HTTP{Method: "POST", Path: "/", Headers: headers, Body: body}}}
			field = "$.script[0].http.body"
		} else {
			bodyEncoding := ""
			if storedBase64 {
				bodyEncoding = "base64"
			}
			in.Version = 3
			in.Cassettes = []Cassette{{Request: CassetteRequest{Method: "GET", Path: "/"}, Response: CassetteResponse{Status: 200, Body: body, BodyEncoding: bodyEncoding, Headers: headers}}}
		}
		budget := 64 << 20
		class, classErr := classifyExportBody(string(raw), contentType, encoding, "", "", field, &budget, storedBase64)
		budget = 64 << 20
		_, _, scanErr := scanExportBodyPayload(string(raw), contentType, encoding, "", "", field, false, 0, &budget, storedBase64)
		out, err := PrepareExport(in, false)
		if err == nil {
			retained := false
			if ws {
				retained = out.Script[0].WS.Messages[0] == body
			} else if http {
				retained = out.Script[0].HTTP.Body == body
			} else {
				retained = out.Cassettes[0].Response.Body == body
			}
			if retained && (storedBase64 || classErr != nil || scanErr != nil || (class.kind != exportCleanText && class.kind != exportCompressed && class.kind != exportMultipart)) {
				t.Fatalf("export retained an unscannable body: classifier=%v scanner=%v", classErr, scanErr)
			}
		}
		var blocked, scanBlocked *ExportBlockedError
		if errors.As(scanErr, &scanBlocked) && scanBlocked.Kind == "unscannable_encoding" && errors.As(err, &blocked) && blocked.Kind == "unscannable_encoding" && blocked.Field == field {
			clean, redactErr := PrepareExport(in, true)
			if redactErr != nil {
				t.Fatalf("unscannable body could not be redacted: %v", redactErr)
			}
			if ws {
				if clean.Script[0].WS.Messages[0] != "REDACTED" {
					t.Fatal("unscannable WebSocket body retained")
				}
			} else if http {
				if clean.Script[0].HTTP.Body != "REDACTED" {
					t.Fatal("unscannable HTTP body retained")
				}
			} else if response := clean.Cassettes[0].Response; response.Body != "REDACTED" || response.BodyEncoding != "" {
				t.Fatal("unscannable cassette body retained")
			}
		}
	})
}
