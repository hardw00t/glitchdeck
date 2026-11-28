package tape

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestScannerFailClosedRepresentations(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("z", 24)
	cases := []struct{ name, body, contentType string }{
		{"sse-comment-pem", ": -----BEGIN " + "PRIVATE KEY-----\n: sensitive-payload\n: -----END " + "PRIVATE KEY-----\n\n", "text/event-stream"},
		{"unfinished-json", `{"key":"sk-ant-\u007a` + strings.Repeat("z", 23), "application/json"},
		{"message", "Content-Transfer-Encoding: base64\r\n\r\nc2VjcmV0", "message/rfc822"},
		{"digest", "--x\r\n\r\nContent-Transfer-Encoding: base64\r\n\r\nc2VjcmV0\r\n--x--\r\n", "multipart/digest; boundary=x"},
		{"mime-encoded-word", "--x\r\nContent-Description: =?UTF-8?B?c2VjcmV0?=\r\n\r\nok\r\n--x--\r\n", "multipart/mixed; boundary=x"},
		{"mime-location", "--x\r\nContent-Location: /?token=Bearer+eyJabc\r\n\r\nok\r\n--x--\r\n", "multipart/mixed; boundary=x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, redact := range []bool{false, true} {
				out, _, err := scanBodyText(tc.body, tc.contentType, "$.body", redact)
				if err == nil && (strings.Contains(out, "sensitive-payload") || strings.Contains(out, secret) || tc.name != "sse-comment-pem") {
					t.Fatalf("accepted uninspectable content, redact=%v", redact)
				}
				if err != nil {
					var blocked *ExportBlockedError
					if !errors.As(err, &blocked) || blocked.Field == "" {
						t.Fatalf("unsafe error: %v", err)
					}
				}
			}
		})
	}
}

func TestScannerHTTPHeadersUseMIMEPolicy(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"Content-Location", "/?token=Bearer+eyJabc"},
		{"Content-Disposition", "attachment; filename*=UTF-8''c2VjcmV0"},
		{"Content-Description", "=?UTF-8?B?c2VjcmV0?="},
		{"X-Custom", "attachment; name*=UTF-8''c2VjcmV0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := Tape{Script: []Step{{HTTP: &HTTP{Headers: map[string]string{tc.name: tc.value}}}}}
			for _, redact := range []bool{false, true} {
				out, err := PrepareExport(input, redact)
				if err == nil && (tc.name != "Content-Location" || strings.Contains(out.Script[0].HTTP.Headers[tc.name], "eyJabc")) {
					t.Fatalf("accepted %s, redact=%v", tc.name, redact)
				}
			}
		})
	}
}

func TestScannerFormDetectionAllocations(t *testing.T) {
	long := strings.Repeat("a&", 100000)
	result := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _ = scanText(long, "$.form", false)
		}
	})
	if got := result.AllocedBytesPerOp(); got > 100000 {
		t.Fatalf("detection allocated %d bytes for separator-heavy form", got)
	}
}

func TestScannerFormReconstructionUsesSharedBudget(t *testing.T) {
	form := "safe=ok&secret=sk-ant-abc"
	budget := 2*len(form) - 1
	if _, _, err := scanTextDepth(form, "$.form", true, 0, &budget); err == nil {
		t.Fatal("redaction exceeded reconstruction budget")
	}
	budget = 2 * len(form)
	out, changed, err := scanTextDepth(form, "$.form", true, 0, &budget)
	if err != nil || !changed || out != "safe=ok&secret=REDACTED" || budget != 0 {
		t.Fatalf("redaction = %q, changed=%v, budget=%d, err=%v", out, changed, budget, err)
	}
}

func TestScannerSSEAndHeaderAllocations(t *testing.T) {
	sseBody := strings.Repeat("\n", 100000)
	header := strings.Repeat(";", 100000)
	for _, tc := range []struct {
		name string
		run  func()
	}{
		{"sse", func() {
			_, _, _ = scanBodyText(sseBody, "text/event-stream", "$.body", false)
		}},
		{"header", func() {
			budget := 64 << 20
			_, _, _ = scanHeader("X-Test", header, "$.headers", false, &budget)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := testing.Benchmark(func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					tc.run()
				}
			})
			if got := result.AllocedBytesPerOp(); got > 2<<20 {
				t.Fatalf("allocated %d bytes for separator-heavy input", got)
			}
		})
	}
}

func TestScannerSSEBufferBudget(t *testing.T) {
	body := strings.Repeat("\n", 1000)
	budget := 1000
	if _, _, err := scanContentBudget(body, "text/event-stream", "$.body", false, 0, &budget, false); err == nil {
		t.Fatal("SSE buffers exceeded work budget")
	}
}

func TestExportUnscannableXML(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("z", 24)
	for _, body := range []string{
		`<!DOCTYPE x [<!ENTITY hyphen "&#45;">]><x key="sk&hyphen;ant-` + strings.Repeat("z", 24) + `"/>`,
		`<!doctype x [ ]><x/>`,
		`<!DOCTYPE x SYSTEM "http://example.invalid/a>b" [ ]><x/>`,
		`&lt;!ENTITY x "value"&gt;<x/>`,
	} {
		for _, ws := range []bool{false, true} {
			input := Tape{Script: []Step{{HTTP: &HTTP{Body: body}}}}
			if ws {
				input.Script[0] = Step{WS: &WS{Messages: []string{body}}}
			}
			_, err := PrepareExport(input, false)
			var blocked *ExportBlockedError
			if !errors.As(err, &blocked) || blocked.Kind != "unscannable_xml_entity" {
				t.Fatalf("body %q ws=%v: expected XML block, got %v", body, ws, err)
			}
			out, err := PrepareExport(input, true)
			if err != nil || !out.Redacted {
				t.Fatalf("redact ws=%v: %v", ws, err)
			}
			got := ""
			if ws {
				got = out.Script[0].WS.Messages[0]
			} else {
				got = out.Script[0].HTTP.Body
			}
			if got != "REDACTED" || strings.Contains(got, secret) {
				t.Fatalf("unsafe replacement %q", got)
			}
		}
	}
}

func TestExportWebSocketEntitySecret(t *testing.T) {
	body := `<x key="sk&#45;ant-` + strings.Repeat("z", 24) + `"/>`
	input := Tape{Script: []Step{{WS: &WS{Messages: []string{body}}}}}
	if _, err := PrepareExport(input, false); err == nil {
		t.Fatal("entity-encoded WebSocket credential accepted")
	}
	out, err := PrepareExport(input, true)
	if err != nil || !out.Redacted || out.Script[0].WS.Messages[0] != "REDACTED" {
		t.Fatalf("redaction failed: %#v, %v", out, err)
	}
}

func TestExportRetainedUnscannableEncoding(t *testing.T) {
	for _, header := range []string{"Content-Encoding", "Grpc-Encoding", "Transfer-Encoding"} {
		input := Tape{Script: []Step{{HTTP: &HTTP{Body: "opaque payload", Headers: map[string]string{header: "br", "Content-Length": "14"}}}}}
		_, err := PrepareExport(input, false)
		var blocked *ExportBlockedError
		if !errors.As(err, &blocked) || blocked.Kind != "unscannable_encoding" {
			t.Fatalf("%s: expected encoding block, got %v", header, err)
		}
		out, err := PrepareExport(input, true)
		if err != nil || !out.Redacted || out.Script[0].HTTP.Body != "REDACTED" || len(out.Script[0].HTTP.Headers) != 0 {
			t.Fatalf("%s: unsafe replacement %#v, %v", header, out, err)
		}
	}
}

func TestExportEncodedXMLDeclaration(t *testing.T) {
	xml := `<!DOCTYPE x [<!ENTITY x "&#45;">]><x>sk&x;ant-synthetic</x>`
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	if _, err := w.Write([]byte(xml)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{base64.StdEncoding.EncodeToString([]byte(xml)), base64.StdEncoding.EncodeToString(compressed.Bytes())} {
		input := Tape{Cassettes: []Cassette{{Response: CassetteResponse{Status: 200, Body: body, BodyEncoding: "base64"}}}}
		_, err := PrepareExport(input, false)
		var blocked *ExportBlockedError
		if !errors.As(err, &blocked) || blocked.Kind != "unscannable_xml_entity" {
			t.Fatalf("expected XML block, got %v", err)
		}
		out, err := PrepareExport(input, true)
		if err != nil || !out.Redacted || out.Cassettes[0].Response.Body != "REDACTED" || out.Cassettes[0].Response.BodyEncoding != "" {
			t.Fatalf("unsafe replacement: %#v, %v", out, err)
		}
	}
}

func TestExportCompressedGRPCFrame(t *testing.T) {
	frame := "\x01\x00\x00\x00\x03abc"
	for _, step := range []Step{
		{HTTP: &HTTP{Body: frame}},
		{GRPC: &GRPC{MessageB64: base64.StdEncoding.EncodeToString([]byte(frame))}},
	} {
		input := Tape{Script: []Step{step}}
		_, err := PrepareExport(input, false)
		var blocked *ExportBlockedError
		if !errors.As(err, &blocked) || blocked.Kind != "unscannable_encoding" {
			t.Fatalf("expected encoding block, got %v", err)
		}
		out, err := PrepareExport(input, true)
		if err != nil || !out.Redacted {
			t.Fatalf("redaction failed: %v", err)
		}
		if out.Script[0].HTTP != nil && out.Script[0].HTTP.Body != "REDACTED" {
			t.Fatal("HTTP frame retained")
		}
		if out.Script[0].GRPC != nil && out.Script[0].GRPC.MessageB64 != "UkVEQUNURUQ=" {
			t.Fatal("gRPC frame retained")
		}
	}
}

func TestExportEmptyEncodedBody(t *testing.T) {
	input := Tape{Cassettes: []Cassette{{Response: CassetteResponse{Status: 204, Headers: map[string]string{"Content-Encoding": "br"}}}}}
	if _, err := PrepareExport(input, false); err != nil {
		t.Fatalf("empty body blocked: %v", err)
	}
	input.Cassettes[0].Response.UnscannableEncoding = true
	if _, err := PrepareExport(input, false); err == nil {
		t.Fatal("discarded encoded body accepted")
	}
	out, err := PrepareExport(input, true)
	if err != nil || out.Cassettes[0].Response.Body != "REDACTED" {
		t.Fatalf("discarded body not redacted: %v", err)
	}
}

func TestExportReviewFailClosed(t *testing.T) {
	t.Run("websocket incomplete PEM", func(t *testing.T) {
		input := Tape{Script: []Step{{WS: &WS{Messages: []string{"-----BEGIN PRIVATE KEY-----\nincomplete"}}}}}
		if _, err := PrepareExport(input, true); err == nil {
			t.Fatal("incomplete private key accepted")
		}
	})
	t.Run("compressed frame before partial frame", func(t *testing.T) {
		input := Tape{Script: []Step{{HTTP: &HTTP{Body: "\x01\x00\x00\x00\x03abc\x00"}}}}
		_, err := PrepareExport(input, false)
		var blocked *ExportBlockedError
		if !errors.As(err, &blocked) || blocked.Kind != "unscannable_encoding" {
			t.Fatalf("expected encoding block, got %v", err)
		}
	})
	t.Run("disallowed charset blocks XML before inspecting declarations", func(t *testing.T) {
		for _, body := range []string{`<!ENTITY x "value">`, `&lt;!ENTITY x "value"&gt;`} {
			input := Tape{Script: []Step{{HTTP: &HTTP{Body: body, Headers: map[string]string{"Content-Type": "text/xml; charset=unknown"}}}}}
			_, err := PrepareExport(input, false)
			var blocked *ExportBlockedError
			if !errors.As(err, &blocked) || blocked.Kind != "unscannable_encoding" {
				t.Fatalf("expected encoding block, got %v", err)
			}
			out, err := PrepareExport(input, true)
			if err != nil || out.Script[0].HTTP.Body != "REDACTED" {
				t.Fatalf("XML redaction failed: %v", err)
			}
		}
	})
	t.Run("partial response replaced completely", func(t *testing.T) {
		input := Tape{Cassettes: []Cassette{{Response: CassetteResponse{Status: 206, Headers: map[string]string{"Content-Range": "bytes 0-2/3"}, Body: `<!ENTITY x "value">`}}}}
		out, err := PrepareExport(input, true)
		if err != nil || out.Cassettes[0].Response.Status != 200 || out.Cassettes[0].Response.Body != "REDACTED" || len(out.Cassettes[0].Response.Headers) != 0 {
			t.Fatalf("partial response replacement failed: %#v, %v", out, err)
		}
	})
}
