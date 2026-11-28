package tape

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/url"
	"reflect"
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
	clean, err := PrepareExport(Tape{Script: []Step{{HTTP: &HTTP{Headers: map[string]string{"Content-Encoding": "gzip"}, Body: gz.String()}}}}, false)
	if err != nil || clean.Script[0].HTTP.Body != "clean" || clean.Script[0].HTTP.Headers["Content-Encoding"] != "" {
		t.Fatalf("gzip metadata was not stripped: %v", err)
	}
	if _, err := PrepareExport(Tape{Script: []Step{{HTTP: &HTTP{Headers: map[string]string{"Content-Encoding": "deflate"}, Body: z.String()}}}}, false); err == nil {
		t.Fatal("deflate trailing data was accepted")
	}
	var raw bytes.Buffer
	fw, _ := flate.NewWriter(&raw, flate.DefaultCompression)
	_, _ = fw.Write([]byte(secret))
	_ = fw.Close()
	in := Tape{Script: []Step{{HTTP: &HTTP{Headers: map[string]string{"Content-Encoding": "deflate"}, Body: raw.String()}}}}
	out, err := PrepareExport(in, true)
	if err != nil {
		t.Fatal(err)
	}
	if out.Script[0].HTTP.Body != "REDACTED" || out.Script[0].HTTP.Headers["Content-Encoding"] != "" {
		t.Fatal("deflate body not decoded and redacted")
	}
}

func TestScannerInvalidatesValidators(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("q", 24)
	in := Tape{Cassettes: []Cassette{{Response: CassetteResponse{Headers: map[string]string{"Content-Length": "1", "Content-MD5": "old", "Content-Digest": "old", "Repr-Digest": "old", "ETag": "\"old\""}, Body: secret}}}}
	out, err := PrepareExport(in, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Cassettes[0].Response.Headers) != 0 {
		t.Fatal("stale validators retained")
	}
}

func TestScannerIndependentParameters(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("z", 24)
	value := `"sk-ant-\u007a` + strings.Repeat("z", 23) + `"`
	query := "a=%22&b=" + url.QueryEscape(value)
	values, err := url.ParseQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	var decoded string
	if err := json.Unmarshal([]byte(values.Get("b")), &decoded); err != nil || decoded != secret {
		t.Fatalf("fixture: %q %v", decoded, err)
	}
	for _, field := range []string{"$.url", "$.http_get", "$.location", "$.form"} {
		input := query
		if field != "$.form" {
			input = "/?" + query
		}
		if _, _, err := scanText(input, field, false); err == nil {
			t.Fatalf("%s: missed decoded parameter", field)
		}
	}
}

func TestScannerMIMEParameters(t *testing.T) {
	header := "form-data; filename*0=sk-ant-; filename*1=" + strings.Repeat("z", 24)
	_, params, err := mime.ParseMediaType(header)
	if err != nil || !strings.HasPrefix(params["filename"], "sk-ant-") {
		t.Fatalf("fixture: %v %v", params, err)
	}
	body := "--x\r\nContent-Disposition: " + header + "\r\n\r\nok\r\n--x--\r\n"
	if _, _, err := scanBodyText(body, "multipart/form-data; boundary=x", "$", false); err == nil {
		t.Fatal("missed decoded filename")
	}
}

func TestScannerRejectsIncompleteMIMEContinuation(t *testing.T) {
	body := "--x\r\nContent-Disposition: form-data; filename*0=clean; filename*2=ignored\r\n\r\nok\r\n--x--\r\n"
	if _, _, err := scanBodyText(body, "multipart/form-data; boundary=x", "$", false); err == nil {
		t.Fatal("accepted incomplete continuation")
	}
}

func TestScannerExportWorkLimit(t *testing.T) {
	value := strings.Repeat("x", 4<<20)
	in := Tape{Cassettes: make([]Cassette, 9)}
	for i := range in.Cassettes {
		in.Cassettes[i].Response.Body = value
	}
	if _, err := PrepareExport(in, false); err == nil {
		t.Fatal("accepted oversized aggregate")
	}
}

func TestScannerCompressedExpansionLimit(t *testing.T) {
	t.Parallel()
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	_, _ = w.Write(bytes.Repeat([]byte("x"), 4<<20))
	_ = w.Close()
	response := CassetteResponse{Headers: map[string]string{"Content-Encoding": "gzip"}, Body: compressed.String()}
	if _, err := PrepareExport(Tape{Cassettes: []Cassette{{Response: response}}}, false); err != nil {
		t.Fatalf("valid 4 MiB gzip: %v", err)
	}
	compressed.Reset()
	w = gzip.NewWriter(&compressed)
	_, _ = w.Write(bytes.Repeat([]byte("x"), 1024))
	_ = w.Close()
	response.Body = compressed.String()
	one := Cassette{Response: response}
	const work = 1 << 20
	budget := work
	if _, _, err := scanValue(reflect.ValueOf(Tape{Cassettes: []Cassette{one}}), "$", false, &budget); err != nil {
		t.Fatalf("one compressed body: %v", err)
	}
	budget = 2*(work-budget) - 1
	if _, _, err := scanValue(reflect.ValueOf(Tape{Cassettes: []Cassette{one, one}}), "$", false, &budget); err == nil {
		t.Fatal("accepted excessive aggregate expansion")
	}
}

func TestScannerDeclaredRepresentations(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("z", 24)
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	_, _ = w.Write([]byte(secret))
	_ = w.Close()
	utf16 := []byte{0xff, 0xfe}
	for _, b := range []byte(secret) {
		utf16 = append(utf16, b, 0)
	}
	for _, tc := range []struct{ ct, body string }{
		{"text/plain", string(utf16)},
		{"application/gzip", compressed.String()},
		{"multipart/form-data; boundary=x", "--x\r\nContent-Type: application/gzip\r\n\r\n" + compressed.String() + "\r\n--x--\r\n"},
	} {
		if _, _, err := scanBody(tc.body, false, "", tc.ct, "", "$", false); err == nil {
			t.Fatalf("missed %s", tc.ct)
		}
	}
}

func TestScannerSSEPrivateKeyPayload(t *testing.T) {
	body := "data: -----BEGIN " + "PRIVATE KEY-----\ndata: sensitive-payload\ndata: -----END " + "PRIVATE KEY-----\n\n"
	clean, _, err := scanBodyText(body, "text/event-stream", "$", true)
	if err == nil && strings.Contains(clean, "sensitive-payload") {
		t.Fatal("private key payload retained")
	}
}

func TestScannerEscapedSSEPrivateKey(t *testing.T) {
	body := "data: \"\\u002d----BEGIN PRIVATE\\u0020KEY-----\"\ndata: sensitive-payload\ndata: \"-----END PRIVATE\\u0020KEY-----\"\n\n"
	out, _, err := scanBodyText(body, "text/event-stream", "$.body", true)
	if err == nil && strings.Contains(out, "sensitive-payload") {
		t.Fatal("escaped private key payload retained")
	}
}

func TestScannerEscapedSSEPrivateKeyAfterOtherSecret(t *testing.T) {
	body := "data: \"sk-ant-secret \\u002d----BEGIN PRIVATE\\u0020KEY-----\"\ndata: sensitive-payload\ndata: \"-----END PRIVATE\\u0020KEY-----\"\n\n"
	out, _, err := scanBodyText(body, "text/event-stream", "$.body", true)
	if err == nil && strings.Contains(out, "sensitive-payload") {
		t.Fatal("escaped private key payload retained after another secret")
	}
}

func TestScannerHeaderQueryAndSafeFields(t *testing.T) {
	for _, name := range []string{"Link", "Refresh", "X-Custom"} {
		in := Tape{Script: []Step{{HTTP: &HTTP{Headers: map[string]string{name: "</?x=Bearer+eyJabc>"}}}}}
		if _, err := PrepareExport(in, false); err == nil {
			t.Fatalf("%s query was not scanned", name)
		}
		out, err := PrepareExport(in, true)
		if err == nil && strings.Contains(out.Script[0].HTTP.Headers[name], "eyJabc") {
			t.Fatalf("%s retained credential", name)
		}
	}
	secret := "sk-ant-secret-name"
	body := "--x\r\n" + secret + ": value\r\n\r\nok\r\n--x--\r\n"
	_, _, err := scanBodyText(body, "multipart/form-data; boundary=x", "$.body", false)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe diagnostic: %v", err)
	}
}

func TestScannerRedactsDispositionFilename(t *testing.T) {
	in := Tape{Script: []Step{{HTTP: &HTTP{Headers: map[string]string{"Content-Disposition": `attachment; filename="sk-ant-secret.txt"`}}}}}
	out, err := PrepareExport(in, true)
	if err != nil || strings.Contains(out.Script[0].HTTP.Headers["Content-Disposition"], "sk-ant-secret") {
		t.Fatalf("filename not redacted: %v", err)
	}
}

func TestScannerBlocksCompressedContainers(t *testing.T) {
	for _, tc := range []struct{ ct, body string }{
		{"application/zip", "anything"},
		{"application/x-bzip2", "anything"}, {"application/x-xz", "anything"},
		{"application/zstd", "anything"}, {"application/x-7z-compressed", "anything"},
		{"application/octet-stream", "PK\x03\x04compressed"},
	} {
		_, _, err := scanBody(tc.body, false, "", tc.ct, "", "$.body", true)
		var blocked *ExportBlockedError
		if !errors.As(err, &blocked) || blocked.Kind != "unscannable_encoding" {
			t.Fatalf("%s: expected unscannable encoding, got %v", tc.ct, err)
		}
	}
}

func TestScannerCompressedMediaAndMagic(t *testing.T) {
	for _, tc := range []struct {
		name      string
		newWriter func(io.Writer) io.WriteCloser
		media     string
	}{
		{"gzip", func(w io.Writer) io.WriteCloser { return gzip.NewWriter(w) }, "application/gzip"},
		{"zlib", func(w io.Writer) io.WriteCloser { return zlib.NewWriter(w) }, "application/zlib"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, payload := range []string{"ordinary", "sk-ant-secret"} {
				var compressed bytes.Buffer
				w := tc.newWriter(&compressed)
				_, _ = io.WriteString(w, payload)
				_ = w.Close()
				for _, media := range []string{tc.media, "text/plain", "application/octet-stream"} {
					got, _, err := scanBody(compressed.String(), false, "", media, "", "$.body", true)
					want := payload
					if want != "ordinary" {
						want = "REDACTED"
					}
					if (err != nil) != (media == "application/octet-stream") || err == nil && got != want {
						t.Fatalf("%s payload %q was not safely normalized: %v", media, payload, err)
					}
				}
			}
		})
	}
}

func TestScannerRejectsSplitAndMismatchedPEM(t *testing.T) {
	for _, body := range []string{
		`["\u002d----BEGIN PRIVATE KEY-----","sensitive-payload","-----END PRIVATE KEY-----"]`,
		`["sk-ant-secret","-----BEGIN RSA ` + `PRIVATE KEY-----payload-----END EC PRIVATE KEY-----"]`,
		`["\u002d----BEGIN RSA PRIVATE KEY-----wrong-----END EC PRIVATE KEY-----sensitive-payload-----END RSA PRIVATE KEY-----"]`,
		`["-----BEGIN PRIVATE ` + `KEY-----payload","-----END PRIVATE KEY-----"]`,
	} {
		in := Tape{Script: []Step{{HTTP: &HTTP{Body: body}}}}
		out, err := PrepareExport(in, true)
		if err == nil {
			t.Fatalf("exported incomplete PEM: %q", out.Script[0].HTTP.Body)
		}
	}
}

func TestScannerBlocksHTTPQuotedPairHeaderCredential(t *testing.T) {
	for _, value := range []string{`</>; title="sk\-\ant-secret"`, `</>; title="sk-an\t-secret"`} {
		in := Tape{Script: []Step{{HTTP: &HTTP{Headers: map[string]string{"Link": value}}}}}
		for _, redact := range []bool{false, true} {
			out, err := PrepareExport(in, redact)
			if err == nil {
				t.Fatalf("exported escaped header: %q", out.Script[0].HTTP.Headers["Link"])
			}
		}
	}
}

func TestScannerBlocksDuplicateMultipartEncodings(t *testing.T) {
	for _, name := range []string{"Content-Transfer-Encoding", "Content-Encoding", "Grpc-Encoding"} {
		value := "identity"
		if name == "Content-Transfer-Encoding" {
			value = "binary"
		}
		body := "--x\r\n" + name + ": " + value + "\r\n" + name + ": " + value + "\r\n\r\nok\r\n--x--\r\n"
		in := Tape{Cassettes: []Cassette{{Response: CassetteResponse{Headers: map[string]string{"Content-Type": "multipart/form-data; boundary=x"}, Body: body}}}}
		if _, err := PrepareExport(in, false); err == nil {
			t.Fatalf("accepted duplicate %s", name)
		}
	}
}

func TestScannerSSELiteralPercent(t *testing.T) {
	body := "data: 50% complete\n\n"
	in := Tape{Cassettes: []Cassette{{Response: CassetteResponse{Headers: map[string]string{"Content-Type": "text/event-stream"}, Body: body}}}}
	for _, redact := range []bool{false, true} {
		out, err := PrepareExport(in, redact)
		if err != nil || out.Cassettes[0].Response.Body != body {
			t.Fatalf("literal percent: %v", err)
		}
	}
	in.Cassettes[0].Response.Body = "data: %2D----BEGIN PRIVATE KEY-----\ndata: sensitive-payload\n\n"
	for _, redact := range []bool{false, true} {
		if _, err := PrepareExport(in, redact); err == nil {
			t.Fatal("escaped SSE private key was exported")
		}
	}
}

func TestScannerRequestOnlyExportSkipsCassetteDigest(t *testing.T) {
	body := "[" + strings.Repeat("0,", 40000) + `"sk-ant-secret"]`
	in := Tape{Script: []Step{{HTTP: &HTTP{Method: "POST", Path: "/", Body: body}}}}
	out, err := PrepareExport(in, true)
	if err != nil || strings.Contains(out.Script[0].HTTP.Body, "sk-ant-secret") || !out.Redacted {
		t.Fatalf("request-only redaction failed: %v", err)
	}
}

func TestScannerBlocksRedactingPartialResponseBody(t *testing.T) {
	in := Tape{Cassettes: []Cassette{{Response: CassetteResponse{Status: 206, Headers: map[string]string{"Content-Range": "bytes 0-24/100"}, Body: "sk-ant-long-secret-value"}}}}
	if _, err := PrepareExport(in, true); err == nil {
		t.Fatal("redacted partial response with stale byte range")
	}
}
