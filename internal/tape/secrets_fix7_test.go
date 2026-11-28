package tape

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestFix7EncodedRepresentations(t *testing.T) {
	secret := "sk" + "-ant-" + strings.Repeat("z", 24)
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	_, _ = w.Write([]byte("v=Bearer+eyJ" + strings.Repeat("x", 20)))
	_ = w.Close()
	cases := []struct {
		name, contentType, body, bodyEncoding, header string
	}{
		{"decimal entity", "application/xml", `<v a="sk&#45;ant-` + strings.Repeat("z", 24) + `"/>`, "", ""},
		{"hex entity", "text/plain", "sk&#x2d;ant-" + strings.Repeat("z", 24), "", ""},
		{"uppercase hex entity", "text/html", "sk&#X2D;ant-" + strings.Repeat("z", 24), "", ""},
		{"nul entity", "application/xml", strings.Join(strings.Split("sk&#45;ant-"+strings.Repeat("z", 24), ""), "\x00"), "", ""},
		{"header comment", "", "clean", "", `(sk\-ant-` + strings.Repeat("z", 24) + `)`},
		{"header unquoted", "", "clean", "", `sk\-ant-` + strings.Repeat("z", 24)},
		{"inferred gzip form", "application/x-www-form-urlencoded", compressed.String(), "", ""},
		{"stored base64", "application/octet-stream", "AK" + "IA" + strings.Repeat("A", 16), "base64", ""},
		{"compress media", "application/x-compress", "clean", "", ""},
		{"compress magic", "application/octet-stream", base64.StdEncoding.EncodeToString([]byte("\x1f\x9d\x90clean")), "base64", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{}
			if tc.contentType != "" {
				headers["Content-Type"] = tc.contentType
			}
			if tc.header != "" {
				headers["Server"] = tc.header
			}
			in := Tape{Cassettes: []Cassette{{Response: CassetteResponse{Headers: headers, Body: tc.body, BodyEncoding: tc.bodyEncoding}}}}
			for _, redact := range []bool{false, true} {
				out, err := PrepareExport(in, redact)
				unscannable := strings.HasPrefix(tc.name, "compress") || tc.name == "nul entity" || tc.name == "stored base64"
				if redact && tc.name == "inferred gzip form" {
					if err != nil || !out.Redacted || out.Cassettes[0].Response.Body != "v=REDACTED" {
						t.Errorf("expected decoded form with the credential removed, got %v", err)
					}
					continue
				}
				if unscannable && redact {
					if err != nil || out.Cassettes[0].Response.Body != "REDACTED" || !out.Redacted {
						t.Errorf("expected whole-body replacement, got %v", err)
					}
					continue
				}
				var blocked *ExportBlockedError
				if !errors.As(err, &blocked) || strings.Contains(err.Error(), secret) {
					t.Errorf("redact=%v: expected safe block, got %v", redact, err)
				}
				if unscannable && blocked != nil && blocked.Kind != "unscannable_encoding" {
					t.Errorf("redact=%v: kind %s", redact, blocked.Kind)
				}
			}
		})
	}
}

func TestFix7SafeRepresentations(t *testing.T) {
	for _, body := range []string{"ordinary &amp; text &#65;", "sk&hyphen;ant-" + strings.Repeat("z", 24), "sk&#45ant-" + strings.Repeat("z", 24), "ordinary"} {
		in := Tape{Cassettes: []Cassette{{Response: CassetteResponse{Headers: map[string]string{"Content-Type": "text/plain", "Server": `ordinary\ value`}, Body: body}}}}
		for _, redact := range []bool{false, true} {
			out, err := PrepareExport(in, redact)
			if err != nil || out.Cassettes[0].Response.Body != body {
				t.Errorf("body %q redact=%v: %v", body, redact, err)
			}
		}
	}
}

func TestFix7LiteralRedactionWithUnrelatedEncoding(t *testing.T) {
	secret := "sk" + "-ant-" + strings.Repeat("z", 24)
	in := Tape{Cassettes: []Cassette{{Response: CassetteResponse{
		Headers: map[string]string{"Content-Type": "text/plain", "Server": secret + ` \x`},
		Body:    secret + " &amp; clean",
	}}}}
	if _, err := PrepareExport(in, false); err == nil {
		t.Fatal("literal secret accepted")
	}
	out, err := PrepareExport(in, true)
	if err != nil {
		t.Fatal(err)
	}
	response := out.Cassettes[0].Response
	if response.Body != "REDACTED &amp; clean" || response.Headers["Server"] != `REDACTED \x` {
		t.Fatalf("unexpected redaction: %#v", response)
	}
}

func TestFix7DerivedOverlapAndContainers(t *testing.T) {
	for _, tc := range []struct{ name, body, header, media string }{
		{"entity overlap", "gh" + "p_xsk&#45;ant-demo", "", "text/html"},
		{"header overlap", "clean", `gh` + `p_xsk\-ant-demo`, ""},
		{"nested quote", "clean", `note="v\q:\"sk\\u002dant-demo\""`, ""},
		{"form feed", "Bearer&#12;eyJdemo", "", "text/html"},
		{"lz4 media", "clean", "", "application/x-lz4"},
		{"lz4 magic", "\x04\x22\x4d\x18clean", "", "application/octet-stream"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := Tape{Cassettes: []Cassette{{Response: CassetteResponse{Body: tc.body, Headers: map[string]string{"Content-Type": tc.media, "Server": tc.header}}}}}
			for _, redact := range []bool{false, true} {
				out, err := PrepareExport(in, redact)
				if redact && strings.HasPrefix(tc.name, "lz4 ") {
					if err != nil || out.Cassettes[0].Response.Body != "REDACTED" || !out.Redacted {
						t.Errorf("expected whole-body replacement, got %v", err)
					}
				} else if err == nil {
					t.Errorf("redact=%v: expected block", redact)
				}
			}
		})
	}
}

func TestFix7UnrelatedEncodingRetainsFormAndURLRedaction(t *testing.T) {
	in := Tape{Cassettes: []Cassette{{Response: CassetteResponse{
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Location": `/?token=Bearer+eyJdemo&note=a\b`},
		Body:    `a="&b=\x&token=gh` + `p_demo`,
	}}}}
	out, err := PrepareExport(in, true)
	if err != nil {
		t.Fatal(err)
	}
	response := out.Cassettes[0].Response
	if response.Body != `a="&b=\x&token=REDACTED` || response.Headers["Location"] != `/?token=REDACTED&note=a\b` {
		t.Fatalf("unexpected redaction: %#v", response)
	}
}
