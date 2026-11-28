package tape

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestPrepareExportSecrets(t *testing.T) {
	secrets := []string{
		"sk-" + strings.Repeat("a", 20), "sk-ant-" + strings.Repeat("b", 20),
		"sk_live_" + strings.Repeat("c", 20), "rk_test_" + strings.Repeat("d", 20),
		"whsec_" + strings.Repeat("e", 20), "AKIA" + strings.Repeat("A", 16),
		"ghp_" + strings.Repeat("f", 30), "github_pat_" + strings.Repeat("g", 30),
		"Bearer eyJ" + strings.Repeat("h", 20), "-----BEGIN " + "PRIVATE KEY-----\nabc\n-----END " + "PRIVATE KEY-----",
	}
	for _, secret := range secrets {
		for _, version := range []int{1, 2, 3} {
			original := Tape{Version: version, Script: []Step{{HTTP: &HTTP{Body: secret}}}}
			_, err := PrepareExport(original, false)
			var blocked *ExportBlockedError
			if !errors.As(err, &blocked) || strings.Contains(err.Error(), secret) {
				t.Fatalf("unsafe or missing block: %v", err)
			}
			clean, err := PrepareExport(original, true)
			if err != nil || !clean.Redacted || strings.Contains(clean.Script[0].HTTP.Body, secret) {
				t.Fatalf("redaction failed: %v", err)
			}
			if original.Script[0].HTTP.Body != secret {
				t.Fatal("mutated original")
			}
			if _, err := PrepareExport(clean, false); err != nil {
				t.Fatalf("rescan: %v", err)
			}
		}
	}
}

func TestPrepareExportEncoded(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("z", 24)
	cases := []Tape{
		{Script: []Step{{HTTP: &HTTP{URL: "https://example.com/?key=sk%2Dant%2D" + strings.Repeat("z", 24)}}}},
		{Script: []Step{{HTTP: &HTTP{Body: `{"key":"sk\u002dant\u002d` + strings.Repeat("z", 24) + `"}`}}}},
		{Script: []Step{{GRPC: &GRPC{MessageB64: base64.StdEncoding.EncodeToString([]byte(secret))}}}},
		{Cassettes: []Cassette{{Response: NewCassetteResponse(200, nil, append([]byte{0xff}, []byte(secret)...), false)}}},
	}
	for _, input := range cases {
		if _, err := PrepareExport(input, false); err == nil {
			t.Fatal("encoded secret not blocked")
		}
		clean, err := PrepareExport(input, true)
		if err != nil {
			t.Fatalf("encoded redaction: %v", err)
		}
		if _, err := PrepareExport(clean, false); err != nil {
			t.Fatalf("rescan: %v", err)
		}
	}
}

func FuzzSecrets(f *testing.F) {
	f.Add("sk-" + strings.Repeat("a", 20))
	f.Add("ordinary text")
	f.Fuzz(func(t *testing.T, value string) {
		input := Tape{Script: []Step{{HTTP: &HTTP{Body: value}}}}
		clean, err := PrepareExport(input, true)
		if err != nil {
			var blocked *ExportBlockedError
			if !errors.As(err, &blocked) {
				t.Fatalf("unsafe error: %v", err)
			}
			return
		}
		if _, err := PrepareExport(clean, false); err != nil {
			t.Fatalf("rescan: %v", err)
		}
		if input.Script[0].HTTP.Body != value {
			t.Fatal("mutated original")
		}
	})
}

func TestPrepareExportSSEAndJSONPrecision(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("z", 24)
	body := "data: {\"n\":9007199254740993,\"key\":\"sk-ant-\\u007a" + strings.Repeat("z", 23) + "\"}\n\n"
	input := Tape{Script: []Step{{Stream: &Stream{Body: body}}}}
	if _, err := PrepareExport(input, false); err == nil {
		t.Fatal("escaped SSE secret not blocked")
	}
	clean, err := PrepareExport(input, true)
	if err != nil {
		t.Fatal(err)
	}
	got := clean.Script[0].Stream.Body
	if strings.Contains(got, secret) || strings.Contains(got, `\u007a`) || !strings.Contains(got, "9007199254740993") {
		t.Fatalf("bad SSE redaction: %s", got)
	}
	input.Script[0].Stream.Body = `{"n":9007199254740993,"key":"` + secret + `"}`
	clean, err = PrepareExport(input, true)
	if err != nil || !strings.Contains(clean.Script[0].Stream.Body, "9007199254740993") {
		t.Fatalf("precision lost: %v", err)
	}
}

func TestPrepareExportQueryBearer(t *testing.T) {
	token := "eyJ" + strings.Repeat("x", 20)
	input := Tape{Script: []Step{{HTTP: &HTTP{URL: "https://example.com/?auth=Bearer+" + token + "&x=a%2Fb"}}}}
	if _, err := PrepareExport(input, false); err == nil {
		t.Fatal("query secret not blocked")
	}
	clean, err := PrepareExport(input, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(clean.Script[0].HTTP.URL, token) || !strings.Contains(clean.Script[0].HTTP.URL, "x=a%2Fb") {
		t.Fatal("query redaction failed")
	}
}

func TestPrepareExportCompressedBodies(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("q", 24)
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(secret)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	body := base64.StdEncoding.EncodeToString(b.Bytes())
	input := Tape{Cassettes: []Cassette{{Response: CassetteResponse{Headers: map[string]string{"Content-Encoding": "gzip"}, Body: body, BodyEncoding: "base64"}}}}
	if _, err := PrepareExport(input, false); err == nil {
		t.Fatal("compressed secret not blocked")
	}
	clean, err := PrepareExport(input, true)
	if err != nil {
		t.Fatal(err)
	}
	data, err := base64.StdEncoding.DecodeString(clean.Cassettes[0].Response.Body)
	if err != nil {
		t.Fatal(err)
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if _, err := output.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	if output.String() != "REDACTED" {
		t.Fatal("compressed redaction failed")
	}
	if input.Cassettes[0].Response.Body != body {
		t.Fatal("mutated original")
	}
	if _, err := PrepareExport(clean, false); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareExportUnscannableBodies(t *testing.T) {
	for _, encoding := range []string{"br", "gzip"} {
		input := Tape{Script: []Step{{HTTP: &HTTP{Headers: map[string]string{"Content-Encoding": encoding}, Body: "invalid"}}}}
		for _, redact := range []bool{false, true} {
			_, err := PrepareExport(input, redact)
			var blocked *ExportBlockedError
			if !errors.As(err, &blocked) || blocked.Kind != "unscannable_body" {
				t.Fatalf("expected unscannable block: %v", err)
			}
		}
	}
}
