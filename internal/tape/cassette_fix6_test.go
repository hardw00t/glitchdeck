package tape

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCassetteLiteralDoubleSlashAndAuthorityValidation(t *testing.T) {
	doc := Tape{Version: 3, Cassettes: []Cassette{{Request: CassetteRequest{Method: "GET", Path: "//items", Host: "EXAMPLE.com:80"}, Response: CassetteResponse{Status: 200, Body: "ok"}}}}
	var out bytes.Buffer
	if err := Encode(&out, doc); err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(&out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoded.CassetteUpstream()(httptest.NewRequest("GET", "http://example.com//items", nil)); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{strings.Repeat("A", 1024), "bad host", "user@example.com", "example.com:99999", "example.com/path", "[invalid]"} {
		doc.Cassettes[0].Request.Host = host
		if err := validate(doc); err == nil {
			t.Errorf("accepted host %q", host)
		}
	}
	doc.Cassettes = nil
	doc.Script = []Step{{HTTP: &HTTP{Path: "//items"}}}
	if err := validate(doc); err == nil {
		t.Fatal("accepted network-path script")
	}
}

func TestRedactionIgnoresUnrelatedComplexRoute(t *testing.T) {
	secret := "sk_" + "live_firstsecret"
	before := Tape{Script: []Step{{HTTP: &HTTP{Method: "POST", Path: "/ok", Body: "simple"}}, {HTTP: &HTTP{Method: "POST", Path: "/limited", Body: "[" + strings.Repeat("0,", 40000) + "0]"}}}, Cassettes: []Cassette{{Request: CassetteRequest{Method: "POST", Path: "/ok", BodySHA256: BodySHA256([]byte("simple"), nil)}, Response: NewCassetteResponse(200, nil, []byte(secret), false)}}}
	after, err := PrepareExport(before, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(after.Cassettes[0].Response.Body, secret) {
		t.Fatal("response secret not redacted")
	}
}

func TestRawBodyDigestDoesNotAllocateIgnoreTable(t *testing.T) {
	paths := make([]string, 32768)
	for i := range paths {
		paths[i] = "id"
	}
	allocs := testing.AllocsPerRun(1, func() { BodySHA256([]byte{0xff}, paths) })
	if allocs > 20 {
		t.Fatalf("raw digest allocated %.0f times", allocs)
	}
}
