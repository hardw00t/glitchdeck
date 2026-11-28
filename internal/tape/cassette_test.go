package tape

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/proxy"
)

func TestCassetteValidation(t *testing.T) {
	for _, tc := range []struct {
		name, doc string
		valid     bool
	}{
		{"v3", "version: 3\ncassettes: [{request: {method: GET, path: /}, response: {status: 200, body: ok}}]", true},
		{"v1 empty", "version: 1\ncassettes: []", false},
		{"v2 cassette", "version: 2\ncassettes: [{request: {method: GET, path: /}, response: {status: 200}}]", false},
		{"v2 null", "version: 2\nignore_json_paths: null", false},
		{"redacted v1", "version: 1\nredacted: true", true},
		{"truncated", "version: 3\ncassettes: [{request: {method: GET, path: /}, response: {status: 200, truncated: true}}]", false},
		{"invalid status", "version: 3\ncassettes: [{request: {method: GET, path: /}, response: {status: 600}}]", false},
		{"query", "version: 3\ncassettes: [{request: {method: GET, path: '/?x=1'}, response: {status: 200}}]", false},
		{"invalid method", "version: 3\ncassettes: [{request: {method: 'GET POST', path: /}, response: {status: 200}}]", false},
		{"duplicate headers", "version: 3\ncassettes: [{request: {method: GET, path: /}, response: {status: 200, headers: {Content-Type: a, content-type: b}}}]", false},
		{"oversized", "version: 3\ncassettes: [{request: {method: GET, path: /}, response: {status: 200, body: " + strings.Repeat("x", (4<<20)+1) + "}}]", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(tc.doc))
			if (err == nil) != tc.valid {
				t.Fatalf("Decode error = %v", err)
			}
			if strings.Contains(tc.name, "v1 empty") || strings.Contains(tc.name, "v2") {
				if err == nil || !strings.Contains(err.Error(), "new keys require version: 3") {
					t.Fatalf("wrong version error: %v", err)
				}
			}
		})
	}
}

func TestIgnoreJSONPathComponentLimit(t *testing.T) {
	paths := []string{strings.Repeat("a.", 16383) + "a", strings.Repeat("b.", 16383) + "b"}
	if err := validate(Tape{Version: 3, IgnoreJSONPaths: paths}); err != nil {
		t.Fatalf("at component limit: %v", err)
	}
	paths = append(paths, "extra")
	if err := validate(Tape{Version: 3, IgnoreJSONPaths: paths}); err == nil {
		t.Fatal("accepted too many ignore path components")
	}
}

func TestCassetteHash(t *testing.T) {
	if BodySHA256([]byte(`{"b":2,"id":"one","a":1}`), []string{"id"}) != BodySHA256([]byte(`{"a":1,"id":"two","b":2}`), []string{"id"}) {
		t.Fatal("ignored field changed digest")
	}
	sum := sha256.Sum256([]byte("not json"))
	if got := BodySHA256([]byte("not json"), []string{"id"}); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("raw hash = %s", got)
	}
}

func TestCassetteMatching(t *testing.T) {
	one := Cassette{Request: CassetteRequest{Method: "POST", Path: "/x", Host: "example.com", BodySHA256: BodySHA256([]byte(`{"v":1}`), nil)}, Response: NewCassetteResponse(201, map[string]string{"Content-Type": "text/plain"}, []byte("one"), false)}
	two := one
	two.Request.BodySHA256 = BodySHA256([]byte(`{"v":2}`), nil)
	two.Response.Body = "two"
	tape := Tape{Cassettes: []Cassette{one, two}}
	upstream := tape.CassetteUpstream()
	tape.Cassettes[1].Response.Body = "changed"
	r := httptest.NewRequest("POST", "http://example.com/x?q=1", strings.NewReader(`{"v":2}`))
	resp, err := upstream(r)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 201 || string(b) != "two" {
		t.Fatalf("response = %d %q", resp.StatusCode, b)
	}
	for _, tc := range []struct {
		name, url, body, kind string
		c                     []Cassette
	}{
		{"miss", "http://other/x", "{}", "cassette_miss", []Cassette{one}},
		{"ambiguous", "http://example.com/x", `{"v":1}`, "cassette_ambiguous", []Cassette{one, one}},
		{"oversized", "http://example.com/x", strings.Repeat("x", (4<<20)+1), "cassette_miss", []Cassette{one, two}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := (Tape{Cassettes: tc.c}).CassetteUpstream()(httptest.NewRequest("POST", tc.url, strings.NewReader(tc.body)))
			var ce *proxy.CassetteError
			if !errors.As(err, &ce) || ce.Kind != tc.kind {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestCassetteEscapedPathIsExact(t *testing.T) {
	upstream := (Tape{Cassettes: []Cassette{
		{Request: CassetteRequest{Method: "GET", Path: "/a%2Fb"}, Response: CassetteResponse{Status: 201}},
		{Request: CassetteRequest{Method: "GET", Path: "/a/b"}, Response: CassetteResponse{Status: 202}},
	}}).CassetteUpstream()
	res, err := upstream(httptest.NewRequest("GET", "/a%2Fb?x=1", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 201 {
		t.Fatalf("escaped path selected status %d", res.StatusCode)
	}
}

func TestCassetteEmptyAbsolutePathMatchesRoot(t *testing.T) {
	upstream := (Tape{Cassettes: []Cassette{{Request: CassetteRequest{Method: "GET", Path: "/"}, Response: CassetteResponse{Status: 200}}}}).CassetteUpstream()
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.URL.Path = ""
	resp, err := upstream(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func FuzzCassette(f *testing.F) {
	f.Add("version: 3\ncassettes: [{request: {method: POST, path: /}, response: {status: 200, body: ok}}]", []byte(`{"id":"abc","v":1}`))
	f.Add("version: 3\ncassettes: [{request: {method: POST, path: /}, response: {status: 200, body_encoding: base64, body: /wA=}}]", []byte{0xff, 0x00})
	f.Fuzz(func(t *testing.T, raw string, body []byte) {
		if len(raw) > 64<<10 || len(body) > 64<<10 {
			return
		}
		r := NewCassetteResponse(200, nil, body, false)
		got, err := r.Bytes()
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("body round trip: %v", err)
		}
		tape, err := Decode(strings.NewReader(raw))
		if err != nil || tape.Version != 3 {
			return
		}
		req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
		resp, err := tape.CassetteUpstream()(req)
		if err != nil {
			var cassErr *proxy.CassetteError
			if !errors.As(err, &cassErr) || cassErr.Kind != "cassette_miss" && cassErr.Kind != "cassette_ambiguous" {
				t.Fatalf("unexpected replay error: %v", err)
			}
		} else {
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
		}
	})
}
