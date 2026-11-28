package tape

import (
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSyncRedactedCassetteRequests(t *testing.T) {
	before := Tape{Script: []Step{{HTTP: &HTTP{Method: "POST", Path: "/v1/x?q=1", Body: `{"id":"one","value":"secret"}`}}, {HTTP: &HTTP{Method: "POST", Path: "/v1/x", Body: `{"id":"two","value":"other"}`}}}}
	for _, step := range before.Script {
		before.Cassettes = append(before.Cassettes, Cassette{Request: CassetteRequest{Method: "POST", Path: "/v1/x", BodySHA256: BodySHA256([]byte(step.HTTP.Body), nil)}, Response: NewCassetteResponse(200, nil, []byte(step.HTTP.Body), false)})
	}
	after := before
	after.Script = []Step{{HTTP: &HTTP{Method: "POST", Path: "/v1/x?q=1", Body: `{"id":"one","value":"REDACTED"}`}}, before.Script[1]}
	after.Cassettes = append([]Cassette(nil), before.Cassettes...)
	if err := syncRedactedCassetteRequests(before, &after); err != nil {
		t.Fatal(err)
	}
	if before.Cassettes[0].Request.BodySHA256 == after.Cassettes[0].Request.BodySHA256 {
		t.Fatal("digest not updated")
	}
	for _, step := range after.Script {
		resp, err := after.CassetteUpstream()(httptest.NewRequest("POST", "http://example.com"+step.HTTP.Path, strings.NewReader(step.HTTP.Body)))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(resp.Body)
	}
}

func TestSyncRedactedCassetteCollision(t *testing.T) {
	before := Tape{Script: []Step{{HTTP: &HTTP{Method: "POST", Path: "/", Body: "same"}}, {HTTP: &HTTP{Method: "POST", Path: "/", Body: "same"}}}, Cassettes: []Cassette{{Request: CassetteRequest{Method: "POST", Path: "/", BodySHA256: BodySHA256([]byte("same"), nil)}}}}
	after := before
	after.Script = []Step{{HTTP: &HTTP{Method: "POST", Path: "/", Body: "first"}}, {HTTP: &HTTP{Method: "POST", Path: "/", Body: "second"}}}
	after.Cassettes = append([]Cassette(nil), before.Cassettes...)
	err := syncRedactedCassetteRequests(before, &after)
	var blocked *ExportBlockedError
	if !errors.As(err, &blocked) || blocked.Kind != "redaction_collision" {
		t.Fatalf("error = %v", err)
	}
	if after.Cassettes[0].Request != before.Cassettes[0].Request {
		t.Fatal("mutated cassette on failure")
	}
}
