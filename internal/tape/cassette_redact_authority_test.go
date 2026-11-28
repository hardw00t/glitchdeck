package tape

import (
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRedactedDemoTLSCassetteReplays(t *testing.T) {
	secret := "sk_" + "live_firstsecret"
	bodies := []string{secret, "ordinary"}
	tape := Tape{}
	for _, body := range bodies {
		tape.Script = append(tape.Script, Step{HTTP: &HTTP{Method: "POST", URL: "${DEMO_TLS}/upload", Body: body}})
		tape.Cassettes = append(tape.Cassettes, Cassette{Request: CassetteRequest{Method: "POST", Path: "/upload", Host: "localhost", BodySHA256: BodySHA256([]byte(body), nil)}, Response: NewCassetteResponse(200, nil, []byte(body), false)})
	}
	exported, err := PrepareExport(tape, true)
	if err != nil {
		t.Fatal(err)
	}
	for i, step := range exported.Script {
		resp, err := exported.CassetteUpstream()(httptest.NewRequest("POST", "https://localhost/upload", strings.NewReader(step.HTTP.Body)))
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != exported.Cassettes[i].Response.Body {
			t.Fatalf("replayed %q, want %q", body, exported.Cassettes[i].Response.Body)
		}
	}
}

func TestRedactedDefaultPortCollisionIsBlocked(t *testing.T) {
	bodies := []string{"sk_" + "live_firstsecret", "sk_" + "live_secondsecret"}
	hosts := []string{"example.com", "example.com:443"}
	tape := Tape{}
	for i, body := range bodies {
		tape.Script = append(tape.Script, Step{HTTP: &HTTP{Method: "POST", URL: "https://" + hosts[i] + "/upload", Body: body}})
		tape.Cassettes = append(tape.Cassettes, Cassette{Request: CassetteRequest{Method: "POST", Path: "/upload", Host: hosts[i], BodySHA256: BodySHA256([]byte(body), nil)}, Response: NewCassetteResponse(200, nil, []byte(hosts[i]), false)})
	}
	for i, body := range bodies {
		resp, err := tape.CassetteUpstream()(httptest.NewRequest("POST", "https://"+hosts[i]+"/upload", strings.NewReader(body)))
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(resp.Body)
		if err != nil || string(got) != hosts[i] {
			t.Fatalf("replay = %q, %v", got, err)
		}
	}
	_, err := PrepareExport(tape, true)
	var blocked *ExportBlockedError
	if !errors.As(err, &blocked) || blocked.Kind != "redaction_collision" {
		t.Fatalf("error = %v", err)
	}
}
