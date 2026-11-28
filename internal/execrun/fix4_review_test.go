package execrun

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/tape"
)

func TestFix4ReplayChild(t *testing.T) {
	mode := os.Getenv("GD_FIX4_CHILD")
	if mode == "" {
		return
	}
	tr := &http.Transport{}
	if path := os.Getenv("GLITCHDECK_CA_CERT"); path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			t.Fatal("invalid CA")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	if mode == "proxy" || mode == "fault" || mode == "record" {
		p, err := url.Parse(os.Getenv("GLITCHDECK_PROXY_URL"))
		if err != nil {
			t.Fatal(err)
		}
		tr.Proxy = http.ProxyURL(p)
	}
	client := &http.Client{Transport: tr}
	if mode == "tls-origin" {
		target := os.Getenv("GLITCHDECK_TARGET")
		for _, tc := range []struct {
			origin string
			status int
		}{{target, http.StatusOK}, {"https://evil.example", http.StatusForbidden}} {
			req, err := http.NewRequest("POST", target+"/", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Origin", tc.origin)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("origin %s: status %d, want %d", tc.origin, resp.StatusCode, tc.status)
			}
		}
		return
	}
	if mode == "hosts" {
		for _, target := range []string{os.Getenv("GLITCHDECK_TARGET"), os.Getenv("GLITCHDECK_DEMO_TLS")} {
			for _, origin := range []bool{false, true} {
				method := "GET"
				if origin {
					method = "POST"
				}
				req, err := http.NewRequest(method, target+"/", nil)
				if err != nil {
					t.Fatal(err)
				}
				if origin {
					req.Header.Set("Origin", "http://evil.example")
				} else {
					req.Host = "evil.example"
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusForbidden {
					t.Fatalf("%s origin=%v: status %d", target, origin, resp.StatusCode)
				}
			}
		}
		return
	}
	path := "/"
	if mode == "record" || mode == "fault" {
		path = "/api/state"
	}
	resp, err := client.Get(os.Getenv("GLITCHDECK_TARGET") + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "fault" {
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("fault status %d", resp.StatusCode)
		}
	} else if mode == "record" {
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("record status %d", resp.StatusCode)
		}
	} else if resp.StatusCode != http.StatusOK || string(body) != "destination" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
}

func TestFix4ReplayListenerAuthorizationAndProxyRedirect(t *testing.T) {
	cassette := []tape.Cassette{
		{Request: tape.CassetteRequest{Method: "GET", Path: "/"}, Response: tape.CassetteResponse{Status: 302, Headers: map[string]string{"Location": "/next"}}},
		{Request: tape.CassetteRequest{Method: "GET", Path: "/next"}, Response: tape.CassetteResponse{Status: 200, Body: "destination"}},
	}
	for _, tc := range []struct {
		mode, target string
		tls          bool
	}{
		{"hosts", "demo", true}, {"proxy", "http://example.test", false}, {"proxy", "https://example.test", true},
	} {
		t.Run(tc.mode+tc.target, func(t *testing.T) {
			t.Setenv("GD_FIX4_CHILD", tc.mode)
			result := Run(context.Background(), tape.Tape{Version: 3, Target: tc.target, Cassettes: cassette}, Options{Mode: "replay", TLS: tc.tls, JSON: true, AllowZeroTraffic: true, Command: []string{os.Args[0], "-test.run=^TestFix4ReplayChild$"}})
			if result.ExitCode != 0 {
				t.Fatalf("run: %+v exec=%+v", result, result.Exec)
			}
		})
	}
}

func TestReplayTLSOriginAuthorization(t *testing.T) {
	t.Setenv("GD_FIX4_CHILD", "tls-origin")
	cassette := []tape.Cassette{{Request: tape.CassetteRequest{Method: "POST", Path: "/"}, Response: tape.CassetteResponse{Status: 200}}}
	result := Run(context.Background(), tape.Tape{Version: 3, Target: "https://example.test", Cassettes: cassette}, Options{Mode: "replay", TLS: true, JSON: true, AllowZeroTraffic: true, Command: []string{os.Args[0], "-test.run=^TestFix4ReplayChild$"}})
	if result.ExitCode != 0 {
		t.Fatalf("run: %+v exec=%+v", result, result.Exec)
	}
}

func TestFix4DemoReplayMatchesLoopbackFault(t *testing.T) {
	t.Setenv("GD_FIX4_CHILD", "record")
	path := filepath.Join(t.TempDir(), "recording.yaml")
	command := []string{os.Args[0], "-test.run=^TestFix4ReplayChild$"}
	recorded := Run(context.Background(), tape.Tape{Version: 2, Target: "demo"}, Options{Mode: "record", TapeOut: path, JSON: true, Command: command})
	if recorded.ExitCode != 0 {
		t.Fatalf("record: %+v exec=%+v", recorded, recorded.Exec)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := tape.Decode(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GD_FIX4_CHILD", "fault")
	min := uint64(1)
	doc.Rules = []fault.Rule{{ID: "host", Enabled: true, Match: fault.Match{Host: "127.0.0.1", PathPrefix: "/"}, Fault: fault.Fault{Type: "rate-limit", Params: map[string]any{"status": 429}}}}
	doc.Expect = tape.Expect{Faults: []tape.FaultExpect{{Rule: "host", MinApplied: &min}}}
	result := Run(context.Background(), doc, Options{Mode: "replay", JSON: true, Command: []string{os.Args[0], "-test.run=^TestFix4ReplayChild$"}})
	if result.ExitCode != 0 {
		t.Fatalf("run: %+v exec=%+v", result, result.Exec)
	}
}
