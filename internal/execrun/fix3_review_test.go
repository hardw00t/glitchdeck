package execrun

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/tape"
)

func TestFix3ReplayChild(t *testing.T) {
	mode := os.Getenv("GD_FIX3_CHILD")
	if mode == "" {
		return
	}
	if mode == "environment" {
		for _, key := range []string{"GLITCHDECK_DEMO_TLS", "GLITCHDECK_UI_URL"} {
			if endpoint := os.Getenv(key); endpoint != "" {
				resp, err := http.Get(endpoint)
				if err == nil {
					resp.Body.Close()
				}
			}
		}
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
			t.Fatal("invalid replay CA")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	if mode == "fault" {
		p, _ := url.Parse(os.Getenv("GLITCHDECK_PROXY_URL"))
		tr.Proxy = http.ProxyURL(p)
	}
	client := &http.Client{Transport: tr}
	target := os.Getenv("GLITCHDECK_TARGET")
	if mode == "demoauth" {
		target = os.Getenv("GLITCHDECK_DEMO_TLS")
	}
	resp, err := client.Get(target + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if mode == "auth" || mode == "demoauth" {
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("unauthenticated status: %d", resp.StatusCode)
		}
	} else if mode == "fault" {
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("fault status %d", resp.StatusCode)
		}
	} else if resp.StatusCode != 200 || string(b) != "destination" {
		t.Fatalf("status %d body %q", resp.StatusCode, b)
	}
}

func TestFix3ReplayIsolationAndRedirect(t *testing.T) {
	cassette := []tape.Cassette{
		{Request: tape.CassetteRequest{Method: "GET", Path: "/"}, Response: tape.CassetteResponse{Status: 302, Headers: map[string]string{"Location": "/next"}}},
		{Request: tape.CassetteRequest{Method: "GET", Path: "/next"}, Response: tape.CassetteResponse{Status: 200, Body: "destination"}},
	}
	for _, tc := range []struct {
		mode, target string
		auth, tls    bool
	}{
		{"environment", "http://example.test", false, false}, {"auth", "http://example.test", true, false},
		{"auth", "https://example.test", true, true}, {"demoauth", "demo", true, true},
		{"redirect", "http://example.test", false, false}, {"redirect", "https://example.test", false, true},
		{"fault", "http://example.test", false, false},
	} {
		t.Run(tc.mode+tc.target, func(t *testing.T) {
			var inheritedHits atomic.Int64
			inherited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				inheritedHits.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer inherited.Close()
			t.Setenv("GD_FIX3_CHILD", tc.mode)
			t.Setenv("GLITCHDECK_DEMO_TLS", inherited.URL)
			t.Setenv("GLITCHDECK_UI_URL", inherited.URL)
			doc := tape.Tape{Version: 3, Target: tc.target, Cassettes: cassette}
			if tc.mode == "fault" {
				doc.Rules = []fault.Rule{{ID: "host", Enabled: true, Match: fault.Match{Host: "example.test", PathPrefix: "/"}, Fault: fault.Fault{Type: "rate-limit", Params: map[string]any{"status": 429}}}}
			}
			result := Run(context.Background(), doc, Options{Mode: "replay", TLS: tc.tls, ProxyAuth: tc.auth, JSON: true, AllowZeroTraffic: true, Command: []string{os.Args[0], "-test.run=^TestFix3ReplayChild$"}})
			if got := inheritedHits.Load(); got != 0 {
				t.Fatalf("replay child reached inherited endpoints %d times", got)
			}
			if result.ExitCode != 0 {
				t.Fatalf("run: %+v exec=%+v", result, result.Exec)
			}
			if tc.mode == "fault" && len(result.FaultsTriggered) == 0 {
				t.Fatalf("host fault not applied: %+v", result)
			}
		})
	}
}

func TestFix3BlockedDiagnosticAndUsage(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("Q", 30)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, secret) }))
	defer server.Close()
	dir := t.TempDir()
	doc := tape.Tape{Version: 2, Target: server.URL, Assertions: []tape.Assertion{{HTTPGet: "/", ExpectStatus: 200}}}
	result := Run(context.Background(), doc, Options{Mode: "record", TapeOut: filepath.Join(dir, "out"), Command: []string{"true"}, JSON: true, AllowZeroTraffic: true})
	data, _ := json.Marshal(result)
	if !strings.Contains(string(data), "secret_kind=anthropic") || !strings.Contains(string(data), "field=$.") || strings.Contains(string(data), secret) || strings.Contains(string(data), dir) {
		t.Fatalf("unsafe or missing diagnostic: %s", data)
	}
	result = Run(context.Background(), doc, Options{Mode: "record", Command: []string{"true"}})
	data, _ = json.Marshal(result)
	if !strings.Contains(string(data), "--mode record requires --tape-out") {
		t.Fatalf("usage: %s", data)
	}
}

func TestFix3RecordPassthrough(t *testing.T) {
	if os.Getenv("GD_FIX3_OUTPUT") == "child" {
		_, _ = io.WriteString(os.Stdout, "child-stdout")
		_, _ = io.WriteString(os.Stderr, "child-stderr")
		return
	}
	for _, jsonOutput := range []bool{false, true} {
		t.Run(map[bool]string{false: "terminal", true: "json"}[jsonOutput], func(t *testing.T) {
			t.Setenv("GD_FIX3_OUTPUT", "child")
			outR, outW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			errR, errW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			oldOut, oldErr := os.Stdout, os.Stderr
			os.Stdout, os.Stderr = outW, errW
			result := Run(context.Background(), tape.Tape{Version: 2, Target: "demo"}, Options{Mode: "record", TapeOut: filepath.Join(t.TempDir(), "tape"), JSON: jsonOutput, AllowZeroTraffic: true, Command: []string{os.Args[0], "-test.run=^TestFix3RecordPassthrough$"}})
			os.Stdout, os.Stderr = oldOut, oldErr
			outW.Close()
			errW.Close()
			stdout, _ := io.ReadAll(outR)
			stderr, _ := io.ReadAll(errR)
			outR.Close()
			errR.Close()
			if result.ExitCode != 0 || strings.Contains(string(stdout), "child-stdout") == jsonOutput || !strings.Contains(string(stderr), "child-stderr") {
				t.Fatalf("result=%+v stdout=%q stderr=%q", result, stdout, stderr)
			}
			data, _ := json.Marshal(result)
			if strings.Contains(string(data), "child-stdout") || strings.Contains(string(data), "child-stderr") {
				t.Fatalf("child output in envelope: %s", data)
			}
		})
	}
}
