package execrun

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/tape"
	"github.com/hardw00t/glitchdeck/internal/tlsmitm"
)

func TestInheritedCertificatesOnlyAndDeduplicated(t *testing.T) {
	ca, err := tlsmitm.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "corporate.pem")
	data := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw, Headers: map[string]string{"Example": "do-not-copy"}}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")})...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", path)
	got := certBundle(inheritedCerts("SSL_CERT_FILE"), ca.PEM)
	if bytes.Contains(got, []byte("PRIVATE KEY")) || bytes.Contains(got, []byte("do-not-copy")) || bytes.Count(got, []byte("BEGIN CERTIFICATE")) != 1 {
		t.Fatalf("unexpected bundle %s", got)
	}
	if !x509.NewCertPool().AppendCertsFromPEM(got) {
		t.Fatal("invalid bundle")
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), 4<<20+1), 0600); err != nil {
		t.Fatal(err)
	}
	if len(inheritedCerts("SSL_CERT_FILE")) != 0 {
		t.Fatal("accepted oversized file")
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")}), 0600); err != nil {
		t.Fatal(err)
	}
	if len(inheritedCerts("SSL_CERT_FILE")) != 0 {
		t.Fatal("accepted invalid certificate DER")
	}
	t.Setenv("SSL_CERT_FILE", t.TempDir())
	if len(inheritedCerts("SSL_CERT_FILE")) != 0 {
		t.Fatal("accepted directory")
	}
}

func TestExecEnvironmentSafetyAndTemporaryFiles(t *testing.T) {
	if os.Getenv("GD_ENV_HELPER") == "1" {
		for _, name := range []string{"NODE_TLS_REJECT_UNAUTHORIZED", "PYTHONHTTPSVERIFY", "GIT_SSL_NO_VERIFY", "BUN_TLS_REJECT_UNAUTHORIZED", "NPM_CONFIG_STRICT_SSL", "CURL_INSECURE"} {
			if _, ok := os.LookupEnv(name); ok {
				t.Fatalf("unexpected %s", name)
			}
		}
		for _, path := range []string{os.Getenv("GLITCHDECK_CA_CERT"), os.Getenv("SSL_CERT_FILE"), os.Getenv("NODE_EXTRA_CA_CERTS")} {
			st, err := os.Stat(path)
			if err != nil || runtime.GOOS != "windows" && st.Mode().Perm() != 0600 {
				t.Fatalf("file %s: %v %v", path, st, err)
			}
			st, err = os.Stat(filepath.Dir(path))
			if err != nil || runtime.GOOS != "windows" && st.Mode().Perm() != 0700 {
				t.Fatalf("dir: %v %v", st, err)
			}
		}
		bundle := os.Getenv("SSL_CERT_FILE")
		data, err := os.ReadFile(bundle)
		if err != nil || !x509.NewCertPool().AppendCertsFromPEM(data) {
			t.Fatalf("child bundle is not usable: %v", err)
		}
		for _, name := range []string{"DENO_CERT", "GIT_SSL_CAINFO", "PIP_CERT", "NPM_CONFIG_CAFILE", "CARGO_HTTP_CAINFO"} {
			if got := os.Getenv(name); got != bundle {
				t.Fatalf("%s = %q, want %q", name, got, bundle)
			}
		}
		println(os.Getenv("SSL_CERT_FILE"))
		return
	}
	for _, name := range []string{"NODE_TLS_REJECT_UNAUTHORIZED", "PYTHONHTTPSVERIFY", "GIT_SSL_NO_VERIFY", "BUN_TLS_REJECT_UNAUTHORIZED", "NPM_CONFIG_STRICT_SSL", "CURL_INSECURE"} {
		t.Setenv(name, "")
		os.Unsetenv(name)
	}
	t.Setenv("GD_ENV_HELPER", "1")
	r := Run(context.Background(), tape.Tape{Version: 2}, Options{TLS: true, JSON: true, AllowZeroTraffic: true, Command: []string{os.Args[0], "-test.run=^TestExecEnvironmentSafetyAndTemporaryFiles$"}})
	if r.ExitCode != 0 {
		t.Fatalf("%+v", r)
	}
	path := strings.TrimSpace(strings.Split(r.Exec.StderrTail, "\n")[0])
	if filepath.Base(path) != "bundle.pem" {
		t.Fatalf("missing bundle path in %q", r.Exec.StderrTail)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("temporary directory remains: %s %v", path, err)
	}
}

func TestPrivateCAUpstreamPassthrough(t *testing.T) {
	if os.Getenv("GD_PRIVATE_HELPER") == "1" {
		p, _ := url.Parse(os.Getenv("GLITCHDECK_PROXY_URL"))
		path := os.Getenv("SSL_CERT_FILE")
		if onlyUpstream := os.Getenv("GD_PRIVATE_CA_ONLY"); onlyUpstream != "" {
			path = onlyUpstream
		}
		bundle, err := os.ReadFile(path)
		roots := x509.NewCertPool()
		if err != nil || !roots.AppendCertsFromPEM(bundle) {
			t.Fatalf("could not load child roots: %v", err)
		}
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(p), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
		resp, err := client.Get(os.Getenv("GD_PRIVATE_URL"))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.TLS == nil || resp.TLS.PeerCertificates[0].Issuer.CommonName != os.Getenv("GD_PRIVATE_ISSUER") {
			t.Fatal("did not receive upstream certificate")
		}
		return
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	cert := srv.Certificate()
	path := filepath.Join(t.TempDir(), "upstream.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", path)
	t.Setenv("GD_PRIVATE_HELPER", "1")
	t.Setenv("GD_PRIVATE_URL", srv.URL)
	t.Setenv("GD_PRIVATE_ISSUER", cert.Issuer.CommonName)
	for _, tc := range []struct {
		name             string
		patterns         []string
		rules            []fault.Rule
		diff             string
		code             int
		passed, rejected int64
	}{
		{name: "no rules", patterns: []string{"127.0.0.1"}, passed: 1},
		{name: "enabled rule", patterns: []string{"127.0.0.1"}, rules: []fault.Rule{{ID: "enabled", Enabled: true, Fault: fault.Fault{Type: "rate-limit"}}}, diff: "zero_faults:", code: 1, passed: 1},
		{name: "intercepted control", diff: "tls_rejected_only:", code: 1, rejected: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.rejected != 0 {
				t.Setenv("GD_PRIVATE_CA_ONLY", path)
			}
			r := Run(context.Background(), tape.Tape{Version: 2, Rules: tc.rules, Expect: tape.Expect{ChildExit: "any"}}, Options{TLS: true, JSON: true, TLSPassthrough: tc.patterns, Command: []string{os.Args[0], "-test.run=^TestPrivateCAUpstreamPassthrough$"}})
			if r.ExitCode != tc.code || tc.passed != 0 && r.Exec.ExitCode != 0 || r.Exec.Traffic.PassthroughOK != tc.passed || r.Exec.Traffic.TLSRejected != tc.rejected || !strings.Contains(strings.Join(r.Diff, " "), tc.diff) {
				t.Fatalf("%+v; traffic %+v", r, r.Exec.Traffic)
			}
		})
	}
}

func TestRuntimeHints(t *testing.T) {
	target, _ := url.Parse("http://localhost:3000")
	for _, name := range []string{"java", "dotnet", "deno", "client"} {
		for _, stats := range []proxy.TrafficStats{{RequestsTotal: 1, TLSRejected: 1}, {}} {
			for _, h := range hint(Options{}, []string{name}, target, stats) {
				if strings.Contains(strings.ToLower(h), "insecure") || strings.Contains(h, "NO_VERIFY") || strings.Contains(h, "REJECT_UNAUTHORIZED=0") {
					t.Fatal(h)
				}
			}
		}
	}
	if !strings.Contains(strings.Join(hint(Options{}, []string{"java"}, target, proxy.TrafficStats{}), " "), "JVM ignores") {
		t.Fatal("missing JVM hint")
	}
}

func TestExecNoProxyEnvironment(t *testing.T) {
	if os.Getenv("GD_NO_PROXY_HELPER") == "1" {
		if os.Getenv("NO_PROXY") != os.Getenv("no_proxy") || !strings.HasPrefix(os.Getenv("NO_PROXY"), "internal.example.test,.svc.test,") {
			t.Fatalf("NO_PROXY=%q no_proxy=%q", os.Getenv("NO_PROXY"), os.Getenv("no_proxy"))
		}
		return
	}
	t.Setenv("GD_NO_PROXY_HELPER", "1")
	t.Setenv("NO_PROXY", "internal.example.test,localhost")
	t.Setenv("no_proxy", ".svc.test")
	r := Run(context.Background(), tape.Tape{Version: 2, Target: "http://localhost:3000"}, Options{JSON: true, AllowZeroTraffic: true, Command: []string{os.Args[0], "-test.run=^TestExecNoProxyEnvironment$"}})
	if r.ExitCode != 0 || strings.Join(r.Exec.NoProxyDropped, ",") != "localhost" {
		t.Fatalf("%+v", r)
	}
}

func TestReportNoProxyOmitsCredentials(t *testing.T) {
	const value = "safe.test,http://user:example-secret@example.com,https://example.com/?key=example-secret"
	if got := reportNoProxy(value); got != "safe.test,[redacted],[redacted]" {
		t.Fatalf("report projection = %q", got)
	}
}
