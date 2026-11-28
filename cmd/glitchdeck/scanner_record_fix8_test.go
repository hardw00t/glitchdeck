package main

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordUnscannableEncoding(t *testing.T) {
	if os.Getenv("GD_FIX8_RECORD_CHILD") != "" {
		req, err := http.NewRequest("GET", os.Getenv("GLITCHDECK_PROXY_URL")+"/", nil)
		if err != nil {
			os.Exit(9)
		}
		req.Header.Set("Accept-Encoding", "identity")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			os.Exit(9)
		}
		_, err = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err != nil {
			os.Exit(9)
		}
		os.Exit(0)
	}
	secret := "sk-ant-" + strings.Repeat("F", 32)
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	_, _ = z.Write([]byte(strings.Repeat(secret+"\n", 8)))
	_ = z.Close()
	frame := make([]byte, 5)
	frame[0] = 1
	binary.BigEndian.PutUint32(frame[1:], uint32(compressed.Len()))
	frame = append(frame, compressed.Bytes()...)
	if bytes.Contains(frame, []byte(secret)) {
		t.Fatal("test frame stores the credential uncompressed")
	}
	for _, encoding := range []string{"grpc", "br", "zstd", "unknown", "br-nominated", "zstd-nominated", "unknown-nominated", "bad-gzip"} {
		for _, redact := range []bool{false, true} {
			t.Run(encoding+map[bool]string{false: "/blocked", true: "/redacted"}[redact], func(t *testing.T) {
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/octet-stream")
					if encoding == "grpc" {
						w.Header().Set("Connection", "Grpc-Encoding")
						w.Header().Set("Grpc-Encoding", "gzip")
						_, _ = w.Write(frame)
					} else {
						value := strings.TrimSuffix(encoding, "-nominated")
						if encoding == "bad-gzip" {
							value = "gzip"
						}
						w.Header().Set("Content-Encoding", value)
						if strings.HasSuffix(encoding, "-nominated") {
							w.Header().Set("Connection", "Content-Encoding")
						}
						_, _ = io.WriteString(w, secret)
					}
				}))
				defer upstream.Close()
				dir := t.TempDir()
				input, output, report := filepath.Join(dir, "in.yaml"), filepath.Join(dir, "out.yaml"), filepath.Join(dir, "report.json")
				if err := os.WriteFile(input, []byte("version: 2\ntarget: "+upstream.URL+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("GD_FIX8_RECORD_CHILD", "1")
				args := []string{"exec", "--tape", input, "--json", "--report", report, "--grace", "3s", "--mode", "record", "--tape-out", output}
				if redact {
					args = append(args, "--redact-secrets")
				}
				args = append(args, "--", os.Args[0], "-test.run=^TestRecordUnscannableEncoding$")
				cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestRecordXMLExport$", "--"}, args...)...)
				log, runErr := cmd.CombinedOutput()
				code, text := cmd.ProcessState.ExitCode(), string(log)
				reportBytes, err := os.ReadFile(report)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(text, secret) || bytes.Contains(reportBytes, []byte(secret)) {
					t.Fatal("credential leaked in output or report")
				}
				if !redact {
					want := "secret_kind=unscannable_encoding field=$.cassettes[0].response.body"
					if code != 2 || !strings.Contains(text, want) || !strings.Contains(string(reportBytes), want) {
						t.Fatalf("expected encoding block: code=%d error=%v output=%s report=%s", code, runErr, text, reportBytes)
					}
					if _, err := os.Stat(output); !os.IsNotExist(err) {
						t.Fatalf("blocked output exists: %v", err)
					}
					return
				}
				if code != 0 {
					t.Fatalf("redacted export failed: code=%d output=%s report=%s", code, text, reportBytes)
				}
				data, err := os.ReadFile(output)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(data, []byte(secret)) || !bytes.Contains(data, []byte("REDACTED")) || !bytes.Contains(data, []byte("redacted: true")) {
					t.Fatalf("invalid redacted tape: %s", data)
				}
				if strings.Contains(strings.ToLower(string(data)), "grpc-encoding") || strings.Contains(strings.ToLower(string(data)), "content-encoding") {
					t.Fatalf("encoding header retained: %s", data)
				}
				if code, out := launchOutput(t, "validate", output); code != 0 {
					t.Fatalf("invalid tape: %s", out)
				}
			})
		}
	}
}
