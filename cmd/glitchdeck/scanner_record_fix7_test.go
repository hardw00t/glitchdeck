package main

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fix7MultipartBody() string {
	secret := "Bearer " + "sk-" + "ant-" + strings.Repeat("Z", 32)
	return "--boundary\r\nContent-Disposition: form-data; name=\"file\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte(secret)) + "\r\n--boundary--\r\n"
}

func TestRecordRejectsFilteredRepresentationMetadata(t *testing.T) {
	if os.Getenv("GD_FIX7_RECORD_CHILD") != "" {
		body := fix7MultipartBody()
		if os.Getenv("GD_FIX7_RECORD_CHILD") == "empty-request" {
			body = ""
		}
		req, err := http.NewRequest("POST", os.Getenv("GLITCHDECK_PROXY_URL")+"/", strings.NewReader(body))
		if err != nil {
			os.Exit(9)
		}
		if strings.HasSuffix(os.Getenv("GD_FIX7_RECORD_CHILD"), "request") {
			req.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
			req.Header.Set("Connection", "Content-Type")
		}
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
	for _, direction := range []string{"request", "response", "empty-request", "empty-response"} {
		for _, redact := range []bool{false, true} {
			t.Run(direction+map[bool]string{false: "/normal", true: "/redacted"}[redact], func(t *testing.T) {
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					io.Copy(io.Discard, r.Body)
					if strings.HasSuffix(direction, "response") {
						w.Header().Set("Connection", "Content-Type")
						w.Header().Set("Content-Type", "multipart/form-data; boundary=boundary")
						if direction == "response" {
							io.WriteString(w, fix7MultipartBody())
						}
					} else {
						io.WriteString(w, "ok")
					}
				}))
				defer upstream.Close()
				dir := t.TempDir()
				input, output := filepath.Join(dir, "in.yaml"), filepath.Join(dir, "out.yaml")
				if err := os.WriteFile(input, []byte("version: 2\nname: test\ntarget: "+upstream.URL+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("GD_FIX7_RECORD_CHILD", direction)
				args := []string{"exec", "--tape", input, "--json", "--grace", "3s", "--mode", "record", "--tape-out", output}
				if redact {
					args = append(args, "--redact-secrets")
				}
				args = append(args, "--", os.Args[0], "-test.run=^TestRecordRejectsFilteredRepresentationMetadata$")
				code, report := launchOutput(t, args...)
				if strings.HasPrefix(direction, "empty-") {
					if code != 0 {
						t.Fatalf("empty body export failed: %s", report)
					}
					if _, err := os.Stat(output); err != nil {
						t.Fatalf("missing safe output: %v", err)
					}
					return
				}
				if redact {
					data, err := os.ReadFile(output)
					if code != 0 || err != nil || !strings.Contains(string(data), "body: REDACTED") {
						t.Fatalf("unscannable body was not replaced: %s (%v)", report, err)
					}
					if status, out := launchOutput(t, "validate", output); status != 0 {
						t.Fatalf("redacted tape did not validate: %s", out)
					}
					return
				}
				if code == 0 {
					t.Fatalf("export unexpectedly succeeded: %s", report)
				}
				if !strings.Contains(report, "EXPORT_BLOCKED") || !strings.Contains(report, "secret_kind=unscannable_encoding") {
					t.Fatalf("wrong failure: %s", report)
				}
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatalf("unsafe output exists: %v", err)
				}
			})
		}
	}
}
