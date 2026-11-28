package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/tape"
)

func TestRecordGzipExportReplay(t *testing.T) {
	const payload = "decoded response from upstream"
	if mode := os.Getenv("GD_FIX12_GZIP_CHILD"); mode != "" {
		client := &http.Client{Transport: &http.Transport{DisableCompression: true}, Timeout: 5 * time.Second}
		req, err := http.NewRequest("GET", os.Getenv("GLITCHDECK_PROXY_URL")+"/gzip", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept-Encoding", "gzip")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body io.Reader = resp.Body
		if mode == "record" {
			if resp.Header.Get("Content-Encoding") != "gzip" {
				t.Fatal("record response was not gzip encoded")
			}
			body, err = gzip.NewReader(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
		} else if resp.Header.Get("Content-Encoding") != "" {
			t.Fatal("replayed response retained content encoding")
		}
		got, err := io.ReadAll(body)
		if err != nil || string(got) != payload || resp.StatusCode != http.StatusOK {
			t.Fatalf("response status=%d body=%q error=%v", resp.StatusCode, got, err)
		}
		return
	}

	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	z.Name = "private-gzip-name"
	z.Comment = "private-gzip-comment"
	z.Extra = []byte("private-gzip-extra\x00\xff")
	if _, err := z.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed.Bytes())
	}))
	defer upstream.Close()

	dir := t.TempDir()
	input, exported := filepath.Join(dir, "input.yaml"), filepath.Join(dir, "exported.yaml")
	if err := os.WriteFile(input, []byte("version: 2\ntarget: "+upstream.URL+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	child := []string{"--", os.Args[0], "-test.run=^TestRecordGzipExportReplay$"}
	t.Setenv("GD_FIX12_GZIP_CHILD", "record")
	args := append([]string{"exec", "--json", "--tape", input, "--mode", "record", "--tape-out", exported, "--redact-secrets"}, child...)
	if code, out := launchOutput(t, args...); code != 0 {
		t.Fatalf("record/export exit %d: %s", code, out)
	}
	data, err := os.ReadFile(exported)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := tape.Decode(bytes.NewReader(data))
	if err != nil || len(doc.Cassettes) != 1 {
		t.Fatalf("invalid exported tape: cassettes=%d error=%v", len(doc.Cassettes), err)
	}
	response := doc.Cassettes[0].Response
	body, err := response.Bytes()
	if err != nil || string(body) != payload || response.BodyEncoding != "" {
		t.Fatalf("exported body=%q encoding=%q error=%v", body, response.BodyEncoding, err)
	}
	for name := range response.Headers {
		if strings.EqualFold(name, "Content-Encoding") {
			t.Fatalf("export retained %s", name)
		}
	}
	for _, forbidden := range []string{"private-gzip-name", "private-gzip-comment", "private-gzip-extra", base64.StdEncoding.EncodeToString(compressed.Bytes())} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatalf("export retained gzip data %q", forbidden)
		}
	}
	t.Setenv("GD_FIX12_GZIP_CHILD", "replay")
	args = append([]string{"exec", "--json", "--tape", exported, "--mode", "replay"}, child...)
	if code, out := launchOutput(t, args...); code != 0 {
		t.Fatalf("replay exit %d: %s", code, out)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("upstream received %d requests, want only the recording", got)
	}
}
