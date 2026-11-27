package main

import (
	"compress/gzip"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/execrun"
)

func TestExecSSECompression(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl unavailable")
	}
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if r.URL.Path == "/br" {
			w.Header().Set("Content-Encoding", "br")
			fmt.Fprint(w, "opaque upstream bytes")
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		for i := 1; i <= 6; i++ {
			fmt.Fprintf(gz, "data: {\"choices\":[{\"delta\":{\"content\":\"token %d\"}}]}\n\n", i)
			_ = gz.Flush()
			w.(http.Flusher).Flush()
		}
		fmt.Fprint(gz, "data: [DONE]\n\n")
	}))
	defer up.Close()
	dir := t.TempDir()
	caPath := filepath.Join(dir, "upstream.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: up.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	tp := filepath.Join(dir, "compression.tape.yaml")
	if err := os.WriteFile(tp, []byte(`version: 2
name: compression
target: `+up.URL+`
rules:
  - id: stream
    enabled: true
    fault: {type: sse-glitch, params: {action: corrupt_json, events: [4]}}
`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/gzip", "/br"} {
		t.Run(path, func(t *testing.T) {
			code, out := launchOutput(t, "exec", "--tape", tp, "--tls", "--upstream-ca", caPath, "--json", "--", "curl", "-q", "--noproxy", "", "-fsiN", "--max-time", "4", up.URL+path)
			var got execrun.Envelope
			if err := json.Unmarshal([]byte(out), &got); err != nil || got.Exec == nil || got.Exec.ExitCode != 0 {
				t.Fatalf("code %d, out %s, decode error %v", code, out, err)
			}
			body := got.Exec.StdoutTail
			if path == "/br" {
				if code != 1 || got.Summary.FaultsTriggered != 0 || !strings.Contains(strings.Join(got.Diff, ";"), "zero_faults") || !strings.HasSuffix(body, "opaque upstream bytes") {
					t.Fatalf("code %d, out %s", code, out)
				}
				return
			}
			if code != 0 || got.Summary.FaultsTriggered != 1 || !strings.Contains(strings.ToLower(body), "x-glitchdeck-decoded: gzip") || strings.Contains(strings.ToLower(body), "content-encoding:") {
				t.Fatalf("code %d, out %s", code, out)
			}
			var events []string
			for line := range strings.SplitSeq(body, "\n") {
				if data, ok := strings.CutPrefix(line, "data: "); ok {
					events = append(events, data)
				}
			}
			if len(events) != 7 || events[6] != "[DONE]" {
				t.Fatalf("unexpected events %q", events)
			}
			for i, event := range events[:6] {
				if json.Valid([]byte(event)) != (i != 3) {
					t.Fatalf("event %d: %q", i+1, event)
				}
			}
		})
	}
}
