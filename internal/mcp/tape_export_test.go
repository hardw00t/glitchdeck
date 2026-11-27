package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/tape"
)

func exportTestServer(t *testing.T, handler http.HandlerFunc) (*Server, string) {
	t.Helper()
	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)
	s := NewServer(nil, nil, Options{Workdir: t.TempDir()})
	s.ctx = context.Background()
	started, _ := s.call("proxy_start", fmt.Appendf(nil, `{"target":%q,"record":true}`, upstream.URL))
	if started["error"] != nil {
		t.Fatal(started)
	}
	t.Cleanup(s.stop)
	return s, started["proxy_url"].(string)
}

func exportTestRequest(t *testing.T, req *http.Request) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.Status)
	}
}

func TestTapeExportVersionsAndRedaction(t *testing.T) {
	s, proxyURL := exportTestServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	req, err := http.NewRequest("GET", proxyURL+"/resource?api_key=query-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer header-secret")
	exportTestRequest(t, req)

	got, _ := s.call("tape_export", []byte(`{"name":"capture"}`))
	data, ok := got["yaml"].(string)
	if !ok || got["version"] != 2 || !strings.HasPrefix(data, "version: 2\n") {
		t.Fatalf("default export: %v", got)
	}
	if strings.Contains(data, "query-secret") || strings.Contains(data, "header-secret") || strings.Contains(strings.ToLower(data), "authorization") {
		t.Fatalf("credentials leaked: %s", data)
	}
	args, err := json.Marshal(map[string]string{"tape_yaml": data})
	if err != nil {
		t.Fatal(err)
	}
	validated, _ := s.call("tape_validate", args)
	if validated["ok"] != true || validated["version"] != 2 {
		t.Fatalf("validation: %v", validated)
	}
}

func TestTapeExportV1ReleaseBytes(t *testing.T) {
	s := NewServer(nil, nil, Options{Workdir: t.TempDir()})
	s.ctx = context.Background()
	t.Cleanup(s.stop)
	start, _ := s.call("proxy_start", []byte(`{"target":"demo","record":true}`))
	if start["error"] != nil {
		t.Fatal(start)
	}
	req, err := http.NewRequest("GET", start["proxy_url"].(string)+"/api/state", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "Python-urllib/3.14")
	exportTestRequest(t, req)
	// Captured from v2.2.2 using the same request.
	const expected = `version: 1
name: live-smoke
seed: 1
target: demo
rules: []
script:
    - name: ""
      seq: 1
      http:
        method: GET
        path: /api/state
        headers:
            Accept-Encoding: identity
            User-Agent: Python-urllib/3.14
assertions: []
`
	v1, _ := s.call("tape_export", []byte(`{"name":"live-smoke","format":"v1"}`))
	if v1["version"] != 1 || v1["yaml"] != expected {
		t.Fatalf("v1 export changed: %v\nwant: %s", v1, expected)
	}
}

func TestTapeExportDoesNotClaimInvalidCaptureIsReplayable(t *testing.T) {
	s, proxyURL := exportTestServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	req, err := http.NewRequest("GET", proxyURL+"//resource", nil)
	if err != nil {
		t.Fatal(err)
	}
	exportTestRequest(t, req)
	v1, _ := s.call("tape_export", []byte(`{"name":"capture","format":"v1"}`))
	if v1["version"] != 1 || v1["replayable"] != false {
		t.Fatalf("invalid legacy capture: %v", v1)
	}
	v2, _ := s.call("tape_export", []byte(`{"name":"capture"}`))
	if e, ok := v2["error"].(map[string]string); !ok || e["code"] != "INVALID_TAPE" {
		t.Fatalf("invalid v2 capture: %v", v2)
	}
}

func TestTapeExportRejectsV1ForStream(t *testing.T) {
	s, proxyURL := exportTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: hello\n\n")
	})
	req, err := http.NewRequest("GET", proxyURL+"/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	exportTestRequest(t, req)
	got, _ := s.call("tape_export", []byte(`{"name":"stream","format":"v1"}`))
	errResult, ok := got["error"].(map[string]string)
	if !ok || errResult["code"] != "VERSION_CONFLICT" {
		t.Fatalf("expected version conflict: %v", got)
	}
}

func TestTapeExportEvictionMetadata(t *testing.T) {
	s, proxyURL := exportTestServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	for range 258 {
		req, err := http.NewRequest("GET", proxyURL+"/resource", nil)
		if err != nil {
			t.Fatal(err)
		}
		exportTestRequest(t, req)
	}
	got, _ := s.call("tape_export", []byte(`{"name":"evicted"}`))
	data, ok := got["yaml"].(string)
	if !ok || got["truncated"] != true || got["dropped_entries"] != 2 || !strings.Contains(data, "truncated: true") || !strings.Contains(data, "dropped_entries: 2") {
		t.Fatalf("eviction metadata: %v", got)
	}
}

func TestTapeExportIncompleteOmittedBody(t *testing.T) {
	s, proxyURL := exportTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})
	req, err := http.NewRequest("POST", proxyURL+"/upload", strings.NewReader(strings.Repeat("x", 80000)))
	if err != nil {
		t.Fatal(err)
	}
	exportTestRequest(t, req)
	got, _ := s.call("tape_export", []byte(`{"name":"large"}`))
	data, ok := got["yaml"].(string)
	omitted, countOK := got["omitted_body_bytes"].(int)
	if !ok || !countOK || omitted <= 0 || got["incomplete"] != true || got["replayable"] != false || !strings.Contains(data, "incomplete: true") || !strings.Contains(data, fmt.Sprintf("omitted_body_bytes: %d", omitted)) {
		t.Fatalf("incomplete export: %v", got)
	}
	if _, err := tape.Decode(strings.NewReader(data)); err == nil {
		t.Fatal("incomplete export was accepted for replay")
	}
}
