package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/tape"
)

func TestConsoleInitialTapeKeepsIgnorePaths(t *testing.T) {
	if target := os.Getenv("GD_CONSOLE_CASSETTE_TARGET"); target != "" {
		os.Exit(run([]string{"proxy", "--tape", os.Getenv("GD_CONSOLE_CASSETTE_PATH"), "--target", target, "--listen", "127.0.0.1:0", "--ui", "127.0.0.1:0", "--json"}))
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, "recorded")
	}))
	defer upstream.Close()
	path := filepath.Join(t.TempDir(), "matching.yaml")
	if err := os.WriteFile(path, []byte("version: 3\nignore_json_paths: [request_id]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GD_CONSOLE_CASSETTE_TARGET", upstream.URL)
	t.Setenv("GD_CONSOLE_CASSETTE_PATH", path)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestConsoleInitialTapeKeepsIgnorePaths$")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	var ready struct{ UI, Proxy string }
	if err := json.NewDecoder(stdout).Decode(&ready); err != nil {
		t.Fatal(err)
	}
	client := http.Client{Timeout: 3 * time.Second}
	post := func(url, body string) {
		t.Helper()
		res, err := client.Post(url, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		io.Copy(io.Discard, res.Body)
		if res.StatusCode != 200 {
			t.Fatalf("post status %d", res.StatusCode)
		}
	}
	post(ready.UI+"/api/tape/record", "")
	post(ready.Proxy+"/match", `{"request_id":"record","mode":1}`)
	post(ready.UI+"/api/tape/stop", "")
	res, err := client.Get(ready.UI + "/api/tape/export")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	doc, err := tape.Decode(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Cassettes) != 1 || !slices.Equal(doc.IgnoreJSONPaths, []string{"request_id"}) {
		t.Fatalf("missing startup cassette metadata: %d cassettes, ignore paths %v", len(doc.Cassettes), doc.IgnoreJSONPaths)
	}
	if digest := tape.BodySHA256([]byte(`{"mode":1}`), nil); doc.Cassettes[0].Request.BodySHA256 != digest {
		t.Fatal("console cassette hash included the ignored field")
	}
}
