package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/execrun"
)

func launchOutput(t *testing.T, args ...string) (int, string) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	old := os.Stdout
	defer func() { os.Stdout = old }()
	os.Stdout = writer
	code := run(args)
	writer.Close()
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return code, string(out)
}

func TestLaunchVersion(t *testing.T) {
	oldVersion, oldCommit, oldDate := version, commit, buildDate
	t.Cleanup(func() { version, commit, buildDate = oldVersion, oldCommit, oldDate })
	version, commit, buildDate = "v2.0.0", "abc1234", "2026-11-27T08:00:00Z"
	for _, alias := range []string{"version", "--version", "-v"} {
		t.Run(alias, func(t *testing.T) {
			const want = "glitchdeck v2.0.0 (commit abc1234, built 2026-11-27T08:00:00Z)\n"
			if code, out := launchOutput(t, alias); code != 0 || out != want {
				t.Fatalf("%s: exit %d, stdout %q; want %q", alias, code, out, want)
			}
		})
	}
}

func TestLaunchVersionJSON(t *testing.T) {
	code, out := launchOutput(t, "version", "--json")
	var got struct {
		Schema  string            `json:"schema"`
		Command string            `json:"command"`
		OK      bool              `json:"ok"`
		Data    map[string]string `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || code != 0 || got.Schema != "glitchdeck.v2" || got.Command != "version" || !got.OK || got.Data["version"] == "" || got.Data["commit"] == "" || got.Data["build_date"] == "" || got.Data["go"] != runtime.Version() || got.Data["os"] != runtime.GOOS || got.Data["arch"] != runtime.GOARCH {
		t.Fatalf("exit %d, stdout %q, decode error %v", code, out, err)
	}
}

func TestOwnAppOpenAISSE(t *testing.T) {
	for _, tool := range []string{"sh", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s unavailable", tool)
		}
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for _, word := range []string{"first", "second", "third", "fourth"} {
			fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q}}]}\n\n", word)
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()
	code, out := launchOutput(t, "exec", "--tape", "../../examples/tapes/your-app-openai-sse-cut.tape.yaml", "--target", upstream.URL, "--json", "--", "sh", "-c", `
		export OPENAI_BASE_URL="$GLITCHDECK_PROXY_URL/v1"
		curl -q -fsSN --max-time 5 -H "Content-Type: application/json" -d '{"model":"local","messages":[{"role":"user","content":"Hi"}],"stream":true}' "$OPENAI_BASE_URL/chat/completions"
	`)
	var got struct {
		execrun.Envelope
		Faults []struct {
			RuleID string `json:"rule_id"`
			Type   string `json:"type"`
		} `json:"faults_triggered"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || code != 0 || !got.OK || got.ExitCode != 0 || got.Exec == nil || got.Exec.ExitCode != 0 || got.Summary.FaultsTriggered != 1 || len(got.Faults) != 1 || got.Faults[0].RuleID != "openai-stream-cut" || got.Faults[0].Type != "sse-glitch" {
		t.Fatalf("exit %d, stdout %q, decode error %v", code, out, err)
	}
	body := got.Exec.StdoutTail
	if strings.Count(body, "data: ") != 3 || !strings.Contains(body, `"content":"third"`) || strings.Contains(body, "fourth") || strings.Contains(body, "[DONE]") {
		t.Fatalf("unexpected child stream %q", body)
	}
}
