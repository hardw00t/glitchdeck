package main

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/wsframe"
)

func TestReplayReports(t *testing.T) {
	const tapePath = "../../examples/tapes/stripe-concurrent-webhook-race.tape.yaml"
	const wantLine = "dup-webhook duplicate mode=concurrent sent=4 200×4 skew="
	check := func(t *testing.T, out string) {
		t.Helper()
		var got struct {
			Faults []struct {
				Replays struct {
					Mode     string
					Sent     uint64
					Status   map[string]uint64
					Outcomes map[string]uint64
					Skew     *int64 `json:"max_skew_ms"`
				}
			} `json:"faults_triggered"`
		}
		if err := json.Unmarshal([]byte(out), &got); err != nil || len(got.Faults) != 1 {
			t.Fatalf("report: %v: %s", err, out)
		}
		r := got.Faults[0].Replays
		if r.Mode != "concurrent" || r.Sent != 4 || r.Skew == nil || !reflect.DeepEqual(r.Status, map[string]uint64{"200": 4}) || !reflect.DeepEqual(r.Outcomes, map[string]uint64{"ok": 4}) {
			t.Fatalf("wrong replay counts: %+v", r)
		}
	}
	t.Run("test and rendered reports", func(t *testing.T) {
		dir := t.TempDir()
		report, summary := filepath.Join(dir, "report.json"), filepath.Join(dir, "summary.md")
		t.Setenv("GITHUB_STEP_SUMMARY", summary)
		code, out := launchOutput(t, "test", tapePath, "--json", "--report", report)
		if code != 1 {
			t.Fatalf("test exit %d: %s", code, out)
		}
		check(t, out)
		for _, args := range [][]string{{"report", report}, {"report", "--github", report}, {"report", "--junit", report}} {
			code, out := launchOutput(t, args...)
			if code != 0 || !strings.Contains(out, wantLine) || !strings.Contains(out, "outcomes=ok×4") {
				t.Fatalf("%v: exit %d: %s", args, code, out)
			}
			if args[1] == "--junit" {
				var doc struct {
					Cases []struct {
						Output string `xml:"system-out"`
					} `xml:"testsuite>testcase"`
				}
				if err := xml.Unmarshal([]byte(out), &doc); err != nil || len(doc.Cases) == 0 || !strings.Contains(doc.Cases[0].Output, wantLine) {
					t.Fatalf("JUnit system-out: %v: %s", err, out)
				}
			}
		}
		if text, err := os.ReadFile(summary); err != nil || !strings.Contains(string(text), wantLine) {
			t.Fatalf("GitHub step summary: %v: %s", err, text)
		}
	})
	t.Run("exec", func(t *testing.T) {
		curl, err := exec.LookPath("curl")
		if err != nil {
			t.Skip("curl not installed")
		}
		code, out := launchOutput(t, "exec", "--tape", tapePath, "--json", "--", "sh", "-c",
			`"$1" -q -fsS -H 'Content-Type: application/json' -d '{"order_id":"ord-1","amount_cents":4900}' "$GLITCHDECK_PROXY_URL/webhooks/payment"`, "sh", curl)
		if code != 1 {
			t.Fatalf("exec exit %d: %s", code, out)
		}
		check(t, out)
	})
}

func TestDeliveryDemoTapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		want string
	}{
		{"stripe-timeout-retry-webhook", 1, `"committed_status":200`},
		{"ws-heartbeat-immune-close", 0, `"ok":true`},
	} {
		path := "../../examples/tapes/" + tc.name + ".tape.yaml"
		if code, out := launchOutput(t, "test", "--json", path); code != tc.code || !strings.Contains(out, tc.want) {
			t.Fatalf("%s: exit %d, want %d and %s: %s", tc.name, code, tc.code, tc.want, out)
		}
	}
}

func TestHeartbeatDemoControl(t *testing.T) {
	original, err := os.ReadFile("../../examples/tapes/ws-heartbeat-immune-close.tape.yaml")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "all.tape.yaml")
	if err := os.WriteFile(path, []byte(strings.Replace(string(original), "frames: data", "frames: all", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if code, out := launchOutput(t, "test", "--json", path); code != 1 || !strings.Contains(out, "ws_broken: expected false, got true") {
		t.Fatalf("all frames should close before the second ticker message: exit %d: %s", code, out)
	}
}

func TestWebSocketFrameErrorReports(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
			wsframe.AcceptKey(r.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n")
		_, _ = rw.Write([]byte{0x82, 127, 0, 0, 0, 0, 0, 0x40, 0, 1})
		_ = rw.Flush()
		_, _ = wsframe.Read(rw, true)
	}))
	defer upstream.Close()
	for _, command := range []string{"test", "exec"} {
		t.Run(command, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "oversized.tape.yaml")
			tape := "version: 2\nname: oversized\ntarget: " + upstream.URL + "\nscript:\n  - name: ws\n    ws: {path: /ws, frames: 1, timeout_ms: 2000}\n"
			if err := os.WriteFile(path, []byte(tape), 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"test", "--json", path}
			if command == "exec" {
				curl, err := exec.LookPath("curl")
				if err != nil {
					t.Skip("curl not installed")
				}
				args = []string{"exec", "--json", "--tape", path, "--allow-zero-traffic", "--", "sh", "-c",
					`"$1" -q -NsS --http1.1 --max-time 2 -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "$GLITCHDECK_PROXY_URL/ws" || :`, "sh", curl}
			}
			_, out := launchOutput(t, args...)
			var report struct {
				Errors []struct {
					Code     string `json:"error"`
					Declared int    `json:"declared_bytes"`
					Dir      string `json:"dir"`
				} `json:"frame_errors"`
			}
			if err := json.Unmarshal([]byte(out), &report); err != nil || len(report.Errors) != 1 {
				t.Fatalf("report: %v: %s", err, out)
			}
			if frame := report.Errors[0]; frame.Code != "frame_too_large" || frame.Declared != 4194305 || frame.Dir != "s2c" {
				t.Fatalf("frame error: %+v", frame)
			}
		})
	}
}

func TestDefaultWebhookTapeGoldens(t *testing.T) {
	for _, tc := range []struct {
		path              string
		requests, applied uint64
		failures          []string
	}{
		{"checkout-dup-webhook", 2, 1, []string{"duplicate_charges: expected 0, got 1", "total_charged_cents: expected 4900, got 9800"}},
		{"tapes/stripe-duplicate-webhook", 2, 1, []string{"duplicate_charges: expected 0, got 1"}},
		{"tapes/your-app-stripe-dup-webhook", 0, 0, []string{"applied: expected >= 1, got 0"}},
	} {
		t.Run(tc.path, func(t *testing.T) {
			report := filepath.Join(t.TempDir(), "report.json")
			code, out := launchOutput(t, "test", "--json", "--report", report, "../../examples/"+tc.path+".tape.yaml")
			if code != 1 {
				t.Fatalf("exit %d: %s", code, out)
			}
			data, err := os.ReadFile(report)
			if err != nil {
				t.Fatal(err)
			}
			var got struct {
				Summary struct {
					Requests uint64 `json:"requests_total"`
					Applied  uint64 `json:"faults_triggered"`
				}
				Assertions []struct {
					Failures []string
				}
			}
			if err := json.Unmarshal(data, &got); err != nil || got.Summary.Requests != tc.requests || got.Summary.Applied != tc.applied ||
				len(got.Assertions) != 1 || !reflect.DeepEqual(got.Assertions[0].Failures, tc.failures) {
				t.Fatalf("legacy report differs: %v: %s", err, data)
			}
		})
	}
}
