package main

import (
	"context"
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
	"github.com/hardw00t/glitchdeck/internal/wsframe"
)

func TestRecordXMLExport(t *testing.T) {
	if i := slices.Index(os.Args, "--"); i >= 0 {
		os.Exit(run(os.Args[i+1:]))
	}
	fake := "sk-" + "ant-" + strings.Repeat("Z", 24)
	entity := `<!DOCTYPE x [<!ENTITY hyphen "&#45;">]><x key="sk&hyphen;` + fake[3:] + `"/>`
	for _, tc := range []struct {
		name, payload, kind, path string
		ws                        bool
	}{
		{"http-entity", entity, "unscannable_xml_entity", "$.cassettes[0].response.body", false},
		{"http-subset", `<!DOCTYPE x [<!ELEMENT x EMPTY>]><x/>`, "unscannable_xml_entity", "$.cassettes[0].response.body", false},
		{"ws-reference", `<x key="sk&#45;` + fake[3:] + `"/>`, "anthropic", "$.script[0].ws.messages[0]", true},
		{"ws-entity", entity, "unscannable_xml_entity", "$.script[0].ws.messages[0]", true},
	} {
		for _, redact := range []bool{false, true} {
			name := tc.name + "/block"
			if redact {
				name = tc.name + "/redact"
			}
			t.Run(name, func(t *testing.T) {
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if !tc.ws {
						w.Header().Set("Content-Type", "application/xml")
						io.WriteString(w, tc.payload)
						return
					}
					conn, rw, err := w.(http.Hijacker).Hijack()
					if err != nil {
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + wsframe.AcceptKey(r.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n")
					if rw.Flush() != nil {
						return
					}
					if frame, err := wsframe.Read(rw, true); err == nil && string(frame.Payload) == tc.payload {
						_ = wsframe.Write(conn, wsframe.Frame{Fin: true, Opcode: 8}, false)
						_, _ = wsframe.Read(rw, true)
					}
				}))
				defer upstream.Close()
				dir := t.TempDir()
				input, output, report := filepath.Join(dir, "input.yaml"), filepath.Join(dir, "output.yaml"), filepath.Join(dir, "report.json")
				if err := os.WriteFile(input, []byte("version: 2\ntarget: "+upstream.URL+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				args := []string{"-test.run=^TestRecordXMLExport$", "--", "exec", "--json", "--tape", input, "--report", report, "--mode", "record", "--tape-out", output, "--grace", "3s"}
				if redact {
					args = append(args, "--redact-secrets")
				}
				cmd := exec.Command(os.Args[0], append(args, "--", os.Args[0], "-test.run=^TestFix8XMLClient$")...)
				cmd.Env = append(os.Environ(), "GD_FIX8_XML="+tc.payload)
				if tc.ws {
					cmd.Env = append(cmd.Env, "GD_FIX8_WS=1")
				}
				log, runErr := cmd.CombinedOutput()
				reportData, err := os.ReadFile(report)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(log)+string(reportData), fake) || strings.Contains(string(log)+string(reportData), tc.payload) {
					t.Fatal("wire content leaked in process output or report")
				}
				if !redact {
					want := "secret_kind=" + tc.kind + " field=" + tc.path
					if cmd.ProcessState.ExitCode() != 2 || !strings.Contains(string(log), want) || !strings.Contains(string(reportData), want) {
						t.Fatalf("expected safe export block, got %v: %s", runErr, log)
					}
					if _, err := os.Stat(output); !os.IsNotExist(err) {
						t.Fatalf("unexpected output file: %v", err)
					}
					return
				}
				if runErr != nil {
					t.Fatalf("redacted export failed: %v: %s", runErr, log)
				}
				data, err := os.ReadFile(output)
				if err != nil {
					t.Fatal(err)
				}
				doc, err := tape.Decode(strings.NewReader(string(data)))
				if err != nil || !doc.Redacted || strings.Contains(string(data), tc.payload) || strings.Contains(string(data), fake) {
					t.Fatalf("expected a valid redacted tape without wire content: %v", err)
				}
				if tc.ws {
					if len(doc.Script) != 1 || doc.Script[0].WS == nil || !slices.Equal(doc.Script[0].WS.Messages, []string{"REDACTED"}) {
						t.Fatal("missing WebSocket message redaction")
					}
				} else if len(doc.Cassettes) != 1 || doc.Cassettes[0].Response.Body != "REDACTED" {
					t.Fatal("missing response body redaction")
				}
			})
		}
	}
}

func TestFix8XMLClient(t *testing.T) {
	body := os.Getenv("GD_FIX8_XML")
	if body == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", os.Getenv("GLITCHDECK_PROXY_URL")+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	ws := os.Getenv("GD_FIX8_WS") != ""
	if ws {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if !ws {
		if _, err := io.Copy(io.Discard, res.Body); err != nil {
			t.Fatal(err)
		}
		return
	}
	stream, ok := res.Body.(io.ReadWriter)
	if !ok || res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade failed: %d", res.StatusCode)
	}
	if err := wsframe.Write(stream, wsframe.Frame{Fin: true, Opcode: 1, Payload: []byte(body)}, true); err != nil {
		t.Fatal(err)
	}
	if frame, err := wsframe.Read(stream, false); err != nil || frame.Opcode != 8 {
		t.Fatalf("missing close: opcode=%d err=%v", frame.Opcode, err)
	}
	if err := wsframe.Write(stream, wsframe.Frame{Fin: true, Opcode: 8}, true); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, stream)
}
