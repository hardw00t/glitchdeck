package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFix3CLIHelper(t *testing.T) {
	for i, arg := range os.Args {
		if arg == "--" {
			os.Exit(run(os.Args[i+1:]))
		}
	}
}

func TestRecordLoggerAndLiveStdio(t *testing.T) {
	if endpoint := os.Getenv("GD_FIX3_LOG_ENDPOINT"); endpoint != "" {
		client := &http.Client{Timeout: 10 * time.Second}
		base := os.Getenv("GLITCHDECK_PROXY_URL")
		if resp, err := client.Get(base + endpoint); err != nil {
			os.Exit(21)
		} else {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		if resp, err := client.Get(base + "/secret"); err != nil {
			os.Exit(22)
		} else {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		fmt.Fprintln(os.Stdout, "child-stdout-marker")
		fmt.Fprintln(os.Stderr, "child-stderr-marker")
		os.Exit(0)
	}
	secret := "sk-ant-" + strings.Repeat("g", 32)
	for _, mode := range []string{"passthrough", "record"} {
		t.Run(mode, func(t *testing.T) {
			idleClosed := make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/secret" {
					select {
					case <-idleClosed:
					case <-r.Context().Done():
						return
					}
					fmt.Fprintf(w, `{"api_key":%q}`, secret)
					return
				}
				conn, rw, err := http.NewResponseController(w).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				defer close(idleClosed)
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				fmt.Fprintf(rw, "HTTP/1.1 204 No Content\r\n\r\n%s", secret)
				rw.Flush()
				io.Copy(io.Discard, conn)
			}))
			defer upstream.Close()
			dir := t.TempDir()
			input, report := filepath.Join(dir, "input.yaml"), filepath.Join(dir, "report.json")
			if err := os.WriteFile(input, []byte("version: 2\ntarget: "+upstream.URL+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			args := []string{"-test.run=^TestFix3CLIHelper$", "--", "exec", "--tape", input, "--report", report, "--mode", mode}
			if mode == "record" {
				args = append(args, "--tape-out", filepath.Join(dir, "output.yaml"))
			}
			args = append(args, "--", os.Args[0], "-test.run=^TestRecordLoggerAndLiveStdio$")
			cmd := exec.CommandContext(ctx, os.Args[0], args...)
			cmd.Env = append(os.Environ(), "GD_FIX3_LOG_ENDPOINT=/idle")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if mode == "passthrough" {
				if err != nil || !strings.Contains(stderr.String(), secret) {
					t.Fatalf("fixture did not trigger the stdlib log: %v; %s", err, stderr.String())
				}
				return
			}
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 2 {
				t.Fatalf("record did not block: %v; %s", err, stderr.String())
			}
			if !bytes.Contains(out, []byte("child-stdout-marker")) || !strings.Contains(stderr.String(), "child-stderr-marker") {
				t.Error("record mode suppressed child output")
			}
			data, err := os.ReadFile(report)
			if err != nil {
				t.Fatal(err)
			}
			for _, sink := range []string{stderr.String(), string(data)} {
				if strings.Contains(sink, secret) || strings.Contains(sink, dir) || !strings.Contains(sink, "secret_kind=anthropic") || !strings.Contains(sink, "field=$.") {
					t.Errorf("unsafe or missing blocked diagnostic: %q", sink)
				}
			}
			if bytes.Contains(data, []byte("child-")) {
				t.Error("child output reached the report")
			}
		})
	}
}

func TestExecRecordCanReplaceInputInPlace(t *testing.T) {
	if input := os.Getenv("GD_FIX3_INPLACE_INPUT"); input != "" {
		moved := input + ".moved"
		if err := os.Rename(input, moved); err != nil {
			os.Exit(26)
		}
		if err := os.Rename(moved, input); err != nil {
			os.Exit(27)
		}
		os.Exit(0)
	}
	input := filepath.Join(t.TempDir(), "input.yaml")
	if err := os.WriteFile(input, []byte("version: 2\ntarget: demo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GD_FIX3_INPLACE_INPUT", input)
	code, out := launchOutput(t, "exec", "--json", "--tape", input, "--mode", "record", "--tape-out", input, "--allow-zero-traffic", "--", os.Args[0], "-test.run=^TestExecRecordCanReplaceInputInPlace$")
	if code != 0 {
		t.Fatalf("in-place record failed: exit %d, %s", code, out)
	}
	data, err := os.ReadFile(input)
	if err != nil || !bytes.Contains(data, []byte("name:")) {
		t.Fatalf("input was not replaced by a recording: %q; %v", data, err)
	}
}

func TestExecRechecksRotatedInputSymlink(t *testing.T) {
	dir := t.TempDir()
	input, original, next := filepath.Join(dir, "input"), filepath.Join(dir, "original"), filepath.Join(dir, "next")
	if target := os.Getenv("GD_FIX3_ROTATE_INPUT"); target != "" {
		if err := os.Remove(target); err != nil {
			os.Exit(24)
		}
		if err := os.Symlink("next", target); err != nil {
			os.Exit(25)
		}
		os.Exit(0)
	}
	const raw = "version: 2\ntarget: demo\n"
	for _, path := range []string{original, next} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("original", input); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	t.Setenv("GD_FIX3_ROTATE_INPUT", input)
	code, out := launchOutput(t, "exec", "--json", "--mode", "replay", "--tape", input, "--report", next, "--allow-zero-traffic", "--", os.Args[0], "-test.run=^TestExecRechecksRotatedInputSymlink$")
	data, err := os.ReadFile(next)
	if code != 3 || string(data) != raw || err != nil {
		t.Fatalf("exit %d, selected input %q, err %v: %s", code, data, err, out)
	}
}
