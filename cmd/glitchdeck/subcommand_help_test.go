package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSubcommandHelp(t *testing.T) {
	for _, tc := range []struct{ command, option string }{
		{"demo", "-listen"}, {"proxy", "-target"}, {"test", "-timeout"},
		{"exec", "-tape"}, {"mcp", "-workdir"}, {"ca", "-ca-dir"},
		{"report", "-github"}, {"validate", "-json"}, {"version", "-json"},
	} {
		for _, alias := range []string{"-h", "-help", "--help"} {
			t.Run(tc.command+"/"+alias, func(t *testing.T) {
				assertCommandHelp(t, tc.command, tc.option, alias)
			})
		}
		t.Run(tc.command+"/invalid", func(t *testing.T) {
			code, stdout, stderr := runHelpProcess(t, tc.command, "--definitely-not-a-flag")
			if code != 2 || stdout != "" || stderr == "" {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestSubcommandHelpPosition(t *testing.T) {
	assertCommandHelp(t, "ca", "-force", "init", "--help")
	assertCommandHelp(t, "test", "-timeout", "missing.yaml", "--json", "--help")
	assertCommandHelp(t, "validate", "-json", "--json", "missing.yaml", "--help")
	assertCommandHelp(t, "exec", "-tape", "--json", "--help", "--", "missing-command")
	assertCommandHelp(t, "mcp", "-workdir", "unexpected", "--help")

	for _, args := range [][]string{{"exec", "--", "--help"}, {"exec", "--tape", "--", "--help"}} {
		code, stdout, stderr := runHelpProcess(t, args...)
		if code != 2 || stdout != "" || stderr == "" {
			t.Fatalf("%v intercepted child help: exit=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
}

func TestExecForwardsChildHelp(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh unavailable")
	}
	path := filepath.Join(t.TempDir(), "valid.tape.yaml")
	if err := os.WriteFile(path, []byte("version: 2\nname: child-help\ntarget: demo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runHelpProcess(t, "exec", "--tape", path, "--json", "--",
		sh, "-c", `printf 'child received %s' "$1"`, "sh", "--help")
	if code != 0 || !strings.Contains(stdout, "child received --help") || stderr != "" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func assertCommandHelp(t *testing.T, command, option string, args ...string) {
	t.Helper()
	code, stdout, stderr := runHelpProcess(t, append([]string{command}, args...)...)
	if code != 0 || !strings.HasPrefix(stdout, "usage: glitchdeck "+command+" ") || !strings.Contains(stdout, "\n  "+option) || stderr != "" {
		t.Fatalf("%s %v: exit=%d stdout=%q stderr=%q", command, args, code, stdout, stderr)
	}
}

func runHelpProcess(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestSubcommandHelpProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "GORACE=atexit_sleep_ms=0")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	err = cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("%v did not exit with stdin held open: %v", args, ctx.Err())
	}
	if err == nil {
		return 0, stdout.String(), stderr.String()
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatal(err)
	}
	return exit.ExitCode(), stdout.String(), stderr.String()
}

func TestSubcommandHelpProcess(t *testing.T) {
	if len(os.Args) > 3 && os.Args[2] == "--" {
		os.Exit(run(os.Args[3:]))
	}
}
