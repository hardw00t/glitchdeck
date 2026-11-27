package main

import (
	"strings"
	"testing"
)

func TestExecHelp(t *testing.T) {
	for _, flag := range []string{"-h", "--help"} {
		code, out := launchOutput(t, "exec", flag)
		if code != 0 || !strings.HasPrefix(out, "usage: glitchdeck exec --tape <file>") || !strings.Contains(out, "-upstream-allow") {
			t.Fatalf("exec %s: code=%d out=%q", flag, code, out)
		}
	}
}
