package main

import (
	"strings"
	"testing"
)

func TestProxyEgressFlagHelp(t *testing.T) {
	for _, command := range []string{"proxy", "demo"} {
		code, out := launchOutput(t, command, "--help")
		if code != 0 || !strings.Contains(out, "-allow-loopback-egress") {
			t.Fatalf("%s help: %d %s", command, code, out)
		}
	}
}
