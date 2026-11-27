//go:build linux

package mcp

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestExecDoesNotInheritMCPOutputDescriptor(t *testing.T) {
	dup, err := OwnedStdioOutput()
	if err != nil {
		t.Fatal(err)
	}
	defer dup.Close()
	target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", dup.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(target, "pipe:[") {
		t.Skip("MCP stdout is not a pipe")
	}
	r := execSingle(t, Options{Workdir: t.TempDir(), AllowExec: true}, map[string]any{"command": []string{"sh", "-c", "ls -l /proc/self/fd"}, "tape_yaml": execTape, "allow_zero_traffic": true})
	out, _ := r.Result.Content["stdout"].(string)
	if r.Result.IsError || r.Result.Content["child_exit"] != float64(0) || strings.Contains(out, target) {
		t.Fatalf("child inherited MCP output %q: %s", target, out)
	}
}
