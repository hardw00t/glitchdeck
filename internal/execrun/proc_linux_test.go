//go:build linux

package execrun

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/tape"
)

func TestExecReapsDetachedChild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pid")
	r := Run(context.Background(), tape.Tape{Version: 2, Target: "demo"}, Options{Command: []string{"sh", "-c", `setsid sleep 300 & echo $! > "$1"; exec sleep 300`, "sh", path}, Timeout: 300 * time.Millisecond, Grace: 100 * time.Millisecond})
	if r.ExitCode != 124 {
		t.Fatalf("got exit %d", r.ExitCode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Kill(pid, 0); err != syscall.ESRCH {
		t.Fatalf("detached process %d remains: %v", pid, err)
	}
}
