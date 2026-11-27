//go:build !linux && !windows

package execrun

import (
	"os"
	"os/exec"
	"time"
)

func subreaper() error    { return nil }
func reapChildren() []int { return nil }
func ownsChildren() bool  { return true }
func isolateProcess(cmd *exec.Cmd, grace time.Duration) (*os.File, *os.File, error) {
	return nil, nil, nil
}

func isolateDetachedProcess(cmd *exec.Cmd, grace time.Duration) (*detachedHelper, error) {
	return nil, nil
}
