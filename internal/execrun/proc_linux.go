//go:build linux

package execrun

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func subreaper() error {
	_, _, err := syscall.RawSyscall(syscall.SYS_PRCTL, 36, 1, 0)
	if err != 0 {
		return err
	}
	return nil
}
func reapChildren() []int {
	deadline := time.Now().Add(2 * time.Second)
	var alive []int
	for {
		alive = nil
		found := false
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return []int{os.Getpid()}
		}
		for _, entry := range entries {
			pid, err := strconv.Atoi(entry.Name())
			if err != nil || pid == os.Getpid() {
				continue
			}
			data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
			if err != nil {
				continue
			}
			text := string(data)
			i := strings.LastIndexByte(text, ')')
			if i < 0 {
				continue
			}
			fields := strings.Fields(text[i+1:])
			if len(fields) < 2 {
				continue
			}
			ppid, err := strconv.Atoi(fields[1])
			if err != nil || ppid != os.Getpid() {
				continue
			}
			found = true
			_ = syscall.Kill(pid, syscall.SIGKILL)
			var status syscall.WaitStatus
			reaped, _ := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
			if reaped == 0 {
				alive = append(alive, pid)
			}
		}
		if !found || time.Now().After(deadline) {
			return alive
		}
		time.Sleep(10 * time.Millisecond)
	}
}
