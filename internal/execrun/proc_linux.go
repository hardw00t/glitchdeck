//go:build linux

package execrun

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const helperEnv = "GLITCHDECK_INTERNAL_EXEC_HELPER"

type helperSpec struct {
	Path  string
	Args  []string
	Grace time.Duration
}

func ownsChildren() bool { return os.Getenv(helperEnv) != "" }

func isolateProcess(cmd *exec.Cmd, grace time.Duration) (*os.File, *os.File, error) {
	if cmd.Err != nil {
		return nil, nil, nil
	}
	if info, err := os.Stat(cmd.Path); err == nil && !info.IsDir() && info.Mode().Perm()&0111 == 0 {
		return nil, nil, nil
	}
	self, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	spec, err := json.Marshal(helperSpec{Path: cmd.Path, Args: cmd.Args, Grace: grace})
	if err != nil {
		reader.Close()
		writer.Close()
		return nil, nil, err
	}
	cmd.Path = self
	cmd.Args = []string{self}
	cmd.Env = append(cmd.Env, helperEnv+"="+string(spec))
	cmd.ExtraFiles = append(cmd.ExtraFiles, writer)
	cmd.WaitDelay = 3*grace + 6*time.Second
	return reader, writer, nil
}

func init() {
	value := os.Getenv(helperEnv)
	if value == "" {
		return
	}
	var spec helperSpec
	if json.Unmarshal([]byte(value), &spec) != nil || spec.Path == "" || len(spec.Args) == 0 {
		os.Exit(125)
	}
	_ = os.Unsetenv(helperEnv)
	if err := subreaper(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(125)
	}
	cmd := &exec.Cmd{Path: spec.Path, Args: spec.Args}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	startSignals, stopSignals := forwardSignals(spec.Grace)
	report := os.NewFile(3, "helper-report")
	syscall.CloseOnExec(3)
	if err := cmd.Start(); err != nil {
		stopSignals()
		code := 125
		if errors.Is(err, os.ErrPermission) {
			code = 126
		} else if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			code = 127
		}
		if report != nil {
			_, _ = fmt.Fprintln(report, 0)
		}
		if report != nil {
			_ = json.NewEncoder(report).Encode(helperReport{SpawnCode: code, SpawnError: err.Error()})
			_ = report.Close()
		}
		os.Exit(code)
	}
	startSignals(cmd)
	if report != nil {
		_, _ = fmt.Fprintln(report, cmd.Process.Pid)
	}
	err := cmd.Wait()
	leaked := cleanupOwnedProcess(cmd, spec.Grace)
	stopSignals()
	if report != nil {
		_ = json.NewEncoder(report).Encode(helperReport{Leaked: leaked})
		_ = report.Close()
	}
	if len(leaked) != 0 {
		os.Exit(125)
	}
	if err == nil {
		os.Exit(0)
	}
	if cmd.ProcessState != nil {
		if code := cmd.ProcessState.ExitCode(); code >= 0 {
			os.Exit(code)
		}
		if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			os.Exit(128 + int(status.Signal()))
		}
	}
	os.Exit(125)
}

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
