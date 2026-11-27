package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hardw00t/glitchdeck/internal/execrun"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/tape"
)

func malformedArgs() *paramError {
	return &paramError{Field: "arguments", Reason: "malformed"}
}

func tapeChoiceError() *paramError {
	return &paramError{Field: "arguments", Reason: "mutually_exclusive", Fields: []string{"tape_path", "tape_yaml"}}
}

func (s *Server) prepareExec(raw []byte) (jobRun, map[string]any, *paramError) {
	var a struct {
		Command          []string `json:"command"`
		TapePath         *string  `json:"tape_path"`
		TapeYAML         *string  `json:"tape_yaml"`
		Cwd              string   `json:"cwd"`
		Target           string   `json:"target"`
		TLS              bool     `json:"tls"`
		TLSPassthrough   []string `json:"tls_passthrough"`
		AllowZeroTraffic bool     `json:"allow_zero_traffic"`
		Seed             *uint64  `json:"seed"`
		TimeoutSec       int      `json:"timeout_sec"`
	}
	if json.Unmarshal(raw, &a) != nil {
		return nil, nil, malformedArgs()
	}
	if (a.TapePath == nil) == (a.TapeYAML == nil) {
		return nil, nil, tapeChoiceError()
	}
	for i, arg := range a.Command {
		if strings.ContainsRune(arg, 0) {
			return nil, nil, &paramError{Field: fmt.Sprintf("arguments.command[%d]", i), Reason: "invalid_value"}
		}
	}
	for i, pattern := range a.TLSPassthrough {
		if proxy.ValidatePassthrough(pattern) != nil {
			return nil, nil, &paramError{Field: fmt.Sprintf("arguments.tls_passthrough[%d]", i), Reason: "invalid_value"}
		}
	}
	dir, err := s.execDir(a.Cwd)
	if err != nil {
		return nil, fail("INVALID_PATH", err.Error()), nil
	}
	name := "<inline>"
	var t tape.Tape
	if a.TapePath == nil {
		t, err = tape.Decode(strings.NewReader(*a.TapeYAML))
	} else {
		name = *a.TapePath
		if !filepath.IsLocal(name) || strings.ContainsRune(name, 0) {
			return nil, fail("INVALID_PATH", "tape_path escapes workdir"), nil
		}
		data, readErr := s.readTapeBytes(name)
		if readErr != nil {
			return nil, fail("INVALID_PATH", "tape_path must name a readable regular file of at most 1 MiB within workdir"), nil
		}
		t, err = tape.Decode(bytes.NewReader(data))
	}
	if err != nil {
		return nil, fail("TAPE_INVALID", "tape failed validation; use tape_validate for details"), nil
	}
	serverAllow := make(map[string]struct{})
	for _, entries := range s.opts.UpstreamAllow {
		for item := range strings.SplitSeq(entries, ",") {
			serverAllow[strings.ToLower(strings.TrimSpace(item))] = struct{}{}
		}
	}
	for i, entry := range t.UpstreamAllow {
		if _, ok := serverAllow[strings.ToLower(strings.TrimSpace(entry))]; !ok {
			return nil, fail("EGRESS_POLICY", fmt.Sprintf("tape upstream_allow entry %d is not permitted by the server --upstream-allow policy", i+1)), nil
		}
	}
	t.UpstreamAllow = nil
	if a.Target == "" {
		a.Target = t.Target
	}
	requireAllow := false
	if a.Target != "" && a.Target != "demo" {
		target, err := proxy.ParseExplicitTarget(a.Target)
		if err != nil {
			return nil, fail("TARGET_INVALID", err.Error()), nil
		}
		if !proxy.UpstreamAllowed(target, s.opts.UpstreamAllow) {
			return nil, fail("EGRESS_POLICY", "target host is not permitted by the server --upstream-allow policy"), nil
		}
		requireAllow = !proxy.UpstreamAllowed(target, nil)
	}
	if a.TimeoutSec == 0 {
		a.TimeoutSec = 30
	}
	o := execrun.Options{
		Command: a.Command, TapePath: name, Dir: dir, Target: a.Target, Listen: "127.0.0.1:0",
		Timeout: time.Duration(a.TimeoutSec) * time.Second, Grace: execGrace, JSON: true, DetachStdio: true, TailBytes: 64 << 10,
		UpstreamAllow: s.opts.UpstreamAllow, RequireUpstreamAllow: requireAllow, TLS: a.TLS,
		TLSPassthrough: a.TLSPassthrough, AllowZeroTraffic: a.AllowZeroTraffic, Seed: a.Seed,
	}
	return func(ctx context.Context) map[string]any { return execResult(execrun.Run(ctx, t, o)) }, nil, nil
}

func execResult(e execrun.Envelope) map[string]any {
	if problem, ok := e.Error.(map[string]string); ok {
		// Process startup and proxy errors can contain absolute paths or environment values.
		message := "exec_run failed"
		switch problem["code"] {
		case "EXEC_SPAWN_FAILED":
			message = "could not start command"
		case "TIMEOUT":
			message = "command exceeded its timeout"
		case "LEAKED_PIDS":
			message = "child processes remain"
		}
		e.Error = map[string]string{"code": problem["code"], "message": message}
	}
	x := e.Exec
	result := map[string]any{
		"schema_version": e.SchemaVersion, "command": e.Command, "ok": e.OK, "exit_code": e.ExitCode,
		"tape": e.Tape, "target": e.Target, "duration_ms": e.DurationMS, "summary": e.Summary,
		"faults_triggered": e.FaultsTriggered, "assertions": e.Assertions, "diff": e.Diff, "error": e.Error,
		"exec": x, "child_exit": x.ExitCode, "timed_out": x.TimedOut, "traffic": x.Traffic,
		"stdout": x.StdoutTail, "stdout_bytes": x.StdoutBytes, "stdout_truncated": x.StdoutTruncated,
		"stderr": x.StderrTail, "stderr_bytes": x.StderrBytes, "stderr_truncated": x.StderrTruncated,
		"leaked_pids": append([]int{}, x.LeakedPIDs...), "warnings": append([]string{}, x.Warnings...),
	}
	if len(e.FrameErrors) != 0 {
		result["frame_errors"] = e.FrameErrors
	}
	if e.FrameErrorsOmitted != 0 {
		result["frame_errors_omitted"] = e.FrameErrorsOmitted
	}
	return result
}

func (s *Server) execDir(p string) (string, error) {
	if p == "" {
		p = "."
	}
	escape := errors.New("cwd escapes workdir")
	notDir := errors.New("cwd is not a directory")
	if !filepath.IsLocal(p) || strings.ContainsRune(p, 0) {
		return "", escape
	}
	base, err := filepath.Abs(s.opts.Workdir)
	if err != nil {
		return "", notDir
	}
	base, err = filepath.EvalSymlinks(base)
	if err != nil {
		return "", notDir
	}
	dir, err := filepath.EvalSymlinks(filepath.Join(base, p))
	if err != nil {
		return "", notDir
	}
	rel, err := filepath.Rel(base, dir)
	if err != nil || !filepath.IsLocal(rel) {
		return "", escape
	}
	if stat, err := os.Lstat(dir); err != nil || !stat.IsDir() {
		return "", notDir
	}
	return dir, nil
}
