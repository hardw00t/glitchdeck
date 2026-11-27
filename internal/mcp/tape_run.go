package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/hardw00t/glitchdeck/internal/execrun"
	"github.com/hardw00t/glitchdeck/internal/tape"
)

func (s *Server) prepareTapeRun(raw []byte) (jobRun, map[string]any, *paramError) {
	var a struct {
		TapePath  *string `json:"tape_path"`
		TapeYAML  *string `json:"tape_yaml"`
		Target    string  `json:"target"`
		TimeoutMS int     `json:"timeout_ms"`
	}
	if json.Unmarshal(raw, &a) != nil {
		return nil, nil, malformedArgs()
	}
	if (a.TapePath == nil) == (a.TapeYAML == nil) {
		return nil, nil, tapeChoiceError()
	}
	var t tape.Tape
	var err error
	var name string
	if a.TapePath != nil {
		name = *a.TapePath
		t, err = s.readTape(name)
	} else {
		t, err = tape.Decode(strings.NewReader(*a.TapeYAML))
		name = t.Name
	}
	if err != nil {
		return nil, fail("INVALID_TAPE", err.Error()), nil
	}
	if len(t.UpstreamAllow) > 0 {
		return nil, fail("INVALID_TAPE", "MCP tapes cannot expand the loopback egress policy"), nil
	}
	if a.TimeoutMS == 0 {
		a.TimeoutMS = 30000
	}
	return func(ctx context.Context) map[string]any {
		return runTape(ctx, t, name, a.Target, time.Duration(a.TimeoutMS)*time.Millisecond)
	}, nil, nil
}

func runTape(ctx context.Context, t tape.Tape, name, override string, timeout time.Duration) map[string]any {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	results, report, err := tape.RunWithReport(ctx, t, override)
	envelope := execrun.Envelope{FaultsTriggered: []any{}}
	envelope.SetAppliedFaults(report.AppliedFaults)
	addDiagnostics := func(result map[string]any) map[string]any {
		if len(report.FrameErrors) != 0 {
			result["frame_errors"] = report.FrameErrors
		}
		if report.FrameErrorsOmitted != 0 {
			result["frame_errors_omitted"] = report.FrameErrorsOmitted
		}
		return result
	}
	if ctx.Err() != nil || err != nil {
		code := "INVALID_TAPE"
		if ctx.Err() != nil {
			code, err = "TIMEOUT", ctx.Err()
		}
		result := fail(code, err.Error())
		if len(envelope.FaultsTriggered) != 0 {
			result["faults_triggered"] = envelope.FaultsTriggered
		}
		return addDiagnostics(result)
	}
	assertions := make([]any, 0, len(results))
	failed := 0
	for _, r := range results {
		ok := len(r.Failures) == 0
		if !ok {
			failed++
		}
		failures := r.Failures
		if failures == nil {
			failures = []string{}
		}
		assertions = append(assertions, map[string]any{"name": r.Name, "passed": ok, "failures": failures})
	}
	code := 0
	if failed > 0 {
		code = 1
	}
	target := t.Target
	if override != "" {
		target = override
	}
	return addDiagnostics(map[string]any{
		"schema_version": 2, "command": "test", "ok": code == 0, "exit_code": code,
		"tape": name, "target": target, "duration_ms": time.Since(start).Milliseconds(),
		"summary":          map[string]any{"assertions_total": len(results), "assertions_failed": failed, "assertions_passed": len(results) - failed, "requests_total": report.RequestsTotal, "faults_triggered": envelope.Summary.FaultsTriggered},
		"faults_triggered": envelope.FaultsTriggered, "assertions": assertions, "error": nil,
	})
}
