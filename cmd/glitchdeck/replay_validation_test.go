package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidateReplayAndFrameParams(t *testing.T) {
	old := validateStdin
	t.Cleanup(func() { validateStdin = old })
	for _, tc := range []struct{ typ, params, param string }{
		{"dup-webhook", "mode: invalid", "mode"},
		{"dup-webhook", "mode: 1", "mode"},
		{"dup-webhook", "replay_timeout_ms: 0", "replay_timeout_ms"},
		{"dup-webhook", "replay_timeout_ms: 60001", "replay_timeout_ms"},
		{"dup-webhook", "replay_timeout_ms: 1.5", "replay_timeout_ms"},
		{"dup-webhook", "client_result: reset", "client_result"},
		{"dup-webhook", "mode: concurrent, client_result: reset", "client_result"},
		{"dup-webhook", "mode: timeout_retry, client_result: invalid", "client_result"},
		{"dup-webhook", "mode: concurrent, delay_ms: 1", "delay_ms"},
		{"dup-webhook", "mode: concurrent, count: 1", "count"},
		{"dup-webhook", "mode: concurrent, count: 21", "count"},
		{"dup-webhook", "mode: timeout_retry, count: 1", "count"},
		{"dup-webhook", "mode: timeout_retry, count: 21", "count"},
		{"ws-glitch", "frames: invalid", "frames"},
		{"ws-glitch", "frames: 1", "frames"},
	} {
		t.Run(tc.typ+"/"+tc.params, func(t *testing.T) {
			validateStdin = strings.NewReader(fmt.Sprintf("version: 2\ntarget: demo\nrules: [{id: race, fault: {type: %s, params: {%s}}}]\n", tc.typ, tc.params))
			code, out := launchOutput(t, "validate", "-")
			if code != 2 || !strings.Contains(out, `rule "race"`) || !strings.Contains(out, `"`+tc.param+`"`) {
				t.Fatalf("exit %d: %s", code, out)
			}
			if (tc.params == "client_result: reset" || tc.params == "mode: concurrent, client_result: reset") && !strings.Contains(out, `param "client_result": requires mode timeout_retry`) {
				t.Fatalf("missing specific error: %s", out)
			}
		})
	}
}
