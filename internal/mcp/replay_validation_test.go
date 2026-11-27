package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestTapeValidateReplayAndFrameParams(t *testing.T) {
	for _, tc := range []struct{ typ, params, param string }{
		{"dup-webhook", "mode: invalid", "mode"},
		{"dup-webhook", "mode: 1", "mode"},
		{"dup-webhook", "replay_timeout_ms: 0", "replay_timeout_ms"},
		{"dup-webhook", "replay_timeout_ms: 60001", "replay_timeout_ms"},
		{"dup-webhook", "replay_timeout_ms: 1.5", "replay_timeout_ms"},
		{"dup-webhook", "client_result: reset", "client_result"},
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
			tape := fmt.Sprintf("version: 2\ntarget: demo\nrules: [{id: race, fault: {type: %s, params: {%s}}}]\n", tc.typ, tc.params)
			args, err := json.Marshal(map[string]string{"tape_yaml": tape})
			if err != nil {
				t.Fatal(err)
			}
			input := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tape_validate","arguments":%s}}`+"\n", args)
			var output strings.Builder
			if err := NewServer(strings.NewReader(input), &output, Options{Workdir: t.TempDir()}).Serve(); err != nil {
				t.Fatal(err)
			}
			var reply struct {
				Result *struct {
					IsError    bool           `json:"isError"`
					Structured map[string]any `json:"structuredContent"`
				} `json:"result"`
			}
			if err := json.Unmarshal([]byte(output.String()), &reply); err != nil {
				t.Fatal(err)
			}
			if reply.Result == nil || !reply.Result.IsError {
				t.Fatal(output.String())
			}
			message, _ := reply.Result.Structured["error"].(string)
			if !strings.Contains(message, `rule "race"`) || !strings.Contains(message, `"`+tc.param+`"`) {
				t.Fatal(output.String())
			}
		})
	}
}
