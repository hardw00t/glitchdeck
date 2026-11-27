package fault

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestReplayAndFrameParams(t *testing.T) {
	for _, tc := range []struct {
		name, typ, param string
		params           map[string]any
	}{
		{"mode enum", "dup-webhook", "mode", map[string]any{"mode": "bad"}},
		{"mode type", "dup-webhook", "mode", map[string]any{"mode": 1}},
		{"timeout zero", "dup-webhook", "replay_timeout_ms", map[string]any{"replay_timeout_ms": 0}},
		{"timeout high", "dup-webhook", "replay_timeout_ms", map[string]any{"replay_timeout_ms": 60001}},
		{"timeout fraction", "dup-webhook", "replay_timeout_ms", map[string]any{"replay_timeout_ms": 1.5}},
		{"client mode", "dup-webhook", "client_result", map[string]any{"client_result": "reset"}},
		{"client enum", "dup-webhook", "client_result", map[string]any{"mode": "timeout_retry", "client_result": "bad"}},
		{"concurrent delay", "dup-webhook", "delay_ms", map[string]any{"mode": "concurrent", "delay_ms": 1}},
		{"concurrent count low", "dup-webhook", "count", map[string]any{"mode": "concurrent", "count": 1}},
		{"concurrent count high", "dup-webhook", "count", map[string]any{"mode": "concurrent", "count": 21}},
		{"retry count low", "dup-webhook", "count", map[string]any{"mode": "timeout_retry", "count": 1}},
		{"retry count high", "dup-webhook", "count", map[string]any{"mode": "timeout_retry", "count": 21}},
		{"frames enum", "ws-glitch", "frames", map[string]any{"frames": "bad"}},
		{"frames type", "ws-glitch", "frames", map[string]any{"frames": 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(Config{Rules: []Rule{{ID: "race", Fault: Fault{Type: tc.typ, Params: tc.params}}}})
			var validation *ValidationError
			if !errors.As(err, &validation) || validation.Param != tc.param {
				t.Fatalf("got %v, want param %s", err, tc.param)
			}
		})
	}
	for _, params := range []map[string]any{nil, {"mode": "sequential", "count": 100}, {"mode": "concurrent", "count": 2, "delay_ms": 0, "replay_timeout_ms": 1}, {"mode": "timeout_retry", "count": 20, "client_result": "reset", "replay_timeout_ms": 60000}, {"mode": "concurrent"}, {"mode": "timeout_retry"}} {
		if err := Validate(Config{Rules: []Rule{{ID: "r", Fault: Fault{Type: "dup-webhook", Params: params}}}}); err != nil {
			t.Fatalf("%v: %v", params, err)
		}
	}
	for _, frames := range []string{"all", "data", "control"} {
		if err := Validate(Config{Rules: []Rule{{ID: "r", Fault: Fault{Type: "ws-glitch", Params: map[string]any{"frames": frames}}}}}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReplayAndFrameCatalog(t *testing.T) {
	for _, tc := range []struct {
		typ, param string
		values     []string
		def        string
	}{
		{"dup-webhook", "mode", []string{"sequential", "concurrent", "timeout_retry"}, "sequential"},
		{"dup-webhook", "client_result", []string{"gateway_timeout", "reset"}, "gateway_timeout"},
		{"ws-glitch", "frames", []string{"all", "data", "control"}, "all"},
	} {
		p := Registry[tc.typ].Params[tc.param]
		if !reflect.DeepEqual(p.Enum, tc.values) || p.Default != tc.def {
			t.Errorf("%s.%s: %+v", tc.typ, tc.param, p)
		}
	}
}

func FuzzReplayParams(f *testing.F) {
	for _, seed := range []string{`{}`, `{"mode":"concurrent","count":5}`, `{"mode":"timeout_retry","count":2,"client_result":"reset"}`, `{"mode":3,"replay_timeout_ms":1.5}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		var params map[string]any
		if json.Unmarshal([]byte(input), &params) != nil {
			return
		}
		_ = Validate(Config{Rules: []Rule{{ID: "fuzz", Fault: Fault{Type: "dup-webhook", Params: params}}}})
	})
}
