package fault

import (
	"strings"
	"testing"
)

func TestInvalidParameterHints(t *testing.T) {
	for _, tc := range []struct {
		typ, param string
		value      any
		hint       string
	}{
		{"rate-limit", "status", 700, "between 200 and 599"},
		{"dup-webhook", "mode", "bad", "sequential, concurrent, timeout_retry"},
		{"sse-glitch", "after_events", -1, "between 0 and 1000000"},
		{"sse-glitch", "mode", "bad", "cut, brace, quote"},
	} {
		params := map[string]any{tc.param: tc.value}
		if tc.typ == "sse-glitch" && tc.param == "mode" {
			params["action"] = "corrupt_json"
			params["every"] = 1
		}
		err := Validate(Config{Rules: []Rule{{ID: "r", Fault: Fault{Type: tc.typ, Params: params}}}})
		if err == nil || !strings.Contains(err.Error(), tc.hint) {
			t.Errorf("%s.%s: %v", tc.typ, tc.param, err)
		}
	}
}
