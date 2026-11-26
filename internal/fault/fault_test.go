package fault

import "testing"

func TestMatchingAndDeterministicLatency(t *testing.T) {
	p := 100
	c := Config{Seed: 42, Rules: []Rule{{ID: "wave", Enabled: true, Match: Match{Method: "GET", PathPrefix: "/a", Seq: []uint64{3}, Probability: &p}, Fault: Fault{Type: "latency-wave", Params: map[string]any{"shape": "jitter", "base_ms": 10, "amp_ms": 20}}}}}
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	if MatchRule(c, "POST", "/a", 3, false) != nil || MatchRule(c, "GET", "/a", 2, false) != nil {
		t.Fatal("matched wrong request")
	}
	r := MatchRule(c, "GET", "/abc", 3, false)
	if r == nil {
		t.Fatal("missing rule")
	}
	a := Latency(c.Seed, 3, r.Fault.Params)
	if a != Latency(c.Seed, 3, r.Fault.Params) || a < 10 || a > 30 {
		t.Fatal(a)
	}
}
func TestRejectInvalidFault(t *testing.T) {
	c := Config{Rules: []Rule{{ID: "x", Fault: Fault{Type: "unknown"}}}}
	if Validate(c) == nil {
		t.Fatal("accepted unknown fault")
	}
}
