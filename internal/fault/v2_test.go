package fault

import "testing"

func TestProtocolEligibility(t *testing.T) {
	c := Config{Rules: []Rule{{ID: "grpc", Enabled: true, Fault: Fault{Type: "grpc-glitch"}}, {ID: "http", Enabled: true, Fault: Fault{Type: "rate-limit"}}}}
	if r := MatchRequest(c, Query{Proto: "h1"}); r == nil || r.ID != "http" {
		t.Fatalf("h1 selected %+v", r)
	}
	if r := MatchRequest(c, Query{Proto: "h2", ContentType: "application/grpc"}); r == nil || r.ID != "grpc" {
		t.Fatalf("h2 selected %+v", r)
	}
}
