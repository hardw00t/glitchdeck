package tape_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/tape"
	"github.com/hardw00t/glitchdeck/internal/ui"
)

func TestRecordedRedirectHopRunsOnce(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/end", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	target, err := proxy.ParseTarget(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := proxy.New(target, fault.Config{}, nil)
	defer p.Close()
	recording := ui.NewRecorder()
	recording.Start(p)
	recording.SetCassetteMetadata(upstream.URL, nil)
	server := httptest.NewServer(p)
	defer server.Close()
	resp, err := http.Get(server.URL + "/start")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if err := p.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	recording.Stop()
	doc, err := recording.Export("redirect")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Script) != 2 {
		t.Fatalf("recorded script: %#v", doc.Script)
	}
	doc.Rules = []fault.Rule{{ID: "destination", Enabled: true, Match: fault.Match{PathPrefix: "/end"}, Fault: fault.Fault{Type: "latency-wave"}}}
	_, report, err := tape.RunReplay(context.Background(), doc, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if report.RequestsTotal != 2 || len(report.AppliedFaults) != 1 {
		t.Fatalf("requests=%d faults=%v", report.RequestsTotal, report.AppliedFaults)
	}
}

func TestNonadjacentRecordedSSERedirectHopRunsOnce(t *testing.T) {
	doc := tape.Tape{Version: 3, Target: "demo",
		Script: []tape.Step{
			{HTTP: &tape.HTTP{Path: "/start"}},
			{HTTP: &tape.HTTP{Path: "/other"}},
			{Name: "stream", Stream: &tape.Stream{Path: "/end"}},
		},
		Cassettes: []tape.Cassette{
			{Request: tape.CassetteRequest{Method: "GET", Path: "/start"}, Response: tape.CassetteResponse{Status: 302, Headers: map[string]string{"Location": "/end"}}},
			{Request: tape.CassetteRequest{Method: "GET", Path: "/other"}, Response: tape.CassetteResponse{Status: 200}},
			{Request: tape.CassetteRequest{Method: "GET", Path: "/end"}, Response: tape.CassetteResponse{Status: 200, Headers: map[string]string{"Content-Type": "text/event-stream"}, Body: "data: [DONE]\n\n"}},
		},
		Rules: []fault.Rule{{ID: "destination", Enabled: true, Match: fault.Match{PathPrefix: "/end"}, Fault: fault.Fault{Type: "latency-wave"}}},
	}
	_, report, err := tape.RunReplay(context.Background(), doc, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if report.RequestsTotal != 3 || len(report.AppliedFaults) != 1 {
		t.Fatalf("requests=%d faults=%v", report.RequestsTotal, report.AppliedFaults)
	}
}

func TestUnrecordedLocalRedirectStillFollows(t *testing.T) {
	doc := tape.Tape{Version: 3, Target: "demo",
		Script: []tape.Step{{HTTP: &tape.HTTP{Path: "/start"}}},
		Cassettes: []tape.Cassette{
			{Request: tape.CassetteRequest{Method: "GET", Path: "/start"}, Response: tape.CassetteResponse{Status: 302, Headers: map[string]string{"Location": "/end"}}},
			{Request: tape.CassetteRequest{Method: "GET", Path: "/end"}, Response: tape.CassetteResponse{Status: 200}},
		},
	}
	_, report, err := tape.RunReplay(context.Background(), doc, "", "", false)
	if err != nil || report.RequestsTotal != 2 {
		t.Fatalf("requests=%d err=%v", report.RequestsTotal, err)
	}
}
