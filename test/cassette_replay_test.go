package integration_test

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/tape"
)

func cassetteListener(t *testing.T, doc tape.Tape) (string, *proxy.Proxy, *atomic.Int64) {
	t.Helper()
	accepts := new(atomic.Int64)
	upstream := httptest.NewUnstartedServer(http.NotFoundHandler())
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepts.Add(1)
		}
	}
	upstream.Start()
	t.Cleanup(upstream.Close)
	target, err := proxy.ParseTarget(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := proxy.New(target, fault.Config{}, nil)
	t.Cleanup(p.Close)
	p.SetOptions(proxy.Options{CassetteUpstream: doc.CassetteUpstream()})
	server := httptest.NewServer(p)
	t.Cleanup(server.Close)
	return server.URL, p, accepts
}

func TestConcurrentCassetteMatcherNeverDials(t *testing.T) {
	doc := tape.Tape{IgnoreJSONPaths: []string{"request_id"}}
	for i := range 2 {
		body := fmt.Sprintf(`{"choice":%d,"request_id":"recorded"}`, i)
		doc.Cassettes = append(doc.Cassettes, tape.Cassette{
			Request:  tape.CassetteRequest{Method: "POST", Path: "/match", BodySHA256: tape.BodySHA256([]byte(body), doc.IgnoreJSONPaths)},
			Response: tape.CassetteResponse{Status: 200, Body: fmt.Sprintf("choice %d", i)},
		})
	}
	addr, p, accepts := cassetteListener(t, doc)
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			input := fmt.Sprintf(`{"request_id":"concurrent-%d","choice":%d}`, i, i%2)
			resp, err := client.Post(addr+"/match", "application/json", strings.NewReader(input))
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if resp.StatusCode != 200 || string(body) != fmt.Sprintf("choice %d", i%2) || err != nil {
				t.Errorf("request %d: status %d, body %q, read %v", i, resp.StatusCode, body, err)
			}
		}()
	}
	wg.Wait()
	if accepts.Load() != 0 || p.CassetteFailure() != nil {
		t.Fatalf("accepts=%d; cassette failure=%v", accepts.Load(), p.CassetteFailure())
	}
}

func TestReplayRedirectsStayOnTheListener(t *testing.T) {
	for _, tc := range []struct {
		name, location string
		wantStatus     int
		wantMiss       bool
	}{
		{"local hit", "next", 200, false},
		{"local miss", "/missing", 502, true},
		{"network path", "//example.invalid/next", 302, false},
		{"browser ambiguous path", "///example.invalid/next", 302, false},
		{"external", "https://example.invalid/next", 302, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := tape.Tape{Cassettes: []tape.Cassette{
				{Request: tape.CassetteRequest{Method: "GET", Path: "/start"}, Response: tape.CassetteResponse{Status: 302, Headers: map[string]string{"Location": tc.location}}},
				{Request: tape.CassetteRequest{Method: "GET", Path: "/next"}, Response: tape.CassetteResponse{Status: 200, Body: "next cassette"}},
			}}
			addr, p, accepts := cassetteListener(t, doc)
			c := http.Client{Timeout: 5 * time.Second, CheckRedirect: func(r *http.Request, _ []*http.Request) error {
				if !strings.HasPrefix(r.URL.String(), addr+"/") {
					t.Errorf("external redirect was exposed: %s", r.URL)
					return http.ErrUseLastResponse
				}
				return nil
			}}
			resp, err := c.Get(addr + "/start")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus || accepts.Load() != 0 {
				t.Fatalf("status=%d, accepts=%d", resp.StatusCode, accepts.Load())
			}
			var miss *proxy.CassetteError
			if hasMiss := errors.As(p.CassetteFailure(), &miss); hasMiss != tc.wantMiss || hasMiss && miss.Kind != "cassette_miss" {
				t.Fatalf("cassette failure: %v", p.CassetteFailure())
			}
		})
	}
}
