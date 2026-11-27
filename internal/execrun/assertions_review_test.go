package execrun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/tape"
)

func TestDetachedDirectAssertionUsesPolicyDial(t *testing.T) {
	var host string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	_, port, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("ambient dial must not be used")
	}
	http.DefaultTransport = transport
	defer func() { http.DefaultTransport = original }()

	address := "localhost:" + port
	doc := tape.Tape{Version: 2, Target: "http://" + address, Assertions: []tape.Assertion{{
		Name: "direct", HTTPGet: "/", Direct: true, ExpectStatus: http.StatusNoContent,
	}}}
	result := Run(context.Background(), doc, Options{
		Command: []string{"sh", "-c", "true"}, DetachStdio: true, AllowZeroTraffic: true,
	})
	if result.Error != nil || !result.OK || host != address {
		t.Fatalf("direct assertion failed or changed Host: host=%q result=%+v", host, result)
	}
}

func TestDetachedJSONAssertionRejectsOversizedResponse(t *testing.T) {
	const max = 4 << 20
	for _, tc := range []struct {
		name        string
		body        string
		wantFailure bool
	}{
		{"at limit", `{"x":1}` + strings.Repeat(" ", max-len(`{"x":1}`)), false},
		{"truncated trailing data", `{"x":1}` + strings.Repeat(" ", max-len(`{"x":1}`)) + "!", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, tc.body)
			}))
			defer target.Close()
			doc := tape.Tape{Assertions: []tape.Assertion{{HTTPGet: "/", Direct: true, JSONEq: map[string]any{"x": 1}}}}
			result := assertions(context.Background(), doc, "", target.URL, "", nil, &assertionLimits{remaining: 64 << 10})
			if len(result) != 1 || (len(result[0].Failures) != 0) != tc.wantFailure {
				t.Fatalf("unexpected assertion result: %+v", result)
			}
		})
	}
}
