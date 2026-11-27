package execrun

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/tape"
)

func TestTailRetainsLastBytesAcrossWrites(t *testing.T) {
	out := tail{limit: 4}
	for _, s := range []string{"abc", "def", "ghijkl", "m"} {
		out.Write([]byte(s))
	}
	if got := out.String(); got != "jklm" || out.total != 13 {
		t.Fatalf("tail = %q, total = %d", got, out.total)
	}
}

func TestExecDetachedStdioAndDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "marker"), []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	r := Run(context.Background(), tape.Tape{Version: 2, Target: "demo"}, Options{
		Command: []string{"sh", "-c", "cat; cat marker; printf 123456789"},
		Dir:     dir, DetachStdio: true, TailBytes: 4, AllowZeroTraffic: true,
	})
	if r.Error != nil || r.Exec.StdoutTail != "6789" || r.Exec.StdoutBytes != 11 || !r.Exec.StdoutTruncated {
		t.Fatalf("unexpected result: %+v, exec: %+v", r, r.Exec)
	}
}

func TestExecRecordsWarnings(t *testing.T) {
	r := Run(context.Background(), tape.Tape{Version: 2, Target: "demo"}, Options{
		Command: []string{"sh", "-c", "true"}, DetachStdio: true, AllowZeroTraffic: true,
		TLSPassthrough: []string{"example.com"},
	})
	if len(r.Exec.Warnings) == 0 || !strings.Contains(r.Exec.Warnings[0], "tls-passthrough") {
		t.Fatalf("warnings = %v", r.Exec.Warnings)
	}
}

func TestDetachedHTTPAssertionUsesAdmittedTargetAndHidesValues(t *testing.T) {
	const secret = "sk-test-SECRET"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"state":%q,"other":%q}`, secret, secret)
	}))
	defer target.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("direct assertion used ambient HTTP proxy")
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	u, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	original := http.DefaultTransport
	override := original.(*http.Transport).Clone()
	override.Proxy = http.ProxyURL(u)
	http.DefaultTransport = override
	defer func() { http.DefaultTransport = original }()

	doc := tape.Tape{Version: 2, Target: target.URL, Assertions: []tape.Assertion{{
		Name: "private", HTTPGet: "/", Direct: true, ExpectStatus: 200,
		JSONEq: map[string]any{"state": "expected", "other": "expected"},
	}}}
	t.Setenv("NO_PROXY", secret)
	e := Run(context.Background(), doc, Options{
		Command: []string{"sh", "-c", "true"}, DetachStdio: true, AllowZeroTraffic: true,
	})
	if e.Error != nil || e.OK || len(e.Diff) != 1 || e.Diff[0] != "private: other: JSON value mismatch" {
		t.Fatalf("unexpected assertion diagnostics: %+v", e)
	}
	if strings.Contains(e.Exec.NoProxy, secret) || strings.Contains(strings.Join(e.Exec.Warnings, " "), secret) || len(e.Exec.NoProxyDropped) != 0 {
		t.Fatal("detached report exposes inherited NO_PROXY entries")
	}
}

func TestDetachedAssertionBudgetSpansChecks(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"x":2}`)
	}))
	defer target.Close()
	doc := tape.Tape{Assertions: []tape.Assertion{
		{Name: "first", HTTPGet: "/", Direct: true, JSONEq: map[string]any{"x": 1}},
		{Name: "second", HTTPGet: "/", Direct: true, JSONEq: map[string]any{"x": 1}},
	}}
	limits := &assertionLimits{remaining: len("x: JSON value mismatch")}
	got := assertions(context.Background(), doc, "", target.URL, "", nil, limits)
	if len(got) != 2 || strings.Join(got[0].Failures, "") != "x: JSON value mismatch" ||
		strings.Join(got[1].Failures, "") != "assertion diagnostics omitted" || limits.omitted != 1 {
		t.Fatalf("unbounded or lost diagnostic: %+v", got)
	}
}
