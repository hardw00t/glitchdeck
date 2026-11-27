package ui

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
)

func TestControlRejectsNonLoopbackPeers(t *testing.T) {
	bus := telemetry.New()
	p := proxy.New(nil, fault.Config{}, bus)
	defer p.Close()
	h := New(p, bus, Options{UI: "0.0.0.0:8081"})
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/", ""}, {"GET", "/api/wire", ""}, {"GET", "/api/tape/export", ""},
		{"PUT", "/api/faults", `{"seed":2,"rules":[]}`}, {"POST", "/api/record/start", ""},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Host = "127.0.0.1:8081"
		r.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Errorf("%s %s: got %d", tc.method, tc.path, w.Code)
		}
	}
}
