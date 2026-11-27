package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/fault"
)

func TestForwardRejectsNonLoopbackAndOrigin(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	for _, target := range []string{"http://" + net.IPv4(192, 0, 2, 1).String() + "/", "http://127.0.0.1/"} {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		if target == "http://127.0.0.1/" {
			r.Header.Set("Origin", "http://localhost")
		}
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s: %d", target, w.Code)
		}
	}
}
