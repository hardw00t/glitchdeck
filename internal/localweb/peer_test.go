package localweb

import (
	"net/http/httptest"
	"testing"
)

func TestLoopbackPeer(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:1234", true}, {"[::1]:1234", true}, {"[::ffff:127.0.0.1]:1234", true},
		{"192.0.2.1:1234", false}, {"localhost:1234", false}, {"127.0.0.1", false}, {"", false},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.addr
		if got := LoopbackPeer(r); got != tc.want {
			t.Errorf("%q: got %v", tc.addr, got)
		}
	}
}
