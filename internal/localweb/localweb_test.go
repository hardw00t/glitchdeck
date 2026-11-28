package localweb

import (
	"net/http/httptest"
	"testing"
)

func TestAllowedControlRequest(t *testing.T) {
	for _, tc := range []struct {
		name, method, host, origin string
		want                       bool
	}{
		{"local client", "POST", "127.0.0.1:3000", "", true},
		{"same origin", "POST", "localhost:3000", "http://localhost:3000", true},
		{"cross port", "POST", "localhost:3000", "http://localhost:8081", false},
		{"opaque origin", "POST", "localhost:3000", "null", false},
		{"origin with path", "POST", "localhost:3000", "http://localhost:3000/", false},
		{"wrong Host", "POST", "bad-" + "host", "", false},
		{"read only", "GET", "localhost:3000", "http://localhost:8081", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/api/reset", nil)
			r.Host = tc.host
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if got := Allowed(r, ""); got != tc.want {
				t.Fatalf("Allowed() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAllowedTLSOrigin(t *testing.T) {
	for _, tc := range []struct {
		origin string
		want   bool
	}{
		{"https://localhost:3000", true},
		{"http://localhost:3000", false},
		{"https://evil.example:3000", false},
	} {
		r := httptest.NewRequest("POST", "https://localhost:3000/", nil)
		r.Header.Set("Origin", tc.origin)
		if got := Allowed(r, "127.0.0.1:3000"); got != tc.want {
			t.Errorf("Origin %q: got %v, want %v", tc.origin, got, tc.want)
		}
	}
}
