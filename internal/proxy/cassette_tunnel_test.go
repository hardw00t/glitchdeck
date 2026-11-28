package proxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/fault"
)

func TestReplayHTTP2ConnectIsStickyFailure(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	p.SetOptions(Options{CassetteUpstream: func(*http.Request) (*http.Response, error) {
		t.Error("CONNECT was dispatched as an HTTP request")
		return nil, nil
	}})
	r := httptest.NewRequest("CONNECT", "example.invalid:443", nil)
	r.ProtoMajor, r.ProtoMinor = 2, 0
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	var cassetteErr *CassetteError
	if w.Code != http.StatusBadGateway || !errors.As(p.CassetteFailure(), &cassetteErr) || cassetteErr.Method != "CONNECT" {
		t.Fatalf("CONNECT status=%d, failure=%v", w.Code, p.CassetteFailure())
	}
}
