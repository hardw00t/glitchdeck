package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
)

type blockedResponse struct {
	*httptest.ResponseRecorder
	started chan struct{}
	release chan struct{}
}

func (w blockedResponse) Write(p []byte) (int, error) {
	close(w.started)
	<-w.release
	return w.ResponseRecorder.Write(p)
}

func TestConfigMutationDoesNotWaitForResponseReader(t *testing.T) {
	target, err := proxy.ParseTarget("http://127.0.0.1:3000")
	if err != nil {
		t.Fatal(err)
	}
	bus := telemetry.New()
	p := proxy.New(target, fault.Config{Seed: 1}, bus)
	defer p.Close()
	h := New(p, bus, Options{Target: target.String()})
	request := func(body string) *http.Request {
		r := httptest.NewRequest(http.MethodPut, "/api/faults", strings.NewReader(body))
		r.Host = "localhost"
		r.RemoteAddr = "127.0.0.1:12345"
		return r
	}
	blocked := blockedResponse{httptest.NewRecorder(), make(chan struct{}), make(chan struct{})}
	defer close(blocked.release)
	go h.ServeHTTP(blocked, request(`{"seed":2,"rules":[]}`))
	select {
	case <-blocked.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first mutation did not begin responding")
	}
	second := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(second, request(`{"seed":3,"rules":[]}`))
		close(done)
	}()
	select {
	case <-done:
		if second.Code != 200 || p.Config().Seed != 3 {
			t.Fatalf("second mutation: %d %s", second.Code, second.Body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("configuration is locked to a stalled response")
	}
}
