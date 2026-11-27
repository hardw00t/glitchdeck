package demo

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDemoStreamHasDone(t *testing.T) {
	r := httptest.NewRequest("POST", "http://127.0.0.1/api/chat/stream", strings.NewReader(`{"tokens":1,"token_ms":0}`))
	w := httptest.NewRecorder()
	New().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "data: [DONE]") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}
