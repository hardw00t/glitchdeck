package demo

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckoutChargesOnlyWhenRequested(t *testing.T) {
	h := New()
	for _, body := range []string{`{"order_id":"a","amount_cents":100}`, `{"order_id":"a","amount_cents":100,"charge":true}`, `{"order_id":"a","amount_cents":100,"charge":true}`} {
		r := httptest.NewRequest("POST", "/checkout", strings.NewReader(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("checkout: %d", w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/state", nil))
	var state struct {
		Orders     []json.RawMessage `json:"orders"`
		Charges    []json.RawMessage `json:"charges"`
		Duplicates int               `json:"duplicate_charges"`
		Total      int               `json:"total_charged_cents"`
		Broken     bool              `json:"ws_broken"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Orders) != 3 || len(state.Charges) != 2 || state.Duplicates != 1 || state.Total != 200 || state.Broken {
		t.Fatalf("state: %+v", state)
	}
}
