package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
)

func TestFaultCollectionAndItemMutations(t *testing.T) {
	bus := telemetry.New()
	p := proxy.New(nil, fault.Config{Seed: 7}, bus)
	defer p.Close()
	h := httptest.NewServer(New(p, bus, Options{}))
	defer h.Close()
	call := func(method, path, body string, want int) map[string]json.RawMessage {
		t.Helper()
		req, err := http.NewRequest(method, h.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "application/json")
		res, err := h.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var data map[string]json.RawMessage
		if err := json.NewDecoder(res.Body).Decode(&data); res.StatusCode != want || err != nil {
			t.Fatalf("%s %s: got %d %s (%v); want %d JSON", method, path, res.StatusCode, data, err, want)
		}
		return data
	}
	const rule = `{"id":"cut","enabled":true,"fault":{"type":"sse-glitch","params":{"action":"truncate"}}}`
	_, events, unsubscribe := bus.Subscribe()
	defer unsubscribe()
	call("POST", "/api/faults", rule, 201)
	call("POST", "/api/faults", rule, 409)
	call("PUT", "/api/faults/cut", `{"enabled":false,"fault":{"type":"sse-glitch"}}`, 200)
	got := call("GET", "/api/faults", "", 200)
	if string(got["schema_version"]) != "2" || string(got["seed"]) != "7" || !strings.Contains(string(got["rules"]), `"enabled":false`) {
		t.Fatalf("unexpected configuration: %s", got)
	}
	call("DELETE", "/api/faults/cut", "", 200)
	call("DELETE", "/api/faults/cut", "", 404)
	for range 3 {
		select {
		case e := <-events:
			if e.Type != "fault_state" {
				t.Fatalf("mutation emitted %s", e.Type)
			}
		default:
			t.Fatal("mutation did not publish state")
		}
	}
	select {
	case e := <-events:
		t.Fatalf("rejected mutation published an event: %v", e)
	default:
	}
}
