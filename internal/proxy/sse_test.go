package proxy

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
)

func TestRelayDropsSelectedEventsAndPreservesDone(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	w := httptest.NewRecorder()
	rule := &fault.Rule{ID: "drop", Fault: fault.Fault{Type: "sse-glitch", Params: map[string]any{"action": "drop", "events": []int{2, 3}}}}
	result := p.relaySSE(context.Background(), w, strings.NewReader("data: 1\n\ndata: 2\n\ndata: [DONE]\n\n"), rule, 1, 1, 0, time.Now(), "")
	if result.err != nil || w.Body.String() != "data: 1\n\ndata: [DONE]\n\n" {
		t.Fatalf("%q %v", w.Body.String(), result.err)
	}
}
