package ui

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/tape"
)

func TestForwardDoubleSlashRecordingReplay(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "//items" {
			t.Errorf("upstream path = %q", r.URL.EscapedPath())
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	target, err := proxy.ParseExplicitTarget(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := proxy.New(target, fault.Config{}, nil)
	defer p.Close()
	recording := NewRecorder()
	p.SetOptions(proxy.Options{AllowLoopbackEgress: true})
	recording.Start(p)
	req := httptest.NewRequest(http.MethodGet, upstream.URL+"//items", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("record status = %d", w.Code)
	}
	recording.Stop()
	doc, err := recording.Export("double-slash")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Cassettes) != 1 || doc.Cassettes[0].Request.Path != "//items" {
		t.Fatalf("cassettes = %+v", doc.Cassettes)
	}
	var encoded bytes.Buffer
	if err := tape.Encode(&encoded, doc); err != nil {
		t.Fatal(err)
	}
	decoded, err := tape.Decode(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := decoded.CassetteUpstream()(httptest.NewRequest(http.MethodGet, upstream.URL+"//items", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "ok" {
		t.Fatalf("body = %q, error = %v", body, err)
	}
}
