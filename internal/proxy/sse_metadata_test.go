package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/fault"
)

func TestSSERepresentationHeadersAndTrailers(t *testing.T) {
	gz := gzipSSEPayload(t, "data: {\"n\":1}\n\ndata: [DONE]\n\n")
	for _, tc := range []struct {
		name, encoding string
		match, decode  bool
	}{{"unmatched gzip", "gzip", false, false}, {"unsupported", "br", true, false}, {"transformed", "gzip", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				h := w.Header()
				h.Set("Content-Type", "text/event-stream")
				h.Set("Content-Encoding", tc.encoding)
				h.Set("Content-Digest", "sha-256=:YWJj:")
				h.Set("Repr-Digest", "sha-256=:YWJj:")
				h.Set("ETag", `"encoded"`)
				h.Set("Trailer", "Digest, X-Complete")
				w.Write(gz)
				h.Set("Digest", "SHA-256=YWJj")
				h.Set("X-Complete", "yes")
			}))
			defer up.Close()
			var cfg fault.Config
			if tc.match {
				cfg = encodedSSEConfig(map[string]any{"action": "corrupt_json", "events": []int{8}})
			}
			p, _ := newEncodedSSEProxy(t, up.URL, cfg)
			server := httptest.NewServer(p)
			defer server.Close()
			r, err := http.NewRequest(http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Accept-Encoding", tc.encoding)
			resp, err := server.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || resp.Trailer.Get("X-Complete") != "yes" {
				t.Fatalf("trailer %v, body error %v", resp.Trailer, err)
			}
			for _, header := range []string{"Content-Digest", "Repr-Digest", "ETag"} {
				if present := resp.Header.Get(header) != ""; present == tc.decode {
					t.Fatalf("wrong %s presence: %v", header, resp.Header)
				}
			}
			if (resp.Trailer.Get("Digest") != "") == tc.decode || bytes.Equal(body, gz) == tc.decode {
				t.Fatalf("incorrect representation body=%q trailers=%v", body, resp.Trailer)
			}
		})
	}
}
