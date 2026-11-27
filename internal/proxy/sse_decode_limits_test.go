package proxy

import (
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDecodedLimitsStopReadingUpstream(t *testing.T) {
	for _, tc := range []struct{ path, encoding string }{{"hijack", "gzip"}, {"h2c", "gzip"}, {"zlib", "deflate"}, {"flate", "deflate"}} {
		for _, truncated := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/truncated=%t", tc.path, truncated), func(t *testing.T) {
				var writes atomic.Int64
				unblock := make(chan struct{})
				finished := make(chan struct{})
				up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer close(finished)
					w.Header().Set("Content-Type", "text/event-stream")
					w.Header().Set("Content-Encoding", tc.encoding)
					var enc interface {
						io.WriteCloser
						Flush() error
					}
					switch tc.path {
					case "zlib":
						enc = zlib.NewWriter(w)
					case "flate":
						enc, _ = flate.NewWriter(w, flate.DefaultCompression)
					default:
						enc = gzip.NewWriter(w)
					}
					if truncated {
						io.WriteString(enc, "data: {\"n\":1}\n\n")
						_ = enc.Flush()
						return // No compression footer or final block.
					}
					block := strings.Repeat("x", 1<<16)
					for range 512 {
						if _, err := io.WriteString(enc, block); err != nil {
							return
						}
						writes.Add(int64(len(block)))
						if enc.Flush() != nil {
							return
						}
						w.(http.Flusher).Flush()
						if !wait(r.Context(), time.Millisecond) {
							return
						}
					}
					select {
					case <-unblock:
					case <-r.Context().Done():
					}
				}))
				protos := new(http.Protocols)
				protos.SetHTTP1(tc.path != "h2c")
				protos.SetUnencryptedHTTP2(tc.path == "h2c")
				up.Config.Protocols = protos
				up.Start()
				defer up.Close()
				defer close(unblock)
				params := map[string]any{"action": "stall", "after_events": 99}
				if tc.path == "hijack" {
					params["action"] = "truncate"
				}
				p, bus := newEncodedSSEProxy(t, up.URL, encodedSSEConfig(params))
				tr := &http.Transport{Protocols: protos, DisableCompression: true}
				defer tr.CloseIdleConnections()
				client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
				resp, err := client.Get("http://" + listenProxy(t, p))
				if err != nil {
					t.Fatal(err)
				}
				_, err = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if err == nil {
					t.Fatal("decoded failure looked like clean EOF")
				}
				end := encodedSSEEnd(t, p, bus)
				reason := "line_too_long"
				if truncated {
					reason = "decode_error"
				}
				if end["end"] != "upstream_error" || end["reason"] != reason {
					t.Fatalf("end: %v", end)
				}
				if !truncated {
					select {
					case <-finished:
					case <-time.After(time.Second):
						t.Fatalf("upstream still open after %d source bytes", writes.Load())
					}
					if writes.Load() >= 2<<20 {
						t.Fatalf("unbounded source read: %d", writes.Load())
					}
				}
			})
		}
	}
}
