package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/sse"
)

type sseCountingReader struct {
	io.Reader
	n int
}

func (r *sseCountingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.n += n
	return n, err
}

var sseLimitFixtures struct {
	sync.Once
	streams   map[string][]byte
	truncated map[string][]byte
	err       error
}

func TestSSEDecoderStopsAtLineLimit(t *testing.T) {
	sseLimitFixtures.Do(func() {
		sseLimitFixtures.streams = make(map[string][]byte)
		sseLimitFixtures.truncated = make(map[string][]byte)
		for _, name := range []string{"gzip", "zlib", "flate"} {
			for _, truncated := range []bool{false, true} {
				var b bytes.Buffer
				var w interface {
					io.WriteCloser
					Flush() error
				}
				switch name {
				case "gzip":
					w = gzip.NewWriter(&b)
				case "zlib":
					w = zlib.NewWriter(&b)
				case "flate":
					w, sseLimitFixtures.err = flate.NewWriter(&b, flate.DefaultCompression)
					if sseLimitFixtures.err != nil {
						return
					}
				}
				block, count := strings.Repeat("x", 1<<16), 512
				if truncated {
					block, count = "data: incomplete", 1
				}
				for range count {
					if _, sseLimitFixtures.err = io.WriteString(w, block); sseLimitFixtures.err != nil {
						return
					}
				}
				if truncated {
					sseLimitFixtures.err = w.Flush()
					sseLimitFixtures.truncated[name] = b.Bytes()
				} else {
					sseLimitFixtures.err = w.Close()
					sseLimitFixtures.streams[name] = b.Bytes()
				}
				if sseLimitFixtures.err != nil {
					return
				}
			}
		}
	})
	if sseLimitFixtures.err != nil {
		t.Fatal(sseLimitFixtures.err)
	}
	for _, tc := range []struct{ name, encoding string }{{"gzip", "gzip"}, {"zlib", "deflate"}, {"flate", "deflate"}} {
		for _, truncated := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/truncated=%t", tc.name, truncated), func(t *testing.T) {
				data := sseLimitFixtures.streams[tc.name]
				if truncated {
					data = sseLimitFixtures.truncated[tc.name]
				}
				src := &sseCountingReader{Reader: bytes.NewReader(data)}
				decoder := &sseDecoder{source: src, encoding: tc.encoding}
				defer decoder.Close()
				decoded := &sseCountingReader{Reader: decoder}
				_, err := sse.NewReader(decoded, 0).Next()
				if truncated {
					if err == nil || errors.Is(err, io.EOF) {
						t.Fatalf("truncated stream: got %v, want decode error", err)
					}
				} else {
					if !errors.Is(err, sse.ErrLineTooLong) {
						t.Fatalf("got %v, want line limit error", err)
					}
					if decoded.n > 1<<20+64<<10+32<<10 {
						t.Fatalf("decoded %d bytes from %d compressed bytes", decoded.n, src.n)
					}
					if src.n >= len(data) {
						t.Fatalf("read all %d compressed bytes before line limit", src.n)
					}
				}
			})
		}
	}
}

func TestDecodedLimitsStopReadingUpstream(t *testing.T) {
	for _, tc := range []struct{ path, encoding string }{{"hijack", "gzip"}, {"h2c", "gzip"}, {"zlib", "deflate"}, {"flate", "deflate"}} {
		for _, truncated := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/truncated=%t", tc.path, truncated), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
					for range 20 {
						if _, err := io.WriteString(enc, block); err != nil {
							return
						}
						if enc.Flush() != nil {
							return
						}
						w.(http.Flusher).Flush()
					}
					<-r.Context().Done()
				}))
				protos := new(http.Protocols)
				protos.SetHTTP1(tc.path != "h2c")
				protos.SetUnencryptedHTTP2(tc.path == "h2c")
				up.Config.Protocols = protos
				up.Start()
				t.Cleanup(up.Close)
				defer cancel()
				params := map[string]any{"action": "stall", "after_events": 99}
				if tc.path == "hijack" {
					params["action"] = "truncate"
				}
				p, bus := newEncodedSSEProxy(t, up.URL, encodedSSEConfig(params))
				tr := &http.Transport{Protocols: protos, DisableCompression: true}
				defer tr.CloseIdleConnections()
				client := &http.Client{Transport: tr}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+listenProxy(t, p), nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if ctx.Err() != nil {
					t.Fatal("hang")
				}
				if err != nil {
					t.Fatal(err)
				}
				_, err = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if ctx.Err() != nil {
					t.Fatal("hang")
				}
				if err == nil {
					t.Fatal("decoded failure looked like clean EOF")
				}
				select {
				case <-finished:
				case <-ctx.Done():
					t.Fatal("hang")
				}
				if err := p.Wait(ctx); err != nil {
					if ctx.Err() != nil {
						t.Fatal("hang")
					}
					t.Fatal(err)
				}
				var end map[string]any
				for _, row := range bus.History(32) {
					if row.Type == "sse_event" {
						var event map[string]any
						if err := json.Unmarshal(row.Data, &event); err != nil {
							t.Fatal(err)
						}
						if event["kind"] == "end" {
							end = event
							break
						}
					}
				}
				reason := "line_too_long"
				if truncated {
					reason = "decode_error"
				}
				if end["end"] != "upstream_error" || end["reason"] != reason {
					t.Fatalf("end: %v", end)
				}
			})
		}
	}
}
