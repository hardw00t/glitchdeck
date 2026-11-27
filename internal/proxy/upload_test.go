package proxy

import (
	"bytes"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
)

func TestLargeUploadsStream(t *testing.T) {
	payload := bytes.Repeat([]byte("abcdef"), 1<<20)
	want := sha256.Sum256(payload)
	for _, forward := range []bool{false, true} {
		for _, recording := range []bool{false, true} {
			for _, method := range []string{"POST", "PUT", "PATCH"} {
				name := method
				if forward {
					name += "/forward"
				} else {
					name += "/reverse"
				}
				if recording {
					name += "/recording"
				} else {
					name += "/plain"
				}
				t.Run(name, func(t *testing.T) {
					got := make(chan [32]byte, 1)
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						data, err := io.ReadAll(r.Body)
						if err != nil {
							t.Error(err)
						}
						got <- sha256.Sum256(data)
					}))
					defer upstream.Close()
					target, _ := url.Parse(upstream.URL)
					if forward {
						target = nil
					}
					p := New(target, fault.Config{}, nil)
					defer p.Close()
					records := make(chan Record, 1)
					if recording {
						p.OnRequest = func(r Record) { records <- r }
					}
					server := httptest.NewServer(p)
					defer server.Close()
					client := server.Client()
					dest := server.URL + "/upload"
					if forward {
						proxyURL, _ := url.Parse(server.URL)
						client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
						defer client.CloseIdleConnections()
						dest = upstream.URL + "/upload"
					}
					req, _ := http.NewRequest(method, dest, bytes.NewReader(payload))
					resp, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					defer resp.Body.Close()
					if resp.StatusCode != 200 {
						b, _ := io.ReadAll(resp.Body)
						t.Fatalf("status %d: %s", resp.StatusCode, b)
					}
					if hash := <-got; hash != want {
						t.Fatal("upstream body differs")
					}
					if recording {
						rec := <-records
						if rec.UnrecordableBody || !rec.BodyTruncated || len(rec.Body) != maxBody || !bytes.Equal(rec.Body, payload[:maxBody]) {
							t.Fatalf("capture length %d, incomplete %v, truncated %v", len(rec.Body), rec.UnrecordableBody, rec.BodyTruncated)
						}
					}
				})
			}
		}
	}
}

func TestReplayUploadOverCap(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("oversized replay reached upstream") }))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	p := New(target, fault.Config{Rules: []fault.Rule{{ID: "dup", Enabled: true, Fault: fault.Fault{Type: "dup-webhook"}}}}, nil)
	defer p.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", bytes.NewReader(make([]byte, maxBody+1)))
	r.Host = "localhost"
	p.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(strings.ToLower(w.Body.String()), "replay") {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
}

func TestRateLimitedPostRecordsPayload(t *testing.T) {
	p := New(nil, fault.Config{Rules: []fault.Rule{{ID: "limit", Enabled: true, Fault: fault.Fault{Type: "rate-limit"}}}}, nil)
	defer p.Close()
	var rec Record
	p.OnRequest = func(r Record) { rec = r }
	r := httptest.NewRequest("POST", "/", strings.NewReader("payload"))
	r.Host = "localhost"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 429 || string(rec.Body) != "payload" || rec.UnrecordableBody || rec.BodyTruncated {
		t.Fatalf("status %d, recorded body %q, incomplete %t, truncated %t", w.Code, rec.Body, rec.UnrecordableBody, rec.BodyTruncated)
	}
}

func TestUploadTrailersReachUpstream(t *testing.T) {
	for _, replay := range []bool{false, true} {
		name, calls := "streamed", 1
		var cfg fault.Config
		if replay {
			name, calls = "replayed", 2
			cfg.Rules = []fault.Rule{{ID: "dup", Enabled: true, Fault: fault.Fault{Type: "dup-webhook", Params: map[string]any{"delay_ms": 1}}}}
		}
		t.Run(name, func(t *testing.T) {
			trailers := make(chan string, calls)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				trailers <- r.Trailer.Get("X-Checksum")
			}))
			defer upstream.Close()
			target, _ := url.Parse(upstream.URL)
			p := New(target, cfg, nil)
			defer p.Close()
			server := httptest.NewServer(p)
			defer server.Close()
			req, _ := http.NewRequest("POST", server.URL, io.NopCloser(strings.NewReader("payload")))
			req.Trailer = http.Header{"X-Checksum": {"verified"}}
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			for range calls {
				select {
				case got := <-trailers:
					if got != "verified" {
						t.Fatalf("trailer = %q", got)
					}
				case <-time.After(time.Second):
					t.Fatal("missing upstream request")
				}
			}
		})
	}
}

func TestStreamedPostSSERecordPrecedesSSE(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: hello\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	p := New(target, fault.Config{}, nil)
	defer p.Close()
	order := make(chan string, 2)
	p.OnRequest = func(r Record) {
		if string(r.Body) != "payload" {
			t.Errorf("body = %q", r.Body)
		}
		order <- "request"
	}
	p.OnSSE = func(uint64) { order <- "sse" }
	server := httptest.NewServer(p)
	defer server.Close()
	resp, err := server.Client().Post(server.URL, "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	for _, want := range []string{"request", "sse"} {
		select {
		case got := <-order:
			if got != want {
				t.Fatalf("callback %q, want %q", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("callback %q did not fire while the stream was open", want)
		}
	}
}
