package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
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
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}))
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
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}))
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
			records := make(chan Record, 1)
			p.OnRequest = func(r Record) { records <- r }
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
			if rec := <-records; !rec.HasTrailers {
				t.Fatal("trailer-bearing request recorded as replayable")
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

func TestRateLimitedGRPCDoesNotReadUpload(t *testing.T) {
	p := New(nil, fault.Config{Rules: []fault.Rule{{ID: "limit", Enabled: true, Fault: fault.Fault{Type: "rate-limit"}}}}, nil)
	defer p.Close()
	records := make(chan Record, 1)
	p.OnRequest = func(r Record) { records <- r }
	reader, writer := io.Pipe()
	defer writer.Close()
	r := httptest.NewRequest("POST", "/", reader)
	r.Host = "localhost"
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}))
	r.ProtoMajor = 2
	r.Header.Set("Content-Type", "application/grpc")
	done := make(chan struct{})
	w := httptest.NewRecorder()
	go func() { p.ServeHTTP(w, r); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("rate limit waited for the upload")
	}
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limit status = %d", w.Code)
	}
	select {
	case rec := <-records:
		if !rec.UnrecordableBody {
			t.Fatal("unread upload was recorded as complete")
		}
	default:
		t.Fatal("rate-limited request was not recorded")
	}
}

func TestBodylessLatencyCancellationRecordsRequest(t *testing.T) {
	p := New(nil, fault.Config{Rules: []fault.Rule{{ID: "delay", Enabled: true, Fault: fault.Fault{Type: "latency-wave", Params: map[string]any{"base_ms": 10000}}}}}, nil)
	defer p.Close()
	records := make(chan Record, 1)
	p.OnRequest = func(r Record) { records <- r }
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}))
	cancel()
	r := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	r.Host = "localhost"
	func() {
		defer func() { _ = recover() }()
		p.ServeHTTP(httptest.NewRecorder(), r)
	}()
	select {
	case <-records:
	default:
		t.Fatal("bodyless request was not recorded")
	}
}

func TestSSEUploadRecordedWhileResponseOpen(t *testing.T) {
	received := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = http.NewResponseController(w).EnableFullDuplex()
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		_, _ = io.Copy(io.Discard, r.Body)
		close(received)
		<-r.Context().Done()
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	p := New(target, fault.Config{}, nil)
	defer p.Close()
	records := make(chan Record, 1)
	sse := make(chan struct{}, 1)
	p.OnRequest = func(r Record) { records <- r }
	p.OnSSE = func(uint64) { sse <- struct{}{} }
	server := httptest.NewServer(p)
	defer server.Close()
	reader, writer := io.Pipe()
	req, _ := http.NewRequest("POST", server.URL, reader)
	client := server.Client()
	client.Timeout = 3 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.WriteString(writer, "payload")
	_ = writer.Close()
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("upload did not finish")
	}
	select {
	case rec := <-records:
		if string(rec.Body) != "payload" || rec.UnrecordableBody || !rec.SSE {
			t.Fatalf("record = %+v", rec)
		}
	case <-time.After(time.Second):
		t.Fatal("request not recorded while SSE open")
	}
	select {
	case <-sse:
	case <-time.After(time.Second):
		t.Fatal("SSE not classified")
	}
}

type uploadReadError struct{}

func (uploadReadError) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestFailedUploadRecordsErrorBeforeSSEResponseEnds(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = http.NewResponseController(w).EnableFullDuplex()
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	p := New(target, fault.Config{}, nil)
	defer p.Close()
	records := make(chan Record, 1)
	p.OnRequest = func(r Record) { records <- r }
	reader, writer := io.Pipe()
	defer writer.Close()
	r := httptest.NewRequest("POST", "/", io.MultiReader(reader, uploadReadError{}))
	r.Host = "localhost"
	ctx, cancel := context.WithCancel(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}))
	defer cancel()
	r = r.WithContext(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = recover() }()
		p.ServeHTTP(httptest.NewRecorder(), r)
	}()
	go func() {
		_, _ = io.WriteString(writer, "payload")
		_ = writer.Close()
	}()
	select {
	case rec := <-records:
		if !rec.UnrecordableBody || string(rec.Body) != "payload" {
			t.Fatalf("record = %+v", rec)
		}
	case <-time.After(time.Second):
		t.Fatal("failed upload was not recorded")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("request handler did not stop")
	}
}

func TestDialFailureRespondsBeforeContinueBody(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse("http://" + listener.Addr().String())
	listener.Close()
	p := New(target, fault.Config{}, nil)
	defer p.Close()
	server := httptest.NewServer(p)
	defer server.Close()
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, _ = fmt.Fprint(conn, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\nExpect: 100-continue\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestUploadInspectorBytesAndPreview(t *testing.T) {
	for _, limited := range []bool{false, true} {
		t.Run(fmt.Sprint(limited), func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
			}))
			defer upstream.Close()
			target, _ := url.Parse(upstream.URL)
			var cfg fault.Config
			if limited {
				cfg.Rules = []fault.Rule{{ID: "limit", Enabled: true, Fault: fault.Fault{Type: "rate-limit"}}}
			}
			bus := telemetry.New()
			p := New(target, cfg, bus)
			defer p.Close()
			if limited {
				p.OnRequest = func(Record) {}
			}
			server := httptest.NewServer(p)
			defer server.Close()
			resp, err := server.Client().Post(server.URL, "text/plain", strings.NewReader("payload"))
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := p.Wait(ctx); err != nil {
				t.Fatal(err)
			}
			for _, event := range bus.History(10) {
				if event.Type != "http_req" {
					continue
				}
				var row struct {
					Bytes   int    `json:"req_bytes"`
					Preview string `json:"body_snippet"`
				}
				if err := json.Unmarshal(event.Data, &row); err != nil {
					t.Fatal(err)
				}
				if row.Bytes != 7 || row.Preview != "payload" {
					t.Fatalf("event = %+v", row)
				}
				return
			}
			t.Fatal("missing request event")
		})
	}
}
