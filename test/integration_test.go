package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/demo"
	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/tape"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
	"github.com/hardw00t/glitchdeck/internal/ui"
	"github.com/hardw00t/glitchdeck/internal/wsframe"
)

func rule(kind, path string, params map[string]any) fault.Rule {
	return fault.Rule{ID: kind, Enabled: true, Match: fault.Match{PathPrefix: path}, Fault: fault.Fault{Type: kind, Params: params}}
}

func startProxy(t *testing.T, upstream http.Handler, rules ...fault.Rule) (*httptest.Server, *proxy.Proxy, *telemetry.Bus, string) {
	t.Helper()
	u := httptest.NewServer(upstream)
	t.Cleanup(u.Close)
	target, err := url.Parse(u.URL)
	if err != nil {
		t.Fatal(err)
	}
	b := telemetry.New()
	p := proxy.New(target, fault.Config{Seed: 42, Rules: rules}, b)
	t.Cleanup(p.Close)
	s := httptest.NewServer(p)
	t.Cleanup(s.Close)
	return s, p, b, u.URL
}

var client = &http.Client{Timeout: 5 * time.Second}

func TestTCPRST(t *testing.T) {
	p, _, _, _ := startProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "4096")
		_, _ = io.WriteString(w, strings.Repeat("x", 4096))
	}), rule("tcp-rst", "/rst", map[string]any{"after_bytes": 128}))
	r, err := client.Get(p.URL + "/rst")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if len(body) > 128 || err == nil {
		t.Fatalf("read %d bytes: %v", len(body), err)
	}
}

func TestDupWebhook(t *testing.T) {
	type call struct {
		at   time.Time
		body string
	}
	calls := make(chan call, 4)
	s, p, _, _ := startProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls <- call{time.Now(), string(body)}
		w.WriteHeader(204)
	}), rule("dup-webhook", "/webhooks/payment", map[string]any{"count": 2, "delay_ms": 50}))
	r, err := client.Post(s.URL+"/webhooks/payment", "application/json", strings.NewReader(`{"payment":1}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := p.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != 204 || len(calls) != 2 {
		t.Fatalf("status=%d calls=%d", r.StatusCode, len(calls))
	}
	a, b := <-calls, <-calls
	if a.body != `{"payment":1}` || b.body != a.body || b.at.Sub(a.at) < 40*time.Millisecond {
		t.Fatalf("first=%+v replay=%+v", a, b)
	}
}

func TestByteTrickleAndRateLimit(t *testing.T) {
	calls := make(chan string, 2)
	s, _, _, _ := startProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls <- r.URL.Path
		_, _ = io.WriteString(w, "abcdefghijkl")
	}), rule("rate-limit", "/rate", map[string]any{"retry_after_sec": 1}), rule("byte-trickle", "/slow", map[string]any{"bytes_per_sec": 40, "chunk_bytes": 4, "stall_after_bytes": 4, "stall_ms": 150}))
	r, err := client.Get(s.URL + "/rate")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 429 || r.Header.Get("Retry-After") != "1" || r.Header.Get("X-Glitchdeck-Fault") != "rate-limit" || len(calls) != 0 {
		t.Fatalf("status=%d headers=%v upstream calls=%d", r.StatusCode, r.Header, len(calls))
	}
	r, err = client.Get(s.URL + "/slow")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	buf := make([]byte, 4)
	times := make([]time.Time, 3)
	var body []byte
	for i := range times {
		if _, err := io.ReadFull(r.Body, buf); err != nil {
			t.Fatal(err)
		}
		body = append(body, buf...)
		times[i] = time.Now()
	}
	if string(body) != "abcdefghijkl" || times[1].Sub(times[0]) < 200*time.Millisecond || times[2].Sub(times[1]) < 70*time.Millisecond {
		t.Fatalf("body=%q gaps=%v,%v", body, times[1].Sub(times[0]), times[2].Sub(times[1]))
	}
}

func TestWSGlitch1006AndDrop(t *testing.T) {
	for _, action := range []string{"drop", "corrupt", "close_1006"} {
		t.Run(action, func(t *testing.T) {
			s, _, b, _ := startProxy(t, demo.New(), rule("ws-glitch", "/ws/ticker", map[string]any{"dir": "s2c", "action": action, "after_frames": 2, "every": 2}))
			conn, err := net.DialTimeout("tcp", s.Listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, err = fmt.Fprintf(conn, "GET /ws/ticker HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", s.Listener.Addr())
			if err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(conn)
			r, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
			if err != nil || r.StatusCode != 101 || r.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
				t.Fatalf("upgrade=%+v err=%v", r, err)
			}
			var first, next struct{ Seq int }
			f, err := wsframe.Read(reader, false)
			if err != nil || json.Unmarshal(f.Payload, &first) != nil || first.Seq != 1 {
				t.Fatalf("first frame=%q seq=%d err=%v", f.Payload, first.Seq, err)
			}
			if action == "close_1006" {
				_, err = reader.ReadByte()
				if err == nil || !errors.Is(err, syscall.ECONNRESET) {
					t.Fatalf("expected reset without close frame, got %v", err)
				}
				return
			}
			f, err = wsframe.Read(reader, false)
			switch action {
			case "drop":
				if err != nil || json.Unmarshal(f.Payload, &next) != nil || next.Seq != 3 {
					t.Fatalf("next frame after drop=%q seq=%d err=%v", f.Payload, next.Seq, err)
				}
			case "corrupt":
				if err != nil || (json.Unmarshal(f.Payload, &next) == nil && next.Seq == 2) {
					t.Fatalf("second frame was not mutated: %q, %v", f.Payload, err)
				}
			case "close_1006":
				if e, ok := err.(net.Error); err == nil || (ok && e.Timeout()) {
					t.Fatalf("expected immediate abnormal close without a close frame; opcode=%d err=%v", f.Opcode, err)
				}
			}
			for _, e := range b.History(0) {
				var frame struct {
					Fault    string `json:"fault"`
					FrameSeq int    `json:"frame_seq"`
				}
				if e.Type == "ws_frame" && json.Unmarshal(e.Data, &frame) == nil && frame.FrameSeq == 2 && frame.Fault == action {
					return
				}
			}
			t.Fatal("missing telemetry for faulted frame #2")
		})
	}
}

func TestTCPRSTWire(t *testing.T) {
	for _, tc := range []struct {
		name    string
		params  map[string]any
		chunked bool
	}{
		{"before", map[string]any{"before_headers": true}, false},
		{"complete", map[string]any{"after_bytes": 32}, false},
		{"chunked", map[string]any{"after_bytes": 32}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _, _ := startProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.chunked {
					w.(http.Flusher).Flush()
				}
				_, _ = io.WriteString(w, "hello")
			}), rule("tcp-rst", "/", tc.params))
			c, err := net.DialTimeout("tcp", s.Listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(4 * time.Second))
			_, err = fmt.Fprintf(c, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n")
			if err != nil {
				t.Fatal(err)
			}
			if tc.name != "before" {
				_, _ = io.WriteString(c, "0123456789")
			}
			data, err := io.ReadAll(c)
			if !errors.Is(err, syscall.ECONNRESET) {
				t.Fatalf("wire %q: expected reset, got %v", data, err)
			}
			if tc.name == "before" && len(data) != 0 {
				t.Fatalf("unexpected bytes before reset: %q", data)
			}
			if tc.name != "before" && (!bytes.Contains(data, []byte("hello")) || bytes.HasSuffix(data, []byte("0\r\n\r\n"))) {
				t.Fatalf("unexpected wire: %q", data)
			}
		})
	}
}

func TestResetDropsOldGeneration(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	s, p, bus, _ := startProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, "late")
	}))
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := client.Get(s.URL)
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-started
	p.ResetWith(func() { bus.Clear() })
	close(release)
	<-done
	if got := bus.History(0); len(got) != 0 {
		t.Fatalf("old generation published: %+v", got)
	}
}

func TestStreamingFlushAndReadError(t *testing.T) {
	for _, kind := range []string{"normal", "byte-trickle"} {
		t.Run(kind, func(t *testing.T) {
			release := make(chan struct{})
			var rules []fault.Rule
			if kind == "byte-trickle" {
				rules = append(rules, rule(kind, "/", map[string]any{"bytes_per_sec": 1000, "chunk_bytes": 4}))
			}
			s, _, _, _ := startProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "20")
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "part")
				w.(http.Flusher).Flush()
				<-release
			}), rules...)
			resp, err := client.Get(s.URL)
			if err != nil {
				close(release)
				t.Fatal(err)
			}
			defer resp.Body.Close()
			got := make([]byte, 4)
			if _, err = io.ReadFull(resp.Body, got); err != nil || string(got) != "part" {
				close(release)
				t.Fatalf("first chunk %q: %v", got, err)
			}
			close(release)
			if _, err = io.ReadAll(resp.Body); err == nil {
				t.Fatal("truncated upstream succeeded")
			}
		})
	}
}

func TestResetDuringLatencyDoesNotSucceed(t *testing.T) {
	hit := make(chan struct{}, 1)
	s, p, _, _ := startProxy(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit <- struct{}{} }),
		rule("latency-wave", "/", map[string]any{"base_ms": 10000}))
	done := make(chan error, 1)
	go func() {
		resp, err := client.Get(s.URL)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode < 500 {
				err = fmt.Errorf("unexpected status %d", resp.StatusCode)
			}
		}
		done <- err
	}()
	for p.Seq() == 0 {
		time.Sleep(time.Millisecond)
	}
	p.Reset()
	if err := <-done; err == nil {
		t.Fatal("canceled latency returned success")
	}
	select {
	case <-hit:
		t.Fatal("upstream was contacted")
	default:
	}
}

func TestStreamedUploadCountOne(t *testing.T) {
	s, p, bus, _ := startProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(204)
	}), rule("dup-webhook", "/", map[string]any{"count": 1}))
	outcomes := make(chan proxy.Outcome, 1)
	p.OnOutcome = func(o proxy.Outcome) { outcomes <- o }
	req, _ := http.NewRequest("DELETE", s.URL, strings.NewReader("streamed"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	select {
	case o := <-outcomes:
		t.Fatalf("unexpected outcome: %+v", o)
	default:
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, event := range bus.History(0) {
			var record struct {
				ReqBytes int `json:"req_bytes"`
			}
			if event.Type == "http_req" && json.Unmarshal(event.Data, &record) == nil && record.ReqBytes == 8 {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("missing streamed byte count")
}

func TestStreamingHeadersFlushBeforeBody(t *testing.T) {
	release := make(chan struct{})
	s, _, _, _ := startProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		<-release
	}))
	defer close(release)
	c := &http.Client{Timeout: time.Second}
	resp, err := c.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestDelayedReplayAfterFiveSeconds(t *testing.T) {
	calls := make(chan struct{}, 2)
	s, p, _, _ := startProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls <- struct{}{}
		w.WriteHeader(204)
	}), rule("dup-webhook", "/", map[string]any{"count": 2, "delay_ms": 5100}))
	resp, err := client.Post(s.URL, "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := p.Wait(ctx); err != nil || len(calls) != 2 {
		t.Fatalf("wait=%v calls=%d", err, len(calls))
	}
}

func TestOversizeReplayPostPublishesError(t *testing.T) {
	s, p, bus, _ := startProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("oversize replay reached upstream")
	}), rule("dup-webhook", "/", map[string]any{"count": 2}))
	outcomes := make(chan proxy.Outcome, 1)
	p.OnOutcome = func(o proxy.Outcome) { outcomes <- o }
	req, _ := http.NewRequest("POST", s.URL, strings.NewReader(strings.Repeat("x", (4<<20)+1)))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", resp.StatusCode)
	}
	select {
	case o := <-outcomes:
		if o.Err == nil {
			t.Fatalf("outcome %+v", o)
		}
	case <-time.After(time.Second):
		t.Fatal("missing error outcome")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, event := range bus.History(0) {
			var record struct {
				Status int `json:"status"`
			}
			if event.Type == "http_req" && json.Unmarshal(event.Data, &record) == nil && record.Status == 413 {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("missing 413 telemetry")
}

func TestEmptyBodyResetUsesIncompleteFraming(t *testing.T) {
	s, _, _, _ := startProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "0")
	}), rule("tcp-rst", "/", map[string]any{"after_bytes": 1}))
	conn, err := net.Dial("tcp", s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
	data, err := io.ReadAll(conn)
	if !errors.Is(err, syscall.ECONNRESET) || !bytes.Contains(data, []byte("Transfer-Encoding: chunked")) || bytes.HasSuffix(data, []byte("0\r\n\r\n")) {
		t.Fatalf("wire %q, err %v", data, err)
	}
}

func TestWebSocketRejectsMultipleSelectedProtocols(t *testing.T) {
	for _, selection := range []string{"one, two", "one\r\nSec-WebSocket-Protocol: two"} {
		t.Run(selection, func(t *testing.T) {
			s, _, _, _ := startProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, b, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				_, _ = fmt.Fprintf(b, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: %s\r\n\r\n", wsframe.AcceptKey(r.Header.Get("Sec-WebSocket-Key")), selection)
				_ = b.Flush()
			}))
			req, _ := http.NewRequest("GET", s.URL, nil)
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Sec-WebSocket-Version", "13")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			req.Header.Set("Sec-WebSocket-Protocol", "one, two")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 502 {
				t.Fatalf("status %d", resp.StatusCode)
			}
		})
	}
}

func TestWebSocketInjectedResetReachesUpstream(t *testing.T) {
	result := make(chan error, 1)
	s, _, _, _ := startProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, b, err := w.(http.Hijacker).Hijack()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = fmt.Fprintf(b, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsframe.AcceptKey(r.Header.Get("Sec-WebSocket-Key")))
		_ = b.Flush()
		_ = wsframe.Write(conn, wsframe.Frame{Fin: true, Opcode: 1, Payload: []byte("x")}, false)
		_, err = b.ReadByte()
		result <- err
	}), rule("ws-glitch", "/", map[string]any{"dir": "s2c", "action": "close_1006"}))
	conn, err := net.Dial("tcp", s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	r := bufio.NewReader(conn)
	if _, err := http.ReadResponse(r, &http.Request{Method: "GET"}); err != nil {
		t.Fatal(err)
	}
	_, err = r.ReadByte()
	if !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("client: %v", err)
	}
	if err = <-result; !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("upstream: %v", err)
	}
}

func TestTapeCIRunnerDeterministic(t *testing.T) {
	for _, tc := range []struct{ name, diff string }{{"checkout-dup-webhook", "duplicate_charges: expected 0, got 1"}, {"clean", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.Open("../examples/" + tc.name + ".tape.yaml")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			tapeDoc, err := tape.Decode(f)
			if err != nil {
				t.Fatal(err)
			}
			var prior string
			for i := range 2 {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				results, err := tape.Run(ctx, tapeDoc, "")
				cancel()
				if err != nil {
					t.Fatal(err)
				}
				var diffs []string
				for _, result := range results {
					diffs = append(diffs, result.Failures...)
				}
				diff := strings.Join(diffs, "\n")
				if (tc.diff == "" && diff != "") || !strings.Contains(diff, tc.diff) || (i > 0 && prior != diff) {
					t.Fatalf("run %d diff=%q (previous %q)", i+1, diff, prior)
				}
				prior = diff
			}
		})
	}
}

func TestControlRecordsReplayableCheckout(t *testing.T) {
	s, p, b, target := startProxy(t, demo.New(), rule("dup-webhook", "/webhooks/payment", map[string]any{"count": 2, "delay_ms": 20}))
	control := httptest.NewServer(ui.New(p, b, ui.Options{Target: target, Listen: s.Listener.Addr().String(), DemoURL: target}))
	defer control.Close()
	for _, path := range []string{"/api/tape/record", "/api/demo/trigger", "/api/tape/stop"} {
		r, err := client.Post(control.URL+path, "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil || r.StatusCode != 200 {
			t.Fatalf("%s: %d %q: %v", path, r.StatusCode, body, err)
		}
	}
	r, err := client.Get(control.URL + "/api/tape/export")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	data, err := io.ReadAll(r.Body)
	if err != nil || r.StatusCode != 200 || r.Header.Get("Content-Type") != "application/x-yaml" {
		t.Fatalf("export: %d %q: %v", r.StatusCode, data, err)
	}
	doc, err := tape.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results, err := tape.Run(ctx, doc, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		for _, diff := range result.Failures {
			if diff == "duplicate_charges: expected 0, got 1" {
				return
			}
		}
	}
	t.Fatalf("exported tape did not reproduce duplicate charge: %+v", results)
}
