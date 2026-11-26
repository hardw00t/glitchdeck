package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"glitchdeck/internal/demo"
	"glitchdeck/internal/fault"
	"glitchdeck/internal/proxy"
	"glitchdeck/internal/tape"
	"glitchdeck/internal/telemetry"
	"glitchdeck/internal/ui"
	"glitchdeck/internal/wsframe"
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
	if len(body) > 128 || err == nil || r.ContentLength != 4096 {
		t.Fatalf("read %d of %d bytes: %v", len(body), r.ContentLength, err)
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
	}), rule("rate-limit", "/rate", map[string]any{"retry_after_sec": 1}), rule("byte-trickle", "/slow", map[string]any{"bytes_per_sec": 40, "chunk_bytes": 4}))
	r, err := client.Get(s.URL + "/rate")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 429 || r.Header.Get("Retry-After") != "1" || r.Header.Get("X-Glitchdeck-Fault") != "rate-limit" || len(calls) != 0 {
		t.Fatalf("status=%d headers=%v upstream calls=%d", r.StatusCode, r.Header, len(calls))
	}
	start := time.Now()
	r, err = client.Get(s.URL + "/slow")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil || string(body) != "abcdefghijkl" || time.Since(start) < 180*time.Millisecond {
		t.Fatalf("body=%q after %s: %v", body, time.Since(start), err)
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
