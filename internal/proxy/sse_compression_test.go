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
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/sse"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
)

func encodedSSEConfig(params map[string]any) fault.Config {
	return fault.Config{Rules: []fault.Rule{{ID: "stream", Enabled: true, Fault: fault.Fault{Type: "sse-glitch", Params: params}}}}
}

func newEncodedSSEProxy(t *testing.T, upstream string, cfg fault.Config) (*Proxy, *telemetry.Bus) {
	t.Helper()
	target, err := ParseTarget(upstream)
	if err != nil {
		t.Fatal(err)
	}
	bus := telemetry.New()
	p := New(target, cfg, bus)
	t.Cleanup(p.Close)
	return p, bus
}

func encodedSSEEnd(t *testing.T, p *Proxy, bus *telemetry.Bus) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	for _, row := range bus.History(32) {
		if row.Type == "sse_event" {
			var got map[string]any
			if err := json.Unmarshal(row.Data, &got); err != nil {
				t.Fatal(err)
			}
			if got["kind"] == "end" {
				return got
			}
		}
	}
	t.Fatal("missing stream end")
	return nil
}

func TestSSEDecodeCompressed(t *testing.T) {
	for _, tc := range []struct {
		name, wire, decoded, action string
		h2c                         bool
	}{
		{"gzip corrupt", "gzip", "gzip", "corrupt_json", false},
		{"gzip reset", "gzip", "gzip", "truncate", false},
		{"gzip early eof", "gzip", "gzip", "eof_early", false},
		{"x-gzip", "x-gzip", "gzip", "corrupt_json", false},
		{"zlib", "deflate", "deflate", "corrupt_json", false},
		{"raw flate", "deflate", "deflate", "corrupt_json", false},
		{"gzip h2c", "gzip", "gzip", "corrupt_json", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.h2c && r.ProtoMajor != 2 {
					t.Errorf("upstream: %s", r.Proto)
				}
				w.Header().Set("Content-Type", "text/event-stream; charset=UTF-8")
				w.Header().Set("Content-Encoding", tc.wire)
				var enc interface {
					io.WriteCloser
					Flush() error
				}
				switch tc.name {
				case "raw flate":
					enc, _ = flate.NewWriter(w, flate.DefaultCompression)
				case "zlib":
					enc = zlib.NewWriter(w)
				default:
					enc = gzip.NewWriter(w)
				}
				defer enc.Close()
				for i := 1; i <= 7; i++ {
					if i == 7 {
						fmt.Fprint(enc, "data: [DONE]\n\n")
					} else {
						fmt.Fprintf(enc, "data: {\"choices\":[{\"delta\":{\"content\":\"token %d\"}}]}\n\n", i)
					}
					if enc.Flush() != nil {
						return
					}
					w.(http.Flusher).Flush()
					if tc.wire == "gzip" && !wait(r.Context(), 50*time.Millisecond) {
						return
					}
				}
			}))
			proto := new(http.Protocols)
			proto.SetUnencryptedHTTP2(tc.h2c)
			proto.SetHTTP1(!tc.h2c)
			up.Config.Protocols = proto
			up.Start()
			defer up.Close()
			params := map[string]any{"action": tc.action}
			if tc.action == "corrupt_json" {
				params["events"] = []int{4}
			} else {
				params["after_events"] = 3
			}
			p, bus := newEncodedSSEProxy(t, up.URL, encodedSSEConfig(params))
			endpoint := "http://" + listenProxy(t, p)
			tr := &http.Transport{Protocols: proto, DisableCompression: true}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
			resp, err := client.Get(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, readErr := io.ReadAll(resp.Body)
			if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("Content-Length") != "" || resp.Header.Get("X-Glitchdeck-Decoded") != tc.decoded || (resp.ProtoMajor == 2) != tc.h2c {
				t.Fatalf("unexpected %s %s %v", resp.Proto, resp.Status, resp.Header)
			}
			frames := strings.Split(string(body), "\n\n")
			end := encodedSSEEnd(t, p, bus)
			if p.Stats()["stream"].Applied != 1 {
				t.Fatalf("stats: %+v, end: %v", p.Stats(), end)
			}
			switch tc.action {
			case "corrupt_json":
				if readErr != nil || len(frames) != 8 || frames[6] != "data: [DONE]" || end["terminal"] != "done_marker" {
					t.Fatalf("body %q, read error %v, end %v", body, readErr, end)
				}
				for i, frame := range frames[:6] {
					if json.Valid([]byte(strings.TrimPrefix(frame, "data: "))) != (i != 3) {
						t.Fatalf("event %d: %q", i+1, frame)
					}
				}
			case "truncate":
				if !errors.Is(readErr, syscall.ECONNRESET) || len(frames) != 4 || end["end"] != "rst" {
					t.Fatalf("body %q, read error %v, end %v", body, readErr, end)
				}
			case "eof_early":
				if readErr != nil || len(frames) != 4 || frames[3] != "" || end["end"] != "eof_early" {
					t.Fatalf("body %q, read error %v, end %v", body, readErr, end)
				}
			}
		})
	}
}

func TestSSEGzipDeliversBeforeUpstreamAcknowledgment(t *testing.T) {
	ack := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		fmt.Fprint(gz, "data: {\"first\":1}\n\n")
		_ = gz.Flush()
		w.(http.Flusher).Flush()
		select {
		case <-ack:
			fmt.Fprint(gz, "data: [DONE]\n\n")
		case <-r.Context().Done():
		}
	}))
	defer up.Close()
	p, _ := newEncodedSSEProxy(t, up.URL, encodedSSEConfig(map[string]any{"action": "drop", "events": []int{9}}))
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + listenProxy(t, p))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	r := sse.NewReader(resp.Body, 0)
	f, err := r.Next()
	if err != nil || f.Data != `{"first":1}` {
		t.Fatalf("first event before upstream acknowledgment: %q %v", f.Data, err)
	}
	close(ack)
	f, err = r.Next()
	if err != nil || f.Data != "[DONE]" {
		t.Fatalf("frame after acknowledgment: %q %v", f.Data, err)
	}
}

func gzipSSEPayload(t *testing.T, raw string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := io.WriteString(gz, raw); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestSSEEncodedPassthroughAndWarning(t *testing.T) {
	gz := gzipSSEPayload(t, "data: [DONE]\n\n")
	br := []byte{0x8b, 0x02, 0x80, 0x00, 0x4f, 0x00, 0xff}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encoding, data := "gzip", gz
		if r.URL.Path != "/gzip" {
			encoding, data = strings.TrimPrefix(r.URL.Path, "/"), br
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", encoding)
		w.Write(data)
	}))
	defer up.Close()
	cfg := encodedSSEConfig(map[string]any{"action": "truncate"})
	cfg.Rules[0].Match.PathPrefix = "/b"
	p, bus := newEncodedSSEProxy(t, up.URL, cfg)
	logFile, err := os.Create(filepath.Join(t.TempDir(), "warnings"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	original := os.Stderr
	os.Stderr = logFile
	defer func() { os.Stderr = original }()
	endpoint := "http://" + listenProxy(t, p)
	tr := &http.Transport{DisableCompression: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	for _, enc := range []string{"gzip", "br", "br", "b-other"} {
		resp, err := client.Get(endpoint + "/" + enc)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		want := br
		if enc == "gzip" {
			want = gz
			if end := encodedSSEEnd(t, p, bus); end["encoding"] != "gzip" || end["inspected"] != false {
				t.Fatalf("end: %v", end)
			}
		}
		if err != nil || !bytes.Equal(body, want) || resp.Header.Get("Content-Encoding") != enc || resp.ContentLength != int64(len(want)) {
			t.Fatalf("%s response %v %x %v", enc, resp.Header, body, err)
		}
	}
	stats := p.Stats()["stream"]
	if stats.Matched != 3 || stats.Applied != 0 || stats.Skipped != 3 || stats.SkipReasons["encoding_unsupported:br"] != 2 || stats.SkipReasons["encoding_unsupported:b-other"] != 1 {
		t.Fatalf("stats: %+v", stats)
	}
	for i := range 32 {
		p.skipUnsupportedSSE(0, &cfg.Rules[0], fmt.Sprintf("b-%d", i))
	}
	stats = p.Stats()["stream"]
	if len(stats.SkipReasons) > 17 || stats.SkipReasons["encoding_unsupported:other"] == 0 || stats.Skipped != 35 {
		t.Fatalf("unsupported encoding cardinality is not bounded: %+v", stats)
	}
	log, err := os.ReadFile(logFile.Name())
	if err != nil || string(log) != "rule stream: SSE fault skipped, upstream Content-Encoding br is not decodable (stdlib supports gzip/deflate)\n" {
		t.Fatalf("warning %q: %v", log, err)
	}
}

func TestSSEGzipDecodeErrorsAndExpansionLimit(t *testing.T) {
	broken := gzipSSEPayload(t, "data: {\"event\":1}\n\n")
	broken[len(broken)-8] ^= 1
	line := gzipSSEPayload(t, strings.Repeat("x", 1<<20+1))
	frame := gzipSSEPayload(t, strings.Repeat("data: "+strings.Repeat("x", (1<<20)-16)+"\n", 5))
	lines := gzipSSEPayload(t, strings.Repeat(":\n", 1<<17)+"\n")
	for _, tc := range []struct {
		name, end, reason string
		member            []byte
		repeat            int
	}{
		{"header", "upstream_error", "decode_error", []byte("not gzip"), 1},
		{"checksum", "upstream_error", "decode_error", broken, 1},
		{"line bomb", "upstream_error", "line_too_long", line, 1024},
		{"frame bomb", "upstream_error", "line_too_long", frame, 256},
		{"metadata limit", "upstream_error", "line_too_long", lines, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Content-Encoding", "gzip")
				for range tc.repeat {
					if _, err := w.Write(tc.member); err != nil {
						return
					}
				}
			}))
			defer up.Close()
			p, bus := newEncodedSSEProxy(t, up.URL, encodedSSEConfig(map[string]any{"action": "corrupt_json", "events": []int{4}}))
			client := &http.Client{Timeout: 3 * time.Second}
			resp, err := client.Get("http://" + listenProxy(t, p))
			if err != nil {
				t.Fatal(err)
			}
			n, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<20+1))
			resp.Body.Close()
			end := encodedSSEEnd(t, p, bus)
			if readErr == nil || n > 4<<20 || end["end"] != tc.end || p.Stats()["stream"].SkipReasons[tc.reason] != 1 {
				t.Fatalf("relayed %d bytes; read error %v; end %v; stats %v", n, readErr, end, p.Stats())
			}
		})
	}
}

func TestSSEDecoderClosesAfterMalformedHeader(t *testing.T) {
	for _, encoding := range []string{"gzip", "deflate"} {
		t.Run(encoding, func(t *testing.T) {
			d := &sseDecoder{source: strings.NewReader("not compressed"), encoding: encoding}
			var b [64]byte
			if _, err := d.Read(b[:]); err == nil {
				t.Fatal("malformed data decoded")
			}
			_ = d.Close()
		})
	}
}
