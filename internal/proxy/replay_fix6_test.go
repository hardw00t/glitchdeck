package proxy_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/tape"
	"github.com/hardw00t/glitchdeck/internal/ui"
)

func cassette(method, path string) tape.Cassette {
	return tape.Cassette{Request: tape.CassetteRequest{Method: method, Path: path}, Response: tape.CassetteResponse{Status: 200, Body: "ok"}}
}

func TestResetInterruptsPausedCassetteUpload(t *testing.T) {
	admitted := make(chan struct{}, 1)
	p := proxy.New(nil, fault.Config{}, nil)
	defer p.Close()
	c := cassette("POST", "/upload")
	p.SetOptions(proxy.Options{CassetteUpstream: (tape.Tape{Cassettes: []tape.Cassette{c, c, cassette("GET", "/next")}}).CassetteUpstream(), OnAdmission: func(_ uint64, method, _, _ string) {
		if method == "POST" {
			admitted <- struct{}{}
		}
	}})
	s := httptest.NewServer(p)
	defer s.Close()
	conn, err := net.Dial("tcp", s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nx")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-admitted:
	case <-time.After(3 * time.Second):
		t.Fatal("upload not admitted")
	}
	done := make(chan struct{})
	go func() { p.Reset(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		conn.Close()
		t.Fatal("reset blocked on paused upload")
	}
	resp, err := s.Client().Get(s.URL + "/next")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("next status %d", resp.StatusCode)
	}
}

func TestUniqueCassetteCapturesUploadOnlyDuringRecording(t *testing.T) {
	for _, recording := range []bool{false, true} {
		t.Run(fmt.Sprint(recording), func(t *testing.T) {
			p := proxy.New(nil, fault.Config{}, nil)
			defer p.Close()
			p.SetOptions(proxy.Options{CassetteUpstream: (tape.Tape{Cassettes: []tape.Cassette{cassette("POST", "/")}}).CassetteUpstream()})
			var got proxy.Record
			p.OnRequest = func(r proxy.Record) { got = r }
			p.ShouldCaptureBody = func(uint64) bool { return recording }
			req := httptest.NewRequest("POST", "/", strings.NewReader("payload"))
			req.Host = "localhost"
			w := httptest.NewRecorder()
			p.ServeHTTP(w, req)
			if w.Code != 200 {
				t.Fatalf("status %d", w.Code)
			}
			if recording && (string(got.Body) != "payload" || got.UnrecordableBody) {
				t.Fatalf("record: %+v", got)
			}
			if !recording && len(got.Body) != 0 {
				t.Fatalf("unexpected capture %q", got.Body)
			}
		})
	}
}

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("upload failed") }
func (failingBody) Close() error             { return nil }

func TestUniqueCassetteCaptureReportsReadFailureAndLimit(t *testing.T) {
	for _, tc := range []struct {
		name               string
		body               io.ReadCloser
		missing, truncated bool
	}{
		{"error", failingBody{}, true, false},
		{"limit", io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), (4<<20)+1))), true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := proxy.New(nil, fault.Config{}, nil)
			defer p.Close()
			p.SetOptions(proxy.Options{CassetteUpstream: (tape.Tape{Cassettes: []tape.Cassette{cassette("POST", "/")}}).CassetteUpstream()})
			var got proxy.Record
			p.OnRequest = func(r proxy.Record) { got = r }
			p.ShouldCaptureBody = func(uint64) bool { return true }
			req := httptest.NewRequest("POST", "/", nil)
			req.Host = "localhost"
			req.Body = tc.body
			req.ContentLength = -1
			p.ServeHTTP(httptest.NewRecorder(), req)
			if got.UnrecordableBody != tc.missing || got.BodyTruncated != tc.truncated {
				t.Fatalf("missing=%v truncated=%v", got.UnrecordableBody, got.BodyTruncated)
			}
		})
	}
}

func TestSyntheticResponsesDoNotReserveResponseSlots(t *testing.T) {
	p := proxy.New(nil, fault.Config{Rules: []fault.Rule{{ID: "limit", Enabled: true, Fault: fault.Fault{Type: "rate-limit"}}}}, nil)
	defer p.Close()
	var mu sync.Mutex
	slots, intentional := 0, 0
	p.ShouldCaptureResponse = func(uint64) bool { mu.Lock(); defer mu.Unlock(); slots++; return true }
	p.OnResponse = func(r proxy.ResponseRecord) {
		mu.Lock()
		defer mu.Unlock()
		if r.Intentional {
			intentional++
		}
	}
	var wg sync.WaitGroup
	for range 33 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("POST", "/", nil)
			req.Host = "localhost"
			p.ServeHTTP(httptest.NewRecorder(), req)
		}()
	}
	wg.Wait()
	if slots != 0 || intentional != 33 {
		t.Fatalf("slots=%d intentional=%d", slots, intentional)
	}
}

func TestRecordingUniqueCassetteExportsBody(t *testing.T) {
	p := proxy.New(nil, fault.Config{}, nil)
	defer p.Close()
	p.SetOptions(proxy.Options{CassetteUpstream: (tape.Tape{Cassettes: []tape.Cassette{cassette("POST", "/")}}).CassetteUpstream()})
	recording := ui.NewRecorder()
	recording.Start(p)
	req := httptest.NewRequest("POST", "/", strings.NewReader("payload"))
	req.Host = "localhost"
	p.ServeHTTP(httptest.NewRecorder(), req)
	recording.Stop()
	doc, err := recording.Export("test")
	if err != nil || doc.Incomplete || len(doc.Script) != 1 || doc.Script[0].HTTP.Body != "payload" || len(doc.Cassettes) != 1 {
		t.Fatalf("export=%+v err=%v", doc, err)
	}
}

type pausedBody struct {
	entered chan<- struct{}
	release <-chan struct{}
}

func (b pausedBody) Read([]byte) (int, error) { b.entered <- struct{}{}; <-b.release; return 0, io.EOF }
func (pausedBody) Close() error               { return nil }

func TestConcurrentSyntheticRecordingExportsWithoutResponseSlots(t *testing.T) {
	p := proxy.New(nil, fault.Config{Rules: []fault.Rule{{ID: "limit", Enabled: true, Match: fault.Match{Host: "localhost"}, Fault: fault.Fault{Type: "rate-limit"}}}}, nil)
	defer p.Close()
	recording := ui.NewRecorder()
	recording.Start(p)
	entered, release := make(chan struct{}, 33), make(chan struct{})
	var wg sync.WaitGroup
	for range 33 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("POST", "/", nil)
			req.Host = "localhost"
			req.Body = pausedBody{entered, release}
			req.ContentLength = -1
			p.ServeHTTP(httptest.NewRecorder(), req)
		}()
	}
	for range 33 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			close(release)
			wg.Wait()
			t.Fatal("requests did not overlap")
		}
	}
	close(release)
	wg.Wait()
	recording.Stop()
	doc, err := recording.Export("test")
	if err != nil || doc.Incomplete || doc.Version != 2 || len(doc.Script) != 33 {
		t.Fatalf("version=%d steps=%d incomplete=%v reason=%q err=%v", doc.Version, len(doc.Script), doc.Incomplete, doc.IncompleteReason, err)
	}
}
