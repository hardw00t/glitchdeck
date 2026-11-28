package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBusyDiagnosticBoundsLongIDAndRetainsCancellation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer upstream.Close()
	defer close(release)
	in, send := io.Pipe()
	out, recv := io.Pipe()
	defer send.Close()
	defer out.Close()
	done := make(chan error, 1)
	go func() { done <- NewServer(in, recv, Options{}).Serve(); recv.Close() }()
	id := strings.Repeat("x", 65536)
	enc := json.NewEncoder(send)
	if err := enc.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": "tape_run", "arguments": map[string]any{"tape_yaml": "version: 2\nscript: [{http: {path: /block}}]\n", "target": upstream.URL, "timeout_ms": 120000}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("job did not start")
	}
	batch := make([]any, 20)
	for i := range batch {
		batch[i] = map[string]any{"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": map[string]any{"name": "tape_run", "arguments": map[string]any{"tape_yaml": "version: 2\nscript: []\n"}}}
	}
	if err := enc.Encode(batch); err != nil {
		t.Fatal(err)
	}
	var replies []json.RawMessage
	if err := json.NewDecoder(out).Decode(&replies); err != nil {
		t.Fatal(err)
	}
	if len(replies) != len(batch) {
		t.Fatalf("got %d replies", len(replies))
	}
	for _, reply := range replies {
		if len(reply) > 2048 || !strings.Contains(string(reply), "BUSY") {
			t.Fatalf("unbounded or missing BUSY: %d bytes", len(reply))
		}
	}
	if err := enc.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": id}}); err != nil {
		t.Fatal(err)
	}
	send.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("full ID did not cancel job")
	}
}

func TestScannerErrorCancelsRunningJob(t *testing.T) {
	started, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
			close(cancelled)
		case <-release:
		}
	}))
	defer upstream.Close()
	defer close(release)
	in, send := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- NewServer(in, io.Discard, Options{}).Serve() }()
	_, err := fmt.Fprintf(send, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tape_run","arguments":{"tape_yaml":"version: 2\nscript: [{http: {path: /block}}]\n","target":%q,"timeout_ms":120000}}}`+"\n", upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("job did not start")
	}
	want := errors.New("input transport failed")
	send.CloseWithError(want)
	select {
	case <-cancelled:
	case <-time.After(10 * time.Second):
		t.Fatal("scanner error did not cancel job")
	}
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not return")
	}
}

func TestJobAdmissionWaitsForVisibleResponse(t *testing.T) {
	s := NewServer(nil, nil, Options{})
	s.ctx = context.Background()
	visible, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	s.startJob(json.RawMessage(`1`), "tape_run", func(context.Context) map[string]any { return map[string]any{"ok": true} }, func(any) { close(visible); <-release })
	<-visible
	admitted := make(chan bool, 1)
	go func() { _, busy := s.busyJob(); admitted <- busy }()
	select {
	case busy := <-admitted:
		if busy {
			t.Fatal("visible completed response caused spurious BUSY")
		}
	case <-time.After(100 * time.Millisecond):
	}
}

func TestCancelledJobDoesNotWaitForStderr(t *testing.T) {
	reader, writer := io.Pipe()
	old := log.Writer()
	log.SetOutput(writer)
	defer func() { reader.Close(); writer.Close(); log.SetOutput(old) }()
	s := NewServer(nil, nil, Options{})
	s.ctx = context.Background()
	started := make(chan struct{})
	done := s.startJob(json.RawMessage(`1`), "tape_run", func(ctx context.Context) map[string]any { close(started); <-ctx.Done(); return nil }, func(any) {})
	<-started
	s.cancelJob(json.RawMessage(`{"requestId":1}`))
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked stderr prevented slot cleanup")
	}
}

func TestTapeExportReturnsReusableRelativePath(t *testing.T) {
	s, proxyURL := exportTestServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	s.p.ShouldCaptureResponse = func(uint64) bool { return false }
	req, err := http.NewRequest("GET", proxyURL+"/resource", nil)
	if err != nil {
		t.Fatal(err)
	}
	exportTestRequest(t, req)
	got, _ := s.call("tape_export", []byte(`{"name":"capture","out_path":"capture.yaml"}`))
	if got["out_path"] != filepath.Join(s.opts.Workdir, "capture.yaml") || got["tape_path"] != "capture.yaml" {
		t.Fatalf("export paths: %v", got)
	}
	for _, format := range []string{"v1", "v2"} {
		args, _ := json.Marshal(map[string]string{"name": "capture", "out_path": format + ".yaml", "format": format})
		legacy, _ := s.call("tape_export", args)
		if legacy["out_path"] != filepath.Join(s.opts.Workdir, format+".yaml") || legacy["tape_path"] != format+".yaml" {
			t.Fatalf("%s export paths: %v", format, legacy)
		}
	}
	args, _ := json.Marshal(map[string]any{"command": []string{"true"}, "tape_path": got["tape_path"]})
	s.opts.AllowExec = true
	_, result, params := s.prepareExec(args)
	if result != nil || params != nil {
		t.Fatalf("exported path rejected: %v %v", result, params)
	}
	absolute, _ := json.Marshal(map[string]string{"name": "capture", "out_path": filepath.Join(s.opts.Workdir, "absolute.yaml")})
	got, _ = s.call("tape_export", absolute)
	if got["out_path"] != filepath.Join(s.opts.Workdir, "absolute.yaml") || got["tape_path"] != "absolute.yaml" {
		t.Fatalf("absolute export paths: %v", got)
	}
}
