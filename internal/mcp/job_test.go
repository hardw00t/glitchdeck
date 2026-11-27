package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestJobPanicRespondsAndReleasesSlot(t *testing.T) {
	s := NewServer(nil, nil, Options{})
	s.ctx = context.Background()
	replies := make(chan any, 1)
	write := func(v any) { replies <- v }
	done := s.startJob(json.RawMessage(`1`), "exec_run", func(context.Context) map[string]any { panic("job failure") }, write)
	select {
	case raw := <-replies:
		reply := raw.(map[string]any)
		if e, ok := reply["error"].(map[string]any); !ok || e["code"] != -32603 {
			t.Fatalf("unexpected panic response: %v", reply)
		}
	case <-time.After(time.Second):
		t.Fatal("panic did not reply")
	}
	<-done
	if _, busy := s.busyJob(); busy {
		t.Fatal("panic left the slot busy")
	}
}

func TestJobKeepsSlotUntilResponseWritten(t *testing.T) {
	s := NewServer(nil, nil, Options{})
	s.ctx = context.Background()
	writing, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	s.startJob(json.RawMessage(`1`), "tape_run", func(context.Context) map[string]any {
		return map[string]any{"ok": true}
	}, func(any) {
		close(writing)
		<-release
	})
	select {
	case <-writing:
	case <-time.After(time.Second):
		t.Fatal("job did not reach the writer")
	}
	admitted := make(chan bool, 1)
	go func() { _, busy := s.busyJob(); admitted <- busy }()
	select {
	case busy := <-admitted:
		t.Fatalf("admission returned before response completed: busy=%v", busy)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case busy := <-admitted:
		if busy {
			t.Fatal("completed response left slot busy")
		}
	case <-time.After(time.Second):
		t.Fatal("admission did not resume")
	}
}

func TestTapeRunCancellation(t *testing.T) {
	started, cancelled := make(chan struct{}), make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(cancelled)
	}))
	defer upstream.Close()
	requests, send := io.Pipe()
	receive, responses := io.Pipe()
	defer receive.Close()
	defer send.Close()
	done := make(chan error, 1)
	go func() {
		done <- NewServer(requests, responses, Options{}).Serve()
		responses.Close()
	}()
	input := json.NewEncoder(send)
	output := json.NewDecoder(receive)
	await := func(ch <-chan struct{}) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Fatal("tape request did not reach expected state")
		}
	}
	write := func(raw string) {
		t.Helper()
		if err := input.Encode(json.RawMessage(raw)); err != nil {
			t.Fatal(err)
		}
	}
	write(fmt.Sprintf(`{"jsonrpc":"2.0","id":"\u0037","method":"tools/call","params":{"name":"tape_run","arguments":{"tape_yaml":"version: 2\nscript: [{http: {path: /block}}]\n","target":%q,"timeout_ms":5000}}}`, upstream.URL))
	await(started)
	write(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}`)
	write(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"7"}}`)
	write(`{"jsonrpc":"2.0","id":8,"method":"ping"}`)
	var r execReply
	if err := output.Decode(&r); err != nil || string(r.ID) != "8" || r.Error != nil {
		t.Fatalf("ping response: %+v (%v)", r, err)
	}
	await(cancelled)
	if err := send.Close(); err != nil {
		t.Fatal(err)
	}
	if err := output.Decode(&r); err != io.EOF {
		t.Fatalf("cancelled tape sent a response: %+v (%v)", r, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
