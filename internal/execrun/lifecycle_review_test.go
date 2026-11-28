package execrun

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/tape"
)

type triggeredDeadline struct {
	context.Context
	done chan struct{}
}

func (c triggeredDeadline) Done() <-chan struct{} { return c.done }
func (c triggeredDeadline) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func TestReplayMissDoesNotMaskTimeout(t *testing.T) {
	if address := os.Getenv("GD_REPLAY_TIMEOUT_SIGNAL"); address != "" {
		response, err := http.Get(os.Getenv("GLITCHDECK_PROXY_URL") + "/missing")
		if err != nil {
			os.Exit(7)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		conn, err := net.Dial("tcp", address)
		if err != nil {
			os.Exit(8)
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
		os.Exit(0)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("GD_REPLAY_TIMEOUT_SIGNAL", listener.Addr().String())
	ctx := triggeredDeadline{Context: context.Background(), done: make(chan struct{})}
	release := make(chan struct{})
	defer close(release)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			close(ctx.done)
			<-release
		}
	}()
	doc := tape.Tape{Version: 3, Target: "http://example.test", Cassettes: []tape.Cassette{{Request: tape.CassetteRequest{Method: "GET", Path: "/other"}, Response: tape.CassetteResponse{Status: 200}}}}
	result := Run(ctx, doc, Options{Mode: "replay", Command: []string{os.Args[0], "-test.run=^TestReplayMissDoesNotMaskTimeout$"}, JSON: true, AllowZeroTraffic: true})
	if result.ExitCode != 124 || !strings.Contains(strings.Join(result.Diff, " "), "cassette_miss") {
		t.Fatalf("lifecycle masked cassette failure: %+v", result)
	}
}
