package execrun

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/hardw00t/glitchdeck/internal/tape"
)

type startupListener struct {
	accepted chan struct{}
	closed   chan struct{}
	once     sync.Once
}

func (l *startupListener) Accept() (net.Conn, error) {
	select {
	case l.accepted <- struct{}{}:
	default:
	}
	<-l.closed
	return nil, net.ErrClosed
}
func (l *startupListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}
func (l *startupListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func TestReplayListenerWaitsForSetup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		proxyListener := &startupListener{accepted: make(chan struct{}, 1), closed: make(chan struct{})}
		targetListener := &startupListener{accepted: make(chan struct{}, 1), closed: make(chan struct{})}
		bindingUI, releaseUI, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		calls := 0
		listen := func(_, _ string) (net.Listener, error) {
			calls++
			switch calls {
			case 1:
				return proxyListener, nil
			case 2:
				return targetListener, nil
			default:
				close(bindingUI)
				<-releaseUI
				return nil, errors.New("stop after UI bind")
			}
		}
		go func() {
			defer close(done)
			Run(context.Background(), tape.Tape{Version: 3, Target: "http://example.test", Cassettes: []tape.Cassette{{Request: tape.CassetteRequest{Method: "GET", Path: "/"}, Response: tape.CassetteResponse{Status: 200}}}}, Options{Mode: "replay", UI: "127.0.0.1:12346", Command: []string{"unused"}, listen: listen})
		}()
		<-bindingUI
		synctest.Wait()
		select {
		case <-targetListener.accepted:
			t.Error("replay listener accepted before UI initialization completed")
		default:
		}
		close(releaseUI)
		<-done
	})
}
