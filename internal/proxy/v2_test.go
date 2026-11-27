package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
)

func TestForwardRejectsNonLoopbackAndOrigin(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	for _, target := range []string{"http://" + net.IPv4(192, 0, 2, 1).String() + "/", "http://127.0.0.1/"} {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		if target == "http://127.0.0.1/" {
			r.Header.Set("Origin", "http://localhost")
		}
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s: %d", target, w.Code)
		}
	}
}

func TestExplicitTargetDoesNotGrantForwardEgress(t *testing.T) {
	host := net.IPv4(192, 0, 2, 1).String()
	target, err := ParseExplicitTarget("http://" + host + ":1234")
	if err != nil {
		t.Fatal(err)
	}
	p := New(target, fault.Config{}, nil)
	defer p.Close()
	if p.allowed(host, "1234") {
		t.Fatal("target granted forward egress")
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "http://"+host+":1234/", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("forward status %d", w.Code)
	}
}

func TestCaptureBoundaryIncludesBlindTunnels(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	_, seq, _ := p.admitTunnel(true, true)
	p.CaptureBoundary(func(next uint64, active int) {
		if next != seq+1 || active != 1 {
			t.Fatalf("next=%d active=%d", next, active)
		}
	})
	p.Reset()
	p.CaptureBoundary(func(_ uint64, active int) {
		if active != 0 {
			t.Fatalf("reset left %d active tunnels", active)
		}
	})
}

func TestAppliedFaultsDistinguishReusedIDs(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	a := &fault.Rule{ID: "same", Fault: fault.Fault{Type: "rate-limit"}}
	b := &fault.Rule{ID: "same", Fault: fault.Fault{Type: "tcp-rst"}}
	p.countRule(0, a, "applied", "")
	p.countRule(0, b, "applied", "")
	p.countRule(0, b, "applied", "")
	got := p.AppliedFaults()
	if len(got) != 2 || got[0].Type != "rate-limit" || got[0].Count != 1 || got[1].Type != "tcp-rst" || got[1].Count != 2 {
		t.Fatalf("applied faults: %+v", got)
	}
	p.Reset()
	if len(p.AppliedFaults()) != 0 {
		t.Fatal("reset retained fault counters")
	}
}

func TestDrainWaitsForFinalCallbackAndStopsAdmission(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var seqs []uint64
	p.SetOptions(Options{BeforeRequest: func(seq uint64) {
		mu.Lock()
		seqs = append(seqs, seq)
		mu.Unlock()
	}})
	p.OnRequest = func(Record) { close(entered); <-release }
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "127.0.0.1"
	go func() { p.ServeHTTP(httptest.NewRecorder(), req); close(finished) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("local request never reached the callback")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if p.Drain(ctx) == nil {
		t.Fatal("drain returned before callback")
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("admission status %d", w.Code)
	}
	close(release)
	<-finished
	if err := p.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seqs) != 1 || seqs[0] != 1 {
		t.Fatalf("admission sequences %v", seqs)
	}
}
