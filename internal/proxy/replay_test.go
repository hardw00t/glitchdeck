package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
)

func TestReplayModes(t *testing.T) {
	for _, mode := range []string{"concurrent", "timeout_retry"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			arrivals := 0
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.ReadAll(r.Body)
				mu.Lock()
				arrivals++
				mu.Unlock()
				time.Sleep(20 * time.Millisecond)
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()
			target, err := ParseTarget(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			p := New(target, fault.Config{Rules: []fault.Rule{{ID: "dup", Enabled: true, Fault: fault.Fault{Type: "dup-webhook", Params: map[string]any{"mode": mode, "count": 3, "delay_ms": 0}}}}}, nil)
			p.SetOptions(Options{AllowLoopbackEgress: true})
			defer p.Close()
			w := httptest.NewRecorder()
			p.ServeHTTP(w, webhookRequest("/", "payload"))
			if mode == "timeout_retry" && w.Code != 504 {
				t.Fatalf("status %d", w.Code)
			}
			if err := p.Wait(context.Background()); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			got := arrivals
			mu.Unlock()
			if got != 3 {
				t.Fatalf("arrivals %d", got)
			}
			stats := p.Stats()["dup"].Replays
			if stats == nil || stats.Sent != 2 || stats.Outcomes["ok"] != 2 {
				t.Fatalf("stats %+v", stats)
			}
			if mode == "timeout_retry" && stats.CommittedStatus != 200 {
				t.Fatalf("stats %+v", stats)
			}
		})
	}
}

func TestConcurrentReplayCapacityIsAllOrNothing(t *testing.T) {
	var mu sync.Mutex
	arrivals := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		arrivals++
		mu.Unlock()
	}))
	defer upstream.Close()
	target, err := ParseTarget(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := New(target, fault.Config{Rules: []fault.Rule{{ID: "dup", Enabled: true, Fault: fault.Fault{Type: "dup-webhook", Params: map[string]any{"mode": "concurrent", "count": 3}}}}}, nil)
	p.SetOptions(Options{AllowLoopbackEgress: true})
	defer p.Close()
	p.mu.Lock()
	for range 63 {
		p.beginPendingLocked()
		p.pending++
	}
	p.mu.Unlock()
	w := httptest.NewRecorder()
	p.ServeHTTP(w, webhookRequest("/", "body"))
	for range 63 {
		p.finishReplay()
	}
	if err := p.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := arrivals
	mu.Unlock()
	stats := p.Stats()["dup"]
	if got != 1 || stats.Applied != 0 || stats.SkipReasons["replay_capacity_exceeded"] != 1 || stats.Replays.Outcomes["capacity_exceeded"] != 2 || stats.Replays.MaxSkewMS != nil {
		t.Fatalf("arrivals=%d stats=%+v", got, stats)
	}
}

func TestConcurrentReplaysCanceledBeforeAdmission(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	rule := &fault.Rule{ID: "dup", Fault: fault.Fault{Type: "dup-webhook"}}
	params := map[string]any{"mode": "concurrent", "count": 3}
	r := webhookRequest("/", "body")
	release, _ := p.concurrentReplays(r, []byte("body"), 1, p.generation, rule, params)
	if release == nil {
		t.Fatal("replays not admitted")
	}
	release(false)
	if err := p.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	stats := p.Stats()["dup"].Replays
	if stats == nil || stats.Sent != 0 || stats.Outcomes["canceled"] != 2 {
		t.Fatalf("replays=%+v", stats)
	}
}

func TestReplayStatusHistogramCap(t *testing.T) {
	var status atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(199 + int(status.Add(1)))
	}))
	defer upstream.Close()
	target, err := ParseTarget(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := New(target, fault.Config{}, nil)
	p.SetOptions(Options{AllowLoopbackEgress: true})
	defer p.Close()
	rule := &fault.Rule{ID: "dup", Fault: fault.Fault{Type: "dup-webhook"}}
	r := webhookRequest("/", "body")
	for i := 1; i <= 18; i++ {
		p.sendReplay(p.ctx, r, []byte("body"), 1, p.generation, rule, nil, i, nil, "", 0)
	}
	stats := p.Stats()["dup"].Replays
	if len(stats.Status) != 17 || stats.Status["other"] != 2 || stats.Sent != 18 {
		t.Fatalf("replays=%+v", stats)
	}
}

func TestTimeoutRetrySurvivesClientCancellation(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	target, err := ParseTarget(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := New(target, fault.Config{Rules: []fault.Rule{{ID: "dup", Enabled: true, Fault: fault.Fault{Type: "dup-webhook", Params: map[string]any{"mode": "timeout_retry", "count": 2, "delay_ms": 0}}}}}, nil)
	p.SetOptions(Options{AllowLoopbackEgress: true})
	defer p.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.ServeHTTP(httptest.NewRecorder(), webhookRequest("/", "body").WithContext(ctx))
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		cancel()
		close(release)
		t.Fatal("original request did not reach receiver")
	}
	cancel()
	close(release)
	<-done
	if err := p.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	default:
		t.Fatal("retry not delivered")
	}
	stats := p.Stats()["dup"].Replays
	if stats.CommittedStatus != 200 || stats.Sent != 1 {
		t.Fatalf("stats %+v", stats)
	}
}

func TestConcurrentReplaysOverlapAndRecordConflicts(t *testing.T) {
	var mu sync.Mutex
	arrivals := 0
	all := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		arrivals++
		n := arrivals
		if n == 5 {
			close(all)
		}
		mu.Unlock()
		select {
		case <-all:
		case <-time.After(time.Second):
		}
		if n > 1 {
			w.WriteHeader(http.StatusConflict)
		}
	}))
	defer upstream.Close()
	target, err := ParseTarget(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := New(target, fault.Config{Rules: []fault.Rule{{ID: "dup", Enabled: true, Fault: fault.Fault{Type: "dup-webhook", Params: map[string]any{"mode": "concurrent", "count": 5}}}}}, nil)
	p.SetOptions(Options{AllowLoopbackEgress: true})
	defer p.Close()
	p.ServeHTTP(httptest.NewRecorder(), webhookRequest("/", "body"))
	if err := p.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	n := arrivals
	mu.Unlock()
	stats := p.Stats()["dup"].Replays
	if n != 5 || stats.Sent != 4 || stats.MaxSkewMS == nil || stats.Outcomes["ok"]+stats.Outcomes["conflict"] != 4 {
		t.Fatalf("arrivals=%d stats=%+v", n, stats)
	}
}

func TestTimeoutRetryAfterOriginalTimeout(t *testing.T) {
	var mu sync.Mutex
	arrivals := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		arrivals++
		n := arrivals
		mu.Unlock()
		_, _ = io.Copy(io.Discard, r.Body)
		if n == 1 {
			<-r.Context().Done()
		}
	}))
	defer upstream.Close()
	target, err := ParseTarget(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := New(target, fault.Config{Rules: []fault.Rule{{ID: "dup", Enabled: true, Fault: fault.Fault{Type: "dup-webhook", Params: map[string]any{"mode": "timeout_retry", "count": 2, "delay_ms": 0, "replay_timeout_ms": 50}}}}}, nil)
	p.SetOptions(Options{AllowLoopbackEgress: true})
	defer p.Close()
	w := httptest.NewRecorder()
	p.ServeHTTP(w, webhookRequest("/", "body"))
	if err := p.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	stats := p.Stats()["dup"].Replays
	if w.Code != 504 || stats.OriginalOutcome != "timeout" || stats.Sent != 1 {
		t.Fatalf("status=%d stats=%+v", w.Code, stats)
	}
}

func TestTimeoutRetryRecordsTimeoutWhileDrainingOriginal(t *testing.T) {
	var mu sync.Mutex
	arrivals := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		arrivals++
		n := arrivals
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}
	}))
	defer upstream.Close()
	target, err := ParseTarget(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := New(target, fault.Config{Rules: []fault.Rule{{ID: "dup", Enabled: true, Fault: fault.Fault{Type: "dup-webhook", Params: map[string]any{"mode": "timeout_retry", "count": 2, "delay_ms": 0, "replay_timeout_ms": 50}}}}}, nil)
	p.SetOptions(Options{AllowLoopbackEgress: true})
	defer p.Close()
	p.ServeHTTP(httptest.NewRecorder(), webhookRequest("/", "body"))
	if err := p.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	stats := p.Stats()["dup"].Replays
	if stats.CommittedStatus != 200 || stats.OriginalOutcome != "timeout" || stats.Sent != 1 {
		t.Fatalf("stats %+v", stats)
	}
}
