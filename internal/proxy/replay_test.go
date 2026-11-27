package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/h2tap"
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

func TestConcurrentReplaysCanceledBeforeAdmission(t *testing.T) {
	var deliveries atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { deliveries.Add(1) }))
	defer upstream.Close()
	p := webhookProxy(t, upstream, map[string]any{"mode": "concurrent", "count": 3})
	server, client := net.Pipe()
	defer client.Close()
	tap := h2tap.New(server)
	defer tap.Close()
	go io.Copy(io.Discard, client)
	tap.Arm(1, h2tap.Plan{Kind: "goaway", BeforeHdrs: true, CloseAfter: time.Second})
	if _, err := tap.Write([]byte{0, 0, 0, 1, 4, 0, 0, 0, 1}); err != nil {
		t.Fatal(err)
	}
	r := webhookRequest("/", "body")
	r.ProtoMajor = 2
	r.Header.Set(h2tap.StreamHeader, "3")
	r = r.WithContext(context.WithValue(r.Context(), connKey{}, ConnMeta{Tap: tap}))
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Error("refused stream did not abort")
			}
		}()
		p.ServeHTTP(httptest.NewRecorder(), r)
	}()
	settleReplays(t, p)
	stats := p.Stats()["delivery"].Replays
	rows := p.AppliedFaults()
	p.mu.Lock()
	pending := p.pending
	p.mu.Unlock()
	if deliveries.Load() != 0 || pending != 0 || stats == nil || stats.Sent != 0 || stats.Outcomes["canceled"] != 2 || len(rows) != 1 || rows[0].Count != 0 {
		t.Fatalf("deliveries=%d pending=%d replays=%+v rows=%+v", deliveries.Load(), pending, stats, rows)
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
	var barrierExpired atomic.Bool
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
			barrierExpired.Store(true)
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
	if barrierExpired.Load() || n != 5 || stats.Sent != 4 || stats.MaxSkewMS == nil || stats.Outcomes["ok"]+stats.Outcomes["conflict"] != 4 {
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

func TestReplayCapacityPreservesOriginal(t *testing.T) {
	for _, tc := range []struct {
		name, mode        string
		held, sent, drops int
	}{
		{"concurrent/one-free", "concurrent", 63, 0, 2},
		{"concurrent/none-free", "concurrent", 64, 0, 2},
		{"timeout-retry/one-free", "timeout_retry", 63, 0, 2},
		{"timeout-retry/none-free", "timeout_retry", 64, 0, 2},
		{"legacy/one-free", "", 62, 1, 1},
		{"legacy/none-free", "", 63, 0, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var deliveries atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				deliveries.Add(1)
				w.WriteHeader(http.StatusCreated)
			}))
			defer upstream.Close()
			params := map[string]any{"count": 3, "delay_ms": 0}
			if tc.mode != "" {
				params["mode"] = tc.mode
			}
			p := webhookProxy(t, upstream, params)
			p.mu.Lock()
			for range tc.held {
				p.beginPendingLocked()
				p.pending++
			}
			p.mu.Unlock()
			w := httptest.NewRecorder()
			p.ServeHTTP(w, webhookRequest("/", "body"))
			for range tc.held {
				p.finishReplay()
			}
			settleReplays(t, p)
			stats := p.Stats()["delivery"]
			if w.Code != http.StatusCreated || int(deliveries.Load()) != 1+tc.sent || stats.Applied != uint64(tc.sent) ||
				stats.SkipReasons["replay_capacity_exceeded"] != 1 || stats.Replays == nil || stats.Replays.Sent != uint64(tc.sent) ||
				stats.Replays.Outcomes["capacity_exceeded"] != uint64(tc.drops) || stats.Replays.MaxSkewMS != nil {
				t.Fatalf("status=%d deliveries=%d stats=%+v", w.Code, deliveries.Load(), stats)
			}
		})
	}
}

func TestReplayOriginalMarkerRemovedWhenEnabled(t *testing.T) {
	headers := make(chan string, 3)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Get("X-Glitchdeck-Replay")
	}))
	defer upstream.Close()
	p := webhookProxy(t, upstream, map[string]any{"count": 3, "delay_ms": 0, "replay_header": true})
	r := webhookRequest("/", "body")
	r.Header.Set("X-Glitchdeck-Replay", "spoofed")
	p.ServeHTTP(httptest.NewRecorder(), r)
	settleReplays(t, p)
	if got := <-headers; got != "" {
		t.Fatalf("original marker=%q", got)
	}
	a, b := <-headers, <-headers
	if !((a == "1" && b == "2") || (a == "2" && b == "1")) {
		t.Fatalf("replica markers=%q,%q", a, b)
	}
}

func TestAppliedFaultReplayOnlySafeCapacityReason(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	other := &fault.Rule{ID: "same", Fault: fault.Fault{Type: "sse-glitch"}}
	replay := &fault.Rule{ID: "same", Fault: fault.Fault{Type: "dup-webhook"}}
	p.countRule(p.generation, other, "applied", "")
	p.countRule(p.generation, other, "skipped", "encoding_unsupported:private")
	p.replayCapacity(p.generation, 1, replay, "concurrent", 1, 2, "", 0)
	rows := p.AppliedFaults()
	if len(rows) != 2 || rows[0].SkipReasons["replay_capacity_exceeded"] != 1 || len(rows[0].SkipReasons) != 1 || len(rows[1].SkipReasons) != 0 {
		t.Fatalf("rows=%+v", rows)
	}
}

func TestSequentialHostnameDenialAccountsForEveryCopy(t *testing.T) {
	p := New(nil, fault.Config{}, nil)
	defer p.Close()
	var outcomes atomic.Int32
	p.OnOutcome = func(Outcome) { outcomes.Add(1) }
	rule := &fault.Rule{ID: "dup", Fault: fault.Fault{Type: "dup-webhook"}}
	r := httptest.NewRequest(http.MethodPost, "http://example.invalid/", nil)
	p.sequentialReplays(r, nil, 1, p.generation, rule, map[string]any{"count": 5})
	rows := p.AppliedFaults()
	if len(rows) != 1 || rows[0].Count != 0 || rows[0].Replays.Outcomes["egress_denied"] != 4 || outcomes.Load() != 0 {
		t.Fatalf("rows=%+v tape outcomes=%d", rows, outcomes.Load())
	}
}

func TestCloseCancelsReservedRetriesDuringOriginal(t *testing.T) {
	entered := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	defer upstream.Close()
	p := webhookProxy(t, upstream, map[string]any{"mode": "timeout_retry", "count": 3})
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.ServeHTTP(httptest.NewRecorder(), webhookRequest("/", "body"))
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("original did not arrive")
	}
	p.Close()
	stats := p.Stats()["delivery"].Replays
	if stats == nil || stats.Outcomes["canceled"] != 2 {
		t.Fatalf("replays=%+v", stats)
	}
	before := p.Stats()["delivery"]
	if before.Applied != 0 {
		t.Errorf("applied immediately after Close: %+v", before)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("original did not stop")
	}
	after := p.Stats()["delivery"]
	if after.Applied != 0 || after.Replays.CommittedStatus != 0 || after.Replays.OriginalOutcome != "" {
		t.Fatalf("canceled original changed report after Close: before=%+v after=%+v", before, after)
	}
}

type gatedReplayFlush struct {
	*httptest.ResponseRecorder
	started chan struct{}
	release chan struct{}
}

func (w *gatedReplayFlush) FlushError() error {
	close(w.started)
	<-w.release
	return nil
}

func TestTimeoutRetryStartsAfterSenderFailure(t *testing.T) {
	retry := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Glitchdeck-Replay") != "" {
			retry <- struct{}{}
		}
	}))
	defer upstream.Close()
	p := webhookProxy(t, upstream, map[string]any{"mode": "timeout_retry", "count": 2, "delay_ms": 0, "replay_header": true})
	w := &gatedReplayFlush{httptest.NewRecorder(), make(chan struct{}), make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.ServeHTTP(w, webhookRequest("/", "body"))
	}()
	select {
	case <-w.started:
	case <-time.After(time.Second):
		close(w.release)
		t.Fatal("sender failure was not flushed")
	}
	select {
	case <-retry:
		close(w.release)
		t.Fatal("retry arrived before the simulated sender failure flushed")
	case <-time.After(75 * time.Millisecond):
		close(w.release)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("original request did not finish")
	}
	settleReplays(t, p)
	if w.Code != http.StatusGatewayTimeout || len(retry) != 1 {
		t.Fatalf("status=%d retries=%d", w.Code, len(retry))
	}
}
