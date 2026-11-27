package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
)

func webhookRequest(path, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Host = "localhost"
	return r
}

func webhookProxy(t *testing.T, upstream *httptest.Server, params map[string]any) *Proxy {
	t.Helper()
	target, err := ParseTarget(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := New(target, fault.Config{Rules: []fault.Rule{{ID: "delivery", Enabled: true, Fault: fault.Fault{Type: "dup-webhook", Params: params}}}}, nil)
	p.SetOptions(Options{AllowLoopbackEgress: true})
	t.Cleanup(p.Close)
	return p
}

func settleReplays(t *testing.T, p *Proxy) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentWebhookRaceAndSkew(t *testing.T) {
	var skews []int64
	doubled := 0
	var largestArrivalSpread time.Duration
	for range 20 {
		var mu sync.Mutex
		var first, last time.Time
		inserts := 0
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			now := time.Now()
			if first.IsZero() {
				first = now
			}
			last = now
			seen := inserts != 0
			mu.Unlock()
			if !seen {
				// Model a check and an insert that are individually safe but not atomic together.
				time.Sleep(20 * time.Millisecond)
				mu.Lock()
				inserts++
				mu.Unlock()
			}
		}))
		p := webhookProxy(t, upstream, map[string]any{"mode": "concurrent", "count": 5})
		w := httptest.NewRecorder()
		p.ServeHTTP(w, webhookRequest("/", "event"))
		settleReplays(t, p)
		p.Close()
		upstream.Close()
		stats := p.Stats()["delivery"].Replays
		if w.Code != 200 || stats == nil || stats.Sent != 4 || stats.MaxSkewMS == nil {
			t.Fatalf("status=%d replays=%+v", w.Code, stats)
		}
		skews = append(skews, *stats.MaxSkewMS)
		mu.Lock()
		if inserts >= 2 {
			doubled++
		}
		largestArrivalSpread = max(largestArrivalSpread, last.Sub(first))
		mu.Unlock()
	}
	slices.Sort(skews)
	p95 := skews[18]
	t.Logf("double-inserts=%d/20 p95 start delta=%dms max arrival spread=%s", doubled, p95, largestArrivalSpread)
	if doubled != 20 || p95 > 25 || largestArrivalSpread > 50*time.Millisecond {
		t.Fatal("concurrent delivery missed the overlap or exceeded the skew bound")
	}
}

func TestWebhookLockedReceiverReportsConflicts(t *testing.T) {
	var inserts atomic.Int32
	committed := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Glitchdeck-Replay") != "" {
			<-committed
		}
		if !inserts.CompareAndSwap(0, 1) {
			w.WriteHeader(http.StatusConflict)
			return
		}
		close(committed)
	}))
	defer upstream.Close()
	p := webhookProxy(t, upstream, map[string]any{"mode": "concurrent", "count": 5, "replay_header": true})
	w := httptest.NewRecorder()
	p.ServeHTTP(w, webhookRequest("/", "event"))
	settleReplays(t, p)
	stats := p.Stats()["delivery"].Replays
	if w.Code != 200 || inserts.Load() != 1 || stats == nil || stats.Sent != 4 || stats.Status["409"] != 4 || stats.Outcomes["conflict"] != 4 {
		t.Fatalf("status=%d inserts=%d replays=%+v", w.Code, inserts.Load(), stats)
	}
}

func TestDefaultWebhookStaggersWithoutOverlap(t *testing.T) {
	var mu sync.Mutex
	var headers []string
	var inHandler, peak atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inHandler.Add(1)
		defer inHandler.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		mu.Lock()
		headers = append(headers, r.Header.Get("X-Glitchdeck-Replay"))
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}))
	defer upstream.Close()
	p := webhookProxy(t, upstream, map[string]any{"count": 5, "delay_ms": 70, "replay_header": true})
	w := httptest.NewRecorder()
	p.ServeHTTP(w, webhookRequest("/", "event"))
	settleReplays(t, p)
	mu.Lock()
	defer mu.Unlock()
	if w.Code != 200 || !slices.Equal(headers, []string{"", "1", "2", "3", "4"}) || peak.Load() != 1 {
		t.Fatalf("status=%d replay headers=%q peak=%d", w.Code, headers, peak.Load())
	}
}

func TestWebhookCapacityWithHundredSenders(t *testing.T) {
	const originals = 100
	var sentOriginal atomic.Int64
	var peak atomic.Int64
	allOriginals, release := make(chan struct{}), make(chan struct{})
	var p *Proxy
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		pending := int64(p.pending)
		p.mu.Unlock()
		for old := peak.Load(); pending > old && !peak.CompareAndSwap(old, pending); old = peak.Load() {
		}
		if r.Header.Get("X-Glitchdeck-Replay") == "" && sentOriginal.Add(1) == originals {
			close(allOriginals)
		}
		<-release
	}))
	defer upstream.Close()
	p = webhookProxy(t, upstream, map[string]any{"mode": "concurrent", "count": 3, "replay_header": true})
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	oldStderr := os.Stderr
	os.Stderr = writer
	defer func() { os.Stderr = oldStderr; writer.Close() }()
	var wg sync.WaitGroup
	var failures atomic.Int32
	for range originals {
		wg.Go(func() {
			w := httptest.NewRecorder()
			p.ServeHTTP(w, webhookRequest("/", "event"))
			if w.Code != http.StatusOK {
				failures.Add(1)
			}
		})
	}
	select {
	case <-allOriginals:
	case <-time.After(5 * time.Second):
		t.Error("originals were not all delivered")
	}
	close(release)
	wg.Wait()
	settleReplays(t, p)
	writer.Close()
	warnings, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	stats := p.Stats()["delivery"]
	if stats.Replays == nil {
		t.Fatal("missing replay stats")
	}
	replays := stats.Replays
	dropped := replays.Outcomes["capacity_exceeded"]
	t.Logf("originals=%d peak pending=%d sent=%d replay_capacity_exceeded=%d dropped=%d", sentOriginal.Load(), peak.Load(), replays.Sent, stats.SkipReasons["replay_capacity_exceeded"], dropped)
	if sentOriginal.Load() != originals || failures.Load() != 0 || peak.Load() > 64 || dropped == 0 || replays.Sent+dropped != 2*originals ||
		stats.SkipReasons["replay_capacity_exceeded"]*2 != dropped || strings.Count(string(warnings), "webhook replay capacity exceeded") != 1 {
		t.Fatalf("failures=%d stats=%+v replays=%+v stderr=%q", failures.Load(), stats, replays, warnings)
	}
}

func TestWebhookCloseReleasesReplicas(t *testing.T) {
	baseline := runtime.NumGoroutine()
	entered := make(chan struct{}, 5)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		entered <- struct{}{}
		<-r.Context().Done()
	}))
	defer upstream.Close()
	p := webhookProxy(t, upstream, map[string]any{"mode": "concurrent", "count": 5})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.ServeHTTP(httptest.NewRecorder(), webhookRequest("/", "event").WithContext(ctx))
	}()
	for i := range 5 {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatalf("arrival %d not delivered", i+1)
		}
	}
	p.Close()
	cancel()
	settleReplays(t, p)
	<-done
	upstream.Close()
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline {
		t.Fatalf("goroutines=%d baseline=%d", got, baseline)
	}
}

func TestReplayDialDoesNotReuseReverseTargetException(t *testing.T) {
	for _, mode := range []string{"sequential", "concurrent", "timeout_retry"} {
		t.Run(mode, func(t *testing.T) {
			var deliveries atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				deliveries.Add(1)
			}))
			defer upstream.Close()
			params := map[string]any{"mode": mode, "count": 3, "delay_ms": 0}
			p := webhookProxy(t, upstream, params)
			p.SetOptions(Options{})
			req := webhookRequest("/", "event")
			req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.IPv4zero}))
			w := httptest.NewRecorder()
			p.ServeHTTP(w, req)
			settleReplays(t, p)
			stats := p.Stats()["delivery"].Replays
			want := http.StatusOK
			if mode == "timeout_retry" {
				want = http.StatusGatewayTimeout
			}
			if w.Code != want || deliveries.Load() != 1 || stats == nil || stats.Outcomes["egress_denied"] != 2 {
				t.Fatalf("status=%d upstream deliveries=%d replays=%+v", w.Code, deliveries.Load(), stats)
			}
		})
	}
}

func TestTimeoutRetrySurvivesWireHangup(t *testing.T) {
	const delay = 40 * time.Millisecond
	entered := make(chan struct{}, 1)
	committed, retry := make(chan time.Time, 1), make(chan time.Time, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.Header.Get("X-Glitchdeck-Replay") != "" {
			retry <- time.Now()
			return
		}
		entered <- struct{}{}
		select {
		case <-time.After(300 * time.Millisecond):
			committed <- time.Now()
		case <-r.Context().Done():
		}
	}))
	defer upstream.Close()
	p := webhookProxy(t, upstream, map[string]any{"mode": "timeout_retry", "count": 2, "delay_ms": 40, "replay_header": true})
	server := httptest.NewServer(p)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, strings.NewReader("event"))
	if err != nil {
		t.Fatal(err)
	}
	clientDone := make(chan error, 1)
	go func() {
		resp, err := server.Client().Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		clientDone <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("original did not reach receiver")
	}
	time.Sleep(100 * time.Millisecond)
	cancel()
	if err := <-clientDone; err == nil {
		t.Fatal("client did not hang up before the commit")
	}
	start := time.Time{}
	select {
	case start = <-committed:
	case <-time.After(time.Second):
		t.Fatal("receiver did not commit after client hangup")
	}
	select {
	case got := <-retry:
		if got.Sub(start) < delay {
			t.Fatalf("retry arrived %s after commit, want at least %s", got.Sub(start), delay)
		}
	case <-time.After(time.Second):
		t.Fatal("retry did not arrive after client hangup")
	}
	settleReplays(t, p)
	stats := p.Stats()["delivery"].Replays
	if stats == nil || stats.CommittedStatus != 200 || stats.Sent != 1 || len(retry) != 0 {
		t.Fatalf("replays=%+v extra retries=%d", stats, len(retry))
	}
}

func TestFrameErrorReportBound(t *testing.T) {
	var log FrameErrorLog
	for seq := uint64(1); seq <= 65; seq++ {
		log.Observe(Outcome{Seq: seq, Err: &FrameError{Code: "protocol_error"}})
	}
	entries, omitted := log.Snapshot()
	if len(entries) != 64 || omitted != 1 || entries[0].Seq != 1 || entries[63].Seq != 64 {
		t.Fatalf("retained=%d omitted=%d", len(entries), omitted)
	}
	log.Reset()
	if entries, omitted := log.Snapshot(); len(entries) != 0 || omitted != 0 {
		t.Fatalf("after reset: retained=%d omitted=%d", len(entries), omitted)
	}
}

func TestReplayStatsKeepModesSeparateAcrossConfigurationChanges(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/concurrent" {
			w.WriteHeader(http.StatusConflict)
		}
	}))
	defer upstream.Close()
	p := webhookProxy(t, upstream, map[string]any{"delay_ms": 0, "count": 2})
	p.ServeHTTP(httptest.NewRecorder(), webhookRequest("/", "event"))
	settleReplays(t, p)
	p.SetConfig(fault.Config{Rules: []fault.Rule{{ID: "delivery", Enabled: true, Fault: fault.Fault{
		Type: "dup-webhook", Params: map[string]any{"mode": "concurrent", "count": 3},
	}}}})
	p.ServeHTTP(httptest.NewRecorder(), webhookRequest("/concurrent", "event"))
	settleReplays(t, p)
	faults := p.AppliedFaults()
	if len(faults) != 1 || faults[0].Count != 2 {
		t.Fatalf("fault counts: %+v", faults)
	}
	stats := faults[0].Replays
	if stats == nil || stats.Sent != 3 || stats.Status["200"] != 1 || stats.Status["409"] != 2 || stats.MaxSkewMS != nil ||
		stats.ByMode["sequential"] == nil || stats.ByMode["sequential"].Status["200"] != 1 ||
		stats.ByMode["concurrent"] == nil || stats.ByMode["concurrent"].Status["409"] != 2 || stats.ByMode["concurrent"].MaxSkewMS == nil {
		t.Fatalf("mixed replay stats: %+v", stats)
	}
	stats.ByMode["concurrent"].Status["409"] = 99
	if p.Stats()["delivery"].Replays.ByMode["concurrent"].Status["409"] != 2 {
		t.Fatal("snapshot mutated live telemetry")
	}
}
