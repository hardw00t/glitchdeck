package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
)

type replayTiming struct {
	mu          sync.Mutex
	first, last time.Time
	p           *Proxy
	gen         uint64
	id          string
	applied     sync.Once
}

func (t *replayTiming) start() {
	now := time.Now()
	t.mu.Lock()
	if t.first.IsZero() || now.Before(t.first) {
		t.first = now
	}
	if now.After(t.last) {
		t.last = now
	}
	t.mu.Unlock()
}
func (t *replayTiming) record() {
	t.mu.Lock()
	skew := t.last.Sub(t.first).Milliseconds()
	t.mu.Unlock()
	t.p.updateReplay(t.gen, t.id, "concurrent", func(s *ReplayStats) {
		if s.MaxSkewMS == nil || skew > *s.MaxSkewMS {
			s.MaxSkewMS = &skew
		}
	})
}

func newReplayStats(mode string) *ReplayStats {
	return &ReplayStats{Mode: mode, Status: make(map[string]uint64), Outcomes: make(map[string]uint64)}
}

func (s *RuleStats) replay(mode string) *ReplayStats {
	if s.Replays == nil {
		s.Replays = newReplayStats(mode)
	}
	if s.Replays.Mode == mode {
		return s.Replays
	}
	if s.Replays.ByMode == nil {
		first := s.Replays
		s.Replays = &ReplayStats{Mode: "mixed", ByMode: map[string]*ReplayStats{first.Mode: first}}
	}
	if s.Replays.ByMode[mode] == nil {
		s.Replays.ByMode[mode] = newReplayStats(mode)
	}
	return s.Replays.ByMode[mode]
}

func (s *ReplayStats) addStatus(code string, count uint64) {
	n := len(s.Status)
	if s.Status["other"] != 0 {
		n--
	}
	if n >= 16 && s.Status[code] == 0 {
		code = "other"
	}
	s.Status[code] += count
}

func (p *Proxy) updateReplay(gen uint64, id, mode string, fn func(*ReplayStats)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if gen != p.generation {
		return
	}
	v := p.stats[id]
	if p.applied == nil {
		p.applied = make(map[appliedKey]uint64)
	}
	key := appliedKey{RuleID: id, Type: "dup-webhook"}
	if _, ok := p.applied[key]; !ok {
		p.applied[key] = 0
	}
	fn(v.replay(mode))
	p.stats[id] = v
}
func (p *Proxy) recordOriginal(gen uint64, rule *fault.Rule, mode string, status int, outcome string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil || gen != p.generation {
		return false
	}
	v := p.stats[rule.ID]
	stats := v.replay(mode)
	stats.CommittedStatus, stats.OriginalOutcome = status, outcome
	v.Applied++
	p.stats[rule.ID] = v
	if p.applied == nil {
		p.applied = make(map[appliedKey]uint64)
	}
	p.applied[appliedKey{RuleID: rule.ID, Type: rule.Fault.Type}]++
	return true
}
func replayError(err error) string {
	if errors.Is(err, errEgressDenied) {
		return "egress_denied"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	return "transport_error"
}
func (p *Proxy) replayCapacity(gen, seq uint64, rule *fault.Rule, mode string, firstIndex, count int, originalOutcome string, committedStatus int) {
	p.mu.Lock()
	if gen != p.generation {
		p.mu.Unlock()
		return
	}
	v := p.stats[rule.ID]
	v.skip("replay_capacity_exceeded")
	if p.applied == nil {
		p.applied = make(map[appliedKey]uint64)
	}
	key := appliedKey{RuleID: rule.ID, Type: rule.Fault.Type}
	if p.replayCapacitySkips == nil {
		p.replayCapacitySkips = make(map[appliedKey]uint64)
	}
	p.replayCapacitySkips[key]++
	if _, ok := p.applied[key]; !ok {
		p.applied[key] = 0
	}
	v.replay(mode).Outcomes["capacity_exceeded"] += uint64(count)
	p.stats[rule.ID] = v
	if p.replayWarned == nil {
		p.replayWarned = make(map[string]bool)
	}
	report := !p.replayWarned[rule.ID] && !p.options.SuppressStderr
	p.replayWarned[rule.ID] = true
	p.mu.Unlock()
	for i := firstIndex; i < firstIndex+count; i++ {
		event := map[string]any{"seq": seq, "fault": "dup-webhook", "rule_id": rule.ID, "applied": false, "replay_index": i, "replay_mode": mode, "outcome": "capacity_exceeded"}
		if mode == "timeout_retry" {
			event["original_outcome"] = originalOutcome
			event["committed_status"] = committedStatus
		}
		p.publish(gen, "http_req", event)
	}
	if report {
		fmt.Fprintf(os.Stderr, "rule %q: webhook replay capacity exceeded\n", rule.ID)
	}
}
func (p *Proxy) concurrentReplays(r *http.Request, body []byte, seq, gen uint64, rule *fault.Rule, params map[string]any) (func(bool), *replayTiming) {
	count := fault.Int(params, "count", 2) - 1
	clock := &replayTiming{p: p, gen: gen, id: rule.ID}
	start := make(chan struct{})
	var once sync.Once
	proceed := false
	release := func(ok bool) { once.Do(func() { proceed = ok; close(start) }) }
	p.mu.Lock()
	ctx := p.ctx
	if p.closed || ctx.Err() != nil || gen != p.generation {
		p.mu.Unlock()
		for i := 1; i <= count; i++ {
			p.replaySkipped(gen, seq, rule, "concurrent", i, "canceled", "", 0)
		}
		return nil, nil
	}
	if p.pending+count > 64 {
		p.mu.Unlock()
		p.replayCapacity(gen, seq, rule, "concurrent", 1, count, "", 0)
		return nil, nil
	}
	for range count {
		p.beginPendingLocked()
		p.pending++
	}
	p.replayWorkers.Add(count)
	p.mu.Unlock()
	for i := 1; i <= count; i++ {
		go func(index int) {
			defer p.replayWorkers.Done()
			defer p.finishReplay()
			select {
			case <-start:
			case <-ctx.Done():
				p.replaySkipped(gen, seq, rule, "concurrent", index, "canceled", "", 0)
				return
			}
			if !proceed || ctx.Err() != nil {
				p.replaySkipped(gen, seq, rule, "concurrent", index, "canceled", "", 0)
				return
			}
			p.sendReplay(ctx, r, body, seq, gen, rule, params, index, clock, "", 0)
		}(i)
	}
	return release, clock
}
func (p *Proxy) sequentialReplays(r *http.Request, body []byte, seq, gen uint64, rule *fault.Rule, params map[string]any) bool {
	count := fault.Int(params, "count", 2) - 1
	const mode = "sequential"
	delay := time.Duration(fault.Int(params, "delay_ms", 150)) * time.Millisecond
	u := r.URL
	if !u.IsAbs() {
		u = p.target
	}
	if u == nil || !p.allowed(u.Hostname(), upstreamPort(u.Scheme, u.Port())) {
		for i := 1; i <= count; i++ {
			p.replaySkipped(gen, seq, rule, mode, i, "egress_denied", "", 0)
		}
		return false
	}
	p.mu.Lock()
	ctx := p.ctx
	if p.closed || ctx.Err() != nil || gen != p.generation {
		p.mu.Unlock()
		for i := 1; i <= count; i++ {
			p.replaySkipped(gen, seq, rule, mode, i, "canceled", "", 0)
		}
		return false
	}
	admitted := min(count, max(0, 64-p.active))
	for range admitted {
		p.beginPendingLocked()
		p.pending++
	}
	p.replayWorkers.Add(admitted)
	p.mu.Unlock()
	if admitted < count {
		p.replayCapacity(gen, seq, rule, mode, admitted+1, count-admitted, "", 0)
	}
	for i := 1; i <= admitted; i++ {
		go func(index int) {
			defer p.replayWorkers.Done()
			defer p.finishReplay()
			if !wait(ctx, time.Duration(index)*delay) {
				p.replaySkipped(gen, seq, rule, mode, index, "canceled", "", 0)
				return
			}
			p.sendReplay(ctx, r, body, seq, gen, rule, params, index, nil, "", 0)
		}(i)
	}
	return admitted > 0
}
func (p *Proxy) sendReplay(ctx context.Context, r *http.Request, body []byte, seq, gen uint64, rule *fault.Rule, params map[string]any, index int, clock *replayTiming, originalOutcome string, committedStatus int) {
	mode := fault.String(params, "mode", "sequential")
	if local := r.Context().Value(http.LocalAddrContextKey); local != nil {
		ctx = context.WithValue(ctx, http.LocalAddrContextKey, local)
	}
	q := p.upstream(r, body, ctx)
	if q == nil || !p.allowed(q.URL.Hostname(), upstreamPort(q.URL.Scheme, q.URL.Port())) {
		p.replaySkipped(gen, seq, rule, mode, index, "egress_denied", originalOutcome, committedStatus)
		return
	}
	if fault.Bool(params, "replay_header", false) {
		q.Header.Set("X-Glitchdeck-Replay", strconv.Itoa(index))
	}
	replayCtx, cancel := context.WithTimeout(ctx, time.Duration(fault.Int(params, "replay_timeout_ms", 5000))*time.Millisecond)
	defer cancel()
	q = q.WithContext(replayCtx)
	transport := p.transportFor(replayCtx, r.ProtoMajor == 2 && q.URL.Scheme == "http")
	start := time.Now()
	if clock != nil {
		clock.start()
	}
	resp, err := transport.RoundTrip(q)
	if clock != nil {
		clock.record()
	}
	status := 0
	var n int64
	if err == nil {
		status = resp.StatusCode
		n, err = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
		_ = resp.Body.Close()
	}
	outcome := "ok"
	if err != nil {
		outcome = replayError(err)
	} else if status == 409 {
		outcome = "conflict"
	} else if status >= 500 {
		outcome = "server_error"
	} else if status < 200 || status >= 300 {
		outcome = "client_error"
	}
	if clock != nil && outcome != "egress_denied" {
		clock.applied.Do(func() { p.countRule(gen, rule, "applied", "") })
	}
	p.updateReplay(gen, rule.ID, mode, func(s *ReplayStats) {
		if outcome != "egress_denied" {
			s.Sent++
		}
		s.Outcomes[outcome]++
		if status != 0 {
			s.addStatus(strconv.Itoa(status), 1)
		}
	})
	if ctx.Err() == nil && (outcome == "transport_error" || outcome == "timeout") {
		p.outcome(gen, Outcome{Seq: seq, Err: err})
	}
	event := map[string]any{"seq": seq, "ts_ms": start.UnixMilli(), "method": q.Method, "path": q.URL.RequestURI(), "status": status, "latency_ms": time.Since(start).Milliseconds(), "req_bytes": len(body), "resp_bytes": n, "fault": "dup-webhook", "rule_id": rule.ID, "applied": outcome != "egress_denied", "replay_index": index, "replay_mode": mode, "outcome": outcome}
	if mode == "timeout_retry" {
		event["original_outcome"] = originalOutcome
		event["committed_status"] = committedStatus
	}
	p.publish(gen, "http_req", event)
}

func (p *Proxy) replaySkipped(gen, seq uint64, rule *fault.Rule, mode string, index int, outcome, originalOutcome string, committedStatus int) {
	p.updateReplay(gen, rule.ID, mode, func(s *ReplayStats) { s.Outcomes[outcome]++ })
	event := map[string]any{"seq": seq, "fault": "dup-webhook", "rule_id": rule.ID, "applied": false, "replay_index": index, "replay_mode": mode, "outcome": outcome}
	if outcome == "egress_denied" {
		event["error"] = "webhook replay egress denied"
	}
	if mode == "timeout_retry" {
		event["original_outcome"] = originalOutcome
		event["committed_status"] = committedStatus
	}
	p.publish(gen, "http_req", event)
}

func (p *Proxy) timeoutReplays(r *http.Request, body []byte, seq, gen uint64, rule *fault.Rule, params map[string]any) func(bool, string, int) {
	count := fault.Int(params, "count", 2) - 1
	p.mu.Lock()
	ctx := p.ctx
	if p.closed || ctx.Err() != nil || gen != p.generation {
		p.mu.Unlock()
		for i := 1; i <= count; i++ {
			p.replaySkipped(gen, seq, rule, "timeout_retry", i, "canceled", "", 0)
		}
		return nil
	}
	if p.pending+count > 64 {
		p.mu.Unlock()
		p.replayCapacity(gen, seq, rule, "timeout_retry", 1, count, "", 0)
		return nil
	}
	for range count {
		p.beginPendingLocked()
		p.pending++
	}
	p.replayWorkers.Add(count)
	p.mu.Unlock()
	start := make(chan struct{})
	var once sync.Once
	var proceed bool
	var originalOutcome string
	var committedStatus int
	release := func(ok bool, outcome string, status int) {
		once.Do(func() {
			proceed, originalOutcome, committedStatus = ok, outcome, status
			close(start)
		})
	}
	var previous <-chan struct{}
	for i := 1; i <= count; i++ {
		done := make(chan struct{})
		go func(index int, prev <-chan struct{}) {
			defer p.replayWorkers.Done()
			defer p.finishReplay()
			defer close(done)
			select {
			case <-start:
			case <-ctx.Done():
				p.replaySkipped(gen, seq, rule, "timeout_retry", index, "canceled", "", 0)
				return
			}
			if !proceed || ctx.Err() != nil {
				p.replaySkipped(gen, seq, rule, "timeout_retry", index, "canceled", originalOutcome, committedStatus)
				return
			}
			if prev != nil {
				select {
				case <-prev:
				case <-ctx.Done():
					p.replaySkipped(gen, seq, rule, "timeout_retry", index, "canceled", originalOutcome, committedStatus)
					return
				}
			}
			if !wait(ctx, time.Duration(fault.Int(params, "delay_ms", 150))*time.Millisecond) {
				p.replaySkipped(gen, seq, rule, "timeout_retry", index, "canceled", originalOutcome, committedStatus)
				return
			}
			p.sendReplay(ctx, r, body, seq, gen, rule, params, index, nil, originalOutcome, committedStatus)
		}(i, previous)
		previous = done
	}
	return release
}
