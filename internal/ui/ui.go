package ui

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"glitchdeck/internal/fault"
	"glitchdeck/internal/proxy"
	"glitchdeck/internal/tape"
	"glitchdeck/internal/telemetry"
)

//go:embed dist/*
var assets embed.FS

const maxInput = 16 << 20

type Options struct{ Target, Listen, UI, DemoURL string }

type control struct {
	Options
	p      *proxy.Proxy
	bus    *telemetry.Bus
	client *http.Client
	cfgMu  sync.Mutex
	rec    recorder
	broken atomic.Bool
}

func New(p *proxy.Proxy, bus *telemetry.Bus, opts Options) http.Handler {
	c := &control{Options: opts, p: p, bus: bus, client: &http.Client{
		Timeout:       25 * time.Second,
		Transport:     &http.Transport{DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	p.OnRequest = c.rec.request
	p.OnClientFrame = c.rec.clientFrame
	p.OnServerFrame = c.rec.serverFrame
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) {
		cfg := c.p.Config()
		respond(w, map[string]any{"target": c.Target, "listen": c.Listen, "ui": c.UI, "demo_mode": c.DemoURL != "", "seed": cfg.Seed, "seq": c.p.Seq(), "rules": rules(cfg)})
	})
	mux.HandleFunc("GET /api/history", c.history)
	mux.HandleFunc("GET /api/events", c.events)
	mux.HandleFunc("PUT /api/faults", c.replace)
	mux.HandleFunc("PATCH /api/faults/{id}", c.patch)
	mux.HandleFunc("POST /api/reset", c.reset)
	mux.HandleFunc("GET /api/tape/status", func(w http.ResponseWriter, r *http.Request) { respond(w, c.rec.status()) })
	mux.HandleFunc("POST /api/tape/record", func(w http.ResponseWriter, r *http.Request) { respond(w, c.rec.start(c.p.Seq)) })
	mux.HandleFunc("POST /api/tape/stop", func(w http.ResponseWriter, r *http.Request) { respond(w, c.rec.stop()) })
	mux.HandleFunc("GET /api/tape/export", c.export)
	mux.HandleFunc("POST /api/tape/import", c.importTape)
	if c.DemoURL != "" {
		mux.HandleFunc("GET /api/demo/state", c.demoState)
		mux.HandleFunc("POST /api/demo/trigger", c.trigger)
		mux.HandleFunc("POST /api/demo/checkout", c.trigger)
		mux.HandleFunc("GET /api/demo/ticker", func(w http.ResponseWriter, r *http.Request) {
			req := r.Clone(r.Context())
			req.URL.Path, req.URL.RawPath, req.URL.RawQuery = "/ws/ticker", "", ""
			req.RequestURI = req.URL.Path
			c.p.ServeHTTP(w, req)
		})
		mux.HandleFunc("POST /api/demo/ticker-state", func(w http.ResponseWriter, r *http.Request) {
			var state struct {
				Broken *bool `json:"broken"`
			}
			if !decode(w, r, &state) {
				return
			}
			if state.Broken == nil {
				http.Error(w, "broken is required", 400)
				return
			}
			c.broken.Store(*state.Broken)
			if *state.Broken {
				c.rec.tickerStalled()
			}
			respond(w, map[string]bool{"broken": *state.Broken})
		})
	}
	dist, err := fs.Sub(assets, "dist")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /", http.FileServer(http.FS(dist)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !trustedHost(r.Host, c.UI) {
			http.Error(w, "invalid control host", 403)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && (r.Method != "GET" || r.Header.Get("Upgrade") != "") {
			u, err := url.Parse(origin)
			if err != nil || u.Scheme != "http" || !strings.EqualFold(u.Host, r.Host) {
				http.Error(w, "cross-origin control request", 403)
				return
			}
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

func hostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func trustedHost(addr, bind string) bool {
	host := hostOnly(addr)
	if strings.EqualFold(host, "localhost") || host == "127.0.0.1" {
		return true
	}
	bound := hostOnly(bind)
	return bound != "" && strings.EqualFold(host, bound)
}

func respond(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}

func decode(w http.ResponseWriter, r *http.Request, dest any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxInput))
	d.DisallowUnknownFields()
	if err := d.Decode(dest); err != nil {
		http.Error(w, err.Error(), 400)
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		http.Error(w, "expected one JSON value", 400)
		return false
	}
	return true
}

func rules(cfg fault.Config) []fault.Rule {
	if cfg.Rules == nil {
		return []fault.Rule{}
	}
	return cfg.Rules
}

func (c *control) history(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 {
			http.Error(w, "limit must be a positive integer", 400)
			return
		}
	}
	respond(w, c.bus.History(limit))
}

func (c *control) events(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	history, ch, unsubscribe := c.bus.Subscribe()
	defer unsubscribe()
	rc := http.NewResponseController(w)
	write := func(format string, a ...any) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err := fmt.Fprintf(w, format, a...)
		return err == nil && rc.Flush() == nil
	}
	writeEvent := func(e telemetry.Event) bool { return write("id: %d\nevent: %s\ndata: %s\n\n", e.ID, e.Type, e.Data) }
	if !write(": connected\n\n") {
		return
	}
	if last, err := strconv.ParseUint(r.Header.Get("Last-Event-ID"), 10, 64); err == nil {
		for _, e := range history {
			if e.ID > last && !writeEvent(e) {
				return
			}
		}
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !write(": keep-alive\n\n") {
				return
			}
		case e := <-ch:
			if !writeEvent(e) {
				return
			}
		}
	}
}

func (c *control) changed() {
	cfg := c.p.Config()
	c.bus.Publish("fault_state", map[string]any{"rules": rules(cfg), "seed": cfg.Seed, "seq": c.p.Seq()})
}

func (c *control) set(w http.ResponseWriter, cfg fault.Config) {
	if err := fault.Validate(cfg); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	c.p.SetConfig(cfg)
	c.changed()
	respond(w, map[string]any{"rules": rules(cfg), "seed": cfg.Seed, "seq": c.p.Seq()})
}

func (c *control) replace(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Rules []fault.Rule `json:"rules"`
		Seed  *uint64      `json:"seed"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Rules == nil {
		http.Error(w, "rules array is required", 400)
		return
	}
	c.cfgMu.Lock()
	defer c.cfgMu.Unlock()
	cfg := c.p.Config()
	cfg.Rules = req.Rules
	if req.Seed != nil {
		cfg.Seed = *req.Seed
	}
	c.set(w, cfg)
}

func (c *control) patch(w http.ResponseWriter, r *http.Request) {
	var patch struct {
		Enabled *bool           `json:"enabled"`
		Match   json.RawMessage `json:"match"`
		Params  map[string]any  `json:"params"`
	}
	if !decode(w, r, &patch) {
		return
	}
	c.cfgMu.Lock()
	defer c.cfgMu.Unlock()
	cfg := c.p.Config()
	cfg.Rules = append([]fault.Rule(nil), cfg.Rules...)
	for i := range cfg.Rules {
		rule := &cfg.Rules[i]
		if rule.ID != r.PathValue("id") {
			continue
		}
		if patch.Enabled != nil {
			rule.Enabled = *patch.Enabled
		}
		if len(patch.Match) != 0 {
			rule.Match.Seq = append([]uint64(nil), rule.Match.Seq...)
			d := json.NewDecoder(bytes.NewReader(patch.Match))
			d.DisallowUnknownFields()
			if err := d.Decode(&rule.Match); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
		}
		if patch.Params != nil {
			merged := make(map[string]any, len(rule.Fault.Params)+len(patch.Params))
			for k, v := range rule.Fault.Params {
				merged[k] = v
			}
			for k, v := range patch.Params {
				merged[k] = v
			}
			rule.Fault.Params = merged
		}
		c.set(w, cfg)
		return
	}
	http.NotFound(w, r)
}

func (c *control) reset(w http.ResponseWriter, r *http.Request) {
	c.cfgMu.Lock()
	defer c.cfgMu.Unlock()
	c.p.Reset()
	c.bus.Clear()
	c.rec.reset()
	c.broken.Store(false)
	if c.DemoURL != "" {
		if status, _, err := c.call(r.Context(), http.MethodPost, c.DemoURL+"/api/reset", nil); err != nil || status >= 400 {
			http.Error(w, "demo reset failed", 502)
			return
		}
	}
	c.changed()
	respond(w, map[string]bool{"ok": true})
}

func (c *control) export(w http.ResponseWriter, r *http.Request) {
	cfg := c.p.Config()
	target := c.Target
	var assertions []tape.Assertion
	if c.DemoURL != "" {
		target = "demo"
		assertions = []tape.Assertion{{Name: "demo invariants", HTTPGet: "/api/state", Direct: true, ExpectStatus: 200, JSONEq: map[string]any{"duplicate_charges": 0, "ws_broken": false}}}
	}
	script, start := c.rec.script()
	doc := tape.Tape{Version: 1, Name: "glitchdeck-recording", Seed: cfg.Seed, Target: target, Rules: cfg.Rules, Script: script, Assertions: assertions, StartSeq: start}
	var data bytes.Buffer
	if err := tape.Encode(&data, doc); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="tape.yaml"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = data.WriteTo(w)
}

func (c *control) importTape(w http.ResponseWriter, r *http.Request) {
	doc, err := tape.Decode(http.MaxBytesReader(w, r.Body, maxInput))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	c.cfgMu.Lock()
	defer c.cfgMu.Unlock()
	c.set(w, fault.Config{Seed: doc.Seed, Rules: doc.Rules})
}

func (c *control) call(ctx context.Context, method, endpoint string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, data, err
}

func (c *control) demoState(w http.ResponseWriter, r *http.Request) {
	status, data, err := c.call(r.Context(), http.MethodGet, c.DemoURL+"/api/state", nil)
	var state map[string]json.RawMessage
	if err != nil || status != http.StatusOK || json.Unmarshal(data, &state) != nil || state == nil {
		http.Error(w, "demo state unavailable", 502)
		return
	}
	state["ws_broken"] = json.RawMessage(strconv.FormatBool(c.broken.Load()))
	respond(w, state)
}

func localEndpoint(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if host == "" || net.ParseIP(host).IsUnspecified() {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port), nil
}

func (c *control) trigger(w http.ResponseWriter, r *http.Request) {
	base, err := localEndpoint(c.Listen)
	if err != nil {
		http.Error(w, "proxy listen address unavailable", 502)
		return
	}
	rule := fault.MatchRule(c.p.Config(), http.MethodPost, "/checkout", c.p.Seq()+1, false)
	brokenCheckout := rule != nil && rule.Fault.Type == "tcp-rst"
	body, _ := json.Marshal(map[string]any{
		"order_id":     "ord-" + strconv.FormatInt(time.Now().UnixNano(), 36),
		"amount_cents": 9900, "charge": brokenCheckout,
	})
	status, retries, err := c.retry(r.Context(), base+"/checkout", body)
	if err == nil && status >= 200 && status < 300 && !brokenCheckout {
		var n int
		status, n, err = c.retry(r.Context(), base+"/webhooks/payment", body)
		retries += n
	}
	result := map[string]any{"status": status, "retries": retries}
	if err != nil {
		result["error"] = err.Error()
	}
	respond(w, result)
}

func (c *control) retry(ctx context.Context, endpoint string, body []byte) (int, int, error) {
	status, _, err := c.call(ctx, http.MethodPost, endpoint, body)
	if err != nil && !errors.Is(err, context.Canceled) {
		// This client intentionally retries an ambiguous checkout without an idempotency key.
		status, _, err = c.call(ctx, http.MethodPost, endpoint, body)
		return status, 1, err
	}
	var retries int
	for status == http.StatusTooManyRequests && retries < 6 {
		timer := time.NewTimer(120 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return status, retries, ctx.Err()
		case <-timer.C:
		}
		retries++
		status, _, err = c.call(ctx, http.MethodPost, endpoint, body)
	}
	return status, retries, err
}
