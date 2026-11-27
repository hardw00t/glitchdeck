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
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/localweb"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/tape"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
)

//go:embed dist/*
var assets embed.FS

const maxInput = 16 << 20

type Options struct{ Target, Listen, UI, DemoURL, ProxyAuth string }

type control struct {
	Options
	p           *proxy.Proxy
	bus         *telemetry.Bus
	client      *http.Client
	cfgMu       sync.Mutex
	rec         recorder
	broken      atomic.Bool
	streamSlots chan struct{}
	streamID    atomic.Uint64
}

func New(p *proxy.Proxy, bus *telemetry.Bus, opts Options) http.Handler {
	c := &control{Options: opts, p: p, bus: bus, client: &http.Client{
		Timeout:       25 * time.Second,
		Transport:     &http.Transport{DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	c.streamSlots = make(chan struct{}, 4)
	c.rec.attach(p)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) {
		cfg := c.p.Config()
		tls, fingerprint := c.p.TLSInfo()
		var ca any
		if fingerprint != "" {
			ca = fingerprint
		}
		respond(w, map[string]any{
			"target": c.Target, "listen": c.Listen, "ui": c.UI, "demo_mode": c.DemoURL != "",
			"seed": cfg.Seed, "seq": c.p.Seq(), "rules": rules(cfg), "tls_mitm": tls,
			"capabilities": map[string]any{"sse": true, "h2": true, "grpc": true, "tls_mitm": tls, "ca_fingerprint": ca},
		})
	})
	mux.HandleFunc("GET /api/history", c.history)
	mux.HandleFunc("GET /api/events", c.events)
	mux.HandleFunc("GET /api/faults", c.faults)
	mux.HandleFunc("GET /api/faults/schema", faultSchema)
	mux.HandleFunc("POST /api/faults", c.mutateFault)
	mux.HandleFunc("PUT /api/faults/{id}", c.mutateFault)
	mux.HandleFunc("DELETE /api/faults/{id}", c.mutateFault)
	mux.HandleFunc("PUT /api/faults", c.replace)
	mux.HandleFunc("PATCH /api/faults/{id}", c.patch)
	mux.HandleFunc("POST /api/reset", c.reset)
	mux.HandleFunc("GET /api/tape/status", func(w http.ResponseWriter, r *http.Request) { respond(w, c.rec.status()) })
	mux.HandleFunc("POST /api/tape/record", c.startRecording)
	mux.HandleFunc("POST /api/tape/stop", c.stopRecording)
	mux.HandleFunc("GET /api/tape/export", c.export)
	mux.HandleFunc("POST /api/tape/import", c.importTape)
	mux.HandleFunc("POST /api/demo/stream", c.demoStream)
	mux.HandleFunc("POST /api/demo/grpc", c.demoGRPC)
	if c.DemoURL != "" {
		mux.HandleFunc("GET /api/demo/state", c.demoState)
		mux.HandleFunc("POST /api/demo/trigger", c.trigger)
		mux.HandleFunc("POST /api/demo/checkout", c.trigger)
		mux.HandleFunc("GET /api/demo/ticker", func(w http.ResponseWriter, r *http.Request) {
			req := r.Clone(r.Context())
			// The control listener has already checked the browser's origin.
			req.Header.Del("Origin")
			req.URL.Path, req.URL.RawPath, req.URL.RawQuery = "/ws/ticker", "", ""
			req.RequestURI = req.URL.Path
			c.authenticateProxy(req)
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
		if !localweb.Allowed(r, c.UI) {
			http.Error(w, "untrusted control host or origin", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' ws://"+r.Host+"; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Frame-Options", "DENY")
		mux.ServeHTTP(w, r)
	})
}

func (c *control) startRecording(w http.ResponseWriter, r *http.Request) {
	c.cfgMu.Lock()
	cfg := c.p.Config()
	var status recordingStatus
	c.p.CaptureBoundary(func(nextSeq uint64, activeStreams int) {
		status = c.rec.start(nextSeq-1, activeStreams, cfg)
	})
	c.cfgMu.Unlock()
	respond(w, status)
}

func (c *control) stopRecording(w http.ResponseWriter, r *http.Request) {
	c.cfgMu.Lock()
	status := c.rec.stop()
	c.cfgMu.Unlock()
	respond(w, status)
}

func respond(w http.ResponseWriter, value any) {
	respondStatus(w, http.StatusOK, value)
}

func respondStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func readJSON(w http.ResponseWriter, r *http.Request, dest any) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxInput))
	d.DisallowUnknownFields()
	if err := d.Decode(dest); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("expected one JSON value")
	}
	return nil
}

func decode(w http.ResponseWriter, r *http.Request, dest any) bool {
	if err := readJSON(w, r, dest); err != nil {
		http.Error(w, err.Error(), 400)
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

func (c *control) changed(cfg fault.Config) map[string]any {
	state := map[string]any{"rules": rules(cfg), "seed": cfg.Seed, "seq": c.p.Seq()}
	c.bus.Publish("fault_state", state)
	return state
}

func (c *control) set(cfg fault.Config) (map[string]any, error) {
	if err := fault.Validate(cfg); err != nil {
		return nil, err
	}
	before := c.p.SetConfigAt(cfg)
	c.rec.changed(before, cfg)
	return c.changed(cfg), nil
}

func respondConfig(w http.ResponseWriter, state map[string]any, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	respond(w, state)
}

func (c *control) replace(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Rules []fault.Rule `json:"rules"`
		Seed  *uint64      `json:"seed"`
	}
	if err := readJSON(w, r, &req); err != nil {
		faultError(w, r, 400, "invalid_rule", "", "", err)
		return
	}
	if req.Rules == nil {
		faultError(w, r, 400, "invalid_rule", "", "", errors.New("rules array is required"))
		return
	}
	c.cfgMu.Lock()
	cfg := c.p.Config()
	cfg.Rules = req.Rules
	if req.Seed != nil {
		cfg.Seed = *req.Seed
	}
	state, err := c.set(cfg)
	c.cfgMu.Unlock()
	if err != nil {
		invalidFault(w, r, "", err)
		return
	}
	respond(w, state)
}

func (c *control) patch(w http.ResponseWriter, r *http.Request) {
	var patch struct {
		Enabled *bool           `json:"enabled"`
		Match   json.RawMessage `json:"match"`
		Params  map[string]any  `json:"params"`
	}
	id := r.PathValue("id")
	if err := readJSON(w, r, &patch); err != nil {
		faultError(w, r, 400, "invalid_rule", id, "", err)
		return
	}
	c.cfgMu.Lock()
	state, err := c.patchConfig(id, patch.Enabled, patch.Match, patch.Params)
	c.cfgMu.Unlock()
	if errors.Is(err, errRuleNotFound) {
		faultError(w, r, 404, "not_found", id, "", err)
		return
	}
	if err != nil {
		invalidFault(w, r, id, err)
		return
	}
	respond(w, state)
}

var errRuleNotFound = errors.New("rule not found")

func (c *control) patchConfig(id string, enabled *bool, match json.RawMessage, params map[string]any) (map[string]any, error) {
	cfg := c.p.Config()
	for i := range cfg.Rules {
		rule := &cfg.Rules[i]
		if rule.ID != id {
			continue
		}
		if enabled != nil {
			rule.Enabled = *enabled
		}
		if len(match) != 0 {
			d := json.NewDecoder(bytes.NewReader(match))
			d.DisallowUnknownFields()
			if err := d.Decode(&rule.Match); err != nil {
				return nil, err
			}
		}
		for k, v := range params {
			if rule.Fault.Params == nil {
				rule.Fault.Params = make(map[string]any, len(params))
			}
			rule.Fault.Params[k] = v
		}
		return c.set(cfg)
	}
	return nil, errRuleNotFound
}

func (c *control) reset(w http.ResponseWriter, r *http.Request) {
	c.cfgMu.Lock()
	var resetErr bool
	c.p.ResetWith(func() {
		c.bus.Clear()
		c.rec.reset()
		c.broken.Store(false)
		if c.DemoURL != "" {
			status, _, err := c.call(r.Context(), http.MethodPost, c.DemoURL+"/api/reset", nil)
			resetErr = err != nil || status >= 400
		}
	})
	c.changed(c.p.Config())
	c.cfgMu.Unlock()
	if resetErr {
		http.Error(w, "demo reset failed", http.StatusBadGateway)
		return
	}
	respond(w, map[string]bool{"ok": true})
}

func (c *control) export(w http.ResponseWriter, r *http.Request) {
	c.cfgMu.Lock()
	doc := c.rec.tape(c.p.Config())
	c.cfgMu.Unlock()
	doc.Name, doc.Target = "glitchdeck-recording", c.Target
	if c.DemoURL != "" {
		doc.Target = "demo"
		doc.Assertions = []tape.Assertion{{Name: "demo invariants", HTTPGet: "/api/state", Direct: true, ExpectStatus: 200, JSONEq: map[string]any{"duplicate_charges": 0, "ws_broken": false}}}
	}
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
	state, err := c.set(fault.Config{Seed: doc.Seed, Rules: doc.Rules})
	c.cfgMu.Unlock()
	respondConfig(w, state, err)
}

func (c *control) call(ctx context.Context, method, endpoint string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if req.URL.Host == c.Listen {
		c.authenticateProxy(req)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, data, err
}

func (c *control) authenticateProxy(r *http.Request) {
	if c.ProxyAuth != "" {
		r.SetBasicAuth("glitchdeck", c.ProxyAuth)
	}
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
