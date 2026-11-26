package tape

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"glitchdeck/internal/demo"
	"glitchdeck/internal/fault"
	"glitchdeck/internal/proxy"
	"glitchdeck/internal/telemetry"
	"glitchdeck/internal/wsframe"
	"gopkg.in/yaml.v3"
)

type Tape struct {
	Version          int            `yaml:"version" json:"version"`
	Name             string         `yaml:"name" json:"name"`
	Seed             uint64         `yaml:"seed" json:"seed"`
	StartSeq         uint64         `yaml:"start_seq,omitempty" json:"start_seq,omitempty"`
	Target           string         `yaml:"target" json:"target"`
	Rules            []fault.Rule   `yaml:"rules" json:"rules"`
	Script           []Step         `yaml:"script" json:"script"`
	Incomplete       bool           `yaml:"incomplete,omitempty" json:"incomplete,omitempty"`
	IncompleteReason string         `yaml:"incomplete_reason,omitempty" json:"incomplete_reason,omitempty"`
	ConfigChanges    []ConfigChange `yaml:"config_changes,omitempty" json:"config_changes,omitempty"`
	Assertions       []Assertion    `yaml:"assertions" json:"assertions"`
}
type ConfigChange struct {
	BeforeSeq uint64       `yaml:"before_seq" json:"before_seq"`
	AtMS      *int64       `yaml:"at_ms,omitempty" json:"at_ms,omitempty"`
	Seed      uint64       `yaml:"seed" json:"seed"`
	Rules     []fault.Rule `yaml:"rules" json:"rules"`
}
type Step struct {
	Name    string `yaml:"name" json:"name"`
	Seq     uint64 `yaml:"seq,omitempty" json:"seq,omitempty"`
	HTTP    *HTTP  `yaml:"http,omitempty" json:"http,omitempty"`
	WS      *WS    `yaml:"ws,omitempty" json:"ws,omitempty"`
	SleepMS int    `yaml:"sleep_ms,omitempty" json:"sleep_ms,omitempty"`
	AtMS    int64  `yaml:"at_ms,omitempty" json:"at_ms,omitempty"`
}
type HTTP struct {
	Method  string            `yaml:"method" json:"method"`
	Path    string            `yaml:"path" json:"path"`
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Body    string            `yaml:"body,omitempty" json:"body,omitempty"`
}
type WS struct {
	Path      string   `yaml:"path" json:"path"`
	Frames    int      `yaml:"frames,omitempty" json:"frames,omitempty"`
	TimeoutMS int      `yaml:"timeout_ms,omitempty" json:"timeout_ms,omitempty"`
	Messages  []string `yaml:"messages,omitempty" json:"messages,omitempty"`
}
type Assertion struct {
	Name         string         `yaml:"name" json:"name"`
	HTTPGet      string         `yaml:"http_get" json:"http_get"`
	ExpectStatus int            `yaml:"expect_status,omitempty" json:"expect_status,omitempty"`
	JSONEq       map[string]any `yaml:"json_eq,omitempty" json:"json_eq,omitempty"`
	MaxLatencyMS int            `yaml:"max_latency_ms,omitempty" json:"max_latency_ms,omitempty"`
	Direct       bool           `yaml:"direct,omitempty" json:"direct,omitempty"`
}
type Result struct {
	Name     string   `json:"name"`
	Failures []string `json:"failures"`
}

func Decode(r io.Reader) (Tape, error) {
	var t Tape
	d := yaml.NewDecoder(r)
	d.KnownFields(true)
	if err := d.Decode(&t); err != nil {
		return t, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			return t, fmt.Errorf("multiple tape documents")
		}
		return t, err
	}
	if err := validate(t); err != nil {
		return t, err
	}
	return t, nil
}
func Encode(w io.Writer, t Tape) error { e := yaml.NewEncoder(w); defer e.Close(); return e.Encode(t) }
func validPath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.ContainsAny(p, "\r\n")
}
func validate(t Tape) error {
	if t.Version != 1 {
		return fmt.Errorf("unsupported tape version %d", t.Version)
	}
	if t.Incomplete {
		return fmt.Errorf("incomplete tape: %s", t.IncompleteReason)
	}
	if t.StartSeq == math.MaxUint64 {
		return fmt.Errorf("invalid start sequence")
	}
	lastChange := t.StartSeq
	for _, c := range t.ConfigChanges {
		if c.BeforeSeq < lastChange || c.BeforeSeq == 0 || (c.AtMS != nil && (*c.AtMS < 0 || *c.AtMS > math.MaxInt64/int64(time.Millisecond))) {
			return fmt.Errorf("invalid configuration timeline")
		}
		if err := fault.Validate(fault.Config{Seed: c.Seed, Rules: c.Rules}); err != nil {
			return err
		}
		lastChange = c.BeforeSeq
	}
	seq := t.StartSeq
	if err := fault.Validate(fault.Config{Seed: t.Seed, Rules: t.Rules}); err != nil {
		return err
	}
	for _, s := range t.Script {
		n := 0
		if s.AtMS < 0 {
			return fmt.Errorf("invalid step offset")
		}
		if s.AtMS > math.MaxInt64/int64(time.Millisecond) {
			return fmt.Errorf("invalid step offset")
		}
		if s.HTTP != nil || s.WS != nil {
			if s.Seq != 0 {
				if s.Seq <= seq {
					return fmt.Errorf("invalid step sequence")
				}
				seq = s.Seq
			} else {
				if seq == math.MaxUint64 {
					return fmt.Errorf("sequence overflow")
				}
				seq++
			}
		} else if s.Seq != 0 {
			return fmt.Errorf("sequence on non-request step")
		}
		if s.HTTP != nil {
			n++
			if !validPath(s.HTTP.Path) {
				return fmt.Errorf("invalid HTTP path")
			}
		}
		if s.WS != nil {
			n++
			if !validPath(s.WS.Path) || s.WS.Frames < 0 || s.WS.TimeoutMS < 0 {
				return fmt.Errorf("invalid WS step")
			}
			if int64(s.WS.TimeoutMS) > math.MaxInt64/int64(time.Millisecond) {
				return fmt.Errorf("invalid WS timeout")
			}
		}
		if s.SleepMS != 0 {
			n++
			if s.SleepMS < 0 || int64(s.SleepMS) > math.MaxInt64/int64(time.Millisecond) {
				return fmt.Errorf("invalid sleep")
			}
		}
		if n != 1 {
			return fmt.Errorf("step %q must have exactly one action", s.Name)
		}
	}
	for _, c := range t.ConfigChanges {
		if c.AtMS == nil && c.BeforeSeq > seq && c.BeforeSeq-seq > 1 {
			return fmt.Errorf("configuration change beyond final sequence")
		}
	}
	for _, a := range t.Assertions {
		if !a.Direct {
			if seq == math.MaxUint64 {
				return fmt.Errorf("sequence overflow")
			}
			seq++
		}
		if !validPath(a.HTTPGet) || a.MaxLatencyMS < 0 {
			return fmt.Errorf("invalid assertion %q", a.Name)
		}
	}
	return nil
}
func Run(ctx context.Context, t Tape, targetOverride string) ([]Result, error) {
	if err := validate(t); err != nil {
		return nil, err
	}
	target := t.Target
	if targetOverride != "" {
		target = targetOverride
	}
	var app *httptest.Server
	isDemo := target == "demo"
	if isDemo {
		app = httptest.NewServer(demo.New())
		defer app.Close()
		target = app.URL
	}
	for _, a := range t.Assertions {
		if a.Direct && (!isDemo || a.HTTPGet != "/api/state") {
			return nil, fmt.Errorf("direct assertions require demo /api/state")
		}
	}
	u, err := proxy.ParseTarget(target)
	if err != nil {
		return nil, err
	}
	p := proxy.New(u, fault.Config{Seed: t.Seed, Rules: t.Rules}, telemetry.New())
	var outcomeMu sync.Mutex
	outcomes := map[uint64]proxy.Outcome{}
	p.OnOutcome = func(o proxy.Outcome) {
		outcomeMu.Lock()
		prev := outcomes[o.Seq]
		prev.Reset = prev.Reset || o.Reset
		prev.WSFault = prev.WSFault || o.WSFault
		if o.Err != nil {
			prev.Err = o.Err
		}
		outcomes[o.Seq] = prev
		outcomeMu.Unlock()
	}
	getOutcome := func(seq uint64) proxy.Outcome { outcomeMu.Lock(); defer outcomeMu.Unlock(); return outcomes[seq] }
	p.SetSeq(t.StartSeq)
	defer p.Close()
	server := httptest.NewServer(p)
	defer server.Close()
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	broken := false
	type streamResult struct {
		seq    uint64
		ticker bool
		ch     <-chan error
	}
	var streams []streamResult
	startRun := time.Now()
	var configMu sync.Mutex
	applied := make([]bool, len(t.ConfigChanges))
	applyChanges := func(seq uint64) {
		configMu.Lock()
		defer configMu.Unlock()
		for i, c := range t.ConfigChanges {
			if applied[i] {
				continue
			}
			due := c.AtMS != nil && time.Since(startRun) >= time.Duration(*c.AtMS)*time.Millisecond
			if c.AtMS == nil {
				due = seq >= c.BeforeSeq
			}
			if due {
				p.SetConfig(fault.Config{Seed: c.Seed, Rules: c.Rules})
				applied[i] = true
			}
		}
	}
	for _, c := range t.ConfigChanges {
		if c.AtMS == nil {
			continue
		}
		at := *c.AtMS
		go func() {
			timer := time.NewTimer(time.Until(startRun.Add(time.Duration(at) * time.Millisecond)))
			defer timer.Stop()
			select {
			case <-timer.C:
				applyChanges(0)
			case <-ctx.Done():
			}
		}()
	}
	for _, s := range t.Script {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if wait := time.Until(startRun.Add(time.Duration(s.AtMS) * time.Millisecond)); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
		if s.HTTP != nil || s.WS != nil {
			if s.Seq != 0 {
				p.SetSeq(s.Seq - 1)
			}
			applyChanges(p.Seq() + 1)
		}
		switch {
		case s.SleepMS > 0:
			timer := time.NewTimer(time.Duration(s.SleepMS) * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		case s.HTTP != nil:
			method := s.HTTP.Method
			if method == "" {
				method = http.MethodGet
			}
			req, e := http.NewRequestWithContext(ctx, method, server.URL+s.HTTP.Path, strings.NewReader(s.HTTP.Body))
			if e != nil {
				return nil, e
			}
			for k, v := range s.HTTP.Headers {
				req.Header.Set(k, v)
			}
			seq := p.Seq() + 1
			resp, e := client.Do(req)
			transportFailure := false
			if e == nil {
				transportFailure = resp.Header.Get(proxy.TransportErrorHeader) != ""
				_, e = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			o := getOutcome(seq)
			if o.Err != nil {
				return nil, fmt.Errorf("step %s: %w", s.Name, o.Err)
			}
			if transportFailure {
				return nil, fmt.Errorf("step %s: proxy transport failure", s.Name)
			}
			if e != nil && !o.Reset {
				return nil, fmt.Errorf("step %s: %w", s.Name, e)
			}
		case s.WS != nil:
			stream, e := startWS(ctx, server.URL, *s.WS, isDemo)
			if e != nil {
				return nil, fmt.Errorf("step %s: %w", s.Name, e)
			}
			streams = append(streams, streamResult{seq: p.Seq(), ticker: isDemo && strings.SplitN(s.WS.Path, "?", 2)[0] == "/ws/ticker", ch: stream})
		}
	}
	for _, stream := range streams {
		select {
		case e := <-stream.ch:
			o := getOutcome(stream.seq)
			if o.Err != nil {
				return nil, o.Err
			}
			if e != nil && !o.WSFault {
				return nil, fmt.Errorf("websocket sequence %d: %w", stream.seq, e)
			}
			if stream.ticker {
				broken = e != nil
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err := p.Wait(ctx); err != nil {
		return nil, err
	}
	outcomeMu.Lock()
	for _, o := range outcomes {
		if o.Err != nil {
			outcomeMu.Unlock()
			return nil, o.Err
		}
	}
	outcomeMu.Unlock()
	results := make([]Result, 0, len(t.Assertions))
	for _, a := range t.Assertions {
		result := Result{Name: a.Name, Failures: []string{}}
		start := time.Now()
		base := server.URL
		if a.Direct {
			base = app.URL
		}
		seq := p.Seq() + 1
		if !a.Direct {
			applyChanges(seq)
		}
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, base+a.HTTPGet, nil)
		if e != nil {
			return nil, e
		}
		resp, e := client.Do(req)
		if e != nil {
			return nil, fmt.Errorf("assertion %s: %w", a.Name, e)
		}
		if !a.Direct && resp.Header.Get(proxy.TransportErrorHeader) != "" {
			resp.Body.Close()
			return nil, fmt.Errorf("assertion %s: proxy transport failure", a.Name)
		}
		var body []byte
		if len(a.JSONEq) > 0 {
			body, e = io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
			if e == nil && len(body) > 4<<20 {
				e = fmt.Errorf("assertion response exceeds 4 MiB")
			}
		} else {
			_, e = io.Copy(io.Discard, resp.Body)
		}
		resp.Body.Close()
		if e != nil {
			return nil, e
		}
		if !a.Direct {
			if o := getOutcome(seq); o.Err != nil {
				return nil, fmt.Errorf("assertion %s: %w", a.Name, o.Err)
			}
		}
		elapsed := time.Since(start)
		if a.ExpectStatus != 0 && resp.StatusCode != a.ExpectStatus {
			result.Failures = append(result.Failures, fmt.Sprintf("status: expected %d, got %d", a.ExpectStatus, resp.StatusCode))
		}
		if a.MaxLatencyMS > 0 && elapsed > time.Duration(a.MaxLatencyMS)*time.Millisecond {
			result.Failures = append(result.Failures, fmt.Sprintf("latency_ms: expected <= %d, got %d", a.MaxLatencyMS, elapsed.Milliseconds()))
		}
		if len(a.JSONEq) > 0 {
			var data map[string]any
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.UseNumber()
			e := decoder.Decode(&data)
			if e == nil {
				var extra any
				if e = decoder.Decode(&extra); e == nil {
					e = fmt.Errorf("multiple JSON documents")
				} else if e == io.EOF {
					e = nil
				}
			}
			if e != nil {
				result.Failures = append(result.Failures, "invalid JSON response: "+e.Error())
			} else {
				if _, ok := data["ws_broken"]; ok && broken && isDemo && a.HTTPGet == "/api/state" {
					data["ws_broken"] = true
				}
				keys := make([]string, 0, len(a.JSONEq))
				for k := range a.JSONEq {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					var got any = data
					present := true
					for _, part := range strings.Split(k, ".") {
						m, ok := got.(map[string]any)
						if !ok {
							present = false
							break
						}
						got, present = m[part]
						if !present {
							break
						}
					}
					expected := a.JSONEq[k]
					eb, _ := json.Marshal(expected)
					gb, _ := json.Marshal(got)
					var en, gn any
					ed := json.NewDecoder(bytes.NewReader(eb))
					ed.UseNumber()
					ed.Decode(&en)
					gd := json.NewDecoder(bytes.NewReader(gb))
					gd.UseNumber()
					gd.Decode(&gn)
					if !present || !jsonEqual(en, gn) {
						if !present {
							gb = []byte("<missing>")
						}
						result.Failures = append(result.Failures, fmt.Sprintf("%s: expected %s, got %s", k, eb, gb))
					}
				}
			}
		}
		results = append(results, result)
	}
	if err := p.Wait(ctx); err != nil {
		return nil, err
	}
	outcomeMu.Lock()
	for _, o := range outcomes {
		if o.Err != nil {
			outcomeMu.Unlock()
			return nil, o.Err
		}
	}
	outcomeMu.Unlock()
	return results, nil
}
func jsonEqual(a, b any) bool {
	if x, ok := a.(json.Number); ok {
		y, ok := b.(json.Number)
		if !ok {
			return false
		}
		xr, xok := new(big.Rat).SetString(string(x))
		yr, yok := new(big.Rat).SetString(string(y))
		return xok && yok && xr.Cmp(yr) == 0
	}
	if x, ok := a.([]any); ok {
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !jsonEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	}
	if x, ok := a.(map[string]any); ok {
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			z, ok := y[k]
			if !ok || !jsonEqual(v, z) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a, b)
}
func startWS(ctx context.Context, base string, w WS, isDemo bool) (<-chan error, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	fail := func(e error) (<-chan error, error) { stop(); conn.Close(); return nil, e }
	timeout := time.Duration(w.TimeoutMS) * time.Millisecond
	if timeout == 0 {
		timeout = 2500 * time.Millisecond
	}
	if isDemo && strings.SplitN(w.Path, "?", 2)[0] == "/ws/ticker" && timeout > 2500*time.Millisecond {
		timeout = 2500 * time.Millisecond
	}
	setDeadline := func() {
		deadline := time.Now().Add(timeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		conn.SetDeadline(deadline)
	}
	setDeadline()
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return fail(err)
	}
	key := base64.StdEncoding.EncodeToString(nonce[:])
	if _, err = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n", w.Path, u.Host, key); err != nil {
		return fail(err)
	}
	reader := bufio.NewReader(conn)
	req := &http.Request{Method: http.MethodGet}
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return fail(err)
	}
	if resp.StatusCode != 101 || resp.Header.Get("Sec-WebSocket-Accept") != wsframe.AcceptKey(key) {
		return fail(fmt.Errorf("websocket handshake returned %s", resp.Status))
	}
	for _, msg := range w.Messages {
		if err = wsframe.Write(conn, wsframe.Frame{Fin: true, Opcode: 1, Payload: []byte(msg)}, true); err != nil {
			return fail(err)
		}
	}
	result := make(chan error, 1)
	go func() {
		defer conn.Close()
		defer stop()
		var failure error
		defer func() { result <- failure }()
		count := w.Frames
		if count == 0 {
			count = 3
		}
		isTicker := isDemo && strings.SplitN(w.Path, "?", 2)[0] == "/ws/ticker"
		setDeadline()
		var message []byte
		var opcode byte
		for i := 0; i < count; {
			frame, e := wsframe.Read(reader, false)
			if e != nil {
				failure = e
				return
			}
			if frame.Opcode == 8 {
				failure = fmt.Errorf("websocket closed before requested messages")
				return
			}
			switch frame.Opcode {
			case 1, 2, 0:
				if frame.Opcode != 0 {
					if opcode != 0 {
						failure = fmt.Errorf("interleaved websocket messages")
						return
					}
					opcode = frame.Opcode
				} else if opcode == 0 {
					failure = fmt.Errorf("unexpected continuation")
					return
				}
				if len(message)+len(frame.Payload) > wsframe.MaxPayload {
					failure = fmt.Errorf("websocket message too large")
					return
				}
				if isTicker {
					message = append(message, frame.Payload...)
				}
				if !frame.Fin {
					continue
				}
				if isTicker && (opcode != 1 || !json.Valid(message)) {
					failure = fmt.Errorf("invalid ticker message")
					return
				}
				message = nil
				opcode = 0
				i++
				setDeadline()
			case 9:
				if e := wsframe.Write(conn, wsframe.Frame{Fin: true, Opcode: 10, Payload: frame.Payload}, true); e != nil {
					failure = e
					return
				}
			}
		}
	}()
	return result, nil
}
