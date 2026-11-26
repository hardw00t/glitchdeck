package tape

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"time"

	"glitchdeck/internal/demo"
	"glitchdeck/internal/fault"
	"glitchdeck/internal/proxy"
	"glitchdeck/internal/telemetry"
	"glitchdeck/internal/wsframe"
	"gopkg.in/yaml.v3"
)

type Tape struct {
	Version    int          `yaml:"version" json:"version"`
	Name       string       `yaml:"name" json:"name"`
	Seed       uint64       `yaml:"seed" json:"seed"`
	StartSeq   uint64       `yaml:"start_seq,omitempty" json:"start_seq,omitempty"`
	Target     string       `yaml:"target" json:"target"`
	Rules      []fault.Rule `yaml:"rules" json:"rules"`
	Script     []Step       `yaml:"script" json:"script"`
	Assertions []Assertion  `yaml:"assertions" json:"assertions"`
}
type Step struct {
	Name    string `yaml:"name" json:"name"`
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
	if err := fault.Validate(fault.Config{Seed: t.Seed, Rules: t.Rules}); err != nil {
		return err
	}
	for _, s := range t.Script {
		n := 0
		if s.AtMS < 0 {
			return fmt.Errorf("invalid step offset")
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
		}
		if s.SleepMS != 0 {
			n++
			if s.SleepMS < 0 {
				return fmt.Errorf("invalid sleep")
			}
		}
		if n != 1 {
			return fmt.Errorf("step %q must have exactly one action", s.Name)
		}
	}
	for _, a := range t.Assertions {
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
	p.SetSeq(t.StartSeq)
	defer p.Close()
	server := httptest.NewServer(p)
	defer server.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	broken := false
	var streams []<-chan bool
	startRun := time.Now()
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
			rule := fault.MatchRule(fault.Config{Seed: t.Seed, Rules: t.Rules}, method, req.URL.Path, p.Seq()+1, false)
			resp, e := client.Do(req)
			if e == nil {
				_, e = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if e != nil && (rule == nil || rule.Fault.Type != "tcp-rst") {
				return nil, fmt.Errorf("step %s: %w", s.Name, e)
			}
		case s.WS != nil:
			stream, e := startWS(ctx, server.URL, *s.WS, isDemo)
			if e != nil {
				return nil, fmt.Errorf("step %s: %w", s.Name, e)
			}
			streams = append(streams, stream)
		}
	}
	for _, stream := range streams {
		select {
		case healthy := <-stream:
			if !healthy {
				broken = true
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err := p.Wait(ctx); err != nil {
		return nil, err
	}
	results := make([]Result, 0, len(t.Assertions))
	for _, a := range t.Assertions {
		result := Result{Name: a.Name, Failures: []string{}}
		start := time.Now()
		base := server.URL
		if a.Direct {
			base = app.URL
		}
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, base+a.HTTPGet, nil)
		if e != nil {
			return nil, e
		}
		resp, e := client.Do(req)
		if e != nil {
			return nil, fmt.Errorf("assertion %s: %w", a.Name, e)
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
			if e := decoder.Decode(&data); e != nil {
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
					for _, part := range strings.Split(k, ".") {
						m, ok := got.(map[string]any)
						if !ok {
							got = nil
							break
						}
						got = m[part]
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
					if !reflect.DeepEqual(en, gn) {
						result.Failures = append(result.Failures, fmt.Sprintf("%s: expected %s, got %s", k, eb, gb))
					}
				}
			}
		}
		results = append(results, result)
	}
	return results, nil
}
func startWS(ctx context.Context, base string, w WS, isDemo bool) (<-chan bool, error) {
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
	fail := func(e error) (<-chan bool, error) { stop(); conn.Close(); return nil, e }
	timeout := time.Duration(w.TimeoutMS) * time.Millisecond
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	setDeadline := func() {
		deadline := time.Now().Add(timeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		conn.SetDeadline(deadline)
	}
	setDeadline()
	key := base64.StdEncoding.EncodeToString([]byte("glitchdeck-wskey"))
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
	result := make(chan bool, 1)
	go func() {
		defer conn.Close()
		defer stop()
		healthy := false
		defer func() { result <- healthy }()
		count := w.Frames
		if count == 0 {
			count = 3
		}
		setDeadline()
		for i := 0; i < count; {
			frame, e := wsframe.Read(reader, false)
			if e != nil || frame.Opcode == 8 {
				return
			}
			switch frame.Opcode {
			case 1, 2:
				if isDemo && strings.SplitN(w.Path, "?", 2)[0] == "/ws/ticker" && (frame.Opcode != 1 || !json.Valid(frame.Payload)) {
					return
				}
				i++
				setDeadline()
			case 9:
				if wsframe.Write(conn, wsframe.Frame{Fin: true, Opcode: 10, Payload: frame.Payload}, true) != nil {
					return
				}
			}
		}
		healthy = true
	}()
	return result, nil
}
