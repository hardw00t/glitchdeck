package execrun

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hardw00t/glitchdeck/internal/demo"
	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/tape"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
	"github.com/hardw00t/glitchdeck/internal/tlsmitm"
	"github.com/hardw00t/glitchdeck/internal/ui"
)

type Options struct {
	Command          []string
	TapePath         string
	Target           string
	Listen           string
	UI               string
	Timeout          time.Duration
	Grace            time.Duration
	TLS              bool
	CADir            string
	NoProxy          string
	UpstreamAllow    []string
	UpstreamCA       string
	InsecureUpstream bool
	ProxyAuth        bool
	JSON             bool
	AllowRemote      bool
	Seed             *uint64
}
type Exec struct {
	Cmd        []string `json:"cmd"`
	ProxyURL   string   `json:"proxy_url"`
	UIURL      string   `json:"ui_url,omitempty"`
	ExitCode   int      `json:"exit_code"`
	TimedOut   bool     `json:"timed_out"`
	StdoutTail string   `json:"stdout_tail"`
	StderrTail string   `json:"stderr_tail"`
	PID        int      `json:"pid,omitempty"`
	LeakedPIDs []int    `json:"leaked_pids"`
}
type Summary struct {
	AssertionsTotal  int    `json:"assertions_total"`
	AssertionsPassed int    `json:"assertions_passed"`
	AssertionsFailed int    `json:"assertions_failed"`
	RequestsTotal    uint64 `json:"requests_total"`
	FaultsTriggered  uint64 `json:"faults_triggered"`
}
type Assertion struct {
	Name     string   `json:"name"`
	Passed   bool     `json:"passed"`
	Failures []string `json:"failures"`
}
type Envelope struct {
	SchemaVersion   int         `json:"schema_version"`
	Command         string      `json:"command"`
	OK              bool        `json:"ok"`
	ExitCode        int         `json:"exit_code"`
	Tape            string      `json:"tape"`
	Target          string      `json:"target"`
	DurationMS      int64       `json:"duration_ms"`
	Summary         Summary     `json:"summary"`
	FaultsTriggered []any       `json:"faults_triggered"`
	Assertions      []Assertion `json:"assertions"`
	Diff            []string    `json:"diff"`
	Exec            *Exec       `json:"exec,omitempty"`
	Error           any         `json:"error"`
}

func NewEnvelope(command, path, target string) Envelope {
	return Envelope{SchemaVersion: 2, Command: command, Tape: path, Target: target, FaultsTriggered: []any{}, Assertions: []Assertion{}, Diff: []string{}}
}
func (e *Envelope) SetResults(results []tape.Result) {
	for _, r := range results {
		if r.Failures == nil {
			r.Failures = []string{}
		}
		ok := len(r.Failures) == 0
		e.Assertions = append(e.Assertions, Assertion{Name: r.Name, Passed: ok, Failures: r.Failures})
		for _, failure := range r.Failures {
			e.Diff = append(e.Diff, r.Name+": "+failure)
		}
		e.Summary.AssertionsTotal++
		if ok {
			e.Summary.AssertionsPassed++
		} else {
			e.Summary.AssertionsFailed++
		}
	}
}
func Run(ctx context.Context, t tape.Tape, o Options) Envelope {
	start := time.Now()
	target := t.Target
	if o.Target != "" {
		target = o.Target
	}
	e := NewEnvelope("exec", o.TapePath, target)
	e.Exec = &Exec{Cmd: o.Command}
	finish := func(code int, kind string, err error) Envelope {
		e.ExitCode = code
		e.OK = code == 0
		e.DurationMS = time.Since(start).Milliseconds()
		if err != nil {
			e.Error = map[string]string{"code": kind, "message": err.Error()}
		}
		return e
	}
	if len(o.Command) == 0 {
		return finish(2, "USAGE_ERROR", fmt.Errorf("missing child command"))
	}
	if o.Listen == "" {
		o.Listen = "127.0.0.1:0"
	}
	host, _, err := net.SplitHostPort(o.Listen)
	if err != nil || (!o.AllowRemote && host != "localhost" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback())) {
		return finish(2, "TARGET_INVALID", fmt.Errorf("listener must be loopback"))
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Minute
	}
	if o.Grace <= 0 {
		o.Grace = 5 * time.Second
	}
	var demoHandler http.Handler
	if target == "demo" {
		al, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			return finish(3, "PROXY_START_FAILED", e)
		}
		defer al.Close()
		demoHandler = demo.New()
		app := &http.Server{Handler: demoHandler, Protocols: demo.Protocols()}
		go app.Serve(al)
		defer app.Close()
		target = "http://" + al.Addr().String()
	}
	var parsed *url.URL
	if target != "" {
		parsed, err = proxy.ParseTarget(target)
		if o.Target != "" {
			parsed, err = proxy.ParseExplicitTarget(target)
		}
		if err != nil {
			return finish(2, "TARGET_INVALID", err)
		}
	}
	listener, err := net.Listen("tcp", o.Listen)
	if err != nil {
		return finish(3, "PROXY_START_FAILED", err)
	}
	defer listener.Close()
	seed := t.Seed
	if o.Seed != nil {
		seed = *o.Seed
	}
	bus := telemetry.New()
	p := proxy.New(parsed, fault.Config{Seed: seed, Rules: t.Rules}, bus)
	p.SetSeq(t.StartSeq)
	defer p.Close()
	opts := proxy.Options{Demo: demoHandler != nil, UpstreamAllow: append(t.UpstreamAllow, o.UpstreamAllow...), InsecureUpstream: o.InsecureUpstream}
	if o.UpstreamCA != "" {
		data, x := os.ReadFile(o.UpstreamCA)
		if x != nil {
			return finish(3, "CA_ERROR", x)
		}
		pool, x := x509.SystemCertPool()
		if x != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(data) {
			return finish(3, "CA_ERROR", fmt.Errorf("invalid CA certificate"))
		}
		opts.UpstreamCA = pool
	}
	env := []string{}
	if o.TLS || t.TLSMITM {
		var ca *tlsmitm.CA
		if o.CADir != "" {
			ca, err = (tlsmitm.Store{Dir: o.CADir}).Load()
		} else {
			ca, err = tlsmitm.Ephemeral()
		}
		if err != nil {
			return finish(3, "CA_ERROR", err)
		}
		opts.CA = ca
		dir, x := os.MkdirTemp("", "glitchdeck-ca-")
		if x != nil {
			return finish(3, "CA_ERROR", x)
		}
		defer os.RemoveAll(dir)
		cert := dir + string(os.PathSeparator) + "ca.pem"
		bundle := dir + string(os.PathSeparator) + "bundle.pem"
		if x = os.WriteFile(cert, ca.PEM, 0600); x != nil {
			return finish(3, "CA_ERROR", x)
		}
		var data []byte
		for _, path := range []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"} {
			data, x = os.ReadFile(path)
			if x == nil {
				break
			}
		}
		data = append(data, ca.PEM...)
		if x = os.WriteFile(bundle, data, 0600); x != nil {
			return finish(3, "CA_ERROR", x)
		}
		env = append(env, "GLITCHDECK_CA_CERT="+cert, "NODE_EXTRA_CA_CERTS="+cert, "SSL_CERT_FILE="+bundle, "REQUESTS_CA_BUNDLE="+bundle, "CURL_CA_BUNDLE="+bundle)
	}
	if opts.CA != nil && demoHandler != nil {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			return finish(3, "PROXY_START_FAILED", e)
		}
		defer l.Close()
		cert, e := tlsmitm.NewMinter(opts.CA, 1, 0).For("localhost")
		if e != nil {
			return finish(3, "CA_ERROR", e)
		}
		if opts.UpstreamCA == nil {
			opts.UpstreamCA, e = x509.SystemCertPool()
			if e != nil {
				opts.UpstreamCA = x509.NewCertPool()
			}
		}
		opts.UpstreamCA.AddCert(opts.CA.Cert)
		protocols := demo.Protocols()
		protocols.SetHTTP2(true)
		server := &http.Server{Handler: demoHandler, Protocols: protocols, TLSConfig: &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12}}
		go server.ServeTLS(l, "", "")
		defer server.Close()
		env = append(env, "GLITCHDECK_DEMO_TLS=https://"+l.Addr().String())
	}
	proxyURL := "http://" + listener.Addr().String()
	publicURL := proxyURL
	if o.ProxyAuth {
		var token [24]byte
		if _, err = rand.Read(token[:]); err != nil {
			return finish(3, "PROXY_START_FAILED", err)
		}
		opts.ProxyAuth = hex.EncodeToString(token[:])
		proxyURL = "http://glitchdeck:" + opts.ProxyAuth + "@" + listener.Addr().String()
	}
	p.SetOptions(opts)
	e.Exec.ProxyURL, e.Exec.LeakedPIDs = publicURL, []int{}
	if o.UI != "" {
		host, _, bindErr := net.SplitHostPort(o.UI)
		if bindErr != nil || host != "localhost" && !net.ParseIP(host).IsLoopback() {
			return finish(2, "TARGET_INVALID", fmt.Errorf("UI listener must be loopback"))
		}
		l, listenErr := net.Listen("tcp", o.UI)
		if listenErr != nil {
			return finish(3, "PROXY_START_FAILED", listenErr)
		}
		defer l.Close()
		demoURL := ""
		if demoHandler != nil {
			demoURL = target
		}
		e.Exec.UIURL = "http://" + l.Addr().String()
		server := &http.Server{Handler: ui.New(p, bus, ui.Options{Target: target, Listen: listener.Addr().String(), UI: l.Addr().String(), DemoURL: demoURL, ProxyAuth: opts.ProxyAuth})}
		go server.Serve(l)
		defer server.Close()
	}
	go p.Serve(listener)
	env = append(env, "GLITCHDECK_PROXY_URL="+proxyURL, "GLITCHDECK_TARGET="+target, "HTTP_PROXY="+proxyURL, "http_proxy="+proxyURL, "HTTPS_PROXY="+proxyURL, "https_proxy="+proxyURL, "NO_PROXY="+o.NoProxy, "no_proxy="+o.NoProxy, "NODE_USE_ENV_PROXY=1")
	if e.Exec.UIURL != "" {
		env = append(env, "GLITCHDECK_UI_URL="+e.Exec.UIURL)
	}
	childCtx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	cmd := exec.CommandContext(childCtx, o.Command[0], o.Command[1:]...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = os.Stdin
	var stdout, stderr tail
	if o.JSON || o.ProxyAuth {
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
	} else {
		cmd.Stdout = io.MultiWriter(os.Stdout, &stdout)
		cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
	}
	if err = setupProcess(cmd, o.Grace); err != nil {
		return finish(3, "PROCESS_SETUP_FAILED", err)
	}
	err = cmd.Start()
	if err != nil {
		code := 125
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			code = 127
		} else if errors.Is(err, os.ErrPermission) {
			code = 126
		}
		return finish(code, "EXEC_SPAWN_FAILED", err)
	}
	e.Exec.PID = cmd.Process.Pid
	stopSignals := forwardSignals(cmd)
	waitErr := cmd.Wait()
	timedOut := waitErr != nil && errors.Is(childCtx.Err(), context.DeadlineExceeded)
	leaked := cleanupProcess(cmd, o.Grace)
	stopSignals()
	if len(leaked) > 0 {
		e.Exec.LeakedPIDs = leaked
	}
	e.Exec.StdoutTail, e.Exec.StderrTail = stdout.String(), stderr.String()
	if opts.ProxyAuth != "" {
		e.Exec.StdoutTail = strings.ReplaceAll(e.Exec.StdoutTail, proxyURL, publicURL)
		e.Exec.StderrTail = strings.ReplaceAll(e.Exec.StderrTail, proxyURL, publicURL)
		e.Exec.StdoutTail = strings.ReplaceAll(e.Exec.StdoutTail, opts.ProxyAuth, "[redacted]")
		e.Exec.StderrTail = strings.ReplaceAll(e.Exec.StderrTail, opts.ProxyAuth, "[redacted]")
		if !o.JSON {
			fmt.Fprintln(os.Stdout, e.Exec.StdoutTail)
			fmt.Fprintln(os.Stderr, e.Exec.StderrTail)
		}
	}
	if cmd.ProcessState != nil {
		e.Exec.ExitCode = cmd.ProcessState.ExitCode()
	}
	waitErr = p.Wait(childCtx)
	e.Summary.RequestsTotal = p.RequestsTotal()
	stats := p.Stats()
	rules := append([]fault.Rule(nil), t.Rules...)
	for _, change := range t.ConfigChanges {
		rules = append(rules, change.Rules...)
	}
	seenRules := make(map[string]bool)
	for _, r := range rules {
		if seenRules[r.ID] {
			continue
		}
		seenRules[r.ID] = true
		n := stats[r.ID].Applied
		if n > 0 {
			e.FaultsTriggered = append(e.FaultsTriggered, map[string]any{"rule_id": r.ID, "type": r.Fault.Type, "count": n})
			e.Summary.FaultsTriggered += n
		}
	}
	if len(leaked) > 0 {
		return finish(3, "LEAKED_PIDS", fmt.Errorf("child processes remain: %v", leaked))
	}
	if timedOut {
		e.Exec.TimedOut = true
		return finish(124, "TIMEOUT", context.DeadlineExceeded)
	}
	if waitErr != nil {
		if errors.Is(waitErr, context.DeadlineExceeded) {
			e.Exec.TimedOut = true
			return finish(124, "TIMEOUT", waitErr)
		}
		return finish(3, "PROXY_WAIT_FAILED", waitErr)
	}
	results := assertions(ctx, t, "http://"+listener.Addr().String(), target, opts.ProxyAuth, bus.History(4096))
	e.SetResults(results)
	failed := e.Summary.AssertionsFailed > 0
	for _, x := range t.Expect.Faults {
		n := stats[x.Rule].Applied
		if x.MinApplied != nil && n < *x.MinApplied || x.MaxApplied != nil && n > *x.MaxApplied {
			failed = true
			e.SetResults([]tape.Result{{Name: "fault " + x.Rule, Failures: []string{fmt.Sprintf("applied count %d outside expected range", n)}}})
		}
	}
	expected := t.Expect.ChildExit
	matched := e.Exec.ExitCode == 0
	switch v := expected.(type) {
	case int:
		matched = e.Exec.ExitCode == v
	case string:
		if v == "any" {
			matched = true
		} else if v == "nonzero" {
			matched = e.Exec.ExitCode != 0
		} else if n, x := strconv.Atoi(v); x == nil {
			matched = e.Exec.ExitCode == n
		}
	}
	if !matched {
		e.Diff = append(e.Diff, fmt.Sprintf("child_exit: expected %v, got %d", expected, e.Exec.ExitCode))
	}
	if !matched || failed {
		return finish(1, "", nil)
	}
	return finish(0, "", nil)
}

type tail struct{ b []byte }

func (t *tail) Write(p []byte) (int, error) {
	n := len(p)
	t.b = append(t.b, p...)
	if len(t.b) > 4096 {
		t.b = append([]byte(nil), t.b[len(t.b)-4096:]...)
	}
	return n, nil
}
func (t *tail) String() string {
	b := bytes.ToValidUTF8(t.b, []byte("�"))
	for len(b) > 0 && !utf8.Valid(b) {
		b = b[1:]
	}
	return strings.TrimSpace(string(b))
}
