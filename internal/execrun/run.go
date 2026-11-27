package execrun

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

type helperReport struct {
	Leaked     []int  `json:"leaked"`
	SpawnCode  int    `json:"spawn_code"`
	SpawnError string `json:"spawn_error"`
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
	evidence := newAssertionEvidence(t)
	bus.SetObserver(evidence.observe)
	p := proxy.New(parsed, fault.Config{Seed: seed, Rules: t.Rules}, bus)
	p.SetSeq(t.StartSeq)
	defer p.Close()
	opts := proxy.Options{Demo: demoHandler != nil, UpstreamAllow: append(t.UpstreamAllow, o.UpstreamAllow...), InsecureUpstream: o.InsecureUpstream}
	var scheduleStart time.Time
	var configMu sync.Mutex
	applied := make([]bool, len(t.ConfigChanges))
	applyChanges := func(seq uint64) {
		configMu.Lock()
		defer configMu.Unlock()
		for i, change := range t.ConfigChanges {
			if applied[i] {
				continue
			}
			due := change.AtMS != nil && time.Since(scheduleStart) >= time.Duration(*change.AtMS)*time.Millisecond
			if change.AtMS == nil {
				due = seq != 0 && seq >= change.BeforeSeq
			}
			if due {
				p.SetConfig(fault.Config{Seed: change.Seed, Rules: change.Rules})
				applied[i] = true
			}
		}
	}
	opts.BeforeRequest = applyChanges
	opts.OnAdmission = evidence.admit
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
		if x = writeCABundle(bundle, data, ca.PEM); x != nil {
			return finish(3, "CA_ERROR", x)
		}
		env = append(env, "GLITCHDECK_CA_CERT="+cert, "NODE_EXTRA_CA_CERTS="+cert, "SSL_CERT_FILE="+bundle, "REQUESTS_CA_BUNDLE="+bundle, "CURL_CA_BUNDLE="+bundle, "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH="+bundle, "AWS_CA_BUNDLE="+bundle)
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
	listenerAddr := listener.Addr().String()
	proxyURL := "http://" + listenerAddr
	publicURL := proxyURL
	if o.ProxyAuth {
		var token [24]byte
		if _, err = rand.Read(token[:]); err != nil {
			return finish(3, "PROXY_START_FAILED", err)
		}
		opts.ProxyAuth = hex.EncodeToString(token[:])
		proxyURL = "http://glitchdeck:" + opts.ProxyAuth + "@" + listenerAddr
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
	scheduleStart = time.Now()
	scheduleCtx, stopSchedule := context.WithCancel(ctx)
	defer stopSchedule()
	for _, change := range t.ConfigChanges {
		if change.AtMS == nil {
			continue
		}
		at := *change.AtMS
		go func() {
			timer := time.NewTimer(time.Until(scheduleStart.Add(time.Duration(at) * time.Millisecond)))
			defer timer.Stop()
			select {
			case <-timer.C:
				applyChanges(0)
			case <-scheduleCtx.Done():
			}
		}()
	}
	go p.Serve(listener)
	noProxy := listenerAddr
	if o.NoProxy != "" {
		noProxy = o.NoProxy + "," + noProxy
	}
	env = append(env, "GLITCHDECK_PROXY_URL="+proxyURL, "GLITCHDECK_TARGET="+target, "HTTP_PROXY="+proxyURL, "http_proxy="+proxyURL, "HTTPS_PROXY="+proxyURL, "https_proxy="+proxyURL, "NO_PROXY="+noProxy, "no_proxy="+noProxy, "NODE_USE_ENV_PROXY=1")
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
	reportReader, reportWriter, err := isolateProcess(cmd, o.Grace)
	if err != nil {
		return finish(3, "PROCESS_SETUP_FAILED", err)
	}
	if reportReader != nil {
		defer reportReader.Close()
	}
	ready := make(chan struct{})
	if reportReader != nil {
		cancelProcess := cmd.Cancel
		cmd.Cancel = func() error {
			<-ready
			return cancelProcess()
		}
	}
	relayGrace := o.Grace
	if reportReader != nil {
		relayGrace = 0
	}
	startSignals, stopSignals := forwardSignals(relayGrace)
	defer stopSignals()
	err = cmd.Start()
	if reportWriter != nil {
		_ = reportWriter.Close()
	}
	if err != nil {
		close(ready)
	}
	if err != nil {
		code := 125
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			code = 127
		} else if errors.Is(err, os.ErrPermission) {
			code = 126
		}
		if code == 127 && !strings.ContainsRune(o.Command[0], os.PathSeparator) {
			for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
				if dir == "" {
					dir = "."
				}
				info, statErr := os.Stat(filepath.Join(dir, o.Command[0]))
				if statErr == nil && !info.IsDir() && info.Mode().Perm()&0111 == 0 {
					code = 126
					break
				}
			}
		}
		return finish(code, "EXEC_SPAWN_FAILED", err)
	}
	e.Exec.PID = cmd.Process.Pid
	var helperOutput *bufio.Reader
	if reportReader != nil {
		helperOutput = bufio.NewReader(reportReader)
		line, _ := helperOutput.ReadString('\n')
		if pid, err := strconv.Atoi(strings.TrimSpace(line)); err == nil && pid > 0 {
			e.Exec.PID = pid
		}
	}
	close(ready)
	startSignals(cmd)
	waitErr := cmd.Wait()
	timedOut := waitErr != nil && errors.Is(childCtx.Err(), context.DeadlineExceeded)
	leaked := cleanupProcess(cmd, o.Grace)
	var helper helperReport
	if reportReader != nil {
		if err := json.NewDecoder(helperOutput).Decode(&helper); err != nil {
			return finish(3, "PROCESS_CLEANUP_FAILED", fmt.Errorf("missing process cleanup result: %w", err))
		}
		leaked = helper.Leaked
	}
	if helper.SpawnCode != 0 {
		return finish(helper.SpawnCode, "EXEC_SPAWN_FAILED", errors.New(helper.SpawnError))
	}
	cancel()
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
	httpTape := t
	httpTape.Assertions = nil
	for _, a := range t.Assertions {
		if a.HTTPGet != "" {
			httpTape.Assertions = append(httpTape.Assertions, a)
		}
	}
	httpResults := assertions(ctx, httpTape, "http://"+listener.Addr().String(), target, opts.ProxyAuth, nil)
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), o.Grace)
	waitErr = p.Drain(drainCtx)
	cancelDrain()
	e.Summary.RequestsTotal = p.RequestsTotal()
	stats := p.Stats()
	e.SetAppliedFaults(p.AppliedFaults())
	if len(leaked) > 0 {
		return finish(3, "LEAKED_PIDS", fmt.Errorf("child processes remain: %v", leaked))
	}
	if timedOut {
		e.Exec.TimedOut = true
		return finish(124, "TIMEOUT", context.DeadlineExceeded)
	}
	if waitErr != nil {
		return finish(3, "PROXY_WAIT_FAILED", waitErr)
	}
	protocolTape := t
	protocolTape.Assertions = nil
	for _, a := range t.Assertions {
		if a.HTTPGet == "" {
			protocolTape.Assertions = append(protocolTape.Assertions, a)
		}
	}
	results := append(httpResults, assertions(ctx, protocolTape, "", target, opts.ProxyAuth, evidence.history())...)
	e.SetResults(results)
	failed := e.Summary.AssertionsFailed > 0
	for _, x := range t.Expect.Faults {
		n := stats[x.Rule].Applied
		result := tape.Result{Name: "fault " + x.Rule, Failures: []string{}}
		if x.MinApplied != nil && n < *x.MinApplied || x.MaxApplied != nil && n > *x.MaxApplied {
			failed = true
			result.Failures = append(result.Failures, fmt.Sprintf("applied count %d outside expected range", n))
		}
		e.SetResults([]tape.Result{result})
	}
	expected := t.Expect.ChildExit
	if expected == nil {
		expected = 0
	}
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

func writeCABundle(path string, data, ca []byte) error {
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	return os.WriteFile(path, append(data, ca...), 0600)
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
