package execrun

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
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
	"slices"
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
	Command              []string
	TapePath             string
	Target               string
	Listen               string
	UI                   string
	Timeout              time.Duration
	Grace                time.Duration
	TLS                  bool
	CADir                string
	NoProxy              string
	UpstreamAllow        []string
	TLSPassthrough       []string
	UpstreamCA           string
	InsecureUpstream     bool
	ProxyAuth            bool
	JSON                 bool
	AllowRemote          bool
	AllowLoopbackEgress  bool
	AllowZeroTraffic     bool
	Seed                 *uint64
	Dir                  string
	DetachStdio          bool
	TailBytes            int
	RequireUpstreamAllow bool
	javaHome             bool
}
type Exec struct {
	Cmd                         []string           `json:"cmd"`
	ProxyURL                    string             `json:"proxy_url"`
	UIURL                       string             `json:"ui_url,omitempty"`
	ExitCode                    int                `json:"exit_code"`
	TimedOut                    bool               `json:"timed_out"`
	StdoutTail                  string             `json:"stdout_tail"`
	StderrTail                  string             `json:"stderr_tail"`
	StdoutBytes                 int64              `json:"stdout_bytes"`
	StderrBytes                 int64              `json:"stderr_bytes"`
	StdoutTruncated             bool               `json:"stdout_truncated,omitempty"`
	StderrTruncated             bool               `json:"stderr_truncated,omitempty"`
	Warnings                    []string           `json:"warnings,omitempty"`
	PID                         int                `json:"pid,omitempty"`
	LeakedPIDs                  []int              `json:"leaked_pids"`
	TLSHandshakeFailures        []json.RawMessage  `json:"tls_handshake_failures,omitempty"`
	TLSHandshakeFailureCount    uint64             `json:"tls_handshake_failure_count,omitempty"`
	TLSHandshakeFailuresOmitted uint64             `json:"tls_handshake_failures_omitted,omitempty"`
	NoProxy                     string             `json:"no_proxy"`
	NoProxyDropped              []string           `json:"no_proxy_dropped,omitempty"`
	Traffic                     proxy.TrafficStats `json:"traffic"`
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
	SchemaVersion      int                     `json:"schema_version"`
	Command            string                  `json:"command"`
	OK                 bool                    `json:"ok"`
	ExitCode           int                     `json:"exit_code"`
	Tape               string                  `json:"tape"`
	Target             *string                 `json:"target,omitempty"`
	DurationMS         int64                   `json:"duration_ms"`
	Summary            Summary                 `json:"summary"`
	FaultsTriggered    []any                   `json:"faults_triggered"`
	FrameErrors        []proxy.FrameErrorEntry `json:"frame_errors,omitempty"`
	FrameErrorsOmitted uint64                  `json:"frame_errors_omitted,omitempty"`
	Assertions         []Assertion             `json:"assertions"`
	Diff               []string                `json:"diff"`
	Exec               *Exec                   `json:"exec,omitempty"`
	Error              any                     `json:"error"`
}

func NewEnvelope(command, path, target string) Envelope {
	e := Envelope{SchemaVersion: 2, Command: command, Tape: path, FaultsTriggered: []any{}, Assertions: []Assertion{}, Diff: []string{}}
	if target == "" || target == "demo" {
		e.Target = &target
	} else if u, err := proxy.ParseExplicitTarget(target); err == nil {
		if authority := publicTargetAuthority(u, false); authority != "" {
			public := u.Scheme + "://" + authority
			e.Target = &public
		}
	}
	return e
}

func publicTargetAuthority(u *url.URL, includeDefaultPort bool) string {
	host := proxy.DiagnosticHostname(u.Hostname())
	if host == "" {
		return ""
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return ""
		}
		return net.JoinHostPort(host, strconv.FormatUint(n, 10))
	}
	if includeDefaultPort {
		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
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
	o.javaHome = os.Getenv("JAVA_HOME") != ""
	o.TLS = o.TLS || t.TLSMITM
	target := t.Target
	if o.Target != "" {
		target = o.Target
	}
	e := NewEnvelope("exec", o.TapePath, target)
	e.Exec = &Exec{Cmd: o.Command}
	warn := func(message string) {
		if !o.DetachStdio {
			fmt.Fprintln(os.Stderr, message)
			return
		}
		if len(e.Exec.Warnings) < 16 {
			message = strings.ToValidUTF8(message, "�")
			if len(message) > 512 {
				message = message[:512]
				for !utf8.ValidString(message) {
					message = message[:len(message)-1]
				}
			}
			e.Exec.Warnings = append(e.Exec.Warnings, message)
		}
	}
	var caWarn func(string)
	if o.DetachStdio {
		caWarn = warn
	}
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
		if o.Target != "" {
			parsed, err = proxy.ParseExplicitTarget(target)
		} else {
			parsed, err = proxy.ParseTarget(target)
			if err != nil {
				if _, explicitErr := proxy.ParseExplicitTarget(target); explicitErr == nil {
					err = fmt.Errorf("%w; for forward mode, omit target and use --tls with tape upstream_allow or --upstream-allow", err)
				}
			}
		}
		if err != nil {
			e.Target = nil
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
	var tlsFailures tlsFailureEvidence
	var hosts trafficHosts
	bus.SetObserver(func(event telemetry.Event) {
		evidence.observe(event)
		tlsFailures.observe(event)
		hosts.observe(event)
	})
	p := proxy.New(parsed, fault.Config{Seed: seed, Rules: t.Rules}, bus)
	var frameErrors proxy.FrameErrorLog
	p.OnOutcome = frameErrors.Observe
	p.SetSeq(t.StartSeq)
	defer p.Close()
	opts := proxy.Options{Demo: demoHandler != nil, UpstreamAllow: append(t.UpstreamAllow, o.UpstreamAllow...), TLSPassthrough: append(append([]string{}, t.TLSPassthrough...), o.TLSPassthrough...), InsecureUpstream: o.InsecureUpstream, AllowLoopbackEgress: o.AllowLoopbackEgress, RequireUpstreamAllow: o.RequireUpstreamAllow}
	opts.SuppressStderr = o.DetachStdio
	for i, pattern := range opts.TLSPassthrough {
		if err := proxy.ValidatePassthrough(pattern); err != nil {
			return finish(2, "USAGE_ERROR", fmt.Errorf("tls_passthrough[%d]: %v: %q", i, err, strings.TrimSpace(pattern)))
		}
	}
	if len(opts.TLSPassthrough) > 0 && !o.TLS {
		warn("tls-passthrough has no effect without --tls")
	}
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
	opts.OnReset = func() {
		tlsFailures.reset()
		hosts.reset()
		frameErrors.Reset()
	}
	var system, sslCerts []byte
	if o.TLS || o.UpstreamCA != "" || os.Getenv("SSL_CERT_FILE") != "" || os.Getenv("SSL_CERT_DIR") != "" {
		system = systemPEM()
		sslCerts = inheritedCerts("SSL_CERT_FILE", caWarn)
		opts.UpstreamCA = proxyRoots(system, sslCerts)
	}
	if o.UpstreamCA != "" {
		data, x := os.ReadFile(o.UpstreamCA)
		if x != nil {
			return finish(3, "CA_ERROR", x)
		}
		if !opts.UpstreamCA.AppendCertsFromPEM(data) {
			return finish(3, "CA_ERROR", fmt.Errorf("invalid CA certificate"))
		}
	}
	env := []string{}
	if o.TLS {
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
		inherited := [][]byte{sslCerts}
		var node []byte
		if len(sslCerts) > 0 && len(opts.TLSPassthrough) > 0 {
			if _, set := os.LookupEnv("NODE_USE_SYSTEM_CA"); !set {
				env = append(env, "NODE_USE_SYSTEM_CA=1")
			}
		}
		for _, name := range []string{
			"REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
			"GRPC_DEFAULT_SSL_ROOTS_FILE_PATH", "AWS_CA_BUNDLE", "DENO_CERT", "GIT_SSL_CAINFO", "PIP_CERT", "NPM_CONFIG_CAFILE", "CARGO_HTTP_CAINFO",
		} {
			certs := inheritedCerts(name, caWarn)
			inherited = append(inherited, certs)
			if name == "NODE_EXTRA_CA_CERTS" {
				node = certs
			}
		}
		inherited = append(inherited, ca.PEM)
		nodePath := filepath.Join(dir, "node-extra.pem")
		if x = os.WriteFile(bundle, certBundleWithSystem(system, inherited...), 0600); x != nil {
			return finish(3, "CA_ERROR", x)
		}
		if x = os.WriteFile(nodePath, certBundle(node, ca.PEM), 0600); x != nil {
			return finish(3, "CA_ERROR", x)
		}
		env = append(env, "GLITCHDECK_CA_CERT="+cert, "NODE_EXTRA_CA_CERTS="+nodePath, "SSL_CERT_FILE="+bundle, "REQUESTS_CA_BUNDLE="+bundle, "CURL_CA_BUNDLE="+bundle, "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH="+bundle, "AWS_CA_BUNDLE="+bundle, "DENO_CERT="+bundle, "GIT_SSL_CAINFO="+bundle, "PIP_CERT="+bundle, "NPM_CONFIG_CAFILE="+bundle, "CARGO_HTTP_CAINFO="+bundle)
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
	if o.DetachStdio {
		e.Exec.NoProxy = listenerAddr
		if os.Getenv("NO_PROXY") != "" || os.Getenv("no_proxy") != "" {
			warn("no_proxy: ignored inherited bypass entries")
		}
	} else {
		var dropped []string
		noProxy, dropped = mergeNoProxy(os.Getenv("NO_PROXY"), os.Getenv("no_proxy"), o.NoProxy, listenerAddr, parsed)
		safeTarget := "(forward-only)"
		if parsed != nil {
			safeTarget = "(unreported)"
			if authority := publicTargetAuthority(parsed, false); authority != "" {
				safeTarget = parsed.Scheme + "://" + authority
			}
		}
		e.Exec.NoProxy, e.Exec.NoProxyDropped = reportNoProxy(noProxy), dropped
		for _, entry := range dropped {
			warn(fmt.Sprintf("no_proxy: dropped %q from inherited NO_PROXY; it would bypass glitchdeck for target %s (pass --no-proxy %s to keep it)", entry, safeTarget, entry))
		}
	}
	env = append(env, "GLITCHDECK_PROXY_URL="+proxyURL, "GLITCHDECK_TARGET="+target, "HTTP_PROXY="+proxyURL, "http_proxy="+proxyURL, "HTTPS_PROXY="+proxyURL, "https_proxy="+proxyURL, "NO_PROXY="+noProxy, "no_proxy="+noProxy, "NODE_USE_ENV_PROXY=1")
	if e.Exec.UIURL != "" {
		env = append(env, "GLITCHDECK_UI_URL="+e.Exec.UIURL)
	}
	childCtx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	cmd := exec.CommandContext(childCtx, o.Command[0], o.Command[1:]...)
	cmd.Dir = o.Dir
	if o.DetachStdio {
		cmd.Env = append(cmd.Environ(), env...)
	} else {
		cmd.Env = append(os.Environ(), env...)
		cmd.Stdin = os.Stdin
	}
	limit := o.TailBytes
	if limit <= 0 {
		limit = 4096
	}
	stdout := tail{limit: limit, boundUTF8: o.DetachStdio}
	stderr := stdout
	if o.JSON || o.ProxyAuth || o.DetachStdio {
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
	} else {
		cmd.Stdout = io.MultiWriter(os.Stdout, &stdout)
		cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
	}
	if err = setupProcess(cmd, o.Grace); err != nil {
		return finish(3, "PROCESS_SETUP_FAILED", err)
	}
	var reportReader, reportWriter *os.File
	var detached *detachedHelper
	if o.DetachStdio {
		detached, err = isolateDetachedProcess(cmd, o.Grace)
		if detached != nil {
			defer detached.close()
			reportReader = detached.reportReader
		}
	} else {
		reportReader, reportWriter, err = isolateProcess(cmd, o.Grace)
		if reportReader != nil {
			defer reportReader.Close()
		}
	}
	if err != nil {
		return finish(3, "PROCESS_SETUP_FAILED", err)
	}
	ready := make(chan struct{})
	authorized := false
	if reportReader != nil {
		cancelProcess := cmd.Cancel
		cmd.Cancel = func() error {
			<-ready
			if detached != nil && !authorized {
				return cmd.Process.Kill()
			}
			return cancelProcess()
		}
	}
	var startSignals func(*exec.Cmd)
	if !o.DetachStdio {
		relayGrace := o.Grace
		if reportReader != nil {
			relayGrace = 0
		}
		var stopSignals func()
		startSignals, stopSignals = forwardSignals(relayGrace)
		defer stopSignals()
	}
	err = cmd.Start()
	if detached != nil {
		detached.afterStart()
	}
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
	}
	if detached != nil {
		err = detached.authorize(childCtx, helperOutput)
		authorized = err == nil
		close(ready)
		var pid int
		if authorized {
			pid, err = detached.readPID(childCtx, helperOutput)
		}
		if err != nil {
			timedOut := errors.Is(childCtx.Err(), context.DeadlineExceeded)
			cancel()
			_ = cmd.Wait()
			if timedOut {
				e.Exec.TimedOut = true
				return finish(124, "TIMEOUT", context.DeadlineExceeded)
			}
			return finish(3, "PROCESS_SETUP_FAILED", err)
		}
		if pid > 0 {
			e.Exec.PID = pid
		}
	} else {
		if helperOutput != nil {
			line, _ := helperOutput.ReadString('\n')
			if pid, err := strconv.Atoi(strings.TrimSpace(line)); err == nil && pid > 0 {
				e.Exec.PID = pid
			}
		}
		close(ready)
	}
	if startSignals != nil {
		startSignals(cmd)
	}
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
	if len(leaked) > 0 {
		e.Exec.LeakedPIDs = leaked
	}
	e.Exec.StdoutTail, e.Exec.StderrTail = stdout.String(), stderr.String()
	e.Exec.StdoutBytes, e.Exec.StderrBytes = stdout.total, stderr.total
	e.Exec.StdoutTruncated, e.Exec.StderrTruncated = stdout.total > int64(limit), stderr.total > int64(limit)
	if opts.ProxyAuth != "" {
		e.Exec.StdoutTail = strings.ReplaceAll(e.Exec.StdoutTail, proxyURL, publicURL)
		e.Exec.StderrTail = strings.ReplaceAll(e.Exec.StderrTail, proxyURL, publicURL)
		e.Exec.StdoutTail = strings.ReplaceAll(e.Exec.StdoutTail, opts.ProxyAuth, "[redacted]")
		e.Exec.StderrTail = strings.ReplaceAll(e.Exec.StderrTail, opts.ProxyAuth, "[redacted]")
		if !o.JSON && !o.DetachStdio {
			fmt.Fprintln(os.Stdout, e.Exec.StdoutTail)
			fmt.Fprintln(os.Stderr, e.Exec.StderrTail)
		}
	}
	if cmd.ProcessState != nil {
		e.Exec.ExitCode = cmd.ProcessState.ExitCode()
	}
	httpTape := t
	httpTape.Assertions = nil
	proxyAssertions := false
	for _, a := range t.Assertions {
		if a.HTTPGet != "" {
			httpTape.Assertions = append(httpTape.Assertions, a)
			proxyAssertions = proxyAssertions || !a.Direct
		}
	}
	assertCtx := ctx
	var limits *assertionLimits
	if o.DetachStdio {
		assertCtx = childCtx
		limits = &assertionLimits{remaining: 64 << 10, dial: p.DialContext}
	}
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), o.Grace)
	defer cancelDrain()
	waitErr = p.Drain(drainCtx)
	// TrafficStats snapshots counters and denied hosts together, even on timeout.
	childStats := p.TrafficStats()
	childFaults := p.AppliedFaults()
	var httpResults []tape.Result
	if waitErr == nil {
		probeURL, probePassword := "", ""
		if proxyAssertions {
			var stop func()
			probeURL, probePassword, stop, waitErr = startAssertionProxy(p, opts.ProxyAuth)
			if stop != nil {
				defer stop()
			}
		}
		if waitErr == nil {
			httpResults = assertions(assertCtx, httpTape, probeURL, target, probePassword, nil, limits, opts.UpstreamCA)
			if o.DetachStdio {
				waitCtx, cancelWait := context.WithTimeout(assertCtx, o.Grace)
				waitErr = p.Wait(waitCtx)
				cancelWait()
			} else {
				waitErr = p.Wait(drainCtx)
			}
		}
	}
	e.Summary.RequestsTotal = p.RequestsTotal()
	e.SetAppliedFaults(p.AppliedFaults())
	e.FrameErrors, e.FrameErrorsOmitted = frameErrors.Snapshot()
	e.Exec.TLSHandshakeFailureCount, e.Exec.TLSHandshakeFailures = tlsFailures.snapshot()
	e.Exec.TLSHandshakeFailuresOmitted = e.Exec.TLSHandshakeFailureCount - uint64(len(e.Exec.TLSHandshakeFailures))
	e.Exec.Traffic = childStats
	deniedList := strings.Join(childStats.EgressDeniedHosts, ", ")
	if deniedList != "" {
		warn(fmt.Sprintf("warning: egress denied %d (hosts: %s)", childStats.EgressDenied, deniedList))
	}
	if len(leaked) > 0 {
		return finish(3, "LEAKED_PIDS", fmt.Errorf("child processes remain: %v", leaked))
	}
	if timedOut || o.DetachStdio && errors.Is(childCtx.Err(), context.DeadlineExceeded) {
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
	results := append(httpResults, assertions(assertCtx, protocolTape, "", target, "", evidence.history(), limits)...)
	if o.DetachStdio && errors.Is(childCtx.Err(), context.DeadlineExceeded) {
		e.Exec.TimedOut = true
		return finish(124, "TIMEOUT", context.DeadlineExceeded)
	}
	e.SetResults(results)
	if limits != nil && limits.omitted != 0 {
		e.Diff = append(e.Diff, fmt.Sprintf("diagnostics omitted for %d assertions", limits.omitted))
	}
	failed := e.Summary.AssertionsFailed > 0
	if childStats.ReverseDialFailed > 0 {
		targetHost := ""
		if authority := publicTargetAuthority(parsed, true); authority != "" {
			targetHost = " " + authority
		}
		e.Diff = append(e.Diff, fmt.Sprintf("target%s unreachable: is your app running / is the port right? (%d dial failure(s))", targetHost, childStats.ReverseDialFailed))
		failed = true
	}
	innerOK := childStats.InnerUsable > 0
	tlsOnly := childStats.TLSRejected > 0 && !innerOK && childStats.PassthroughOK+childStats.BlindOK == 0
	// Denied replicas are report evidence, not a new denied-only verdict input.
	deniedOnly := childStats.EgressDenied > childStats.ReplayAdmissionDenied && !innerOK && childStats.InterceptedOK+childStats.PassthroughOK+childStats.BlindOK == 0
	tlsHosts := hosts.tlsList()
	if opts.ProxyAuth != "" {
		tlsHosts = strings.ReplaceAll(tlsHosts, opts.ProxyAuth, "[redacted]")
	}
	if childStats.TLSRejected > 0 && innerOK {
		warn(fmt.Sprintf("warning: tls_rejected: %d handshake(s) failed for hosts %s", childStats.TLSRejected, tlsHosts))
	}
	if !o.AllowZeroTraffic {
		if tlsOnly {
			line := fmt.Sprintf("tls_rejected_only: %d CONNECT tunnel(s) reached glitchdeck but the client rejected the interception certificate (hosts: %s); trust $GLITCHDECK_CA_CERT in the client, or add pinned hosts to --tls-passthrough", childStats.TLSRejected, tlsHosts)
			e.Diff = append(e.Diff, strings.Join(append([]string{line}, hint(o, o.Command, parsed, childStats)...), "; "))
			failed = true
		} else if deniedOnly {
			e.Diff = append(e.Diff, fmt.Sprintf("egress_denied_only: %d request(s) blocked by upstream egress policy (hosts: %s); check the upstream allowlist (--upstream-allow or tape upstream_allow) and the listener's resolved-address policy", childStats.EgressDenied, deniedList))
			failed = true
		} else if childStats.RequestsTotal == 0 {
			line := "zero_traffic: no requests reached the proxy; check HTTP(S)_PROXY bypass (Go ignores proxies for localhost/127.0.0.1) and CA trust"
			e.Diff = append(e.Diff, strings.Join(append([]string{line}, hint(o, o.Command, parsed, childStats)...), "; "))
			failed = true
		} else if (childStats.InterceptedEmpty > 0 || childStats.InterceptedOK > 0 && childStats.InnerRequests == 0) && !innerOK && childStats.PassthroughOK+childStats.BlindOK == 0 {
			e.Diff = append(e.Diff, "no_usable_traffic: intercepted CONNECT closed without usable application traffic; check client proxy configuration and CA trust")
			failed = true
		} else if !slices.ContainsFunc(childFaults, func(f proxy.AppliedFault) bool { return f.Count != 0 }) && len(t.Rules)+len(t.ConfigChanges) != 0 {
			rules := make(map[string]bool)
			for _, rule := range t.Rules {
				if rule.Enabled {
					rules[rule.ID] = true
				}
			}
			for _, change := range t.ConfigChanges {
				for _, rule := range change.Rules {
					if rule.Enabled {
						rules[rule.ID] = true
					}
				}
			}
			for _, x := range t.Expect.Faults {
				if (x.MinApplied != nil && *x.MinApplied == 0) || (x.MinApplied == nil && x.MaxApplied != nil) {
					delete(rules, x.Rule)
				}
			}
			if len(rules) > 0 {
				e.Diff = append(e.Diff, "zero_faults: no faults triggered; check rule matching, proxy bypass and CA trust")
				failed = true
			}
		}
	}
	var childCounts map[string]uint64
	if len(t.Expect.Faults) != 0 {
		childCounts = make(map[string]uint64, len(childFaults))
		for _, f := range childFaults {
			childCounts[f.RuleID] += f.Count
		}
	}
	for _, x := range t.Expect.Faults {
		n := childCounts[x.Rule]
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

func startAssertionProxy(p *proxy.Proxy, proxyPassword string) (addr, password string, closeServer func(), err error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", nil, err
	}
	password = rand.Text()
	probeAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("glitchdeck:"+password))
	proxyAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("glitchdeck:"+proxyPassword))
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Proxy-Authorization")), []byte(probeAuth)) != 1 {
			http.Error(w, "assertion proxy authentication required", http.StatusForbidden)
			return
		}
		r.Header.Del("Proxy-Authorization")
		if proxyPassword != "" {
			r.Header.Set("Proxy-Authorization", proxyAuth)
		}
		p.ServeProbeHTTP(w, r)
	})}
	go server.Serve(listener)
	return "http://" + listener.Addr().String(), password, func() {
		_ = server.Close()
		_ = listener.Close()
	}, nil
}

type tail struct {
	b         []byte
	limit     int
	boundUTF8 bool
	total     int64
}

func (t *tail) Write(p []byte) (int, error) {
	n := len(p)
	t.total += int64(n)
	if t.limit <= 0 {
		t.limit = 4096
	}
	if t.b == nil {
		t.b = make([]byte, 0, 2*t.limit)
	}
	if len(p) >= t.limit {
		t.b = append(t.b[:0], p[len(p)-t.limit:]...)
		return n, nil
	}
	if len(t.b)+len(p) > 2*t.limit {
		copy(t.b, t.b[len(t.b)-t.limit:])
		t.b = t.b[:t.limit]
	}
	t.b = append(t.b, p...)
	return n, nil
}

func (t *tail) String() string {
	b := t.b
	if len(b) > t.limit {
		b = b[len(b)-t.limit:]
	}
	if !utf8.Valid(b) {
		b = bytes.ToValidUTF8(b, []byte("�"))
		if t.boundUTF8 && len(b) > t.limit {
			b = b[len(b)-t.limit:]
			for len(b) != 0 && !utf8.RuneStart(b[0]) {
				b = b[1:]
			}
		}
	}
	return strings.TrimSpace(string(b))
}
