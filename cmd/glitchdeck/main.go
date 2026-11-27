package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hardw00t/glitchdeck/internal/cli"
	"github.com/hardw00t/glitchdeck/internal/demo"
	"github.com/hardw00t/glitchdeck/internal/execrun"
	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/tape"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
	"github.com/hardw00t/glitchdeck/internal/tlsmitm"
	"github.com/hardw00t/glitchdeck/internal/ui"
)

func main() { os.Exit(run(os.Args[1:])) }

const usage = "usage: glitchdeck demo|proxy|test|exec|mcp|ca|report|validate|version"

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprintln(os.Stdout, usage)
		return 0
	case "validate":
		return validateCommand(args[1:])
	case "demo":
		return serve(args[1:], true)
	case "proxy":
		return serve(args[1:], false)
	case "test":
		return testTape(args[1:])
	case "exec":
		return execCommand(args[1:])
	case "mcp":
		return mcpCommand(args[1:])
	case "ca":
		return caCommand(args[1:])
	case "version", "--version", "-v":
		return versionCommand(args[1:])
	case "report":
		return reportCommand(args[1:])
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", args[0])
		return 2
	}
}

// Check for help before parsing so it also works after positional arguments.
func showCommandHelp(f *flag.FlagSet, args []string, usage string) bool {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		name, ok := strings.CutPrefix(arg, "-")
		if !ok {
			continue
		}
		name, _, assigned := strings.Cut(strings.TrimPrefix(name, "-"), "=")
		if name == "h" || name == "help" {
			f.SetOutput(os.Stdout)
			f.Usage = func() {
				fmt.Fprintln(f.Output(), usage)
				f.PrintDefaults()
			}
			return f.Parse(args[i:i+1]) == flag.ErrHelp
		}
		if option := f.Lookup(name); !assigned && option != nil {
			if b, ok := option.Value.(interface{ IsBoolFlag() bool }); !ok || !b.IsBoolFlag() {
				if i+1 < len(args) && args[i+1] == "--" {
					break
				}
				i++
			}
		}
	}
	return false
}

func testTape(args []string) int {
	f := flag.NewFlagSet("test", flag.ContinueOnError)
	wantJSON := cli.JSONRequested(args)
	if wantJSON {
		f.SetOutput(io.Discard)
	}
	target := f.String("target", "", "override target")
	timeout := f.Duration("timeout", 30*time.Second, "run timeout")
	asJSON := f.Bool("json", false, "JSON output")
	report := f.String("report", "", "write JSON report")
	tlsEnabled := f.Bool("tls", false, "enable TLS")
	caDir := f.String("ca-dir", "", "CA directory")
	const testUsage = "usage: glitchdeck test [flags] tape.yaml"
	if showCommandHelp(f, args, testUsage) {
		return 0
	}
	flags, files := cli.SplitArgs(args, "target", "timeout", "report", "ca-dir")
	filename := ""
	if len(files) == 1 {
		filename = files[0]
	}
	version := 0
	fail := func(machine string, err error) int {
		e := execrun.NewEnvelope("test", filename, *target)
		e.ExitCode = 2
		e.Error = map[string]string{"code": machine, "message": err.Error()}
		if *report != "" {
			if err := execrun.WriteReport(*report, e); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}
		if wantJSON {
			if version != 1 {
				_ = json.NewEncoder(os.Stdout).Encode(e)
			}
			cli.Error(os.Stderr, strings.ToLower(machine), err, 2)
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		return 2
	}
	if err := f.Parse(flags); err != nil {
		return fail("USAGE", err)
	}
	if filename == "" || *timeout <= 0 {
		return fail("USAGE", errors.New(testUsage))
	}
	file, err := os.Open(filename)
	if err != nil {
		return fail("TAPE_IO", err)
	}
	t, err := tape.Decode(file)
	file.Close()
	if err != nil {
		return fail("TAPE_INVALID", err)
	}
	version = t.Version
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	results, runReport, err := tape.RunWithTLS(ctx, t, *target, *caDir, *tlsEnabled)
	if err != nil {
		return fail("INTERNAL", err)
	}
	failed := false
	for _, r := range results {
		if len(r.Failures) > 0 {
			failed = true
		}
	}
	code := 0
	if failed {
		code = 1
	}
	envelope := execrun.NewEnvelope("test", filename, t.Target)
	if *target != "" {
		envelope.Target = *target
	}
	envelope.ExitCode = code
	envelope.OK = !failed
	envelope.DurationMS = time.Since(started).Milliseconds()
	envelope.SetResults(results)
	envelope.Summary.RequestsTotal = runReport.RequestsTotal
	envelope.SetAppliedFaults(runReport.AppliedFaults)
	if *report != "" {
		if e := execrun.WriteReport(*report, envelope); e != nil {
			return fail("TAPE_IO", e)
		}
	}
	if *asJSON {
		var output any = results
		if t.Version >= 2 {
			output = envelope
		}
		if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	} else {
		for _, r := range results {
			if len(r.Failures) == 0 {
				fmt.Printf("PASS %s\n", r.Name)
			} else {
				fmt.Printf("FAIL %s: %s\n", r.Name, strings.Join(r.Failures, "; "))
			}
		}
	}
	if failed {
		return 1
	}
	return 0
}
func serve(args []string, isDemo bool) int {
	name := "proxy"
	if isDemo {
		name = "demo"
	}
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	wantJSON := cli.JSONRequested(args)
	if wantJSON {
		f.SetOutput(io.Discard)
	}
	fail := func(machine string, err error) int {
		if wantJSON {
			cli.Error(os.Stderr, machine, err, 2)
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		return 2
	}
	listen := f.String("listen", "127.0.0.1:8080", "proxy listener")
	uiAddr := f.String("ui", "127.0.0.1:8081", "control listener")
	app := f.String("app", "127.0.0.1:3000", "demo listener")
	target := f.String("target", "", "loopback upstream")
	tapePath := f.String("tape", "", "initial tape")
	seed := f.Uint64("seed", 1, "fault seed")
	open := f.Bool("open", false, "open control UI")
	tlsEnabled := f.Bool("tls", isDemo, "enable TLS interception")
	caDir := f.String("ca-dir", "", "CA directory")
	asJSON := f.Bool("json", false, "stream JSON events")
	var upstreamAllow listFlag
	f.Var(&upstreamAllow, "upstream-allow", "allow upstream")
	var passthrough listFlag
	f.Var(&passthrough, "tls-passthrough", "tunnel matching TLS hosts without interception")
	upstreamCA := f.String("upstream-ca", "", "upstream CA")
	insecure := f.Bool("insecure-upstream", false, "skip upstream TLS verification")
	alpn := f.String("mitm-alpn", "", "MITM ALPN")
	h2tap := f.String("h2-tap", "on", "HTTP/2 tap")
	sseMax := f.Int("sse-telemetry-max", 512, "SSE telemetry limit")
	allowRemote := f.Bool("allow-remote", false, "allow remote listener")
	allowLoopbackEgress := f.Bool("allow-loopback-egress", false, "allow loopback, link-local and unspecified upstream addresses on non-loopback proxy listeners")
	if showCommandHelp(f, args, "usage: glitchdeck "+name+" [flags]") {
		return 0
	}
	if err := f.Parse(args); err != nil {
		return fail("usage", err)
	}
	if f.NArg() != 0 || *sseMax < 0 || (*alpn != "" && *alpn != "h1" && *alpn != "h2") || (*h2tap != "on" && *h2tap != "off") {
		return fail("usage", errors.New("unexpected argument or invalid protocol option"))
	}
	for i, pattern := range passthrough {
		if err := proxy.ValidatePassthrough(pattern); err != nil {
			return fail("usage", fmt.Errorf("tls_passthrough[%d]: %v: %q", i, err, strings.TrimSpace(pattern)))
		}
	}
	cfg := fault.Config{Seed: *seed}
	var startSeq uint64
	if *tapePath != "" {
		file, e := os.Open(*tapePath)
		if e != nil {
			return fail("tape_io", e)
		}
		t, e := tape.Decode(file)
		file.Close()
		if e != nil {
			return fail("tape_invalid", e)
		}
		cfg = fault.Config{Seed: t.Seed, Rules: t.Rules}
		startSeq = t.StartSeq
		passthrough = append(passthrough, t.TLSPassthrough...)
	}
	if len(passthrough) != 0 && !*tlsEnabled {
		fmt.Fprintln(os.Stderr, "tls-passthrough has no effect without --tls")
	}
	for _, endpoint := range []string{*listen, *uiAddr} {
		if !cli.Loopback(endpoint) {
			if *tlsEnabled && !*allowRemote {
				return fail("listen_not_loopback", errors.New("TLS listeners must be loopback unless --allow-remote is set"))
			}
			fmt.Fprintln(os.Stderr, "warning: non-loopback listener:", endpoint)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var appListener net.Listener
	var err error
	if isDemo {
		host, port, e := net.SplitHostPort(*app)
		n, portErr := strconv.Atoi(port)
		if e != nil || portErr != nil || n < 0 || n > 65535 {
			return fail("usage", errors.New("invalid demo listener"))
		}
		if _, e = proxy.ParseTarget("http://" + net.JoinHostPort(host, "1")); e != nil {
			return fail("listen_not_loopback", e)
		}
		appListener, err = net.Listen("tcp", *app)
		if err != nil {
			return fail("listen_failed", err)
		}
		defer appListener.Close()
		*target = "http://" + appListener.Addr().String()
	}
	u, err := proxy.ParseExplicitTarget(*target)
	if err != nil {
		return fail("usage", err)
	}
	pl, err := net.Listen("tcp", *listen)
	if err != nil {
		return fail("listen_failed", err)
	}
	defer pl.Close()
	ul, err := net.Listen("tcp", *uiAddr)
	if err != nil {
		return fail("listen_failed", err)
	}
	defer ul.Close()
	bus := telemetry.New()
	p := proxy.New(u, cfg, bus)
	opts := proxy.Options{Demo: isDemo, UpstreamAllow: upstreamAllow, TLSPassthrough: passthrough, InsecureUpstream: *insecure, MITMALPN: *alpn, H2TapOff: *h2tap == "off", SSETelemetryMax: *sseMax, AllowLoopbackEgress: *allowLoopbackEgress}
	if *upstreamCA != "" {
		data, e := os.ReadFile(*upstreamCA)
		if e != nil {
			return fail("ca_missing", e)
		}
		pool, e := x509.SystemCertPool()
		if e != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(data) {
			return fail("usage", errors.New("invalid upstream CA"))
		}
		opts.UpstreamCA = pool
	}
	if *tlsEnabled {
		if *caDir == "" {
			opts.CA, err = tlsmitm.Ephemeral()
		} else {
			opts.CA, err = (tlsmitm.Store{Dir: *caDir}).Load()
		}
		if err != nil {
			code := "ca_missing"
			if errors.Is(err, tlsmitm.ErrInsecurePerms) {
				code = "ca_insecure_perms"
			}
			if errors.Is(err, os.ErrNotExist) && *caDir != "" {
				err = fmt.Errorf("CA store is not initialized; run glitchdeck ca init --ca-dir %q", *caDir)
			}
			return fail(code, err)
		}
	}
	p.SetOptions(opts)
	p.SetSeq(startSeq)
	defer p.Close()
	demoURL := ""
	if isDemo {
		demoURL = *target
	}
	handler := ui.New(p, bus, ui.Options{Target: *target, Listen: pl.Addr().String(), UI: ul.Addr().String(), DemoURL: demoURL})
	servers := []*http.Server{{Handler: handler}}
	listeners := []net.Listener{ul}
	if isDemo {
		servers = append(servers, &http.Server{Handler: demo.New(), Protocols: demo.Protocols()})
		listeners = append(listeners, appListener)
	}
	errs := make(chan error, len(servers)+1)
	var events <-chan telemetry.Event
	var stopEvents func()
	if *asJSON {
		_, events, stopEvents = bus.Subscribe()
	}
	go func() { errs <- p.Serve(pl) }()
	for i, s := range servers {
		l := listeners[i]
		go func(s *http.Server) { errs <- s.Serve(l) }(s)
	}
	var eventsDone chan struct{}
	if *asJSON {
		var fingerprint any
		var certPath any
		if opts.CA != nil {
			fingerprint = opts.CA.Fingerprint()
			if *caDir != "" {
				certPath = (tlsmitm.Store{Dir: *caDir}).CertPath()
			}
		}
		var demoValue any
		if demoURL != "" {
			demoValue = demoURL
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"type": "ready", "proxy": "http://" + pl.Addr().String(), "ui": "http://" + ul.Addr().String(), "demo": demoValue, "tls": map[string]any{"enabled": *tlsEnabled, "ca_cert": certPath, "fingerprint": fingerprint}})
		encoder := json.NewEncoder(os.Stdout)
		eventsDone = make(chan struct{})
		go func() {
			defer close(eventsDone)
			var lastID uint64
			for event := range events {
				if event.ID > lastID+1 {
					_ = encoder.Encode(map[string]any{"type": "event_gap", "first_id": lastID + 1, "last_id": event.ID - 1})
				}
				_ = encoder.Encode(map[string]any{"type": "event", "event": event})
				lastID = event.ID
			}
		}()
	} else {
		fmt.Printf("Proxy: http://%s\nUI: http://%s\n", pl.Addr(), ul.Addr())
		if isDemo {
			fmt.Printf("Demo: %s\nOpen the UI and run a checkout.\n", demoURL)
		}
	}
	if *open {
		name, args := browserCommand(runtime.GOOS, "http://"+ul.Addr().String())
		if name == "" {
			fmt.Fprintln(os.Stderr, "warning: --open requires a loopback UI URL")
		} else {
			cmd := exec.Command(name, args...)
			if err := cmd.Start(); err != nil {
				fmt.Fprintln(os.Stderr, "warning: opening UI:", err)
			} else {
				go func() { _ = cmd.Wait() }()
			}
		}
	}
	code := 0
	select {
	case <-ctx.Done():
	case e := <-errs:
		if e != nil && !errors.Is(e, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, e)
			code = 2
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, s := range servers {
		if s.Shutdown(shutdown) != nil {
			_ = s.Close()
		}
	}
	p.Close()
	if *asJSON {
		stopEvents()
		<-eventsDone
		json.NewEncoder(os.Stdout).Encode(map[string]any{"type": "shutdown", "exit_code": code})
	}
	return code
}

func browserCommand(goos, rawURL string) (string, []string) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "http" || u.User != nil || !cli.Loopback(net.JoinHostPort(u.Hostname(), u.Port())) {
		return "", nil
	}
	switch goos {
	case "darwin":
		return "open", []string{rawURL}
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", rawURL}
	default:
		return "xdg-open", []string{rawURL}
	}
}
