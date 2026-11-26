package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"glitchdeck/internal/demo"
	"glitchdeck/internal/fault"
	"glitchdeck/internal/proxy"
	"glitchdeck/internal/tape"
	"glitchdeck/internal/telemetry"
	"glitchdeck/internal/ui"
)

func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: glitchdeck demo|proxy|test")
		return 2
	}
	switch args[0] {
	case "demo":
		return serve(args[1:], true)
	case "proxy":
		return serve(args[1:], false)
	case "test":
		return testTape(args[1:])
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", args[0])
		return 2
	}
}
func testTape(args []string) int {
	f := flag.NewFlagSet("test", flag.ContinueOnError)
	target := f.String("target", "", "override target")
	timeout := f.Duration("timeout", 30*time.Second, "run timeout")
	asJSON := f.Bool("json", false, "JSON output")
	var flags []string
	var filename string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			key := strings.TrimLeft(strings.SplitN(a, "=", 2)[0], "-")
			if !strings.Contains(a, "=") && (key == "target" || key == "timeout") && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		} else if filename == "" {
			filename = a
		} else {
			fmt.Fprintln(os.Stderr, "expected one tape file")
			return 2
		}
	}
	if f.Parse(flags) != nil || filename == "" || *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "usage: glitchdeck test [flags] tape.yaml")
		return 2
	}
	file, err := os.Open(filename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	t, err := tape.Decode(file)
	file.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	results, err := tape.Run(ctx, t, *target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	failed := false
	for _, r := range results {
		if len(r.Failures) > 0 {
			failed = true
		}
	}
	if *asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	} else {
		for _, r := range results {
			if len(r.Failures) == 0 {
				fmt.Printf("PASS %s\n", r.Name)
			} else {
				for _, failure := range r.Failures {
					fmt.Printf("FAIL %s: %s\n", r.Name, failure)
				}
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
	listen := f.String("listen", "127.0.0.1:8080", "proxy listener")
	uiAddr := f.String("ui", "127.0.0.1:8081", "control listener")
	app := f.String("app", "127.0.0.1:3000", "demo listener")
	target := f.String("target", "", "loopback upstream")
	tapePath := f.String("tape", "", "initial tape")
	seed := f.Uint64("seed", 1, "fault seed")
	open := f.Bool("open", false, "open control UI")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var appListener net.Listener
	var err error
	if isDemo {
		appListener, err = net.Listen("tcp", *app)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		defer appListener.Close()
		_, port, e := net.SplitHostPort(appListener.Addr().String())
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 2
		}
		*target = "http://127.0.0.1:" + port
	}
	u, err := proxy.ParseTarget(*target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	cfg := fault.Config{Seed: *seed}
	var startSeq uint64
	if *tapePath != "" {
		file, e := os.Open(*tapePath)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 2
		}
		t, e := tape.Decode(file)
		file.Close()
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 2
		}
		cfg = fault.Config{Seed: t.Seed, Rules: t.Rules}
		startSeq = t.StartSeq
	}
	pl, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer pl.Close()
	ul, err := net.Listen("tcp", *uiAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer ul.Close()
	bus := telemetry.New()
	p := proxy.New(u, cfg, bus)
	p.SetSeq(startSeq)
	defer p.Close()
	demoURL := ""
	if isDemo {
		demoURL = *target
	}
	handler := ui.New(p, bus, ui.Options{Target: *target, Listen: pl.Addr().String(), UI: ul.Addr().String(), DemoURL: demoURL})
	servers := []*http.Server{{Handler: p}, {Handler: handler}}
	listeners := []net.Listener{pl, ul}
	if isDemo {
		servers = append(servers, &http.Server{Handler: demo.New()})
		listeners = append(listeners, appListener)
	}
	errs := make(chan error, len(servers))
	for i, s := range servers {
		l := listeners[i]
		go func(s *http.Server) { errs <- s.Serve(l) }(s)
	}
	fmt.Printf("Proxy: http://%s\nUI: http://%s\n", pl.Addr(), ul.Addr())
	if isDemo {
		fmt.Printf("Demo: %s\nOpen the UI and run a checkout.\n", demoURL)
	}
	if *open {
		_ = exec.Command("xdg-open", "http://"+ul.Addr().String()).Start()
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
	return code
}
