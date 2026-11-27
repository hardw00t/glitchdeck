package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/hardw00t/glitchdeck/internal/cli"
	"github.com/hardw00t/glitchdeck/internal/execrun"
	"github.com/hardw00t/glitchdeck/internal/mcp"
	"github.com/hardw00t/glitchdeck/internal/tape"
	"github.com/hardw00t/glitchdeck/internal/tlsmitm"
)

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error {
	*l = append(*l, strings.Split(s, ",")...)
	return nil
}

func execCommand(args []string) int {
	f := flag.NewFlagSet("exec", flag.ContinueOnError)
	path := f.String("tape", "", "tape file")
	report := f.String("report", "", "report file")
	asJSON := f.Bool("json", false, "JSON output")
	var o execrun.Options
	f.StringVar(&o.Target, "target", "", "target override")
	f.StringVar(&o.Listen, "listen", "127.0.0.1:0", "proxy listener")
	f.StringVar(&o.UI, "ui", "", "UI listener")
	f.DurationVar(&o.Timeout, "timeout", 10*time.Minute, "child timeout")
	f.DurationVar(&o.Grace, "grace", 5*time.Second, "shutdown grace")
	f.BoolVar(&o.TLS, "tls", false, "enable TLS MITM")
	f.StringVar(&o.CADir, "ca-dir", "", "CA directory")
	f.StringVar(&o.NoProxy, "no-proxy", "", "proxy bypass list")
	f.StringVar(&o.UpstreamCA, "upstream-ca", "", "upstream CA")
	f.BoolVar(&o.InsecureUpstream, "insecure-upstream", false, "skip upstream TLS verification")
	f.BoolVar(&o.AllowRemote, "allow-remote", false, "permit non-loopback listener")
	f.BoolVar(&o.ProxyAuth, "proxy-auth", false, "enable proxy authentication")
	var allow listFlag
	f.Var(&allow, "upstream-allow", "allow upstream")
	seed := f.Uint64("seed", 0, "override seed")
	const execUsage = "usage: glitchdeck exec --tape <file> [flags] -- <command> [args...]"
	f.Usage = func() {
		fmt.Fprintln(f.Output(), execUsage)
		f.PrintDefaults()
	}
	wantJSON := cli.JSONRequested(args)
	if wantJSON {
		f.SetOutput(io.Discard)
	}
	head := args
	if i := slices.Index(args, "--"); i >= 0 {
		head = args[:i]
	}
	if !wantJSON && (slices.Contains(head, "-h") || slices.Contains(head, "-help") || slices.Contains(head, "--help")) {
		f.SetOutput(os.Stdout)
		f.Usage()
		return 0
	}
	emit := func(e execrun.Envelope) int {
		if *report != "" {
			if err := execrun.WriteReport(*report, e); err != nil {
				e.ExitCode, e.OK = 3, false
				e.Error = map[string]string{"code": "TAPE_IO", "message": err.Error()}
			}
		}
		if wantJSON {
			_ = json.NewEncoder(os.Stdout).Encode(e)
		} else if e.Error != nil {
			if m, ok := e.Error.(map[string]string); ok {
				fmt.Fprintln(os.Stderr, "glitchdeck exec: "+m["message"])
				if m["code"] == "USAGE_ERROR" {
					f.SetOutput(os.Stderr)
					f.Usage()
				}
			} else {
				fmt.Fprintln(os.Stderr, e.Error)
			}
		} else {
			fmt.Printf("exec exit %d\n", e.ExitCode)
			for _, diff := range e.Diff {
				fmt.Println(diff)
			}
		}
		return e.ExitCode
	}
	fail := func(code string, err error) int {
		e := execrun.NewEnvelope("exec", *path, o.Target)
		e.ExitCode = 2
		e.Error = map[string]string{"code": code, "message": err.Error()}
		e.Exec = &execrun.Exec{Cmd: f.Args(), LeakedPIDs: []int{}}
		return emit(e)
	}
	sep := slices.Index(args, "--")
	if sep < 0 {
		return fail("USAGE_ERROR", errors.New("expected --tape, positive timeout and grace, and -- <command>"))
	}
	if err := f.Parse(args[:sep]); err != nil {
		return fail("USAGE_ERROR", err)
	}
	if *path == "" || f.NArg() != 0 || sep+1 == len(args) || o.Timeout <= 0 || o.Grace <= 0 {
		return fail("USAGE_ERROR", errors.New("expected --tape, positive timeout and grace, and -- <command>"))
	}
	file, err := os.Open(*path)
	if err != nil {
		return fail("TAPE_IO", err)
	}
	t, err := tape.Decode(file)
	_ = file.Close()
	if err != nil {
		return fail("TAPE_INVALID", err)
	}
	f.Visit(func(option *flag.Flag) {
		if option.Name == "seed" {
			o.Seed = seed
		}
	})
	o.Command, o.TapePath, o.JSON, o.UpstreamAllow = args[sep+1:], *path, *asJSON, allow
	return emit(execrun.Run(context.Background(), t, o))
}

func mcpCommand(args []string) int {
	f := flag.NewFlagSet("mcp", flag.ContinueOnError)
	workdir := f.String("workdir", ".", "working directory")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	output, err := mcp.OwnedStdioOutput()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	defer output.Close()
	if err := mcp.NewServer(os.Stdin, output, mcp.Options{Workdir: *workdir, Version: buildVersion(), CloseOutputOnCancel: true}).Serve(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	return 0
}

func caCommand(args []string) int {
	flags, pos := cli.SplitArgs(args, "ca-dir")
	f := flag.NewFlagSet("ca", flag.ContinueOnError)
	dir := f.String("ca-dir", tlsmitm.DefaultDir(), "CA directory")
	force := f.Bool("force", false, "replace CA")
	asJSON := f.Bool("json", false, "JSON output")
	wantJSON := cli.JSONRequested(flags)
	if wantJSON {
		f.SetOutput(io.Discard)
	}
	fail := func(code string, err error, exit int) int {
		if wantJSON {
			cli.Error(os.Stderr, code, err, exit)
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		return exit
	}
	if err := f.Parse(flags); err != nil {
		return fail("usage", err, 2)
	}
	if len(pos) != 1 {
		return fail("usage", errors.New("usage: glitchdeck ca init|path|print [--ca-dir path]"), 2)
	}
	store := tlsmitm.Store{Dir: *dir}
	var ca *tlsmitm.CA
	var err error
	switch pos[0] {
	case "init":
		ca, err = store.Init(*force)
	case "path":
	case "print":
		ca, err = store.Load()
	default:
		return fail("usage", errors.New("unknown CA operation"), 2)
	}
	if err != nil {
		code := "ca_missing"
		if errors.Is(err, tlsmitm.ErrInsecurePerms) {
			code = "ca_insecure_perms"
		}
		return fail(code, err, 3)
	}
	if pos[0] == "print" {
		if _, err := os.Stdout.Write(ca.PEM); err != nil {
			return fail("internal", err, 3)
		}
		return 0
	}
	if *asJSON {
		data := map[string]string{"path": store.CertPath()}
		if ca != nil {
			data["fingerprint"] = ca.Fingerprint()
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": "glitchdeck.v2", "command": "ca." + pos[0], "ok": true, "data": data})
	} else {
		fmt.Println(store.CertPath())
	}
	return 0
}

func buildVersion() string {
	v, _, _ := buildMetadata()
	return v
}

func buildMetadata() (v, rev, date string) {
	v, rev, date = version, commit, buildDate
	if v != "dev" {
		return
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			v = info.Main.Version
		}
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				if rev == "none" {
					rev = setting.Value
				}
			case "vcs.time":
				if date == "unknown" {
					date = setting.Value
				}
			}
		}
	}
	return
}

func versionCommand(args []string) int {
	f := flag.NewFlagSet("version", flag.ContinueOnError)
	asJSON := f.Bool("json", false, "JSON output")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	v, rev, date := buildMetadata()
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"schema": "glitchdeck.v2", "command": "version", "ok": true,
			"data": map[string]string{
				"version": v, "commit": rev, "build_date": date,
				"go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH,
			},
		})
	} else {
		fmt.Printf("glitchdeck %s (commit %s, built %s)\n", v, rev, date)
	}
	return 0
}

func reportCommand(args []string) int {
	flags, pos := cli.SplitArgs(args)
	f := flag.NewFlagSet("report", flag.ContinueOnError)
	github := f.Bool("github", false, "GitHub annotations")
	asJSON := f.Bool("json", false, "JSON output")
	if f.Parse(flags) != nil || len(pos) != 1 || *github && *asJSON {
		return 2
	}
	data, err := os.ReadFile(pos[0])
	var e execrun.Envelope
	if err == nil {
		err = json.Unmarshal(data, &e)
	}
	if err != nil {
		if *asJSON {
			cli.Error(os.Stderr, "tape_io", err, 3)
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		return 3
	}
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(e)
		return 0
	}
	if *github {
		escape := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
		for _, line := range e.Diff {
			fmt.Printf("::error::%s\n", escape.Replace(line))
		}
		if failure, ok := e.Error.(map[string]any); ok {
			message, _ := failure["message"].(string)
			code, _ := failure["code"].(string)
			if message != "" {
				fmt.Printf("::error::%s\n", escape.Replace(code+": "+message))
			}
		}
		if e.OK {
			fmt.Println("::notice::Glitchdeck expectations passed")
		}
		if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
			out, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 3
			}
			_, err = fmt.Fprintf(out, "## Glitchdeck\n\n| Exit | Assertions passed | Assertions failed |\n| --- | --- | --- |\n| %d | %d | %d |\n", e.ExitCode, e.Summary.AssertionsPassed, e.Summary.AssertionsFailed)
			closeErr := out.Close()
			if err != nil || closeErr != nil {
				fmt.Fprintln(os.Stderr, errors.Join(err, closeErr))
				return 3
			}
		}
	} else {
		for _, line := range e.Diff {
			fmt.Println(line)
		}
		fmt.Printf("Exit code: %d\n", e.ExitCode)
	}
	return 0
}
