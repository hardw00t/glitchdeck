package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/hardw00t/glitchdeck/internal/cli"
	"github.com/hardw00t/glitchdeck/internal/execrun"
	"github.com/hardw00t/glitchdeck/internal/mcp"
	"github.com/hardw00t/glitchdeck/internal/proxy"
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
	f.StringVar(&o.Mode, "mode", "passthrough", "passthrough, record, or replay")
	f.StringVar(&o.TapeOut, "tape-out", "", "output path for record mode")
	f.BoolVar(&o.RedactSecrets, "redact-secrets", false, "redact detected secrets before tape export")
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
	f.BoolVar(&o.AllowLoopbackEgress, "allow-loopback-egress", false, "allow loopback, link-local and unspecified upstream addresses on non-loopback proxy listeners")
	f.BoolVar(&o.AllowZeroTraffic, "allow-zero-traffic", false, "allow zero, TLS-rejected-only or egress-denied-only traffic, or zero triggered faults")
	f.BoolVar(&o.ProxyAuth, "proxy-auth", false, "enable proxy authentication")
	var allow listFlag
	f.Var(&allow, "upstream-allow", "allow upstream")
	var passthrough listFlag
	f.Var(&passthrough, "tls-passthrough", "tunnel matching TLS hosts without interception")
	seed := f.Uint64("seed", 0, "override seed")
	const execUsage = "usage: glitchdeck exec --tape <file> [flags] -- <command> [args...]"
	f.Usage = func() {
		fmt.Fprintln(f.Output(), execUsage)
		f.PrintDefaults()
	}
	wantJSON := cli.JSONRequested(args)
	sep := slices.Index(args, "--")
	options := args
	if sep >= 0 {
		options = args[:sep]
	}
	recordRequested := false
	for i, arg := range options {
		if arg == "--mode=record" || arg == "-mode=record" ||
			(arg == "--mode" || arg == "-mode") && i+1 < len(options) && options[i+1] == "record" {
			recordRequested = true
			break
		}
	}
	if wantJSON || recordRequested {
		f.SetOutput(io.Discard)
	}
	if showCommandHelp(f, args, execUsage) {
		return 0
	}
	var reportDestination *execrun.Destination
	var reportSafe func() error
	emit := func(e execrun.Envelope) int {
		if reportDestination != nil {
			err := reportSafe()
			if err == nil {
				err = reportDestination.WriteReport(e)
			}
			if err != nil {
				if problem, ok := e.Error.(map[string]string); ok && problem["code"] == "EXPORT_BLOCKED" {
					fmt.Fprintln(os.Stderr, "glitchdeck exec: could not write report")
				} else {
					e.ExitCode, e.OK = 3, false
					message := err.Error()
					if o.Mode == "record" {
						message = "could not write report"
					}
					e.Error = map[string]string{"code": "TAPE_IO", "message": message}
				}
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
			fmt.Printf("exec exit %d", e.ExitCode)
			if e.Exec != nil {
				if e.Exec.Traffic.TLSRejected != 0 {
					fmt.Printf(", tls rejected %d", e.Exec.Traffic.TLSRejected)
				}
				if e.Exec.Traffic.PassthroughOK != 0 {
					fmt.Printf(", passthrough %d", e.Exec.Traffic.PassthroughOK)
				}
				if e.Exec.Traffic.EgressDenied != 0 {
					fmt.Printf(", egress denied %d", e.Exec.Traffic.EgressDenied)
				}
			}
			fmt.Println()
			for _, diff := range e.Diff {
				fmt.Println(diff)
			}
		}
		return e.ExitCode
	}
	fail := func(code string, err error) int {
		if recordRequested || o.Mode == "record" {
			e := execrun.NewEnvelope("exec", "", "")
			e.Target, e.ExitCode = nil, 2
			if code == "OUTPUT_IO" {
				code, e.ExitCode = "TAPE_IO", 3
			}
			message := "invalid record options"
			switch code {
			case "TAPE_IO":
				message = "could not access a tape or report destination"
			case "TAPE_INVALID":
				message = "invalid input tape"
			}
			e.Error = map[string]string{"code": code, "message": message}
			return emit(e)
		}
		e := execrun.NewEnvelope("exec", *path, o.Target)
		e.ExitCode = 2
		if code == "OUTPUT_IO" {
			code, e.ExitCode = "TAPE_IO", 3
		}
		e.Error = map[string]string{"code": code, "message": err.Error()}
		e.Exec = &execrun.Exec{Cmd: f.Args(), LeakedPIDs: []int{}}
		return emit(e)
	}
	if sep < 0 {
		return fail("USAGE_ERROR", errors.New("expected --tape, positive timeout and grace, and -- <command>"))
	}
	if err := f.Parse(args[:sep]); err != nil {
		return fail("USAGE_ERROR", err)
	}
	if *path == "" || f.NArg() != 0 || sep+1 == len(args) || o.Timeout <= 0 || o.Grace <= 0 {
		return fail("USAGE_ERROR", errors.New("expected --tape, positive timeout and grace, and -- <command>"))
	}
	if err := o.ValidateMode(); err != nil {
		return fail("USAGE_ERROR", err)
	}
	file, inputErr := os.Open(*path)
	if file != nil {
		defer file.Close()
	}
	if o.TapeOut != "" {
		var err error
		o.TapeDestination, err = execrun.OpenDestination(o.TapeOut)
		if err != nil {
			return fail("OUTPUT_IO", err)
		}
		defer o.TapeDestination.Close()
	}
	if *report != "" {
		inputDestination, err := execrun.OpenDestination(*path)
		if err != nil {
			return fail("TAPE_IO", err)
		}
		defer inputDestination.Close()
		destination, err := execrun.OpenDestination(*report)
		if err != nil {
			return fail("OUTPUT_IO", err)
		}
		defer destination.Close()
		var inputInfo os.FileInfo
		if file != nil {
			inputInfo, err = file.Stat()
			if err != nil {
				return fail("TAPE_IO", err)
			}
		}
		reportSafe = func() error {
			alias, err := destination.Same(inputDestination, inputInfo)
			if err == nil && !alias && o.TapeDestination != nil {
				alias, err = destination.Same(o.TapeDestination)
			}
			if err != nil || alias {
				return errors.New("report and tape destinations must be distinct and resolvable")
			}
			return nil
		}
		if err := reportSafe(); err != nil {
			return fail("USAGE_ERROR", err)
		}
		reportDestination = destination
	}
	if inputErr != nil {
		return fail("TAPE_IO", inputErr)
	}
	for i, pattern := range passthrough {
		if err := proxy.ValidatePassthrough(pattern); err != nil {
			return fail("USAGE_ERROR", fmt.Errorf("tls_passthrough[%d]: %v: %q", i, err, strings.TrimSpace(pattern)))
		}
	}
	t, err := tape.Decode(file)
	if err != nil {
		return fail("TAPE_INVALID", err)
	}
	f.Visit(func(option *flag.Flag) {
		if option.Name == "seed" {
			o.Seed = seed
		}
	})
	o.Command, o.TapePath, o.JSON, o.UpstreamAllow, o.TLSPassthrough = args[sep+1:], *path, *asJSON, allow, passthrough
	return emit(execrun.Run(context.Background(), t, o))
}

func mcpCommand(args []string) int {
	f := flag.NewFlagSet("mcp", flag.ContinueOnError)
	workdir := f.String("workdir", ".", "working directory")
	allowExec := f.Bool("allow-exec", false, "permit the MCP client to execute commands as the server user")
	var allow listFlag
	f.Var(&allow, "upstream-allow", "allow upstream for exec_run")
	if showCommandHelp(f, args, "usage: glitchdeck mcp [flags]") {
		return 0
	}
	if f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	if err := closeInheritedOnExec(); err != nil {
		mcp.LogDiagnostic(err.Error())
		return 3
	}
	output, err := mcp.OwnedStdioOutput()
	if err != nil {
		mcp.LogDiagnostic(err.Error())
		return 3
	}
	defer output.Close()
	if err := mcp.NewServer(os.Stdin, output, mcp.Options{Workdir: *workdir, Version: buildVersion(), CloseOutputOnCancel: true, AllowExec: *allowExec, UpstreamAllow: allow}).Serve(); err != nil {
		mcp.LogDiagnostic(err.Error())
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
	const caUsage = "usage: glitchdeck ca init|path|print [--ca-dir path]"
	if showCommandHelp(f, args, caUsage) {
		return 0
	}
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
		return fail("usage", errors.New(caUsage), 2)
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
	if showCommandHelp(f, args, "usage: glitchdeck version [--json]") {
		return 0
	}
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
	junit := f.Bool("junit", false, "JUnit XML output")
	if showCommandHelp(f, args, "usage: glitchdeck report [--github|--json|--junit] report.json") {
		return 0
	}
	if f.Parse(flags) != nil || len(pos) != 1 || *github && *asJSON || *junit && (*github || *asJSON) {
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
	if *junit {
		if err := writeJUnitReport(os.Stdout, e); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 3
		}
		return 0
	}
	details := reportDetails(e)
	if *github {
		failures := e.Diff
		if failure, ok := e.Error.(map[string]any); ok {
			message, _ := failure["message"].(string)
			code, _ := failure["code"].(string)
			if message != "" {
				if code != "" {
					message = code + ": " + message
				}
				failures = append(failures, message)
			}
		}
		escape := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
		for _, line := range failures {
			fmt.Printf("::error::%s\n", escape.Replace(line))
		}
		if e.OK {
			fmt.Println("::notice::Glitchdeck expectations passed")
		}
		for _, line := range details {
			fmt.Printf("::notice::%s\n", escape.Replace(line))
		}
		if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
			out, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 3
			}
			_, err = io.WriteString(out, githubSummary(e, failures, details))
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
		for _, line := range details {
			fmt.Println(line)
		}
		fmt.Printf("Exit code: %d\n", e.ExitCode)
	}
	return 0
}

func reportDetails(e execrun.Envelope) []string {
	var lines []string
	for _, entry := range e.FaultsTriggered {
		fault, _ := entry.(map[string]any)
		r, ok := fault["replays"].(map[string]any)
		if !ok {
			continue
		}
		rule, _ := fault["rule_id"].(string)
		if byMode, ok := r["by_mode"].(map[string]any); ok {
			for _, mode := range slices.Sorted(maps.Keys(byMode)) {
				if stats, ok := byMode[mode].(map[string]any); ok {
					lines = append(lines, replayReportLine(rule, stats))
				}
			}
		} else {
			lines = append(lines, replayReportLine(rule, r))
		}
	}
	for _, frame := range e.FrameErrors {
		lines = append(lines, fmt.Sprintf("ws_frame %s dir=%s seq=%d declared_bytes=%d limit_bytes=%d: %s",
			frame.Code, frame.Dir, frame.Seq, frame.Declared, frame.Limit, frame.Detail))
	}
	if e.FrameErrorsOmitted != 0 {
		lines = append(lines, fmt.Sprintf("ws_frame errors omitted: %d", e.FrameErrorsOmitted))
	}
	return lines
}

func replayReportLine(rule string, r map[string]any) string {
	var line strings.Builder
	fmt.Fprintf(&line, "dup-webhook %s mode=%s sent=%.0f", rule, r["mode"], r["sent"])
	status, _ := r["status"].(map[string]any)
	for _, k := range slices.Sorted(maps.Keys(status)) {
		fmt.Fprintf(&line, " %s×%.0f", k, status[k])
	}
	if skew, ok := r["max_skew_ms"].(float64); ok {
		fmt.Fprintf(&line, " skew=%.0fms", skew)
	}
	if committed, ok := r["committed_status"].(float64); ok {
		fmt.Fprintf(&line, " committed_status=%.0f", committed)
	}
	if outcome, ok := r["original_outcome"].(string); ok {
		fmt.Fprintf(&line, " original_outcome=%s", outcome)
	}
	outcomes, _ := r["outcomes"].(map[string]any)
	sep := " outcomes="
	for _, k := range slices.Sorted(maps.Keys(outcomes)) {
		fmt.Fprintf(&line, "%s%s×%.0f", sep, k, outcomes[k])
		sep = ","
	}
	return line.String()
}

func writeJUnitReport(w io.Writer, e execrun.Envelope) error {
	type problem struct {
		Message string `xml:"message,attr"`
		Text    string `xml:",chardata"`
	}
	type testcase struct {
		Name      string   `xml:"name,attr"`
		Classname string   `xml:"classname,attr"`
		Failure   *problem `xml:"failure,omitempty"`
		Error     *problem `xml:"error,omitempty"`
		Output    string   `xml:"system-out,omitempty"`
	}
	doc := struct {
		XMLName xml.Name `xml:"testsuites"`
		Suite   struct {
			Name     string     `xml:"name,attr"`
			Tests    int        `xml:"tests,attr"`
			Failures int        `xml:"failures,attr"`
			Errors   int        `xml:"errors,attr"`
			Cases    []testcase `xml:"testcase"`
		} `xml:"testsuite"`
	}{}
	suite := &doc.Suite
	suite.Name = e.Tape
	if suite.Name == "" {
		suite.Name = "glitchdeck"
	}
	add := func(c testcase) {
		c.Classname = suite.Name
		suite.Cases = append(suite.Cases, c)
		if c.Failure != nil {
			suite.Failures++
		}
		if c.Error != nil {
			suite.Errors++
		}
	}
	represented := make(map[string]struct{})
	for _, a := range e.Assertions {
		c := testcase{Name: a.Name}
		if !a.Passed {
			c.Failure = &problem{Message: "assertion failed"}
			if len(a.Failures) > 0 {
				c.Failure.Message = a.Failures[0]
				c.Failure.Text = strings.Join(a.Failures, "\n")
			}
			for _, line := range a.Failures {
				represented[a.Name+": "+line] = struct{}{}
			}
		}
		add(c)
	}
	for i, line := range e.Diff {
		if _, ok := represented[line]; !ok {
			add(testcase{Name: fmt.Sprintf("diff %d", i+1), Failure: &problem{Message: line, Text: line}})
		}
	}
	if failure, ok := e.Error.(map[string]any); ok {
		code, _ := failure["code"].(string)
		message, _ := failure["message"].(string)
		if message == "" {
			message = code
		} else if code != "" {
			message = code + ": " + message
		}
		add(testcase{Name: "error", Error: &problem{Message: message, Text: message}})
	}
	if !e.OK && suite.Failures == 0 && suite.Errors == 0 {
		message := fmt.Sprintf("exit code %d", e.ExitCode)
		add(testcase{Name: "glitchdeck", Failure: &problem{Message: message, Text: message}})
	} else if e.OK && len(e.Assertions) == 0 {
		add(testcase{Name: "expectations"})
	}
	if details := reportDetails(e); len(details) != 0 {
		suite.Cases[0].Output = strings.Join(details, "\n")
	}
	suite.Tests = len(suite.Cases)

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	// encoding/xml escapes text and attributes and replaces invalid XML characters.
	return xml.NewEncoder(w).Encode(doc)
}

func githubSummary(e execrun.Envelope, failures, details []string) string {
	var summary strings.Builder
	summary.WriteString("## Glitchdeck\n\n| Exit code |")
	childHeading, childSeparator, childValue := "", "", ""
	if e.Command == "exec" && e.Exec != nil {
		childHeading, childSeparator = " Child exit code |", " --- |"
		childValue = fmt.Sprintf(" %d |", e.Exec.ExitCode)
	}
	fmt.Fprintf(&summary, "%s Requests total | Faults triggered | Assertions passed | Assertions failed |\n", childHeading)
	fmt.Fprintf(&summary, "| --- |%s --- | --- | --- | --- |\n", childSeparator)
	fmt.Fprintf(&summary, "| %d |%s %d | %d | %d | %d |\n", e.ExitCode, childValue,
		e.Summary.RequestsTotal, e.Summary.FaultsTriggered, e.Summary.AssertionsPassed, e.Summary.AssertionsFailed)

	escape := strings.NewReplacer(
		"\r\n", " ", "\r", " ", "\n", " ",
		"\\", "\\\\", "|", "\\|", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "~", "\\~",
		"&", "&amp;", "<", "&lt;", ">", "&gt;",
	)
	if len(e.FaultsTriggered) > 0 {
		summary.WriteString("\n**Faults by rule**\n\n")
		for _, entry := range e.FaultsTriggered {
			fault, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			rule, _ := fault["rule_id"].(string)
			kind, _ := fault["type"].(string)
			count, ok := fault["count"].(float64)
			if ok {
				fmt.Fprintf(&summary, "- %s (%s): %.0f\n", escape.Replace(rule), escape.Replace(kind), count)
			}
		}
	}
	if len(details) > 0 {
		summary.WriteString("\n**Fault details**\n\n")
		for _, line := range details {
			fmt.Fprintf(&summary, "- %s\n", escape.Replace(line))
		}
	}
	if len(failures) > 0 {
		summary.WriteString("\n**Failures**\n\n")
		for _, line := range failures {
			fmt.Fprintf(&summary, "- %s\n", escape.Replace(line))
		}
	}
	return summary.String()
}
