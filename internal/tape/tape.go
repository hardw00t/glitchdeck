package tape

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hardw00t/glitchdeck/internal/demo"
	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/sse"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
	"github.com/hardw00t/glitchdeck/internal/tlsmitm"
	"github.com/hardw00t/glitchdeck/internal/wsframe"
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
	Truncated        bool           `yaml:"truncated,omitempty" json:"truncated,omitempty"`
	DroppedEntries   int            `yaml:"dropped_entries,omitempty" json:"dropped_entries,omitempty"`
	OmittedBodyBytes int            `yaml:"omitted_body_bytes,omitempty" json:"omitted_body_bytes,omitempty"`
	ConfigChanges    []ConfigChange `yaml:"config_changes,omitempty" json:"config_changes,omitempty"`
	Assertions       []Assertion    `yaml:"assertions" json:"assertions"`
	TLSMITM          bool           `yaml:"tls_mitm,omitempty" json:"tls_mitm,omitempty"`
	UpstreamAllow    []string       `yaml:"upstream_allow,omitempty" json:"upstream_allow,omitempty"`
	TLSPassthrough   []string       `yaml:"tls_passthrough,omitempty" json:"tls_passthrough,omitempty"`
	Cassettes        []Cassette     `yaml:"cassettes,omitempty" json:"cassettes,omitempty"`
	IgnoreJSONPaths  []string       `yaml:"ignore_json_paths,omitempty" json:"ignore_json_paths,omitempty"`
	Redacted         bool           `yaml:"redacted,omitempty" json:"redacted,omitempty"`
	Expect           Expect         `yaml:"expect,omitempty" json:"expect,omitempty"`
}
type ConfigChange struct {
	BeforeSeq uint64       `yaml:"before_seq" json:"before_seq"`
	AtMS      *int64       `yaml:"at_ms,omitempty" json:"at_ms,omitempty"`
	Seed      uint64       `yaml:"seed" json:"seed"`
	Rules     []fault.Rule `yaml:"rules" json:"rules"`
}
type Step struct {
	Name    string  `yaml:"name" json:"name"`
	Seq     uint64  `yaml:"seq,omitempty" json:"seq,omitempty"`
	HTTP    *HTTP   `yaml:"http,omitempty" json:"http,omitempty"`
	WS      *WS     `yaml:"ws,omitempty" json:"ws,omitempty"`
	SleepMS int     `yaml:"sleep_ms,omitempty" json:"sleep_ms,omitempty"`
	AtMS    int64   `yaml:"at_ms,omitempty" json:"at_ms,omitempty"`
	Stream  *Stream `yaml:"stream,omitempty" json:"stream,omitempty"`
	GRPC    *GRPC   `yaml:"grpc,omitempty" json:"grpc,omitempty"`
}
type HTTP struct {
	Method  string            `yaml:"method" json:"method"`
	Path    string            `yaml:"path" json:"path"`
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Body    string            `yaml:"body,omitempty" json:"body,omitempty"`
	URL     string            `yaml:"url,omitempty" json:"url,omitempty"`
	Proto   string            `yaml:"proto,omitempty" json:"proto,omitempty"`
}
type WS struct {
	Path      string   `yaml:"path" json:"path"`
	Frames    int      `yaml:"frames,omitempty" json:"frames,omitempty"`
	TimeoutMS int      `yaml:"timeout_ms,omitempty" json:"timeout_ms,omitempty"`
	Messages  []string `yaml:"messages,omitempty" json:"messages,omitempty"`
}
type Assertion struct {
	Name             string         `yaml:"name" json:"name"`
	HTTPGet          string         `yaml:"http_get" json:"http_get"`
	ExpectStatus     int            `yaml:"expect_status,omitempty" json:"expect_status,omitempty"`
	JSONEq           map[string]any `yaml:"json_eq,omitempty" json:"json_eq,omitempty"`
	MaxLatencyMS     int            `yaml:"max_latency_ms,omitempty" json:"max_latency_ms,omitempty"`
	Direct           bool           `yaml:"direct,omitempty" json:"direct,omitempty"`
	StreamStep       string         `yaml:"stream_step,omitempty" json:"stream_step,omitempty"`
	ExpectSSE        *SSEExpect     `yaml:"expect_sse,omitempty" json:"expect_sse,omitempty"`
	GRPCStep         string         `yaml:"grpc_step,omitempty" json:"grpc_step,omitempty"`
	ExpectGRPCStatus *int           `yaml:"expect_grpc_status,omitempty" json:"expect_grpc_status,omitempty"`
}
type Result struct {
	Name     string   `json:"name"`
	Failures []string `json:"failures"`
}

func leadingV3(raw []byte) bool {
	data := bytes.TrimPrefix(raw, []byte("\ufeff"))
	documentStart := false
	for {
		line, rest, ok := bytes.Cut(data, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 || trimmed[0] == '#' {
			if !ok {
				return false
			}
			data = rest
			continue
		}
		if bytes.Equal(line, []byte("---")) && !documentStart {
			documentStart = true
			if !ok {
				return false
			}
			data = rest
			continue
		}
		if !bytes.HasPrefix(line, []byte("version:")) {
			return false
		}
		value := bytes.TrimSpace(line[len("version:"):])
		if bytes.Equal(value, []byte("3")) {
			return ok
		}
		if len(value) < 2 || value[0] != '3' || value[1] != ' ' && value[1] != '\t' {
			return false
		}
		comment := bytes.TrimSpace(value[1:])
		return ok && len(comment) != 0 && comment[0] == '#'
	}
}

func Decode(r io.Reader) (Tape, error) {
	var t Tape
	raw, err := io.ReadAll(io.LimitReader(r, maxTapeInput+1))
	if err != nil {
		return t, err
	}
	if len(raw) > maxTapeInput {
		if leadingV3(raw) {
			return t, fmt.Errorf("tape exceeds input limit")
		}
		rest, err := io.ReadAll(r)
		if err != nil {
			return t, err
		}
		raw = append(raw, rest...)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return t, err
	}
	if err := checkYAMLGraph(&doc); err != nil {
		return t, err
	}
	if len(doc.Content) != 0 {
		var version int
		if node := yamlField(doc.Content[0], "version"); node != nil {
			_ = node.Decode(&version)
		}
		if version == 3 {
			if len(raw) > maxTapeInput {
				return t, fmt.Errorf("tape exceeds input limit")
			}
			if len(yamlItems(yamlField(doc.Content[0], "cassettes"))) > maxCassettes {
				return t, fmt.Errorf("too many cassettes")
			}
		}
	}
	d := yaml.NewDecoder(bytes.NewReader(raw))
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
	var presence struct {
		Assertions []struct {
			ExpectSSE map[string]any `yaml:"expect_sse"`
		} `yaml:"assertions"`
	}
	if err := yaml.Unmarshal(raw, &presence); err != nil {
		return t, err
	}
	for _, assertion := range presence.Assertions {
		if terminal, ok := assertion.ExpectSSE["terminal"]; ok {
			if value, ok := terminal.(string); !ok || value == "" {
				return t, fmt.Errorf("invalid terminal %q", terminal)
			}
		}
	}
	if (t.Version == 1 || t.Version == 2) && len(doc.Content) != 0 &&
		(yamlField(doc.Content[0], "cassettes") != nil || yamlField(doc.Content[0], "ignore_json_paths") != nil) {
		return t, fmt.Errorf("new keys require version: 3")
	}
	if t.Version == 1 || len(t.Expect.Faults) != 0 {
		if len(doc.Content) == 0 {
			return t, fmt.Errorf("empty tape document")
		}
		var err error
		if t.Version == 1 {
			err = v1Keys(&doc)
		} else {
			err = integerFaultBounds(&doc)
		}
		if err != nil {
			return t, err
		}
	}
	if t.Version >= 2 && len(doc.Content) != 0 {
		for i, item := range yamlItems(yamlField(doc.Content[0], "tls_passthrough")) {
			if item.Kind == yaml.AliasNode {
				item = item.Alias
			}
			if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
				return t, fmt.Errorf("tls_passthrough[%d]: expected a string", i)
			}
		}
	}
	if err := validate(t); err != nil {
		return t, err
	}
	return t, nil
}
func Encode(w io.Writer, t Tape) error {
	if _, err := PrepareExport(t, false); err != nil {
		return err
	}
	e := yaml.NewEncoder(w)
	defer e.Close()
	return e.Encode(t)
}
func validPath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.ContainsAny(p, "\r\n")
}
func validate(t Tape) error {
	if t.Version != 1 && t.Version != 2 && t.Version != 3 {
		return fmt.Errorf("unsupported tape version %d", t.Version)
	}
	if t.Version < 3 && (len(t.Cassettes) != 0 || len(t.IgnoreJSONPaths) != 0) {
		return fmt.Errorf("new keys require version: 3")
	}
	if len(t.Cassettes) > maxCassettes {
		return fmt.Errorf("too many cassettes")
	}
	for _, path := range t.IgnoreJSONPaths {
		for _, part := range strings.Split(path, ".") {
			if part == "" {
				return fmt.Errorf("invalid ignore_json_paths")
			}
		}
	}
	total := 0
	for i, c := range t.Cassettes {
		if !validCassetteMethod(c.Request.Method) || !validPath(c.Request.Path) || strings.ContainsAny(c.Request.Path, "?#") {
			return fmt.Errorf("cassettes[%d]: invalid request", i)
		}
		if c.Request.BodySHA256 != "" {
			digest, err := hex.DecodeString(c.Request.BodySHA256)
			if err != nil || len(digest) != sha256.Size {
				return fmt.Errorf("cassettes[%d]: invalid request digest", i)
			}
		}
		if c.Response.Status < 100 || c.Response.Status > 599 {
			return fmt.Errorf("cassettes[%d]: invalid response status", i)
		}
		size, err := c.Response.decodedSize()
		if err != nil || size > maxCassetteBody || size > maxDecodedAggregate-total || c.Response.Truncated {
			return fmt.Errorf("cassettes[%d]: invalid or truncated response body", i)
		}
		total += size
		if _, err := c.Response.Bytes(); err != nil {
			return fmt.Errorf("cassettes[%d]: invalid or truncated response body", i)
		}
	}
	if t.Version == 1 {
		if t.TLSMITM || len(t.UpstreamAllow) != 0 || len(t.TLSPassthrough) != 0 || t.Expect.ChildExit != nil || len(t.Expect.Faults) != 0 {
			return fmt.Errorf("new keys require version: 2")
		}
		if v2RuleSet(t.Rules) {
			return fmt.Errorf("new rule keys require version: 2")
		}
		for _, s := range t.Script {
			if s.Stream != nil || s.GRPC != nil || (s.HTTP != nil && (s.HTTP.URL != "" || s.HTTP.Proto != "")) {
				return fmt.Errorf("new step keys require version: 2")
			}
		}
		for _, a := range t.Assertions {
			if a.StreamStep != "" || a.GRPCStep != "" || a.ExpectSSE != nil || a.ExpectGRPCStatus != nil {
				return fmt.Errorf("new assertion keys require version: 2")
			}
		}
	}
	if t.Target != "" && t.Target != "demo" {
		if _, err := proxy.ParseExplicitTarget(t.Target); err != nil {
			return fmt.Errorf("target: %w", err)
		}
	}
	if t.DroppedEntries < 0 {
		return fmt.Errorf("dropped_entries cannot be negative")
	}
	if t.OmittedBodyBytes < 0 {
		return fmt.Errorf("omitted_body_bytes cannot be negative")
	}
	switch value := t.Expect.ChildExit.(type) {
	case nil:
	case int:
		if value < -1 {
			return fmt.Errorf("invalid child_exit")
		}
	case string:
		n, err := strconv.Atoi(value)
		if (err != nil || n < -1) && value != "any" && value != "nonzero" {
			return fmt.Errorf("invalid child_exit")
		}
	default:
		return fmt.Errorf("invalid child_exit")
	}
	for _, entry := range t.UpstreamAllow {
		for item := range strings.SplitSeq(entry, ",") {
			if strings.EqualFold(strings.TrimSpace(item), "any") {
				return fmt.Errorf("upstream_allow cannot contain any")
			}
		}
	}
	for i, pattern := range t.TLSPassthrough {
		if err := proxy.ValidatePassthrough(pattern); err != nil {
			return fmt.Errorf("tls_passthrough[%d]: %v: %q", i, err, strings.TrimSpace(pattern))
		}
	}
	if t.Incomplete || t.Version == 3 && t.Truncated {
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
		if t.Version == 1 && v2RuleSet(c.Rules) {
			return fmt.Errorf("new rule keys require version: 2")
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
	var terminals []string
	for _, rule := range t.Rules {
		terminals = append(terminals, fault.Strings(rule.Fault.Params, "done_events")...)
	}
	for _, change := range t.ConfigChanges {
		for _, rule := range change.Rules {
			terminals = append(terminals, fault.Strings(rule.Fault.Params, "done_events")...)
		}
	}
	if len(t.Expect.Faults) != 0 {
		ids := make(map[string]struct{}, len(t.Rules))
		for _, rule := range t.Rules {
			ids[rule.ID] = struct{}{}
		}
		for _, change := range t.ConfigChanges {
			for _, rule := range change.Rules {
				ids[rule.ID] = struct{}{}
			}
		}
		for _, want := range t.Expect.Faults {
			if _, ok := ids[want.Rule]; !ok {
				return fmt.Errorf("expect.faults references unknown rule %q", want.Rule)
			}
			if want.MinApplied != nil && want.MaxApplied != nil && *want.MinApplied > *want.MaxApplied {
				return fmt.Errorf("expect.faults rule %q: min_applied exceeds max_applied", want.Rule)
			}
		}
	}
	for _, s := range t.Script {
		n := 0
		if s.AtMS < 0 {
			return fmt.Errorf("invalid step offset")
		}
		if s.AtMS > math.MaxInt64/int64(time.Millisecond) {
			return fmt.Errorf("invalid step offset")
		}
		if s.HTTP != nil || s.WS != nil || s.Stream != nil || s.GRPC != nil {
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
			if !validPath(s.HTTP.Path) && s.HTTP.URL == "" {
				return fmt.Errorf("invalid HTTP path")
			}
			if s.HTTP.Proto != "" && s.HTTP.Proto != "h1" && s.HTTP.Proto != "h2c" && s.HTTP.Proto != "h2" {
				return fmt.Errorf("invalid HTTP protocol")
			}
			if err := validateStepProtocol(s.HTTP.URL, s.HTTP.Proto); err != nil {
				return err
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
		if s.Stream != nil {
			n++
			if (!validPath(s.Stream.Path) && s.Stream.URL == "") || s.Stream.IdleTimeoutMS < 0 || s.Stream.MaxMS < 0 {
				return fmt.Errorf("invalid stream step")
			}
			if err := validateStepProtocol(s.Stream.URL, s.Stream.Proto); err != nil {
				return err
			}
		}
		if s.GRPC != nil {
			n++
			if (!validPath(s.GRPC.Path) && s.GRPC.URL == "") || s.GRPC.TimeoutMS < 0 {
				return fmt.Errorf("invalid grpc step")
			}
			if s.GRPC.Proto != "" && s.GRPC.Proto != "h2c" && s.GRPC.Proto != "h2" {
				return fmt.Errorf("invalid grpc protocol")
			}
			if err := validateStepProtocol(s.GRPC.URL, s.GRPC.Proto); err != nil {
				return err
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
		if a.HTTPGet != "" && !a.Direct {
			if seq == math.MaxUint64 {
				return fmt.Errorf("sequence overflow")
			}
			seq++
		}
		kinds := 0
		if a.HTTPGet != "" {
			kinds++
		}
		if a.StreamStep != "" {
			kinds++
		}
		if a.GRPCStep != "" {
			kinds++
		}
		if kinds != 1 || (a.HTTPGet != "" && !validPath(a.HTTPGet)) || a.MaxLatencyMS < 0 {
			return fmt.Errorf("invalid assertion %q", a.Name)
		}
		if a.ExpectGRPCStatus != nil && *a.ExpectGRPCStatus < 0 || a.ExpectStatus < 0 {
			return fmt.Errorf("assertion %q has a negative expected status", a.Name)
		}
		if x := a.ExpectSSE; x != nil {
			if x.Terminal != "" && a.StreamStep == "" {
				return fmt.Errorf("assertion %q: terminal requires stream_step", a.Name)
			}
			if x.Terminal != "" && !sse.IsTerminalKind(x.Terminal) && !slices.Contains(terminals, x.Terminal) {
				return fmt.Errorf("assertion %q: invalid terminal %q", a.Name, x.Terminal)
			}
			if x.MinEvents != nil && *x.MinEvents < 0 || x.MaxEvents != nil && *x.MaxEvents < 0 ||
				x.MaxGapMS != nil && *x.MaxGapMS < 0 {
				return fmt.Errorf("assertion %q: min_events, max_events and max_gap_ms cannot be negative", a.Name)
			}
			if x.MinEvents != nil && x.MaxEvents != nil && *x.MinEvents > *x.MaxEvents {
				return fmt.Errorf("assertion %q: min_events exceeds max_events", a.Name)
			}
		}
	}
	return nil
}

func v2RuleSet(rules []fault.Rule) bool {
	for _, r := range rules {
		if r.Match.Host != "" || r.Match.Scheme != "" || r.Match.Proto != "" || r.Fault.Type == "sse-glitch" || r.Fault.Type == "h2-glitch" || r.Fault.Type == "grpc-glitch" {
			return true
		}
	}
	return false
}

func Run(ctx context.Context, t Tape, targetOverride string) ([]Result, error) {
	results, _, err := RunWithReport(ctx, t, targetOverride)
	return results, err
}

type RunReport struct {
	RequestsTotal      uint64
	Rules              map[string]proxy.RuleStats
	AppliedFaults      []proxy.AppliedFault
	FrameErrors        []proxy.FrameErrorEntry
	FrameErrorsOmitted uint64
	CassetteError      error
}

func RunWithReport(ctx context.Context, t Tape, targetOverride string) ([]Result, RunReport, error) {
	return RunWithOptions(ctx, t, targetOverride, "")
}

func RunWithOptions(ctx context.Context, t Tape, targetOverride, caDir string) ([]Result, RunReport, error) {
	return RunWithTLS(ctx, t, targetOverride, caDir, false)
}

func RunWithTLS(ctx context.Context, t Tape, targetOverride, caDir string, tlsOverride bool) ([]Result, RunReport, error) {
	return runWithMode(ctx, t, targetOverride, caDir, tlsOverride, false)
}

func RunReplay(ctx context.Context, t Tape, targetOverride, caDir string, tlsOverride bool) ([]Result, RunReport, error) {
	return runWithMode(ctx, t, targetOverride, caDir, tlsOverride, true)
}

func runWithMode(ctx context.Context, t Tape, targetOverride, caDir string, tlsOverride, replay bool) ([]Result, RunReport, error) {
	if err := validate(t); err != nil {
		return nil, RunReport{}, err
	}
	t.TLSMITM = t.TLSMITM || tlsOverride
	var report RunReport
	results, err := run(ctx, t, targetOverride, caDir, &report, replay)
	return results, report, err
}

func run(ctx context.Context, t Tape, targetOverride, caDir string, report *RunReport, replay bool) (results []Result, runErr error) {
	if replay && t.Version == 3 && len(t.Cassettes) == 0 {
		return nil, &proxy.CassetteError{Kind: "cassette_miss"}
	}
	target := t.Target
	if targetOverride != "" {
		target = targetOverride
	}
	var ca *tlsmitm.CA
	var upstreamRoots *x509.CertPool
	var roots *x509.CertPool
	var demoTLS string
	if t.TLSMITM {
		var err error
		if caDir == "" {
			ca, err = tlsmitm.Ephemeral()
		} else {
			ca, err = (tlsmitm.Store{Dir: caDir}).Load()
		}
		if err != nil {
			return nil, err
		}
		roots = x509.NewCertPool()
		if len(t.TLSPassthrough) != 0 {
			if systemRoots, err := x509.SystemCertPool(); err == nil && systemRoots != nil {
				roots = systemRoots
			}
		}
		roots.AddCert(ca.Cert)
	}
	var app *httptest.Server
	isDemo := !replay && target == "demo"
	if replay && target == "demo" && ca != nil {
		demoTLS = "https://localhost"
	}
	if isDemo {
		handler := demo.New()
		app = httptest.NewUnstartedServer(handler)
		app.Config.Protocols = demo.Protocols()
		app.Start()
		defer app.Close()
		target = app.URL
		if ca != nil {
			upstreamRoots, _ = x509.SystemCertPool()
			if upstreamRoots == nil {
				upstreamRoots = x509.NewCertPool()
			}
			upstreamRoots.AddCert(ca.Cert)
			cert, err := tlsmitm.NewMinter(ca, 1, time.Hour).For("localhost")
			if err != nil {
				return nil, err
			}
			secure := httptest.NewUnstartedServer(handler)
			secure.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"h2", "http/1.1"}}
			secure.Config.Protocols = demo.Protocols()
			secure.Config.Protocols.SetHTTP2(true)
			secure.StartTLS()
			defer secure.Close()
			demoTLS = secure.URL
		}
	}
	for _, a := range t.Assertions {
		if replay && a.Direct {
			return nil, fmt.Errorf("direct assertions are not available in replay mode")
		}
		if a.Direct && (!isDemo || a.HTTPGet != "/api/state") {
			return nil, fmt.Errorf("direct assertions require demo /api/state")
		}
	}
	var u *url.URL
	if replay {
		if target == "demo" {
			target = "http://127.0.0.1"
		}
		if target != "" {
			var err error
			u, err = proxy.ParseExplicitTarget(target)
			if err != nil {
				return nil, err
			}
		}
	} else {
		var err error
		u, err = proxy.ParseTarget(target)
		if err != nil && len(t.UpstreamAllow) != 0 {
			u, err = proxy.ParseExplicitTarget(target)
		}
		if err != nil {
			return nil, err
		}
	}
	p := proxy.New(u, fault.Config{Seed: t.Seed, Rules: t.Rules}, telemetry.New())
	var frameErrors proxy.FrameErrorLog
	defer func() {
		p.Close()
		_ = p.Wait(context.Background())
		report.Rules = p.Stats()
		report.RequestsTotal = p.RequestsTotal()
		report.AppliedFaults = p.AppliedFaults()
		report.FrameErrors, report.FrameErrorsOmitted = frameErrors.Snapshot()
		if replay {
			if err := p.CassetteFailure(); err != nil {
				report.CassetteError = err
				if runErr == nil {
					runErr = err
				}
			}
		}
	}()
	opts := proxy.Options{CA: ca, UpstreamCA: upstreamRoots, UpstreamAllow: t.UpstreamAllow, TLSPassthrough: t.TLSPassthrough, Demo: isDemo, RequireUpstreamAllow: true}
	if replay {
		opts.CassetteUpstream = t.CassetteUpstream()
	}
	p.SetOptions(opts)
	var outcomeMu sync.Mutex
	type wsEvidence struct {
		drop    time.Time
		delay   time.Time
		delayAt time.Time
		corrupt time.Time
	}
	type outcome struct {
		proxy.Outcome
		messages map[uint64]wsEvidence
		limit    uint64
	}
	outcomes := map[uint64]*outcome{}
	p.OnOutcome = func(o proxy.Outcome) {
		frameErrors.Observe(o)
		outcomeMu.Lock()
		defer outcomeMu.Unlock()
		prev := outcomes[o.Seq]
		if prev == nil {
			prev = &outcome{}
			outcomes[o.Seq] = prev
		}
		prev.Reset = prev.Reset || o.Reset
		prev.H2Fault = prev.H2Fault || o.H2Fault
		if o.Err != nil {
			prev.Err = o.Err
		}
		switch o.WSAction {
		case "close_1006", "truncate":
			prev.WSAction = o.WSAction
		case "drop", "delay", "corrupt":
			if o.WSMessage == 0 || o.WSMessage > prev.limit {
				break
			}
			if prev.messages == nil {
				prev.messages = make(map[uint64]wsEvidence)
			}
			ev := prev.messages[o.WSMessage]
			switch o.WSAction {
			case "drop":
				if ev.drop.IsZero() {
					ev.drop = time.Now()
				}
			case "delay":
				if o.WSUntil.After(ev.delay) {
					ev.delay, ev.delayAt = o.WSUntil, time.Now()
				}
			case "corrupt":
				if ev.corrupt.IsZero() {
					ev.corrupt = time.Now()
				}
			}
			prev.messages[o.WSMessage] = ev
		}
	}
	getOutcome := func(seq uint64) outcome {
		outcomeMu.Lock()
		defer outcomeMu.Unlock()
		if o := outcomes[seq]; o != nil {
			copy := *o
			if o.messages != nil {
				copy.messages = make(map[uint64]wsEvidence, len(o.messages))
				for k, v := range o.messages {
					copy.messages[k] = v
				}
			}
			return copy
		}
		return outcome{}
	}
	p.SetSeq(t.StartSeq)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	go p.Serve(listener)
	serverURL := "http://" + listener.Addr().String()
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
	sseResults := map[string]streamEvidence{}
	grpcResults := map[string]int{}
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
	for stepIndex, s := range t.Script {
		if s.HTTP != nil {
			copy := *s.HTTP
			copy.URL = strings.ReplaceAll(copy.URL, "${DEMO_TLS}", demoTLS)
			s.HTTP = &copy
		}
		if s.Stream != nil {
			copy := *s.Stream
			copy.URL = strings.ReplaceAll(copy.URL, "${DEMO_TLS}", demoTLS)
			s.Stream = &copy
		}
		if s.GRPC != nil {
			copy := *s.GRPC
			copy.URL = strings.ReplaceAll(copy.URL, "${DEMO_TLS}", demoTLS)
			s.GRPC = &copy
		}
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
		if s.HTTP != nil || s.WS != nil || s.Stream != nil || s.GRPC != nil {
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
			requestURL := serverURL + s.HTTP.Path
			if s.HTTP.URL != "" {
				requestURL = s.HTTP.URL
			}
			req, e := http.NewRequestWithContext(ctx, method, requestURL, strings.NewReader(s.HTTP.Body))
			if e != nil {
				return nil, e
			}
			for k, v := range s.HTTP.Headers {
				req.Header.Set(k, v)
			}
			tr, e := replayTransport(req, serverURL, s.HTTP.URL != "", s.HTTP.Proto, roots)
			if e != nil {
				return nil, fmt.Errorf("step %s: %w", s.Name, e)
			}
			stepClient := &http.Client{Transport: tr, CheckRedirect: client.CheckRedirect}
			if replay {
				stepClient.CheckRedirect = func(next *http.Request, via []*http.Request) error {
					if len(via) >= 10 || next.URL.Scheme != "http" || next.URL.Host != listener.Addr().String() || next.URL.User != nil {
						return http.ErrUseLastResponse
					}
					if stepIndex+1 < len(t.Script) {
						hop := t.Script[stepIndex+1].HTTP
						if hop != nil {
							method := hop.Method
							if method == "" {
								method = http.MethodGet
							}
							hopURL := serverURL + hop.Path
							if hop.URL != "" {
								hopURL = strings.ReplaceAll(hop.URL, "${DEMO_TLS}", demoTLS)
							}
							if method == next.Method && hopURL == next.URL.String() {
								return http.ErrUseLastResponse
							}
						}
					}
					return nil
				}
			}
			seq := p.Seq() + 1
			resp, e := stepClient.Do(req)
			tr.CloseIdleConnections()
			transportFailure := false
			if e == nil {
				transportFailure = resp.Header.Get(proxy.TransportErrorHeader) != ""
				if (s.HTTP.Proto == "h2" || s.HTTP.Proto == "h2c") && resp.ProtoMajor != 2 {
					resp.Body.Close()
					return nil, fmt.Errorf("step %s: expected HTTP/2, got %s", s.Name, resp.Proto)
				}
				_, e = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if e != nil && (s.HTTP.Proto == "h2c" || s.HTTP.Proto == "h2") {
				if err := p.Wait(ctx); err != nil {
					return nil, err
				}
			}
			o := getOutcome(seq)
			if o.Err != nil {
				return nil, fmt.Errorf("step %s: %w", s.Name, o.Err)
			}
			if transportFailure {
				return nil, fmt.Errorf("step %s: proxy transport failure", s.Name)
			}
			if e != nil && !o.Reset && !o.H2Fault {
				return nil, fmt.Errorf("step %s: %w", s.Name, e)
			}
		case s.WS != nil:
			seq := p.Seq() + 1
			count := s.WS.Frames
			if count == 0 {
				count = 3
			}
			outcomeMu.Lock()
			outcomes[seq] = &outcome{limit: uint64(count)}
			outcomeMu.Unlock()
			stream, e := startWS(ctx, serverURL, *s.WS, isDemo, func(message uint64) {
				outcomeMu.Lock()
				delete(outcomes[seq].messages, message)
				outcomeMu.Unlock()
			})
			if e != nil {
				o := getOutcome(seq)
				if o.Err != nil {
					return nil, fmt.Errorf("step %s: %w", s.Name, o.Err)
				}
				if !abruptWS(o.WSAction, e) {
					return nil, fmt.Errorf("step %s: %w", s.Name, e)
				}
				failed := make(chan error, 1)
				failed <- e
				stream = failed
			}
			streams = append(streams, streamResult{seq: seq, ticker: isDemo && strings.SplitN(s.WS.Path, "?", 2)[0] == "/ws/ticker", ch: stream})
		case s.Stream != nil:
			if err := validateStepProtocol(s.Stream.URL, s.Stream.Proto); err != nil {
				return nil, fmt.Errorf("step %s: %w", s.Name, err)
			}
			sseResults[s.Name] = func() streamEvidence {
				runID, admission, cleanup := p.WatchSSEAdmission()
				defer cleanup()
				passthrough := t.TLSPassthrough
				if replay {
					passthrough = nil
				}
				return runStreamWithAdmission(ctx, serverURL, *s.Stream, nil, runID, admission, passthrough, t.TLSMITM, roots)
			}()
		case s.GRPC != nil:
			status, e := runGRPC(ctx, serverURL, *s.GRPC, roots)
			if e != nil {
				return nil, fmt.Errorf("step %s: %w", s.Name, e)
			}
			grpcResults[s.Name] = status
		}
	}
	for _, stream := range streams {
		select {
		case e := <-stream.ch:
			o := getOutcome(stream.seq)
			if o.Err != nil {
				return nil, o.Err
			}
			if e != nil && !abruptWS(o.WSAction, e) {
				var failure *wsFailure
				allowed := false
				if errors.As(e, &failure) {
					ev := o.messages[failure.message]
					var ne net.Error
					if errors.As(failure.err, &ne) && ne.Timeout() {
						allowed = (!ev.drop.IsZero() && !ev.drop.After(failure.at)) ||
							(!ev.delayAt.IsZero() && !ev.delayAt.After(failure.at) && failure.at.Before(ev.delay))
					} else if failure.invalidTicker {
						allowed = !ev.corrupt.IsZero() && !ev.corrupt.After(failure.at)
					}
				}
				if !allowed {
					return nil, fmt.Errorf("websocket sequence %d: %w", stream.seq, e)
				}
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
	results = make([]Result, 0, len(t.Assertions))
	diagnostics := assertionDiagnostics{remaining: assertionDiagnosticBudget}
	for _, a := range t.Assertions {
		result := Result{Name: a.Name, Failures: []string{}}
		if a.StreamStep != "" {
			e, ok := sseResults[a.StreamStep]
			if !ok {
				result.Failures = append(result.Failures, "unknown stream step")
			} else {
				result.Failures = checkStream(a, e)
			}
			results = append(results, result)
			continue
		}
		if a.GRPCStep != "" {
			status, ok := grpcResults[a.GRPCStep]
			if !ok {
				result.Failures = append(result.Failures, "unknown grpc step")
			} else if a.ExpectGRPCStatus != nil && status != *a.ExpectGRPCStatus {
				result.Failures = append(result.Failures, fmt.Sprintf("grpc_status: expected %d, got %d", *a.ExpectGRPCStatus, status))
			}
			results = append(results, result)
			continue
		}
		start := time.Now()
		base := serverURL
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
				result.Failures = append(result.Failures, diagnostics.compare(data, a.JSONEq, nil)...)
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
	stats := p.Stats()
	for _, expected := range t.Expect.Faults {
		actual := stats[expected.Rule].Applied
		r := Result{Name: "fault " + expected.Rule, Failures: []string{}}
		if expected.MinApplied != nil && actual < *expected.MinApplied {
			r.Failures = append(r.Failures, fmt.Sprintf("applied: expected >= %d, got %d", *expected.MinApplied, actual))
		}
		if expected.MaxApplied != nil && actual > *expected.MaxApplied {
			r.Failures = append(r.Failures, fmt.Sprintf("applied: expected <= %d, got %d", *expected.MaxApplied, actual))
		}
		results = append(results, r)
	}
	return results, nil
}

// CheckAssertionJSON compares the selected dotted keys against a JSON object.
func CheckAssertionJSON(body []byte, expected map[string]any, keys []string) []string {
	return checkAssertionJSON(body, expected, keys, false)
}

// CheckAssertionJSONRedacted reports the first JSON mismatch without exposing values.
func CheckAssertionJSONRedacted(body []byte, expected map[string]any) []string {
	return checkAssertionJSON(body, expected, nil, true)
}

func checkAssertionJSON(body []byte, expected map[string]any, keys []string, redact bool) []string {
	var data map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	err := decoder.Decode(&data)
	if err == nil {
		var extra any
		if err = decoder.Decode(&extra); err == nil {
			err = fmt.Errorf("multiple JSON documents")
		} else if err == io.EOF {
			err = nil
		}
	}
	if err != nil {
		if redact {
			return []string{"invalid JSON response"}
		}
		return []string{"invalid JSON response: " + err.Error()}
	}
	budget := assertionDiagnostics{remaining: assertionDiagnosticBudget, redact: redact}
	return budget.compare(data, expected, keys)
}

const assertionDiagnosticBudget = 64 << 10

type assertionDiagnostics struct {
	remaining int
	redact    bool
}

func (d *assertionDiagnostics) compare(data map[string]any, expected map[string]any, keys []string) []string {
	if keys == nil {
		keys = make([]string, 0, len(expected))
		for k := range expected {
			keys = append(keys, k)
		}
		sort.Strings(keys)
	}
	var failures []string
	var omitted int
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
		eb, _ := json.Marshal(expected[k])
		var en any
		ed := json.NewDecoder(bytes.NewReader(eb))
		ed.UseNumber()
		ed.Decode(&en)
		if present && jsonEqual(en, got) {
			continue
		}
		if d.redact {
			if !present {
				return []string{diagnosticPreview(k) + ": missing JSON field"}
			}
			return []string{diagnosticPreview(k) + ": JSON value mismatch"}
		}
		if d.remaining == 0 {
			omitted++
			continue
		}
		gb := []byte("<missing>")
		if present {
			gb, _ = json.Marshal(got)
		}
		failure := fmt.Sprintf("%s: expected %s, got %s", diagnosticPreview(k), diagnosticPreview(string(eb)), diagnosticPreview(string(gb)))
		if len(failure) > d.remaining {
			d.remaining = 0
			omitted++
			continue
		}
		d.remaining -= len(failure)
		failures = append(failures, failure)
	}
	if omitted != 0 {
		failures = append(failures, fmt.Sprintf("%d JSON mismatches omitted (diagnostics truncated)", omitted))
	}
	return failures
}

func diagnosticPreview(s string) string {
	if len(s) <= 256 {
		return s
	}
	return strings.ToValidUTF8(s[:256], "") + "… (truncated)"
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

type wsFailure struct {
	err           error
	message       uint64
	at            time.Time
	invalidTicker bool
}

func (e *wsFailure) Error() string { return e.err.Error() }
func (e *wsFailure) Unwrap() error { return e.err }

func abruptWS(action string, err error) bool {
	if action != "close_1006" && action != "truncate" {
		return false
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}
func startWS(ctx context.Context, base string, w WS, isDemo bool, progress ...func(uint64)) (<-chan error, error) {
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
	if isDemo && strings.SplitN(w.Path, "?", 2)[0] == "/ws/ticker" && timeout > 2500*time.Millisecond {
		timeout = 2500 * time.Millisecond
	}
	setDeadline()
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
				failure = &wsFailure{err: e, message: uint64(i + 1), at: time.Now()}
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
					failure = &wsFailure{err: fmt.Errorf("invalid ticker message"), message: uint64(i + 1), at: time.Now(), invalidTicker: true}
					return
				}
				message = nil
				opcode = 0
				i++
				if len(progress) != 0 {
					progress[0](uint64(i))
				}
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
