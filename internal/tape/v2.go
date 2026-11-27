package tape

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/sse"
)

type Stream struct {
	Method        string            `yaml:"method,omitempty" json:"method,omitempty"`
	Path          string            `yaml:"path,omitempty" json:"path,omitempty"`
	URL           string            `yaml:"url,omitempty" json:"url,omitempty"`
	Proto         string            `yaml:"proto,omitempty" json:"proto,omitempty"`
	Headers       map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Body          string            `yaml:"body,omitempty" json:"body,omitempty"`
	IdleTimeoutMS int               `yaml:"idle_timeout_ms,omitempty" json:"idle_timeout_ms,omitempty"`
	MaxMS         int               `yaml:"max_ms,omitempty" json:"max_ms,omitempty"`
}
type GRPC struct {
	Path       string `yaml:"path,omitempty" json:"path,omitempty"`
	URL        string `yaml:"url,omitempty" json:"url,omitempty"`
	MessageB64 string `yaml:"message_b64,omitempty" json:"message_b64,omitempty"`
	Proto      string `yaml:"proto,omitempty" json:"proto,omitempty"`
	TimeoutMS  int    `yaml:"timeout_ms,omitempty" json:"timeout_ms,omitempty"`
}
type Expect struct {
	ChildExit any           `yaml:"child_exit,omitempty" json:"child_exit,omitempty"`
	Faults    []FaultExpect `yaml:"faults,omitempty" json:"faults,omitempty"`
}
type FaultExpect struct {
	Rule       string  `yaml:"rule" json:"rule"`
	MinApplied *uint64 `yaml:"min_applied,omitempty" json:"min_applied,omitempty"`
	MaxApplied *uint64 `yaml:"max_applied,omitempty" json:"max_applied,omitempty"`
}
type SSEExpect struct {
	End       string `yaml:"end,omitempty" json:"end,omitempty"`
	Terminal  string `yaml:"terminal,omitempty" json:"terminal,omitempty"`
	Done      *bool  `yaml:"done,omitempty" json:"done,omitempty"`
	MinEvents *int   `yaml:"min_events,omitempty" json:"min_events,omitempty"`
	MaxEvents *int   `yaml:"max_events,omitempty" json:"max_events,omitempty"`
	ValidJSON *bool  `yaml:"valid_json,omitempty" json:"valid_json,omitempty"`
	MaxGapMS  *int   `yaml:"max_gap_ms,omitempty" json:"max_gap_ms,omitempty"`
}
type streamEvidence struct {
	End       string
	Terminal  string
	Status    int
	Done      bool
	Events    int
	ValidJSON bool
	MaxGapMS  int64
	Inspected bool
}

func runStream(ctx context.Context, base string, s Stream, root ...*x509.CertPool) streamEvidence {
	return runStreamWithTerminals(ctx, base, s, nil, root...)
}

func runStreamWithTerminals(ctx context.Context, base string, s Stream, extra []string, root ...*x509.CertPool) streamEvidence {
	return runStreamWithAdmission(ctx, base, s, extra, "", nil, nil, false, root...)
}

func runStreamWithAdmission(ctx context.Context, base string, s Stream, extra []string, runID string, admission <-chan []string, passthrough []string, intercept bool, root ...*x509.CertPool) streamEvidence {
	result := streamEvidence{End: "eof", Terminal: "none", ValidJSON: true}
	if s.MaxMS <= 0 {
		s.MaxMS = 30000
	}
	if s.IdleTimeoutMS <= 0 {
		s.IdleTimeoutMS = 5000
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(s.MaxMS)*time.Millisecond)
	defer cancel()
	method := s.Method
	if method == "" {
		method = http.MethodGet
	}
	path := base + s.Path
	if s.URL != "" {
		path = s.URL
	}
	req, err := http.NewRequestWithContext(ctx, method, path, strings.NewReader(s.Body))
	if err != nil {
		result.End = "error"
		return result
	}
	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Del(proxy.SSEAdmissionHeader)
	if runID != "" {
		tunneled := s.URL != "" && strings.EqualFold(req.URL.Scheme, "https")
		port := req.URL.Port()
		if port == "" {
			port = "443"
		}
		_, matched := proxy.MatchPassthrough(passthrough, req.URL.Hostname(), port)
		if !tunneled || intercept && !matched {
			req.Header.Set(proxy.SSEAdmissionHeader, runID)
		}
	}
	var roots *x509.CertPool
	if len(root) != 0 {
		roots = root[0]
	}
	transport, err := replayTransport(req, base, s.URL != "", s.Proto, roots)
	if err != nil {
		result.End = "error"
		return result
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	type response struct {
		resp *http.Response
		err  error
	}
	responses := make(chan response)
	go func() {
		resp, err := client.Do(req)
		select {
		case responses <- response{resp, err}:
		case <-ctx.Done():
			if resp != nil {
				resp.Body.Close()
			}
		}
	}()
	var resp *http.Response
	timer := time.NewTimer(time.Duration(s.IdleTimeoutMS) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		result.End = "max_ms"
		return result
	case <-timer.C:
		result.End = "idle_timeout"
		return result
	case r := <-responses:
		resp = r.resp
		if r.err != nil {
			if ctx.Err() != nil {
				result.End = "max_ms"
			} else {
				result.End = "rst"
			}
			return result
		}
	}
	defer resp.Body.Close()
	result.Status = resp.StatusCode
	if admission != nil {
		select {
		case extra = <-admission:
		default:
		}
	}
	media, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	encoding := strings.TrimSpace(resp.Header.Get("Content-Encoding"))
	if media != "text/event-stream" || (encoding != "" && !strings.EqualFold(encoding, "identity")) {
		return result
	}
	result.Inspected = true
	if (s.Proto == "h2" || s.Proto == "h2c") && resp.ProtoMajor != 2 {
		result.End = "error"
		return result
	}
	type item struct {
		frame sse.Frame
		err   error
	}
	frames := make(chan item, 1)
	go func() {
		r := sse.NewReader(resp.Body, 0)
		r.LimitFrameLines(64 << 10)
		for {
			frame, e := r.Next()
			select {
			case frames <- item{frame, e}:
			case <-ctx.Done():
				return
			}
			if e != nil {
				return
			}
		}
	}()
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(time.Duration(s.IdleTimeoutMS) * time.Millisecond)
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			result.End = "max_ms"
			return result
		case <-timer.C:
			result.End = "idle_timeout"
			return result
		case x := <-frames:
			if x.err != nil {
				if x.err != io.EOF {
					if errors.Is(x.err, sse.ErrLineTooLong) {
						result.Inspected = false
					}
					result.End = "rst"
				} else if result.Events > 0 && result.Terminal == "none" {
					result.End = "eof_early"
				}
				return result
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(time.Duration(s.IdleTimeoutMS) * time.Millisecond)
			if !x.frame.Dispatch {
				continue
			}
			result.Events++
			gap := time.Since(last).Milliseconds()
			if gap > result.MaxGapMS {
				result.MaxGapMS = gap
			}
			last = time.Now()
			if x.frame.IsJSON() && !json.Valid([]byte(x.frame.Data)) {
				result.ValidJSON = false
			}
			if kind, ok := x.frame.Terminal(extra); ok && result.Terminal == "none" {
				result.Terminal = kind
				result.Done = kind != "error"
			}
			if x.frame.IsDone() {
				result.End = "done"
				return result
			}
			if x.frame.Event == "message_stop" {
				result.End = "eof"
				return result
			}
		}
	}
}

func validateStepProtocol(rawURL, protocol string) error {
	scheme := "http"
	if rawURL != "" {
		u, err := url.Parse(strings.ReplaceAll(rawURL, "${DEMO_TLS}", "https://127.0.0.1"))
		if err != nil || !u.IsAbs() || u.Host == "" {
			return fmt.Errorf("expected an absolute HTTP or HTTPS URL")
		}
		scheme = u.Scheme
	}
	return validateProtocol(scheme, protocol)
}

func validateProtocol(scheme, protocol string) error {
	if scheme != "https" && scheme != "http" {
		return fmt.Errorf("expected HTTP or HTTPS scheme")
	}
	switch protocol {
	case "", "h1":
	case "h2":
		if scheme != "https" {
			return fmt.Errorf("h2 requires an HTTPS URL")
		}
	case "h2c":
		if scheme != "http" {
			return fmt.Errorf("h2c requires cleartext HTTP")
		}
	default:
		return fmt.Errorf("invalid HTTP protocol %q", protocol)
	}
	return nil
}

func replayTransport(req *http.Request, base string, forward bool, protocol string, roots *x509.CertPool) (*http.Transport, error) {
	if err := validateProtocol(req.URL.Scheme, protocol); err != nil {
		return nil, err
	}
	endpoint, err := url.Parse(base)
	if err != nil || endpoint.Host == "" {
		return nil, fmt.Errorf("invalid replay proxy endpoint")
	}
	dialer := &net.Dialer{}
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, endpoint.Host)
		},
	}
	switch protocol {
	case "h2":
		tr.Protocols = new(http.Protocols)
		tr.Protocols.SetHTTP2(true)
	case "h2c":
		tr.Protocols = proxy.H2CProtocols()
	}
	if roots != nil {
		tr.TLSClientConfig = &tls.Config{RootCAs: roots}
	}
	if forward {
		if protocol == "h2c" {
			// HTTP/2 carries the target authority separately from the dial address.
			req.Header.Set(proxy.ForwardH2CHeader, "1")
		} else {
			tr.Proxy = http.ProxyURL(endpoint)
		}
	}
	return tr, nil
}

func runGRPC(ctx context.Context, base string, g GRPC, root ...*x509.CertPool) (int, error) {
	payload, err := base64.StdEncoding.DecodeString(g.MessageB64)
	if err != nil {
		return 0, err
	}
	body := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(body[1:5], uint32(len(payload)))
	copy(body[5:], payload)
	if g.TimeoutMS > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(g.TimeoutMS)*time.Millisecond)
		defer cancel()
	}
	path := base + g.Path
	var roots *x509.CertPool
	if len(root) != 0 {
		roots = root[0]
	}
	if g.URL != "" {
		path = g.URL
	}
	req, err := http.NewRequestWithContext(ctx, "POST", path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	protocol := g.Proto
	if protocol == "" {
		protocol = "h2c"
		if req.URL.Scheme == "https" {
			protocol = "h2"
		}
	}
	transport, err := replayTransport(req, base, g.URL != "", protocol, roots)
	if err != nil {
		return 0, err
	}
	defer transport.CloseIdleConnections()
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	if g.TimeoutMS > 0 {
		req.Header.Set("grpc-timeout", strconv.Itoa(g.TimeoutMS)+"m")
	}
	c := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return 4, nil
		}
		return 0, err
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		return 0, fmt.Errorf("expected HTTP/2, got %s", resp.Proto)
	}
	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return 4, nil
		}
		return 0, err
	}
	status := resp.Trailer.Get("grpc-status")
	if status == "" {
		status = resp.Header.Get("grpc-status")
	}
	n, err := strconv.Atoi(status)
	if err != nil {
		return 0, fmt.Errorf("missing grpc status")
	}
	return n, nil
}
func checkStream(a Assertion, e streamEvidence) []string {
	out := []string{}
	if a.ExpectStatus != 0 && a.ExpectStatus != e.Status {
		out = append(out, fmt.Sprintf("status: expected %d, got %d", a.ExpectStatus, e.Status))
	}
	x := a.ExpectSSE
	if x == nil {
		return out
	}
	if !e.Inspected {
		return append(out, "SSE response was not inspected")
	}
	add := func(field string, want, got any) {
		out = append(out, fmt.Sprintf("%s: expected %v, got %v", field, want, got))
	}
	if x.End != "" && x.End != e.End {
		add("end", x.End, e.End)
	}
	if x.Terminal != "" && x.Terminal != e.Terminal {
		add("terminal", x.Terminal, e.Terminal)
	}
	if x.Done != nil && *x.Done != e.Done {
		add("done", *x.Done, e.Done)
	}
	if x.MinEvents != nil && e.Events < *x.MinEvents {
		add("min_events", *x.MinEvents, e.Events)
	}
	if x.MaxEvents != nil && e.Events > *x.MaxEvents {
		add("max_events", *x.MaxEvents, e.Events)
	}
	if x.ValidJSON != nil && *x.ValidJSON != e.ValidJSON {
		add("valid_json", *x.ValidJSON, e.ValidJSON)
	}
	if x.MaxGapMS != nil && e.MaxGapMS > int64(*x.MaxGapMS) {
		add("max_gap_ms", *x.MaxGapMS, e.MaxGapMS)
	}
	return out
}
