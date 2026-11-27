package tape

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/sse"
)

type Stream struct {
	Method        string            `yaml:"method,omitempty" json:"method,omitempty"`
	Path          string            `yaml:"path,omitempty" json:"path,omitempty"`
	URL           string            `yaml:"url,omitempty" json:"url,omitempty"`
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
	Done      *bool  `yaml:"done,omitempty" json:"done,omitempty"`
	MinEvents *int   `yaml:"min_events,omitempty" json:"min_events,omitempty"`
	MaxEvents *int   `yaml:"max_events,omitempty" json:"max_events,omitempty"`
	ValidJSON *bool  `yaml:"valid_json,omitempty" json:"valid_json,omitempty"`
	MaxGapMS  *int   `yaml:"max_gap_ms,omitempty" json:"max_gap_ms,omitempty"`
}
type streamEvidence struct {
	End       string
	Done      bool
	Events    int
	ValidJSON bool
	MaxGapMS  int64
}

func runStream(ctx context.Context, base string, s Stream, root ...*x509.CertPool) streamEvidence {
	result := streamEvidence{End: "eof", ValidJSON: true}
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
	transport := &http.Transport{DisableKeepAlives: true}
	if len(root) > 0 && root[0] != nil {
		transport.TLSClientConfig = &tls.Config{RootCAs: root[0]}
	}
	if s.URL != "" {
		proxyURL, _ := url.Parse(base)
		transport.Proxy = http.ProxyURL(proxyURL)
	}
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
	type item struct {
		frame sse.Frame
		err   error
	}
	frames := make(chan item, 1)
	go func() {
		r := sse.NewReader(resp.Body, 0)
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
					result.End = "rst"
				} else if result.Events > 0 {
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
			if x.frame.IsDone() {
				result.Done = true
				result.End = "done"
				return result
			}
			if x.frame.Event == "message_stop" {
				result.Done = true
				result.End = "eof"
				return result
			}
			if x.frame.Data != "" && !json.Valid([]byte(x.frame.Data)) {
				result.ValidJSON = false
			}
		}
	}
}

// HTTP/2 carries the target authority separately from the dial address.
func routeH2CForward(tr *http.Transport, req *http.Request, base string) {
	endpoint, _ := url.Parse(base)
	tr.Protocols = proxy.H2CProtocols()
	networkDialer := &net.Dialer{}
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return networkDialer.DialContext(ctx, network, endpoint.Host)
	}
	req.Header.Set(proxy.ForwardH2CHeader, "1")
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
	transport := &http.Transport{Protocols: proxy.H2CProtocols()}
	if len(root) > 0 && root[0] != nil {
		transport.TLSClientConfig = &tls.Config{RootCAs: root[0]}
	}
	if g.URL != "" {
		path = g.URL
		if strings.HasPrefix(path, "https://") {
			proxyURL, _ := url.Parse(base)
			transport.Proxy = http.ProxyURL(proxyURL)
			transport.Protocols = nil
			transport.ForceAttemptHTTP2 = true
		}
	}
	req, err := http.NewRequestWithContext(ctx, "POST", path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	defer transport.CloseIdleConnections()
	if g.URL != "" && req.URL.Scheme == "http" {
		routeH2CForward(transport, req, base)
	}
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
	x := a.ExpectSSE
	if x == nil {
		return out
	}
	add := func(field string, want, got any) {
		out = append(out, fmt.Sprintf("%s: expected %v, got %v", field, want, got))
	}
	if x.End != "" && x.End != e.End {
		add("end", x.End, e.End)
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

func h2FaultApplied(rules []fault.Rule, before, after map[string]proxy.RuleStats) bool {
	for _, r := range rules {
		if r.Fault.Type == "h2-glitch" && after[r.ID].Applied > before[r.ID].Applied {
			return true
		}
	}
	return false
}
