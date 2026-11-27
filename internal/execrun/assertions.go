package execrun

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hardw00t/glitchdeck/internal/tape"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
)

type assertionLimits struct {
	remaining int
	omitted   int
}

func (l *assertionLimits) trim(r tape.Result) tape.Result {
	for _, failure := range r.Failures {
		l.remaining -= len(failure)
		if l.remaining < 0 {
			l.omitted++
			r.Failures = []string{"assertion diagnostics omitted"}
			break
		}
	}
	return r
}

func assertions(ctx context.Context, t tape.Tape, proxyURL, directURL, password string, events []telemetry.Event, limits *assertionLimits, roots ...*x509.CertPool) []tape.Result {
	if len(t.Assertions) == 0 {
		return nil
	}
	private := limits != nil
	out := make([]tape.Result, 0, len(t.Assertions))
	add := func(r tape.Result) {
		if private {
			r = limits.trim(r)
		}
		out = append(out, r)
	}
	client := http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if private || len(roots) > 0 && roots[0] != nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if private {
			transport.Proxy = nil
		}
		if len(roots) > 0 && roots[0] != nil {
			transport.TLSClientConfig = &tls.Config{RootCAs: roots[0], MinVersion: tls.VersionTLS12}
		}
		client.Transport = transport
		defer transport.CloseIdleConnections()
	}
	for _, a := range t.Assertions {
		if private && ctx.Err() != nil {
			break
		}
		if a.HTTPGet == "" {
			add(observedAssertion(a, t, events))
			continue
		}
		r := tape.Result{Name: a.Name, Failures: []string{}}
		base := proxyURL
		if a.Direct {
			base = directURL
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+a.HTTPGet, nil)
		if err != nil {
			r.Failures = append(r.Failures, "invalid assertion request URL")
			add(r)
			continue
		}
		if password != "" && !a.Direct {
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("glitchdeck:"+password)))
		}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			if private {
				r.Failures = append(r.Failures, "assertion request failed")
				add(r)
				continue
			}
			safeURL := *req.URL
			safeURL.User = nil
			safeURL.RawQuery = ""
			safeURL.Fragment = ""
			r.Failures = append(r.Failures, fmt.Sprintf("assertion request failed: %s", safeURL.String()))
			add(r)
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if err != nil {
			if private {
				r.Failures = append(r.Failures, "could not read assertion response")
			} else {
				r.Failures = append(r.Failures, err.Error())
			}
		}
		if a.ExpectStatus != 0 && resp.StatusCode != a.ExpectStatus {
			r.Failures = append(r.Failures, fmt.Sprintf("status: expected %d, got %d", a.ExpectStatus, resp.StatusCode))
		}
		if a.MaxLatencyMS > 0 && time.Since(start) > time.Duration(a.MaxLatencyMS)*time.Millisecond {
			r.Failures = append(r.Failures, "latency exceeded")
		}
		if len(a.JSONEq) > 0 {
			if private {
				r.Failures = append(r.Failures, tape.CheckAssertionJSONRedacted(body, a.JSONEq)...)
			} else {
				r.Failures = append(r.Failures, tape.CheckAssertionJSON(body, a.JSONEq, nil)...)
			}
		}
		add(r)
	}
	return out
}
