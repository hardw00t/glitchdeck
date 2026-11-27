package execrun

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hardw00t/glitchdeck/internal/tape"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
)

func assertions(ctx context.Context, t tape.Tape, proxyURL, directURL, password string, events []telemetry.Event) []tape.Result {
	out := make([]tape.Result, 0, len(t.Assertions))
	client := http.Client{Timeout: 10 * time.Second}
	for _, a := range t.Assertions {
		if a.HTTPGet == "" {
			out = append(out, observedAssertion(a, t, events))
			continue
		}
		r := tape.Result{Name: a.Name, Failures: []string{}}
		base := proxyURL
		if a.Direct {
			base = directURL
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+a.HTTPGet, nil)
		if err != nil {
			r.Failures = append(r.Failures, err.Error())
			out = append(out, r)
			continue
		}
		if password != "" && !a.Direct {
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("glitchdeck:"+password)))
		}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			r.Failures = append(r.Failures, err.Error())
			out = append(out, r)
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if err != nil {
			r.Failures = append(r.Failures, err.Error())
		}
		if a.ExpectStatus != 0 && resp.StatusCode != a.ExpectStatus {
			r.Failures = append(r.Failures, fmt.Sprintf("status: expected %d, got %d", a.ExpectStatus, resp.StatusCode))
		}
		if a.MaxLatencyMS > 0 && time.Since(start) > time.Duration(a.MaxLatencyMS)*time.Millisecond {
			r.Failures = append(r.Failures, "latency exceeded")
		}
		if len(a.JSONEq) > 0 {
			r.Failures = append(r.Failures, tape.CheckAssertionJSON(body, a.JSONEq, nil)...)
		}
		out = append(out, r)
	}
	return out
}
