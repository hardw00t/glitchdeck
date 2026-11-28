package execrun

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/tape"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
)

type evidenceKey struct {
	method, path, host string
}

type tlsFailureEvidence struct {
	mu      sync.Mutex
	count   uint64
	details []json.RawMessage
}

type trafficHosts struct {
	mu  sync.Mutex
	tls []string
}

func (c *trafficHosts) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tls = nil
}

func (c *tlsFailureEvidence) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count, c.details = 0, nil
}

func (c *trafficHosts) observe(e telemetry.Event) {
	if e.Type != "tls_handshake_failed" {
		return
	}
	var data struct {
		Host string `json:"host"`
	}
	if json.Unmarshal(e.Data, &data) != nil {
		return
	}
	host := proxy.DiagnosticHostname(data.Host)
	const limit = 5
	if host == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	i := sort.SearchStrings(c.tls, host)
	if i == limit || i < len(c.tls) && c.tls[i] == host {
		return
	}
	if len(c.tls) < limit {
		c.tls = append(c.tls, "")
	}
	copy(c.tls[i+1:], c.tls[i:])
	c.tls[i] = host
}

func (c *trafficHosts) tlsList() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.tls, ", ")
}

func (c *tlsFailureEvidence) observe(e telemetry.Event) {
	if e.Type != "tls_handshake_failed" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	if len(c.details) < 100 && len(e.Data) <= 4096 {
		c.details = append(c.details, e.Data)
	}
}

func (c *tlsFailureEvidence) snapshot() (uint64, []json.RawMessage) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count, append([]json.RawMessage(nil), c.details...)
}

type assertionEvidence struct {
	mu       sync.Mutex
	quota    int
	limits   map[evidenceKey]int
	explicit map[uint64]bool
	selected map[uint64]evidenceKey
	events   map[uint64]map[string]telemetry.Event
}

func newAssertionEvidence(t tape.Tape) *assertionEvidence {
	c := &assertionEvidence{quota: len(t.Script), limits: make(map[evidenceKey]int), explicit: make(map[uint64]bool), selected: make(map[uint64]evidenceKey), events: make(map[uint64]map[string]telemetry.Event)}
	wanted := make(map[string]bool)
	for _, a := range t.Assertions {
		wanted[a.StreamStep] = a.StreamStep != ""
		wanted[a.GRPCStep] = a.GRPCStep != ""
	}
	for _, s := range t.Script {
		if !wanted[s.Name] {
			continue
		}
		key := evidenceKey{}
		var raw string
		if s.Stream != nil {
			key.method, key.path, raw = s.Stream.Method, s.Stream.Path, s.Stream.URL
			if key.method == "" {
				key.method = "GET"
			}
		} else if s.GRPC != nil {
			key.method, key.path, raw = "POST", s.GRPC.Path, s.GRPC.URL
		} else {
			continue
		}
		if raw != "" {
			if u, err := url.Parse(raw); err == nil {
				key.path, key.host = u.RequestURI(), strings.ToLower(u.Host)
			}
		}
		key.method = strings.ToUpper(key.method)
		c.limits[key] = c.quota
		if s.Seq != 0 {
			c.explicit[s.Seq] = true
		}
	}
	return c
}

func (c *assertionEvidence) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.selected)
	clear(c.events)
	for key := range c.limits {
		c.limits[key] = c.quota
	}
}

func (c *assertionEvidence) admit(seq uint64, method, path, host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	method = strings.ToUpper(method)
	for key, remaining := range c.limits {
		if key.method != method || key.path != path || key.host != "" && !strings.EqualFold(key.host, host) {
			continue
		}
		if remaining > 0 {
			c.limits[key]--
		} else if !c.explicit[seq] {
			continue
		}
		if match, ok := c.selected[seq]; !ok || match.host == "" && key.host != "" {
			c.selected[seq] = key
		}
	}
}

func (c *assertionEvidence) observe(e telemetry.Event) {
	if e.Type != "http_req" && e.Type != "grpc_call" && e.Type != "sse_event" {
		return
	}
	var v struct {
		Seq         uint64 `json:"seq"`
		Kind        string `json:"kind"`
		Method      string `json:"method"`
		ReplayIndex int    `json:"replay_index"`
		Error       string `json:"error"`
		Status      int    `json:"status"`
	}
	if json.Unmarshal(e.Data, &v) != nil || e.Type == "sse_event" && v.Kind != "end" ||
		e.Type == "http_req" && (v.ReplayIndex != 0 || v.Method == "" && v.Error != "egress_denied") {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key, ok := c.selected[v.Seq]
	if !ok {
		return
	}
	if e.Type == "http_req" && v.Error == "egress_denied" {
		// Restore the match key only in the private assertion view.
		e.Data, _ = json.Marshal(map[string]any{"seq": v.Seq, "status": v.Status, "method": key.method, "path": key.path, "host": key.host})
	}
	if c.events[v.Seq] == nil {
		c.events[v.Seq] = make(map[string]telemetry.Event)
	}
	c.events[v.Seq][e.Type] = e
}

func (c *assertionEvidence) history() []telemetry.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var events []telemetry.Event
	for _, entries := range c.events {
		for _, e := range entries {
			events = append(events, e)
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].ID < events[j].ID })
	return events
}

func observedAssertion(a tape.Assertion, t tape.Tape, events []telemetry.Event) tape.Result {
	r := tape.Result{Name: a.Name, Failures: []string{}}
	var path string
	var wantedSeq uint64
	method, host := "", ""
	occurrence := 0
	stepName := a.StreamStep
	if stepName == "" {
		stepName = a.GRPCStep
	}
	for _, s := range t.Script {
		if s.Name != stepName {
			continue
		}
		wantedSeq = s.Seq
		if s.Stream != nil {
			method = s.Stream.Method
			if method == "" {
				method = "GET"
			}
			path = s.Stream.Path
			if s.Stream.URL != "" {
				if u, err := url.Parse(s.Stream.URL); err == nil {
					host = u.Host
					path = u.RequestURI()
				}
			}
		} else if s.GRPC != nil {
			method = "POST"
			path = s.GRPC.Path
			if s.GRPC.URL != "" {
				if u, err := url.Parse(s.GRPC.URL); err == nil {
					host = u.Host
					path = u.RequestURI()
				}
			}
		}
		break
	}
	for _, s := range t.Script {
		if s.Name == stepName {
			break
		}
		stepPath := ""
		stepMethod, stepHost := "", ""
		switch {
		case s.HTTP != nil:
			stepMethod = s.HTTP.Method
			if stepMethod == "" {
				stepMethod = "GET"
			}
			stepPath = s.HTTP.Path
			if s.HTTP.URL != "" {
				if u, err := url.Parse(s.HTTP.URL); err == nil {
					stepHost = u.Host
					stepPath = u.RequestURI()
				}
			}
		case s.WS != nil:
			stepPath = s.WS.Path
			stepMethod = "GET"
		case s.Stream != nil:
			stepPath = s.Stream.Path
			stepMethod = s.Stream.Method
			if stepMethod == "" {
				stepMethod = "GET"
			}
			if s.Stream.URL != "" {
				if u, err := url.Parse(s.Stream.URL); err == nil {
					stepPath = u.RequestURI()
					stepHost = u.Host
				}
			}
		case s.GRPC != nil:
			stepPath = s.GRPC.Path
			stepMethod = "POST"
			if s.GRPC.URL != "" {
				if u, err := url.Parse(s.GRPC.URL); err == nil {
					stepHost = u.Host
					stepPath = u.RequestURI()
				}
			}
		}
		if stepPath == path && strings.EqualFold(stepMethod, method) && strings.EqualFold(stepHost, host) {
			occurrence++
		}
	}
	type request struct {
		Seq         uint64 `json:"seq"`
		Path        string `json:"path"`
		Method      string `json:"method"`
		Host        string `json:"host"`
		Status      int    `json:"status"`
		ReplayIndex int    `json:"replay_index"`
	}
	var requests []request
	for _, event := range events {
		if event.Type != "http_req" {
			continue
		}
		var v request
		if json.Unmarshal(event.Data, &v) == nil && v.ReplayIndex == 0 && v.Path == path &&
			(v.Method == "" || strings.EqualFold(v.Method, method)) &&
			(host == "" || strings.EqualFold(v.Host, host)) {
			requests = append(requests, v)
		}
	}
	sort.Slice(requests, func(i, j int) bool { return requests[i].Seq < requests[j].Seq })
	var seq uint64
	var httpStatus int
	for _, v := range requests {
		if wantedSeq != 0 {
			if v.Seq == wantedSeq {
				seq = v.Seq
				httpStatus = v.Status
				break
			}
		} else if occurrence == 0 {
			seq = v.Seq
			httpStatus = v.Status
			break
		} else {
			occurrence--
		}
	}
	if seq == 0 {
		r.Failures = append(r.Failures, "no matching observed request for step")
		return r
	}
	var end string
	terminal := "none"
	var count int
	var done bool
	var last, maxGap int64
	valid := true
	known := true
	found := false
	var opaque bool
	var status *int
	for _, event := range events {
		var v struct {
			Seq                uint64 `json:"seq"`
			Kind               string `json:"kind"`
			End                string `json:"end"`
			Terminal           string `json:"terminal"`
			Inspected          *bool  `json:"inspected"`
			Events             int    `json:"events"`
			Done               bool   `json:"is_done"`
			Preview            string `json:"preview"`
			DataBytes          int    `json:"data_bytes"`
			Time               int64  `json:"t_rel_ms"`
			Status             *int   `json:"grpc_status"`
			DeliveredEvents    *int   `json:"delivered_events"`
			DeliveredValidJSON *bool  `json:"delivered_valid_json"`
			DeliveredDone      *bool  `json:"delivered_done"`
			DeliveredMaxGapMS  *int64 `json:"delivered_max_gap_ms"`
		}
		if json.Unmarshal(event.Data, &v) != nil || v.Seq != seq {
			continue
		}
		if event.Type == "grpc_call" {
			found = true
			status = v.Status
		}
		if event.Type != "sse_event" {
			continue
		}
		found = true
		if v.Kind == "end" {
			opaque = v.Inspected != nil && !*v.Inspected
			end = v.End
			if v.Terminal != "" {
				terminal = v.Terminal
			}
			count = v.Events
			done = v.Done
			if v.DeliveredEvents != nil && v.DeliveredValidJSON != nil && v.DeliveredDone != nil && v.DeliveredMaxGapMS != nil {
				count, valid, done, maxGap = *v.DeliveredEvents, *v.DeliveredValidJSON, *v.DeliveredDone, *v.DeliveredMaxGapMS
				known = true
			}
			continue
		}
		if v.Kind == "event" {
			if v.Time-last > maxGap {
				maxGap = v.Time - last
			}
			last = v.Time
			if !v.Done && v.DataBytes > 0 {
				if len(v.Preview) < v.DataBytes {
					known = false
				} else if !json.Valid([]byte(v.Preview)) {
					valid = false
				}
			}
			if v.Done {
				done = true
			}
		}
	}
	if !found && (a.ExpectSSE != nil || a.ExpectGRPCStatus != nil) {
		r.Failures = append(r.Failures, "no protocol observation for step")
		return r
	}
	add := func(field string, want, got any) {
		r.Failures = append(r.Failures, fmt.Sprintf("%s: expected %v, got %v", field, want, got))
	}
	if a.ExpectGRPCStatus != nil {
		if status == nil {
			r.Failures = append(r.Failures, "grpc status not observed")
		} else if *status != *a.ExpectGRPCStatus {
			add("grpc_status", *a.ExpectGRPCStatus, *status)
		}
	}
	if a.ExpectStatus != 0 && a.ExpectStatus != httpStatus {
		add("status", a.ExpectStatus, httpStatus)
	}
	if x := a.ExpectSSE; x != nil {
		if opaque {
			r.Failures = append(r.Failures, "SSE frames not inspected for compressed pass-through")
			return r
		}
		if x.End != "" && x.End != end {
			add("end", x.End, end)
		}
		if x.Terminal != "" && x.Terminal != terminal {
			add("terminal", x.Terminal, terminal)
		}
		if x.Done != nil && *x.Done != done {
			add("done", *x.Done, done)
		}
		if x.MinEvents != nil && count < *x.MinEvents {
			add("min_events", *x.MinEvents, count)
		}
		if x.MaxEvents != nil && count > *x.MaxEvents {
			add("max_events", *x.MaxEvents, count)
		}
		if x.ValidJSON != nil {
			if !known && valid {
				r.Failures = append(r.Failures, "JSON validity unavailable for truncated telemetry preview")
			} else if *x.ValidJSON != valid {
				add("valid_json", *x.ValidJSON, valid)
			}
		}
		if x.MaxGapMS != nil && maxGap > int64(*x.MaxGapMS) {
			add("max_gap_ms", *x.MaxGapMS, maxGap)
		}
	}
	return r
}
