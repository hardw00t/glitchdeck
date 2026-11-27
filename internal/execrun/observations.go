package execrun

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/hardw00t/glitchdeck/internal/tape"
	"github.com/hardw00t/glitchdeck/internal/telemetry"
)

func observedAssertion(a tape.Assertion, t tape.Tape, events []telemetry.Event) tape.Result {
	r := tape.Result{Name: a.Name, Failures: []string{}}
	var path string
	var wantedSeq uint64
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
			path = s.Stream.Path
			if s.Stream.URL != "" {
				if u, err := url.Parse(s.Stream.URL); err == nil {
					path = u.RequestURI()
				}
			}
		} else if s.GRPC != nil {
			path = s.GRPC.Path
			if s.GRPC.URL != "" {
				if u, err := url.Parse(s.GRPC.URL); err == nil {
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
		switch {
		case s.HTTP != nil:
			stepPath = s.HTTP.Path
			if s.HTTP.URL != "" {
				if u, err := url.Parse(s.HTTP.URL); err == nil {
					stepPath = u.RequestURI()
				}
			}
		case s.WS != nil:
			stepPath = s.WS.Path
		case s.Stream != nil:
			stepPath = s.Stream.Path
			if s.Stream.URL != "" {
				if u, err := url.Parse(s.Stream.URL); err == nil {
					stepPath = u.RequestURI()
				}
			}
		case s.GRPC != nil:
			stepPath = s.GRPC.Path
			if s.GRPC.URL != "" {
				if u, err := url.Parse(s.GRPC.URL); err == nil {
					stepPath = u.RequestURI()
				}
			}
		}
		if stepPath == path {
			occurrence++
		}
	}
	var seq uint64
	for _, event := range events {
		if event.Type != "http_req" {
			continue
		}
		var v struct {
			Seq  uint64 `json:"seq"`
			Path string `json:"path"`
		}
		if json.Unmarshal(event.Data, &v) != nil || v.Path != path {
			continue
		}
		if wantedSeq != 0 {
			if v.Seq == wantedSeq {
				seq = v.Seq
				break
			}
		} else if occurrence == 0 {
			seq = v.Seq
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
	var count int
	var done bool
	var last, maxGap int64
	valid := true
	known := true
	found := false
	var status *int
	for _, event := range events {
		var v struct {
			Seq       uint64 `json:"seq"`
			Kind      string `json:"kind"`
			End       string `json:"end"`
			Events    int    `json:"events"`
			Done      bool   `json:"is_done"`
			Preview   string `json:"preview"`
			DataBytes int    `json:"data_bytes"`
			Time      int64  `json:"t_rel_ms"`
			Status    *int   `json:"grpc_status"`
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
			end = v.End
			count = v.Events
			done = v.Done
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
	if !found {
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
	if x := a.ExpectSSE; x != nil {
		if x.End != "" && x.End != end {
			add("end", x.End, end)
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
