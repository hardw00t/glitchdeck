package tape

import (
	"net/http"
	"net/url"
	"strings"
)

type cassetteStepKey struct {
	method, path, host, digest string
}

func cassetteStepRequest(s Step, ignore []string) (cassetteStepKey, bool) {
	var method, path, address, body string
	switch {
	case s.HTTP != nil:
		method, path, address, body = s.HTTP.Method, s.HTTP.Path, s.HTTP.URL, s.HTTP.Body
	case s.Stream != nil:
		method, path, address, body = s.Stream.Method, s.Stream.Path, s.Stream.URL, s.Stream.Body
	default:
		return cassetteStepKey{}, false
	}
	if method == "" {
		method = http.MethodGet
	}
	if address != "" {
		path = address
	}
	u, err := url.Parse(path)
	if err != nil {
		return cassetteStepKey{}, false
	}
	path = u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return cassetteStepKey{strings.ToUpper(method), path, strings.ToLower(u.Host), BodySHA256([]byte(body), ignore)}, true
}

func cassetteRequestKey(r CassetteRequest) cassetteStepKey {
	return cassetteStepKey{strings.ToUpper(r.Method), r.Path, strings.ToLower(r.Host), r.BodySHA256}
}

func syncRedactedCassetteRequests(before Tape, after *Tape) error {
	blocked := func() error { return &ExportBlockedError{Kind: "redaction_collision", Field: "$.cassettes"} }
	if len(before.Cassettes) != len(after.Cassettes) || len(before.Script) != len(after.Script) {
		return blocked()
	}
	updated := make([]CassetteRequest, len(after.Cassettes))
	for i, cassette := range before.Cassettes {
		old := cassetteRequestKey(cassette.Request)
		updated[i] = after.Cassettes[i].Request
		var next cassetteStepKey
		found := false
		for j, step := range before.Script {
			key, ok := cassetteStepRequest(step, before.IgnoreJSONPaths)
			if !ok || key.method != old.method || key.path != old.path || key.digest != old.digest || old.host != "" && key.host != old.host {
				continue
			}
			candidate, ok := cassetteStepRequest(after.Script[j], after.IgnoreJSONPaths)
			if !ok {
				return blocked()
			}
			if old.host == "" {
				candidate.host = ""
			}
			if found && candidate != next {
				return blocked()
			}
			next, found = candidate, true
		}
		if found {
			updated[i].Method = next.method
			updated[i].Path = next.path
			updated[i].Host = next.host
			updated[i].BodySHA256 = next.digest
		}
	}
	overlap := func(x, y cassetteStepKey) bool {
		return x.method == y.method && x.path == y.path && x.digest == y.digest && (x.host == "" || y.host == "" || x.host == y.host)
	}
	for i := range updated {
		for j := range i {
			a, b := cassetteRequestKey(updated[i]), cassetteRequestKey(updated[j])
			oldA, oldB := cassetteRequestKey(before.Cassettes[i].Request), cassetteRequestKey(before.Cassettes[j].Request)
			if overlap(a, b) && !overlap(oldA, oldB) {
				return blocked()
			}
		}
	}
	for i := range updated {
		after.Cassettes[i].Request = updated[i]
	}
	return nil
}
