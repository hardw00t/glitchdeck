package tape

import (
	"net/http"
	"net/url"
	"strings"
)

type cassetteStepKey struct {
	method, path, host, digest string
}

func cassetteStepRequest(s Step) (cassetteStepKey, string, bool) {
	var method, path, address, body string
	switch {
	case s.HTTP != nil:
		method, path, address, body = s.HTTP.Method, s.HTTP.Path, s.HTTP.URL, s.HTTP.Body
	case s.Stream != nil:
		method, path, address, body = s.Stream.Method, s.Stream.Path, s.Stream.URL, s.Stream.Body
	default:
		return cassetteStepKey{}, "", false
	}
	if method == "" {
		method = http.MethodGet
	}
	if address != "" {
		path = address
	}
	u, err := url.Parse(strings.ReplaceAll(path, "${DEMO_TLS}", "https://localhost"))
	if err != nil {
		return cassetteStepKey{}, "", false
	}
	path = u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return cassetteStepKey{method: strings.ToUpper(method), path: path, host: strings.ToLower(u.Host)}, body, true
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
	matcher := NewBodyMatcher(before.IgnoreJSONPaths)
	afterMatcher := NewBodyMatcher(after.IgnoreJSONPaths)
	for i, cassette := range before.Cassettes {
		old := cassetteRequestKey(cassette.Request)
		updated[i] = after.Cassettes[i].Request
		var next cassetteStepKey
		found := false
		for j, step := range before.Script {
			key, body, ok := cassetteStepRequest(step)
			if !ok || key.method != old.method || key.path != old.path || old.host != "" && key.host != "" && !overlappingAuthorities(key.host, old.host) {
				continue
			}
			key.digest = matcher.SHA256([]byte(body))
			if key.digest == "" {
				return blocked()
			}
			if key.digest != old.digest {
				continue
			}
			candidate, afterBody, ok := cassetteStepRequest(after.Script[j])
			if !ok {
				return blocked()
			}
			candidate.digest = afterMatcher.SHA256([]byte(afterBody))
			if candidate.digest == "" {
				return blocked()
			}
			if old.host == "" {
				candidate.host = ""
			} else if candidate.host == "" {
				candidate.host = old.host
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
		return x.method == y.method && x.path == y.path && x.digest == y.digest && (x.host == "" || y.host == "" || overlappingAuthorities(x.host, y.host))
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

func overlappingAuthorities(a, b string) bool {
	return SameAuthority(a, b, "http") || SameAuthority(a, b, "https")
}
