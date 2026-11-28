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
	u, err := url.Parse(strings.ReplaceAll(path, "${DEMO_TLS}", "https://localhost"))
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
	type stepKeys struct {
		before, after     cassetteStepKey
		beforeOK, afterOK bool
	}
	keys := make([]stepKeys, len(before.Script))
	for i := range before.Script {
		keys[i].before, keys[i].beforeOK = cassetteStepRequest(before.Script[i], before.IgnoreJSONPaths)
		keys[i].after, keys[i].afterOK = cassetteStepRequest(after.Script[i], after.IgnoreJSONPaths)
		if keys[i].beforeOK && keys[i].before.digest == "" || keys[i].afterOK && keys[i].after.digest == "" {
			return blocked()
		}
	}
	for i, cassette := range before.Cassettes {
		old := cassetteRequestKey(cassette.Request)
		updated[i] = after.Cassettes[i].Request
		var next cassetteStepKey
		found := false
		for _, step := range keys {
			key, ok := step.before, step.beforeOK
			if !ok || key.method != old.method || key.path != old.path || key.digest != old.digest || old.host != "" && key.host != "" && !overlappingAuthorities(key.host, old.host) {
				continue
			}
			candidate, ok := step.after, step.afterOK
			if !ok {
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
