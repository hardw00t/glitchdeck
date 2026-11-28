package tape

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/hardw00t/glitchdeck/internal/proxy"
)

const maxCassetteBody = 4 << 20

func validCassetteMethod(method string) bool {
	if method == "" {
		return false
	}
	for i := range len(method) {
		c := method[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}

type Cassette struct {
	Request  CassetteRequest  `yaml:"request" json:"request"`
	Response CassetteResponse `yaml:"response" json:"response"`
}

type CassetteRequest struct {
	Method     string `yaml:"method" json:"method"`
	Path       string `yaml:"path" json:"path"`
	Host       string `yaml:"host,omitempty" json:"host,omitempty"`
	BodySHA256 string `yaml:"body_sha256,omitempty" json:"body_sha256,omitempty"`
}

type CassetteResponse struct {
	Status       int               `yaml:"status" json:"status"`
	Headers      map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Body         string            `yaml:"body,omitempty" json:"body,omitempty"`
	BodyEncoding string            `yaml:"body_encoding,omitempty" json:"body_encoding,omitempty"`
	Truncated    bool              `yaml:"truncated,omitempty" json:"truncated,omitempty"`
}

func (r CassetteResponse) Bytes() ([]byte, error) {
	switch r.BodyEncoding {
	case "":
		if !utf8.ValidString(r.Body) {
			return nil, fmt.Errorf("invalid UTF-8 cassette body")
		}
		return []byte(r.Body), nil
	case "base64":
		return base64.StdEncoding.DecodeString(r.Body)
	default:
		return nil, fmt.Errorf("invalid cassette body encoding")
	}
}

func NewCassetteResponse(status int, headers map[string]string, body []byte, truncated bool) CassetteResponse {
	r := CassetteResponse{Status: status, Headers: headers, Truncated: truncated}
	if utf8.Valid(body) {
		r.Body = string(body)
	} else {
		r.Body = base64.StdEncoding.EncodeToString(body)
		r.BodyEncoding = "base64"
	}
	return r
}

func BodySHA256(body []byte, ignore []string) string {
	var value any
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if d.Decode(&value) == nil {
		var extra any
		if d.Decode(&extra) == io.EOF {
			for _, path := range ignore {
				parts := strings.Split(path, ".")
				obj, ok := value.(map[string]any)
				for _, part := range parts[:len(parts)-1] {
					if !ok {
						break
					}
					obj, ok = obj[part].(map[string]any)
				}
				if ok {
					delete(obj, parts[len(parts)-1])
				}
			}
			var b bytes.Buffer
			enc := json.NewEncoder(&b)
			enc.SetEscapeHTML(false)
			if enc.Encode(value) == nil {
				body = bytes.TrimSuffix(b.Bytes(), []byte("\n"))
			}
		}
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func (t Tape) CassetteUpstream() func(*http.Request) (*http.Response, error) {
	type replayCassette struct {
		cassette Cassette
		valid    bool
	}
	cassettes := make([]replayCassette, len(t.Cassettes))
	for i, c := range t.Cassettes {
		valid := !c.Response.Truncated && c.Response.Status >= 100 && c.Response.Status <= 599
		switch c.Response.BodyEncoding {
		case "":
			valid = valid && utf8.ValidString(c.Response.Body) && len(c.Response.Body) <= maxCassetteBody
		case "base64":
			body, err := base64.StdEncoding.DecodeString(c.Response.Body)
			valid = valid && err == nil && len(body) <= maxCassetteBody
			c.Response.Body = string(body)
		default:
			valid = false
		}
		if c.Response.Headers != nil {
			headers := make(map[string]string, len(c.Response.Headers))
			for k, v := range c.Response.Headers {
				headers[k] = v
			}
			c.Response.Headers = headers
		}
		cassettes[i] = replayCassette{cassette: c, valid: valid}
	}
	ignore := append([]string(nil), t.IgnoreJSONPaths...)
	return func(req *http.Request) (*http.Response, error) {
		path := req.URL.EscapedPath()
		matches := func(c Cassette) bool {
			return strings.EqualFold(c.Request.Method, req.Method) && c.Request.Path == path && (c.Request.Host == "" || strings.EqualFold(c.Request.Host, req.Host))
		}
		miss := func() (*http.Response, error) { return nil, &proxy.CassetteError{Kind: "cassette_miss"} }
		index, count := -1, 0
		for i := range cassettes {
			if matches(cassettes[i].cassette) {
				index = i
				count++
			}
		}
		if count == 0 {
			return miss()
		}
		if count > 1 {
			var body []byte
			if req.Body != nil {
				var err error
				body, err = io.ReadAll(io.LimitReader(req.Body, maxCassetteBody+1))
				if err != nil || len(body) > maxCassetteBody {
					return miss()
				}
			}
			digest := BodySHA256(body, ignore)
			count = 0
			for i := range cassettes {
				c := cassettes[i].cassette
				if matches(c) && c.Request.BodySHA256 == digest {
					index = i
					count++
				}
			}
		}
		if count == 0 {
			return miss()
		}
		if count > 1 {
			return nil, &proxy.CassetteError{Kind: "cassette_ambiguous"}
		}
		selected := cassettes[index]
		if !selected.valid {
			return miss()
		}
		c := selected.cassette.Response
		header := make(http.Header, len(c.Headers))
		for k, v := range c.Headers {
			header.Set(k, v)
		}
		return &http.Response{StatusCode: c.Status, Status: fmt.Sprintf("%d %s", c.Status, http.StatusText(c.Status)), Header: header, Body: io.NopCloser(strings.NewReader(c.Body)), ContentLength: int64(len(c.Body)), Request: req}, nil
	}
}
