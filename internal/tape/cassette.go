package tape

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/hardw00t/glitchdeck/internal/proxy"
)

const (
	maxCassetteBody     = 4 << 20
	maxTapeInput        = 16 << 20
	maxCassettes        = 256
	maxDecodedAggregate = 8 << 20
)

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

func (r CassetteResponse) decodedSize() (int, error) {
	switch r.BodyEncoding {
	case "":
		return len(r.Body), nil
	case "base64":
		n, padding := 0, 0
		for i := range len(r.Body) {
			switch r.Body[i] {
			case '\r', '\n':
			case '=':
				n++
				padding++
			default:
				n++
			}
		}
		if n%4 != 0 || padding > 2 {
			return 0, fmt.Errorf("invalid base64 cassette body")
		}
		return n/4*3 - padding, nil
	default:
		return 0, fmt.Errorf("invalid cassette body encoding")
	}
}

func (r CassetteResponse) Bytes() ([]byte, error) {
	size, err := r.decodedSize()
	if err != nil || size > maxCassetteBody {
		return nil, fmt.Errorf("invalid or oversized cassette body")
	}
	switch r.BodyEncoding {
	case "":
		if !utf8.ValidString(r.Body) {
			return nil, fmt.Errorf("invalid UTF-8 cassette body")
		}
		return []byte(r.Body), nil
	case "base64":
		return io.ReadAll(io.LimitReader(base64.NewDecoder(base64.StdEncoding, strings.NewReader(r.Body)), int64(size)+1))
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

const maxMatchWork int64 = 256 << 20

var matchWork atomic.Int64

type matchReader struct {
	r        io.Reader
	reserved int64
	limited  bool
}

func (r *matchReader) Read(p []byte) (int, error) {
	// Account for the input, JSON tree, duplicate-key maps and canonical output.
	n := int64(len(p)) * 32
	for {
		used := matchWork.Load()
		if n > maxMatchWork-used {
			r.limited = true
			return 0, io.ErrShortBuffer
		}
		if matchWork.CompareAndSwap(used, used+n) {
			break
		}
	}
	r.reserved += n
	return r.r.Read(p)
}

func matchJSONComplexityOK(body []byte) bool {
	if !utf8.Valid(body) || !json.Valid(body) {
		return true
	}
	depth, nodes := 0, 0
	inString, escaped := false, false
	for _, c := range body {
		if inString {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
			nodes++
			if depth > 128 {
				return false
			}
		case '}', ']':
			depth--
		case ',', ':':
			nodes++
		}
		if nodes > 32768 {
			return false
		}
	}
	return true
}

func BodySHA256(body []byte, ignore []string) string {
	if !matchJSONComplexityOK(body) {
		return ""
	}
	var value any
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if losslessJSON(body) && d.Decode(&value) == nil {
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
func losslessJSON(body []byte) bool {
	if !utf8.Valid(body) || !json.Valid(body) {
		return false
	}
	inString := false
	for i := 0; i < len(body); i++ {
		if body[i] == '"' {
			inString = !inString
		} else if inString && body[i] == '\\' {
			i++
			if i >= len(body) {
				return false
			}
			if body[i] != 'u' {
				continue
			}
			if i+4 >= len(body) {
				return false
			}
			n, err := strconv.ParseUint(string(body[i+1:i+5]), 16, 16)
			if err != nil {
				return false
			}
			i += 4
			if n >= 0xdc00 && n <= 0xdfff {
				return false
			}
			if n >= 0xd800 && n <= 0xdbff {
				if i+6 >= len(body) || body[i+1] != '\\' || body[i+2] != 'u' {
					return false
				}
				low, err := strconv.ParseUint(string(body[i+3:i+7]), 16, 16)
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return false
				}
				i += 6
			}
		}
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	return uniqueJSONValue(d)
}

func uniqueJSONValue(d *json.Decoder) bool {
	token, err := d.Token()
	if err != nil {
		return false
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return true
	}
	if delim == '{' {
		keys := make(map[string]bool)
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return false
			}
			name, ok := key.(string)
			if !ok || keys[name] {
				return false
			}
			keys[name] = true
			if !uniqueJSONValue(d) {
				return false
			}
		}
	} else if delim == '[' {
		for d.More() {
			if !uniqueJSONValue(d) {
				return false
			}
		}
	} else {
		return false
	}
	_, err = d.Token()
	return err == nil
}

// SameAuthority reports whether two authorities match for a request scheme.
func SameAuthority(a, b, scheme string) bool {
	normalize := func(authority string) string {
		host, port, err := net.SplitHostPort(authority)
		if err == nil && (scheme == "https" && port == "443" || scheme == "http" && port == "80") {
			return strings.ToLower(strings.Trim(host, "[]"))
		}
		return strings.ToLower(strings.Trim(authority, "[]"))
	}
	return normalize(a) == normalize(b)
}

func (t Tape) CassetteUpstream() func(*http.Request) (*http.Response, error) {
	type replayCassette struct {
		cassette Cassette
		valid    bool
	}
	cassettes := make([]replayCassette, len(t.Cassettes))
	total := 0
	for i, c := range t.Cassettes {
		size, err := c.Response.decodedSize()
		valid := len(t.Cassettes) <= maxCassettes && err == nil && size <= maxCassetteBody && size <= maxDecodedAggregate-total && !c.Response.Truncated && c.Response.Status >= 100 && c.Response.Status <= 599
		if valid {
			total += size
			body, err := c.Response.Bytes()
			valid = err == nil
			if valid && c.Response.BodyEncoding == "base64" {
				c.Response.Body = string(body)
			}
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
		scheme := req.URL.Scheme
		if scheme == "" && req.TLS != nil {
			scheme = "https"
		}
		if scheme == "" {
			scheme = "http"
		}
		matches := func(c Cassette) bool {
			return strings.EqualFold(c.Request.Method, req.Method) && c.Request.Path == path && (c.Request.Host == "" || SameAuthority(c.Request.Host, req.Host, strings.ToLower(scheme)))
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
			digest, limited, err := func() (string, bool, error) {
				reader := &matchReader{r: http.NoBody}
				if req.Body != nil {
					reader.r = req.Body
				}
				defer func() { matchWork.Add(-reader.reserved) }()
				body, err := io.ReadAll(io.LimitReader(reader, maxCassetteBody+1))
				if reader.limited {
					return "", true, nil
				}
				if err != nil || len(body) > maxCassetteBody {
					return "", false, err
				}
				if !matchJSONComplexityOK(body) {
					return "", true, nil
				}
				return BodySHA256(body, ignore), false, nil
			}()
			if limited {
				return nil, &proxy.CassetteError{Kind: "cassette_match_limit"}
			}
			if err != nil || digest == "" {
				return miss()
			}
			count = 0
			for i := range cassettes {
				c := cassettes[i].cassette
				if matches(c) && (c.Request.BodySHA256 == "" || strings.EqualFold(c.Request.BodySHA256, digest)) {
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
