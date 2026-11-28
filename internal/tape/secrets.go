package tape

import (
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"reflect"
	"regexp"
	"strings"
)

// ExportBlockedError identifies a secret without disclosing its value.
type ExportBlockedError struct {
	Kind  string
	Field string
}

func (e *ExportBlockedError) Error() string {
	return fmt.Sprintf("export blocked: secret_kind=%s field=%s", e.Kind, e.Field)
}

var secretPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"anthropic", regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]+`)},
	{"openai", regexp.MustCompile(`sk-[A-Za-z0-9_-]{20,}`)},
	{"stripe", regexp.MustCompile(`(?:sk_live_|sk_test_|rk_live_|rk_test_|whsec_)[A-Za-z0-9_-]+`)},
	{"aws", regexp.MustCompile(`AKIA[A-Z0-9]{16}`)},
	{"private_key", regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z0-9 ]* )?PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9 ]* )?PRIVATE KEY-----|$)`)},
	{"github", regexp.MustCompile(`(?:ghp_|github_pat_)[A-Za-z0-9_]+`)},
	{"bearer_jwt", regexp.MustCompile(`(?i:Bearer)\s+eyJ[A-Za-z0-9_.-]*`)},
}

// PrepareExport scans the tape without exposing secret values in errors.
func PrepareExport(t Tape, redact bool) (Tape, error) {
	remaining := 32 << 20
	if err := boundExport(reflect.ValueOf(t), &remaining, 0); err != nil {
		return Tape{}, err
	}
	budget := 64 << 20
	v, changed, err := scanValue(reflect.ValueOf(t), "$", false, &budget)
	redacted := err != nil && redact
	if redacted {
		v, changed, err = scanValue(reflect.ValueOf(t), "$", true, &budget)
	}
	if err != nil {
		return Tape{}, err
	}
	out := v.Interface().(Tape)
	if changed && len(t.Cassettes) > 0 {
		out.Cassettes = append([]Cassette(nil), out.Cassettes...)
		if err := syncRedactedCassetteRequests(t, &out); err != nil {
			return Tape{}, err
		}
	}
	if redacted {
		out.Redacted = true
		if _, _, err := scanValue(reflect.ValueOf(out), "$", false, &budget); err != nil {
			return Tape{}, err
		}
	}
	return out, nil
}

func boundExport(v reflect.Value, remaining *int, depth int) error {
	if depth > 64 {
		return unsupportedBody("$")
	}
	if !v.IsValid() {
		return nil
	}
	*remaining--
	if *remaining < 0 {
		return unsupportedBody("$")
	}
	switch v.Kind() {
	case reflect.String:
		*remaining -= v.Len()
		if *remaining < 0 {
			return unsupportedBody("$")
		}
	case reflect.Interface, reflect.Pointer:
		if !v.IsNil() {
			return boundExport(v.Elem(), remaining, depth+1)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				if err := boundExport(v.Field(i), remaining, depth+1); err != nil {
					return err
				}
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if err := boundExport(v.Index(i), remaining, depth+1); err != nil {
				return err
			}
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			if err := boundExport(iter.Key(), remaining, depth+1); err != nil {
				return err
			}
			if err := boundExport(iter.Value(), remaining, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

var quotedString = regexp.MustCompile(`"(?:\\.|[^"\\])*"`)
var pemMarker = regexp.MustCompile(`-----(BEGIN|END) ((?:[A-Z0-9 ]* )?PRIVATE KEY)-----`)

func checkPEMClosers(s, field string) error {
	var opened string
	for {
		match := pemMarker.FindStringSubmatchIndex(s)
		if match == nil {
			if opened == "" {
				return nil
			}
			break
		}
		kind, label := s[match[2]:match[3]], s[match[4]:match[5]]
		if kind == "BEGIN" {
			if opened != "" {
				break
			}
			opened = label
		} else if opened != "" {
			if opened != label {
				break
			}
			opened = ""
		}
		s = s[match[1]:]
	}
	return &ExportBlockedError{Kind: "private_key", Field: field}
}

func scanText(s, field string, redact bool) (string, bool, error) {
	budget := 64 << 20
	return scanTextDepth(s, field, redact, 0, &budget)
}

func scanTextDepth(s, field string, redact bool, depth int, budget *int) (string, bool, error) {
	if depth > 8 {
		return "", false, &ExportBlockedError{Kind: "unsupported_encoding", Field: field}
	}
	if redact {
		if err := checkPEMClosers(s, field); err != nil {
			return "", false, err
		}
	}
	if depth == 0 && redact {
		if _, _, err := scanTextDepth(s, field, false, 0, budget); err == nil {
			return s, false, nil
		}
	}
	if depth == 0 && (strings.HasSuffix(field, ".url") || strings.HasSuffix(field, ".path") || strings.HasSuffix(field, ".target") || strings.HasSuffix(field, ".http_get") || strings.HasSuffix(field, ".location") || strings.HasSuffix(field, ".form")) {
		prefix, query, changed := "", s, false
		if !strings.HasSuffix(field, ".form") {
			i := strings.IndexByte(s, '?')
			if i < 0 {
				return scanTextDepth(s, field+".component", redact, 1, budget)
			}
			prefix, query = s[:i+1], s[i+1:]
			clean, c, err := scanTextDepth(prefix, field+".component", redact, 1, budget)
			if err != nil {
				return "", false, err
			}
			prefix, changed = clean, c
		}
		var rebuilt strings.Builder
		offset := 0
		rebuilding := false
		componentField := field + ".form"
		for {
			part, rest, more := strings.Cut(query[offset:], "&")
			key, value, hasValue := strings.Cut(part, "=")
			cleanKey, keyChanged, err := scanTextDepth(key, componentField, redact, 1, budget)
			if err != nil {
				return "", false, err
			}
			cleanValue, valueChanged := value, false
			if hasValue {
				cleanValue, valueChanged, err = scanTextDepth(value, componentField, redact, 1, budget)
				if err != nil {
					return "", false, err
				}
			}
			if rebuilding || keyChanged || valueChanged {
				size := rebuilt.Len() + len(cleanKey) + len(cleanValue)
				if !rebuilding {
					size += offset
				}
				if hasValue {
					size++
				}
				if more {
					size++
				}
				if size > 2*len(query) {
					return "", false, unsupportedBody(field)
				}
			}
			if keyChanged || valueChanged {
				if !rebuilding {
					if len(query) > *budget/2 {
						return "", false, unsupportedBody(field)
					}
					*budget -= 2 * len(query)
					rebuilt.Grow(2 * len(query))
					rebuilt.WriteString(query[:offset])
					rebuilding = true
				}
				rebuilt.WriteString(cleanKey)
				if hasValue {
					rebuilt.WriteByte('=')
					rebuilt.WriteString(cleanValue)
				}
				changed = true
			} else if rebuilding {
				rebuilt.WriteString(part)
			}
			offset = len(query) - len(rest)
			if !more {
				break
			}
			if rebuilding {
				rebuilt.WriteByte('&')
			}
		}
		if !changed {
			return s, false, nil
		}
		if !rebuilding {
			return prefix + query, true, nil
		}
		return prefix + rebuilt.String(), true, nil
	}
	changed := false
	var scanErr error
	if strings.Contains(s, `\`) || redact && strings.Contains(s, `"`) {
		if len(s) > *budget/4 {
			return "", false, unsupportedBody(field)
		}
		*budget -= 4 * len(s)
		inString, escaped, hasEscape := false, false, false
		for i := range s {
			if !inString {
				if s[i] == '"' {
					inString, hasEscape = true, false
				}
			} else if escaped {
				escaped = false
			} else if s[i] == '\\' {
				escaped, hasEscape = true, true
			} else if s[i] == '"' {
				inString = false
			}
		}
		if inString && hasEscape {
			return "", false, unsupportedBody(field)
		}
		s = quotedString.ReplaceAllStringFunc(s, func(part string) string {
			if scanErr != nil {
				return part
			}
			var value string
			if json.Unmarshal([]byte(part), &value) != nil {
				return part
			}
			if redact {
				if err := checkPEMClosers(value, field); err != nil {
					scanErr = err
					return part
				}
			}
			if !strings.Contains(part, `\`) {
				return part
			}
			clean, c, err := scanTextDepth(value, field, redact, depth+1, budget)
			if err != nil {
				scanErr = err
				return part
			}
			if c {
				b, _ := json.Marshal(clean)
				changed = true
				return string(b)
			}
			return part
		})
		if scanErr != nil {
			return "", false, scanErr
		}
	}
	query := -1
	if strings.HasSuffix(field, ".url") || strings.HasSuffix(field, ".path") || strings.HasSuffix(field, ".target") || strings.HasSuffix(field, ".form") || strings.HasSuffix(field, ".location") {
		query = strings.IndexByte(s, '?')
	}
	if strings.Contains(s, "%") || (strings.Contains(s, "+") && (query >= 0 || strings.HasSuffix(field, ".form") || strings.HasSuffix(field, ".location"))) {
		if len(s) > *budget/20 {
			return "", false, unsupportedBody(field)
		}
		*budget -= 20 * len(s)
		var decoded strings.Builder
		var starts []int
		if redact {
			starts = make([]int, 0, len(s)+1)
		}
		for i := 0; i < len(s); {
			if redact {
				starts = append(starts, i)
			}
			if s[i] == '%' && i+2 < len(s) {
				hex := func(b byte) int {
					if b >= '0' && b <= '9' {
						return int(b - '0')
					}
					if b >= 'a' && b <= 'f' {
						return int(b-'a') + 10
					}
					if b >= 'A' && b <= 'F' {
						return int(b-'A') + 10
					}
					return -1
				}
				a, b := hex(s[i+1]), hex(s[i+2])
				if a >= 0 && b >= 0 {
					decoded.WriteByte(byte(a*16 + b))
					i += 3
					continue
				}
			}
			if s[i] == '+' && (strings.HasSuffix(field, ".form") || strings.HasSuffix(field, ".location") || query >= 0 && i > query) {
				decoded.WriteByte(' ')
			} else {
				decoded.WriteByte(s[i])
			}
			i++
		}
		if redact {
			starts = append(starts, len(s))
		}
		d := decoded.String()
		if d != s {
			_, composed, err := scanTextDepth(d, field, redact, depth+1, budget)
			if err != nil {
				return "", false, err
			}
			if composed && strings.ContainsAny(d, `\%`) {
				return "", false, unsupportedBody(field)
			}
			for _, p := range secretPatterns {
				match := p.re.FindStringIndex(d)
				if match == nil {
					continue
				}
				if !redact || strings.Contains(d, `\`) {
					return "", false, &ExportBlockedError{Kind: p.kind, Field: field}
				}
				if len(s) > *budget/2 {
					return "", false, unsupportedBody(field)
				}
				*budget -= 2 * len(s)
				var b strings.Builder
				b.Grow(2 * len(s))
				last, offset := 0, 0
				for match != nil {
					from, to := offset+match[0], offset+match[1]
					b.WriteString(s[last:starts[from]])
					b.WriteString("REDACTED")
					last, offset = starts[to], to
					match = p.re.FindStringIndex(d[offset:])
				}
				b.WriteString(s[last:])
				s = b.String()
				clean, _, err := scanTextDepth(s, field, true, depth+1, budget)
				return clean, true, err
			}
		}
	}
	for _, p := range secretPatterns {
		if p.re.MatchString(s) {
			if !redact {
				return "", false, &ExportBlockedError{Kind: p.kind, Field: field}
			}
			s = p.re.ReplaceAllString(s, "REDACTED")
			changed = true
		}
	}
	return s, changed, nil
}

func scanBody(body string, encoded bool, encoding, contentType, transfer, field string, redact bool) (string, bool, error) {
	budget := 64 << 20
	return scanBodyBudget(body, encoded, encoding, contentType, transfer, field, redact, &budget)
}

func scanBodyBudget(body string, encoded bool, encoding, contentType, transfer, field string, redact bool, budget *int) (string, bool, error) {
	return scanStoredExportBody(body, encoded, encoding, contentType, transfer, field, redact, budget)
}

func scanStoredExportBody(body string, storedBase64 bool, encoding, contentType, transfer, field string, redact bool, budget *int) (string, bool, error) {
	if len(body) > *budget {
		return "", false, &ExportBlockedError{Kind: "unscannable_encoding", Field: field}
	}
	*budget -= len(body)
	clean, changed, err := scanExportBodyPayload(body, contentType, encoding, transfer, "", field, redact, 0, budget, storedBase64)
	if err != nil {
		return "", false, err
	}
	if changed {
		return clean, true, nil
	}
	return body, false, nil
}

func scanExportBodyBytes(body, contentType, encoding, transfer, inheritedCharset, field string, redact bool, depth int, budget *int) (string, bool, error) {
	return scanExportBodyPayload(body, contentType, encoding, transfer, inheritedCharset, field, redact, depth, budget, false)
}

func scanExportBodyPayload(body, contentType, encoding, transfer, inheritedCharset, field string, redact bool, depth int, budget *int, storedBase64 bool) (string, bool, error) {
	if depth > 8 || len(body) > maxCassetteBody {
		return "", false, &ExportBlockedError{Kind: "unscannable_encoding", Field: field}
	}
	class, err := classifyExportBody(body, contentType, encoding, transfer, inheritedCharset, field, budget, storedBase64)
	if err != nil {
		return "", false, err
	}
	if class.kind != exportCompressed {
		return scanClassifiedBody(class, body, field, redact, depth, budget)
	}
	if exportCompressionMedia(class.media) != "" {
		contentType = exportDecodedMedia(class.params)
	}
	return scanCompressedExportBody(body, contentType, class.compression, inheritedCharset, field, redact, depth, budget)
}

func exportDecodedMedia(params map[string]string) string {
	if charset := params["charset"]; charset != "" {
		return mime.FormatMediaType("text/plain", map[string]string{"charset": charset})
	}
	return ""
}

func scanCompressedExportBody(body, contentType, encoding, inheritedCharset, field string, redact bool, depth int, budget *int) (string, bool, error) {
	blocked := func() (string, bool, error) {
		return "", false, &ExportBlockedError{Kind: "unscannable_encoding", Field: field}
	}
	var reader io.ReadCloser
	var err error
	source := strings.NewReader(body)
	switch encoding {
	case "gzip", "x-gzip":
		var g *gzip.Reader
		g, err = gzip.NewReader(source)
		if err == nil {
			g.Multistream(false)
			reader = g
		}
	case "deflate":
		if len(body) >= 2 && body[0]&15 == 8 && body[0]>>4 <= 7 && (int(body[0])*256+int(body[1]))%31 == 0 {
			reader, err = zlib.NewReader(source)
		} else {
			reader = flate.NewReader(source)
		}
	default:
		return blocked()
	}
	if err != nil {
		return blocked()
	}
	limit := min(maxCassetteBody, *budget)
	raw, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	closeErr := reader.Close()
	if len(raw) > limit {
		return blocked()
	}
	if err != nil || closeErr != nil || source.Len() != 0 {
		return blocked()
	}
	*budget -= len(raw)
	decoded := string(raw)
	clean, changed, err := scanExportBodyBytes(decoded, contentType, "", "", inheritedCharset, field, redact, depth+1, budget)
	if err != nil {
		return "", false, err
	}
	if changed {
		return clean, true, nil
	}
	return decoded, true, nil
}
