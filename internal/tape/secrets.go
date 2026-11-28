package tape

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	_, _, err := scanValue(reflect.ValueOf(t), "$", false)
	if err == nil {
		return t, nil
	}
	if !redact {
		return Tape{}, err
	}
	v, changed, err := scanValue(reflect.ValueOf(t), "$", true)
	if err != nil {
		return Tape{}, err
	}
	out := v.Interface().(Tape)
	if changed {
		if err := syncRedactedCassetteRequests(t, &out); err != nil {
			return Tape{}, err
		}
		out.Redacted = true
	}
	if redact && changed {
		if _, _, err := scanValue(reflect.ValueOf(out), "$", false); err != nil {
			return Tape{}, err
		}
	}
	return out, nil
}

var quotedString = regexp.MustCompile(`"(?:\\.|[^"\\])*"`)

func scanText(s, field string, redact bool) (string, bool, error) {
	return scanTextDepth(s, field, redact, 0)
}

func scanTextDepth(s, field string, redact bool, depth int) (string, bool, error) {
	if depth > 8 {
		return "", false, &ExportBlockedError{Kind: "unsupported_encoding", Field: field}
	}
	changed := false
	var scanErr error
	if strings.Contains(s, `\`) {
		s = quotedString.ReplaceAllStringFunc(s, func(part string) string {
			if scanErr != nil || !strings.Contains(part, `\`) {
				return part
			}
			var value string
			if json.Unmarshal([]byte(part), &value) != nil {
				return part
			}
			clean, c, err := scanTextDepth(value, field, redact, depth+1)
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
		var decoded strings.Builder
		starts := make([]int, 0, len(s)+1)
		for i := 0; i < len(s); {
			starts = append(starts, i)
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
		starts = append(starts, len(s))
		d := decoded.String()
		if d != s {
			_, composed, err := scanTextDepth(d, field, redact, depth+1)
			if err != nil {
				return "", false, err
			}
			if composed && strings.ContainsAny(d, `\%`) {
				return "", false, unsupportedBody(field)
			}
			for _, p := range secretPatterns {
				matches := p.re.FindAllStringIndex(d, -1)
				if len(matches) == 0 {
					continue
				}
				if !redact || strings.Contains(d, `\`) {
					return "", false, &ExportBlockedError{Kind: p.kind, Field: field}
				}
				var b strings.Builder
				last := 0
				for _, m := range matches {
					b.WriteString(s[last:starts[m[0]]])
					b.WriteString("REDACTED")
					last = starts[m[1]]
				}
				b.WriteString(s[last:])
				s = b.String()
				clean, _, err := scanTextDepth(s, field, true, depth+1)
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

func scanValue(v reflect.Value, field string, redact bool) (reflect.Value, bool, error) {
	if !v.IsValid() {
		return v, false, nil
	}
	if v.Type() == reflect.TypeOf(json.Number("")) {
		return v, false, nil
	}
	switch v.Kind() {
	case reflect.String:
		s, c, err := scanText(v.String(), field, redact)
		if err != nil {
			return reflect.Value{}, false, err
		}
		if !redact {
			return v, false, nil
		}
		out := reflect.New(v.Type()).Elem()
		out.SetString(s)
		return out, c, nil
	case reflect.Interface:
		if v.IsNil() {
			return v, false, nil
		}
		x, c, err := scanValue(v.Elem(), field, redact)
		if err != nil {
			return reflect.Value{}, false, err
		}
		if !redact {
			return v, c, nil
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(x)
		return out, c, nil
	case reflect.Pointer:
		if v.IsNil() {
			return v, false, nil
		}
		x, c, err := scanValue(v.Elem(), field, redact)
		if err != nil {
			return reflect.Value{}, false, err
		}
		if !redact {
			return v, c, nil
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(x)
		return out, c, nil
	case reflect.Struct:
		out := v
		if redact {
			out = reflect.New(v.Type()).Elem()
			out.Set(v)
		}
		changed := false
		base64Body := false
		bodyChanged := false
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !f.IsExported() {
				continue
			}
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" {
				name = f.Name
			}
			if name == "-" {
				continue
			}
			path := field + "." + name
			encoded := f.Name == "MessageB64" || (f.Name == "Body" && v.Type().Name() == "CassetteResponse" && v.FieldByName("BodyEncoding").String() == "base64")
			body := f.Name == "Body" && (v.Type().Name() == "HTTP" || v.Type().Name() == "Stream" || v.Type().Name() == "CassetteResponse")
			if encoded || body {
				encoding, contentType, transfer, grpcEncoding := "", "", "", ""
				if body {
					headers := v.FieldByName("Headers")
					iter := headers.MapRange()
					seen := map[string]bool{}
					for iter.Next() {
						key := strings.ToLower(iter.Key().String())
						switch key {
						case "content-encoding", "content-type", "content-transfer-encoding", "grpc-encoding":
							if seen[key] {
								return reflect.Value{}, false, &ExportBlockedError{Kind: "unsupported_encoding", Field: path}
							}
							seen[key] = true
							value := strings.TrimSpace(iter.Value().String())
							switch key {
							case "content-encoding":
								encoding = strings.ToLower(value)
							case "content-type":
								contentType = value
							case "content-transfer-encoding":
								transfer = strings.ToLower(value)
							case "grpc-encoding":
								grpcEncoding = strings.ToLower(value)
							}
						}
					}
				}
				if grpcEncoding != "" && grpcEncoding != "identity" {
					return reflect.Value{}, false, &ExportBlockedError{Kind: "unsupported_encoding", Field: path}
				}
				s, c, err := scanBody(v.Field(i).String(), encoded, encoding, contentType, transfer, path, redact)
				if err != nil {
					return reflect.Value{}, false, err
				}
				if c && body {
					bodyChanged = true
				}
				if c && redact && body && v.Type().Name() == "CassetteResponse" && !encoded && encoding != "" && encoding != "identity" {
					s = base64.StdEncoding.EncodeToString([]byte(s))
					base64Body = true
				}
				if redact {
					out.Field(i).SetString(s)
				}
				changed = changed || c
				continue
			}
			x, c, err := scanValue(v.Field(i), path, redact)
			if err != nil {
				return reflect.Value{}, false, err
			}
			if redact {
				out.Field(i).Set(x)
			}
			changed = changed || c
		}
		if base64Body {
			out.FieldByName("BodyEncoding").SetString("base64")
		}
		if bodyChanged {
			headers := out.FieldByName("Headers")
			iter := headers.MapRange()
			for iter.Next() {
				key := strings.ToLower(iter.Key().String())
				if key == "content-length" || key == "content-md5" || key == "content-digest" || key == "digest" || key == "etag" {
					headers.SetMapIndex(iter.Key(), reflect.Value{})
				}
			}
		}
		return out, changed, nil
	case reflect.Slice:
		if v.IsNil() {
			return v, false, nil
		}
		out := v
		if redact {
			out = reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		}
		changed := false
		for i := 0; i < v.Len(); i++ {
			x, c, err := scanValue(v.Index(i), fmt.Sprintf("%s[%d]", field, i), redact)
			if err != nil {
				return reflect.Value{}, false, err
			}
			if redact {
				out.Index(i).Set(x)
			}
			changed = changed || c
		}
		return out, changed, nil
	case reflect.Map:
		if v.IsNil() {
			return v, false, nil
		}
		out := v
		if redact {
			out = reflect.MakeMapWithSize(v.Type(), v.Len())
		}
		changed := false
		iter := v.MapRange()
		for iter.Next() {
			k, c, err := scanValue(iter.Key(), field, redact)
			if err != nil {
				return reflect.Value{}, false, err
			}
			changed = changed || c
			valueField := field
			if strings.EqualFold(iter.Key().String(), "Location") {
				valueField += ".location"
			}
			x, c, err := scanValue(iter.Value(), valueField, redact)
			if err != nil {
				return reflect.Value{}, false, err
			}
			changed = changed || c
			if redact {
				if out.MapIndex(k).IsValid() {
					return reflect.Value{}, false, &ExportBlockedError{Kind: "redaction_collision", Field: field}
				}
				out.SetMapIndex(k, x)
			}
		}
		return out, changed, nil
	default:
		return v, false, nil
	}
}

func scanBody(body string, encoded bool, encoding, contentType, transfer, field string, redact bool) (string, bool, error) {
	blocked := func() (string, bool, error) {
		return "", false, &ExportBlockedError{Kind: "unscannable_body", Field: field}
	}
	if err := checkBodyEncoding(contentType, transfer, field); err != nil {
		return "", false, err
	}
	if encoding != "" && encoding != "identity" && encoding != "gzip" && encoding != "x-gzip" && encoding != "deflate" {
		return "", false, &ExportBlockedError{Kind: "unsupported_encoding", Field: field}
	}
	if body == "" {
		return body, false, nil
	}
	raw := []byte(body)
	if encoded {
		var err error
		raw, err = base64.StdEncoding.DecodeString(body)
		if err != nil {
			return blocked()
		}
	}
	var reader io.ReadCloser
	var err error
	source := bytes.NewReader(raw)
	rawDeflate := false
	switch encoding {
	case "", "identity":
	case "gzip", "x-gzip":
		var g *gzip.Reader
		g, err = gzip.NewReader(source)
		if err == nil {
			g.Multistream(false)
		}
		if err == nil {
			for _, metadata := range []string{g.Name, g.Comment, string(g.Extra)} {
				if _, _, e := scanText(metadata, field, false); e != nil {
					g.Close()
					return "", false, e
				}
			}
			reader = g
		}
	case "deflate":
		if len(raw) >= 2 && raw[0]&15 == 8 && raw[0]>>4 <= 7 && (int(raw[0])*256+int(raw[1]))%31 == 0 {
			reader, err = zlib.NewReader(source)
		} else {
			rawDeflate = true
			reader = flate.NewReader(source)
		}
	}
	if err != nil {
		return blocked()
	}
	if reader != nil {
		raw, err = io.ReadAll(io.LimitReader(reader, (4<<20)+1))
		closeErr := reader.Close()
		if err != nil || closeErr != nil || len(raw) > 4<<20 || source.Len() != 0 {
			return blocked()
		}
	}
	clean, changed, err := scanBodyText(string(raw), contentType, field, redact)
	if err != nil {
		return "", false, err
	}
	if !changed {
		return body, false, nil
	}
	raw = []byte(clean)
	if encoding != "" && encoding != "identity" {
		var output bytes.Buffer
		var writer io.WriteCloser
		if encoding == "deflate" {
			if rawDeflate {
				writer, err = flate.NewWriter(&output, flate.DefaultCompression)
				if err != nil {
					return blocked()
				}
			} else {
				writer = zlib.NewWriter(&output)
			}
		} else {
			writer = gzip.NewWriter(&output)
		}
		if _, err := writer.Write(raw); err != nil {
			return blocked()
		}
		if err := writer.Close(); err != nil {
			return blocked()
		}
		raw = output.Bytes()
	}
	if encoded {
		return base64.StdEncoding.EncodeToString(raw), true, nil
	}
	return string(raw), true, nil
}
