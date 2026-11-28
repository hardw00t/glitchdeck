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
	_, _, err := scanValue(reflect.ValueOf(t), "$", false, &budget)
	if err == nil {
		return t, nil
	}
	if !redact {
		return Tape{}, err
	}
	v, changed, err := scanValue(reflect.ValueOf(t), "$", true, &budget)
	if err != nil {
		return Tape{}, err
	}
	out := v.Interface().(Tape)
	if changed {
		if len(t.Cassettes) > 0 {
			if err := syncRedactedCassetteRequests(t, &out); err != nil {
				return Tape{}, err
			}
		}
		out.Redacted = true
	}
	if redact && changed {
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

func scanValue(v reflect.Value, field string, redact bool, budget *int) (reflect.Value, bool, error) {
	return scanValueFiltered(v, field, redact, budget, false)
}

func scanValueFiltered(v reflect.Value, field string, redact bool, budget *int, omitBodyHeaders bool) (reflect.Value, bool, error) {
	if !v.IsValid() {
		return v, false, nil
	}
	if v.Type() == reflect.TypeOf(json.Number("")) {
		return v, false, nil
	}
	switch v.Kind() {
	case reflect.String:
		s, c, err := scanTextDepth(v.String(), field, redact, 0, budget)
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
		x, c, err := scanValue(v.Elem(), field, redact, budget)
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
		x, c, err := scanValue(v.Elem(), field, redact, budget)
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
		replaceBody := false
		bodyType := v.Type().Name()
		hasBody := bodyType == "HTTP" || bodyType == "Stream" || bodyType == "CassetteResponse"
		bodyIndex := -1
		if hasBody {
			f, _ := v.Type().FieldByName("Body")
			bodyIndex = f.Index[0]
		}
		for i := range v.NumField() {
			switch i {
			case 0:
				if hasBody {
					i = bodyIndex
				}
			case bodyIndex:
				i = 0
			}
			f := v.Type().Field(i)
			if !f.IsExported() {
				continue
			}
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" {
				name = f.Name
			}
			if name == "-" {
				continue
			}
			path := field + "." + name
			if f.Name == "Messages" && bodyType == "WS" {
				messages := v.Field(i)
				if redact && !messages.IsNil() {
					out.Field(i).Set(reflect.MakeSlice(messages.Type(), messages.Len(), messages.Len()))
				}
				for j := range messages.Len() {
					message := messages.Index(j).String()
					messagePath := fmt.Sprintf("%s[%d]", path, j)
					clean, c, err := scanBodyBudget(message, false, "", "", "", messagePath, redact, budget)
					if blocked, ok := err.(*ExportBlockedError); ok && redact {
						replace := blocked.Kind == "unscannable_xml_entity" || blocked.Kind == "unscannable_encoding"
						for _, pattern := range secretPatterns {
							replace = replace || pattern.kind != "private_key" && blocked.Kind == pattern.kind
						}
						if replace {
							clean, c, err = "REDACTED", true, nil
						}
					}
					if err != nil {
						return reflect.Value{}, false, err
					}
					if redact {
						out.Field(i).Index(j).SetString(clean)
					}
					changed = changed || c
				}
				continue
			}
			body := f.Name == "Body" && hasBody
			bodyEncoding := ""
			if body && bodyType == "CassetteResponse" {
				bodyEncoding = v.FieldByName("BodyEncoding").String()
			}
			encoded := f.Name == "MessageB64" || bodyEncoding == "base64"
			if encoded || body {
				if body && v.Field(i).String() == "" && bodyEncoding == "" && !v.FieldByName("UnscannableEncoding").Bool() {
					continue
				}
				encoding, contentType, transfer, grpcEncoding, httpTransfer := "", "", "", "", ""
				ambiguous := false
				if body {
					headers := v.FieldByName("Headers")
					iter := headers.MapRange()
					seen := map[string]bool{}
					for iter.Next() {
						key := strings.ToLower(iter.Key().String())
						switch key {
						case "content-encoding", "content-type", "content-transfer-encoding", "grpc-encoding", "transfer-encoding":
							if seen[key] {
								ambiguous = true
							}
							seen[key] = true
							value := strings.TrimSpace(iter.Value().String())
							switch key {
							case "content-encoding":
								encoding = strings.ToLower(value)
							case "content-type":
								contentType = value
								ambiguous = ambiguous || value == ""
							case "content-transfer-encoding":
								transfer = strings.ToLower(value)
							case "grpc-encoding":
								grpcEncoding = strings.ToLower(value)
							case "transfer-encoding":
								httpTransfer = strings.ToLower(value)
							}
						}
					}
				}
				unscannable := body && (ambiguous || v.FieldByName("UnscannableEncoding").Bool() ||
					grpcEncoding != "" && grpcEncoding != "identity" ||
					httpTransfer != "" && httpTransfer != "identity" ||
					bodyEncoding != "" && bodyEncoding != "base64")
				var s string
				var c bool
				var err error
				if unscannable {
					err = &ExportBlockedError{Kind: "unscannable_encoding", Field: path}
				} else {
					s, c, err = scanStoredExportBody(v.Field(i).String(), encoded, bodyEncoding == "base64", encoding, contentType, transfer, path, redact, budget)
				}
				if blocked, ok := err.(*ExportBlockedError); ok && redact && (blocked.Kind == "unscannable_encoding" || blocked.Kind == "unscannable_xml_entity") {
					s, c, err = "REDACTED", true, nil
					replaceBody = body
					if encoded && !body {
						s = base64.StdEncoding.EncodeToString([]byte(s))
					}
				}
				if err != nil {
					return reflect.Value{}, false, err
				}
				if c && body {
					bodyChanged = true
				}
				if c && redact && body && !replaceBody && v.Type().Name() == "CassetteResponse" && !encoded && encoding != "" && encoding != "identity" {
					s = base64.StdEncoding.EncodeToString([]byte(s))
					base64Body = true
				}
				if redact {
					out.Field(i).SetString(s)
				}
				changed = changed || c
				continue
			}
			x, c, err := scanValueFiltered(v.Field(i), path, redact, budget, replaceBody && f.Name == "Headers")
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
			if replaceBody {
				out.FieldByName("UnscannableEncoding").SetBool(false)
				if v.Type().Name() == "CassetteResponse" {
					out.FieldByName("BodyEncoding").SetString("")
				}
			}
			if !replaceBody && v.Type().Name() == "CassetteResponse" && v.FieldByName("Status").Int() == 206 {
				return reflect.Value{}, false, unsupportedBody(field + ".body")
			}
			if replaceBody && v.Type().Name() == "CassetteResponse" && v.FieldByName("Status").Int() == 206 {
				out.FieldByName("Status").SetInt(200)
			}
			headers := out.FieldByName("Headers")
			iter := headers.MapRange()
			for iter.Next() {
				key := strings.ToLower(iter.Key().String())
				if key == "content-length" || key == "content-md5" || key == "content-digest" || key == "repr-digest" || key == "digest" || key == "etag" {
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
			x, c, err := scanValue(v.Index(i), fmt.Sprintf("%s[%d]", field, i), redact, budget)
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
			if omitBodyHeaders {
				switch strings.ToLower(iter.Key().String()) {
				case "content-type", "content-encoding", "grpc-encoding", "transfer-encoding", "content-transfer-encoding", "content-range":
					continue
				}
			}
			k, c, err := scanValue(iter.Key(), field, redact, budget)
			if err != nil {
				return reflect.Value{}, false, err
			}
			changed = changed || c
			var x reflect.Value
			if strings.HasSuffix(field, ".headers") && iter.Value().Kind() == reflect.String {
				var clean string
				clean, c, err = scanHeader(iter.Key().String(), iter.Value().String(), field, redact, budget)
				if err == nil {
					x = iter.Value()
					if redact && c {
						x = reflect.New(iter.Value().Type()).Elem()
						x.SetString(clean)
					}
				}
			} else {
				valueField := field
				if strings.EqualFold(iter.Key().String(), "Location") {
					valueField += ".location"
				}
				x, c, err = scanValue(iter.Value(), valueField, redact, budget)
			}
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
	budget := 64 << 20
	return scanBodyBudget(body, encoded, encoding, contentType, transfer, field, redact, &budget)
}

func scanBodyBudget(body string, encoded bool, encoding, contentType, transfer, field string, redact bool, budget *int) (string, bool, error) {
	return scanStoredExportBody(body, encoded, false, encoding, contentType, transfer, field, redact, budget)
}

func scanStoredExportBody(body string, encoded, cassetteBase64 bool, encoding, contentType, transfer, field string, redact bool, budget *int) (string, bool, error) {
	if len(body) > *budget {
		return "", false, &ExportBlockedError{Kind: "unscannable_body", Field: field}
	}
	*budget -= len(body)
	raw := body
	if encoded {
		if base64.StdEncoding.DecodedLen(len(body)) > *budget+2 {
			return "", false, &ExportBlockedError{Kind: "unscannable_body", Field: field}
		}
		bytes, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			return "", false, &ExportBlockedError{Kind: "unscannable_encoding", Field: field}
		}
		if len(bytes) > *budget {
			return "", false, &ExportBlockedError{Kind: "unscannable_body", Field: field}
		}
		*budget -= len(bytes)
		raw = string(bytes)
	}
	clean, changed, err := scanExportBodyPayload(raw, contentType, encoding, transfer, "", field, redact, 0, budget, cassetteBase64)
	if err != nil {
		return "", false, err
	}
	if encoded {
		if _, _, err := scanTextDepth(body, field, false, 0, budget); err != nil {
			return "", false, err
		}
		if changed {
			return base64.StdEncoding.EncodeToString([]byte(clean)), true, nil
		}
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
	explicitEncoding := encoding != "" && encoding != "identity"
	if !explicitEncoding {
		switch class.media {
		case "application/gzip", "application/x-gzip", "application/zlib":
			contentType = ""
			if charset, ok := class.params["charset"]; ok {
				contentType = mime.FormatMediaType("text/plain", map[string]string{"charset": charset})
			}
		}
	}
	return scanCompressedExportBody(body, contentType, class.compression, inheritedCharset, field, redact && explicitEncoding, depth, budget)
}

func scanCompressedExportBody(body, contentType, encoding, inheritedCharset, field string, redact bool, depth int, budget *int) (string, bool, error) {
	blocked := func() (string, bool, error) {
		return "", false, &ExportBlockedError{Kind: "unscannable_encoding", Field: field}
	}
	var reader io.ReadCloser
	var header gzip.Header
	var err error
	source := strings.NewReader(body)
	rawDeflate := false
	switch encoding {
	case "gzip", "x-gzip":
		var g *gzip.Reader
		g, err = gzip.NewReader(source)
		if err == nil {
			g.Multistream(false)
			header, reader = g.Header, g
		}
	case "deflate":
		if len(body) >= 2 && body[0]&15 == 8 && body[0]>>4 <= 7 && (int(body[0])*256+int(body[1]))%31 == 0 {
			reader, err = zlib.NewReader(source)
		} else {
			rawDeflate = true
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
		return "", false, &ExportBlockedError{Kind: "unscannable_body", Field: field}
	}
	if err != nil || closeErr != nil || source.Len() != 0 {
		return blocked()
	}
	*budget -= len(raw)
	clean, changed, err := scanExportBodyBytes(string(raw), contentType, "", "", inheritedCharset, field, redact, depth+1, budget)
	if err != nil {
		return "", false, err
	}
	for _, value := range [...]string{header.Name, header.Comment, string(header.Extra)} {
		if _, _, err := scanTextDepth(value, field, false, 0, budget); err != nil {
			return "", false, err
		}
	}
	if !changed {
		return body, false, nil
	}
	var output bytes.Buffer
	var writer io.WriteCloser
	if rawDeflate {
		writer, err = flate.NewWriter(&output, flate.DefaultCompression)
		if err != nil {
			return blocked()
		}
	} else if encoding == "deflate" {
		writer = zlib.NewWriter(&output)
	} else {
		writer = gzip.NewWriter(&output)
	}
	_, err = io.WriteString(writer, clean)
	closeErr = writer.Close()
	if err != nil || closeErr != nil {
		return blocked()
	}
	return output.String(), true, nil
}
