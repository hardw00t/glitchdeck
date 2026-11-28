package tape

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var bodyEntity = regexp.MustCompile(`&(?:amp|lt|gt|quot|apos|#[0-9]+|#[xX][0-9a-fA-F]+);`)

func decodeBodyEntity(entity string) string {
	switch entity {
	case "&amp;":
		return "&"
	case "&lt;":
		return "<"
	case "&gt;":
		return ">"
	case "&quot;":
		return `"`
	case "&apos;":
		return "'"
	}
	digits, base := entity[2:len(entity)-1], 10
	if digits[0] == 'x' || digits[0] == 'X' {
		digits, base = digits[1:], 16
	}
	n, err := strconv.ParseUint(digits, base, 32)
	if err != nil || !(n >= 1 && n <= 0xd7ff || n >= 0xe000 && n <= 0xfffd || n >= 0x10000 && n <= 0x10ffff) {
		return entity
	}
	return string(rune(n))
}

func checkDerived(raw, decoded, field string, redact bool, budget *int, decode func(string) (string, error)) error {
	_, _, originalErr := scanTextDepth(decoded, field, false, 0, budget)
	if originalErr == nil || !redact {
		return originalErr
	}
	cleanRaw, _, err := scanTextDepth(raw, field, true, 0, budget)
	if err != nil {
		return err
	}
	cleanDecoded, _, err := scanTextDepth(decoded, field, true, 0, budget)
	if err != nil {
		return err
	}
	// Rewriting the original must remove exactly the same matches in the decoded view.
	if len(cleanRaw) > *budget {
		return unsupportedBody(field)
	}
	*budget -= len(cleanRaw)
	derivedClean, err := decode(cleanRaw)
	if err != nil || derivedClean != cleanDecoded {
		return originalErr
	}
	return nil
}

func scanBodyEntities(body, field string, redact bool, budget *int) error {
	if !strings.Contains(body, "&") {
		return nil
	}
	if len(body) > *budget/2 {
		return unsupportedBody(field)
	}
	*budget -= 2 * len(body)
	decode := func(s string) (string, error) {
		return bodyEntity.ReplaceAllStringFunc(s, decodeBodyEntity), nil
	}
	decoded, _ := decode(body)
	if decoded != body {
		return checkDerived(body, decoded, field, redact, budget, decode)
	}
	return nil
}

func decodeHeaderPairs(value string) (string, error) {
	var decoded strings.Builder
	decoded.Grow(len(value))
	inQuote, escapedQuote := false, false
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' {
			i++
			if i == len(value) || value[i] < 0x20 && value[i] != '\t' || value[i] == 0x7f {
				return "", unsupportedBody("")
			}
			escapedQuote = escapedQuote || inQuote
		} else if value[i] == '"' {
			inQuote = !inQuote
			escapedQuote = false
		}
		decoded.WriteByte(value[i])
	}
	if inQuote && escapedQuote {
		return "", unsupportedBody("")
	}
	return decoded.String(), nil
}

func checkHeaderPairs(raw, decoded, field string, redact bool, budget *int) error {
	return checkDerived(raw, decoded, field, redact, budget, func(clean string) (string, error) {
		for a, b := raw, clean; ; {
			_, afterA, hasA := strings.Cut(a, `\`)
			_, afterB, hasB := strings.Cut(b, `\`)
			if !hasA && !hasB {
				break
			}
			if afterA == "" || afterB == "" || afterA[0] != afterB[0] {
				return "", unsupportedBody(field)
			}
			a, b = afterA[1:], afterB[1:]
		}
		return decodeHeaderPairs(clean)
	})
}

func unsupportedBody(field string) error {
	return &ExportBlockedError{Kind: "unsupported_encoding", Field: field}
}

func checkSSEPrivateKey(s, field string, budget *int, depth int) error {
	if depth > 8 {
		return unsupportedBody(field)
	}
	for _, pattern := range secretPatterns {
		if pattern.kind == "private_key" && pattern.re.MatchString(s) {
			return &ExportBlockedError{Kind: pattern.kind, Field: field}
		}
	}
	if strings.Contains(s, "%") {
		if len(s) > *budget/2 {
			return unsupportedBody(field)
		}
		*budget -= 2 * len(s)
		var decodedBuilder strings.Builder
		decodedBuilder.Grow(len(s))
		for i := 0; i < len(s); i++ {
			if s[i] == '%' && i+2 < len(s) {
				if decoded, err := url.PathUnescape(s[i : i+3]); err == nil {
					decodedBuilder.WriteString(decoded)
					i += 2
					continue
				}
			}
			decodedBuilder.WriteByte(s[i])
		}
		decoded := decodedBuilder.String()
		if decoded != s {
			if err := checkSSEPrivateKey(decoded, field, budget, depth+1); err != nil {
				return err
			}
		}
	}
	if strings.Contains(s, `\`) {
		for rest := s; rest != ""; {
			match := quotedString.FindStringIndex(rest)
			if match == nil {
				break
			}
			part := rest[match[0]:match[1]]
			rest = rest[match[1]:]
			if !strings.Contains(part, `\`) {
				continue
			}
			if len(part) > *budget/2 {
				return unsupportedBody(field)
			}
			*budget -= 2 * len(part)
			var decoded string
			if json.Unmarshal([]byte(part), &decoded) != nil {
				return unsupportedBody(field)
			}
			if err := checkSSEPrivateKey(decoded, field, budget, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func scanHeader(name, value, field string, redact bool, budget *int) (string, bool, error) {
	if _, _, err := scanTextDepth(name, field, false, 0, budget); err != nil {
		return "", false, err
	}
	if strings.Contains(value, "=?") {
		return "", false, unsupportedBody(field)
	}
	if strings.Contains(value, `\`) {
		if len(value) > *budget/2 {
			return "", false, unsupportedBody(field)
		}
		*budget -= 2 * len(value)
		decoded, err := decodeHeaderPairs(value)
		if err != nil {
			return "", false, unsupportedBody(field)
		}
		for _, suffix := range [...]string{"", ".location", ".form"} {
			if err := checkHeaderPairs(value, decoded, field+suffix, redact, budget); err != nil {
				return "", false, err
			}
		}
		for rest := value; rest != ""; {
			match := quotedString.FindStringIndex(rest)
			if match == nil {
				break
			}
			part := rest[match[0]:match[1]]
			rest = rest[match[1]:]
			if !strings.Contains(part, `\`) {
				continue
			}
			inner := part[1 : len(part)-1]
			decoded, err := decodeHeaderPairs(inner)
			if err != nil {
				return "", false, unsupportedBody(field)
			}
			if err := checkHeaderPairs(inner, decoded, field, redact, budget); err != nil {
				return "", false, err
			}
		}
	}
	for rest := value; strings.Contains(rest, ";"); {
		_, rest, _ = strings.Cut(rest, ";")
		segment, _, _ := strings.Cut(rest, ";")
		key, _, ok := strings.Cut(strings.TrimSpace(segment), "=")
		if ok && strings.Contains(key, "*") {
			return "", false, unsupportedBody(field)
		}
	}
	changed := false
	if strings.EqualFold(name, "Content-Disposition") || strings.EqualFold(name, "Content-Type") {
		if len(value) > *budget/32 {
			return "", false, unsupportedBody(field)
		}
		*budget -= 32 * len(value)
		media, params, err := mime.ParseMediaType(value)
		if err != nil {
			return "", false, unsupportedBody(field)
		}
		for key, param := range params {
			clean, c, err := scanTextDepth(param, field+".location", redact, 0, budget)
			if err != nil {
				return "", false, err
			}
			if c {
				params[key], changed = clean, true
			}
		}
		if changed {
			value = mime.FormatMediaType(media, params)
			if value == "" {
				return "", false, unsupportedBody(field)
			}
		}
	}
	clean, c, err := scanTextDepth(value, field, redact, 0, budget)
	if err != nil {
		return "", false, err
	}
	clean, urlChanged, err := scanTextDepth(clean, field+".location", redact, 0, budget)
	if err != nil {
		return "", false, err
	}
	clean, queryChanged, err := scanTextDepth(clean, field+".form", redact, 0, budget)
	return clean, changed || c || urlChanged || queryChanged, err
}

func checkBodyEncoding(contentType, transfer, field string, budget *int) error {
	if transfer != "" && transfer != "binary" && transfer != "8bit" && transfer != "7bit" {
		return unsupportedBody(field)
	}
	if contentType == "" {
		return nil
	}
	if len(contentType) > *budget/32 {
		return unsupportedBody(field)
	}
	*budget -= 32 * len(contentType)
	media, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return unsupportedBody(field)
	}
	for rest := contentType; strings.Contains(rest, ";"); {
		_, rest, _ = strings.Cut(rest, ";")
		segment, _, _ := strings.Cut(rest, ";")
		name, _, ok := strings.Cut(strings.TrimSpace(segment), "=")
		if !ok || strings.Contains(name, "*") {
			return unsupportedBody(field)
		}
	}
	for _, value := range params {
		if _, _, err := scanTextDepth(value, field, false, 0, budget); err != nil {
			return err
		}
	}
	charset := strings.ToLower(params["charset"])
	if charset != "" && charset != "utf-8" && charset != "us-ascii" {
		return unsupportedBody(field)
	}
	if strings.HasPrefix(media, "application/grpc") || strings.HasPrefix(media, "message/") || media == "multipart/digest" {
		return unsupportedBody(field)
	}
	return nil
}

func scanBodyText(body, contentType, field string, redact bool) (string, bool, error) {
	budget := 64 << 20
	return scanContentBudget(body, contentType, field, redact, 0, &budget)
}

func scanContentBudget(body, contentType, field string, redact bool, depth int, budget *int) (string, bool, error) {
	if depth > 8 || len(body) > 4<<20 {
		return "", false, unsupportedBody(field)
	}
	if len(contentType) > *budget/32 {
		return "", false, unsupportedBody(field)
	}
	*budget -= 32 * len(contentType)
	media, params, _ := mime.ParseMediaType(contentType)
	entityField := field
	if media == "application/x-www-form-urlencoded" {
		entityField += ".form"
	}
	if err := scanBodyEntities(body, entityField, redact, budget); err != nil {
		return "", false, err
	}
	if strings.ContainsRune(body, 0) {
		if len(body) > *budget {
			return "", false, unsupportedBody(field)
		}
		*budget -= len(body)
		stripped := strings.ReplaceAll(body, "\x00", "")
		if err := scanBodyEntities(stripped, entityField, false, budget); err != nil {
			return "", false, err
		}
		if _, _, err := scanTextDepth(stripped, field, false, 0, budget); err != nil {
			return "", false, err
		}
	}
	if strings.HasPrefix(body, "\xff\xfe") || strings.HasPrefix(body, "\xfe\xff") || strings.HasPrefix(body, "\x00\x00\xfe\xff") {
		return "", false, unsupportedBody(field)
	}
	if strings.HasPrefix(media, "message/") || media == "multipart/digest" {
		return "", false, unsupportedBody(field)
	}
	encoding := ""
	declaredJSON := (media == "application/json" || strings.HasSuffix(media, "+json")) && json.Valid([]byte(body))
	if media == "application/gzip" || media == "application/x-gzip" || !declaredJSON && strings.HasPrefix(body, "\x1f\x8b") {
		encoding = "gzip"
	} else if media == "application/zlib" || !declaredJSON && len(body) >= 2 && body[0]&15 == 8 && body[0]>>4 <= 7 && (int(body[0])*256+int(body[1]))%31 == 0 {
		encoding = "deflate"
	}
	if encoding != "" {
		innerType := contentType
		if media == "application/gzip" || media == "application/x-gzip" || media == "application/zlib" {
			innerType = ""
		}
		if _, _, err := scanBodyBudgetDepth(body, false, encoding, innerType, "", field, false, budget, depth+1); err != nil {
			return "", false, err
		}
		return body, false, nil
	}
	switch media {
	case "application/zip", "application/x-zip-compressed", "application/x-bzip2", "application/x-bzip",
		"application/x-xz", "application/zstd", "application/x-zstd",
		"application/x-7z-compressed", "application/x-tar", "application/x-rar-compressed",
		"application/vnd.rar", "application/x-compress", "application/compress", "application/x-lz4", "application/lz4":
		return "", false, unsupportedBody(field)
	}
	if !declaredJSON && (strings.HasPrefix(body, "PK\x03\x04") || strings.HasPrefix(body, "PK\x05\x06") || strings.HasPrefix(body, "PK\x07\x08") ||
		strings.HasPrefix(body, "BZh") || strings.HasPrefix(body, "\xfd7zXZ\x00") ||
		strings.HasPrefix(body, "\x28\xb5\x2f\xfd") || strings.HasPrefix(body, "7z\xbc\xaf\x27\x1c") ||
		strings.HasPrefix(body, "\x1f\x9d") || strings.HasPrefix(body, "\x04\x22\x4d\x18") ||
		strings.HasPrefix(body, "Rar!\x1a\x07") || (len(body) >= 262 && body[257:262] == "ustar")) {
		return "", false, unsupportedBody(field)
	}
	if strings.HasPrefix(media, "multipart/") {
		if len(body) > *budget/32 {
			return "", false, unsupportedBody(field)
		}
		*budget -= 32 * len(body)
		if params["boundary"] == "" {
			return "", false, unsupportedBody(field)
		}
		r := multipart.NewReader(strings.NewReader(body), params["boundary"])
		for {
			p, err := r.NextRawPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return "", false, unsupportedBody(field)
			}
			for _, name := range []string{"Content-Encoding", "Grpc-Encoding"} {
				enc := strings.TrimSpace(strings.ToLower(p.Header.Get(name)))
				if enc != "" && enc != "identity" {
					return "", false, unsupportedBody(field)
				}
			}
			for k, values := range p.Header {
				if (strings.EqualFold(k, "Content-Disposition") || strings.EqualFold(k, "Content-Type") ||
					strings.EqualFold(k, "Content-Transfer-Encoding") || strings.EqualFold(k, "Content-Encoding") ||
					strings.EqualFold(k, "Grpc-Encoding")) && len(values) != 1 {
					return "", false, unsupportedBody(field)
				}
				for _, v := range values {
					if _, _, err = scanHeader(k, v, field+".part.headers", false, budget); err != nil {
						return "", false, err
					}
				}
			}
			var source io.Reader = p
			switch strings.ToLower(strings.TrimSpace(p.Header.Get("Content-Transfer-Encoding"))) {
			case "", "binary", "8bit", "7bit":
			case "base64":
				source = base64.NewDecoder(base64.StdEncoding, p)
			case "quoted-printable":
				source = quotedprintable.NewReader(p)
			default:
				return "", false, unsupportedBody(field)
			}
			limit := 4 << 20
			if *budget < limit {
				limit = *budget
			}
			data, err := io.ReadAll(io.LimitReader(source, int64(limit)+1))
			if err != nil || len(data) > limit {
				return "", false, unsupportedBody(field)
			}
			*budget -= len(data)
			ct := p.Header.Get("Content-Type")
			if err = checkBodyEncoding(ct, "", field, budget); err != nil {
				return "", false, err
			}
			if _, _, err = scanContentBudget(string(data), ct, field, false, depth+1, budget); err != nil {
				return "", false, err
			}
		}
		// Preserve MIME bytes only after checking the decoded parts.
		return scanTextDepth(body, field, redact, 0, budget)
	}
	if media == "application/x-www-form-urlencoded" {
		field += ".form"
	}
	if media == "text/event-stream" {
		if *budget < 1 || len(body) > (*budget-1)/5 {
			return "", false, unsupportedBody(field)
		}
		*budget -= 5*len(body) + 1
		var values strings.Builder
		values.Grow(len(body) + 1)
		for rest := body; rest != ""; {
			i := strings.IndexAny(rest, "\r\n")
			line := rest
			if i >= 0 {
				ending := rest[i]
				line, rest = rest[:i], rest[i+1:]
				if ending == '\r' && strings.HasPrefix(rest, "\n") {
					rest = rest[1:]
				}
			} else {
				rest = ""
			}
			_, value, ok := strings.Cut(line, ":")
			if ok {
				values.WriteString(strings.TrimPrefix(value, " "))
			} else {
				values.WriteString(line)
			}
			values.WriteByte('\n')
		}
		joined := values.String()
		for _, pattern := range secretPatterns {
			for rest := joined; rest != ""; {
				match := pattern.re.FindStringIndex(rest)
				if match == nil {
					break
				}
				if strings.Contains(rest[match[0]:match[1]], "\n") {
					return "", false, &ExportBlockedError{Kind: pattern.kind, Field: field}
				}
				rest = rest[match[1]:]
			}
		}
		var output strings.Builder
		output.Grow(2 * len(body))
		data := make([]byte, 0, len(body))
		changed, first := false, true
		for rest := body; rest != ""; {
			i := strings.IndexAny(rest, "\r\n")
			line, ending := rest, ""
			if i >= 0 {
				line, ending, rest = rest[:i], rest[i:i+1], rest[i+1:]
				if ending == "\r" && strings.HasPrefix(rest, "\n") {
					ending, rest = "\r\n", rest[1:]
				}
			} else {
				rest = ""
			}
			bom := ""
			if first && strings.HasPrefix(line, "\uFEFF") {
				bom, line = "\uFEFF", strings.TrimPrefix(line, "\uFEFF")
			}
			first = false
			if line == "" {
				if len(data) > 0 {
					if _, _, err := scanTextDepth(string(data), field, false, 0, budget); err != nil {
						return "", false, err
					}
					data = data[:0]
				}
				output.WriteString(bom)
				output.WriteString(ending)
				continue
			}
			if err := checkSSEPrivateKey(line, field, budget, 0); err != nil {
				return "", false, err
			}
			clean, replaced, err := scanTextDepth(line, field, redact, 0, budget)
			if err != nil {
				return "", false, err
			}
			changed = changed || replaced
			output.WriteString(bom)
			output.WriteString(clean)
			output.WriteString(ending)
			name, value, _ := strings.Cut(clean, ":")
			if name == "data" {
				data = append(data, strings.TrimPrefix(value, " ")...)
				data = append(data, '\n')
			}
		}
		if len(data) > 0 {
			if _, _, err := scanTextDepth(string(data), field, false, 0, budget); err != nil {
				return "", false, err
			}
		}
		if changed {
			return output.String(), true, nil
		}
		return body, false, nil
	}
	return scanTextDepth(body, field, redact, 0, budget)
}
