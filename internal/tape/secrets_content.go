package tape

import (
	"encoding/json"
	"mime"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var bodyEntity = regexp.MustCompile(`&(?:amp|lt|gt|quot|apos|#[0-9]+|#[xX][0-9a-fA-F]+);`)
var xmlEntityDeclaration = regexp.MustCompile(`(?is)<!ENTITY\b|<!DOCTYPE\b(?:[^>"'\[]|"[^"]*"|'[^']*')*\[`)

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
	if strings.Contains(body, "<!") && xmlEntityDeclaration.MatchString(body) {
		return &ExportBlockedError{Kind: "unscannable_xml_entity", Field: field}
	}
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
	if strings.Contains(decoded, "<!") && xmlEntityDeclaration.MatchString(decoded) {
		return &ExportBlockedError{Kind: "unscannable_xml_entity", Field: field}
	}
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

func scanBodyText(body, contentType, field string, redact bool) (string, bool, error) {
	return scanBody(body, false, "", contentType, "", field, redact)
}

func scanClassifiedBody(class exportBodyClass, original, field string, redact bool, depth int, budget *int) (out string, changed bool, err error) {
	body, media := class.text, class.media
	if class.kind == exportMultipart {
		if err := scanExportMultipart(body, media, class.params["boundary"], field, &body, redact, depth, budget); err != nil {
			return "", false, err
		}
	}
	if class.order != nil && redact {
		defer func() {
			if changed && err == nil {
				out = encodeUTF16Body(out, class.order, len(original))
			}
		}()
	}
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
	clean, c, err := scanTextDepth(body, field, redact, 0, budget)
	return clean, c || body != class.text, err
}
