package tape

import (
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"strconv"
	"strings"
)

func unsupportedBody(field string) error {
	return &ExportBlockedError{Kind: "unsupported_encoding", Field: field}
}

func checkBodyEncoding(contentType, transfer, field string) error {
	if transfer != "" && transfer != "binary" && transfer != "8bit" && transfer != "7bit" {
		return unsupportedBody(field)
	}
	if contentType == "" {
		return nil
	}
	media, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return unsupportedBody(field)
	}
	for _, segment := range strings.Split(contentType, ";")[1:] {
		name, _, ok := strings.Cut(strings.TrimSpace(segment), "=")
		if !ok || strings.Contains(name, "*") {
			return unsupportedBody(field)
		}
	}
	for _, value := range params {
		if _, _, err := scanText(value, field, false); err != nil {
			return err
		}
	}
	charset := strings.ToLower(params["charset"])
	if charset != "" && charset != "utf-8" && charset != "us-ascii" {
		return unsupportedBody(field)
	}
	if strings.HasPrefix(media, "application/grpc") {
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
	if strings.HasPrefix(body, "\xff\xfe") || strings.HasPrefix(body, "\xfe\xff") || strings.HasPrefix(body, "\x00\x00\xfe\xff") {
		return "", false, unsupportedBody(field)
	}
	media, params, _ := mime.ParseMediaType(contentType)
	if media == "application/gzip" || media == "application/x-gzip" {
		if _, _, err := scanBodyBudget(body, false, "gzip", "", "", field, false, budget); err != nil {
			return "", false, err
		}
		return body, false, nil
	}
	if strings.HasPrefix(media, "multipart/") {
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
				for _, v := range values {
					if _, _, err = scanText(k+": "+v, field, false); err != nil {
						return "", false, err
					}
					if strings.EqualFold(k, "Content-Disposition") || strings.EqualFold(k, "Content-Type") {
						if len(values) != 1 {
							return "", false, unsupportedBody(field)
						}
						_, parsed, err := mime.ParseMediaType(values[0])
						if err != nil {
							return "", false, unsupportedBody(field)
						}
						next := map[string]int{}
						for _, segment := range strings.Split(values[0], ";")[1:] {
							name, _, ok := strings.Cut(strings.TrimSpace(segment), "=")
							if !ok {
								return "", false, unsupportedBody(field)
							}
							if i := strings.IndexByte(name, '*'); i >= 0 {
								suffix := strings.TrimSuffix(name[i+1:], "*")
								if suffix != "" {
									index, e := strconv.Atoi(suffix)
									base := strings.ToLower(name[:i])
									if e != nil || index != next[base] {
										return "", false, unsupportedBody(field)
									}
									next[base]++
								}
								if _, ok := parsed[strings.ToLower(name[:i])]; !ok {
									return "", false, unsupportedBody(field)
								}
							}
						}
						for _, value := range parsed {
							if _, _, err := scanText(value, field, false); err != nil {
								return "", false, err
							}
						}
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
			if err = checkBodyEncoding(ct, "", field); err != nil {
				return "", false, err
			}
			if _, _, err = scanContentBudget(string(data), ct, field, false, depth+1, budget); err != nil {
				return "", false, err
			}
		}
		// Preserve MIME bytes only after checking the decoded parts.
		return scanText(body, field, redact)
	}
	if media == "application/x-www-form-urlencoded" {
		field += ".form"
	}
	if media == "text/event-stream" {
		normalized := strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\r", "\n")
		lines := strings.Split(normalized, "\n")
		changed := false
		var data, original []string
		flush := func() error {
			if len(data) == 0 {
				return nil
			}
			for _, pattern := range secretPatterns {
				if pattern.kind == "private_key" && pattern.re.MatchString(strings.Join(original, "\n")) {
					return &ExportBlockedError{Kind: pattern.kind, Field: field}
				}
			}
			_, _, err := scanText(strings.Join(data, "\n"), field, false)
			data = nil
			original = nil
			return err
		}
		for i, line := range lines {
			bom := ""
			if i == 0 && strings.HasPrefix(line, "\uFEFF") {
				bom = "\uFEFF"
				line = strings.TrimPrefix(line, bom)
			}
			if line == "" {
				if err := flush(); err != nil {
					return "", false, err
				}
				continue
			}
			name, value, _ := strings.Cut(line, ":")
			if name == "data" {
				original = append(original, strings.TrimPrefix(value, " "))
			}
			clean, replaced, err := scanText(line, field, redact)
			if err != nil {
				return "", false, err
			}
			if replaced {
				changed = true
				lines[i] = bom + clean
			}
			name, value, _ = strings.Cut(clean, ":")
			if name == "data" {
				data = append(data, strings.TrimPrefix(value, " "))
			}
		}
		if err := flush(); err != nil {
			return "", false, err
		}
		if changed {
			return strings.Join(lines, "\n"), true, nil
		}
		return body, false, nil
	}
	return scanText(body, field, redact)
}
