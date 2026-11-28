package tape

import (
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"strings"
)

func scanExportMultipart(body, media, boundary, field string, depth int, budget *int) error {
	blocked := func() error { return &ExportBlockedError{Kind: "unscannable_encoding", Field: field} }
	if budget == nil || *budget < 0 || depth < 0 || depth > 8 || len(body) > 4<<20 || boundary == "" || media == "multipart/digest" {
		return blocked()
	}
	if len(body) > *budget/32 {
		return blocked()
	}
	*budget -= len(body) * 32
	delimiter := "--" + boundary
	first, _, _ := strings.Cut(body, "\n")
	first = strings.TrimSuffix(first, "\r")
	if !strings.HasPrefix(first, delimiter) || (strings.Trim(first[len(delimiter):], " \t") != "" && strings.Trim(first[len(delimiter):], " \t") != "--") {
		return blocked()
	}
	closed := false
	for rest := body; rest != ""; {
		line, next, _ := strings.Cut(rest, "\n")
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, delimiter+"--") && strings.Trim(line[len(delimiter)+2:], " \t") == "" {
			if strings.Trim(next, " \t\r\n\v\f") != "" {
				return blocked()
			}
			closed = true
			break
		}
		rest = next
	}
	if !closed {
		return blocked()
	}
	type part struct {
		body, contentType, contentEncoding string
		charsetField                       bool
	}
	var parts []part
	var charset string
	charsetSeen := false
	r := multipart.NewReader(strings.NewReader(body), boundary)
	for {
		p, err := r.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return blocked()
		}
		for k, values := range p.Header {
			switch strings.ToLower(k) {
			case "content-disposition", "content-type", "content-transfer-encoding", "content-encoding", "grpc-encoding", "transfer-encoding":
				if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
					return blocked()
				}
			}
			for _, v := range values {
				if _, _, err := scanHeader(k, v, field+".part.headers", false, budget); err != nil {
					if e, ok := err.(*ExportBlockedError); ok && (e.Kind == "unsupported_encoding" || e.Kind == "unscannable_encoding") {
						return blocked()
					}
					return err
				}
			}
		}
		for _, name := range []string{"Grpc-Encoding", "Transfer-Encoding"} {
			if enc := strings.TrimSpace(p.Header.Get(name)); enc != "" && !strings.EqualFold(enc, "identity") {
				return blocked()
			}
		}
		var source io.Reader = p
		switch strings.ToLower(strings.TrimSpace(p.Header.Get("Content-Transfer-Encoding"))) {
		case "", "binary", "8bit", "7bit":
		case "base64":
			source = base64.NewDecoder(base64.StdEncoding.Strict(), p)
		case "quoted-printable":
			source = quotedprintable.NewReader(p)
		default:
			return blocked()
		}
		limit := 4 << 20
		if *budget < limit {
			limit = *budget
		}
		if limit < 0 {
			return blocked()
		}
		data, err := io.ReadAll(io.LimitReader(source, int64(limit)+1))
		if err != nil || len(data) > limit {
			return blocked()
		}
		*budget -= len(data)
		ct := p.Header.Get("Content-Type")
		if ct == "" {
			ct = "text/plain"
		}
		isCharset := false
		if disposition := p.Header.Get("Content-Disposition"); disposition != "" {
			kind, params, err := mime.ParseMediaType(disposition)
			if err != nil {
				return blocked()
			}
			if media == "multipart/form-data" && kind == "form-data" && params["name"] == "_charset_" {
				if charsetSeen {
					return blocked()
				}
				isCharset = true
				charsetSeen = true
				charset = strings.ToLower(strings.TrimSpace(string(data)))
				switch charset {
				case "utf-8", "utf8", "us-ascii", "ascii", "utf-16", "utf-16le", "utf-16be":
				default:
					return blocked()
				}
			}
		}
		parts = append(parts, part{string(data), ct, p.Header.Get("Content-Encoding"), isCharset})
	}
	for _, p := range parts {
		inherited := charset
		if p.charsetField {
			inherited = ""
		}
		if _, _, err := scanExportBodyBytes(p.body, p.contentType, p.contentEncoding, "", inherited, field, false, depth+1, budget); err != nil {
			return err
		}
	}
	return nil
}
