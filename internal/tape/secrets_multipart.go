package tape

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"strings"
)

func scanExportMultipart(body, media, boundary, field string, normalized *string, redact bool, depth int, budget *int) error {
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
		body, raw, contentType string
		headers                textproto.MIMEHeader
		charsetField           bool
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
				if _, _, err := scanExportHeader(k, v, field+".part.headers", false, budget); err != nil {
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
		transfer := strings.ToLower(strings.TrimSpace(p.Header.Get("Content-Transfer-Encoding")))
		switch transfer {
		case "", "binary", "8bit", "7bit", "quoted-printable":
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
		raw, err := io.ReadAll(io.LimitReader(p, int64(limit)+1))
		if err != nil || len(raw) > limit {
			return blocked()
		}
		*budget -= len(raw)
		data := raw
		if transfer == "quoted-printable" {
			if len(raw) > *budget {
				return blocked()
			}
			data, err = io.ReadAll(quotedprintable.NewReader(bytes.NewReader(raw)))
			if err != nil {
				return blocked()
			}
			*budget -= len(data)
		}
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
		rawBody := string(raw)
		decoded := rawBody
		if transfer == "quoted-printable" {
			decoded = string(data)
		}
		parts = append(parts, part{decoded, rawBody, ct, p.Header, isCharset})
	}
	changed := false
	for i := range parts {
		p := &parts[i]
		inherited := charset
		if p.charsetField {
			inherited = ""
		}
		clean, c, err := scanExportBodyBytes(p.body, p.contentType, p.headers.Get("Content-Encoding"), "", inherited, field, redact, depth+1, budget)
		if err != nil {
			return err
		}
		if c {
			if media == "multipart/signed" || strings.Contains(clean, delimiter) {
				return blocked()
			}
			p.raw, changed = clean, true
			for _, name := range [...]string{"Content-Encoding", "Content-Transfer-Encoding", "Content-Length", "Content-Md5", "Content-Digest", "Repr-Digest", "Digest", "Etag"} {
				p.headers.Del(name)
			}
			if media, params, _ := mime.ParseMediaType(p.contentType); exportCompressionMedia(media) != "" {
				p.headers.Del("Content-Type")
				if decoded := exportDecodedMedia(params); decoded != "" {
					p.headers.Set("Content-Type", decoded)
				}
			}
		}
	}
	if changed {
		var rebuilt strings.Builder
		w := multipart.NewWriter(&rebuilt)
		if err := w.SetBoundary(boundary); err != nil {
			return blocked()
		}
		for _, p := range parts {
			part, err := w.CreatePart(p.headers)
			if err != nil || len(p.raw) > maxCassetteBody-rebuilt.Len() {
				return blocked()
			}
			if _, err := io.WriteString(part, p.raw); err != nil {
				return blocked()
			}
		}
		if err := w.Close(); err != nil || rebuilt.Len() > maxCassetteBody {
			return blocked()
		}
		*normalized = rebuilt.String()
	}
	return nil
}
