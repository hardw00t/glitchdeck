package tape

import (
	"encoding/binary"
	"encoding/json"
	"mime"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

type utf16Order interface {
	binary.ByteOrder
	binary.AppendByteOrder
}

var xmlDeclaration = regexp.MustCompile(`(?i)^<\?xml[\t\r\n ]+[^?]*\?>`)
var xmlEncoding = regexp.MustCompile(`(?i)[\t\r\n ]encoding[\t\r\n ]*=[\t\r\n ]*(?:"([^"]*)"|'([^']*)')`)

func allowedTextEncoding(name string, order utf16Order) bool {
	name = strings.TrimSpace(name)
	if len(name) >= 2 && (name[0] == '\'' || name[0] == '"') && name[len(name)-1] == name[0] {
		name = strings.TrimSpace(name[1 : len(name)-1])
	}
	switch strings.ToLower(name) {
	case "utf-8", "utf8", "us-ascii", "ascii":
		return order == nil
	case "utf-16":
		return order != nil
	case "utf-16le":
		return order == binary.LittleEndian
	case "utf-16be":
		return order == binary.BigEndian
	}
	return false
}

func allowedXMLDeclarations(body string, order utf16Order) bool {
	body = strings.TrimLeft(strings.TrimPrefix(strings.TrimLeft(body, " \t\r\n"), "\xef\xbb\xbf"), " \t\r\n")
	if !strings.HasPrefix(body, "<?") {
		return true
	}
	match := xmlDeclaration.FindStringIndex(body)
	if match == nil {
		return true
	}
	enc := xmlEncoding.FindStringSubmatch(body[:match[1]])
	return enc == nil || allowedTextEncoding(enc[1]+enc[2], order)
}

type exportBodyKind uint8

const (
	exportCleanText exportBodyKind = iota
	exportCompressed
	exportMultipart
)

type exportBodyClass struct {
	kind        exportBodyKind
	text        string
	order       utf16Order
	media       string
	params      map[string]string
	compression string
}

func textMedia(media string) bool {
	if media == "" || strings.HasPrefix(media, "text/") || strings.HasSuffix(media, "+xml") || strings.HasSuffix(media, "+json") {
		return true
	}
	switch media {
	case "application/xml", "application/xml-dtd", "application/xml-external-parsed-entity",
		"application/json", "application/json-seq", "application/x-ndjson",
		"application/x-www-form-urlencoded", "application/javascript", "application/yaml", "application/x-yaml",
		"application/sql", "application/x-sql", "application/graphql":
		return true
	}
	return false
}

func exportCompressionMedia(media string) string {
	switch media {
	case "application/gzip", "application/x-gzip":
		return "gzip"
	case "application/zlib":
		return "deflate"
	}
	return ""
}

func classifyExportBody(body, contentType, encoding, transfer, inheritedCharset, field string, budget *int, storedBase64 bool) (exportBodyClass, error) {
	blocked := func() (exportBodyClass, error) {
		return exportBodyClass{}, &ExportBlockedError{Kind: "unscannable_encoding", Field: field}
	}
	if storedBase64 || len(body) > maxCassetteBody {
		return blocked()
	}
	result := exportBodyClass{text: body}
	if transfer = strings.ToLower(strings.TrimSpace(transfer)); transfer != "" && transfer != "binary" && transfer != "7bit" && transfer != "8bit" {
		return blocked()
	}
	if contentType != "" {
		if len(contentType) > *budget/32 {
			return blocked()
		}
		*budget -= len(contentType) * 32
		var err error
		result.media, result.params, err = mime.ParseMediaType(contentType)
		if err != nil {
			return blocked()
		}
	}
	if inheritedCharset != "" && textMedia(result.media) {
		if _, ok := result.params["charset"]; !ok {
			if result.params == nil {
				result.params = make(map[string]string, 1)
			}
			result.params["charset"] = inheritedCharset
		}
	}
	charset, charsetDeclared := result.params["charset"]
	charset = strings.ToLower(strings.TrimSpace(charset))
	if len(charset) >= 2 && (charset[0] == '\'' || charset[0] == '"') && charset[len(charset)-1] == charset[0] {
		charset = strings.TrimSpace(charset[1 : len(charset)-1])
	}
	if charsetDeclared {
		switch charset {
		case "utf-8", "utf8", "us-ascii", "ascii", "utf-16", "utf-16le", "utf-16be":
		default:
			return blocked()
		}
		result.params["charset"] = charset
	}
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	switch encoding {
	case "", "identity":
		encoding = ""
	case "gzip", "x-gzip":
		encoding = "gzip"
	case "deflate":
	default:
		return blocked()
	}
	declaredJSON := (result.media == "application/json" || strings.HasSuffix(result.media, "+json")) && json.Valid([]byte(body))
	if encoding == "" {
		encoding = exportCompressionMedia(result.media)
	}
	if encoding == "" {
		switch {
		case !declaredJSON && strings.HasPrefix(body, "\x1f\x8b"):
			encoding = "gzip"
		case !declaredJSON && len(body) >= 8 && body[0]&15 == 8 && body[0]>>4 <= 7 && (int(body[0])*256+int(body[1]))%31 == 0:
			encoding = "deflate"
		}
	}
	if encoding != "" {
		result.kind, result.compression = exportCompressed, encoding
		return result, nil
	}
	frame := body
	compressedFrame := false
	for len(frame) >= 5 && frame[0] <= 1 {
		size := uint64(binary.BigEndian.Uint32([]byte(frame[1:5])))
		if size > uint64(len(frame)-5) {
			break
		}
		compressedFrame = compressedFrame || frame[0] == 1
		frame = frame[5+int(size):]
	}
	knownGRPC := strings.HasPrefix(result.media, "application/grpc") || strings.HasSuffix(field, ".message_b64")
	if compressedFrame || knownGRPC && len(body) >= 5 && body[0] == 1 {
		return blocked()
	}
	switch result.media {
	case "application/x-bzip2", "application/x-bzip",
		"application/x-xz", "application/zstd", "application/x-zstd", "application/x-7z-compressed",
		"application/x-tar", "application/x-rar-compressed", "application/vnd.rar",
		"application/x-compress", "application/compress", "application/x-lz4", "application/lz4":
		return blocked()
	case "application/octet-stream", "application/pdf", "application/zip":
		return blocked()
	}
	if strings.HasPrefix(result.media, "image/") || strings.HasPrefix(result.media, "audio/") ||
		strings.HasPrefix(result.media, "video/") || strings.HasPrefix(result.media, "font/") {
		return blocked()
	}
	if !declaredJSON && (strings.HasPrefix(body, "BZh") ||
		strings.HasPrefix(body, "\xfd7zXZ\x00") || strings.HasPrefix(body, "\x28\xb5\x2f\xfd") ||
		strings.HasPrefix(body, "7z\xbc\xaf\x27\x1c") || strings.HasPrefix(body, "\x1f\x9d") ||
		strings.HasPrefix(body, "\x04\x22\x4d\x18") || strings.HasPrefix(body, "Rar!\x1a\x07") ||
		strings.HasPrefix(body, "PK\x03\x04") || strings.HasPrefix(body, "PK\x05\x06") ||
		strings.HasPrefix(body, "%PDF-") || strings.HasPrefix(body, "GIF87a") || strings.HasPrefix(body, "GIF89a") ||
		len(body) >= 12 && (body[4:8] == "ftyp" || body[:4] == "RIFF" && (body[8:12] == "WEBP" || body[8:12] == "WAVE")) ||
		strings.HasPrefix(body, "wOFF") || strings.HasPrefix(body, "wOF2") || strings.HasPrefix(body, "OTTO") ||
		strings.HasPrefix(body, "OggS") || len(body) >= 10 && strings.HasPrefix(body, "ID3") ||
		len(body) >= 262 && body[257:262] == "ustar") {
		return blocked()
	}
	if strings.HasPrefix(result.media, "multipart/") {
		if result.media == "multipart/digest" || charsetDeclared {
			return blocked()
		}
		result.kind = exportMultipart
		return result, nil
	}
	if textMedia(result.media) {
		var err error
		result.text, result.order, err = textScanView(body, result.params, field, budget)
		if err != nil {
			return exportBodyClass{}, err
		}
		result.kind = exportCleanText
		return result, nil
	}
	return blocked()
}

func textScanView(body string, params map[string]string, field string, budget *int) (string, utf16Order, error) {
	blocked := func() (string, utf16Order, error) {
		return "", nil, &ExportBlockedError{Kind: "unscannable_encoding", Field: field}
	}
	if view := strings.TrimPrefix(body, "\xef\xbb\xbf"); len(view) >= 4 && strings.HasPrefix(view, "+/v") && strings.ContainsRune("89+/", rune(view[3])) {
		return blocked()
	}
	if strings.HasPrefix(body, "\xff\xfe\x00\x00") || strings.HasPrefix(body, "\x00\x00\xfe\xff") {
		return blocked()
	}
	var order utf16Order
	switch {
	case strings.HasPrefix(body, "\xff\xfe"):
		order = binary.LittleEndian
	case strings.HasPrefix(body, "\xfe\xff"):
		order = binary.BigEndian
	}
	charset, declared := params["charset"]
	if declared && !allowedTextEncoding(charset, order) {
		return blocked()
	}
	if order != nil {
		raw := body[2:]
		if len(raw)%2 != 0 {
			return blocked()
		}
		if len(raw) > *budget/3 {
			return "", nil, unsupportedBody(field)
		}
		*budget -= len(raw) * 3
		var text strings.Builder
		text.Grow(len(raw))
		for len(raw) != 0 {
			u := rune(uint16(raw[0])<<8 | uint16(raw[1]))
			if order == binary.LittleEndian {
				u = rune(uint16(raw[1])<<8 | uint16(raw[0]))
			}
			raw = raw[2:]
			if utf16.IsSurrogate(u) {
				if len(raw) < 2 {
					return blocked()
				}
				v := rune(uint16(raw[0])<<8 | uint16(raw[1]))
				if order == binary.LittleEndian {
					v = rune(uint16(raw[1])<<8 | uint16(raw[0]))
				}
				u = utf16.DecodeRune(u, v)
				if u == utf8.RuneError {
					return blocked()
				}
				raw = raw[2:]
			}
			text.WriteRune(u)
		}
		body = text.String()
	} else if strings.ContainsRune(body, 0) || !utf8.ValidString(body) {
		return blocked()
	}
	if declared && (strings.EqualFold(charset, "ascii") || strings.EqualFold(charset, "us-ascii")) {
		for _, r := range body {
			if r >= utf8.RuneSelf {
				return blocked()
			}
		}
	}
	if view := strings.TrimPrefix(body, "\xef\xbb\xbf"); len(view) >= 4 && strings.HasPrefix(view, "+/v") && strings.ContainsRune("89+/", rune(view[3])) {
		return blocked()
	}
	if strings.ContainsRune(body, 0) || !allowedXMLDeclarations(body, order) {
		return blocked()
	}
	return body, order, nil
}

func encodeUTF16Body(text string, order utf16Order, capacity int) string {
	out := order.AppendUint16(make([]byte, 0, capacity), 0xfeff)
	for _, r := range text {
		if r <= 0xffff {
			out = order.AppendUint16(out, uint16(r))
		} else {
			a, b := utf16.EncodeRune(r)
			out = order.AppendUint16(order.AppendUint16(out, uint16(a)), uint16(b))
		}
	}
	return string(out)
}
