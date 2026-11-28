package tape

import (
	"encoding/binary"
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

func textMedia(media string) bool {
	if strings.HasPrefix(media, "text/") || strings.HasSuffix(media, "+xml") || strings.HasSuffix(media, "+json") {
		return true
	}
	switch media {
	case "application/xml", "application/xml-dtd", "application/xml-external-parsed-entity",
		"application/json", "application/json-seq", "application/x-ndjson",
		"application/x-www-form-urlencoded", "application/javascript", "application/yaml", "application/x-yaml":
		return true
	}
	return false
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
	} else if !utf8.ValidString(body) {
		return blocked()
	}
	if !allowedXMLDeclarations(body, order) {
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
