package tape

import (
	"encoding/json"
	"fmt"
	"maps"
	"mime"
	"reflect"
	"strings"
)

var exportStructuralFields = map[reflect.Type]map[string]bool{
	reflect.TypeFor[HTTP]():            {"Method": true, "Proto": true},
	reflect.TypeFor[Stream]():          {"Method": true, "Proto": true},
	reflect.TypeFor[CassetteRequest](): {"Method": true},
	reflect.TypeFor[GRPC]():            {"Proto": true},
}

const redactedBase64 = "UkVEQUNURUQ="

func replaceUnscannable(err error) bool {
	e, ok := err.(*ExportBlockedError)
	return ok && (e.Kind == "unscannable_encoding" || e.Kind == "unscannable_xml_entity")
}

func scanExportScalar(value, field string, storedBase64, redact bool, budget *int) (string, bool, error) {
	if value == "" || storedBase64 && value == redactedBase64 {
		return value, false, nil
	}
	clean, changed, err := scanStoredExportBody(value, storedBase64, "", "", "", field, redact, budget)
	if redact && replaceUnscannable(err) {
		if storedBase64 {
			return redactedBase64, true, nil
		}
		return "REDACTED", true, nil
	}
	return clean, changed, err
}

func scanValue(v reflect.Value, field string, redact bool, budget *int) (reflect.Value, bool, error) {
	if !v.IsValid() {
		return v, false, nil
	}
	switch v.Kind() {
	case reflect.String:
		s, changed, err := scanExportScalar(v.String(), field, base64Field(field), redact, budget)
		if err != nil || !changed {
			return v, false, err
		}
		out := reflect.New(v.Type()).Elem()
		if v.Type() == reflect.TypeFor[json.Number]() && !json.Valid([]byte(s)) {
			return reflect.ValueOf("REDACTED"), true, nil
		}
		out.SetString(s)
		return out, true, nil
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return v, false, nil
		}
		x, changed, err := scanValue(v.Elem(), field, redact, budget)
		if err != nil || !changed {
			return v, false, err
		}
		if v.Kind() == reflect.Interface {
			if !x.Type().AssignableTo(v.Type()) {
				return v, false, unsupportedBody(field)
			}
			out := reflect.New(v.Type()).Elem()
			out.Set(x)
			return out, true, nil
		}
		if x.Type() != v.Type().Elem() {
			return v, false, unsupportedBody(field)
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(x)
		return out, true, nil
	case reflect.Struct:
		return scanExportStruct(v, field, redact, budget)
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return v, false, nil
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			var raw []byte
			if v.Kind() == reflect.Slice {
				raw = v.Bytes()
			} else {
				raw = make([]byte, v.Len())
				for i := range raw {
					raw[i] = byte(v.Index(i).Uint())
				}
			}
			s, changed, err := scanExportScalar(string(raw), field, base64Field(field), redact, budget)
			if err != nil || !changed {
				return v, false, err
			}
			out := reflect.MakeSlice(reflect.SliceOf(v.Type().Elem()), len(s), len(s))
			for i := range len(s) {
				out.Index(i).SetUint(uint64(s[i]))
			}
			if v.Kind() == reflect.Slice {
				out = out.Convert(v.Type())
			}
			return out, true, nil
		}
		out, changed := v, false
		for i := range v.Len() {
			path := fmt.Sprintf("%s[%d]", field, i)
			x, c, err := scanValue(v.Index(i), path, redact, budget)
			if err != nil {
				return v, false, err
			}
			if c {
				if !x.Type().AssignableTo(v.Type().Elem()) {
					return v, false, unsupportedBody(path)
				}
				if !changed {
					if v.Kind() == reflect.Array {
						out = reflect.New(v.Type()).Elem()
						out.Set(v)
					} else {
						out = reflect.MakeSlice(v.Type(), v.Len(), v.Len())
						reflect.Copy(out, v)
					}
				}
				out.Index(i).Set(x)
				changed = true
			}
		}
		return out, changed, nil
	case reflect.Map:
		return scanExportMap(v, field, redact, false, budget)
	}
	return v, false, nil
}

func base64Field(field string) bool {
	i := strings.LastIndexByte(field, '.')
	name, _, _ := strings.Cut(field[i+1:], "[")
	name = strings.ToLower(name)
	return strings.HasSuffix(name, "b64") || strings.HasSuffix(name, "base64")
}

func scanExportStruct(v reflect.Value, field string, redact bool, budget *int) (reflect.Value, bool, error) {
	typ := v.Type()
	out, changed := v, false
	set := func(i int, x reflect.Value) {
		if !changed {
			out = reflect.New(typ).Elem()
			out.Set(v)
			changed = true
		}
		out.Field(i).Set(x)
	}
	cassette := typ == reflect.TypeFor[CassetteResponse]()
	bodyIndex := -1
	bodyChanged, replaced := false, false
	if cassette || typ == reflect.TypeFor[HTTP]() || typ == reflect.TypeFor[Stream]() {
		body, _ := typ.FieldByName("Body")
		bodyIndex = body.Index[0]
		value := v.Field(bodyIndex).String()
		encoding := ""
		if cassette {
			encoding = v.FieldByName("BodyEncoding").String()
		}
		flagged := v.FieldByName("UnscannableEncoding").Bool()
		if value != "" || encoding != "" || flagged {
			headers := v.FieldByName("Headers").Interface().(map[string]string)
			clean, c, err := scanExportHTTPBody(value, encoding, headers, flagged, field+".body", redact, budget)
			if redact && replaceUnscannable(err) {
				clean, c, err, replaced = "REDACTED", true, nil, true
			}
			if err != nil {
				return v, false, err
			}
			if c {
				set(bodyIndex, reflect.ValueOf(clean))
				bodyChanged = true
			}
		}
	}
	for i := range v.NumField() {
		f := typ.Field(i)
		if i == bodyIndex || !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			name, _, _ = strings.Cut(f.Tag.Get("yaml"), ",")
			if name == "-" {
				continue
			}
		}
		if name == "" {
			name = f.Name
		}
		path, value := field+"."+name, v.Field(i)
		var x reflect.Value
		var c bool
		var err error
		switch {
		case exportStructuralFields[typ][f.Name]:
			var clean string
			clean, c, err = scanTextDepth(value.String(), path, redact, 0, budget)
			x = reflect.ValueOf(clean)
		case bodyIndex >= 0 && f.Name == "Headers":
			x, c, err = scanExportMap(value, path, redact, replaced, budget)
		case typ == reflect.TypeFor[WS]() && f.Name == "Messages":
			x, c, err = scanExportMessages(value, path, redact, budget)
		default:
			x, c, err = scanValue(value, path, redact, budget)
		}
		if err != nil {
			return v, false, err
		}
		if c {
			if !x.Type().AssignableTo(f.Type) {
				return v, false, unsupportedBody(path)
			}
			set(i, x)
		}
	}
	if bodyChanged {
		if replaced {
			out.FieldByName("UnscannableEncoding").SetBool(false)
			if cassette {
				out.FieldByName("BodyEncoding").SetString("")
			}
		}
		if cassette && v.FieldByName("Status").Int() == 206 {
			if !replaced {
				return v, false, unsupportedBody(field + ".body")
			}
			out.FieldByName("Status").SetInt(200)
		}
		headers := out.FieldByName("Headers")
		next := maps.Clone(headers.Interface().(map[string]string))
		for name, value := range next {
			switch strings.ToLower(name) {
			case "content-encoding", "content-length", "content-md5", "content-digest", "repr-digest", "digest", "etag":
				delete(next, name)
			case "content-type":
				if media, params, _ := mime.ParseMediaType(value); exportCompressionMedia(media) != "" {
					if decoded := exportDecodedMedia(params); decoded != "" {
						next[name] = decoded
					} else {
						delete(next, name)
					}
				}
			}
		}
		headers.Set(reflect.ValueOf(next))
	}
	return out, changed, nil
}

func scanExportHTTPBody(body, storage string, headers map[string]string, flagged bool, field string, redact bool, budget *int) (string, bool, error) {
	var contentType, encoding, transfer string
	seen := map[string]bool{}
	for name, value := range headers {
		key := strings.ToLower(name)
		value = strings.TrimSpace(value)
		switch key {
		case "content-encoding":
			encoding = value
		case "content-type":
			contentType = value
			flagged = flagged || value == ""
		case "content-transfer-encoding":
			transfer = value
		case "grpc-encoding", "transfer-encoding":
			flagged = flagged || value != "" && !strings.EqualFold(value, "identity")
		default:
			continue
		}
		flagged = flagged || seen[key]
		seen[key] = true
	}
	if flagged || storage != "" && storage != "base64" {
		return "", false, &ExportBlockedError{Kind: "unscannable_encoding", Field: field}
	}
	return scanStoredExportBody(body, storage == "base64", encoding, contentType, transfer, field, redact, budget)
}

func scanExportMessages(v reflect.Value, field string, redact bool, budget *int) (reflect.Value, bool, error) {
	out, changed := v, false
	for i := range v.Len() {
		path := fmt.Sprintf("%s[%d]", field, i)
		clean, c, err := scanExportScalar(v.Index(i).String(), path, false, redact, budget)
		if blocked, ok := err.(*ExportBlockedError); ok && redact {
			for _, pattern := range secretPatterns {
				if blocked.Kind == pattern.kind && blocked.Kind != "private_key" {
					clean, c, err = "REDACTED", true, nil
					break
				}
			}
		}
		if err != nil {
			return v, false, err
		}
		if c {
			if !changed {
				out = reflect.MakeSlice(v.Type(), v.Len(), v.Len())
				reflect.Copy(out, v)
				changed = true
			}
			out.Index(i).SetString(clean)
		}
	}
	return out, changed, nil
}

func scanExportMap(v reflect.Value, field string, redact, omitBodyHeaders bool, budget *int) (reflect.Value, bool, error) {
	if v.IsNil() {
		return v, false, nil
	}
	out, changed := v, false
	if redact {
		out = reflect.MakeMapWithSize(v.Type(), v.Len())
	}
	storedBody := false
	if v.Type().Key().Kind() == reflect.String {
		key := reflect.ValueOf("body_encoding").Convert(v.Type().Key())
		value := v.MapIndex(key)
		if value.IsValid() && value.Kind() == reflect.Interface && !value.IsNil() {
			value = value.Elem()
		}
		storedBody = value.IsValid() && value.Kind() == reflect.String && strings.EqualFold(value.String(), "base64")
	}
	iter := v.MapRange()
	for iter.Next() {
		key, value := iter.Key(), iter.Value()
		name := ""
		if key.Kind() == reflect.String {
			name = key.String()
		}
		if omitBodyHeaders {
			switch strings.ToLower(name) {
			case "content-type", "content-encoding", "grpc-encoding", "transfer-encoding", "content-transfer-encoding", "content-range":
				changed = true
				continue
			}
		}
		k, keyChanged, err := scanValue(key, field+".key", redact, budget)
		if err != nil {
			return v, false, err
		}
		if keyChanged && !redact {
			return v, false, &ExportBlockedError{Kind: "unscannable_encoding", Field: field}
		}
		var x reflect.Value
		var c bool
		if strings.HasSuffix(field, ".headers") && value.Kind() == reflect.String && name != "" {
			var clean string
			clean, c, err = scanExportHeader(name, value.String(), field, redact, budget)
			x = value
			if c {
				x = reflect.New(value.Type()).Elem()
				x.SetString(clean)
			}
		} else {
			path := field
			if strings.EqualFold(name, "Location") {
				path += ".location"
			} else if base64Field(name) || storedBody && name == "body" {
				path += ".base64"
			}
			x, c, err = scanValue(value, path, redact, budget)
		}
		if err != nil {
			return v, false, err
		}
		if redact || c {
			if !k.Type().AssignableTo(v.Type().Key()) || !x.Type().AssignableTo(v.Type().Elem()) {
				return v, false, unsupportedBody(field)
			}
			if redact {
				if out.MapIndex(k).IsValid() {
					return v, false, &ExportBlockedError{Kind: "redaction_collision", Field: field}
				}
			} else if !changed {
				out = reflect.MakeMapWithSize(v.Type(), v.Len())
				all := v.MapRange()
				for all.Next() {
					out.SetMapIndex(all.Key(), all.Value())
				}
			}
			out.SetMapIndex(k, x)
		}
		changed = changed || c || keyChanged
	}
	return out, changed, nil
}

func scanExportHeader(name, value, field string, redact bool, budget *int) (string, bool, error) {
	class, err := classifyExportBody(value, "", "", "", "", field, budget, false)
	if err == nil && (class.kind != exportCleanText || class.order != nil) {
		err = &ExportBlockedError{Kind: "unscannable_encoding", Field: field}
	}
	if redact && replaceUnscannable(err) {
		return "REDACTED", true, nil
	}
	if err != nil {
		return "", false, err
	}
	return scanHeader(name, value, field, redact, budget)
}
