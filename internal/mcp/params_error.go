package mcp

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

type paramError struct {
	Tool      string   `json:"tool,omitempty"`
	Field     string   `json:"field,omitempty"`
	Reason    string   `json:"reason"`
	Fields    []string `json:"fields,omitempty"`
	Expected  string   `json:"expected,omitempty"`
	Allowed   []string `json:"allowed,omitempty"`
	Minimum   *int     `json:"minimum,omitempty"`
	Maximum   *int     `json:"maximum,omitempty"`
	MinLength *int     `json:"minLength,omitempty"`
	MaxLength *int     `json:"maxLength,omitempty"`
	MinItems  *int     `json:"minItems,omitempty"`
	MaxItems  *int     `json:"maxItems,omitempty"`
}

func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || r == utf8.RuneError {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > 64 {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (e *paramError) message() string {
	msg := "Invalid params"
	switch e.Reason {
	case "unknown_tool":
		msg += ": unknown tool"
	case "unknown_field":
		msg += ": unknown field"
	case "required":
		msg += ": " + e.Field + " is required"
	case "type_mismatch":
		msg += ": " + e.Field + " must be " + e.Expected
	case "out_of_range":
		msg += ": " + e.Field + " must be an integer"
		if e.Minimum != nil && e.Maximum != nil {
			msg += fmt.Sprintf(" between %d and %d", *e.Minimum, *e.Maximum)
		} else if e.Minimum != nil {
			msg += fmt.Sprintf(" at least %d", *e.Minimum)
		} else if e.Maximum != nil {
			msg += fmt.Sprintf(" at most %d", *e.Maximum)
		}
	case "not_in_enum":
		msg += ": " + e.Field + " must be an allowed value"
	case "too_long":
		msg += ": " + e.Field + " is too long"
	case "too_short":
		msg += ": " + e.Field + " is too short"
	case "not_integer":
		msg += ": " + e.Field + " must be an integer"
	case "mutually_exclusive":
		msg += ": supply exactly one of tape_path or tape_yaml"
	case "invalid_value":
		msg += ": " + e.Field + " has an invalid value"
	case "not_batchable":
		msg += ": tool cannot be called in a batch"
	case "malformed":
		msg += ": malformed request"
	}
	if len(msg) > 256 {
		msg = msg[:256]
		for !utf8.ValidString(msg) {
			msg = msg[:len(msg)-1]
		}
	}
	return msg
}
