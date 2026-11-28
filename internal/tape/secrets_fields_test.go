package tape

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/fault"
)

func TestExportRuleBodyPaths(t *testing.T) {
	for _, change := range []bool{false, true} {
		t.Run(fmt.Sprintf("config_change=%v", change), func(t *testing.T) {
			rule := fault.Rule{ID: "limit", Enabled: true, Fault: fault.Fault{Type: "rate-limit", Params: map[string]any{"body": "ordinary\x00binary"}}}
			in := Tape{Version: 2, Target: "demo"}
			if change {
				in.ConfigChanges = []ConfigChange{{BeforeSeq: 1, Rules: []fault.Rule{rule}}}
			} else {
				in.Rules = []fault.Rule{rule}
			}
			_, err := PrepareExport(in, false)
			var blocked *ExportBlockedError
			if !errors.As(err, &blocked) || blocked.Kind != "unscannable_encoding" {
				t.Fatalf("expected encoding block, got %v", err)
			}
			out, err := PrepareExport(in, true)
			if err != nil || !out.Redacted {
				t.Fatalf("redaction: redacted=%v err=%v", out.Redacted, err)
			}
			var encoded bytes.Buffer
			if err := Encode(&encoded, out); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encoded.Bytes(), []byte("ordinary")) {
				t.Fatal("export retained original body")
			}
			decoded, err := Decode(&encoded)
			if err != nil {
				t.Fatalf("redacted tape failed validation: %v", err)
			}
			rules := decoded.Rules
			if change {
				rules = decoded.ConfigChanges[0].Rules
			}
			if rules[0].Fault.Params["body"] != "REDACTED" || !decoded.Redacted {
				t.Fatalf("unexpected decoded redaction: %#v", rules[0].Fault.Params)
			}
		})
	}
}

func TestExportNestedInterfaceValues(t *testing.T) {
	for _, change := range []bool{false, true} {
		for _, binary := range []bool{false, true} {
			t.Run(fmt.Sprintf("config_change=%v/bytes=%v", change, binary), func(t *testing.T) {
				var value any = "unsafe\x00value"
				if binary {
					value = []byte("unsafe\x00value")
				}
				rule := fault.Rule{Fault: fault.Fault{Params: map[string]any{"nested": []any{map[string]any{"value": value}}}}}
				in := Tape{}
				if change {
					in.ConfigChanges = []ConfigChange{{Rules: []fault.Rule{rule}}}
				} else {
					in.Rules = []fault.Rule{rule}
				}
				if _, err := PrepareExport(in, false); err == nil {
					t.Fatal("accepted nested binary content")
				}
				out, err := PrepareExport(in, true)
				if err != nil || !out.Redacted {
					t.Fatalf("redaction: redacted=%v err=%v", out.Redacted, err)
				}
				rules := out.Rules
				if change {
					rules = out.ConfigChanges[0].Rules
				}
				got := rules[0].Fault.Params["nested"].([]any)[0].(map[string]any)["value"]
				if fmt.Sprint(got) != "REDACTED" && !reflect.DeepEqual(got, []byte("REDACTED")) {
					t.Fatalf("nested redaction = %#v", got)
				}
			})
		}
	}
}

func TestExportGRPCStoredBase64Repeated(t *testing.T) {
	in := Tape{Version: 2, Target: "demo", Script: []Step{{GRPC: &GRPC{Path: "/service/method", Proto: "h2c", MessageB64: "b3JkaW5hcnk="}}}}
	_, err := PrepareExport(in, false)
	var blocked *ExportBlockedError
	if !errors.As(err, &blocked) || blocked.Kind != "unscannable_encoding" {
		t.Fatalf("expected stored-base64 block, got %v", err)
	}
	out, err := PrepareExport(in, true)
	if err != nil || !out.Redacted || out.Script[0].GRPC.MessageB64 != "UkVEQUNURUQ=" {
		t.Fatalf("first redaction: %#v, %v", out, err)
	}
	again, err := PrepareExport(out, true)
	if err != nil || !again.Redacted || again.Script[0].GRPC.MessageB64 != "UkVEQUNURUQ=" {
		t.Fatalf("repeated redaction: %#v, %v", again, err)
	}
	var encoded bytes.Buffer
	if err := Encode(&encoded, again); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded.String(), "b3JkaW5hcnk=") {
		t.Fatal("original base64 retained")
	}
	decoded, err := Decode(&encoded)
	if err != nil || decoded.Script[0].GRPC.MessageB64 != "UkVEQUNURUQ=" {
		t.Fatalf("decode redacted grpc: %#v, %v", decoded, err)
	}
}

func TestExportAssertionNestedValues(t *testing.T) {
	for _, value := range []any{"unsafe\x00value", []byte("unsafe\x00value")} {
		in := Tape{Assertions: []Assertion{{JSONEq: map[string]any{"nested": []any{map[string]any{"value": value}}}}}}
		if _, err := PrepareExport(in, false); err == nil {
			t.Fatal("accepted nested assertion binary")
		}
		out, err := PrepareExport(in, true)
		if err != nil || !out.Redacted {
			t.Fatalf("redaction: redacted=%v err=%v", out.Redacted, err)
		}
		got := out.Assertions[0].JSONEq["nested"].([]any)[0].(map[string]any)["value"]
		if fmt.Sprint(got) != "REDACTED" && !reflect.DeepEqual(got, []byte("REDACTED")) {
			t.Fatalf("nested redaction = %#v", got)
		}
	}
}

func TestExportAssertionStringArray(t *testing.T) {
	in := Tape{Assertions: []Assertion{{JSONEq: map[string]any{"array": [2]string{"safe", "unsafe\x00value"}}}}}
	if _, err := PrepareExport(in, false); err == nil {
		t.Fatal("accepted binary content inside string array")
	}
	out, err := PrepareExport(in, true)
	if err != nil || !out.Redacted {
		t.Fatalf("redaction: redacted=%v err=%v", out.Redacted, err)
	}
	if got := out.Assertions[0].JSONEq["array"]; got != ([2]string{"safe", "REDACTED"}) {
		t.Fatalf("array redaction = %#v", got)
	}
}

// Every field capable of carrying text or dynamically typed data needs a reviewed export decision.
func TestExportFieldInventory(t *testing.T) {
	decisions := map[reflect.Type]string{
		reflect.TypeOf(Tape{}):             "Name Target IncompleteReason UpstreamAllow TLSPassthrough IgnoreJSONPaths",
		reflect.TypeOf(Step{}):             "Name",
		reflect.TypeOf(HTTP{}):             "Path Headers Body URL",
		reflect.TypeOf(WS{}):               "Path Messages",
		reflect.TypeOf(Stream{}):           "Path URL Headers Body",
		reflect.TypeOf(GRPC{}):             "Path URL MessageB64",
		reflect.TypeOf(Assertion{}):        "Name HTTPGet JSONEq StreamStep GRPCStep",
		reflect.TypeOf(Expect{}):           "ChildExit",
		reflect.TypeOf(FaultExpect{}):      "Rule",
		reflect.TypeOf(SSEExpect{}):        "End Terminal",
		reflect.TypeOf(CassetteRequest{}):  "Path Host BodySHA256",
		reflect.TypeOf(CassetteResponse{}): "Headers Body BodyEncoding",
		reflect.TypeOf(fault.Rule{}):       "ID",
		reflect.TypeOf(fault.Match{}):      "Method PathPrefix Host Scheme Proto",
		reflect.TypeOf(fault.Fault{}):      "Type Params",
	}
	structural := map[reflect.Type]string{
		reflect.TypeOf(HTTP{}):            "Method Proto",
		reflect.TypeOf(Stream{}):          "Method Proto",
		reflect.TypeOf(GRPC{}):            "Proto",
		reflect.TypeOf(CassetteRequest{}): "Method",
	}
	expectedStructural := map[reflect.Type]map[string]bool{}
	for typ, fields := range structural {
		expectedStructural[typ] = map[string]bool{}
		for _, name := range strings.Fields(fields) {
			expectedStructural[typ][name] = true
		}
	}
	if !reflect.DeepEqual(exportStructuralFields, expectedStructural) {
		t.Errorf("structural export decisions differ from production: %#v", exportStructuralFields)
	}
	seen := map[reflect.Type]bool{}
	var visit func(reflect.Type)
	var textCarrier func(reflect.Type) bool
	textCarrier = func(typ reflect.Type) bool {
		switch typ.Kind() {
		case reflect.String, reflect.Interface:
			return true
		case reflect.Ptr, reflect.Array, reflect.Slice:
			return typ.Kind() != reflect.Ptr && typ.Elem().Kind() == reflect.Uint8 || textCarrier(typ.Elem())
		case reflect.Map:
			return textCarrier(typ.Key()) || textCarrier(typ.Elem())
		}
		return false
	}
	visit = func(typ reflect.Type) {
		switch typ.Kind() {
		case reflect.Ptr, reflect.Array, reflect.Slice:
			visit(typ.Elem())
		case reflect.Map:
			visit(typ.Key())
			visit(typ.Elem())
		case reflect.Struct:
			if seen[typ] {
				return
			}
			seen[typ] = true
			listed := map[string]bool{}
			for _, name := range strings.Fields(decisions[typ]) {
				listed[name] = true
			}
			for _, name := range strings.Fields(structural[typ]) {
				if listed[name] {
					t.Errorf("%v.%s has conflicting export decisions", typ, name)
				}
				listed[name] = true
			}
			for i := range typ.NumField() {
				field := typ.Field(i)
				if !field.IsExported() {
					continue
				}
				if textCarrier(field.Type) {
					if !listed[field.Name] {
						t.Errorf("%v.%s needs an explicit export decision", typ, field.Name)
					}
					delete(listed, field.Name)
				}
				visit(field.Type)
			}
			for name := range listed {
				t.Errorf("stale export decision %v.%s", typ, name)
			}
		}
	}
	visit(reflect.TypeOf(Tape{}))
}
