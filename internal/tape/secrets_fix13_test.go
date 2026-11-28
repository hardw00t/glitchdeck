package tape

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestFix13StructuralControls(t *testing.T) {
	for _, method := range []string{"A\x00B", "A\rB", "A\u0085B", "A\xffB"} {
		in := Tape{Script: []Step{{HTTP: &HTTP{Method: method}}}}
		if _, err := PrepareExport(in, false); err == nil {
			t.Error("ordinary export accepted an invalid method")
		}
		out, err := PrepareExport(in, true)
		if err == nil && out.Script[0].HTTP.Method == method {
			t.Error("redaction retained an invalid method")
		}
	}
}

func TestFix13HeaderXMLEntities(t *testing.T) {
	in := Tape{Script: []Step{{HTTP: &HTTP{Headers: map[string]string{"X-Note": `<!DOCTYPE x [<!ENTITY label "ordinary">]><x/>`}}}}}
	var blocked *ExportBlockedError
	if _, err := PrepareExport(in, false); !errors.As(err, &blocked) || blocked.Kind != "unscannable_xml_entity" {
		t.Errorf("expected XML entity block, got %v", err)
	}
	out, err := PrepareExport(in, true)
	if err != nil || !out.Redacted || out.Script[0].HTTP.Headers["X-Note"] != "REDACTED" {
		t.Fatalf("expected XML header replacement, got %v", err)
	}
}

func TestFix13Base64Maps(t *testing.T) {
	const encoded = "b3JkaW5hcnk="
	for _, name := range []string{"BoDy", "MeSsAgE_B64", "pointerB64", "custom_b64"} {
		for _, payload := range []any{
			map[string]any{"BoDy_EnCoDiNg": "BaSe64", name: encoded},
			map[any]any{"BoDy_EnCoDiNg": "BaSe64", name: encoded},
		} {
			in := Tape{Assertions: []Assertion{{JSONEq: map[string]any{"data": payload}}}}
			var blocked *ExportBlockedError
			if _, err := PrepareExport(in, false); !errors.As(err, &blocked) || blocked.Kind != "unscannable_encoding" {
				t.Errorf("%T %s: expected base64 block, got %v", payload, name, err)
			}
			out, err := PrepareExport(in, true)
			if err != nil || !out.Redacted {
				t.Fatalf("%T %s: expected redaction, got %v", payload, name, err)
			}
			var yaml bytes.Buffer
			if err := Encode(&yaml, out); err != nil || strings.Contains(yaml.String(), encoded) {
				t.Fatalf("%T %s: unsafe serialization: %v", payload, name, err)
			}
		}
	}
}

func TestFix13Base64MarkerInput(t *testing.T) {
	const marker = "UkVEQUNURUQ="
	for _, redacted := range []bool{false, true} {
		in := Tape{Redacted: redacted, Script: []Step{{GRPC: &GRPC{MessageB64: marker}}}}
		var blocked *ExportBlockedError
		if _, err := PrepareExport(in, false); !errors.As(err, &blocked) || blocked.Kind != "unscannable_encoding" {
			t.Errorf("input marker was trusted: %v", err)
		}
		out, err := PrepareExport(in, true)
		if err != nil || !out.Redacted || out.Script[0].GRPC.MessageB64 != marker {
			t.Fatalf("expected export-generated marker, got %v", err)
		}
		if err := Encode(&bytes.Buffer{}, out); err != nil {
			t.Fatalf("export-generated marker refused: %v", err)
		}
	}
}

func TestFix13OpaqueValue(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("Z", 24)
	addr := netip.IPv6Loopback().WithZone(secret)
	in := Tape{Assertions: []Assertion{{JSONEq: map[string]any{"ip": addr}}}}
	var out bytes.Buffer
	if err := Encode(&out, in); err == nil || strings.Contains(err.Error(), secret) || out.Len() != 0 {
		t.Fatalf("opaque value was not safely refused: %v", err)
	}
}

func TestFix13ComparableMapKeys(t *testing.T) {
	in := Tape{Assertions: []Assertion{{JSONEq: map[string]any{"map": map[any]any{[1]byte{0}: "value"}}}}}
	out, err := PrepareExport(in, true)
	if err == nil && !out.Redacted {
		t.Fatal("unsafe key was retained")
	}
}

func TestFix13UnsupportedDynamicKinds(t *testing.T) {
	for _, value := range []any{make(chan int), func() {}} {
		func() {
			defer func() {
				if recover() != nil {
					t.Errorf("%T reached the encoder and panicked", value)
				}
			}()
			in := Tape{Assertions: []Assertion{{JSONEq: map[string]any{"value": value}}}}
			var out bytes.Buffer
			if err := Encode(&out, in); err == nil || out.Len() != 0 {
				t.Errorf("%T was not refused: %v", value, err)
			}
		}()
	}
}

func TestFix13EmptyEncodedHTTPBody(t *testing.T) {
	for _, encoding := range []string{"gzip", "deflate", "br"} {
		in := Tape{Script: []Step{{HTTP: &HTTP{Headers: map[string]string{"CoNtEnT-EnCoDiNg": encoding}}}}}
		for _, redact := range []bool{false, true} {
			out, err := PrepareExport(in, redact)
			if err == nil && out.Script[0].HTTP.Headers["CoNtEnT-EnCoDiNg"] != "" {
				t.Errorf("redact=%v: retained stale %s encoding", redact, encoding)
			}
		}
	}
}
