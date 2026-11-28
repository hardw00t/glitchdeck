package tape

import (
	"errors"
	"strings"
	"testing"
)

func TestScannerFailClosedRepresentations(t *testing.T) {
	secret := "sk-ant-" + strings.Repeat("z", 24)
	cases := []struct{ name, body, contentType string }{
		{"sse-comment-pem", ": -----BEGIN " + "PRIVATE KEY-----\n: sensitive-payload\n: -----END " + "PRIVATE KEY-----\n\n", "text/event-stream"},
		{"unfinished-json", `{"key":"sk-ant-\u007a` + strings.Repeat("z", 23), "application/json"},
		{"message", "Content-Transfer-Encoding: base64\r\n\r\nc2VjcmV0", "message/rfc822"},
		{"digest", "--x\r\n\r\nContent-Transfer-Encoding: base64\r\n\r\nc2VjcmV0\r\n--x--\r\n", "multipart/digest; boundary=x"},
		{"mime-encoded-word", "--x\r\nContent-Description: =?UTF-8?B?c2VjcmV0?=\r\n\r\nok\r\n--x--\r\n", "multipart/mixed; boundary=x"},
		{"mime-location", "--x\r\nContent-Location: /?token=Bearer+eyJabc\r\n\r\nok\r\n--x--\r\n", "multipart/mixed; boundary=x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, redact := range []bool{false, true} {
				out, _, err := scanBodyText(tc.body, tc.contentType, "$.body", redact)
				if err == nil && (strings.Contains(out, "sensitive-payload") || strings.Contains(out, secret) || tc.name != "sse-comment-pem") {
					t.Fatalf("accepted uninspectable content, redact=%v", redact)
				}
				if err != nil {
					var blocked *ExportBlockedError
					if !errors.As(err, &blocked) || blocked.Field == "" {
						t.Fatalf("unsafe error: %v", err)
					}
				}
			}
		})
	}
}

func TestScannerHTTPHeadersUseMIMEPolicy(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"Content-Location", "/?token=Bearer+eyJabc"},
		{"Content-Disposition", "attachment; filename*=UTF-8''c2VjcmV0"},
		{"Content-Description", "=?UTF-8?B?c2VjcmV0?="},
		{"X-Custom", "attachment; name*=UTF-8''c2VjcmV0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := Tape{Script: []Step{{HTTP: &HTTP{Headers: map[string]string{tc.name: tc.value}}}}}
			for _, redact := range []bool{false, true} {
				out, err := PrepareExport(input, redact)
				if err == nil && (tc.name != "Content-Location" || strings.Contains(out.Script[0].HTTP.Headers[tc.name], "eyJabc")) {
					t.Fatalf("accepted %s, redact=%v", tc.name, redact)
				}
			}
		})
	}
}

func TestScannerFormDetectionAllocations(t *testing.T) {
	long := strings.Repeat("a&", 100000)
	result := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _ = scanText(long, "$.form", false)
		}
	})
	if got := result.AllocedBytesPerOp(); got > 100000 {
		t.Fatalf("detection allocated %d bytes for separator-heavy form", got)
	}
}

func TestScannerFormReconstructionUsesSharedBudget(t *testing.T) {
	form := "safe=ok&secret=sk-ant-abc"
	budget := 2*len(form) - 1
	if _, _, err := scanTextDepth(form, "$.form", true, 0, &budget); err == nil {
		t.Fatal("redaction exceeded reconstruction budget")
	}
	budget = 2 * len(form)
	out, changed, err := scanTextDepth(form, "$.form", true, 0, &budget)
	if err != nil || !changed || out != "safe=ok&secret=REDACTED" || budget != 0 {
		t.Fatalf("redaction = %q, changed=%v, budget=%d, err=%v", out, changed, budget, err)
	}
}

func TestScannerSSEAndHeaderAllocations(t *testing.T) {
	sseBody := strings.Repeat("\n", 100000)
	header := strings.Repeat(";", 100000)
	for _, tc := range []struct {
		name string
		run  func()
	}{
		{"sse", func() {
			_, _, _ = scanBodyText(sseBody, "text/event-stream", "$.body", false)
		}},
		{"header", func() {
			budget := 64 << 20
			_, _, _ = scanHeader("X-Test", header, "$.headers", false, &budget)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := testing.Benchmark(func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					tc.run()
				}
			})
			if got := result.AllocedBytesPerOp(); got > 2<<20 {
				t.Fatalf("allocated %d bytes for separator-heavy input", got)
			}
		})
	}
}

func TestScannerSSEBufferBudget(t *testing.T) {
	body := strings.Repeat("\n", 1000)
	budget := 1000
	if _, _, err := scanContentBudget(body, "text/event-stream", "$.body", false, 0, &budget); err == nil {
		t.Fatal("SSE buffers exceeded work budget")
	}
}
