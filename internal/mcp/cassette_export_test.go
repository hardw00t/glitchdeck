package mcp

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/tape"
)

func TestExportBlocksSecretsBeforeFormatDowngrade(t *testing.T) {
	secret := "sk-" + "ant-" + strings.Repeat("z", 24)
	s, proxyURL := exportTestServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(secret)) })
	req, _ := http.NewRequest("GET", proxyURL+"/", nil)
	exportTestRequest(t, req)
	for _, format := range []string{"v1", "v2", "v3"} {
		result, _ := s.call("tape_export", []byte(`{"name":"capture","format":"`+format+`"}`))
		err, ok := result["error"].(map[string]string)
		if !ok || err["code"] != "EXPORT_BLOCKED" || strings.Contains(err["message"], secret) {
			t.Fatalf("%s: %v", format, result)
		}
	}
	result, _ := s.call("tape_export", []byte(`{"name":"capture","redact_secrets":true}`))
	data, ok := result["yaml"].(string)
	if !ok || strings.Contains(data, secret) || !strings.Contains(data, "REDACTED") {
		t.Fatalf("redaction: %v", result)
	}
}

func TestInlineExportTrimsOldestCassettesWhenMetadataExceedsLimit(t *testing.T) {
	doc := tape.Tape{Version: 3, Script: []tape.Step{{HTTP: &tape.HTTP{Method: "GET", Path: "/kept"}}}, DroppedEntries: 2}
	for i := range 256 {
		doc.Cassettes = append(doc.Cassettes, tape.Cassette{
			Request:  tape.CassetteRequest{Method: "GET", Path: fmt.Sprintf("/%03d-%s", i, strings.Repeat("x", 100)), BodySHA256: strings.Repeat("a", 64)},
			Response: tape.CassetteResponse{Status: 200},
		})
	}
	data, err := encodeExport(&doc, 8192)
	if err != nil || len(data) > 8192 || len(doc.Cassettes) == 0 || len(doc.Cassettes) == 256 || !strings.HasPrefix(doc.Cassettes[0].Request.Path, fmt.Sprintf("/%03d-", 256-len(doc.Cassettes))) || len(doc.Script) != 1 || doc.Script[0].HTTP.Path != "/kept" || !doc.Incomplete || !doc.Truncated || doc.DroppedEntries != 2 {
		t.Fatalf("bounded export: bytes=%d cassettes=%d tape=%+v err=%v", len(data), len(doc.Cassettes), doc, err)
	}
}

func TestLegacyForwardExportWarning(t *testing.T) {
	doc := tape.Tape{Version: 3, Script: []tape.Step{{HTTP: &tape.HTTP{Method: "GET", URL: "https://example.com/path"}}}}
	markLegacyForwardIncomplete(&doc)
	if !doc.Incomplete || !strings.Contains(doc.IncompleteReason, "authorization") {
		t.Fatalf("missing legacy warning: %+v", doc)
	}
}

func TestExportRedactsNameInEntireResult(t *testing.T) {
	secret := "sk-" + "ant-" + strings.Repeat("z", 24)
	s, _ := exportTestServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	result, _ := s.call("tape_export", []byte(`{"name":"`+secret+`","redact_secrets":true}`))
	b, err := json.Marshal(result)
	if err != nil || strings.Contains(string(b), secret) || !strings.Contains(string(b), "REDACTED") {
		t.Fatalf("unsafe result: %s %v", b, err)
	}
}

func TestInlineExportDoesNotSplitCompressedBody(t *testing.T) {
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	var state uint32 = 1
	raw := make([]byte, 70000)
	for i := range raw {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		raw[i] = byte(state)
	}
	_, _ = w.Write(raw)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	doc := tape.Tape{Version: 2, Script: []tape.Step{{HTTP: &tape.HTTP{Method: "POST", Path: "/", Headers: map[string]string{"Content-Encoding": "gzip"}, Body: compressed.String()}}}}
	data, err := encodeExport(&doc, 8192)
	if err != nil || len(data) > 8192 || doc.Script[0].HTTP.Body != "" {
		t.Fatalf("compressed body not omitted intact: size=%d err=%v", len(data), err)
	}
}
