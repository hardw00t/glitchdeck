package tape

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/proxy"
)

type countingReader struct {
	r io.Reader
	n int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += n
	return n, err
}

func TestLeadingV3StopsReadingAtLimit(t *testing.T) {
	input := "\ufeff# comment\n---\nversion: 3 # cassette\nname: " + strings.Repeat("x", 2*maxTapeInput)
	r := &countingReader{r: strings.NewReader(input)}
	if _, err := Decode(r); err == nil {
		t.Fatal("oversized v3 accepted")
	}
	if r.n > maxTapeInput+1 {
		t.Fatalf("read %d bytes past bounded preflight", r.n)
	}
}

func TestReorderedV3StopsReadingAtRawLimit(t *testing.T) {
	r := &countingReader{r: io.MultiReader(strings.NewReader("name: reordered\nversion: 3\npadding: "), strings.NewReader(strings.Repeat("x", 65<<20)))}
	if _, err := Decode(r); err == nil {
		t.Fatal("oversized reordered v3 accepted")
	}
	if r.n > (64<<20)+1 {
		t.Fatalf("read %d bytes, exceeding the raw input bound", r.n)
	}
}

func TestReorderedV3JustOverLimitRejectedBeforeParsing(t *testing.T) {
	input := "name: reordered\nversion: 3\n" + strings.Repeat("x", maxTapeInput)
	r := &countingReader{r: strings.NewReader(input)}
	_, err := Decode(r)
	if err == nil || err.Error() != "tape exceeds input limit" || r.n > maxTapeInput+1 {
		t.Fatalf("error=%v, bytes read=%d", err, r.n)
	}
}

func TestOversizedLegacyWithAmbiguousVersionRejected(t *testing.T) {
	for _, suffix := range []string{"version: 3\n", "'version': 3\n"} {
		input := "version: 1\n" + suffix + "name: " + strings.Repeat("x", maxTapeInput)
		_, err := Decode(strings.NewReader(input))
		if err == nil || err.Error() != "tape exceeds input limit" {
			t.Fatalf("suffix %q: %v", suffix, err)
		}
	}
}

func TestLegacyLargeInputAndV3Limit(t *testing.T) {
	padding := strings.Repeat("x", maxTapeInput)
	for _, version := range []int{1, 2, 3} {
		input := fmt.Sprintf("version: %d\nname: %s\ntarget: demo\n", version, padding)
		_, err := Decode(strings.NewReader(input))
		if version < 3 && err != nil {
			t.Errorf("version %d: %v", version, err)
		}
		if version == 3 && err == nil {
			t.Error("oversized v3 accepted")
		}
	}
}

func TestLargeLegacyUnfinishedKeyAndIndentlessSequence(t *testing.T) {
	for _, version := range []string{"1", "2"} {
		prefix := "version: " + version + "\n#"
		padding := strings.Repeat("x", maxTapeInput-3-len(prefix)-1)
		doc := prefix + padding + "\nname: legacy\n"
		if _, err := Decode(strings.NewReader(doc)); err != nil {
			t.Fatalf("version %s unfinished key: %v", version, err)
		}
		doc = "version: " + version + "\n#" + strings.Repeat("x", maxTapeInput) + "\nscript:\n- http:\n    method: GET\n    path: /\n"
		if _, err := Decode(strings.NewReader(doc)); err != nil {
			t.Fatalf("version %s indentless sequence: %v", version, err)
		}
	}
}

func TestLargeLegacyReorderedAndQuotedVersion(t *testing.T) {
	for _, prefix := range []string{"name: legacy\nversion: 1\n", "'version': 2\nname: legacy\n", "\"version\": 1\nname: legacy\n", "version: !!int '2'\n"} {
		doc := prefix + "#" + strings.Repeat("x", maxTapeInput) + "\n"
		if _, err := Decode(strings.NewReader(doc)); err != nil {
			t.Fatalf("prefix %q: %v", prefix, err)
		}
	}
	doc := "#" + strings.Repeat("x", maxTapeInput) + "\nversion: 2\n"
	if _, err := Decode(strings.NewReader(doc)); err != nil {
		t.Fatalf("version after first window: %v", err)
	}
}

func TestLargeLegacyVersionFromMerge(t *testing.T) {
	doc := "<<: {version: 2}\n#" + strings.Repeat("x", maxTapeInput) + "\n"
	if _, err := Decode(strings.NewReader(doc)); err != nil {
		t.Fatal(err)
	}
}

func TestLargeLegacyFlowContainsVersionKey(t *testing.T) {
	doc := "version: 1\nassertions: [{name: check, http_get: /, json_eq: {a: 1,\nversion: 3}}]\n#" + strings.Repeat("x", maxTapeInput) + "\n"
	loaded, err := Decode(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Assertions[0].JSONEq["version"]; got != 3 {
		t.Fatalf("nested version = %v", got)
	}
}

func TestMergeCycleRejected(t *testing.T) {
	_, err := Decode(strings.NewReader("version: 1\n<<: &loop {<<: *loop}\n"))
	if err == nil {
		t.Fatal("cyclic merge accepted")
	}
}

func TestNestedMergePreservesLegacyValidation(t *testing.T) {
	input := "version: 1\nscript:\n  - <<: &outer\n      <<: &inner\n        http: {path: /, url: 'http://example.com/'}\n"
	if _, err := Decode(strings.NewReader(input)); err == nil {
		t.Fatal("nested merged v2 key accepted in v1")
	}
}

func TestNestedMergeLoadsVersion(t *testing.T) {
	input := "<<: {<<: {version: 2, target: demo}}\nname: merged\n"
	doc, err := Decode(strings.NewReader(input))
	if err != nil || doc.Version != 2 || doc.Target != "demo" {
		t.Fatalf("doc=%+v err=%v", doc, err)
	}
}

func TestReplayPreservesDeadlineAndCassetteFailure(t *testing.T) {
	doc := Tape{
		Version: 3, Target: "demo",
		Cassettes: []Cassette{{Request: CassetteRequest{Method: "GET", Path: "/present"}, Response: CassetteResponse{Status: 200}}},
		Script:    []Step{{HTTP: &HTTP{Path: "/missing"}}, {SleepMS: 60000}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, report, err := RunReplay(ctx, doc, "", "", false)
	var cassette *proxy.CassetteError
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(report.CassetteError, &cassette) {
		t.Fatalf("run error=%v, cassette error=%v", err, report.CassetteError)
	}
}
