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
	for _, suffix := range []string{"version: 3\n", "'version': 3\n", "<<: {version: 3}\n", "# comment\ufeff\u2028---\u2028version: 3\n"} {
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
