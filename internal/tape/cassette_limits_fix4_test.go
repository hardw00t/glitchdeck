package tape

import (
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hardw00t/glitchdeck/internal/proxy"
)

func TestCassetteMatchingComplexityLimit(t *testing.T) {
	c := Cassette{Request: CassetteRequest{Method: "POST", Path: "/"}, Response: NewCassetteResponse(200, nil, nil, false)}
	upstream := (Tape{Cassettes: []Cassette{c, c}}).CassetteUpstream()
	for _, body := range []string{"[" + strings.Repeat("0,", 40000) + "0]", strings.Repeat("[", 200) + "0" + strings.Repeat("]", 200)} {
		_, err := upstream(httptest.NewRequest("POST", "http://example.com/", strings.NewReader(body)))
		var cassetteErr *proxy.CassetteError
		if !errors.As(err, &cassetteErr) || cassetteErr.Kind != "cassette_match_limit" {
			t.Fatalf("complex JSON: got %v", err)
		}
		if digest := BodySHA256([]byte(body), nil); digest != "" {
			t.Fatalf("complex JSON produced digest %q", digest)
		}
	}
	// Non-JSON bytes remain eligible for raw matching, regardless of punctuation.
	_, err := upstream(httptest.NewRequest("POST", "http://example.com/", strings.NewReader(strings.Repeat("[", 40000))))
	var cassetteErr *proxy.CassetteError
	if !errors.As(err, &cassetteErr) || cassetteErr.Kind != "cassette_ambiguous" {
		t.Fatalf("raw body: got %v", err)
	}
	raw := "[" + strings.Repeat("0,", 40000) + "\"\xff\"]"
	_, err = upstream(httptest.NewRequest("POST", "http://example.com/", strings.NewReader(raw)))
	if !errors.As(err, &cassetteErr) || cassetteErr.Kind != "cassette_ambiguous" {
		t.Fatalf("invalid UTF-8 body: got %v", err)
	}
}

func TestCassetteMatchingReservationAndConcurrency(t *testing.T) {
	c := Cassette{Request: CassetteRequest{Method: "POST", Path: "/"}, Response: NewCassetteResponse(200, nil, nil, false)}
	upstream := (Tape{Cassettes: []Cassette{c, c}}).CassetteUpstream()
	matchWork.Store(maxMatchWork)
	_, err := upstream(httptest.NewRequest("POST", "http://example.com/", strings.NewReader(`{"x":1}`)))
	matchWork.Store(0)
	var cassetteErr *proxy.CassetteError
	if !errors.As(err, &cassetteErr) || cassetteErr.Kind != "cassette_match_limit" {
		t.Fatalf("exhausted budget: got %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := upstream(httptest.NewRequest("POST", "http://example.com/", strings.NewReader(`{"x":1}`)))
			var e *proxy.CassetteError
			if !errors.As(err, &e) || e.Kind != "cassette_ambiguous" {
				t.Errorf("small match: got %v", err)
			}
		}()
	}
	wg.Wait()
	if n := matchWork.Load(); n != 0 {
		t.Fatalf("leaked reservation: %d", n)
	}
}

func TestCassetteMatchingFullSizeBody(t *testing.T) {
	body := strings.Repeat("x", maxCassetteBody)
	c := Cassette{Request: CassetteRequest{Method: "POST", Path: "/", BodySHA256: BodySHA256([]byte(body), nil)}, Response: NewCassetteResponse(200, nil, nil, false)}
	other := c
	other.Request.BodySHA256 = strings.Repeat("0", 64)
	upstream := (Tape{Cassettes: []Cassette{c, other}}).CassetteUpstream()
	resp, err := upstream(httptest.NewRequest("POST", "http://example.com/", strings.NewReader(body)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
