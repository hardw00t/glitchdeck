package main

import "testing"

func TestTapeExitCodes(t *testing.T) {
	for _, tc := range []struct {
		file string
		want int
	}{
		{"checkout-dup-webhook.tape.yaml", 1},
		{"clean.tape.yaml", 0},
		{"missing.tape.yaml", 2},
	} {
		t.Run(tc.file, func(t *testing.T) {
			if got := run([]string{"test", "../../examples/" + tc.file, "--timeout", "5s"}); got != tc.want {
				t.Fatalf("exit = %d, want %d", got, tc.want)
			}
		})
	}
}
