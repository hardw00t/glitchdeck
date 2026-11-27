package main

import "testing"

func TestExecRejectsPositionalBeforeSeparator(t *testing.T) {
	if got := execCommand([]string{"unexpected", "--tape", "missing", "--", "echo"}); got != 2 {
		t.Fatalf("expected usage exit 2, got %d", got)
	}
}
