package mcp

import (
	"fmt"
	"os"
	"sync/atomic"
)

var diagnosticBusy atomic.Bool

// LogDiagnostic reports a diagnostic without blocking server cleanup.
func LogDiagnostic(message string) {
	if !diagnosticBusy.CompareAndSwap(false, true) {
		return
	}
	if len(message) > 512 {
		message = message[:512]
	}
	stderr := os.Stderr
	go func() {
		defer diagnosticBusy.Store(false)
		fmt.Fprintln(stderr, message)
	}()
}
