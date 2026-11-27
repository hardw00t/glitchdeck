//go:build unix && (!linux || (!amd64 && !arm64))

package main

func closeInheritedRange() bool { return false }
