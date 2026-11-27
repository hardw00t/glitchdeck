//go:build !unix

package main

func closeInheritedOnExec() error { return nil }
