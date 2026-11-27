package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/hardw00t/glitchdeck/internal/cli"
	"github.com/hardw00t/glitchdeck/internal/tape"
)

type validationResult struct {
	File    string `json:"file"`
	OK      bool   `json:"ok"`
	Version int    `json:"version"`
	Name    string `json:"name"`
	Rules   int    `json:"rules"`
	Error   string `json:"error,omitempty"`
}

func validateCommand(args []string) int {
	f := flag.NewFlagSet("validate", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	asJSON := f.Bool("json", false, "JSON output")
	flags, files := cli.SplitArgs(args)
	parseErr := f.Parse(flags)
	if parseErr == nil && len(files) == 0 {
		parseErr = errors.New("usage: glitchdeck validate [--json] <file...>")
	}
	results := make([]validationResult, 0, len(files))
	ok := parseErr == nil
	if parseErr != nil {
		if cli.JSONRequested(args) {
			*asJSON = true
			cli.Error(os.Stderr, "usage", parseErr, 2)
		} else {
			fmt.Fprintln(os.Stderr, parseErr)
		}
	} else {
		for _, path := range files {
			result := validationResult{File: path}
			file, err := os.Open(path)
			if err == nil {
				t, decodeErr := tape.Decode(file)
				file.Close()
				result.Version, result.Name, result.Rules = t.Version, t.Name, len(t.Rules)
				err = decodeErr
			}
			result.OK = err == nil
			if err != nil {
				ok = false
				result.Error = err.Error()
			}
			if *asJSON {
				results = append(results, result)
			} else if result.OK {
				fmt.Println("OK", path)
			} else {
				fmt.Printf("INVALID %s: %s\n", path, result.Error)
			}
		}
	}
	if *asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
			"schema": "glitchdeck.v2", "command": "validate", "ok": ok, "results": results,
		}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	if !ok {
		return 2
	}
	return 0
}
