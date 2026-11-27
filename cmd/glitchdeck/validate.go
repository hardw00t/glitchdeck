package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/hardw00t/glitchdeck/internal/cli"
	"github.com/hardw00t/glitchdeck/internal/tape"
)

var validateStdin io.Reader = os.Stdin

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
	const validateUsage = "usage: glitchdeck validate [--json] <file...>"
	if showCommandHelp(f, args, validateUsage) {
		return 0
	}
	flags, files := cli.SplitArgs(args)
	parseErr := f.Parse(flags)
	if parseErr == nil {
		if len(files) == 0 {
			parseErr = errors.New(validateUsage)
		} else if i := slices.Index(files, "-"); i >= 0 && slices.Contains(files[i+1:], "-") {
			parseErr = errors.New("stdin (-) may be specified only once")
		}
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
			t, err := readValidationTape(path)
			result := validationResult{File: path, OK: err == nil, Version: t.Version, Name: t.Name, Rules: len(t.Rules)}
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

func readValidationTape(path string) (tape.Tape, error) {
	if path == "-" {
		const limit = 1 << 20
		data, err := io.ReadAll(io.LimitReader(validateStdin, limit+1))
		if len(data) > limit {
			return tape.Tape{}, errors.New("stdin exceeds 1 MiB limit")
		}
		if err != nil {
			return tape.Tape{}, err
		}
		return tape.Decode(bytes.NewReader(data))
	}
	file, err := os.Open(path)
	if err != nil {
		return tape.Tape{}, err
	}
	defer file.Close()
	return tape.Decode(file)
}
