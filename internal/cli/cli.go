package cli

import (
	"encoding/json"
	"io"
	"net"
	"slices"
	"strings"
)

func SplitArgs(args []string, valueFlags ...string) (flags, positional []string) {
	for len(args) != 0 {
		arg := args[0]
		args = args[1:]
		if arg == "--" {
			return flags, append(positional, args...)
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}
		flags = append(flags, arg)
		name, _, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if !hasValue && slices.Contains(valueFlags, name) && len(args) != 0 {
			flags = append(flags, args[0])
			args = args[1:]
		}
	}
	return flags, positional
}

func JSONRequested(args []string) bool {
	var requested bool
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		switch strings.TrimLeft(arg, "-") {
		case "json", "json=true":
			requested = strings.HasPrefix(arg, "-")
		case "json=false":
			requested = false
		}
	}
	return requested
}

func Error(out io.Writer, code string, err error, exit int) {
	_ = json.NewEncoder(out).Encode(map[string]any{"type": "error", "code": code, "message": err.Error(), "exit_code": exit})
}

func Loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	return err == nil && (strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback())
}
