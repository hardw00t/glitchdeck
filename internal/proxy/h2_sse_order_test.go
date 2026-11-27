package proxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/h2tap"
	"golang.org/x/net/http2/hpack"
)

func TestH2SSEFinalFrameBeforeReset(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		params            map[string]any
	}{
		{"inject_error", "data: {\"n\":1}\n\n", `"error"`, map[string]any{"action": "inject_error", "provider": "openai", "close": "rst"}},
		{"corrupt_tool_args", "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"abcdef\"}}]}}]}\n\n", `"arguments":"abc"`, map[string]any{"action": "corrupt_tool_args", "mode": "truncate", "then": "rst"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, tc.input)
			}))
			protocols := new(http.Protocols)
			protocols.SetUnencryptedHTTP2(true)
			upstream.Config.Protocols = protocols
			upstream.Start()
			defer upstream.Close()
			target, err := ParseTarget(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			p := New(target, fault.Config{Rules: []fault.Rule{{ID: "sse", Enabled: true, Fault: fault.Fault{Type: "sse-glitch", Params: tc.params}}}}, nil)
			addr := listenProxy(t, p)
			c, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			var block bytes.Buffer
			enc := hpack.NewEncoder(&block)
			for _, f := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: addr}, {Name: ":path", Value: "/"}} {
				if err := enc.WriteField(f); err != nil {
					t.Fatal(err)
				}
			}
			wire := append([]byte(h2tap.Preface), 0, 0, 0, 4, 0, 0, 0, 0, 0)
			wire = append(wire, 0, 0, byte(block.Len()), 1, 5, 0, 0, 0, 1)
			wire = append(wire, block.Bytes()...)
			if _, err := c.Write(wire); err != nil {
				t.Fatal(err)
			}
			var data []byte
			for {
				h, b, err := h2tap.ReadFrame(c)
				if err != nil {
					t.Fatalf("frames after %q: %v", data, err)
				}
				if h.Stream != 1 {
					continue
				}
				if h.Type == 0 {
					data = append(data, b...)
					if h.Flags&1 != 0 {
						t.Fatalf("unexpected END_STREAM: %q", data)
					}
				}
				if h.Type == 3 {
					if len(b) != 4 || binary.BigEndian.Uint32(b) != 2 {
						t.Fatalf("wrong reset: %x", b)
					}
					if !strings.Contains(string(data), tc.want) || !strings.HasSuffix(string(data), "\n\n") {
						t.Fatalf("missing final frame before reset: %q", data)
					}
					return
				}
			}
		})
	}
}
