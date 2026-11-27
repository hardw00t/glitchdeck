package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
)

func TestGRPCStatusAndMessageThreshold(t *testing.T) {
	for _, scenario := range []struct {
		name         string
		after        int
		upstreamOnly bool
		wantStatus   string
	}{
		{"upstream-trailers-only", 0, true, "7"},
		{"inject-after-message", 1, false, "14"},
		{"forward-when-threshold-unreached", 2, false, "0"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			frame := []byte{0, 0, 0, 0, 1, 'x'}
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/grpc")
				if scenario.upstreamOnly {
					w.Header().Set("Grpc-Status", "7")
					w.WriteHeader(200)
					return
				}
				w.Header().Add("Trailer", "Grpc-Status")
				_, _ = w.Write(frame)
				w.Header().Set("Grpc-Status", "0")
			}))
			upstream.Config.Protocols = H2CProtocols()
			upstream.Start()
			defer upstream.Close()
			target, err := ParseTarget(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			var cfg fault.Config
			if scenario.after != 0 {
				cfg.Rules = []fault.Rule{{ID: "status", Enabled: true, Fault: fault.Fault{Type: "grpc-glitch", Params: map[string]any{"after_messages": scenario.after}}}}
			}
			p := New(target, cfg, nil)
			addr := listenProxy(t, p)
			transport := &http.Transport{Protocols: H2CProtocols()}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			response, err := client.Post("http://"+addr+"/quotes/Get", "application/grpc", bytes.NewReader(frame))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || grpcHeader(response, "Grpc-Status") != scenario.wantStatus {
				t.Fatalf("got status %q, body %x, error %v", grpcHeader(response, "Grpc-Status"), body, err)
			}
			if scenario.upstreamOnly {
				if response.Header.Get("Grpc-Status") != "7" || len(body) != 0 {
					t.Fatalf("not trailers-only: %v %x", response.Header, body)
				}
			} else if !bytes.Equal(body, frame) || response.Trailer.Get("Grpc-Status") != scenario.wantStatus {
				t.Fatalf("incorrect message or trailers: %x %v", body, response.Trailer)
			}
		})
	}
}

func TestGRPCFaultDoesNotWaitForUploadEOF(t *testing.T) {
	p := New(nil, fault.Config{Rules: []fault.Rule{{ID: "unavailable", Enabled: true, Fault: fault.Fault{Type: "grpc-glitch"}}}}, nil)
	addr := listenProxy(t, p)
	transport := &http.Transport{Protocols: H2CProtocols()}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	upload, writer := io.Pipe()
	defer writer.Close()
	response, err := client.Post("http://"+addr+"/quotes/Get", "application/grpc", upload)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if code := response.Header.Get("Grpc-Status"); code != "14" {
		t.Fatalf("got status %q while upload remains open", code)
	}
}
