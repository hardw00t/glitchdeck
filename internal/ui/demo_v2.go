package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/grpcwire"
	"github.com/hardw00t/glitchdeck/internal/proxy"
	"github.com/hardw00t/glitchdeck/internal/sse"
)

type streamInput struct {
	Flavor       string `json:"flavor"`
	Tokens       int    `json:"tokens"`
	TokenMS      int    `json:"token_ms"`
	Wait         bool   `json:"wait"`
	MaxMS        int    `json:"max_ms"`
	WedgeAfterMS int    `json:"wedge_after_ms"`
}

type streamResult struct {
	RunID       string  `json:"run_id"`
	Phase       string  `json:"phase"`
	Seq         *uint64 `json:"seq"`
	Outcome     string  `json:"outcome"`
	Tokens      int     `json:"tokens"`
	Text        string  `json:"text"`
	ElapsedMS   int64   `json:"elapsed_ms"`
	ClientError string  `json:"client_error"`
}

func (c *control) demoStream(w http.ResponseWriter, r *http.Request) {
	if c.DemoURL == "" {
		http.NotFound(w, r)
		return
	}
	in := streamInput{Flavor: "openai", Tokens: 24, TokenMS: 40, MaxMS: 60000, WedgeAfterMS: 3000}
	if err := readJSON(w, r, &in); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if (in.Flavor != "openai" && in.Flavor != "anthropic") || in.Tokens < 1 || in.Tokens > 256 || in.TokenMS < 0 || in.TokenMS > 1000 || in.MaxMS < 1000 || in.MaxMS > 300000 || in.WedgeAfterMS < 1 || in.WedgeAfterMS > 300000 {
		http.Error(w, "invalid demo stream configuration", http.StatusBadRequest)
		return
	}
	select {
	case c.streamSlots <- struct{}{}:
	default:
		http.Error(w, "four demo streams already running", http.StatusTooManyRequests)
		return
	}
	id := "r-" + strconv.FormatUint(c.streamID.Add(1), 10)
	c.bus.Publish("demo_stream", streamResult{RunID: id, Phase: "started"})
	run := func(ctx context.Context) streamResult {
		defer func() { <-c.streamSlots }()
		result := c.readDemoStream(ctx, id, in)
		body, _ := json.Marshal(map[string]string{"outcome": result.Outcome})
		reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_, _, _ = c.call(reportCtx, http.MethodPost, c.DemoURL+"/api/stream-result", body)
		c.bus.Publish("demo_stream", result)
		return result
	}
	if in.Wait {
		respond(w, run(r.Context()))
		return
	}
	go run(context.WithoutCancel(r.Context()))
	respondStatus(w, http.StatusAccepted, map[string]string{"run_id": id})
}

func (c *control) readDemoStream(ctx context.Context, id string, in streamInput) (out streamResult) {
	start := time.Now()
	out = streamResult{RunID: id, Phase: "finished", Outcome: "error"}
	defer func() { out.ElapsedMS = time.Since(start).Milliseconds() }()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(in.MaxMS)*time.Millisecond)
	defer cancel()
	base, err := localEndpoint(c.Listen)
	if err != nil {
		out.ClientError = err.Error()
		return
	}
	path := "/api/chat/stream"
	if in.Flavor == "anthropic" {
		path = "/v1/messages"
	}
	body, _ := json.Marshal(map[string]int{"tokens": in.Tokens, "token_ms": in.TokenMS})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		out.ClientError = err.Error()
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Glitchdeck-Run", id)
	c.authenticateProxy(req)
	var extra []string
	if target, err := url.Parse(c.DemoURL); err == nil {
		query := fault.Query{Method: req.Method, Path: path, Host: target.Host, Scheme: target.Scheme, Proto: "h1", ContentType: "application/json", Seq: c.p.Seq() + 1}
		if rule := fault.MatchRequest(c.p.Config(), query); rule != nil && rule.Fault.Type == "sse-glitch" {
			extra = fault.Strings(rule.Fault.Params, "done_events")
		}
	}
	// Unlike the other demo operations this client has no per-read idle timeout.
	client := *c.client
	client.Timeout = 0
	resp, err := client.Do(req)
	if err != nil {
		out.ClientError = err.Error()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			out.Outcome = "wedged"
		}
		return
	}
	defer resp.Body.Close()
	if seq, err := strconv.ParseUint(resp.Header.Get("X-Glitchdeck-Seq"), 10, 64); err == nil {
		out.Seq = &seq
	}
	media, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK || media != "text/event-stream" {
		out.ClientError = "expected an SSE response, got " + resp.Status
		return
	}
	var text strings.Builder
	reader := sse.NewReader(resp.Body, 1<<20)
	lastFrame := time.Now()
	for {
		frame, err := reader.Next()
		if err != nil {
			out.Text = text.String()
			switch {
			case errors.Is(ctx.Err(), context.DeadlineExceeded) && time.Since(lastFrame).Milliseconds() >= int64(in.WedgeAfterMS):
				out.Outcome, out.ClientError = "wedged", err.Error()
			case errors.Is(err, io.EOF) && len(reader.Tail()) == 0:
				out.Outcome = "silent_truncation"
			default:
				out.Outcome, out.ClientError = "truncated", err.Error()
			}
			return
		}
		if !frame.Dispatch {
			continue
		}
		lastFrame = time.Now()
		if kind, ok := frame.Terminal(extra); ok {
			out.Outcome, out.Text = "complete", text.String()
			if kind == "error" {
				out.Outcome, out.ClientError = "error", frame.Data
			}
			return
		}
		var chunk struct {
			Type  string `json:"type"`
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(frame.Data), &chunk); err != nil {
			out.Outcome, out.ClientError = "parse_error", err.Error()
			return
		}
		token := chunk.Delta.Text
		if len(chunk.Choices) != 0 {
			token = chunk.Choices[0].Delta.Content
		}
		if token != "" {
			out.Tokens++
			text.WriteString(token)
		}
	}
}

func (c *control) demoGRPC(w http.ResponseWriter, r *http.Request) {
	if c.DemoURL == "" {
		http.NotFound(w, r)
		return
	}
	base, err := localEndpoint(c.Listen)
	if err != nil {
		http.Error(w, "proxy listen address unavailable", http.StatusBadGateway)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	// One gRPC message: protobuf field 1, string "ACME".
	message := []byte{0, 0, 0, 0, 6, 10, 4, 'A', 'C', 'M', 'E'}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/glitchdeck.demo.v1.Quotes/Get", bytes.NewReader(message))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	req.Header.Set("Grpc-Timeout", "2500m")
	c.authenticateProxy(req)
	t := &http.Transport{Protocols: proxy.H2CProtocols(), DisableCompression: true}
	defer t.CloseIdleConnections()
	result := map[string]any{"grpc_status": nil, "grpc_message": "", "h2_error": "", "http_status": 0}
	resp, err := t.RoundTrip(req)
	if err == nil {
		defer resp.Body.Close()
		result["http_status"] = resp.StatusCode
		_, err = io.Copy(io.Discard, resp.Body)
		if err == nil {
			get := func(key string) string {
				if v := resp.Trailer.Get(key); v != "" {
					return v
				}
				return resp.Header.Get(key)
			}
			if status, err := strconv.Atoi(get("Grpc-Status")); err == nil {
				result["grpc_status"] = status
			}
			result["grpc_message"] = grpcwire.DecodeMessage(get("Grpc-Message"))
		}
	}
	if err != nil {
		result["h2_error"] = err.Error()
	}
	respond(w, result)
}
