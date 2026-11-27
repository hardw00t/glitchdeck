package proxy

import (
	"net/http"
	"strconv"
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
)

func rateLimitResponse(h http.Header, params map[string]any, status int, seq uint64, now time.Time) string {
	h.Set("Retry-After", strconv.Itoa(fault.Int(params, "retry_after_sec", 5)))
	h.Set("X-Glitchdeck-Fault", "rate-limit")
	provider := fault.String(params, "provider", "none")
	if _, ok := params["retry_after_ms"]; ok && provider != "gemini" {
		h.Set("Retry-After-Ms", strconv.Itoa(fault.Int(params, "retry_after_ms", 0)))
	}
	body := fault.String(params, "body", "")
	reset := fault.Int(params, "reset_sec", 0)
	switch provider {
	case "openai":
		h.Set("X-Ratelimit-Limit-Requests", strconv.Itoa(fault.Int(params, "burst", 1)))
		h.Set("X-Ratelimit-Remaining-Requests", "0")
		if reset > 0 {
			duration := strconv.Itoa(reset) + "s"
			h.Set("X-Ratelimit-Reset-Requests", duration)
			h.Set("X-Ratelimit-Reset-Tokens", duration)
		}
		h.Set("X-Request-Id", "req_glitchdeck_"+strconv.FormatUint(seq, 10))
	case "anthropic":
		h.Set("Anthropic-Ratelimit-Requests-Remaining", "0")
		if reset > 0 {
			h.Set("Anthropic-Ratelimit-Requests-Reset", now.UTC().Add(time.Duration(reset)*time.Second).Format(time.RFC3339))
		}
		h.Set("Request-Id", "req_glitchdeck_"+strconv.FormatUint(seq, 10))
	}
	if body != "" {
		return body
	}
	switch provider {
	case "openai":
		body = `{"error":{"message":"Rate limit reached (glitchdeck)","type":"requests","param":null,"code":"rate_limit_exceeded"}}`
	case "anthropic":
		if status == 529 {
			body = `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`
		} else {
			body = `{"type":"error","error":{"type":"rate_limit_error","message":"Rate limit reached (glitchdeck)"}}`
		}
	case "gemini":
		code := "RESOURCE_EXHAUSTED"
		if status == 503 {
			code = "UNAVAILABLE"
		}
		body = `{"error":{"code":` + strconv.Itoa(status) + `,"message":"Resource has been exhausted (e.g. check quota).","status":"` + code + `"}}`
	default:
		return body
	}
	h.Set("Content-Type", "application/json")
	return body
}
