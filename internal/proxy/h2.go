package proxy

import (
	"time"

	"github.com/hardw00t/glitchdeck/internal/fault"
	"github.com/hardw00t/glitchdeck/internal/h2tap"
)

var h2Names = [...]string{"NO_ERROR", "PROTOCOL_ERROR", "INTERNAL_ERROR", "FLOW_CONTROL_ERROR", "SETTINGS_TIMEOUT", "STREAM_CLOSED", "FRAME_SIZE_ERROR", "REFUSED_STREAM", "CANCEL", "COMPRESSION_ERROR", "CONNECT_ERROR", "ENHANCE_YOUR_CALM", "INADEQUATE_SECURITY", "HTTP_1_1_REQUIRED"}

func h2Plan(params map[string]any, stream uint32) (plan h2tap.Plan, action, end string) {
	action = fault.String(params, "action", "rst_stream")
	plan.Kind, plan.Code, end = "rst", 2, "h2_rst"
	plan.BeforeHdrs = fault.Bool(params, "before_headers", true)
	plan.AfterBytes = int64(fault.Int(params, "after_bytes", 0))
	if action == "goaway" {
		plan.Kind, plan.Code, end = "goaway", 0, "h2_goaway"
		plan.LastStream = stream
		if fault.Bool(params, "refuse_current", true) && stream > 0 {
			plan.LastStream = max(stream, 2) - 2
		}
		plan.CloseAfter = time.Duration(fault.Int(params, "close_after_ms", 100)) * time.Millisecond
		plan.Debug = []byte(fault.String(params, "debug", ""))
	}
	if code, err := fault.H2Code(params["code"]); err == nil {
		plan.Code = code
	}
	return
}
