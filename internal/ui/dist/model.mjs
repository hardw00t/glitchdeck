export function mergeEvents(a, b) {
  const events = new Map();
  for (const event of [...a, ...b]) events.set(Number(event.id), event);
  return [...events.values()].sort((x, y) => x.id - y.id);
}
export function chunkBytes(speed, duration) {
  return Math.max(1, Math.round((speed * duration) / 1000));
}
export function percentile(values, p) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.max(0, Math.ceil(sorted.length * p) - 1)];
}
export function numericValue(value, fallback) {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}
export function duplicateTotal(charges) {
  const duplicate = [...charges].reverse().find((c) => c.duplicate);
  if (!duplicate) return null;
  return {
    order: duplicate.order_id,
    cents: charges
      .filter((c) => c.order_id === duplicate.order_id)
      .reduce((sum, c) => sum + numericValue(c.amount_cents, 0), 0),
  };
}

export function faultFired(e) {
  const d = e.data || {};
  return Boolean(d.fault) && !d.fault_skipped &&
    !(e.type === "sse_event" && (!d.action || d.action === "none")) &&
    !(e.type === "http_req" && (d.fault === "sse-glitch" && d.sse || d.grpc_status != null));
}

export function matchesFilter(e, filter) {
  const d = e.data || {};
  return filter === "all" || (filter === "fault" && faultFired(e)) ||
    (filter === "http" && e.type === "http_req") ||
    (filter === "ws" && e.type === "ws_frame") ||
    (filter === "sse" && (e.type === "sse_event" || d.protocol === "sse")) ||
    (filter === "grpc" && (["grpc_call", "h2_frame"].includes(e.type) || ["grpc", "h2"].includes(d.protocol)));
}
export function faultTag(d) {
  if (d.fault === "sse-glitch") return ({stall:"SSE-STL", drop:"SSE-DRP", truncate:"SSE-TRN", corrupt_json:"SSE-BAD", eof_early:"SSE-EOF"})[d.action ?? d.fault_action] || "SSE";
  if (d.fault === "grpc-glitch") return d.grpc_status === 14 ? "gRPC14" : d.grpc_status === 4 ? "gRPC4" : "H2";
  if (d.fault === "h2-glitch") return (d.action ?? d.fault_action) === "goaway" ? "GOAWY" : "RST_S";
  return ({"tcp-rst":"RST", "dup-webhook":"DUP", "rate-limit":"429", "byte-trickle":"TRK", "latency-wave":"LAT"})[d.fault] || "WS";
}
export function streamPreview(d) {
  if (d.kind !== "event" || ["drop", "truncate", "eof_early"].includes(d.action)) return {done:false, text:""};
  if (d.is_done === true) return {done:true, text:""};
  try {
    const value = JSON.parse(d.preview);
    return {done:false, text:value.choices?.[0]?.delta?.content || value.delta?.text || ""};
  } catch {
    return {done:false, text:""};
  }
}
export function streamOutcome(d, cutAfter) {
  switch (d.outcome) {
    case "complete": return {state:"done", alert:""};
    case "wedged": return {state:"stalled", alert:"STREAM STALLED: no SSE tokens for 2.5s"};
    case "parse_error": return {state:"corrupted", alert:"STREAM CORRUPTED: invalid SSE JSON chunk"};
    case "silent_truncation": return {state:"truncated", alert:`EARLY EOF: connection closed before [DONE] · client reported success with ${d.tokens || 0} tokens`};
    case "truncated": return {state:"truncated", alert:`TRUNCATED BEFORE [DONE]: stream cut after ${cutAfter ?? d.tokens ?? 0} events`};
    default: return {state:"truncated", alert:`STREAM ERROR: ${d.client_error || "connection closed before [DONE]"}`};
  }
}
