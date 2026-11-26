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
