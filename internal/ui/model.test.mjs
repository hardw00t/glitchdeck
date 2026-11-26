import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { mergeEvents, chunkBytes, percentile, numericValue, duplicateTotal } from './dist/model.mjs';

test('snapshot and stream events deduplicate by ID and stay ordered', () => {
  assert.deepEqual(mergeEvents([{id: 2}, {id: 1}], [{id: 2}, {id: 3}]).map(e => e.id), [1, 2, 3]);
});
test('trickle duration converts speed to bytes with a minimum of one', () => {
  assert.equal(chunkBytes(256, 500), 128);
  assert.equal(chunkBytes(16, 50), 1);
});
test('percentiles use actual values and handle empty data', () => {
  assert.equal(percentile([], 0.95), null);
  assert.equal(percentile([40, 10, 30, 20], 0.95), 40);
});
test('merge retains more than 200 recent scope samples', () => {
  assert.equal(mergeEvents([], Array.from({length: 300}, (_, id) => ({id}))).length, 300);
});
test('invalid numeric values fall back without coercing strings', () => {
  assert.equal(numericValue('<img>', 150), 150);
  assert.equal(numericValue(0, 150), 0);
});
test('duplicate totals are scoped to the duplicated order', () => {
  assert.deepEqual(duplicateTotal([{order_id:'a',amount_cents:9900}, {order_id:'b',amount_cents:9900}, {order_id:'b',amount_cents:9900,duplicate:true}]), {order:'b', cents:19800});
});
