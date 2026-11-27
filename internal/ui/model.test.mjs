import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { mergeEvents, chunkBytes, percentile, numericValue, duplicateTotal, matchesFilter, faultTag, streamPreview, streamOutcome } from './dist/model.mjs';

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

test('protocol filters include SSE and gRPC without mixing HTTP', () => {
  assert.equal(matchesFilter({type:'sse_event', data:{}}, 'sse'), true);
  assert.equal(matchesFilter({type:'grpc_call', data:{}}, 'grpc'), true);
  assert.equal(matchesFilter({type:'h2_frame', data:{}}, 'grpc'), true);
  assert.equal(matchesFilter({type:'http_req', data:{protocol:'h2'}}, 'grpc'), true);
  assert.equal(matchesFilter({type:'sse_event', data:{fault:'sse-glitch', action:'drop'}}, 'fault'), true);
  assert.equal(matchesFilter({type:'sse_event', data:{fault:'sse-glitch', action:'none'}}, 'fault'), false);
  assert.equal(matchesFilter({type:'sse_event', data:{}}, 'http'), false);
});
test('fault tags identify SSE actions and gRPC statuses', () => {
  assert.equal(faultTag({fault:'sse-glitch', action:'truncate'}), 'SSE-TRN');
  assert.equal(faultTag({fault:'grpc-glitch', grpc_status:14}), 'gRPC14');
  assert.equal(faultTag({fault:'h2-glitch', action:'goaway'}), 'GOAWY');
});
test('stream preview never infers DONE or corruption from a partial preview', () => {
  assert.deepEqual(streamPreview({kind:'event', is_done:true, preview:'[DONE]'}), {done:true, text:''});
  assert.deepEqual(streamPreview({kind:'event', action:'eof_early', is_done:true, preview:'[DONE]'}), {done:false, text:''});
  assert.deepEqual(streamPreview({kind:'event', is_done:false, preview:'{"choices":['}), {done:false, text:''});
  assert.deepEqual(streamPreview({kind:'event', is_done:false, preview:'{"choices":[{"delta":{"content":"Hi"}}]}'}), {done:false, text:'Hi'});
});
test('finished demo outcome is authoritative even when preview missed DONE', () => {
  assert.equal(streamOutcome({outcome:'complete'}).state, 'done');
  assert.equal(streamOutcome({outcome:'silent_truncation', tokens:9}).state, 'truncated');
  assert.match(streamOutcome({outcome:'silent_truncation', tokens:9}).alert, /EARLY EOF/);
  assert.equal(streamOutcome({outcome:'parse_error'}).state, 'corrupted');
  assert.match(streamOutcome({outcome:'truncated', tokens:7}, 8).alert, /after 8 events/);
  assert.equal(streamOutcome({outcome:'wedged'}).state, 'stalled');
});
