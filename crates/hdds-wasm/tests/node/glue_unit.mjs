// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
//
// Node gate for the browser artefact: instantiate the wasm32 build through
// the hand-written glue and drive the relay protocol and the CDR codec.
// No network, no relay, no browser.
//
// Run: HDDS_WASM_ARTIFACT=<path to hdds_wasm.wasm> node glue_unit.mjs

import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { HddsWasm, HddsClient, CdrWriter, EVENT } from '../../js/hdds-wasm.js';

const artifact = process.env.HDDS_WASM_ARTIFACT;
if (!artifact) {
  console.error('HDDS_WASM_ARTIFACT is required (path to hdds_wasm.wasm)');
  process.exit(1);
}
if (!existsSync(artifact)) {
  console.error(`artefact not found: ${artifact}`);
  process.exit(1);
}

const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push([name, null]);
    console.log(`ok   ${name}`);
  } catch (e) {
    results.push([name, e]);
    console.log(`FAIL ${name}: ${e && e.stack ? e.stack : e}`);
  }
}

const wasm = await HddsWasm.load(artifact);

await test('the module exports the C ABI and its memory', () => {
  for (const name of [
    'memory',
    'hdds_wasm_alloc',
    'hdds_wasm_free',
    'hdds_wasm_participant_new',
    'hdds_wasm_participant_free',
    'hdds_wasm_build_connect',
    'hdds_wasm_build_create_topic',
    'hdds_wasm_build_subscribe',
    'hdds_wasm_build_publish',
    'hdds_wasm_process',
    'hdds_wasm_cdr_encoder_new',
    'hdds_wasm_cdr_encoder_len',
    'hdds_wasm_cdr_encoder_finish',
  ]) {
    assert.ok(wasm.exports[name], `missing export ${name}`);
  }
});

await test('CONNECT is built and CONNECT_ACK marks the client connected', () => {
  const client = new HddsClient(wasm, 7);
  try {
    const connect = client.buildConnect();
    // header: type CONNECT (1), flags 0, topic 0, seq 0, then domain id 7.
    assert.equal(connect[0], 0x01);
    assert.equal(connect.length, 10);
    assert.equal(connect[8] | (connect[9] << 8), 7);
    assert.equal(client.connected, false);

    // The relay answers CONNECT_ACK with participant id 42.
    const ack = new Uint8Array(12);
    ack[0] = 0x02;
    new DataView(ack.buffer).setUint32(8, 42, true);
    const { code } = client.handleFrame(ack);
    assert.equal(code, EVENT.CONNECT_ACK);
    assert.equal(client.connected, true);
  } finally {
    client.close();
  }
});

await test('CREATE_TOPIC, TOPIC_ACK, SUBSCRIBE and PUBLISH round trip', () => {
  const client = new HddsClient(wasm, 0);
  try {
    const ack = new Uint8Array(12);
    ack[0] = 0x02;
    client.handleFrame(ack);

    const create = client.buildCreateTopic('Chatter', 'std_msgs::String');
    assert.equal(create[0], 0x03);
    const nameLen = create[8] | (create[9] << 8);
    assert.equal(nameLen, 'Chatter'.length);
    assert.equal(new TextDecoder().decode(create.slice(10, 10 + nameLen)), 'Chatter');

    // Relay: TOPIC_ACK topic_id = 5, name "Chatter".
    const name = new TextEncoder().encode('Chatter');
    const topicAck = new Uint8Array(8 + 4 + name.length);
    topicAck[0] = 0x04;
    const view = new DataView(topicAck.buffer);
    view.setUint16(2, 5, true);
    view.setUint16(8, 5, true);
    view.setUint16(10, name.length, true);
    topicAck.set(name, 12);
    const acked = client.handleFrame(topicAck);
    assert.equal(acked.code, EVENT.TOPIC_ACK);
    assert.equal(acked.out[0] | (acked.out[1] << 8), 5);

    const subscribe = client.buildSubscribe(5);
    assert.equal(subscribe[0], 0x05);
    assert.equal(subscribe[2] | (subscribe[3] << 8), 5);

    const payload = new Uint8Array([1, 2, 3, 4]);
    const publish = client.buildPublish(5, payload);
    assert.equal(publish[0], 0x07);
    assert.deepEqual(Array.from(publish.slice(8)), [1, 2, 3, 4]);

    // Relay: DATA on topic 5.
    let received = null;
    client.subscribers.set(5, (bytes) => { received = bytes; });
    const data = new Uint8Array(8 + 3);
    data[0] = 0x08;
    new DataView(data.buffer).setUint16(2, 5, true);
    data.set([9, 8, 7], 8);
    const got = client.handleFrame(data);
    assert.equal(got.code, EVENT.DATA);
    assert.deepEqual(Array.from(received), [9, 8, 7]);
  } finally {
    client.close();
  }
});

await test('CDR encodes and decodes through linear memory', () => {
  const writer = new CdrWriter(wasm);
  const bytes = writer.u32(0x11223344).f64(2.5).string('hello').finish();
  // XCDR2: u32 (4) + f64 (8, aligned at 4, no padding) + length (4) +
  // "hello\0" (6). The layout Cyclone DDS 0.11 writes for the same @final
  // struct at encoding version 2.
  assert.equal(bytes.length, 22);

  const [ptr, len] = wasm.writeBytes(bytes);
  const outPtr = wasm.alloc(64);
  try {
    const n = wasm.exports.hdds_wasm_cdr_decode_u32_f64_string(ptr, len, outPtr, 64);
    assert.ok(n > 0, `decode returned ${n}`);
    const out = wasm.readBytes(outPtr, n);
    const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
    assert.equal(view.getUint32(0, true), 0x11223344);
    assert.equal(view.getFloat64(4, true), 2.5);
    assert.equal(new TextDecoder().decode(out.slice(12)), 'hello');
  } finally {
    wasm.free(ptr, len);
    wasm.free(outPtr, 64);
  }
});

await test('a CDR payload larger than the scratch buffer survives the retry', () => {
  // The scratch buffer starts at 4096 bytes, so this forces the
  // ERR_BUFFER_TOO_SMALL path through hdds_wasm_cdr_encoder_finish. The
  // encoder must still be alive on that path: consuming it and answering -2
  // left the glue retrying with a dangling handle, which aborted the module
  // inside the allocator.
  const big = 'x'.repeat(10000);
  const writer = new CdrWriter(wasm);
  const bytes = writer.u32(1).f64(0.5).string(big).finish();
  // XCDR2: u32 (4) + f64 (8) + length (4) + big + NUL
  assert.equal(bytes.length, 16 + big.length + 1);
  assert.equal(new TextDecoder().decode(bytes.slice(16, 16 + big.length)), big);

  // And the raw ABI says so directly: a refusal keeps the handle usable.
  const handle = wasm.exports.hdds_wasm_cdr_encoder_new();
  wasm.exports.hdds_wasm_cdr_encode_u32(handle, 7);
  const tiny = wasm.alloc(2);
  try {
    assert.equal(wasm.exports.hdds_wasm_cdr_encoder_finish(handle, tiny, 2), -2);
    assert.equal(wasm.exports.hdds_wasm_cdr_encoder_len(handle), 4);
  } finally {
    wasm.free(tiny, 2);
  }
  const room = wasm.alloc(8);
  try {
    assert.equal(wasm.exports.hdds_wasm_cdr_encoder_finish(handle, room, 8), 4);
  } finally {
    wasm.free(room, 8);
  }
});

await test('hdds_wasm_process does not consume a frame it cannot answer', () => {
  const client = new HddsClient(wasm, 0);
  try {
    const ack = new Uint8Array(12);
    ack[0] = 0x02;
    new DataView(ack.buffer).setUint32(8, 42, true);
    // Hand the raw entry point a buffer that cannot hold the answer. The
    // participant must be untouched, so a retry is a retry.
    const frame = wasm.writeBytes(ack);
    const outPtr = wasm.alloc(1);
    const lenPtr = wasm.alloc(4);
    try {
      const rc = wasm.exports.hdds_wasm_process(
        client.participant, frame[0], frame[1], outPtr, 1, lenPtr);
      assert.equal(rc, -2);
      assert.equal(wasm.exports.hdds_wasm_is_connected(client.participant), 0,
        'a refused call still ran the state machine');
    } finally {
      wasm.free(frame[0], frame[1]);
      wasm.free(outPtr, 1);
      wasm.free(lenPtr, 4);
    }
    // The retry, with room, is the one that connects.
    assert.equal(client.handleFrame(ack).code, EVENT.CONNECT_ACK);
    assert.equal(client.connected, true);
  } finally {
    client.close();
  }
});

await test('a malformed frame is an error, not a crash', () => {
  const client = new HddsClient(wasm, 0);
  try {
    assert.throws(() => client.handleFrame(new Uint8Array([0x7f, 0, 0, 0, 0, 0, 0, 0])));
    assert.throws(() => client.handleFrame(new Uint8Array([1, 2])));
  } finally {
    client.close();
  }
});

const failed = results.filter(([, e]) => e !== null);
console.log(`\n${results.length - failed.length}/${results.length} node glue tests passed`);
process.exit(failed.length === 0 ? 0 : 1);
