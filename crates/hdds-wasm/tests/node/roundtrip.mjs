// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
//
// End-to-end gate for the browser story: node instantiates the wasm32
// artefact through the hand-written glue, connects to a running
// hdds-wasm-relay over a real WebSocket, and two "browser" clients exchange
// a CDR sample through the DDS domain.
//
// node stands in for the browser: same ES module, same binary frames, same
// WebSocket API (node >= 22 has a global WebSocket).
//
// Run: HDDS_WASM_ARTIFACT=<hdds_wasm.wasm> HDDS_RELAY_URL=ws://127.0.0.1:PORT/ws \
//        node roundtrip.mjs

import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { HddsWasm, HddsClient } from '../../js/hdds-wasm.js';

const artifact = process.env.HDDS_WASM_ARTIFACT;
const relayUrl = process.env.HDDS_RELAY_URL;
if (!artifact || !existsSync(artifact)) {
  console.error(`HDDS_WASM_ARTIFACT is required and must exist (got ${artifact})`);
  process.exit(1);
}
if (!relayUrl) {
  console.error('HDDS_RELAY_URL is required (ws://host:port/ws)');
  process.exit(1);
}
if (typeof globalThis.WebSocket !== 'function') {
  console.error(`node ${process.version} has no global WebSocket; this gate needs node >= 22`);
  process.exit(1);
}

const TOPIC = 'WasmNodeChatter';
const TYPE_NAME = 'std_msgs::String';

const wasm = await HddsWasm.load(artifact);

function withTimeout(promise, ms, what) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`timed out waiting for ${what}`)), ms)),
  ]);
}

async function newClient(name) {
  const client = new HddsClient(wasm, 0);
  await withTimeout(client.connect(relayUrl), 10_000, `${name} CONNECT_ACK`);
  assert.equal(client.connected, true, `${name} did not connect`);
  const topicId = await withTimeout(
    client.createTopic(TOPIC, TYPE_NAME), 10_000, `${name} TOPIC_ACK`);
  return { client, topicId };
}

const publisher = await newClient('publisher');
const subscriber = await newClient('subscriber');
assert.equal(publisher.topicId, subscriber.topicId, 'the relay handed out two ids for one topic');

const received = [];
subscriber.client.subscribe(subscriber.topicId, (payload) => received.push(payload));

// Let the relay's DDS endpoints match before the first publish.
await new Promise((r) => setTimeout(r, 1500));

const expected = publisher.client.cdr().u32(7).f64(1.5).string('through the relay').finish();

let attempts = 0;
while (attempts < 60 && !received.some((p) => Buffer.compare(Buffer.from(p), Buffer.from(expected)) === 0)) {
  publisher.client.publish(publisher.topicId, expected);
  await new Promise((r) => setTimeout(r, 100));
  attempts += 1;
}

publisher.client.close();
subscriber.client.close();

const got = received.some((p) => Buffer.compare(Buffer.from(p), Buffer.from(expected)) === 0);
if (!got) {
  console.log(`FAIL browser-to-browser sample through DDS (saw ${received.length} frame(s))`);
  process.exit(1);
}
console.log(`ok   browser-to-browser CDR sample through the relay and DDS (${attempts} publish attempt(s))`);
console.log('1/1 node relay roundtrip test passed');
process.exit(0);
