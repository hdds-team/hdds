// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Cross-language test helper: TypeScript pub/sub.
 *
 * Usage:
 *   node test.js pub <topic> <count>
 *   node test.js sub <topic> <count>
 *
 * Mirrors scripts/cross-lang/test.py exactly: the same "XTEST-<i>" payloads,
 * the same reliable + transient_local + history(count + 5) QoS, the same
 * 300 ms settle before the first write, the same 2 s linger for late joiners,
 * the same 10 s receive deadline and the same "OK: received n/n" line that
 * scripts/test-sdk.sh greps for.
 *
 * Compiled by build_typescript_sdk() in scripts/test-sdk.sh (an inline `npx
 * tsc` invocation, no tsconfig file) into $CARGO_TARGET_DIR/ts-xlang, next to
 * a node_modules/@hdds/client symlink, so "@hdds/client" resolves through the
 * package's own exports map and the worktree stays clean.
 */

import { Participant, QoS, WaitSet } from "@hdds/client";

const PAYLOAD_PREFIX = "XTEST-";

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runPub(topic: string, count: number): Promise<number> {
  const participant = Participant.create("xtest_ts_pub");
  try {
    const qos = QoS.reliable().transientLocal().historyDepth(count + 5);
    // Explicit "RawBytes", exactly like test.py: the C ABI defaults to it when
    // the type name is NULL, but the two drivers must not disagree on the wire
    // if that default ever moves.
    const writer = participant.createWriter(topic, qos, "RawBytes");

    // Let discovery happen
    await sleep(300);

    for (let i = 0; i < count; i += 1) {
      writer.write(Buffer.from(`${PAYLOAD_PREFIX}${i}`));
    }

    // Keep alive for late joiners
    await sleep(2000);
    return 0;
  } finally {
    participant.dispose();
  }
}

function runSub(topic: string, count: number): number {
  const participant = Participant.create("xtest_ts_sub");
  const received: Buffer[] = [];
  try {
    const qos = QoS.reliable().transientLocal().historyDepth(count + 5);
    const reader = participant.createReader(topic, qos, "RawBytes");

    const waitset = new WaitSet();
    waitset.attachReader(reader);

    const deadline = Date.now() + 10_000;
    while (received.length < count && Date.now() < deadline) {
      if (waitset.wait(1.0)) {
        for (;;) {
          const data = reader.take();
          if (data === null) break;
          received.push(Buffer.from(data));
        }
      }
    }

    waitset.dispose();
  } finally {
    participant.dispose();
  }

  let ok = true;
  for (let i = 0; i < count; i += 1) {
    const expected = `${PAYLOAD_PREFIX}${i}`;
    const got = received[i];
    if (got === undefined) {
      console.error(`MISSING sample ${i}`);
      ok = false;
    } else if (got.toString() !== expected) {
      console.error(
        `MISMATCH at ${i}: got ${JSON.stringify(got.toString())}, ` +
          `want ${JSON.stringify(expected)}`
      );
      ok = false;
    }
  }

  if (ok && received.length === count) {
    console.log(`OK: received ${count}/${count} samples`);
    return 0;
  }
  console.error(`FAIL: received ${received.length}/${count} samples`);
  return 1;
}

async function main(): Promise<number> {
  if (process.argv.length !== 5) {
    console.error("Usage: node test.js <pub|sub> <topic> <count>");
    return 1;
  }
  const mode = process.argv[2]!;
  const topic = process.argv[3]!;
  const count = Number(process.argv[4]);

  if (mode === "pub") {
    return runPub(topic, count);
  }
  if (mode === "sub") {
    return runSub(topic, count);
  }
  console.error(`Unknown mode: ${mode}`);
  return 1;
}

main().then((code) => process.exit(code));
