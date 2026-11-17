// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * hello_world - the smallest complete HDDS program in TypeScript.
 *
 * One participant, one writer, one reader, one WaitSet, five samples. The
 * transport is INTRA_PROCESS, so this sample needs no network and cannot
 * disturb anything else on the machine.
 *
 * Build and run (Node >= 18, no ts-node and no tsx needed):
 *   cd sdk/typescript
 *   npm ci && npm run build && npm run build:samples
 *   HDDS_LIB_PATH=<repo>/target/release node dist-samples/hello_world.js
 */

import {
  Participant,
  QoS,
  WaitSet,
  TransportMode,
  version,
} from "@hdds/client";

const TOPIC = "hello_world";
const COUNT = 5;

function main(): number {
  console.log(`HDDS ${version()} - hello_world`);

  const participant = Participant.create("hello_world_ts", {
    transport: TransportMode.INTRA_PROCESS,
  });

  try {
    const qos = QoS.reliable().transientLocal().historyDepth(COUNT + 5);
    const writer = participant.createWriter(TOPIC, qos);
    const reader = participant.createReader(TOPIC, qos);

    const waitset = new WaitSet();
    waitset.attachReader(reader);

    for (let i = 0; i < COUNT; i += 1) {
      const payload = `hello ${i}`;
      writer.write(Buffer.from(payload));
      console.log(`sent    ${payload}`);
    }

    const received: string[] = [];
    const deadline = Date.now() + 10_000;
    while (received.length < COUNT && Date.now() < deadline) {
      if (waitset.wait(1.0)) {
        for (;;) {
          const sample = reader.take();
          if (sample === null) break;
          const text = sample.toString();
          received.push(text);
          console.log(`received ${text}`);
        }
      }
    }

    waitset.dispose();

    if (received.length !== COUNT) {
      console.error(`FAIL: received ${received.length}/${COUNT} samples`);
      return 1;
    }
    console.log(`Done: ${received.length}/${COUNT} samples`);
    return 0;
  } finally {
    participant.dispose();
  }
}

process.exit(main());
