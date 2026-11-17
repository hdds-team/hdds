// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * subscriber - listen on a topic and print every sample until a count or a
 * timeout is reached.
 *
 * Usage:
 *   node dist-samples/subscriber.js [topic] [count] [timeoutSecs] [domainId]
 *
 * Defaults: topic "temperature", 5 samples, 30 s, domain 39. Pair it with
 * publisher.ts on the same topic and domain. Exit code 0 means the expected
 * number of samples arrived; 1 means the timeout won.
 *
 * Build and run (Node >= 18, no ts-node and no tsx needed):
 *   cd sdk/typescript
 *   npm ci && npm run build && npm run build:samples
 *   HDDS_LIB_PATH=<repo>/target/release node dist-samples/subscriber.js
 */

import {
  Participant,
  QoS,
  WaitSet,
  TransportMode,
  version,
} from "@hdds/client";

function main(): number {
  const topic = process.argv[2] ?? "temperature";
  const count = Number(process.argv[3] ?? 5);
  const timeoutSecs = Number(process.argv[4] ?? 30);
  const domainId = Number(process.argv[5] ?? 39);

  console.log(
    `HDDS ${version()} - subscriber topic=${topic} count=${count} ` +
      `timeout=${timeoutSecs}s domain=${domainId}`
  );

  const participant = Participant.create("subscriber_ts", {
    domainId,
    transport: TransportMode.UDP_MULTICAST,
  });

  try {
    const qos = QoS.reliable().transientLocal().historyDepth(count + 5);
    const reader = participant.createReader(topic, qos);

    const waitset = new WaitSet();
    waitset.attachReader(reader);

    let received = 0;
    const deadline = Date.now() + timeoutSecs * 1000;
    while (received < count && Date.now() < deadline) {
      // wait() returns false on timeout, so this loop makes progress without
      // spinning on an idle topic.
      if (!waitset.wait(1.0)) {
        continue;
      }
      for (;;) {
        const sample = reader.take();
        if (sample === null) break;
        received += 1;
        console.log(`received ${sample.toString()}`);
      }
    }

    waitset.dispose();

    if (received < count) {
      console.error(`FAIL: received ${received}/${count} samples`);
      return 1;
    }
    console.log(`Done: received ${received}/${count} samples on "${topic}"`);
    return 0;
  } finally {
    participant.dispose();
  }
}

process.exit(main());
