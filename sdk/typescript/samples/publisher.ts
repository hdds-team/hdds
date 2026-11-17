// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * publisher - publish JSON sensor samples on a topic at a fixed rate.
 *
 * Usage:
 *   node dist-samples/publisher.js [topic] [intervalMs] [count] [domainId]
 *
 * Defaults: topic "temperature", 1000 ms, 5 samples, domain 39. Pair it with subscriber.ts on the same
 * topic and domain.
 *
 * Build and run (Node >= 18, no ts-node and no tsx needed):
 *   cd sdk/typescript
 *   npm ci && npm run build && npm run build:samples
 *   HDDS_LIB_PATH=<repo>/target/release node dist-samples/publisher.js
 */

import {
  Participant,
  QoS,
  TransportMode,
  version,
} from "@hdds/client";

interface Reading {
  sensor: string;
  celsius: number;
  seq: number;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main(): Promise<number> {
  const topic = process.argv[2] ?? "temperature";
  const intervalMs = Number(process.argv[3] ?? 1000);
  const count = Number(process.argv[4] ?? 5);
  const domainId = Number(process.argv[5] ?? 39);

  console.log(
    `HDDS ${version()} - publisher topic=${topic} interval=${intervalMs}ms ` +
      `count=${count} domain=${domainId}`
  );

  const participant = Participant.create("publisher_ts", {
    domainId,
    transport: TransportMode.UDP_MULTICAST,
  });

  try {
    const qos = QoS.reliable().transientLocal().historyDepth(count + 5);
    const writer = participant.createWriter<Reading>(topic, qos);

    // Give discovery a moment before the first sample.
    await sleep(300);

    for (let seq = 0; seq < count; seq += 1) {
      const reading: Reading = {
        sensor: topic,
        celsius: 20 + Math.round(Math.sin(seq) * 100) / 10,
        seq,
      };
      writer.writeJson(reading);
      console.log(`sent    ${JSON.stringify(reading)}`);
      if (seq + 1 < count) {
        await sleep(intervalMs);
      }
    }

    // Stay alive briefly so a late-joining reliable subscriber can still be
    // served from the transient-local history.
    await sleep(2000);
    console.log(`Done: published ${count} samples on "${topic}"`);
    return 0;
  } finally {
    participant.dispose();
  }
}

main().then((code) => process.exit(code));
