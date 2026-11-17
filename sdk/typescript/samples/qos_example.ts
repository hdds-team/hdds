// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * qos_example - what RELIABLE + TRANSIENT_LOCAL buys you, measured rather
 * than asserted.
 *
 * Two runs on the same INTRA_PROCESS participant, both writing BEFORE the
 * reader exists (a late joiner):
 *
 *   1. BEST_EFFORT + VOLATILE     -> the late joiner gets nothing.
 *   2. RELIABLE + TRANSIENT_LOCAL -> the late joiner is served the history.
 *
 * The sample also prints the QoS getters so the settings can be read back
 * from the native library rather than trusted.
 *
 * Build and run (Node >= 18, no ts-node and no tsx needed):
 *   cd sdk/typescript
 *   npm ci && npm run build && npm run build:samples
 *   HDDS_LIB_PATH=<repo>/target/release node dist-samples/qos_example.js
 */

import {
  Participant,
  QoS,
  WaitSet,
  TransportMode,
  version,
} from "@hdds/client";

const DEPTH = 5;

/** Write DEPTH samples, THEN create the reader, then drain it. */
function lateJoinerCount(
  participant: Participant,
  topic: string,
  writerQos: QoS,
  readerQos: QoS
): number {
  const writer = participant.createWriter(topic, writerQos);
  for (let i = 0; i < DEPTH; i += 1) {
    writer.write(Buffer.from(`${topic}-${i}`));
  }

  const reader = participant.createReader(topic, readerQos);
  const waitset = new WaitSet();
  waitset.attachReader(reader);

  let received = 0;
  const deadline = Date.now() + 2000;
  while (received < DEPTH && Date.now() < deadline) {
    if (!waitset.wait(0.5)) {
      continue;
    }
    for (;;) {
      const sample = reader.take();
      if (sample === null) break;
      received += 1;
    }
  }

  waitset.dispose();
  return received;
}

function main(): number {
  console.log(`HDDS ${version()} - qos_example`);

  const participant = Participant.create("qos_example_ts", {
    transport: TransportMode.INTRA_PROCESS,
  });

  try {
    const volatileQos = QoS.bestEffort().historyDepth(DEPTH);
    console.log(
      `best_effort/volatile : reliable=${volatileQos.isReliable()} ` +
        `transientLocal=${volatileQos.isTransientLocal()} ` +
        `historyDepth=${volatileQos.getHistoryDepth()}`
    );
    const volatileCount = lateJoinerCount(
      participant,
      `qos_volatile_${process.pid}`,
      volatileQos,
      QoS.bestEffort().historyDepth(DEPTH)
    );
    console.log(`best_effort/volatile late joiner: ${volatileCount}/${DEPTH}`);

    const durableQos = QoS.reliable().transientLocal().historyDepth(DEPTH);
    console.log(
      `reliable/transient   : reliable=${durableQos.isReliable()} ` +
        `transientLocal=${durableQos.isTransientLocal()} ` +
        `historyDepth=${durableQos.getHistoryDepth()} ` +
        `deadlineNs=${durableQos.getDeadlineNs()}`
    );
    const durableCount = lateJoinerCount(
      participant,
      `qos_durable_${process.pid}`,
      durableQos,
      QoS.reliable().transientLocal().historyDepth(DEPTH)
    );
    console.log(`reliable/transient late joiner:   ${durableCount}/${DEPTH}`);

    if (durableCount !== DEPTH) {
      console.error(
        `FAIL: transient_local late joiner got ${durableCount}/${DEPTH}`
      );
      return 1;
    }
    if (volatileCount >= durableCount) {
      console.error(
        `FAIL: volatile late joiner got ${volatileCount}, ` +
          `expected fewer than transient_local's ${durableCount}`
      );
      return 1;
    }

    console.log(
      `Done: transient_local kept ${durableCount} samples for the late ` +
        `joiner, volatile kept ${volatileCount}`
    );
    return 0;
  } finally {
    participant.dispose();
  }
}

process.exit(main());
