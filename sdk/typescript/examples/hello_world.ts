#!/usr/bin/env npx ts-node
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Hello World - Basic DDS pub/sub example using native FFI bindings.
 *
 * Prerequisites:
 *   - Build hdds-c: cargo build --release -p hdds-c
 *   - Set HDDS_LIB_PATH if not building from the repo root
 *
 * Usage:
 *   npx ts-node examples/hello_world.ts
 */

import {
  Participant,
  QoS,
  WaitSet,
  TransportMode,
  LogLevel,
  initLogging,
} from "../src/index.js";

interface HelloMessage {
  message: string;
  count: number;
  timestamp: number;
}

function main(): void {
  console.log("=== HDDS TypeScript Hello World (Native FFI) ===\n");

  // Initialize logging (optional)
  try {
    initLogging(LogLevel.INFO);
  } catch {
    // May fail if already initialized
  }

  // Create a participant with intra-process transport (no network needed)
  const participant = Participant.create("ts_hello_world", {
    transport: TransportMode.INTRA_PROCESS,
  });

  console.log(`Participant: ${participant.name}`);
  console.log(`Domain ID:   ${participant.domainId}`);
  console.log(`Part ID:     ${participant.participantId}\n`);

  // Create writer and reader with reliable QoS
  const qos = QoS.reliable().transientLocal().historyDepth(10);
  console.log(`QoS: ${qos.toString()}\n`);

  const writer = participant.createWriter<HelloMessage>("hello_world", qos);
  const reader = participant.createReader<HelloMessage>("hello_world", qos.clone());

  console.log(`Writer: ${writer.toString()}`);
  console.log(`Reader: ${reader.toString()}\n`);

  // Set up a WaitSet for the reader
  const waitset = new WaitSet();
  waitset.attachReader(reader);

  // Publish messages
  const messageCount = 5;
  for (let i = 1; i <= messageCount; i++) {
    const msg: HelloMessage = {
      message: "Hello from TypeScript!",
      count: i,
      timestamp: Date.now(),
    };

    writer.writeJson(msg);
    console.log(`Published: "${msg.message}" (count: ${msg.count})`);

    // Wait for data (short timeout for intra-process)
    const triggered = waitset.wait(1.0);
    if (triggered) {
      const received = reader.takeJson<HelloMessage>();
      if (received !== null) {
        console.log(
          `Received:  "${received.message}" (count: ${received.count})\n`
        );
      }
    }
  }

  // Clean up
  console.log("Cleaning up...");
  waitset.dispose();
  qos.dispose();
  participant.dispose();

  console.log("Done!");
}

main();
