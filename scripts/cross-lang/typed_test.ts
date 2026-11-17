// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Typed cross-language test: TypeScript pub/sub with hddsgen-generated CDR2
 * types.
 *
 * Usage:
 *   node typed_test.js pub <topic> <count>
 *   node typed_test.js sub <topic> <count>
 *   node typed_test.js vector <topic> 1
 *   node typed_test.js pub-default|sub-default <topic> <count>
 *   node typed_test.js pub-ext|sub-ext <ExtFinal*|ExtAppendable*|ExtMutable*> <count>
 *
 * pub-ext / sub-ext write and read FinalProbe, SensorReading (APPENDABLE) or
 * MutableProbe, by topic prefix; the writer is given the
 * `extensibility<Name>` the generated module exports.
 *
 * Mirrors scripts/cross-lang/typed_test.py field for field: the same literal
 * values, the same CDR2 LE encapsulation header, the same "Keyed" topic-prefix
 * dispatch, the same lowercase-hex "vector" output (CDR2 body only, no
 * encapsulation header) and the same "OK: received n/n" line.
 *
 * The generated module is copied next to this file by
 * scripts/test-sdk-typed.sh before compilation.
 */

import {
  Cdr2Buffer,
  SensorReading,
  SensorKind,
  GeoPoint,
  KeyedSample,
  encodeSensorReading,
  decodeSensorReading,
  encodeKeyedSample,
  decodeKeyedSample,
  decodeSensorReadingByEncapsulation,
  FinalProbe,
  MutableProbe,
  encodeFinalProbe,
  encodeMutableProbe,
  decodeFinalProbeByEncapsulation,
  decodeMutableProbeByEncapsulation,
  extensibilityFinalProbe,
  extensibilityMutableProbe,
  extensibilitySensorReading,
} from "./interop_types.js";
import * as generated from "./interop_types.js";

import { Participant, QoS, WaitSet } from "@hdds/client";

/** CDR2 LE encapsulation header. */
const ENCAP_CDR2_LE = Buffer.from([0x00, 0x01, 0x00, 0x00]);

const ENCODE_CAPACITY = 4096;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function encodeCdr2Le(
  encode: (obj: never, buf: Cdr2Buffer) => void,
  obj: unknown
): Buffer {
  const scratch = new Uint8Array(ENCODE_CAPACITY);
  const buf = new Cdr2Buffer(scratch);
  encode(obj as never, buf);
  return Buffer.from(buf.toBytes());
}

function createTestMessage(): SensorReading {
  return {
    sensor_id: 42,
    kind: SensorKind.PRESSURE,
    value: 3.15,
    label: "test-sensor",
    timestamp_ns: 1700000000000000000n,
    history: [1.0, 2.0, 3.0],
    error_code: 7,
    location: { latitude: 48.8566, longitude: 2.3522 } as GeoPoint,
  };
}

/** Compare two floats the way typed_test.py does: through their f32 bits. */
function sameFloat32(a: number, b: number): boolean {
  const x = new DataView(new ArrayBuffer(4));
  const y = new DataView(new ArrayBuffer(4));
  x.setFloat32(0, a, true);
  y.setFloat32(0, b, true);
  return x.getUint32(0, true) === y.getUint32(0, true);
}

function validateMessage(msg: SensorReading): string[] {
  const errs: string[] = [];
  if (msg.sensor_id !== 42) errs.push(`sensor_id: got ${msg.sensor_id}, want 42`);
  if (msg.kind !== SensorKind.PRESSURE)
    errs.push(`kind: got ${msg.kind}, want PRESSURE`);
  if (!sameFloat32(msg.value, 3.15))
    errs.push(`value: got ${msg.value}, want 3.15f`);
  if (msg.label !== "test-sensor")
    errs.push(`label: got ${JSON.stringify(msg.label)}, want 'test-sensor'`);
  if (msg.timestamp_ns !== 1700000000000000000n)
    errs.push(`timestamp_ns: got ${msg.timestamp_ns}`);
  if (msg.history.length !== 3) {
    errs.push(`history len: got ${msg.history.length}, want 3`);
  } else {
    [1.0, 2.0, 3.0].forEach((want, i) => {
      if (!sameFloat32(msg.history[i]!, want))
        errs.push(`history[${i}]: got ${msg.history[i]}, want ${want}`);
    });
  }
  if (msg.error_code !== 7)
    errs.push(`error_code: got ${msg.error_code}, want 7`);
  if (Math.abs(msg.location.latitude - 48.8566) > 1e-10)
    errs.push(`latitude: got ${msg.location.latitude}`);
  if (Math.abs(msg.location.longitude - 2.3522) > 1e-10)
    errs.push(`longitude: got ${msg.location.longitude}`);
  return errs;
}

function createKeyedMessage(): KeyedSample {
  return {
    id: 99,
    active: true,
    kind: SensorKind.HUMIDITY,
    name: "device-alpha",
    origin: { latitude: 37.7749, longitude: -122.4194 } as GeoPoint,
    reading: 1.618,
  };
}

function validateKeyedMessage(msg: KeyedSample): string[] {
  const errs: string[] = [];
  if (msg.id !== 99) errs.push(`id: got ${msg.id}, want 99`);
  if (msg.active !== true) errs.push(`active: got ${msg.active}, want true`);
  if (msg.kind !== SensorKind.HUMIDITY)
    errs.push(`kind: got ${msg.kind}, want HUMIDITY`);
  if (msg.name !== "device-alpha")
    errs.push(`name: got ${JSON.stringify(msg.name)}, want 'device-alpha'`);
  if (Math.abs(msg.origin.latitude - 37.7749) > 1e-10)
    errs.push(`origin.latitude: got ${msg.origin.latitude}`);
  if (Math.abs(msg.origin.longitude - -122.4194) > 1e-10)
    errs.push(`origin.longitude: got ${msg.origin.longitude}`);
  if (!sameFloat32(msg.reading, 1.618))
    errs.push(`reading: got ${msg.reading}, want 1.618`);
  return errs;
}

function isKeyedTopic(topic: string): boolean {
  return topic.startsWith("Keyed");
}

function encodeFor(topic: string): Buffer {
  return isKeyedTopic(topic)
    ? encodeCdr2Le(encodeKeyedSample as never, createKeyedMessage())
    : encodeCdr2Le(encodeSensorReading as never, createTestMessage());
}

function runVector(topic: string): number {
  console.log(encodeFor(topic).toString("hex"));
  return 0;
}

async function runPub(topic: string, count: number): Promise<number> {
  const participant = Participant.create("typed_ts_pub");
  try {
    const qos = QoS.reliable().transientLocal().historyDepth(count + 5);
    const writer = participant.createWriter(topic, qos);

    await sleep(300);

    for (let i = 0; i < count; i += 1) {
      writer.write(Buffer.concat([ENCAP_CDR2_LE, encodeFor(topic)]));
    }

    await sleep(2000);
    return 0;
  } finally {
    participant.dispose();
  }
}

function runSub(topic: string, count: number): number {
  const participant = Participant.create("typed_ts_sub");
  const received: Buffer[] = [];
  try {
    const qos = QoS.reliable().transientLocal().historyDepth(count + 5);
    const reader = participant.createReader(topic, qos);

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

  const keyed = isKeyedTopic(topic);
  let ok = true;
  received.forEach((raw, i) => {
    if (raw.length < 4) {
      console.error(`FAIL: sample ${i} too short (${raw.length} bytes)`);
      ok = false;
      return;
    }
    const body = new Cdr2Buffer(new Uint8Array(raw.subarray(4)));
    let errs: string[];
    try {
      errs = keyed
        ? validateKeyedMessage(decodeKeyedSample(body))
        : validateMessage(decodeSensorReading(body));
    } catch (e) {
      console.error(`FAIL: decode error at sample ${i}: ${String(e)}`);
      ok = false;
      return;
    }
    for (const err of errs) {
      console.error(`FAIL: sample ${i}: ${err}`);
      ok = false;
    }
  });

  if (ok && received.length === count) {
    console.log(`OK: received ${count}/${count} samples`);
    return 0;
  }
  console.error(`FAIL: received ${received.length}/${count} samples`);
  return 1;
}

// The SDK as an application uses it: the body, labelled with the type's
// extensibility (APPENDABLE); a reader told the generated module, which
// decodes XCDR1 (HDDS_DECODES_XCDR1), requests XCDR and XCDR2 and decodes
// by the sample's representation. A default Rust writer offers XCDR only, so
// a sample received from it is an XCDR1 sample decoded as XCDR1.
async function runPubDefault(topic: string, count: number): Promise<number> {
  const participant = Participant.create("typed_ts_pub_default");
  try {
    const qos = QoS.reliable().transientLocal().historyDepth(count + 5);
    const writer = participant.createWriter(topic, qos, null, extensibilitySensorReading);
    await sleep(300);
    for (let i = 0; i < count; i += 1) {
      writer.write(encodeFor(topic));
    }
    await sleep(2000);
    return 0;
  } finally {
    participant.dispose();
  }
}

async function runSubDefault(topic: string, count: number): Promise<number> {
  if (generated.HDDS_DECODES_XCDR1 !== true) {
    console.error("FAIL: the generated module does not decode XCDR1");
    return 1;
  }
  const participant = Participant.create("typed_ts_sub_default");
  const received: SensorReading[] = [];
  try {
    const qos = QoS.reliable().transientLocal().historyDepth(count + 5);
    const reader = participant.createReader(topic, qos, null, generated);
    const deadline = Date.now() + 10_000;
    while (received.length < count && Date.now() < deadline) {
      const msg = reader.takeTyped(decodeSensorReadingByEncapsulation);
      if (msg === null) {
        await sleep(50);
      } else {
        received.push(msg);
      }
    }
  } finally {
    participant.dispose();
  }
  let ok = true;
  received.forEach((msg, i) => {
    for (const err of validateMessage(msg)) {
      console.error(`FAIL: sample ${i}: ${err}`);
      ok = false;
    }
  });
  if (ok && received.length === count) {
    console.log(`OK: received ${count}/${count} samples`);
    return 0;
  }
  console.error(`FAIL: received ${received.length}/${count} samples`);
  return 1;
}

// Extensibility lanes: FinalProbe, SensorReading (APPENDABLE), MutableProbe.
const PROBE_ID = 7;
const PROBE_LABEL = "ext-probe";

interface ExtLane {
  extensibility: "final" | "appendable" | "mutable";
  body: Buffer;
  decode: (id: number, data: Uint8Array) => string[];
}

function probeErrs(msg: FinalProbe | MutableProbe): string[] {
  return msg.id === PROBE_ID && msg.label === PROBE_LABEL
    ? []
    : [`got (${msg.id}, ${JSON.stringify(msg.label)})`];
}

function extLane(topic: string): ExtLane | null {
  const probe = { id: PROBE_ID, label: PROBE_LABEL };
  if (topic.startsWith("ExtFinal")) {
    return {
      extensibility: extensibilityFinalProbe,
      body: encodeCdr2Le(encodeFinalProbe as never, probe),
      decode: (id, data) => probeErrs(decodeFinalProbeByEncapsulation(id, data)),
    };
  }
  if (topic.startsWith("ExtMutable")) {
    return {
      extensibility: extensibilityMutableProbe,
      body: encodeCdr2Le(encodeMutableProbe as never, probe),
      decode: (id, data) => probeErrs(decodeMutableProbeByEncapsulation(id, data)),
    };
  }
  if (topic.startsWith("ExtAppendable")) {
    return {
      extensibility: extensibilitySensorReading,
      body: encodeCdr2Le(encodeSensorReading as never, createTestMessage()),
      decode: (id, data) => validateMessage(decodeSensorReadingByEncapsulation(id, data)),
    };
  }
  return null;
}

async function runPubExt(topic: string, count: number): Promise<number> {
  const lane = extLane(topic);
  if (lane === null) {
    console.error("pub-ext: not an Ext* topic");
    return 1;
  }
  const participant = Participant.create("typed_ts_pub_ext");
  try {
    const qos = QoS.reliable().transientLocal().historyDepth(count + 5);
    const writer = participant.createWriter(topic, qos, null, lane.extensibility);
    await sleep(300);
    for (let i = 0; i < count; i += 1) {
      writer.write(lane.body);
    }
    await sleep(2000);
    return 0;
  } finally {
    participant.dispose();
  }
}

async function runSubExt(topic: string, count: number): Promise<number> {
  const lane = extLane(topic);
  if (lane === null) {
    console.error("sub-ext: not an Ext* topic");
    return 1;
  }
  const participant = Participant.create("typed_ts_sub_ext");
  const errs: string[] = [];
  let received = 0;
  try {
    const qos = QoS.reliable().transientLocal().historyDepth(count + 5);
    const reader = participant.createReader(topic, qos, null, generated);
    const deadline = Date.now() + 10_000;
    while (received < count && Date.now() < deadline) {
      const got = reader.takeTyped((id: number, data: Uint8Array) => lane.decode(id, data));
      if (got === null) {
        await sleep(50);
      } else {
        received += 1;
        errs.push(...got);
      }
    }
  } finally {
    participant.dispose();
  }
  for (const e of errs) {
    console.error(`FAIL: ${e}`);
  }
  if (errs.length === 0 && received === count) {
    console.log(`OK: received ${count}/${count} samples`);
    return 0;
  }
  console.error(`FAIL: received ${received}/${count} samples`);
  return 1;
}

async function main(): Promise<number> {
  if (process.argv.length !== 5) {
    console.error("Usage: node typed_test.js <pub|sub|vector> <topic> <count>");
    return 1;
  }
  const mode = process.argv[2]!;
  const topic = process.argv[3]!;
  const count = Number(process.argv[4]);

  if (mode === "pub") return runPub(topic, count);
  if (mode === "sub") return runSub(topic, count);
  if (mode === "vector") return runVector(topic);
  if (mode === "pub-default") return runPubDefault(topic, count);
  if (mode === "sub-default") return runSubDefault(topic, count);
  if (mode === "pub-ext") return runPubExt(topic, count);
  if (mode === "sub-ext") return runSubExt(topic, count);
  console.error(`Unknown mode: ${mode}`);
  return 1;
}

main().then((code) => process.exit(code));
