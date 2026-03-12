#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""Typed cross-language test: Python pub/sub with generated CDR2 types.

Usage:
    python typed_test.py pub <topic> <count>
    python typed_test.py sub <topic> <count>

Dispatches on topic name:
  - Topics starting with 'Keyed' use KeyedSample (tests @key edge cases)
  - All other topics use SensorReading (baseline)

The publisher creates messages with deterministic values, encodes to CDR2,
prepends the 4-byte encapsulation header (CDR2 LE), and writes the raw
payload via hdds. The subscriber reads raw, strips the encap header,
decodes CDR2, and validates all fields.
"""

import sys
import os
import time
import struct

# Add SDK to path
SDK_ROOT = os.path.join(os.path.dirname(__file__), '..', '..', 'sdk', 'python')
sys.path.insert(0, SDK_ROOT)

# Generated types path (set by test script via TYPED_TEST_TYPES env)
TYPES_PATH = os.environ.get('TYPED_TEST_TYPES', os.path.dirname(__file__))
sys.path.insert(0, TYPES_PATH)

import hdds
from interop_types import SensorReading, SensorKind, GeoPoint, KeyedSample

# CDR2 LE encapsulation header: [0x00, 0x01, 0x00, 0x00]
ENCAP_CDR2_LE = b'\x00\x01\x00\x00'


def create_test_message():
    return SensorReading(
        sensor_id=42,
        kind=SensorKind.PRESSURE,
        value=3.15,
        label="test-sensor",
        timestamp_ns=1700000000000000000,
        history=[1.0, 2.0, 3.0],
        error_code=7,
        location=GeoPoint(latitude=48.8566, longitude=2.3522)
    )


def validate_message(msg):
    errs = []
    if msg.sensor_id != 42:
        errs.append(f"sensor_id: got {msg.sensor_id}, want 42")
    if msg.kind != SensorKind.PRESSURE:
        errs.append(f"kind: got {msg.kind}, want PRESSURE")
    if struct.pack('<f', msg.value) != struct.pack('<f', 3.15):
        errs.append(f"value: got {msg.value}, want 3.15f")
    if msg.label != "test-sensor":
        errs.append(f"label: got {msg.label!r}, want 'test-sensor'")
    if msg.timestamp_ns != 1700000000000000000:
        errs.append(f"timestamp_ns: got {msg.timestamp_ns}")
    if len(msg.history) != 3:
        errs.append(f"history len: got {len(msg.history)}, want 3")
    else:
        for i, (got, want) in enumerate(zip(msg.history, [1.0, 2.0, 3.0])):
            if struct.pack('<f', got) != struct.pack('<f', want):
                errs.append(f"history[{i}]: got {got}, want {want}")
    if msg.error_code != 7:
        errs.append(f"error_code: got {msg.error_code}, want 7")
    if abs(msg.location.latitude - 48.8566) > 1e-10:
        errs.append(f"latitude: got {msg.location.latitude}")
    if abs(msg.location.longitude - 2.3522) > 1e-10:
        errs.append(f"longitude: got {msg.location.longitude}")
    return errs


def create_keyed_message():
    return KeyedSample(
        id=99,
        active=True,
        kind=SensorKind.HUMIDITY,
        name="device-alpha",
        origin=GeoPoint(latitude=37.7749, longitude=-122.4194),
        reading=1.618
    )


def validate_keyed_message(msg):
    errs = []
    if msg.id != 99:
        errs.append(f"id: got {msg.id}, want 99")
    if msg.active is not True:
        errs.append(f"active: got {msg.active}, want True")
    if msg.kind != SensorKind.HUMIDITY:
        errs.append(f"kind: got {msg.kind}, want HUMIDITY")
    if msg.name != "device-alpha":
        errs.append(f"name: got {msg.name!r}, want 'device-alpha'")
    if abs(msg.origin.latitude - 37.7749) > 1e-10:
        errs.append(f"origin.latitude: got {msg.origin.latitude}")
    if abs(msg.origin.longitude - (-122.4194)) > 1e-10:
        errs.append(f"origin.longitude: got {msg.origin.longitude}")
    if struct.pack('<f', msg.reading) != struct.pack('<f', 1.618):
        errs.append(f"reading: got {msg.reading}, want 1.618")
    return errs


def is_keyed_topic(topic):
    return topic.startswith("Keyed")


def run_pub(topic, count):
    with hdds.Participant("typed_py_pub") as p:
        qos = hdds.QoS.reliable().transient_local().history_depth(count + 5)
        writer = p.create_writer(topic, qos=qos, type_name="RawBytes")

        time.sleep(0.3)

        create_fn = create_keyed_message if is_keyed_topic(topic) else create_test_message
        for i in range(count):
            msg = create_fn()
            cdr2_bytes = msg.encode_cdr2_le()
            payload = ENCAP_CDR2_LE + cdr2_bytes
            writer.write(payload)

        time.sleep(2.0)
    return 0


def run_sub(topic, count):
    with hdds.Participant("typed_py_sub") as p:
        qos = hdds.QoS.reliable().transient_local().history_depth(count + 5)
        reader = p.create_reader(topic, qos=qos, type_name="RawBytes")

        ws = hdds.WaitSet()
        ws.attach_reader(reader)

        received = []
        deadline = time.monotonic() + 10.0

        while len(received) < count and time.monotonic() < deadline:
            if ws.wait(timeout=1.0):
                while True:
                    data = reader.take()
                    if data is None:
                        break
                    received.append(data)

        ws.close()

    # Validate
    keyed = is_keyed_topic(topic)
    decode_type = KeyedSample if keyed else SensorReading
    validate_fn = validate_keyed_message if keyed else validate_message

    ok = True
    for i, raw in enumerate(received):
        if len(raw) < 4:
            print(f"FAIL: sample {i} too short ({len(raw)} bytes)", file=sys.stderr)
            ok = False
            continue

        cdr2_bytes = raw[4:]  # strip encap header
        try:
            msg, _ = decode_type.decode_cdr2_le(cdr2_bytes)
        except Exception as e:
            print(f"FAIL: decode error at sample {i}: {e}", file=sys.stderr)
            ok = False
            continue

        errs = validate_fn(msg)
        if errs:
            for e in errs:
                print(f"FAIL: sample {i}: {e}", file=sys.stderr)
            ok = False

    if ok and len(received) == count:
        print(f"OK: received {count}/{count} samples")
        return 0
    else:
        print(f"FAIL: received {len(received)}/{count} samples", file=sys.stderr)
        return 1


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 1

    mode = sys.argv[1]
    topic = sys.argv[2]
    count = int(sys.argv[3])

    if mode == "pub":
        return run_pub(topic, count)
    elif mode == "sub":
        return run_sub(topic, count)
    else:
        print(f"Unknown mode: {mode}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
