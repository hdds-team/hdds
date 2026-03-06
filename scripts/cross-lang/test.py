#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""Cross-language test helper: Python pub/sub.

Usage:
    python test.py pub <topic> <count>
    python test.py sub <topic> <count>
"""

import sys
import os
import time

# Add SDK to path
SDK_ROOT = os.path.join(os.path.dirname(__file__), '..', '..', 'sdk', 'python')
sys.path.insert(0, SDK_ROOT)

import hdds


PAYLOAD_PREFIX = b"XTEST-"


def run_pub(topic, count):
    with hdds.Participant("xtest_py_pub") as p:
        qos = hdds.QoS.reliable().transient_local().history_depth(count + 5)
        writer = p.create_writer(topic, qos=qos, type_name="RawBytes")

        # Let discovery happen
        time.sleep(0.3)

        for i in range(count):
            payload = PAYLOAD_PREFIX + str(i).encode()
            writer.write(payload)

        # Keep alive for late joiners
        time.sleep(2.0)

    return 0


def run_sub(topic, count):
    with hdds.Participant("xtest_py_sub") as p:
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
    ok = True
    for i in range(count):
        expected = PAYLOAD_PREFIX + str(i).encode()
        if i < len(received):
            if received[i] != expected:
                print(f"MISMATCH at {i}: got {received[i]!r}, want {expected!r}",
                      file=sys.stderr)
                ok = False
        else:
            print(f"MISSING sample {i}", file=sys.stderr)
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
