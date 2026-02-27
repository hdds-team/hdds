#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: Time-Based Filter (Python)

Demonstrates TIME_BASED_FILTER QoS for reader-side minimum separation.
Reader A receives all messages. Reader B uses a 500ms filter,
so it only receives samples at most once every 500ms.

This sample runs in single-process mode (no pub/sub arguments).

Usage:
    python time_based_filter.py
"""

import sys
import time

sys.path.insert(0, str(__file__ + "/../../01_basics/python"))

import hdds
from generated.HelloWorld import HelloWorld

NUM_MESSAGES = 20
PUBLISH_INTERVAL_MS = 100  # 100ms between messages
FILTER_MS = 500  # 500ms minimum separation


def main():
    hdds.logging.init(hdds.LogLevel.INFO)

    print("=" * 60)
    print("Time-Based Filter Demo")
    print("QoS: TIME_BASED_FILTER - reader-side minimum separation")
    print("=" * 60)

    with hdds.Participant("TimeFilterDemo") as participant:
        # --- Writer ---
        writer_qos = hdds.QoS.best_effort()
        writer = participant.create_writer("FilteredTopic", qos=writer_qos)

        # --- Reader A: no filter (receives all) ---
        qos_all = hdds.QoS.best_effort()
        reader_all = participant.create_reader("FilteredTopic", qos=qos_all)

        # --- Reader B: 500ms time-based filter ---
        qos_filtered = hdds.QoS.best_effort().time_based_filter_ms(FILTER_MS)
        reader_filtered = participant.create_reader("FilteredTopic", qos=qos_filtered)

        waitset_all = hdds.WaitSet()
        waitset_all.attach(reader_all)

        waitset_filtered = hdds.WaitSet()
        waitset_filtered.attach(reader_filtered)

        print(f"\nPublishing {NUM_MESSAGES} messages at {PUBLISH_INTERVAL_MS}ms intervals...")
        print(f"Reader A: no filter (expects all {NUM_MESSAGES} messages)")
        print(f"Reader B: {FILTER_MS}ms filter (expects ~{int(NUM_MESSAGES * PUBLISH_INTERVAL_MS / FILTER_MS)} messages)\n")

        # --- Publish all messages ---
        start = time.monotonic()

        for i in range(NUM_MESSAGES):
            msg = HelloWorld(id=i + 1, message=f"Sample #{i + 1}")
            writer.write(msg.serialize())

            elapsed = int((time.monotonic() - start) * 1000)
            print(f"  [{elapsed:5d}ms] Sent id={msg.id}")

            time.sleep(PUBLISH_INTERVAL_MS / 1000.0)

        # --- Give readers time to process ---
        print("\nWaiting for readers to process...\n")
        time.sleep(0.5)

        # --- Drain Reader A ---
        received_all = 0
        while True:
            if not waitset_all.wait(timeout_secs=0.5):
                break
            while True:
                data = reader_all.take()
                if data is None:
                    break
                msg = HelloWorld.deserialize(data)
                received_all += 1

        # --- Drain Reader B ---
        received_filtered = 0
        while True:
            if not waitset_filtered.wait(timeout_secs=0.5):
                break
            while True:
                data = reader_filtered.take()
                if data is None:
                    break
                msg = HelloWorld.deserialize(data)
                received_filtered += 1

        # --- Results ---
        print("-" * 60)
        print(f"Reader A (no filter):       {received_all:3d} messages received")
        print(f"Reader B ({FILTER_MS}ms filter):   {received_filtered:3d} messages received")
        print()
        print(f"Total sent: {NUM_MESSAGES} messages over "
              f"{NUM_MESSAGES * PUBLISH_INTERVAL_MS}ms")
        print(f"Filter reduced delivery by ~{100 - int(received_filtered / max(received_all, 1) * 100)}%")
        print("-" * 60)


if __name__ == "__main__":
    main()
