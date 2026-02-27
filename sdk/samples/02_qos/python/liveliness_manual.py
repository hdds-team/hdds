#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: Liveliness Manual (Python)

Demonstrates MANUAL_BY_PARTICIPANT liveliness - application must
explicitly assert liveliness. Useful for detecting app-level failures.

Usage:
    python liveliness_manual.py        # Subscriber (monitors liveliness)
    python liveliness_manual.py pub    # Publisher (with manual assertion)
"""

import sys
import time

sys.path.insert(0, str(__file__ + "/../../01_basics/python"))

import hdds
from generated.HelloWorld import HelloWorld

LEASE_DURATION_MS = 2000  # 2 second lease
NUM_MESSAGES = 6


def run_publisher(participant):
    """Publish with MANUAL_BY_PARTICIPANT liveliness."""
    qos = hdds.QoS.reliable().liveliness_manual_participant(LEASE_DURATION_MS / 1000.0)
    writer = participant.create_writer("ManualLivenessTopic", qos=qos)

    print(f"Publishing with MANUAL_BY_PARTICIPANT liveliness (lease: {LEASE_DURATION_MS}ms)")
    print("Application must explicitly assert liveliness.\n")

    start = time.monotonic()

    for i in range(NUM_MESSAGES):
        msg = HelloWorld(id=i + 1, message=f"Manual update #{i + 1}")

        # Writing data implicitly asserts liveliness
        writer.write(msg.serialize())

        elapsed = int((time.monotonic() - start) * 1000)
        print(f"  [{elapsed}ms] Published id={msg.id} (liveliness asserted via write)")

        # First 3 messages: normal rate
        # Last 3 messages: slow rate (will miss liveliness)
        if i < 3:
            time.sleep(0.5)  # 500ms - OK
        else:
            print("  (simulating slow processing...)")
            time.sleep(2.5)  # 2.5s - exceeds lease!

    print("\nPublisher done. Some liveliness violations occurred.")


def run_subscriber(participant):
    """Monitor MANUAL_BY_PARTICIPANT liveliness."""
    qos = hdds.QoS.reliable().liveliness_manual_participant(LEASE_DURATION_MS / 1000.0)
    reader = participant.create_reader("ManualLivenessTopic", qos=qos)

    waitset = hdds.WaitSet()
    waitset.attach(reader)

    print(f"Monitoring MANUAL_BY_PARTICIPANT liveliness (lease: {LEASE_DURATION_MS}ms)...")
    print("Writer must assert liveliness explicitly (by writing).\n")

    received = 0
    liveliness_changed = 0
    start = time.monotonic()
    last_msg = start

    while received < NUM_MESSAGES or liveliness_changed < 3:
        if waitset.wait(timeout_secs=LEASE_DURATION_MS / 1000.0):
            while True:
                data = reader.take()
                if data is None:
                    break

                msg = HelloWorld.deserialize(data)
                now = time.monotonic()
                elapsed = int((now - start) * 1000)
                delta = int((now - last_msg) * 1000)

                status = " [LIVELINESS WAS LOST]" if (delta > LEASE_DURATION_MS and received > 0) else ""

                print(f"  [{elapsed}ms] Received id={msg.id} (delta={delta}ms){status}")

                last_msg = now
                received += 1
        else:
            now = time.monotonic()
            elapsed = int((now - start) * 1000)
            since_last = int((now - last_msg) * 1000)

            if since_last > LEASE_DURATION_MS and received > 0:
                print(f"  [{elapsed}ms] LIVELINESS LOST! (no assertion for {since_last}ms)")
                liveliness_changed += 1

            if liveliness_changed >= 3:
                break

    print()
    print("-" * 60)
    print(f"Summary: {received} messages, {liveliness_changed} liveliness events detected")
    print("MANUAL liveliness requires explicit app-level assertion.")
    print("-" * 60)


def main():
    is_publisher = len(sys.argv) > 1 and sys.argv[1] == "pub"

    hdds.logging.init(hdds.LogLevel.INFO)

    print("=" * 60)
    print("Liveliness Manual Demo")
    print("QoS: MANUAL_BY_PARTICIPANT - app must assert liveliness")
    print("=" * 60)

    with hdds.Participant("LivelinessManualDemo") as participant:
        if is_publisher:
            run_publisher(participant)
        else:
            run_subscriber(participant)


if __name__ == "__main__":
    main()
