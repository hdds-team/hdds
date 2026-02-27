#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: Liveliness Automatic (Python)

Demonstrates AUTOMATIC liveliness - system automatically asserts
liveliness via heartbeats. Reader detects when writer goes offline.

Usage:
    python liveliness_auto.py        # Subscriber (monitors liveliness)
    python liveliness_auto.py pub    # Publisher (sends periodic data)
"""

import sys
import time

sys.path.insert(0, str(__file__ + "/../../01_basics/python"))

import hdds
from generated.HelloWorld import HelloWorld

LEASE_DURATION_MS = 1000  # 1 second lease
NUM_MESSAGES = 8


def run_publisher(participant):
    """Publish with AUTOMATIC liveliness."""
    qos = hdds.QoS.reliable().liveliness_automatic(LEASE_DURATION_MS / 1000.0)
    writer = participant.create_writer("LivelinessTopic", qos=qos)

    print(f"Publishing with AUTOMATIC liveliness (lease: {LEASE_DURATION_MS}ms)")
    print("System automatically sends heartbeats to maintain liveliness.\n")

    start = time.monotonic()

    for i in range(NUM_MESSAGES):
        msg = HelloWorld(id=i + 1, message=f"Heartbeat #{i + 1}")
        writer.write(msg.serialize())

        elapsed = int((time.monotonic() - start) * 1000)
        print(f"  [{elapsed}ms] Published id={msg.id} - writer is ALIVE")

        time.sleep(0.4)  # 400ms - faster than lease

    print("\nPublisher going offline. Subscriber should detect liveliness lost.")


def run_subscriber(participant):
    """Monitor AUTOMATIC liveliness."""
    qos = hdds.QoS.reliable().liveliness_automatic(LEASE_DURATION_MS / 1000.0)
    reader = participant.create_reader("LivelinessTopic", qos=qos)

    waitset = hdds.WaitSet()
    waitset.attach(reader)

    print(f"Monitoring AUTOMATIC liveliness (lease: {LEASE_DURATION_MS}ms)...")
    print("Will detect if writer goes offline.\n")

    received = 0
    liveliness_lost_count = 0
    start = time.monotonic()
    last_msg = start

    while received < NUM_MESSAGES + 2:
        if waitset.wait(timeout_secs=LEASE_DURATION_MS * 2 / 1000.0):
            while True:
                data = reader.take()
                if data is None:
                    break

                msg = HelloWorld.deserialize(data)
                elapsed = int((time.monotonic() - start) * 1000)
                print(f"  [{elapsed}ms] Received id={msg.id} - writer ALIVE")

                last_msg = time.monotonic()
                received += 1
        else:
            now = time.monotonic()
            elapsed = int((now - start) * 1000)
            since_last = int((now - last_msg) * 1000)

            if since_last > LEASE_DURATION_MS:
                print(f"  [{elapsed}ms] LIVELINESS LOST - no heartbeat for {since_last}ms!")
                liveliness_lost_count += 1

                if liveliness_lost_count >= 2:
                    break

    print()
    print("-" * 60)
    print(f"Summary: {received} messages, liveliness lost {liveliness_lost_count} times")
    print("-" * 60)


def main():
    is_publisher = len(sys.argv) > 1 and sys.argv[1] == "pub"

    hdds.logging.init(hdds.LogLevel.INFO)

    print("=" * 60)
    print("Liveliness Automatic Demo")
    print("QoS: AUTOMATIC liveliness - system heartbeats")
    print("=" * 60)

    with hdds.Participant("LivelinessAutoDemo") as participant:
        if is_publisher:
            run_publisher(participant)
        else:
            run_subscriber(participant)


if __name__ == "__main__":
    main()
