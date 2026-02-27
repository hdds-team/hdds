#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: Deadline Monitor (Python)

Demonstrates DEADLINE QoS for monitoring update rates.
Publisher must send data within deadline or violation is reported.

Usage:
    python deadline_monitor.py        # Subscriber (monitors deadline)
    python deadline_monitor.py pub    # Publisher (normal rate)
    python deadline_monitor.py slow   # Publisher (misses deadlines)
"""

import sys
import time

sys.path.insert(0, str(__file__ + "/../../01_basics/python"))

import hdds
from generated.HelloWorld import HelloWorld

DEADLINE_MS = 500  # 500ms deadline period
NUM_MESSAGES = 10


def run_publisher(participant, slow_mode):
    """Publish messages at specified rate."""
    qos = hdds.QoS.reliable().deadline_ms(DEADLINE_MS)
    writer = participant.create_writer("DeadlineTopic", qos=qos)

    interval_ms = 800 if slow_mode else 300

    print(f"Publishing with {interval_ms}ms interval (deadline: {DEADLINE_MS}ms)")
    if slow_mode:
        print("WARNING: This will MISS deadlines!")
    else:
        print("This should meet all deadlines.")
    print()

    start = time.monotonic()

    for i in range(NUM_MESSAGES):
        msg = HelloWorld(id=i + 1, message=f"Update #{i + 1}")
        writer.write(msg.serialize())

        elapsed = int((time.monotonic() - start) * 1000)
        print(f"  [{elapsed:5d}ms] Sent id={msg.id}")

        time.sleep(interval_ms / 1000.0)

    print("\nDone publishing.")


def run_subscriber(participant):
    """Monitor for deadline violations."""
    qos = hdds.QoS.reliable().deadline_ms(DEADLINE_MS)
    reader = participant.create_reader("DeadlineTopic", qos=qos)

    waitset = hdds.WaitSet()
    waitset.attach(reader)

    print(f"Monitoring for deadline violations (deadline: {DEADLINE_MS}ms)...\n")

    received = 0
    deadline_violations = 0
    start = time.monotonic()
    last_recv = start

    while received < NUM_MESSAGES:
        if waitset.wait(timeout_secs=DEADLINE_MS * 2 / 1000.0):
            while True:
                data = reader.take()
                if data is None:
                    break

                msg = HelloWorld.deserialize(data)
                now = time.monotonic()
                elapsed = int((now - start) * 1000)
                delta = int((now - last_recv) * 1000)

                status = "DEADLINE MISSED!" if (delta > DEADLINE_MS and received > 0) else "OK"

                if delta > DEADLINE_MS and received > 0:
                    deadline_violations += 1

                print(f"  [{elapsed:5d}ms] Received id={msg.id} (delta={delta}ms) {status}")

                last_recv = now
                received += 1
        else:
            elapsed = int((time.monotonic() - start) * 1000)
            print(f"  [{elapsed:5d}ms] DEADLINE VIOLATION - no data received!")
            deadline_violations += 1

    print()
    print("-" * 60)
    print(f"Summary: {received} messages received, {deadline_violations} deadline violations")
    print("-" * 60)


def main():
    is_publisher = len(sys.argv) > 1 and sys.argv[1] == "pub"
    slow_mode = len(sys.argv) > 1 and sys.argv[1] == "slow"

    hdds.logging.init(hdds.LogLevel.INFO)

    print("=" * 60)
    print("Deadline Monitor Demo")
    print("QoS: DEADLINE - monitor update rate violations")
    print("=" * 60)

    with hdds.Participant("DeadlineDemo") as participant:
        if is_publisher or slow_mode:
            run_publisher(participant, slow_mode)
        else:
            run_subscriber(participant)


if __name__ == "__main__":
    main()
