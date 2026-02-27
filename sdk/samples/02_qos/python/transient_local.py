#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: Transient Local (Python)

Demonstrates TRANSIENT_LOCAL durability for late-joiner support.
New subscribers receive historical data from publishers' cache.

Usage:
    python transient_local.py        # Late subscriber (joins after pub)
    python transient_local.py pub    # Publisher (publishes and waits)
"""

import sys
import time
import signal

sys.path.insert(0, str(__file__ + "/../../01_basics/python"))

import hdds
from generated.HelloWorld import HelloWorld

NUM_MESSAGES = 5
running = True


def signal_handler(sig, frame):
    global running
    running = False


def run_publisher(participant):
    """Publish messages with TRANSIENT_LOCAL QoS."""
    qos = hdds.QoS.reliable().transient_local().history_depth(NUM_MESSAGES)
    writer = participant.create_writer("TransientTopic", qos=qos)

    print(f"Publishing {NUM_MESSAGES} messages with TRANSIENT_LOCAL QoS...\n")

    for i in range(NUM_MESSAGES):
        msg = HelloWorld(id=i + 1, message=f"Historical data #{i + 1}")
        writer.write(msg.serialize())
        print(f"  [CACHED] id={msg.id} msg='{msg.message}'")

    print("\nAll messages cached. Waiting for late-joining subscribers...")
    print("(Run 'python transient_local.py' in another terminal to see late-join)")
    print("Press Ctrl+C to exit.")

    signal.signal(signal.SIGINT, signal_handler)
    while running:
        time.sleep(1)


def run_subscriber(participant):
    """Receive historical messages as late-joiner."""
    print("Creating TRANSIENT_LOCAL subscriber (late-joiner)...")
    print("If publisher ran first, we should receive cached historical data.\n")

    qos = hdds.QoS.reliable().transient_local()
    reader = participant.create_reader("TransientTopic", qos=qos)

    waitset = hdds.WaitSet()
    waitset.attach(reader)

    print("Waiting for historical data...\n")

    received = 0
    timeouts = 0

    while timeouts < 2:
        if waitset.wait(timeout_secs=3.0):
            while True:
                data = reader.take()
                if data is None:
                    break
                msg = HelloWorld.deserialize(data)
                print(f"  [HISTORICAL] id={msg.id} msg='{msg.message}'")
                received += 1
            timeouts = 0
        else:
            timeouts += 1

    if received > 0:
        print(f"\nReceived {received} historical messages via TRANSIENT_LOCAL!")
        print("Late-joiners automatically get cached data.")
    else:
        print("\nNo historical data received. Start publisher first:")
        print("  python transient_local.py pub")


def main():
    is_publisher = len(sys.argv) > 1 and sys.argv[1] == "pub"

    hdds.logging.init(hdds.LogLevel.INFO)

    print("=" * 60)
    print("Transient Local Demo")
    print("QoS: TRANSIENT_LOCAL - late-joiners receive historical data")
    print("=" * 60)

    with hdds.Participant("TransientLocalDemo") as participant:
        if is_publisher:
            run_publisher(participant)
        else:
            run_subscriber(participant)


if __name__ == "__main__":
    main()
