#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: Ownership Exclusive (Python)

Demonstrates EXCLUSIVE ownership with strength-based arbitration.
Only the writer with highest strength publishes to a topic.

Usage:
    python ownership_exclusive.py             # Subscriber
    python ownership_exclusive.py pub 100     # Publisher with strength 100
    python ownership_exclusive.py pub 200     # Publisher with strength 200 (wins)
"""

import sys
import time
import signal

sys.path.insert(0, str(__file__ + "/../../01_basics/python"))

import hdds
from generated.HelloWorld import HelloWorld

running = True


def signal_handler(sig, frame):
    global running
    running = False


def run_publisher(participant, strength):
    """Publish with EXCLUSIVE ownership."""
    qos = hdds.QoS.reliable().ownership_exclusive(strength)
    writer = participant.create_writer("OwnershipTopic", qos=qos)

    print(f"Publishing with EXCLUSIVE ownership (strength: {strength})")
    print("Higher strength wins ownership. Start another publisher with different strength.\n")

    signal.signal(signal.SIGINT, signal_handler)

    seq = 0
    while running:
        msg = HelloWorld(id=strength, message=f"Writer[{strength}] seq={seq}")
        writer.write(msg.serialize())
        print(f"  [PUBLISHED strength={strength}] seq={seq}")

        seq += 1
        time.sleep(0.5)

    print(f"\nPublisher (strength={strength}) shutting down.")


def run_subscriber(participant):
    """Subscribe with EXCLUSIVE ownership."""
    qos = hdds.QoS.reliable().ownership_exclusive(0)  # Strength doesn't matter for reader
    reader = participant.create_reader("OwnershipTopic", qos=qos)

    waitset = hdds.WaitSet()
    waitset.attach(reader)

    print("Subscribing with EXCLUSIVE ownership...")
    print("Only data from the highest-strength writer will be received.\n")

    signal.signal(signal.SIGINT, signal_handler)

    last_owner = -1

    while running:
        if waitset.wait(timeout_secs=1.0):
            while True:
                data = reader.take()
                if data is None:
                    break

                msg = HelloWorld.deserialize(data)

                if msg.id != last_owner:
                    print(f"\n  ** OWNERSHIP CHANGED to writer with strength={msg.id} **\n")
                    last_owner = msg.id

                print(f"  [RECV from strength={msg.id}] {msg.message}")

    print("\nSubscriber shutting down.")


def main():
    is_publisher = len(sys.argv) > 1 and sys.argv[1] == "pub"
    strength = int(sys.argv[2]) if len(sys.argv) > 2 else 100

    hdds.logging.init(hdds.LogLevel.INFO)

    print("=" * 60)
    print("Ownership Exclusive Demo")
    print("QoS: EXCLUSIVE ownership - highest strength writer wins")
    print("=" * 60)

    with hdds.Participant("OwnershipDemo") as participant:
        if is_publisher:
            run_publisher(participant, strength)
        else:
            run_subscriber(participant)


if __name__ == "__main__":
    main()
