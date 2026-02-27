#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: Reliable Delivery (Python)

Demonstrates RELIABLE QoS for guaranteed message delivery.
Messages are retransmitted if lost (NACK-based recovery).

Usage:
    python reliable_delivery.py        # Subscriber
    python reliable_delivery.py pub    # Publisher
"""

import sys
import time

# Add parent path for generated types
sys.path.insert(0, str(__file__ + "/../../01_basics/python"))

import hdds
from generated.HelloWorld import HelloWorld

NUM_MESSAGES = 10


def run_publisher(participant):
    """Publish messages with RELIABLE QoS."""
    qos = hdds.QoS.reliable()
    writer = participant.create_writer("ReliableTopic", qos=qos)

    print(f"Publishing {NUM_MESSAGES} messages with RELIABLE QoS...\n")

    for i in range(NUM_MESSAGES):
        msg = HelloWorld(id=i + 1, message=f"Reliable message #{i + 1}")
        writer.write(msg.serialize())
        print(f"  [SENT] id={msg.id} msg='{msg.message}'")
        time.sleep(0.1)

    print("\nDone publishing. RELIABLE ensures all messages delivered.")


def run_subscriber(participant):
    """Receive messages with RELIABLE QoS."""
    qos = hdds.QoS.reliable()
    reader = participant.create_reader("ReliableTopic", qos=qos)

    waitset = hdds.WaitSet()
    waitset.attach(reader)

    print("Waiting for RELIABLE messages...\n")

    received = 0
    while received < NUM_MESSAGES:
        if waitset.wait(timeout_secs=5.0):
            while True:
                data = reader.take()
                if data is None:
                    break
                msg = HelloWorld.deserialize(data)
                print(f"  [RECV] id={msg.id} msg='{msg.message}'")
                received += 1
        else:
            print("  (timeout waiting for messages)")

    print(f"\nReceived all {received} messages. RELIABLE QoS guarantees delivery!")


def main():
    is_publisher = len(sys.argv) > 1 and sys.argv[1] == "pub"

    hdds.logging.init(hdds.LogLevel.INFO)

    print("=" * 60)
    print("Reliable Delivery Demo")
    print("QoS: RELIABLE - guaranteed delivery via NACK retransmission")
    print("=" * 60)

    with hdds.Participant("ReliableDemo") as participant:
        if is_publisher:
            run_publisher(participant)
        else:
            run_subscriber(participant)


if __name__ == "__main__":
    main()
