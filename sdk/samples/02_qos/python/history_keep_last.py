#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: History Keep Last (Python)

Demonstrates KEEP_LAST history QoS with configurable depth.
Only the N most recent samples are retained per instance.

Usage:
    python history_keep_last.py        # Subscriber (default depth=3)
    python history_keep_last.py pub    # Publisher (burst of 10 messages)
    python history_keep_last.py sub 5  # Subscriber with depth=5
"""

import sys
import time

sys.path.insert(0, str(__file__ + "/../../01_basics/python"))

import hdds
from generated.HelloWorld import HelloWorld

NUM_MESSAGES = 10


def run_publisher(participant):
    """Publish a burst of messages."""
    qos = hdds.QoS.reliable().transient_local().history_depth(NUM_MESSAGES)
    writer = participant.create_writer("HistoryTopic", qos=qos)

    print(f"Publishing {NUM_MESSAGES} messages in rapid succession...\n")

    for i in range(NUM_MESSAGES):
        msg = HelloWorld(id=i + 1, message=f"Message #{i + 1}")
        writer.write(msg.serialize())
        print(f"  [SENT] id={msg.id} msg='{msg.message}'")

    print(f"\nAll {NUM_MESSAGES} messages published.")
    print(f"Subscriber with history depth < {NUM_MESSAGES} will only see most recent.")
    input("Press Enter to exit (keep writer alive for late-join test)...")


def run_subscriber(participant, history_depth):
    """Subscribe with configurable history depth."""
    qos = hdds.QoS.reliable().transient_local().history_depth(history_depth)
    reader = participant.create_reader("HistoryTopic", qos=qos)

    waitset = hdds.WaitSet()
    waitset.attach(reader)

    print(f"Subscribing with KEEP_LAST history (depth={history_depth})...")
    print(f"Will only retain the {history_depth} most recent samples.\n")

    received = 0
    timeouts = 0

    while timeouts < 2:
        if waitset.wait(timeout_secs=2.0):
            while True:
                data = reader.take()
                if data is None:
                    break
                msg = HelloWorld.deserialize(data)
                print(f"  [RECV] id={msg.id} msg='{msg.message}'")
                received += 1
            timeouts = 0
        else:
            timeouts += 1

    print()
    print("-" * 60)
    print(f"Summary: Received {received} messages (history depth was {history_depth})")

    if received <= history_depth:
        print("All received messages fit within history depth.")
    else:
        print(f"Note: If publisher sent more than {history_depth} messages,")
        print(f"only the most recent {history_depth} were retained in history.")
    print("-" * 60)


def main():
    is_publisher = len(sys.argv) > 1 and sys.argv[1] == "pub"
    history_depth = 3  # Default history depth

    if len(sys.argv) > 2:
        try:
            history_depth = max(1, int(sys.argv[2]))
        except ValueError:
            pass

    hdds.logging.init(hdds.LogLevel.INFO)

    print("=" * 60)
    print("History Keep Last Demo")
    print("QoS: KEEP_LAST - retain N most recent samples per instance")
    print("=" * 60)

    with hdds.Participant("HistoryDemo") as participant:
        if is_publisher:
            run_publisher(participant)
        else:
            run_subscriber(participant, history_depth)


if __name__ == "__main__":
    main()
