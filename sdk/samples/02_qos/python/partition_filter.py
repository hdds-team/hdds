#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: Partition Filter (Python)

Demonstrates PARTITION QoS for logical data filtering.
Writers and readers only communicate when partitions match.

Usage:
    python partition_filter.py                # Subscriber (partition A)
    python partition_filter.py pub            # Publisher (partition A)
    python partition_filter.py pub B          # Publisher (partition B - no match)
    python partition_filter.py sub B          # Subscriber (partition B)
"""

import sys
import time

sys.path.insert(0, str(__file__ + "/../../01_basics/python"))

import hdds
from generated.HelloWorld import HelloWorld

NUM_MESSAGES = 5


def run_publisher(participant, partition):
    """Publish to a specific partition."""
    qos = hdds.QoS.reliable().partition(partition)
    writer = participant.create_writer("PartitionTopic", qos=qos)

    print(f"Publishing to partition '{partition}'...\n")

    for i in range(NUM_MESSAGES):
        msg = HelloWorld(id=i + 1, message=f"[{partition}] Message #{i + 1}")
        writer.write(msg.serialize())
        print(f"  [SENT:{partition}] id={msg.id} msg='{msg.message}'")
        time.sleep(0.2)

    print(f"\nDone publishing to partition '{partition}'.")
    print("Only readers in matching partition will receive data.")


def run_subscriber(participant, partition):
    """Subscribe to a specific partition."""
    qos = hdds.QoS.reliable().partition(partition)
    reader = participant.create_reader("PartitionTopic", qos=qos)

    waitset = hdds.WaitSet()
    waitset.attach(reader)

    print(f"Subscribing to partition '{partition}'...")
    print("Only publishers in matching partition will be received.\n")

    received = 0
    timeouts = 0

    while timeouts < 3:
        if waitset.wait(timeout_secs=2.0):
            while True:
                data = reader.take()
                if data is None:
                    break
                msg = HelloWorld.deserialize(data)
                print(f"  [RECV:{partition}] id={msg.id} msg='{msg.message}'")
                received += 1
            timeouts = 0
        else:
            timeouts += 1
            print(f"  (waiting for partition '{partition}'...)")

    if received > 0:
        print(f"\nReceived {received} messages in partition '{partition}'.")
    else:
        print(f"\nNo messages received. Is there a publisher in partition '{partition}'?")
        print(f"Try: python partition_filter.py pub {partition}")


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "sub"
    partition = sys.argv[2] if len(sys.argv) > 2 else "A"

    is_publisher = (mode == "pub")

    hdds.logging.init(hdds.LogLevel.INFO)

    print("=" * 60)
    print("Partition Filter Demo")
    print("QoS: PARTITION - logical data filtering by namespace")
    print("=" * 60)

    with hdds.Participant("PartitionDemo") as participant:
        if is_publisher:
            run_publisher(participant, partition)
        else:
            run_subscriber(participant, partition)


if __name__ == "__main__":
    main()
