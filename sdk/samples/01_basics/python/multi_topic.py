#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: Multi-Topic (Python)

Demonstrates pub/sub on multiple topics from a single participant.
Shows how to use WaitSet to multiplex across multiple readers.

Usage:
    # Terminal 1 - Subscriber
    python multi_topic.py

    # Terminal 2 - Publisher
    python multi_topic.py pub
"""

import sys
import time

sys.path.insert(0, '../../../python')

import hdds
from generated.HelloWorld import HelloWorld


TOPICS = ["SensorData", "Commands", "Status"]


def run_publisher(participant):
    """Publish to multiple topics."""
    writers = {}
    for topic in TOPICS:
        writers[topic] = participant.create_writer(topic)
        print(f"  Created writer for '{topic}'")

    print("\nPublishing to all topics...")
    for i in range(5):
        for topic in TOPICS:
            msg = HelloWorld(id=i, message=f"{topic} message")
            writers[topic].write(msg.encode_cdr2_le())
            print(f"  [{topic}] Sent #{i}")
        time.sleep(0.5)

    print("Done publishing.")


def run_subscriber(participant):
    """Subscribe to multiple topics using a single WaitSet."""
    readers = {}
    waitset = hdds.WaitSet()

    for topic in TOPICS:
        reader = participant.create_reader(topic)
        readers[topic] = reader
        waitset.attach_reader(reader)
        print(f"  Created reader for '{topic}'")

    print("\nWaiting for messages on all topics...")
    received = {t: 0 for t in TOPICS}
    total_expected = len(TOPICS) * 5

    while sum(received.values()) < total_expected:
        if waitset.wait(timeout=3.0):
            # Check all readers
            for topic, reader in readers.items():
                while True:
                    data = reader.take()
                    if data is None:
                        break
                    msg, _ = HelloWorld.decode_cdr2_le(data)
                    print(f"  [{topic}] Received: {msg.message} #{msg.id}")
                    received[topic] += 1
        else:
            print("  (timeout)")

    print("\nReceived counts:")
    for topic, count in received.items():
        print(f"  {topic}: {count} messages")
    print("Done receiving.")


def main():
    is_publisher = len(sys.argv) > 1 and sys.argv[1].lower() in ('pub', 'publisher', '-p')

    hdds.logging.init(hdds.LogLevel.INFO)

    print("=" * 60)
    print("Multi-Topic Demo")
    print(f"Topics: {', '.join(TOPICS)}")
    print("=" * 60)

    participant = hdds.Participant("MultiTopicDemo")

    try:
        if is_publisher:
            run_publisher(participant)
        else:
            run_subscriber(participant)
    except KeyboardInterrupt:
        print("\nInterrupted.")


if __name__ == "__main__":
    main()
