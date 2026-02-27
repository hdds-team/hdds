#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: Multi-Participant (Python)

Demonstrates multiple DDS participants in the same process.
Each participant can have its own domain, QoS, and discovery settings.

Usage:
    python multi_participant.py
"""

import sys
import time
import threading

sys.path.insert(0, '../../../python')

import hdds
from generated.HelloWorld import HelloWorld


def publisher_thread(name: str, topic: str, domain: int = 0):
    """Run a publisher in its own participant."""
    print(f"[{name}] Creating participant on domain {domain}...")
    participant = hdds.Participant(name, domain_id=domain)

    writer = participant.create_writer(topic)
    print(f"[{name}] Publishing to '{topic}'...")

    for i in range(5):
        msg = HelloWorld(message=f"From {name}", count=i)
        writer.write(msg.serialize())
        print(f"[{name}] Sent: {msg.message} #{msg.count}")
        time.sleep(0.3)

    print(f"[{name}] Done.")


def subscriber_thread(name: str, topic: str, domain: int = 0):
    """Run a subscriber in its own participant."""
    print(f"[{name}] Creating participant on domain {domain}...")
    participant = hdds.Participant(name, domain_id=domain)

    reader = participant.create_reader(topic)
    waitset = hdds.WaitSet()
    waitset.attach(reader.get_status_condition())

    print(f"[{name}] Subscribing to '{topic}'...")
    received = 0

    while received < 10:  # Expect messages from 2 publishers
        if waitset.wait(timeout=2.0):
            while True:
                data = reader.take()
                if data is None:
                    break
                msg, _ = HelloWorld.deserialize(data)
                print(f"[{name}] Received: {msg.message} #{msg.count}")
                received += 1

    print(f"[{name}] Done.")


def main():
    hdds.logging.init(hdds.LogLevel.INFO)

    print("=" * 60)
    print("Multi-Participant Demo")
    print("Creating 3 participants: 2 publishers + 1 subscriber")
    print("=" * 60)

    topic = "MultiParticipantTopic"

    # Start threads
    threads = [
        threading.Thread(target=subscriber_thread, args=("Subscriber", topic)),
        threading.Thread(target=publisher_thread, args=("Publisher-A", topic)),
        threading.Thread(target=publisher_thread, args=("Publisher-B", topic)),
    ]

    # Small delay to let subscriber start first
    threads[0].start()
    time.sleep(0.2)
    threads[1].start()
    threads[2].start()

    for t in threads:
        t.join()

    print("=" * 60)
    print("All participants finished.")
    print("=" * 60)


if __name__ == "__main__":
    main()
