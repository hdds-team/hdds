#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: Hello World (Python)

Demonstrates basic pub/sub with HDDS Python API.

Usage:
    # Terminal 1 - Subscriber
    python hello_world.py

    # Terminal 2 - Publisher
    python hello_world.py pub
"""

import sys
import time

# Add SDK to path
sys.path.insert(0, '../../../python')

import hdds
from generated.HelloWorld import HelloWorld


def run_publisher(participant):
    """Run publisher sending HelloWorld messages."""
    print("Creating writer...")
    writer = participant.create_writer("HelloWorldTopic")

    print("Publishing messages...")
    for i in range(10):
        msg = HelloWorld(message="Hello from HDDS Python!", count=i)
        data = msg.serialize()
        writer.write(data)
        print(f"  Published: {msg.message} (count={msg.count})")
        time.sleep(0.5)

    print("Done publishing.")


def run_subscriber(participant):
    """Run subscriber receiving HelloWorld messages."""
    print("Creating reader...")
    reader = participant.create_reader("HelloWorldTopic")

    # Create waitset for efficient waiting
    waitset = hdds.WaitSet()
    cond = reader.get_status_condition()
    waitset.attach(cond)

    print("Waiting for messages (Ctrl+C to exit)...")
    received = 0

    while received < 10:
        # Wait up to 5 seconds
        if waitset.wait(timeout=5.0):
            # Take all available samples
            while True:
                data = reader.take()
                if data is None:
                    break
                msg, _ = HelloWorld.deserialize(data)
                print(f"  Received: {msg.message} (count={msg.count})")
                received += 1
        else:
            print("  (timeout - no messages)")

    print("Done receiving.")


def main():
    is_publisher = len(sys.argv) > 1 and sys.argv[1].lower() in ('pub', 'publisher', '-p')

    # Initialize logging
    hdds.logging.init(hdds.LogLevel.INFO)

    # Create participant
    print("Creating participant...")
    participant = hdds.Participant("HelloWorld")

    try:
        if is_publisher:
            run_publisher(participant)
        else:
            run_subscriber(participant)
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        print("Cleanup complete.")


if __name__ == "__main__":
    main()
