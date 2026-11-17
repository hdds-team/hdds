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

# The publisher gives up if no subscriber matches within this time (seconds).
DISCOVERY_TIMEOUT = 30.0
# The subscriber exits when no message arrives for this long (seconds).
IDLE_TIMEOUT = 30.0


def run_publisher(participant):
    """Run publisher sending HelloWorld messages. Returns an exit status."""
    print("Creating writer...")
    writer = participant.create_writer("HelloWorldTopic")

    # A sample written before discovery completes is never delivered,
    # so wait until a subscriber has matched.
    print("Waiting for a subscriber...")
    if not writer.wait_for_readers(1, timeout=DISCOVERY_TIMEOUT):
        print(f"No subscriber matched within {DISCOVERY_TIMEOUT:g} s; start the subscriber first")
        return 1

    print("Publishing messages...")
    for i in range(10):
        msg = HelloWorld(id=i, message="Hello from HDDS Python!")
        data = msg.encode_cdr2_le()
        writer.write(data)
        print(f"  Published: {msg.message} (id={msg.id})")
        time.sleep(0.5)

    print("Done publishing.")
    return 0


def run_subscriber(participant):
    """Run subscriber receiving HelloWorld messages."""
    print("Creating reader...")
    reader = participant.create_reader("HelloWorldTopic")

    # Create waitset for efficient waiting
    waitset = hdds.WaitSet()
    waitset.attach_reader(reader)

    print("Waiting for messages (Ctrl+C to exit)...")
    received = 0
    last_message = time.monotonic()

    while received < 10:
        # Wait up to 1 second, so the idle check runs regularly
        if waitset.wait(timeout=1.0):
            # Take all available samples
            while True:
                data = reader.take()
                if data is None:
                    break
                msg, _ = HelloWorld.decode_cdr2_le(data)
                print(f"  Received: {msg.message} (id={msg.id})")
                received += 1
                last_message = time.monotonic()

        if time.monotonic() - last_message >= IDLE_TIMEOUT:
            print(f"  No message for {IDLE_TIMEOUT:g} s, giving up.")
            break

    print(f"Done receiving. Got {received} of 10 messages.")


def main():
    is_publisher = len(sys.argv) > 1 and sys.argv[1].lower() in ('pub', 'publisher', '-p')

    # Initialize logging
    hdds.logging.init(hdds.LogLevel.INFO)

    # Create participant. No domain is passed: the library reads HDDS_DOMAIN_ID
    # (a malformed value raises), else uses domain 0.
    print("Creating participant...")
    participant = hdds.Participant("HelloWorld")
    print(f"Participant created (domain {participant.domain_id})")

    status = 0
    try:
        if is_publisher:
            status = run_publisher(participant)
        else:
            run_subscriber(participant)
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        print("Cleanup complete.")
    return status


if __name__ == "__main__":
    sys.exit(main())
