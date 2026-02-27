#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Basic HDDS pub/sub example.

Usage:
    python basic_pubsub.py pub   # Run publisher
    python basic_pubsub.py sub   # Run subscriber
"""

import sys
import time


def publisher():
    """Run publisher."""
    import hdds

    print("Starting publisher...")

    with hdds.Participant("python_publisher") as p:
        qos = hdds.QoS.reliable().transient_local().history_depth(10)
        writer = p.create_writer("HelloWorld", qos=qos)

        print(f"Created writer on topic: {writer.topic_name}")
        print(f"QoS: {writer.qos}")

        # Wait for discovery
        time.sleep(1)

        for i in range(10):
            message = f"Hello #{i} from Python!".encode('utf-8')
            writer.write(message)
            print(f"Published: {message.decode()}")
            time.sleep(0.5)

    print("Publisher done.")


def subscriber():
    """Run subscriber."""
    import hdds

    print("Starting subscriber...")

    with hdds.Participant("python_subscriber") as p:
        qos = hdds.QoS.reliable().transient_local()
        reader = p.create_reader("HelloWorld", qos=qos)

        print(f"Created reader on topic: {reader.topic_name}")
        print(f"QoS: {reader.qos}")

        # Create waitset
        waitset = hdds.WaitSet()
        waitset.attach_reader(reader)

        print("Waiting for messages (Ctrl+C to exit)...")

        try:
            while True:
                if waitset.wait(timeout=1.0):
                    data = reader.take()
                    if data:
                        print(f"Received: {data.decode('utf-8', errors='replace')}")
        except KeyboardInterrupt:
            print("\nSubscriber interrupted.")

    print("Subscriber done.")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    mode = sys.argv[1].lower()
    if mode == "pub":
        publisher()
    elif mode == "sub":
        subscriber()
    else:
        print(f"Unknown mode: {mode}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
