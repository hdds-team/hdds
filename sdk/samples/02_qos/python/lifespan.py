#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: Lifespan (Python)

Demonstrates LIFESPAN QoS for automatic data expiration.
Data samples expire after a configurable duration and are removed
from the cache. Late-joining subscribers only receive surviving samples.

Usage:
    python lifespan.py        # Subscriber (joins after 3s delay)
    python lifespan.py pub    # Publisher (sends 10 msgs with 2s lifespan)
"""

import sys
import time

sys.path.insert(0, str(__file__ + "/../../01_basics/python"))

import hdds
from generated.HelloWorld import HelloWorld

LIFESPAN_MS = 2000  # 2 second lifespan
NUM_MESSAGES = 10
PUBLISH_INTERVAL_MS = 500  # 500ms between messages
SUBSCRIBER_DELAY_S = 3  # 3 second delay before subscribing


def run_publisher(participant):
    """Publish messages with TRANSIENT_LOCAL + LIFESPAN QoS."""
    qos = hdds.QoS.transient_local().lifespan_ms(LIFESPAN_MS)
    writer = participant.create_writer("LifespanTopic", qos=qos)

    print(f"Publishing {NUM_MESSAGES} messages with {LIFESPAN_MS}ms lifespan...")
    print(f"Interval: {PUBLISH_INTERVAL_MS}ms between messages")
    print(f"Messages will expire {LIFESPAN_MS}ms after being written.\n")

    start = time.monotonic()

    for i in range(NUM_MESSAGES):
        msg = HelloWorld(id=i + 1, message=f"Lifespan sample #{i + 1}")
        writer.write(msg.serialize())

        elapsed = int((time.monotonic() - start) * 1000)
        print(f"  [{elapsed:5d}ms] Sent id={msg.id} msg='{msg.message}'")

        time.sleep(PUBLISH_INTERVAL_MS / 1000.0)

    total_ms = int((time.monotonic() - start) * 1000)
    print(f"\nAll {NUM_MESSAGES} messages sent in {total_ms}ms.")
    print(f"Oldest messages will have expired by now (lifespan={LIFESPAN_MS}ms).")
    print("Waiting for late-joining subscribers...")
    print("(Run 'python lifespan.py' in another terminal)")
    input("Press Enter to exit...")


def run_subscriber(participant):
    """Join late and observe which messages survived the lifespan."""
    print(f"Waiting {SUBSCRIBER_DELAY_S}s before creating reader...")
    print(f"Messages older than {LIFESPAN_MS}ms will have expired.\n")

    time.sleep(SUBSCRIBER_DELAY_S)

    qos = hdds.QoS.transient_local().lifespan_ms(LIFESPAN_MS)
    reader = participant.create_reader("LifespanTopic", qos=qos)

    waitset = hdds.WaitSet()
    waitset.attach(reader)

    print("Reader created. Checking for surviving messages...\n")

    received = 0
    timeouts = 0

    while timeouts < 2:
        if waitset.wait(timeout_secs=2.0):
            while True:
                data = reader.take()
                if data is None:
                    break

                msg = HelloWorld.deserialize(data)
                print(f"  [SURVIVED] id={msg.id} msg='{msg.message}'")
                received += 1
            timeouts = 0
        else:
            timeouts += 1

    expired = NUM_MESSAGES - received

    print()
    print("-" * 60)
    print(f"Summary: {received} messages survived, ~{expired} expired")
    print(f"Lifespan was {LIFESPAN_MS}ms, subscriber delay was {SUBSCRIBER_DELAY_S}s")
    if received > 0:
        print("Only the most recent messages survived the lifespan window.")
    else:
        print("All messages expired before subscriber joined.")
        print("Try: python lifespan.py pub  (then quickly run subscriber)")
    print("-" * 60)


def main():
    is_publisher = len(sys.argv) > 1 and sys.argv[1] == "pub"

    hdds.logging.init(hdds.LogLevel.INFO)

    print("=" * 60)
    print("Lifespan Demo")
    print("QoS: LIFESPAN - automatic data expiration after duration")
    print("=" * 60)

    with hdds.Participant("LifespanDemo") as participant:
        if is_publisher:
            run_publisher(participant)
        else:
            run_subscriber(participant)


if __name__ == "__main__":
    main()
