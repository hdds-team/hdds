#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: Best Effort (Python)

Demonstrates BEST_EFFORT QoS for fire-and-forget messaging.
Lower latency than RELIABLE, but no delivery guarantees.

Usage:
    python best_effort.py        # Subscriber
    python best_effort.py pub    # Publisher
"""

import sys
import time

sys.path.insert(0, str(__file__ + "/../../01_basics/python"))

import hdds
from generated.HelloWorld import HelloWorld

NUM_MESSAGES = 20


def run_publisher(participant):
    """Publish messages with BEST_EFFORT QoS."""
    qos = hdds.QoS.best_effort()
    writer = participant.create_writer("BestEffortTopic", qos=qos)

    print(f"Publishing {NUM_MESSAGES} messages with BEST_EFFORT QoS...")
    print("(Some messages may be lost - fire-and-forget)\n")

    for i in range(NUM_MESSAGES):
        msg = HelloWorld(id=i + 1, message=f"BestEffort #{i + 1}")
        writer.write(msg.serialize())
        print(f"  [SENT] id={msg.id} msg='{msg.message}'")
        time.sleep(0.05)  # Fast publishing

    print("\nDone publishing. Some messages may have been dropped.")


def run_subscriber(participant):
    """Receive messages with BEST_EFFORT QoS."""
    qos = hdds.QoS.best_effort()
    reader = participant.create_reader("BestEffortTopic", qos=qos)

    waitset = hdds.WaitSet()
    waitset.attach(reader)

    print("Waiting for BEST_EFFORT messages...")
    print("(Lower latency, but delivery not guaranteed)\n")

    received = 0
    timeouts = 0
    max_timeouts = 3

    while timeouts < max_timeouts:
        if waitset.wait(timeout_secs=2.0):
            while True:
                data = reader.take()
                if data is None:
                    break
                msg = HelloWorld.deserialize(data)
                print(f"  [RECV] id={msg.id} msg='{msg.message}'")
                received += 1
            timeouts = 0  # Reset on data
        else:
            timeouts += 1
            print(f"  (timeout {timeouts}/{max_timeouts})")

    print(f"\nReceived {received}/{NUM_MESSAGES} messages. "
          "BEST_EFFORT trades reliability for speed.")


def main():
    is_publisher = len(sys.argv) > 1 and sys.argv[1] == "pub"

    hdds.logging.init(hdds.LogLevel.INFO)

    print("=" * 60)
    print("Best Effort Demo")
    print("QoS: BEST_EFFORT - fire-and-forget, lowest latency")
    print("=" * 60)

    with hdds.Participant("BestEffortDemo") as participant:
        if is_publisher:
            run_publisher(participant)
        else:
            run_subscriber(participant)


if __name__ == "__main__":
    main()
