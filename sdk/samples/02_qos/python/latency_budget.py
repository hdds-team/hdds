#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: Latency Budget (Python)

Demonstrates LATENCY_BUDGET QoS for delivery latency hints.
A low budget (0ms) requests immediate delivery, while a higher budget
(100ms) allows the middleware to batch or optimize delivery.

Usage:
    python latency_budget.py        # Subscriber (monitors both topics)
    python latency_budget.py pub    # Publisher (sends on both topics)
"""

import sys
import time

sys.path.insert(0, str(__file__ + "/../../01_basics/python"))

import hdds
from generated.HelloWorld import HelloWorld

LOW_LATENCY_MS = 0
HIGH_LATENCY_MS = 100
NUM_MESSAGES = 5


def run_publisher(participant):
    """Publish to two topics with different latency budgets."""
    qos_low = hdds.QoS.reliable().latency_budget_ms(LOW_LATENCY_MS)
    qos_high = hdds.QoS.reliable().latency_budget_ms(HIGH_LATENCY_MS)

    writer_low = participant.create_writer("LowLatencyTopic", qos=qos_low)
    writer_high = participant.create_writer("BatchedTopic", qos=qos_high)

    print(f"Publishing {NUM_MESSAGES} messages on each topic...")
    print(f"  LowLatencyTopic: latency_budget = {LOW_LATENCY_MS}ms (immediate)")
    print(f"  BatchedTopic:    latency_budget = {HIGH_LATENCY_MS}ms (batched)\n")

    start = time.monotonic()

    for i in range(NUM_MESSAGES):
        elapsed = int((time.monotonic() - start) * 1000)

        msg_low = HelloWorld(id=i + 1, message=f"Low-latency #{i + 1}")
        writer_low.write(msg_low.serialize())
        print(f"  [{elapsed:5d}ms] Sent LowLatency  id={msg_low.id}")

        msg_high = HelloWorld(id=i + 1, message=f"Batched #{i + 1}")
        writer_high.write(msg_high.serialize())
        print(f"  [{elapsed:5d}ms] Sent Batched     id={msg_high.id}")

        time.sleep(0.3)

    print("\nDone publishing on both topics.")


def run_subscriber(participant):
    """Monitor both topics and compare delivery timing."""
    qos_low = hdds.QoS.reliable().latency_budget_ms(LOW_LATENCY_MS)
    qos_high = hdds.QoS.reliable().latency_budget_ms(HIGH_LATENCY_MS)

    reader_low = participant.create_reader("LowLatencyTopic", qos=qos_low)
    reader_high = participant.create_reader("BatchedTopic", qos=qos_high)

    waitset = hdds.WaitSet()
    waitset.attach(reader_low)
    waitset.attach(reader_high)

    print("Subscribing to both topics...")
    print(f"  LowLatencyTopic: latency_budget = {LOW_LATENCY_MS}ms")
    print(f"  BatchedTopic:    latency_budget = {HIGH_LATENCY_MS}ms\n")

    received_low = 0
    received_high = 0
    start = time.monotonic()
    timeouts = 0

    while timeouts < 3:
        if waitset.wait(timeout_secs=2.0):
            while True:
                data = reader_low.take()
                if data is None:
                    break
                msg = HelloWorld.deserialize(data)
                elapsed = int((time.monotonic() - start) * 1000)
                print(f"  [{elapsed:5d}ms] LowLatency  received id={msg.id}")
                received_low += 1

            while True:
                data = reader_high.take()
                if data is None:
                    break
                msg = HelloWorld.deserialize(data)
                elapsed = int((time.monotonic() - start) * 1000)
                print(f"  [{elapsed:5d}ms] Batched     received id={msg.id}")
                received_high += 1

            timeouts = 0
        else:
            timeouts += 1

    print()
    print("-" * 60)
    print(f"Summary:")
    print(f"  LowLatency (budget={LOW_LATENCY_MS}ms): {received_low} messages")
    print(f"  Batched    (budget={HIGH_LATENCY_MS}ms): {received_high} messages")
    print()
    print("Note: Latency budget is a HINT to the middleware.")
    print("Actual delivery depends on transport and implementation.")
    print("-" * 60)


def main():
    is_publisher = len(sys.argv) > 1 and sys.argv[1] == "pub"

    hdds.logging.init(hdds.LogLevel.INFO)

    print("=" * 60)
    print("Latency Budget Demo")
    print("QoS: LATENCY_BUDGET - delivery latency hints for optimization")
    print("=" * 60)

    with hdds.Participant("LatencyBudgetDemo") as participant:
        if is_publisher:
            run_publisher(participant)
        else:
            run_subscriber(participant)


if __name__ == "__main__":
    main()
