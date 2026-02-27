#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: Resource Limits (Python)

Demonstrates RESOURCE_LIMITS QoS for bounding memory usage.
Reader A is constrained to max 5 samples; Reader B has no limits.
Both receive from the same writer, showing how limits cap delivery.

This sample runs in single-process mode (no pub/sub arguments).

Usage:
    python resource_limits.py
"""

import sys
import time

sys.path.insert(0, str(__file__ + "/../../01_basics/python"))

import hdds
from generated.HelloWorld import HelloWorld

NUM_MESSAGES = 20
MAX_SAMPLES = 5
MAX_INSTANCES = 1
MAX_SAMPLES_PER_INSTANCE = 5


def main():
    hdds.logging.init(hdds.LogLevel.INFO)

    print("=" * 60)
    print("Resource Limits Demo")
    print("QoS: RESOURCE_LIMITS - bound memory usage per reader")
    print("=" * 60)

    with hdds.Participant("ResourceLimitsDemo") as participant:
        # --- Writer: large history so all samples are available ---
        writer_qos = hdds.QoS.reliable().transient_local().history_depth(100)
        writer = participant.create_writer("ResourceTopic", qos=writer_qos)

        # --- Publish all messages first ---
        print(f"\nPublishing {NUM_MESSAGES} messages...\n")

        start = time.monotonic()

        for i in range(NUM_MESSAGES):
            msg = HelloWorld(id=i + 1, message=f"Resource sample #{i + 1}")
            writer.write(msg.serialize())

            elapsed = int((time.monotonic() - start) * 1000)
            print(f"  [{elapsed:5d}ms] Sent id={msg.id}")

        print(f"\nAll {NUM_MESSAGES} messages published and cached.\n")

        # --- Small delay to ensure writer cache is populated ---
        time.sleep(0.5)

        # --- Reader A: limited resources ---
        qos_limited = (hdds.QoS.reliable()
                        .transient_local()
                        .resource_limits(MAX_SAMPLES, MAX_INSTANCES,
                                         MAX_SAMPLES_PER_INSTANCE))
        reader_limited = participant.create_reader("ResourceTopic",
                                                   qos=qos_limited)

        # --- Reader B: unlimited resources ---
        qos_unlimited = hdds.QoS.reliable().transient_local()
        reader_unlimited = participant.create_reader("ResourceTopic",
                                                     qos=qos_unlimited)

        waitset_limited = hdds.WaitSet()
        waitset_limited.attach(reader_limited)

        waitset_unlimited = hdds.WaitSet()
        waitset_unlimited.attach(reader_unlimited)

        print(f"Reader A: resource_limits(max_samples={MAX_SAMPLES}, "
              f"max_instances={MAX_INSTANCES}, "
              f"max_per_instance={MAX_SAMPLES_PER_INSTANCE})")
        print(f"Reader B: no resource limits (unlimited)\n")

        # --- Give readers time to receive cached data ---
        time.sleep(1.0)

        # --- Drain Reader A (limited) ---
        received_limited = 0
        print("Reader A (limited) received:")
        while True:
            if not waitset_limited.wait(timeout_secs=1.0):
                break
            while True:
                data = reader_limited.take()
                if data is None:
                    break
                msg = HelloWorld.deserialize(data)
                print(f"  [LIMITED]   id={msg.id} msg='{msg.message}'")
                received_limited += 1

        # --- Drain Reader B (unlimited) ---
        received_unlimited = 0
        print("\nReader B (unlimited) received:")
        while True:
            if not waitset_unlimited.wait(timeout_secs=1.0):
                break
            while True:
                data = reader_unlimited.take()
                if data is None:
                    break
                msg = HelloWorld.deserialize(data)
                received_unlimited += 1

        if received_unlimited > 10:
            print(f"  ... {received_unlimited} messages total (showing summary)")
        else:
            print(f"  {received_unlimited} messages received")

        # --- Results ---
        print()
        print("-" * 60)
        print(f"Summary:")
        print(f"  Published:              {NUM_MESSAGES} messages")
        print(f"  Reader A (limited):     {received_limited} messages "
              f"(max_samples={MAX_SAMPLES})")
        print(f"  Reader B (unlimited):   {received_unlimited} messages")
        print()
        if received_limited < received_unlimited:
            print(f"Resource limits capped Reader A at {received_limited} samples,")
            print(f"while Reader B received {received_unlimited} (all available).")
        else:
            print("Note: Both readers received similar counts.")
            print("Resource limits take effect when cache exceeds the limit.")
        print("-" * 60)


if __name__ == "__main__":
    main()
