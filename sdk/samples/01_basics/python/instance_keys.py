#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: Instance Keys (Python)

Demonstrates keyed instances in DDS. Each unique key value represents
a separate data instance that can be independently managed.

Use cases:
- Tracking multiple sensors (key = sensor_id)
- Managing multiple robots (key = robot_id)
- State machines per entity

Usage:
    # Terminal 1 - Subscriber
    python instance_keys.py

    # Terminal 2 - Publisher
    python instance_keys.py pub
"""

import sys
import time

sys.path.insert(0, '../../../python')

import hdds
from generated.KeyedData import KeyedData


NUM_INSTANCES = 3  # Simulate 3 sensors


def run_publisher(participant):
    """Publish updates for multiple keyed instances."""
    writer = participant.create_writer("SensorTopic")
    print(f"Publishing updates for {NUM_INSTANCES} sensor instances...\n")

    # Send multiple updates per instance
    for seq in range(5):
        for sensor_id in range(NUM_INSTANCES):
            msg = KeyedData(
                id=sensor_id,
                data=f"Sensor-{sensor_id} reading",
                sequence_num=seq
            )
            writer.write(msg.serialize())
            print(f"  [Sensor {sensor_id}] seq={seq} -> '{msg.data}'")

        time.sleep(0.5)

    print("\nDone publishing.")


def run_subscriber(participant):
    """Subscribe and track state per instance."""
    reader = participant.create_reader("SensorTopic")
    waitset = hdds.WaitSet()
    waitset.attach(reader.get_status_condition())

    # Track latest state per instance
    instance_state = {}

    print(f"Subscribing to {NUM_INSTANCES} sensor instances...\n")
    total_expected = NUM_INSTANCES * 5

    received = 0
    while received < total_expected:
        if waitset.wait(timeout=3.0):
            while True:
                data = reader.take()
                if data is None:
                    break
                msg, _ = KeyedData.deserialize(data)

                # Update instance state
                prev_seq = instance_state.get(msg.id, -1)
                instance_state[msg.id] = msg.sequence_num

                print(f"  [Sensor {msg.id}] seq={msg.sequence_num} "
                      f"(prev={prev_seq}) -> '{msg.data}'")
                received += 1
        else:
            print("  (timeout)")

    print("\nFinal instance states:")
    for sensor_id, last_seq in sorted(instance_state.items()):
        print(f"  Sensor {sensor_id}: last_seq={last_seq}")

    print("Done.")


def main():
    is_publisher = len(sys.argv) > 1 and sys.argv[1].lower() in ('pub', 'publisher', '-p')

    hdds.logging.init(hdds.LogLevel.INFO)

    print("=" * 60)
    print("Instance Keys Demo")
    print(f"Simulating {NUM_INSTANCES} sensor instances with keyed data")
    print("=" * 60)

    participant = hdds.Participant("InstanceKeysDemo")

    try:
        if is_publisher:
            run_publisher(participant)
        else:
            run_subscriber(participant)
    except KeyboardInterrupt:
        print("\nInterrupted.")


if __name__ == "__main__":
    main()
