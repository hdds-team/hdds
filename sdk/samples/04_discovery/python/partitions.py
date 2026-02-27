#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Partitions Sample - Demonstrates logical data separation with partitions

Partitions provide a way to logically separate data within a domain.
Only endpoints with matching partitions will communicate.

Key concepts:
- Publisher/Subscriber partitions via QoS
- Wildcard partition matching
- Dynamic partition changes

Run multiple instances with different partitions:
  python partitions.py --partition "SensorA"
  python partitions.py --partition "SensorB"
  python partitions.py --partition "Sensor*"   (receives from both)
"""

import argparse
import os
import sys
import time
from typing import List

# Add SDK to path
sys.path.insert(0, '../../../python')

import hdds


def main():
    parser = argparse.ArgumentParser(description="HDDS Partitions Sample")
    parser.add_argument(
        "-p", "--partition",
        action="append",
        dest="partitions",
        help="Add partition (can be repeated)"
    )
    parser.add_argument(
        "-w", "--wildcard",
        action="store_true",
        help="Use wildcard partition '*'"
    )
    args = parser.parse_args()

    print("=== HDDS Partitions Sample ===\n")

    # Build partition list
    partitions: List[str] = []

    if args.wildcard:
        partitions.append("*")
    elif args.partitions:
        partitions.extend(args.partitions)
    else:
        partitions.append("DefaultPartition")

    partition_str = "[" + ", ".join(f'"{p}"' for p in partitions) + "]"

    print("Configuration:")
    print(f"  Partitions: {partition_str}\n")

    # Initialize logging
    hdds.logging.init(hdds.LogLevel.INFO)

    # Create participant
    print("Creating DomainParticipant...")
    participant = hdds.Participant("Partitions")
    print("[OK] Participant created")

    # Create QoS with partitions
    print(f"\nCreating endpoints with partitions {partition_str}...")

    # Build QoS with partition(s)
    writer_qos = hdds.QoS.default()
    for p in partitions:
        writer_qos.partition(p)

    reader_qos = hdds.QoS.default()
    for p in partitions:
        reader_qos.partition(p)

    # Create writer and reader with partition QoS
    writer = participant.create_writer("PartitionDemo", qos=writer_qos)
    print("[OK] DataWriter created with partition QoS")

    reader = participant.create_reader("PartitionDemo", qos=reader_qos)
    print("[OK] DataReader created with partition QoS")

    # Create waitset for efficient waiting
    waitset = hdds.WaitSet()
    waitset.attach_reader(reader)

    print("\n--- Partition Matching Rules ---")
    print("Two endpoints match if they share at least one partition.")
    print("The '*' wildcard matches any partition name.")
    print("'Sensor*' matches 'SensorA', 'SensorB', etc.\n")

    print("--- Communication Loop ---")
    print("Only endpoints in matching partitions will communicate.\n")

    # Communication loop
    instance_id = os.getpid()

    try:
        for msg_count in range(1, 11):
            # Send message
            message = f"Message #{msg_count} from partition {partition_str} (pid={instance_id})"

            print(f"[SEND] {message}")
            writer.write(message.encode('utf-8'))

            # Check for received messages
            if waitset.wait(timeout=0.1):
                while True:
                    data = reader.take()
                    if data is None:
                        break
                    print(f"[RECV] {data.decode('utf-8')}")

            time.sleep(2)

    except KeyboardInterrupt:
        print("\n--- Interrupted ---")

    # Demonstrate partition concept
    print("\n--- Partition Information ---")
    print(f"Writer partition(s): {partition_str}")
    print(f"Reader partition(s): {partition_str}")
    print("\nNote: To change partitions at runtime, create new endpoints")
    print("with different QoS settings.")

    # Cleanup
    waitset.close()
    participant.close()

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
