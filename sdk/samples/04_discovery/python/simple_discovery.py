#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Simple Discovery Sample - Demonstrates automatic multicast discovery

This sample shows how DDS participants automatically discover each other
using SPDP (Simple Participant Discovery Protocol) over multicast.

Run multiple instances to see them discover each other:
  Terminal 1: python3 simple_discovery.py
  Terminal 2: python3 simple_discovery.py

Key concepts:
- Automatic peer discovery via multicast
- No manual configuration required
- Domain ID for logical separation
"""

import os
import sys
import time

# Add SDK to path
sys.path.insert(0, '../../../python')

import hdds


def main():
    print("=== HDDS Simple Discovery Sample ===\n")

    # Get instance ID from args or generate random
    if len(sys.argv) > 1:
        instance_id = int(sys.argv[1])
    else:
        instance_id = os.getpid()

    print(f"Instance ID: {instance_id}")
    print("Domain ID: 0 (default)\n")

    # Initialize logging
    hdds.logging.init(hdds.LogLevel.INFO)

    # Create participant with default discovery settings
    print("Creating DomainParticipant...")
    participant = hdds.Participant(f"SimpleDiscovery_{instance_id}")

    print(f"[OK] Participant created: {participant.name}")
    print(f"     Domain ID: {participant.domain_id}")

    # Create writer and reader for discovery demo topic
    print("Creating DataWriter...")
    writer = participant.create_writer("DiscoveryDemo")
    print("[OK] DataWriter created")

    print("Creating DataReader...")
    reader = participant.create_reader("DiscoveryDemo")
    print("[OK] DataReader created")

    # Create waitset for efficient waiting
    waitset = hdds.WaitSet()
    waitset.attach_reader(reader)

    print("\n--- Discovery in Progress ---")
    print("Waiting for other participants to join...")
    print("(Run another instance of this sample to see discovery)\n")

    # Announce ourselves periodically
    announce_interval = 2.0  # seconds
    announce_count = 0

    try:
        while announce_count < 10:
            # Send an announcement
            announce_count += 1
            message = f"Hello from instance {instance_id} (message #{announce_count})"

            try:
                writer.write(message.encode('utf-8'))
                print(f"[SENT] {message}")
            except Exception as e:
                print(f"[ERROR] Failed to send: {e}")

            # Check for messages from other participants using waitset
            # Non-blocking poll (timeout=0)
            if waitset.wait(timeout=0.1):
                # Take all available samples
                while True:
                    data = reader.take()
                    if data is None:
                        break
                    print(f"[RECV] {data.decode('utf-8')}")

            # Wait before next announcement
            time.sleep(announce_interval)

    except KeyboardInterrupt:
        print("\n--- Interrupted ---")

    print("\n--- Sample complete (10 announcements sent) ---")
    print("\n=== Sample Complete ===")

    # Cleanup
    waitset.close()
    participant.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
