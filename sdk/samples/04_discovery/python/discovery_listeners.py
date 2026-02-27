#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Discovery Listeners Sample - Demonstrates discovery event handling

This sample shows how to monitor discovery events:
- When data becomes available on readers
- Matching between writers and readers

Key concepts:
- WaitSet for event-driven programming
- Status conditions for data availability
- GuardCondition for manual signaling
"""

import os
import sys
import time
from dataclasses import dataclass
from enum import Enum
from typing import List

# Add SDK to path
sys.path.insert(0, '../../../python')

import hdds


class EventType(Enum):
    DATA_AVAILABLE = "data_available"
    TIMEOUT = "timeout"


@dataclass
class DiscoveryEvent:
    event_type: EventType
    topic: str = ""
    data: bytes = b""


def main():
    print("=== HDDS Discovery Listeners Sample ===\n")

    # Initialize logging
    hdds.logging.init(hdds.LogLevel.INFO)

    # Create participant
    print("Creating DomainParticipant...")
    participant = hdds.Participant("DiscoveryListeners")
    print(f"[OK] Participant created: {participant.name}")

    # Create writer and reader on the same topic
    print("\nCreating DataWriter...")
    writer = participant.create_writer("ListenerDemo")
    print("[OK] DataWriter created")

    print("Creating DataReader...")
    reader = participant.create_reader("ListenerDemo")
    print("[OK] DataReader created")

    # Create waitset and attach reader for data availability events
    print("\nSetting up WaitSet for event monitoring...")
    waitset = hdds.WaitSet()
    waitset.attach_reader(reader)
    print("[OK] WaitSet configured with reader status condition")

    # Create a guard condition for demonstrating manual triggering
    guard = hdds.GuardCondition()
    waitset.attach_guard(guard)
    print("[OK] GuardCondition attached to WaitSet")

    print("\n--- Listening for Discovery Events ---")
    print("Run other HDDS applications to see events.")
    print("Press Ctrl+C to exit.\n")

    # Event processing loop
    event_count = 0
    events_received: List[DiscoveryEvent] = []

    try:
        for iteration in range(1, 11):
            # Write a message
            message = f"Discovery message #{iteration} from {os.getpid()}"
            writer.write(message.encode('utf-8'))
            print(f"[SENT] {message}")

            # Wait for data with timeout
            if waitset.wait(timeout=2.0):
                # Data is available - take all samples
                while True:
                    data = reader.take()
                    if data is None:
                        break

                    event_count += 1
                    event = DiscoveryEvent(
                        event_type=EventType.DATA_AVAILABLE,
                        topic="ListenerDemo",
                        data=data
                    )
                    events_received.append(event)

                    print(f"[EVENT {event_count}] Data AVAILABLE")
                    print(f"          Topic: {event.topic}")
                    print(f"          Data: {data.decode('utf-8')}")
                    print()
            else:
                print(f"[TIMEOUT] No data received within 2 seconds")
                print()

            time.sleep(1.0)

    except KeyboardInterrupt:
        print("\n--- Interrupted ---")

    # Summary
    print("\n--- Discovery Summary ---")
    print(f"Total events received: {event_count}")
    print(f"Messages sent: 10")

    # Cleanup
    print("\nCleaning up...")
    guard.close()
    waitset.close()
    participant.close()

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
