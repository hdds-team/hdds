#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HelloWorld HDDS Python SDK Demo

Demonstrates:
- IDL-generated type (SensorData) with CDR2 serialization
- Publisher sending incrementing values
- Subscriber receiving and printing data
- UUID-based sensor ID
- Real timestamps

Usage:
    # Terminal 1 - Subscriber
    python hello_world.py sub

    # Terminal 2 - Publisher
    python hello_world.py pub

Discovery uses UDP multicast. If the two sides never see each other (VPN,
container, firewall, no multicast route), the publisher reports that no
subscriber was found; on a single machine, run both with HDDS_INTERFACE=lo.
See https://docs.hdds.io/getting-started/network-prerequisites
"""

import sys
import time
import uuid
from pathlib import Path

# Add SDK to path (source checkout). An installed wheel needs no sys.path edit.
sys.path.insert(0, str(Path(__file__).parent.parent))

# Fails closed: without a loadable libhdds_c.so this raises ImportError listing
# the paths tried and the build command (see hdds/_native.py discovery order).
import hdds
from hello_types import SensorData

# How long to wait for the other side before printing a discovery hint.
DISCOVERY_HINT_AFTER_S = 10.0

DISCOVERY_HINT = (
    "Discovery uses UDP multicast. On one machine, try HDDS_INTERFACE=lo on both "
    "sides; across a VPN, container or firewall see "
    "https://docs.hdds.io/getting-started/network-prerequisites"
)

def get_timestamp_ns() -> int:
    """Get current timestamp in nanoseconds."""
    return int(time.time() * 1_000_000_000)

def generate_sensor_id() -> int:
    """Generate a unique sensor ID from UUID (use lower 32 bits)."""
    return uuid.uuid4().int & 0xFFFFFFFF

def run_publisher():
    """Run the publisher demo."""
    # Force the native library to load now so a missing build fails here,
    # before any entity is created.
    print(f"Native library: {hdds.library_path()}")

    # Initialize logging
    try:
        hdds.logging.init(hdds.LogLevel.INFO)
    except Exception:
        pass  # Already initialized

    print("=" * 60)
    print("HDDS HelloWorld Publisher")
    print("=" * 60)

    sensor_id = generate_sensor_id()
    print(f"Sensor ID: 0x{sensor_id:08X}")

    # Create participant
    with hdds.Participant("hello_publisher") as participant:
        print(f"Participant: {participant.name} (domain={participant.domain_id})")

        # Create writer with reliable QoS. SensorData positionally: the
        # writer labels every sample with the type's actual extensibility
        # (hdds_gen default: APPENDABLE) instead of mislabelling it FINAL.
        qos = hdds.QoS.reliable().history_depth(10)
        writer = participant.create_writer("HelloWorld/SensorData", SensorData, qos=qos)
        print(f"Writer created for topic: HelloWorld/SensorData")

        # Without a matched reader the samples go nowhere: say so instead of
        # publishing silently into the void.
        print(f"Waiting up to {DISCOVERY_HINT_AFTER_S:.0f}s for a subscriber...")
        if writer.wait_for_readers(1, timeout=DISCOVERY_HINT_AFTER_S):
            print("Subscriber matched.")
        else:
            print("No subscriber matched yet; publishing anyway.")
            print(DISCOVERY_HINT)
        print("-" * 60)

        value = 0.0
        seq = 0

        try:
            while True:
                # Create message
                msg = SensorData(
                    timestamp=get_timestamp_ns(),
                    id=sensor_id,
                    value=value
                )

                # write_typed() CDR2-encodes the message (encode_cdr2_le()).
                # The encapsulation header is added by the library: never
                # prepend one yourself, it would end up inside the payload.
                writer.write_typed(msg)

                print(f"[{seq:04d}] Sent: timestamp={msg.timestamp}, "
                      f"id=0x{msg.id:08X}, value={msg.value:.1f}")

                # Increment
                value += 0.5
                seq += 1

                time.sleep(1.0)

        except KeyboardInterrupt:
            print("\nPublisher stopped.")

def run_subscriber():
    """Run the subscriber demo."""
    # Force the native library to load now so a missing build fails here,
    # before any entity is created.
    print(f"Native library: {hdds.library_path()}")

    # Initialize logging
    try:
        hdds.logging.init(hdds.LogLevel.INFO)
    except Exception:
        pass

    print("=" * 60)
    print("HDDS HelloWorld Subscriber")
    print("=" * 60)

    # Create participant
    with hdds.Participant("hello_subscriber") as participant:
        print(f"Participant: {participant.name} (domain={participant.domain_id})")

        # Create reader with reliable QoS
        qos = hdds.QoS.reliable().history_depth(10)
        reader = participant.create_reader("HelloWorld/SensorData", qos=qos)
        print(f"Reader created for topic: HelloWorld/SensorData")
        print("-" * 60)
        print("Waiting for data... (Ctrl+C to exit)")
        print()

        started = time.monotonic()
        received = 0
        hinted = False
        try:
            while True:
                # take_typed() returns a decoded SensorData, or None when no
                # sample is available.
                try:
                    msg = reader.take_typed(SensorData)
                except Exception as e:
                    print(f"Decode error: {e}")
                    continue

                if msg is not None:
                    received += 1
                    # Calculate age
                    now = get_timestamp_ns()
                    age_ms = (now - msg.timestamp) / 1_000_000

                    print(f"Received: timestamp={msg.timestamp}, "
                          f"id=0x{msg.id:08X}, value={msg.value:.1f}, "
                          f"age={age_ms:.2f}ms")
                else:
                    if (not received and not hinted
                            and time.monotonic() - started > DISCOVERY_HINT_AFTER_S):
                        print(f"Nothing received after {DISCOVERY_HINT_AFTER_S:.0f}s. "
                              "Is the publisher running?")
                        print(DISCOVERY_HINT)
                        hinted = True
                    # No data, wait a bit
                    time.sleep(0.01)

        except KeyboardInterrupt:
            print("\nSubscriber stopped.")

def main():
    # Print each line as it is produced, even when stdout is a pipe or a file
    # (Python block-buffers a non-terminal stdout).
    sys.stdout.reconfigure(line_buffering=True)

    if len(sys.argv) < 2:
        print("Usage: python hello_world.py [pub|sub]")
        print()
        print("  pub  - Run publisher (sends data)")
        print("  sub  - Run subscriber (receives data)")
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode in ('pub', 'publisher', 'p'):
        run_publisher()
    elif mode in ('sub', 'subscriber', 's'):
        run_subscriber()
    else:
        print(f"Unknown mode: {mode}")
        print("Use 'pub' or 'sub'")
        sys.exit(1)

if __name__ == "__main__":
    main()
