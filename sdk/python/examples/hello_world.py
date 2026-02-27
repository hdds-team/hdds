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
"""

import sys
import time
import uuid
import struct
from pathlib import Path

# Add SDK to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from hello_types import SensorData

# For now, we'll use raw bytes since hdds Python SDK uses raw writer/reader
# In a full implementation, we'd have typed wrappers

def get_timestamp_ns() -> int:
    """Get current timestamp in nanoseconds."""
    return int(time.time() * 1_000_000_000)

def generate_sensor_id() -> int:
    """Generate a unique sensor ID from UUID (use lower 32 bits)."""
    return uuid.uuid4().int & 0xFFFFFFFF

def run_publisher():
    """Run the publisher demo."""
    try:
        # Set library path to local build
        import os
        os.environ.setdefault('HDDS_LIB_PATH', os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'target', 'release'))
        import hdds
        hdds._native.get_lib()  # Force load to check availability
    except (ImportError, OSError) as e:
        print(f"HDDS Python SDK not available ({e}), using mock mode")
        mock_publisher()
        return

    # Initialize logging
    try:
        hdds.logging.init(hdds.LogLevel.INFO)
    except:
        pass  # Already initialized

    print("=" * 60)
    print("HDDS HelloWorld Publisher")
    print("=" * 60)

    sensor_id = generate_sensor_id()
    print(f"Sensor ID: 0x{sensor_id:08X}")

    # Create participant
    with hdds.Participant("hello_publisher") as participant:
        print(f"Participant: {participant.name} (domain={participant.domain_id})")

        # Create writer with reliable QoS
        qos = hdds.QoS.reliable().history_depth(10)
        writer = participant.create_writer("HelloWorld/SensorData", qos=qos)
        print(f"Writer created for topic: HelloWorld/SensorData")
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

                # Serialize to CDR2
                # Add encapsulation header (CDR2 LE)
                encap = struct.pack('<HH', 0x0001, 0x0000)  # CDR_LE, options=0
                payload = encap + msg.encode_cdr2_le()

                # Write
                writer.write(payload)

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
    try:
        # Set library path to local build
        import os
        os.environ.setdefault('HDDS_LIB_PATH', os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'target', 'release'))
        import hdds
        hdds._native.get_lib()  # Force load to check availability
    except (ImportError, OSError) as e:
        print(f"HDDS Python SDK not available ({e}), using mock mode")
        mock_subscriber()
        return

    # Initialize logging
    try:
        hdds.logging.init(hdds.LogLevel.INFO)
    except:
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

        try:
            while True:
                # Try to take data
                data = reader.take()

                if data:
                    # Skip encapsulation header (4 bytes)
                    payload = data[4:]

                    # Deserialize
                    try:
                        msg, _ = SensorData.decode_cdr2_le(payload)

                        # Calculate age
                        now = get_timestamp_ns()
                        age_ms = (now - msg.timestamp) / 1_000_000

                        print(f"Received: timestamp={msg.timestamp}, "
                              f"id=0x{msg.id:08X}, value={msg.value:.1f}, "
                              f"age={age_ms:.2f}ms")
                    except Exception as e:
                        print(f"Decode error: {e}")
                else:
                    # No data, wait a bit
                    time.sleep(0.01)

        except KeyboardInterrupt:
            print("\nSubscriber stopped.")

def mock_publisher():
    """Mock publisher for testing without HDDS library."""
    print("=" * 60)
    print("MOCK HelloWorld Publisher (no HDDS library)")
    print("=" * 60)

    sensor_id = generate_sensor_id()
    print(f"Sensor ID: 0x{sensor_id:08X}")
    print("-" * 60)

    value = 0.0
    seq = 0

    try:
        while True:
            msg = SensorData(
                timestamp=get_timestamp_ns(),
                id=sensor_id,
                value=value
            )

            # Test serialization
            encoded = msg.encode_cdr2_le()
            decoded, _ = SensorData.decode_cdr2_le(encoded)

            assert decoded.timestamp == msg.timestamp
            assert decoded.id == msg.id
            assert abs(decoded.value - msg.value) < 0.001

            print(f"[{seq:04d}] Mock send: timestamp={msg.timestamp}, "
                  f"id=0x{msg.id:08X}, value={msg.value:.1f} "
                  f"(encoded={len(encoded)} bytes, roundtrip OK)")

            value += 0.5
            seq += 1
            time.sleep(1.0)

    except KeyboardInterrupt:
        print("\nMock publisher stopped.")

def mock_subscriber():
    """Mock subscriber for testing without HDDS library."""
    print("=" * 60)
    print("MOCK HelloWorld Subscriber (no HDDS library)")
    print("=" * 60)
    print("Would wait for data here...")
    print("Press Ctrl+C to exit")

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nMock subscriber stopped.")

def main():
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
