#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Content Filter Sample - Demonstrates content-filtered topics

Content filters allow subscribers to receive only data matching
SQL-like filter expressions, reducing network and CPU overhead.

Key concepts:
- ContentFilteredTopic creation
- SQL filter expressions
- Filter parameters
- Dynamic filter updates

Note: This sample demonstrates content filtering patterns. The actual
filtering is performed client-side since HDDS topic-level content
filtering requires application-level implementation.

NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for ContentFilteredTopic.
The native ContentFilteredTopic API is not yet exported to the C/C++/Python SDK.
This sample uses standard participant/writer/reader API to show the concept.
"""

import os
import sys
import random
import time
import struct
from dataclasses import dataclass
from typing import List, Optional

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'python'))

import hdds


@dataclass
class SensorData:
    """Sensor data type"""
    sensor_id: int = 0
    location: str = ""
    temperature: float = 0.0
    humidity: float = 0.0
    timestamp: int = 0

    def serialize(self) -> bytes:
        """Serialize to bytes."""
        location_bytes = self.location.encode('utf-8')
        # Format: sensor_id(i), loc_len(I), location(s), temp(d), humidity(d), timestamp(q)
        return struct.pack(
            f'<iI{len(location_bytes)}sddq',
            self.sensor_id,
            len(location_bytes),
            location_bytes,
            self.temperature,
            self.humidity,
            self.timestamp
        )

    @classmethod
    def deserialize(cls, data: bytes) -> 'SensorData':
        """Deserialize from bytes."""
        sensor_id, loc_len = struct.unpack_from('<iI', data, 0)
        offset = 8
        location = data[offset:offset + loc_len].decode('utf-8')
        offset += loc_len
        temperature, humidity, timestamp = struct.unpack_from('<ddq', data, offset)
        return cls(sensor_id, location, temperature, humidity, timestamp)


class ContentFilter:
    """Content filter for client-side filtering."""

    def __init__(self, expression: str, parameters: List[str]):
        self.expression = expression
        self.parameters = parameters

    def matches(self, data: SensorData) -> bool:
        """Check if data matches the filter expression."""
        # Simple expression parser for demonstration
        expr = self.expression
        for i, param in enumerate(self.parameters):
            expr = expr.replace(f'%{i}', param)

        # Parse simple conditions
        if ' AND ' in expr:
            parts = expr.split(' AND ')
            return all(self._eval_condition(p.strip(), data) for p in parts)
        elif ' OR ' in expr:
            parts = expr.split(' OR ')
            return any(self._eval_condition(p.strip(), data) for p in parts)
        else:
            return self._eval_condition(expr, data)

    def _eval_condition(self, cond: str, data: SensorData) -> bool:
        """Evaluate a single condition."""
        if '>' in cond:
            field, value = cond.split('>')
            field = field.strip()
            value = float(value.strip())
            return getattr(data, field, 0) > value
        elif '<' in cond:
            field, value = cond.split('<')
            field = field.strip()
            value = float(value.strip())
            return getattr(data, field, 0) < value
        elif '=' in cond:
            field, value = cond.split('=')
            field = field.strip()
            value = value.strip().strip("'\"")
            return str(getattr(data, field, '')) == value
        return False


def print_filter_info():
    print("--- Content Filter Overview ---\n")
    print("Content filters use SQL-like WHERE clause syntax:\n")
    print("  Filter Expression          | Description")
    print("  ---------------------------|---------------------------")
    print("  temperature > 25.0         | High temperature readings")
    print("  location = 'Room1'         | Specific location only")
    print("  sensor_id BETWEEN 1 AND 10 | Sensor ID range")
    print("  humidity > %0              | Parameterized threshold")
    print("  location LIKE 'Building%'  | Pattern matching")
    print()


def main():
    print("=== HDDS Content Filter Sample ===\n")
    print("NOTE: CONCEPT DEMO - Native ContentFilteredTopic API not yet in SDK.")
    print("      Using standard pub/sub API to demonstrate the pattern.\n")

    print_filter_info()

    # Initialize logging
    hdds.logging.init(hdds.LogLevel.INFO)

    # Create participant
    participant = hdds.Participant("ContentFilterDemo")
    print("[OK] Participant created")

    # Create writer with reliable QoS
    writer = participant.create_writer("SensorData", qos=hdds.QoS.reliable())
    print("[OK] DataWriter created (publishes all sensor data)")

    # Create reader
    reader = participant.create_reader("SensorData", qos=hdds.QoS.reliable())
    print("[OK] DataReader created\n")

    # Define content filters (client-side filtering)
    print("--- Creating Content Filters ---\n")

    # Filter 1: High temperature
    high_temp_filter = ContentFilter("temperature > %0", ["30.0"])
    print("[OK] Filter 1: temperature > 30.0 (high temperature alerts)")

    # Filter 2: Specific location
    server_room_filter = ContentFilter("location = %0", ["ServerRoom"])
    print("[OK] Filter 2: location = 'ServerRoom'")

    # Filter 3: Combined filter
    alert_filter = ContentFilter("temperature > %0 AND humidity > %1", ["25.0", "60.0"])
    print("[OK] Filter 3: temperature > 25.0 AND humidity > 60.0\n")

    # Generate and publish sensor data
    print("--- Publishing Sensor Data ---\n")

    locations = ["ServerRoom", "Office1", "Lobby", "DataCenter"]
    samples: List[SensorData] = []

    for i in range(10):
        data = SensorData(
            sensor_id=i + 1,
            location=locations[i % 4],
            temperature=random.uniform(20.0, 40.0),
            humidity=random.uniform(40.0, 80.0),
            timestamp=int(time.time() * 1000)
        )
        samples.append(data)

        print(f"Publishing: sensor={data.sensor_id}, loc={data.location}, "
              f"temp={data.temperature:.1f}, hum={data.humidity:.1f}")

        writer.write(data.serialize())

    # Allow time for data to be received
    time.sleep(0.1)

    # Show filter results
    print("\n--- Filter Results ---\n")

    print("High Temperature Filter (temp > 30.0):")
    for s in samples:
        if high_temp_filter.matches(s):
            print(f"  [MATCH] sensor={s.sensor_id}, temp={s.temperature:.1f}")

    print("\nServerRoom Filter (location = 'ServerRoom'):")
    for s in samples:
        if server_room_filter.matches(s):
            print(f"  [MATCH] sensor={s.sensor_id}, loc={s.location}")

    print("\nEnvironment Alert Filter (temp > 25 AND hum > 60):")
    for s in samples:
        if alert_filter.matches(s):
            print(f"  [MATCH] sensor={s.sensor_id}, temp={s.temperature:.1f}, hum={s.humidity:.1f}")

    # Dynamic filter update
    print("\n--- Dynamic Filter Update ---\n")
    print("Changing high temperature threshold from 30.0 to 35.0...")

    high_temp_filter.expression = "temperature > %0"
    high_temp_filter.parameters = ["35.0"]
    print("[OK] Filter updated dynamically")

    print("\nNew matches (temp > 35.0):")
    for s in samples:
        if high_temp_filter.matches(s):
            print(f"  [MATCH] sensor={s.sensor_id}, temp={s.temperature:.1f}")

    # Read any available data from the reader
    print("\n--- Reading Data from Reader ---\n")
    count = 0
    while True:
        data = reader.take()
        if data is None:
            break
        sample = SensorData.deserialize(data)
        # Apply filter on received data
        if high_temp_filter.matches(sample):
            print(f"  [FILTERED] sensor={sample.sensor_id}, temp={sample.temperature:.1f}")
        count += 1
    print(f"  Total samples received: {count}")

    # Benefits summary
    print("\n--- Content Filter Benefits ---\n")
    print("1. Network Efficiency: Filtering at source reduces traffic")
    print("2. CPU Efficiency: Subscriber processes only relevant data")
    print("3. Flexibility: SQL-like expressions for complex filters")
    print("4. Dynamic Updates: Change filters without recreating readers")
    print("5. Parameterization: Use %0, %1 for runtime values")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
