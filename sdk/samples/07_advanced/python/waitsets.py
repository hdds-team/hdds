#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
WaitSets Sample - Demonstrates condition-based event handling

WaitSets allow efficient waiting on multiple conditions:
- ReadConditions: data available on readers
- StatusConditions: entity status changes
- GuardConditions: application-triggered events

Key concepts:
- WaitSet creation and condition attachment
- Blocking vs timeout-based waiting
- Condition dispatching
"""

import os
import sys
import time
import struct
import threading
from dataclasses import dataclass
from typing import Optional

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'python'))

import hdds


@dataclass
class SensorReading:
    """Sample sensor data."""
    sensor_id: int = 0
    value: float = 0.0
    timestamp: int = 0

    def serialize(self) -> bytes:
        return struct.pack('<idq', self.sensor_id, self.value, self.timestamp)

    @classmethod
    def deserialize(cls, data: bytes) -> 'SensorReading':
        sensor_id, value, timestamp = struct.unpack('<idq', data)
        return cls(sensor_id, value, timestamp)


@dataclass
class Command:
    """Sample command data."""
    command_id: int = 0
    action: str = ""

    def serialize(self) -> bytes:
        action_bytes = self.action.encode('utf-8')
        return struct.pack(f'<iI{len(action_bytes)}s', self.command_id, len(action_bytes), action_bytes)

    @classmethod
    def deserialize(cls, data: bytes) -> 'Command':
        command_id, action_len = struct.unpack_from('<iI', data, 0)
        action = data[8:8 + action_len].decode('utf-8')
        return cls(command_id, action)


def print_waitset_overview():
    print("--- WaitSet Overview ---\n")
    print("WaitSet Architecture:\n")
    print("  +---------------------------------------------+")
    print("  |               WaitSet                       |")
    print("  |  +-----------+ +-----------+               |")
    print("  |  | Reader A  | | Reader B  |               |")
    print("  |  | (Sensors) | | (Commands)|               |")
    print("  |  +-----------+ +-----------+               |")
    print("  |  +-----------+                             |")
    print("  |  | GuardCond |                             |")
    print("  |  | (Shutdown)|                             |")
    print("  |  +-----------+                             |")
    print("  +---------------------------------------------+")
    print("                    |")
    print("                    v")
    print("              wait(timeout)")
    print("                    |")
    print("                    v")
    print("         Returns True/False")
    print()
    print("Condition Types:")
    print("  - DataReader: Data available on topic")
    print("  - GuardCondition: Application-triggered signal")
    print()


def main():
    print("=== HDDS WaitSets Sample ===\n")

    print_waitset_overview()

    # Initialize logging
    hdds.logging.init(hdds.LogLevel.INFO)

    # Create participant
    participant = hdds.Participant("WaitSetDemo")
    print("[OK] Participant created")

    # Create WaitSet
    waitset = hdds.WaitSet()
    print("[OK] WaitSet created\n")

    # Create readers for different topics
    print("--- Creating Readers and Conditions ---\n")

    sensor_reader = participant.create_reader("SensorTopic", qos=hdds.QoS.reliable())
    waitset.attach_reader(sensor_reader)
    print("[OK] Reader 'SensorTopic' attached to WaitSet")

    command_reader = participant.create_reader("CommandTopic", qos=hdds.QoS.reliable())
    waitset.attach_reader(command_reader)
    print("[OK] Reader 'CommandTopic' attached to WaitSet")

    # Guard condition for shutdown
    shutdown_guard = hdds.GuardCondition()
    waitset.attach_guard(shutdown_guard)
    print("[OK] GuardCondition 'shutdown' attached to WaitSet\n")

    # Create writers for publishing test data
    sensor_writer = participant.create_writer("SensorTopic", qos=hdds.QoS.reliable())
    command_writer = participant.create_writer("CommandTopic", qos=hdds.QoS.reliable())

    # Demonstrate waiting scenarios
    print("--- WaitSet Operations ---\n")

    timeout_secs = 1.0

    # Scenario 1: No conditions triggered
    print("Scenario 1: Wait with no triggered conditions")
    print(f"  Waiting up to {timeout_secs} seconds...")
    if not waitset.wait(timeout=timeout_secs):
        print("  [TIMEOUT] No conditions triggered\n")

    # Scenario 2: Sensor data arrives
    print("Scenario 2: Sensor data arrives")
    sensor_data = SensorReading(
        sensor_id=101,
        value=23.5,
        timestamp=int(time.time() * 1000)
    )
    sensor_writer.write(sensor_data.serialize())
    print("  [PUBLISHED] Sensor data")

    time.sleep(0.05)  # Brief delay for data propagation

    if waitset.wait(timeout=timeout_secs):
        print("  [WAKE] Condition triggered!")
        # Read all available sensor data
        while True:
            data = sensor_reader.take()
            if data is None:
                break
            reading = SensorReading.deserialize(data)
            print(f"    Received sensor {reading.sensor_id}: {reading.value}")
    print()

    # Scenario 3: Command arrives
    print("Scenario 3: Command data arrives")
    cmd = Command(command_id=1, action="start_recording")
    command_writer.write(cmd.serialize())
    print("  [PUBLISHED] Command")

    time.sleep(0.05)

    if waitset.wait(timeout=timeout_secs):
        print("  [WAKE] Condition triggered!")
        while True:
            data = command_reader.take()
            if data is None:
                break
            command = Command.deserialize(data)
            print(f"    Received command {command.command_id}: {command.action}")
    print()

    # Scenario 4: Multiple data sources
    print("Scenario 4: Multiple conditions trigger simultaneously")
    sensor_data2 = SensorReading(sensor_id=102, value=25.0, timestamp=int(time.time() * 1000))
    cmd2 = Command(command_id=2, action="calibrate")
    sensor_writer.write(sensor_data2.serialize())
    command_writer.write(cmd2.serialize())
    print("  [PUBLISHED] Both sensor and command data")

    time.sleep(0.05)

    if waitset.wait(timeout=timeout_secs):
        print("  [WAKE] Conditions triggered!")
        # Process both readers
        sensor_count = 0
        while True:
            data = sensor_reader.take()
            if data is None:
                break
            reading = SensorReading.deserialize(data)
            print(f"    Sensor {reading.sensor_id}: {reading.value}")
            sensor_count += 1

        cmd_count = 0
        while True:
            data = command_reader.take()
            if data is None:
                break
            command = Command.deserialize(data)
            print(f"    Command {command.command_id}: {command.action}")
            cmd_count += 1

        print(f"    Total: {sensor_count} sensor readings, {cmd_count} commands")
    print()

    # Scenario 5: Guard condition (shutdown signal)
    print("Scenario 5: Application triggers shutdown via GuardCondition")

    # Trigger guard condition from another thread
    def trigger_shutdown():
        time.sleep(0.2)
        shutdown_guard.trigger()
        print("  [SIGNAL] Shutdown triggered from background thread")

    trigger_thread = threading.Thread(target=trigger_shutdown)
    trigger_thread.start()

    print("  Waiting for shutdown signal...")
    if waitset.wait(timeout=5.0):
        print("  [WAKE] GuardCondition triggered - shutdown requested!")
    print()

    trigger_thread.join()

    # Event loop pattern
    print("--- Event Loop Pattern ---\n")
    print("Typical WaitSet event loop (Python):\n")
    print("  running = True")
    print("  while running:")
    print("      if waitset.wait(timeout=1.0):")
    print("          # Check guard condition first")
    print("          # (handled separately via trigger)")
    print("          ")
    print("          # Process sensor data")
    print("          while True:")
    print("              data = sensor_reader.take()")
    print("              if data is None:")
    print("                  break")
    print("              process_sensor(data)")
    print("          ")
    print("          # Process commands")
    print("          while True:")
    print("              data = command_reader.take()")
    print("              if data is None:")
    print("                  break")
    print("              if is_shutdown_command(data):")
    print("                  running = False")
    print("              else:")
    print("                  handle_command(data)")
    print()

    # Cleanup
    print("--- Cleanup ---\n")
    waitset.detach_reader(sensor_reader)
    print("[OK] Detached SensorTopic reader")
    waitset.detach_reader(command_reader)
    print("[OK] Detached CommandTopic reader")
    waitset.detach_guard(shutdown_guard)
    print("[OK] Detached shutdown GuardCondition")

    shutdown_guard.close()
    waitset.close()

    # Best practices
    print("\n--- WaitSet Best Practices ---\n")
    print("1. Use one WaitSet per processing thread")
    print("2. Prefer WaitSets over polling for efficiency")
    print("3. Use GuardConditions for inter-thread signaling")
    print("4. Set appropriate timeouts for responsiveness")
    print("5. Process all available data before waiting again")
    print("6. Detach conditions before closing resources")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
