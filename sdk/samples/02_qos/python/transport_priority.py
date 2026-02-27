#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: Transport Priority (Python)

Demonstrates TRANSPORT_PRIORITY QoS for network priority levels.
Alarm data uses high priority (10), telemetry uses low priority (0).
Priority mapping depends on OS support (e.g., DSCP/TOS bits).

Usage:
    python transport_priority.py        # Subscriber (monitors both topics)
    python transport_priority.py pub    # Publisher (sends on both topics)
"""

import sys
import time

sys.path.insert(0, str(__file__ + "/../../01_basics/python"))

import hdds
from generated.HelloWorld import HelloWorld

PRIORITY_HIGH = 10  # Alarm data
PRIORITY_LOW = 0    # Telemetry data
NUM_MESSAGES = 5


def run_publisher(participant):
    """Publish alarm (high priority) and telemetry (low priority) data."""
    qos_alarm = hdds.QoS.reliable().transport_priority(PRIORITY_HIGH)
    qos_telemetry = hdds.QoS.reliable().transport_priority(PRIORITY_LOW)

    writer_alarm = participant.create_writer("AlarmTopic", qos=qos_alarm)
    writer_telemetry = participant.create_writer("TelemetryTopic", qos=qos_telemetry)

    print(f"Publishing {NUM_MESSAGES} messages on each topic...")
    print(f"  AlarmTopic:     priority = {PRIORITY_HIGH} (high)")
    print(f"  TelemetryTopic: priority = {PRIORITY_LOW} (low)\n")

    start = time.monotonic()

    # Send interleaved bursts: telemetry first, then alarm
    for i in range(NUM_MESSAGES):
        elapsed = int((time.monotonic() - start) * 1000)

        msg_tel = HelloWorld(id=i + 1, message=f"Telemetry #{i + 1}")
        writer_telemetry.write(msg_tel.serialize())
        print(f"  [{elapsed:5d}ms] Sent Telemetry (priority={PRIORITY_LOW})  id={msg_tel.id}")

        msg_alarm = HelloWorld(id=i + 1, message=f"ALARM #{i + 1}")
        writer_alarm.write(msg_alarm.serialize())
        print(f"  [{elapsed:5d}ms] Sent Alarm     (priority={PRIORITY_HIGH}) id={msg_alarm.id}")

        time.sleep(0.2)

    print("\nDone publishing.")
    print("Note: With OS/DSCP support, alarm data may arrive before telemetry.")


def run_subscriber(participant):
    """Monitor both topics and observe arrival order."""
    qos_alarm = hdds.QoS.reliable().transport_priority(PRIORITY_HIGH)
    qos_telemetry = hdds.QoS.reliable().transport_priority(PRIORITY_LOW)

    reader_alarm = participant.create_reader("AlarmTopic", qos=qos_alarm)
    reader_telemetry = participant.create_reader("TelemetryTopic", qos=qos_telemetry)

    waitset = hdds.WaitSet()
    waitset.attach(reader_alarm)
    waitset.attach(reader_telemetry)

    print("Subscribing to both topics...")
    print(f"  AlarmTopic:     priority = {PRIORITY_HIGH} (high)")
    print(f"  TelemetryTopic: priority = {PRIORITY_LOW} (low)")
    print("\nMonitoring arrival order...\n")

    received_alarm = 0
    received_telemetry = 0
    arrival_order = []
    start = time.monotonic()
    timeouts = 0

    while timeouts < 3:
        if waitset.wait(timeout_secs=2.0):
            while True:
                data = reader_alarm.take()
                if data is None:
                    break
                msg = HelloWorld.deserialize(data)
                elapsed = int((time.monotonic() - start) * 1000)
                print(f"  [{elapsed:5d}ms] ALARM     received id={msg.id}")
                arrival_order.append(f"ALARM-{msg.id}")
                received_alarm += 1

            while True:
                data = reader_telemetry.take()
                if data is None:
                    break
                msg = HelloWorld.deserialize(data)
                elapsed = int((time.monotonic() - start) * 1000)
                print(f"  [{elapsed:5d}ms] Telemetry received id={msg.id}")
                arrival_order.append(f"TEL-{msg.id}")
                received_telemetry += 1

            timeouts = 0
        else:
            timeouts += 1

    print()
    print("-" * 60)
    print(f"Summary:")
    print(f"  Alarm     (priority={PRIORITY_HIGH}): {received_alarm} messages")
    print(f"  Telemetry (priority={PRIORITY_LOW}):  {received_telemetry} messages")
    print(f"  Arrival order: {' -> '.join(arrival_order[:10])}")
    print()
    print("Note: Transport priority maps to OS-level DSCP/TOS bits.")
    print("Actual prioritization depends on network stack and QoS support.")
    print("Without OS support, arrival order may appear identical.")
    print("-" * 60)


def main():
    is_publisher = len(sys.argv) > 1 and sys.argv[1] == "pub"

    hdds.logging.init(hdds.LogLevel.INFO)

    print("=" * 60)
    print("Transport Priority Demo")
    print("QoS: TRANSPORT_PRIORITY - network-level priority hints")
    print("=" * 60)

    with hdds.Participant("TransportPriorityDemo") as participant:
        if is_publisher:
            run_publisher(participant)
        else:
            run_subscriber(participant)


if __name__ == "__main__":
    main()
