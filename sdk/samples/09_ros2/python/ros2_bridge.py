#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
ROS2 Bridge - Bridges HDDS DDS topics to/from ROS2 topic namespace.

This uses HDDS natively. ROS2 nodes using rmw_hdds will interoperate transparently.
In production, use `RMW_IMPLEMENTATION=rmw_hdds` with standard rclpy instead.

The bridge subscribes on a "native" DDS topic and republishes on the
ROS2-prefixed topic (rt/<name>), and vice versa. This shows the core
mechanism of the ROS Middleware (RMW) layer.

Usage:
    python ros2_bridge.py --topic sensor_data
    python ros2_bridge.py --topic sensor_data --domain 42
"""

import os
import sys
import time
import argparse
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'python'))

import hdds


def forward_loop(waitset, reader, writer, label):
    """Forward messages between two DDS endpoints until waitset is closed."""
    count = 0
    while True:
        try:
            if not waitset.wait(timeout=1.0):
                continue
        except Exception:
            break
        while True:
            data = reader.take()
            if data is None:
                break
            writer.write(data)
            count += 1
            print(f"  [Bridge] {label} ({len(data)} bytes) [{count}]")


def main() -> int:
    parser = argparse.ArgumentParser(description='HDDS-ROS2 topic bridge')
    parser.add_argument('--topic', default='sensor_data', help='Topic to bridge')
    parser.add_argument('--domain', type=int, default=0, help='DDS domain ID')
    parser.add_argument('--duration', type=float, default=30.0, help='Run time (s)')
    args = parser.parse_args()

    ros2_topic = f"rt/{args.topic}"
    print("=" * 60)
    print(f"HDDS ROS2 Bridge: '{args.topic}' <-> '{ros2_topic}'")
    print("=" * 60)
    print("\nHow rmw_hdds works:")
    print("  1. ROS2 publishes to '/topic' via rclpy")
    print("  2. RMW maps '/topic' -> 'rt/topic' in DDS")
    print("  3. DDS discovery + RTPS transport deliver the data")
    print("  4. Remote RMW maps 'rt/topic' back to '/topic'\n")

    hdds.logging.init(hdds.LogLevel.INFO)

    participant = hdds.Participant(
        "ros2_bridge", domain_id=args.domain,
        transport=hdds.TransportMode.UDP_MULTICAST,
    )
    qos = hdds.QoS.reliable()

    # DDS-side and ROS2-side endpoints
    dds_reader = participant.create_reader(args.topic, qos=qos)
    ros2_writer = participant.create_writer(ros2_topic, qos=qos)
    ros2_reader = participant.create_reader(ros2_topic, qos=qos)
    dds_writer = participant.create_writer(args.topic, qos=qos)

    dds_ws = hdds.WaitSet()
    dds_ws.attach_reader(dds_reader)
    ros2_ws = hdds.WaitSet()
    ros2_ws.attach_reader(ros2_reader)

    # Start bidirectional forwarding threads
    t1 = threading.Thread(target=forward_loop, daemon=True,
                          args=(dds_ws, dds_reader, ros2_writer,
                                f"DDS->ROS2: '{args.topic}'->'{ros2_topic}'"))
    t2 = threading.Thread(target=forward_loop, daemon=True,
                          args=(ros2_ws, ros2_reader, dds_writer,
                                f"ROS2->DDS: '{ros2_topic}'->'{args.topic}'"))
    t1.start()
    t2.start()

    print(f"[OK] Bridge active (Ctrl+C to stop)\n")
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print("\n[OK] Interrupted")

    dds_ws.close()
    ros2_ws.close()
    print("\n=== Bridge stopped ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
