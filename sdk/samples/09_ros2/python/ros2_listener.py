#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
ROS2 Listener - HDDS subscriber on /chatter, decodes std_msgs/String.

This uses HDDS directly to subscribe to DDS messages compatible with ROS2.
In production, use `RMW_IMPLEMENTATION=rmw_hdds` with standard rclpy instead.

The topic "rt/chatter" in DDS maps to "/chatter" in ROS2 (rt/ = ROS Topic prefix).
This subscriber is compatible with `ros2 run demo_nodes_cpp talker`.

Usage:
    python ros2_listener.py
    python ros2_listener.py --timeout 30

Expected output:
    [Listener] I heard: "Hello HDDS World: 0"
    [Listener] I heard: "Hello HDDS World: 1"
    ...
"""

import os
import sys
import struct
import time
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'python'))

import hdds


def decode_ros2_string(data: bytes) -> str:
    """Decode a ROS2 std_msgs/String from CDR bytes.

    ROS2 String message layout (CDR little-endian):
      - uint32 length (including null terminator)
      - char[length] data (null-terminated)
    """
    if len(data) < 4:
        return ""
    length = struct.unpack_from('<I', data, 0)[0]
    if length == 0:
        return ""
    # Strip null terminator
    return data[4:4 + length - 1].decode('utf-8', errors='replace')


def main() -> int:
    parser = argparse.ArgumentParser(description='HDDS ROS2-compatible listener')
    parser.add_argument('--timeout', type=float, default=5.0, help='Wait timeout (s)')
    parser.add_argument('--count', type=int, default=50, help='Messages to receive')
    parser.add_argument('--domain', type=int, default=0, help='DDS domain ID')
    args = parser.parse_args()

    print("=" * 60)
    print("HDDS ROS2 Listener")
    print("Topic: rt/chatter (ROS2: /chatter)")
    print("Type: std_msgs/msg/String (CDR-decoded)")
    print("=" * 60)
    print()

    hdds.logging.init(hdds.LogLevel.INFO)

    participant = hdds.Participant(
        "ros2_listener", domain_id=args.domain,
        transport=hdds.TransportMode.UDP_MULTICAST,
    )
    print(f"[OK] Participant created (domain_id={args.domain})")

    reader = participant.create_reader("rt/chatter", qos=hdds.QoS.reliable())
    print("[OK] Reader created on 'rt/chatter'")

    waitset = hdds.WaitSet()
    waitset.attach_reader(reader)
    print("[OK] WaitSet attached")
    print(f"Waiting for messages (timeout={args.timeout}s)...\n")

    received = 0
    while received < args.count:
        if waitset.wait(timeout=args.timeout):
            while True:
                data = reader.take()
                if data is None:
                    break
                msg = decode_ros2_string(data)
                received += 1
                print(f"  [Listener] I heard: \"{msg}\"")
        else:
            print("  (waiting for talker node...)")

    waitset.close()
    print(f"\nListener finished. Received {received} messages.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
