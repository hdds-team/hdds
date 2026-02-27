#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
ROS2 Talker - HDDS publisher mimicking ROS2 std_msgs/String on /chatter.

This uses HDDS directly to publish DDS messages compatible with ROS2.
In production, use `RMW_IMPLEMENTATION=rmw_hdds` with standard rclpy instead.

The topic "rt/chatter" in DDS maps to "/chatter" in ROS2 (rt/ = ROS Topic prefix).
This publisher is compatible with `ros2 topic echo /chatter std_msgs/msg/String`.

Usage:
    python ros2_talker.py
    python ros2_talker.py --rate 10  # 10 Hz publish rate

Expected output:
    [Talker] Publishing: "Hello HDDS World: 0"
    [Talker] Publishing: "Hello HDDS World: 1"
    ...
"""

import os
import sys
import struct
import time
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'python'))

import hdds


def encode_ros2_string(text: str) -> bytes:
    """Encode a string in ROS2 std_msgs/String CDR format.

    ROS2 String message layout (CDR little-endian):
      - uint32 length (including null terminator)
      - char[length] data (null-terminated)
    """
    encoded = text.encode('utf-8') + b'\x00'
    return struct.pack('<I', len(encoded)) + encoded


def main() -> int:
    parser = argparse.ArgumentParser(description='HDDS ROS2-compatible talker')
    parser.add_argument('--rate', type=float, default=2.0, help='Publish rate in Hz')
    parser.add_argument('--count', type=int, default=50, help='Number of messages')
    parser.add_argument('--domain', type=int, default=0, help='DDS domain ID')
    args = parser.parse_args()

    print("=" * 60)
    print("HDDS ROS2 Talker")
    print("Topic: rt/chatter (ROS2: /chatter)")
    print("Type: std_msgs/msg/String (CDR-encoded)")
    print("=" * 60)
    print()

    hdds.logging.init(hdds.LogLevel.INFO)

    participant = hdds.Participant(
        "ros2_talker", domain_id=args.domain,
        transport=hdds.TransportMode.UDP_MULTICAST,
    )
    print(f"[OK] Participant created (domain_id={args.domain})")

    # ROS2 default QoS for /chatter is RELIABLE
    writer = participant.create_writer("rt/chatter", qos=hdds.QoS.reliable())
    print(f"[OK] Writer created on 'rt/chatter'")
    print(f"[OK] Publishing at {args.rate} Hz\n")

    period = 1.0 / args.rate
    for i in range(args.count):
        msg = f"Hello HDDS World: {i}"
        payload = encode_ros2_string(msg)
        writer.write(payload)
        print(f"  [Talker] Publishing: \"{msg}\"")
        time.sleep(period)

    print(f"\nTalker finished. Published {args.count} messages.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
