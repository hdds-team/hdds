#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Nested Structs Sample - Demonstrates nested/composite DDS types

This sample shows how to work with nested types:
- Point (x, y, z coordinates)
- Pose (position + orientation as Points)
- Robot (complex type with nested structs and sequences)
"""

import sys
import math
sys.path.insert(0, '.')

from generated.Nested import Point, Pose, Robot


def main():
    print("=== HDDS Nested Struct Types Sample ===\n")

    # Point - simple nested struct
    print("--- Point ---")
    point = Point(x=10.5, y=20.3, z=0.0)

    print(f"Original: Point({point.x:.1f}, {point.y:.1f}, {point.z:.1f})")

    data = point.encode_cdr2_le()
    print(f"Serialized size: {len(data)} bytes (3 x f64)")

    deser, _ = Point.decode_cdr2_le(data)
    print(f"Deserialized: Point({deser.x:.1f}, {deser.y:.1f}, {deser.z:.1f})")

    if point == deser:
        print("[OK] Point round-trip successful\n")

    # Pose - struct containing nested Point structs
    print("--- Pose ---")
    pose = Pose(
        position=Point(x=100.0, y=200.0, z=0.0),
        orientation=Point(x=0.0, y=0.0, z=math.pi / 4.0),  # 45 degrees yaw
    )

    print("Original Pose:")
    print(f"  position: ({pose.position.x:.1f}, {pose.position.y:.1f}, {pose.position.z:.1f})")
    print(f"  orientation: ({pose.orientation.x:.4f}, {pose.orientation.y:.4f}, {pose.orientation.z:.4f}) rad")

    data = pose.encode_cdr2_le()
    print(f"Serialized size: {len(data)} bytes (6 x f64)")

    deser, _ = Pose.decode_cdr2_le(data)
    print("Deserialized Pose:")
    print(f"  position: ({deser.position.x:.1f}, {deser.position.y:.1f}, {deser.position.z:.1f})")
    print(f"  orientation: ({deser.orientation.x:.4f}, {deser.orientation.y:.4f}, {deser.orientation.z:.4f}) rad")

    if pose == deser:
        print("[OK] Pose round-trip successful\n")

    # Robot - complex type with nested structs and sequences
    print("--- Robot ---")
    robot = Robot(
        name="RobotOne",
        pose=Pose(
            position=Point(x=0.0, y=0.0, z=0.0),
            orientation=Point(x=0.0, y=0.0, z=0.0),
        ),
        trajectory=[
            Point(x=10.0, y=0.0, z=0.0),
            Point(x=10.0, y=10.0, z=0.0),
            Point(x=0.0, y=10.0, z=0.0),
            Point(x=0.0, y=0.0, z=0.0),
        ],
    )

    print("Original Robot:")
    print(f'  name: "{robot.name}"')
    print(f"  pose: ({robot.pose.position.x:.1f}, {robot.pose.position.y:.1f}, {robot.pose.position.z:.1f})")
    print(f"  trajectory ({len(robot.trajectory)}):")
    for i, wp in enumerate(robot.trajectory):
        print(f"    [{i}] ({wp.x:.1f}, {wp.y:.1f}, {wp.z:.1f})")

    data = robot.encode_cdr2_le()
    print(f"Serialized size: {len(data)} bytes")

    deser, _ = Robot.decode_cdr2_le(data)
    print("Deserialized Robot:")
    print(f'  name: "{deser.name}"')
    print(f"  pose: ({deser.pose.position.x:.1f}, {deser.pose.position.y:.1f}, {deser.pose.position.z:.1f})")
    print(f"  trajectory: {len(deser.trajectory)}")

    if robot == deser:
        print("[OK] Robot round-trip successful\n")

    # Robot with no trajectory
    print("--- Robot with empty trajectory ---")
    simple_robot = Robot(
        name="SimpleBot",
        pose=Pose(
            position=Point(x=5.0, y=5.0, z=0.0),
            orientation=Point(x=0.0, y=0.0, z=math.pi),
        ),
        trajectory=[],
    )

    simple_data = simple_robot.encode_cdr2_le()
    simple_deser, _ = Robot.decode_cdr2_le(simple_data)

    print(f'Robot "{simple_deser.name}" with {len(simple_deser.trajectory)} trajectory points')
    if simple_robot == simple_deser:
        print("[OK] Empty trajectory handled correctly\n")

    # Test default values
    print("--- Default Values ---")
    default_point = Point(x=0.0, y=0.0, z=0.0)
    default_pose = Pose(position=default_point, orientation=default_point)
    default_robot = Robot(name="", pose=default_pose, trajectory=[])

    print(f"Default Point: ({default_point.x}, {default_point.y}, {default_point.z})")
    print(f"Default Pose orientation: ({default_pose.orientation.x}, {default_pose.orientation.y}, {default_pose.orientation.z})")
    print(f'Default Robot name: "{default_robot.name}"')

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
