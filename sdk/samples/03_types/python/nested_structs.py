#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Nested Structs Sample - Demonstrates nested/composite DDS types

This sample shows how to work with nested types:
- Point (x, y coordinates)
- Pose (position + orientation)
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
    point = Point(x=10.5, y=20.3)

    print(f"Original: Point({point.x:.1f}, {point.y:.1f})")

    data = point.serialize()
    print(f"Serialized size: {len(data)} bytes (2 × f64)")

    deser = Point.deserialize(data)
    print(f"Deserialized: Point({deser.x:.1f}, {deser.y:.1f})")

    if point == deser:
        print("[OK] Point round-trip successful\n")

    # Pose - struct containing another struct
    print("--- Pose ---")
    pose = Pose(
        position=Point(x=100.0, y=200.0),
        orientation=math.pi / 4.0,  # 45 degrees
    )

    print("Original Pose:")
    print(f"  position: ({pose.position.x:.1f}, {pose.position.y:.1f})")
    print(f"  orientation: {pose.orientation:.4f} rad ({math.degrees(pose.orientation):.1f}°)")

    data = pose.serialize()
    print(f"Serialized size: {len(data)} bytes (3 × f64)")

    deser = Pose.deserialize(data)
    print("Deserialized Pose:")
    print(f"  position: ({deser.position.x:.1f}, {deser.position.y:.1f})")
    print(f"  orientation: {deser.orientation:.4f} rad")

    if pose == deser:
        print("[OK] Pose round-trip successful\n")

    # Robot - complex type with nested structs and sequences
    print("--- Robot ---")
    robot = Robot(
        id=42,
        name="RobotOne",
        pose=Pose(position=Point(x=0.0, y=0.0), orientation=0.0),
        waypoints=[
            Point(x=10.0, y=0.0),
            Point(x=10.0, y=10.0),
            Point(x=0.0, y=10.0),
            Point(x=0.0, y=0.0),
        ],
    )

    print("Original Robot:")
    print(f"  id: {robot.id}")
    print(f'  name: "{robot.name}"')
    print(f"  pose: ({robot.pose.position.x:.1f}, {robot.pose.position.y:.1f}) @ {math.degrees(robot.pose.orientation):.1f}°")
    print(f"  waypoints ({len(robot.waypoints)}):")
    for i, wp in enumerate(robot.waypoints):
        print(f"    [{i}] ({wp.x:.1f}, {wp.y:.1f})")

    data = robot.serialize()
    print(f"Serialized size: {len(data)} bytes")

    deser = Robot.deserialize(data)
    print("Deserialized Robot:")
    print(f"  id: {deser.id}")
    print(f'  name: "{deser.name}"')
    print(f"  pose: ({deser.pose.position.x:.1f}, {deser.pose.position.y:.1f})")
    print(f"  waypoints: {len(deser.waypoints)}")

    if robot == deser:
        print("[OK] Robot round-trip successful\n")

    # Robot with no waypoints
    print("--- Robot with empty waypoints ---")
    simple_robot = Robot(
        id=1,
        name="SimpleBot",
        pose=Pose(position=Point(x=5.0, y=5.0), orientation=math.pi),
        waypoints=[],
    )

    simple_data = simple_robot.serialize()
    simple_deser = Robot.deserialize(simple_data)

    print(f'Robot "{simple_deser.name}" with {len(simple_deser.waypoints)} waypoints')
    if simple_robot == simple_deser:
        print("[OK] Empty waypoints handled correctly\n")

    # Test default values
    print("--- Default Values ---")
    default_point = Point()
    default_pose = Pose()
    default_robot = Robot()

    print(f"Default Point: ({default_point.x}, {default_point.y})")
    print(f"Default Pose orientation: {default_pose.orientation}")
    print(f"Default Robot id: {default_robot.id}")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
