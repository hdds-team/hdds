# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Generated from Nested.idl
Demonstrates nested struct types
"""
from dataclasses import dataclass, field
from typing import List
import struct


@dataclass
class Point:
    """2D Point"""
    x: float = 0.0
    y: float = 0.0

    def serialize(self) -> bytes:
        return struct.pack('<dd', self.x, self.y)

    @classmethod
    def deserialize(cls, data: bytes) -> 'Point':
        if len(data) < 16:
            raise ValueError("Buffer too small for Point")
        x, y = struct.unpack('<dd', data[:16])
        return cls(x=x, y=y)


@dataclass
class Pose:
    """Position and orientation"""
    position: Point = field(default_factory=Point)
    orientation: float = 0.0  # radians

    def serialize(self) -> bytes:
        return self.position.serialize() + struct.pack('<d', self.orientation)

    @classmethod
    def deserialize(cls, data: bytes) -> 'Pose':
        if len(data) < 24:
            raise ValueError("Buffer too small for Pose")
        position = Point.deserialize(data[:16])
        orientation = struct.unpack('<d', data[16:24])[0]
        return cls(position=position, orientation=orientation)


@dataclass
class Robot:
    """Robot with nested types"""
    id: int = 0
    name: str = ""
    pose: Pose = field(default_factory=Pose)
    waypoints: List[Point] = field(default_factory=list)

    def serialize(self) -> bytes:
        parts = []

        # ID
        parts.append(struct.pack('<I', self.id))

        # Name
        name_bytes = self.name.encode('utf-8')
        parts.append(struct.pack('<I', len(name_bytes)))
        parts.append(name_bytes)
        parts.append(b'\x00')

        # Pose
        parts.append(self.pose.serialize())

        # Waypoints
        parts.append(struct.pack('<I', len(self.waypoints)))
        for wp in self.waypoints:
            parts.append(wp.serialize())

        return b''.join(parts)

    @classmethod
    def deserialize(cls, data: bytes) -> 'Robot':
        pos = 0

        # ID
        if pos + 4 > len(data):
            raise ValueError("Buffer too small for robot id")
        robot_id = struct.unpack('<I', data[pos:pos+4])[0]
        pos += 4

        # Name
        if pos + 4 > len(data):
            raise ValueError("Buffer too small for name length")
        name_len = struct.unpack('<I', data[pos:pos+4])[0]
        pos += 4
        if pos + name_len + 1 > len(data):
            raise ValueError("Buffer too small for name")
        name = data[pos:pos+name_len].decode('utf-8')
        pos += name_len + 1

        # Pose
        if pos + 24 > len(data):
            raise ValueError("Buffer too small for pose")
        pose = Pose.deserialize(data[pos:pos+24])
        pos += 24

        # Waypoints
        if pos + 4 > len(data):
            raise ValueError("Buffer too small for waypoint count")
        wp_count = struct.unpack('<I', data[pos:pos+4])[0]
        pos += 4

        waypoints = []
        for _ in range(wp_count):
            if pos + 16 > len(data):
                raise ValueError("Buffer too small for waypoint")
            waypoints.append(Point.deserialize(data[pos:pos+16]))
            pos += 16

        return cls(id=robot_id, name=name, pose=pose, waypoints=waypoints)
