# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Generated from Enums.idl
Demonstrates enum types
"""
from dataclasses import dataclass
from enum import IntEnum
import struct


class Color(IntEnum):
    """Color enum"""
    RED = 0
    GREEN = 1
    BLUE = 2


class Status(IntEnum):
    """Status enum with explicit values"""
    UNKNOWN = 0
    PENDING = 10
    ACTIVE = 20
    COMPLETED = 30
    FAILED = 100


@dataclass
class EnumDemo:
    """Container for enum values"""
    color: Color = Color.RED
    status: Status = Status.UNKNOWN

    def serialize(self) -> bytes:
        return struct.pack('<II', int(self.color), int(self.status))

    @classmethod
    def deserialize(cls, data: bytes) -> 'EnumDemo':
        if len(data) < 8:
            raise ValueError("Buffer too small for enums")
        color_val, status_val = struct.unpack('<II', data[:8])
        return cls(
            color=Color(color_val),
            status=Status(status_val),
        )
