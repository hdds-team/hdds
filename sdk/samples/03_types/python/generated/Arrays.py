# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Generated from Arrays.idl
Demonstrates array types
"""
from dataclasses import dataclass, field
from typing import List
import struct


@dataclass
class LongArray:
    """Fixed-size long array (10 elements)"""
    values: List[int] = field(default_factory=lambda: [0] * 10)

    def __post_init__(self):
        if len(self.values) != 10:
            raise ValueError("LongArray must have exactly 10 elements")

    def serialize(self) -> bytes:
        return struct.pack('<10i', *self.values)

    @classmethod
    def deserialize(cls, data: bytes) -> 'LongArray':
        if len(data) < 40:
            raise ValueError("Buffer too small for array")
        values = list(struct.unpack('<10i', data[:40]))
        return cls(values=values)


@dataclass
class StringArray:
    """Fixed-size string array (5 elements)"""
    values: List[str] = field(default_factory=lambda: [""] * 5)

    def __post_init__(self):
        if len(self.values) != 5:
            raise ValueError("StringArray must have exactly 5 elements")

    def serialize(self) -> bytes:
        parts = []
        for s in self.values:
            encoded = s.encode('utf-8')
            parts.append(struct.pack('<I', len(encoded)))
            parts.append(encoded)
            parts.append(b'\x00')
        return b''.join(parts)

    @classmethod
    def deserialize(cls, data: bytes) -> 'StringArray':
        pos = 0
        values = []
        for _ in range(5):
            if pos + 4 > len(data):
                raise ValueError("Buffer too small for string length")
            slen = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            if pos + slen + 1 > len(data):
                raise ValueError("Buffer too small for string data")
            values.append(data[pos:pos+slen].decode('utf-8'))
            pos += slen + 1
        return cls(values=values)


@dataclass
class Matrix:
    """2D matrix (3x3)"""
    values: List[List[float]] = field(default_factory=lambda: [[0.0] * 3 for _ in range(3)])

    def __post_init__(self):
        if len(self.values) != 3 or any(len(row) != 3 for row in self.values):
            raise ValueError("Matrix must be 3x3")

    @classmethod
    def identity(cls) -> 'Matrix':
        return cls(values=[
            [1.0, 0.0, 0.0],
            [0.0, 1.0, 0.0],
            [0.0, 0.0, 1.0],
        ])

    def serialize(self) -> bytes:
        parts = []
        for row in self.values:
            for v in row:
                parts.append(struct.pack('<d', v))
        return b''.join(parts)

    @classmethod
    def deserialize(cls, data: bytes) -> 'Matrix':
        if len(data) < 72:
            raise ValueError("Buffer too small for matrix")
        values = []
        pos = 0
        for _ in range(3):
            row = []
            for _ in range(3):
                row.append(struct.unpack('<d', data[pos:pos+8])[0])
                pos += 8
            values.append(row)
        return cls(values=values)
