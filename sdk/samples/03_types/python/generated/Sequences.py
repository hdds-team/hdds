# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Generated from Sequences.idl
Demonstrates sequence types
"""
from dataclasses import dataclass, field
from typing import List
import struct


@dataclass
class LongSeq:
    """Long sequence (unbounded)"""
    values: List[int] = field(default_factory=list)

    def serialize(self) -> bytes:
        parts = [struct.pack('<I', len(self.values))]
        for v in self.values:
            parts.append(struct.pack('<i', v))
        return b''.join(parts)

    @classmethod
    def deserialize(cls, data: bytes) -> 'LongSeq':
        if len(data) < 4:
            raise ValueError("Buffer too small for sequence length")
        count = struct.unpack('<I', data[0:4])[0]
        pos = 4
        if pos + count * 4 > len(data):
            raise ValueError("Buffer too small for sequence data")
        values = []
        for _ in range(count):
            values.append(struct.unpack('<i', data[pos:pos+4])[0])
            pos += 4
        return cls(values=values)


@dataclass
class StringSeq:
    """String sequence (unbounded)"""
    values: List[str] = field(default_factory=list)

    def serialize(self) -> bytes:
        parts = [struct.pack('<I', len(self.values))]
        for s in self.values:
            encoded = s.encode('utf-8')
            parts.append(struct.pack('<I', len(encoded)))
            parts.append(encoded)
            parts.append(b'\x00')
        return b''.join(parts)

    @classmethod
    def deserialize(cls, data: bytes) -> 'StringSeq':
        if len(data) < 4:
            raise ValueError("Buffer too small for sequence length")
        count = struct.unpack('<I', data[0:4])[0]
        pos = 4
        values = []
        for _ in range(count):
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
class BoundedLongSeq:
    """Bounded long sequence (max 10 elements)"""
    MAX_SIZE: int = 10
    values: List[int] = field(default_factory=list)

    def __post_init__(self):
        if len(self.values) > self.MAX_SIZE:
            raise ValueError(f"Sequence exceeds maximum size of {self.MAX_SIZE}")

    def serialize(self) -> bytes:
        parts = [struct.pack('<I', len(self.values))]
        for v in self.values:
            parts.append(struct.pack('<i', v))
        return b''.join(parts)

    @classmethod
    def deserialize(cls, data: bytes) -> 'BoundedLongSeq':
        if len(data) < 4:
            raise ValueError("Buffer too small for sequence length")
        count = struct.unpack('<I', data[0:4])[0]
        if count > cls.MAX_SIZE:
            raise ValueError(f"Sequence exceeds maximum size of {cls.MAX_SIZE}")
        pos = 4
        if pos + count * 4 > len(data):
            raise ValueError("Buffer too small for sequence data")
        values = []
        for _ in range(count):
            values.append(struct.unpack('<i', data[pos:pos+4])[0])
            pos += 4
        return cls(values=values)
