# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Generated from Maps.idl
Demonstrates map types
"""
from dataclasses import dataclass, field
from typing import Dict
import struct


@dataclass
class StringLongMap:
    """String to long map"""
    entries: Dict[str, int] = field(default_factory=dict)

    def serialize(self) -> bytes:
        parts = [struct.pack('<I', len(self.entries))]
        for key, value in self.entries.items():
            key_bytes = key.encode('utf-8')
            parts.append(struct.pack('<I', len(key_bytes)))
            parts.append(key_bytes)
            parts.append(b'\x00')
            parts.append(struct.pack('<i', value))
        return b''.join(parts)

    @classmethod
    def deserialize(cls, data: bytes) -> 'StringLongMap':
        if len(data) < 4:
            raise ValueError("Buffer too small for map count")
        count = struct.unpack('<I', data[0:4])[0]
        pos = 4
        entries = {}

        for _ in range(count):
            if pos + 4 > len(data):
                raise ValueError("Buffer too small for key length")
            key_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            if pos + key_len + 1 + 4 > len(data):
                raise ValueError("Buffer too small for key/value")
            key = data[pos:pos+key_len].decode('utf-8')
            pos += key_len + 1
            value = struct.unpack('<i', data[pos:pos+4])[0]
            pos += 4
            entries[key] = value

        return cls(entries=entries)


@dataclass
class LongStringMap:
    """Long to string map"""
    entries: Dict[int, str] = field(default_factory=dict)

    def serialize(self) -> bytes:
        parts = [struct.pack('<I', len(self.entries))]
        for key, value in self.entries.items():
            parts.append(struct.pack('<i', key))
            val_bytes = value.encode('utf-8')
            parts.append(struct.pack('<I', len(val_bytes)))
            parts.append(val_bytes)
            parts.append(b'\x00')
        return b''.join(parts)

    @classmethod
    def deserialize(cls, data: bytes) -> 'LongStringMap':
        if len(data) < 4:
            raise ValueError("Buffer too small for map count")
        count = struct.unpack('<I', data[0:4])[0]
        pos = 4
        entries = {}

        for _ in range(count):
            if pos + 4 > len(data):
                raise ValueError("Buffer too small for key")
            key = struct.unpack('<i', data[pos:pos+4])[0]
            pos += 4
            if pos + 4 > len(data):
                raise ValueError("Buffer too small for value length")
            val_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            if pos + val_len + 1 > len(data):
                raise ValueError("Buffer too small for value")
            value = data[pos:pos+val_len].decode('utf-8')
            pos += val_len + 1
            entries[key] = value

        return cls(entries=entries)
