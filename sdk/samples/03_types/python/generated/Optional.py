# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Generated from Optional.idl
Demonstrates optional field types
"""
from dataclasses import dataclass, field
from typing import Optional
import struct


@dataclass
class OptionalFields:
    """Struct with optional fields"""
    required_id: int = 0
    optional_name: Optional[str] = None
    optional_value: Optional[float] = None
    optional_count: Optional[int] = None

    def serialize(self) -> bytes:
        parts = []

        # Required ID
        parts.append(struct.pack('<I', self.required_id))

        # Presence flags
        flags = 0
        if self.optional_name is not None:
            flags |= 1 << 0
        if self.optional_value is not None:
            flags |= 1 << 1
        if self.optional_count is not None:
            flags |= 1 << 2
        parts.append(struct.pack('<B', flags))

        # Optional name
        if self.optional_name is not None:
            encoded = self.optional_name.encode('utf-8')
            parts.append(struct.pack('<I', len(encoded)))
            parts.append(encoded)
            parts.append(b'\x00')

        # Optional value
        if self.optional_value is not None:
            parts.append(struct.pack('<d', self.optional_value))

        # Optional count
        if self.optional_count is not None:
            parts.append(struct.pack('<i', self.optional_count))

        return b''.join(parts)

    @classmethod
    def deserialize(cls, data: bytes) -> 'OptionalFields':
        pos = 0

        # Required ID
        if pos + 4 > len(data):
            raise ValueError("Buffer too small for required_id")
        required_id = struct.unpack('<I', data[pos:pos+4])[0]
        pos += 4

        # Presence flags
        if pos >= len(data):
            raise ValueError("Buffer too small for presence flags")
        flags = data[pos]
        pos += 1

        has_name = (flags & (1 << 0)) != 0
        has_value = (flags & (1 << 1)) != 0
        has_count = (flags & (1 << 2)) != 0

        # Optional name
        optional_name = None
        if has_name:
            if pos + 4 > len(data):
                raise ValueError("Buffer too small for name length")
            name_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            if pos + name_len + 1 > len(data):
                raise ValueError("Buffer too small for name data")
            optional_name = data[pos:pos+name_len].decode('utf-8')
            pos += name_len + 1

        # Optional value
        optional_value = None
        if has_value:
            if pos + 8 > len(data):
                raise ValueError("Buffer too small for optional_value")
            optional_value = struct.unpack('<d', data[pos:pos+8])[0]
            pos += 8

        # Optional count
        optional_count = None
        if has_count:
            if pos + 4 > len(data):
                raise ValueError("Buffer too small for optional_count")
            optional_count = struct.unpack('<i', data[pos:pos+4])[0]
            pos += 4

        return cls(
            required_id=required_id,
            optional_name=optional_name,
            optional_value=optional_value,
            optional_count=optional_count,
        )
