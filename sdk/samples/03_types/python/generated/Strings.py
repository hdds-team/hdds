# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Generated from Strings.idl
Demonstrates string types
"""
from dataclasses import dataclass
import struct


@dataclass
class Strings:
    unbounded_str: str = ""
    bounded_str: str = ""   # max 256 chars
    wide_str: str = ""      # wstring stored as UTF-8

    def serialize(self) -> bytes:
        """Serialize to CDR bytes."""
        parts = []
        for s in [self.unbounded_str, self.bounded_str, self.wide_str]:
            encoded = s.encode('utf-8')
            parts.append(struct.pack('<I', len(encoded)))
            parts.append(encoded)
            parts.append(b'\x00')  # null terminator
        return b''.join(parts)

    @classmethod
    def deserialize(cls, data: bytes) -> 'Strings':
        """Deserialize from CDR bytes."""
        pos = 0
        strings = []

        for _ in range(3):
            if pos + 4 > len(data):
                raise ValueError("Buffer too small for string length")
            slen = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            if pos + slen + 1 > len(data):
                raise ValueError("Buffer too small for string data")
            strings.append(data[pos:pos+slen].decode('utf-8'))
            pos += slen + 1  # skip null terminator

        return cls(
            unbounded_str=strings[0],
            bounded_str=strings[1],
            wide_str=strings[2],
        )
