# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HelloWorld.py - Generated from HelloWorld.idl

Simple message type for pub/sub samples.
"""

import struct
from dataclasses import dataclass
from typing import Tuple


@dataclass
class HelloWorld:
    """HelloWorld message structure (matches IDL: long id; string message)."""
    id: int = 0
    message: str = ""

    def serialize(self) -> bytes:
        """Serialize to CDR2 little-endian buffer."""
        buffer = bytearray()

        # Write id (int32)
        buffer.extend(struct.pack('<i', self.id))

        # Encode string with length prefix
        encoded = self.message.encode('utf-8') + b'\x00'
        str_len = len(encoded)
        buffer.extend(struct.pack('<I', str_len))
        buffer.extend(encoded)

        # Align to 4 bytes
        while len(buffer) % 4 != 0:
            buffer.append(0)

        return bytes(buffer)

    @classmethod
    def deserialize(cls, data: bytes) -> Tuple['HelloWorld', int]:
        """Deserialize from CDR2 little-endian buffer. Returns (message, bytes_consumed)."""
        offset = 0

        # Read id (int32)
        id_val = struct.unpack_from('<i', data, offset)[0]
        offset += 4

        # Read string length
        str_len = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        # Read string data (excluding null terminator)
        message = data[offset:offset + str_len - 1].decode('utf-8')
        offset += str_len

        # Align to 4 bytes
        while offset % 4 != 0:
            offset += 1

        return cls(id=id_val, message=message), offset


# Convenience for imports
__all__ = ['HelloWorld']
