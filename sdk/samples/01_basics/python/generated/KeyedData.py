# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
KeyedData.py - Generated from KeyedData.idl

Keyed data type for instance management samples.
"""

import struct
from dataclasses import dataclass
from typing import Tuple


@dataclass
class KeyedData:
    """
    KeyedData - Data with instance key
    @key id - Instance identifier
    """
    id: int = 0           # @key
    data: str = ""
    sequence_num: int = 0

    def serialize(self) -> bytes:
        buffer = bytearray()

        # Write key (id)
        buffer.extend(struct.pack('<i', self.id))

        # Write string length + data
        encoded = self.data.encode('utf-8') + b'\x00'
        buffer.extend(struct.pack('<I', len(encoded)))
        buffer.extend(encoded)

        # Align to 4 bytes
        while len(buffer) % 4 != 0:
            buffer.append(0)

        # Write sequence_num
        buffer.extend(struct.pack('<I', self.sequence_num))

        return bytes(buffer)

    @classmethod
    def deserialize(cls, data: bytes) -> Tuple['KeyedData', int]:
        offset = 0

        # Read key (id)
        id_val = struct.unpack_from('<i', data, offset)[0]
        offset += 4

        # Read string
        str_len = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        data_str = data[offset:offset + str_len - 1].decode('utf-8')
        offset += str_len

        # Align
        while offset % 4 != 0:
            offset += 1

        # Read sequence_num
        sequence_num = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        return cls(id=id_val, data=data_str, sequence_num=sequence_num), offset


__all__ = ['KeyedData']
