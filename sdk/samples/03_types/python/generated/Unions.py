# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Generated from Unions.idl
Demonstrates union types
"""
from dataclasses import dataclass
from enum import IntEnum
from typing import Union
import struct


class DataKind(IntEnum):
    """Discriminator for DataValue union"""
    INTEGER = 0
    FLOAT = 1
    TEXT = 2


@dataclass
class DataValue:
    """Union type with discriminator"""
    kind: DataKind
    value: Union[int, float, str]

    @classmethod
    def integer(cls, v: int) -> 'DataValue':
        return cls(kind=DataKind.INTEGER, value=v)

    @classmethod
    def float_val(cls, v: float) -> 'DataValue':
        return cls(kind=DataKind.FLOAT, value=v)

    @classmethod
    def text(cls, v: str) -> 'DataValue':
        return cls(kind=DataKind.TEXT, value=v)

    def serialize(self) -> bytes:
        parts = [struct.pack('<I', int(self.kind))]

        if self.kind == DataKind.INTEGER:
            parts.append(struct.pack('<i', self.value))
        elif self.kind == DataKind.FLOAT:
            parts.append(struct.pack('<d', self.value))
        elif self.kind == DataKind.TEXT:
            encoded = self.value.encode('utf-8')
            parts.append(struct.pack('<I', len(encoded)))
            parts.append(encoded)
            parts.append(b'\x00')

        return b''.join(parts)

    @classmethod
    def deserialize(cls, data: bytes) -> 'DataValue':
        if len(data) < 4:
            raise ValueError("Buffer too small for discriminator")

        kind_val = struct.unpack('<I', data[:4])[0]
        kind = DataKind(kind_val)

        if kind == DataKind.INTEGER:
            if len(data) < 8:
                raise ValueError("Buffer too small for integer")
            value = struct.unpack('<i', data[4:8])[0]
            return cls(kind=kind, value=value)

        elif kind == DataKind.FLOAT:
            if len(data) < 12:
                raise ValueError("Buffer too small for float")
            value = struct.unpack('<d', data[4:12])[0]
            return cls(kind=kind, value=value)

        elif kind == DataKind.TEXT:
            if len(data) < 8:
                raise ValueError("Buffer too small for string length")
            slen = struct.unpack('<I', data[4:8])[0]
            if len(data) < 8 + slen + 1:
                raise ValueError("Buffer too small for string data")
            value = data[8:8+slen].decode('utf-8')
            return cls(kind=kind, value=value)

        else:
            raise ValueError(f"Unknown discriminator: {kind_val}")
