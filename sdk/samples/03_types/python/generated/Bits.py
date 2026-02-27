# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Generated from Bits.idl
Demonstrates bitmask and bitset types
"""
from dataclasses import dataclass
from enum import IntFlag
import struct


class Permissions(IntFlag):
    """Permission bitmask"""
    NONE = 0
    READ = 1 << 0
    WRITE = 1 << 1
    EXECUTE = 1 << 2
    DELETE = 1 << 3


class StatusFlags(IntFlag):
    """Status flags bitset"""
    NONE = 0
    ENABLED = 1 << 0
    VISIBLE = 1 << 1
    SELECTED = 1 << 2
    FOCUSED = 1 << 3
    ERROR = 1 << 4
    WARNING = 1 << 5


@dataclass
class BitsDemo:
    """Container for bit types"""
    permissions: Permissions = Permissions.NONE
    status: StatusFlags = StatusFlags.NONE

    def serialize(self) -> bytes:
        return struct.pack('<IB', int(self.permissions), int(self.status))

    @classmethod
    def deserialize(cls, data: bytes) -> 'BitsDemo':
        if len(data) < 5:
            raise ValueError("Buffer too small for bits")
        perm_val, status_val = struct.unpack('<IB', data[:5])
        return cls(
            permissions=Permissions(perm_val),
            status=StatusFlags(status_val),
        )
