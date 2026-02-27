# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Generated from Primitives.idl
Demonstrates all DDS primitive types
"""
from dataclasses import dataclass
import struct


@dataclass
class Primitives:
    bool_val: bool = False
    octet_val: int = 0
    char_val: str = '\0'
    short_val: int = 0
    ushort_val: int = 0
    long_val: int = 0
    ulong_val: int = 0
    llong_val: int = 0
    ullong_val: int = 0
    float_val: float = 0.0
    double_val: float = 0.0

    def serialize(self) -> bytes:
        """Serialize to CDR bytes."""
        return struct.pack(
            '<BBBhhiIqQfd',
            1 if self.bool_val else 0,
            self.octet_val,
            ord(self.char_val) if isinstance(self.char_val, str) else self.char_val,
            self.short_val,
            self.ushort_val,
            self.long_val,
            self.ulong_val,
            self.llong_val,
            self.ullong_val,
            self.float_val,
            self.double_val,
        )

    @classmethod
    def deserialize(cls, data: bytes) -> 'Primitives':
        """Deserialize from CDR bytes."""
        if len(data) < 43:
            raise ValueError(f"Buffer too small: {len(data)} < 43")

        values = struct.unpack('<BBBhhiIqQfd', data[:43])
        return cls(
            bool_val=values[0] != 0,
            octet_val=values[1],
            char_val=chr(values[2]),
            short_val=values[3],
            ushort_val=values[4],
            long_val=values[5],
            ulong_val=values[6],
            llong_val=values[7],
            ullong_val=values[8],
            float_val=values[9],
            double_val=values[10],
        )
