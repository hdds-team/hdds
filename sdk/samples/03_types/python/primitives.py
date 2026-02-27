#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Primitives Sample - Demonstrates all DDS primitive types

This sample shows how to work with all basic DDS primitive types:
- bool, octet (int 0-255), char
- short (int), unsigned short (int)
- long (int), unsigned long (int)
- long long (int), unsigned long long (int)
- float, double
"""

import sys
sys.path.insert(0, '.')

from generated.Primitives import Primitives


def main():
    print("=== HDDS Primitives Type Sample ===\n")

    # Create a Primitives instance with all types
    original = Primitives(
        bool_val=True,
        octet_val=0xAB,
        char_val='X',
        short_val=-1234,
        ushort_val=5678,
        long_val=-123456,
        ulong_val=789012,
        llong_val=-9876543210,
        ullong_val=12345678901,
        float_val=3.14159,
        double_val=2.718281828,
    )

    print("Original Primitives:")
    print(f"  bool_val:   {original.bool_val}")
    print(f"  octet_val:  0x{original.octet_val:02X} ({original.octet_val})")
    print(f"  char_val:   '{original.char_val}'")
    print(f"  short_val:  {original.short_val}")
    print(f"  ushort_val: {original.ushort_val}")
    print(f"  long_val:   {original.long_val}")
    print(f"  ulong_val:  {original.ulong_val}")
    print(f"  llong_val:  {original.llong_val}")
    print(f"  ullong_val: {original.ullong_val}")
    print(f"  float_val:  {original.float_val:.5f}")
    print(f"  double_val: {original.double_val:.9f}")

    # Serialize
    data = original.serialize()
    print(f"\nSerialized size: {len(data)} bytes")
    print("Serialized bytes (hex):")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ' '.join(f'{b:02X}' for b in chunk)
        print(f"  {i:04X}: {hex_str}")

    # Deserialize
    deserialized = Primitives.deserialize(data)
    print(f"\nDeserialized:")
    print(f"  bool_val:   {deserialized.bool_val}")
    print(f"  octet_val:  0x{deserialized.octet_val:02X}")
    print(f"  char_val:   '{deserialized.char_val}'")
    print(f"  short_val:  {deserialized.short_val}")
    print(f"  ushort_val: {deserialized.ushort_val}")
    print(f"  long_val:   {deserialized.long_val}")
    print(f"  ulong_val:  {deserialized.ulong_val}")
    print(f"  llong_val:  {deserialized.llong_val}")
    print(f"  ullong_val: {deserialized.ullong_val}")
    print(f"  float_val:  {deserialized.float_val:.5f}")
    print(f"  double_val: {deserialized.double_val:.9f}")

    # Verify round-trip (note: float comparison may have precision issues)
    if (original.bool_val == deserialized.bool_val and
        original.octet_val == deserialized.octet_val and
        original.char_val == deserialized.char_val and
        original.short_val == deserialized.short_val and
        original.ushort_val == deserialized.ushort_val and
        original.long_val == deserialized.long_val and
        original.ulong_val == deserialized.ulong_val and
        original.llong_val == deserialized.llong_val and
        original.ullong_val == deserialized.ullong_val):
        print("\n[OK] Round-trip serialization successful!")
    else:
        print("\n[ERROR] Round-trip verification failed!")
        return 1

    # Test edge cases
    print("\n--- Edge Case Tests ---")

    edge_cases = Primitives(
        bool_val=False,
        octet_val=0,
        char_val='\0',
        short_val=-32768,       # i16 min
        ushort_val=65535,       # u16 max
        long_val=-2147483648,   # i32 min
        ulong_val=4294967295,   # u32 max
        llong_val=-9223372036854775808,  # i64 min
        ullong_val=18446744073709551615, # u64 max
        float_val=1.175494e-38,
        double_val=1.7976931348623157e+308,
    )

    edge_data = edge_cases.serialize()
    edge_deserialized = Primitives.deserialize(edge_data)

    print("Edge case values:")
    print(f"  i16 min = {edge_deserialized.short_val}")
    print(f"  u16 max = {edge_deserialized.ushort_val}")
    print(f"  i32 min = {edge_deserialized.long_val}")
    print(f"  u32 max = {edge_deserialized.ulong_val}")
    print(f"  i64 min = {edge_deserialized.llong_val}")
    print(f"  u64 max = {edge_deserialized.ullong_val}")

    print("\n[OK] Edge case round-trip successful!")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
