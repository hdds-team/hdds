#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Enums Sample - Demonstrates DDS enumeration types

This sample shows how to work with enum types:
- Simple enums (Color)
- Enums with explicit values (Status)
"""

import sys
sys.path.insert(0, '.')

from generated.Enums import Color, Status, Enums


def main():
    print("=== HDDS Enum Types Sample ===\n")

    # Color enum
    print("--- Color Enum ---")
    print("Color values:")
    print(f"  RED   = {Color.RED.value}")
    print(f"  GREEN = {Color.GREEN.value}")
    print(f"  BLUE  = {Color.BLUE.value}")

    # Status enum with explicit values
    print("\n--- Status Enum (explicit values) ---")
    print("Status values:")
    print(f"  UNKNOWN  = {Status.UNKNOWN.value}")
    print(f"  ACTIVE   = {Status.ACTIVE.value}")
    print(f"  INACTIVE = {Status.INACTIVE.value}")
    print(f"  ERROR    = {Status.ERROR.value}")

    # Enums with both enums
    print("\n--- Enums Serialization ---")
    demo = Enums(color=Color.GREEN, status=Status.ACTIVE)

    print("Original:")
    print(f"  color:  {demo.color.name} ({demo.color.value})")
    print(f"  status: {demo.status.name} ({demo.status.value})")

    data = demo.encode_cdr2_le()
    print(f"Serialized size: {len(data)} bytes")
    print(f"Serialized bytes: {data.hex().upper()}")

    deser, _ = Enums.decode_cdr2_le(data)
    print("Deserialized:")
    print(f"  color:  {deser.color.name}")
    print(f"  status: {deser.status.name}")

    if demo == deser:
        print("[OK] Enums round-trip successful\n")

    # Test all color values
    print("--- All Color Values Test ---")
    for color in [Color.RED, Color.GREEN, Color.BLUE]:
        test = Enums(color=color, status=Status.UNKNOWN)
        test_data = test.encode_cdr2_le()
        test_deser, _ = Enums.decode_cdr2_le(test_data)
        print(f"  {color.name}: {color.value} -> {test_deser.color.name}")
        assert test == test_deser
    print("[OK] All colors round-trip correctly\n")

    # Test all status values
    print("--- All Status Values Test ---")
    for status in [Status.UNKNOWN, Status.ACTIVE, Status.INACTIVE,
                   Status.ERROR]:
        test = Enums(color=Color.RED, status=status)
        test_data = test.encode_cdr2_le()
        test_deser, _ = Enums.decode_cdr2_le(test_data)
        print(f"  {status.name}: {status.value} -> {test_deser.status.name}")
        assert test == test_deser
    print("[OK] All statuses round-trip correctly\n")

    # Default values
    print("--- Default Values ---")
    default_demo = Enums(color=Color.RED, status=Status.UNKNOWN)
    print(f"Default color:  {default_demo.color.name}")
    print(f"Default status: {default_demo.status.name}")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
