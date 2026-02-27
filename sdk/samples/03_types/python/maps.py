#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Maps Sample - Demonstrates DDS map types

This sample shows how to work with map types:
- String to long maps
- Long to string maps
"""

import sys
sys.path.insert(0, '.')

from generated.Maps import StringLongMap, LongStringMap


def main():
    print("=== HDDS Map Types Sample ===\n")

    # StringLongMap
    print("--- StringLongMap ---")
    str_long_map = StringLongMap(entries={
        "alpha": 1,
        "beta": 2,
        "gamma": 3,
        "delta": 4,
    })

    print("Original map:")
    for k, v in str_long_map.entries.items():
        print(f'  "{k}" => {v}')

    data = str_long_map.serialize()
    print(f"Serialized size: {len(data)} bytes")

    deser = StringLongMap.deserialize(data)
    print("Deserialized map:")
    for k, v in deser.entries.items():
        print(f'  "{k}" => {v}')

    if str_long_map == deser:
        print("[OK] StringLongMap round-trip successful\n")

    # LongStringMap
    print("--- LongStringMap ---")
    long_str_map = LongStringMap(entries={
        100: "one hundred",
        200: "two hundred",
        300: "three hundred",
    })

    print("Original map:")
    for k, v in long_str_map.entries.items():
        print(f'  {k} => "{v}"')

    data = long_str_map.serialize()
    print(f"Serialized size: {len(data)} bytes")

    deser = LongStringMap.deserialize(data)
    print("Deserialized map:")
    for k, v in deser.entries.items():
        print(f'  {k} => "{v}"')

    if long_str_map == deser:
        print("[OK] LongStringMap round-trip successful\n")

    # Empty map
    print("--- Empty Map Test ---")
    empty_map = StringLongMap(entries={})
    empty_data = empty_map.serialize()
    empty_deser = StringLongMap.deserialize(empty_data)

    print(f"Empty map size: {len(empty_deser.entries)}")
    if empty_map == empty_deser:
        print("[OK] Empty map handled correctly\n")

    # Map with special characters
    print("--- Special Characters Test ---")
    special_map = StringLongMap(entries={
        "café": 42,
        "日本語": 100,
        "emoji 🎉": 999,
    })

    special_data = special_map.serialize()
    special_deser = StringLongMap.deserialize(special_data)

    print("Special character keys:")
    for k, v in special_deser.entries.items():
        print(f'  "{k}" => {v}')

    if special_map == special_deser:
        print("[OK] Special characters handled correctly")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
