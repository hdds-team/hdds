#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Maps Sample - Demonstrates DDS map types

This sample shows how to work with map types:
- String to long maps (scores)
- Long to string maps (labels)
- Enclosing Maps struct
"""

import sys
sys.path.insert(0, '.')

from generated.Maps import Maps


def main():
    print("=== HDDS Map Types Sample ===\n")

    # Maps with scores (StringLongMap) and labels (LongStringMap)
    print("--- Maps: scores (string->long) ---")
    maps = Maps(
        scores={
            "alpha": 1,
            "beta": 2,
            "gamma": 3,
            "delta": 4,
        },
        labels={
            100: "one hundred",
            200: "two hundred",
            300: "three hundred",
        },
    )

    print("Scores map:")
    for k, v in maps.scores.items():
        print(f'  "{k}" => {v}')

    print("\n--- Maps: labels (long->string) ---")
    print("Labels map:")
    for k, v in maps.labels.items():
        print(f'  {k} => "{v}"')

    data = maps.encode_cdr2_le()
    print(f"\nSerialized size: {len(data)} bytes")

    deser, _ = Maps.decode_cdr2_le(data)
    print("Deserialized scores:")
    for k, v in deser.scores.items():
        print(f'  "{k}" => {v}')
    print("Deserialized labels:")
    for k, v in deser.labels.items():
        print(f'  {k} => "{v}"')

    if maps == deser:
        print("[OK] Maps round-trip successful\n")

    # Empty maps
    print("--- Empty Maps Test ---")
    empty_maps = Maps(scores={}, labels={})
    empty_data = empty_maps.encode_cdr2_le()
    empty_deser, _ = Maps.decode_cdr2_le(empty_data)

    print(f"Empty scores size: {len(empty_deser.scores)}")
    print(f"Empty labels size: {len(empty_deser.labels)}")
    if empty_maps == empty_deser:
        print("[OK] Empty maps handled correctly\n")

    # Maps with special characters in keys
    print("--- Special Characters Test ---")
    special_maps = Maps(
        scores={
            "cafe": 42,
            "nihongo": 100,
            "emoji": 999,
        },
        labels={
            1: "first",
            2: "second",
        },
    )

    special_data = special_maps.encode_cdr2_le()
    special_deser, _ = Maps.decode_cdr2_le(special_data)

    print("Special character keys:")
    for k, v in special_deser.scores.items():
        print(f'  "{k}" => {v}')

    if special_maps == special_deser:
        print("[OK] Special characters handled correctly")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
