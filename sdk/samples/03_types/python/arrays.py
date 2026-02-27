#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Arrays Sample - Demonstrates DDS fixed-size array types

This sample shows how to work with array types:
- Fixed-size integer arrays
- Fixed-size string arrays
- Multi-dimensional arrays (matrices)
"""

import sys
sys.path.insert(0, '.')

from generated.Arrays import LongArray, StringArray, Matrix


def main():
    print("=== HDDS Array Types Sample ===\n")

    # LongArray - fixed 10-element array
    print("--- LongArray (10 elements) ---")
    long_arr = LongArray(values=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])

    print(f"Original: {long_arr.values}")

    data = long_arr.serialize()
    print(f"Serialized size: {len(data)} bytes (10 × 4 = 40)")

    deser = LongArray.deserialize(data)
    print(f"Deserialized: {deser.values}")

    if long_arr == deser:
        print("[OK] LongArray round-trip successful\n")

    # StringArray - fixed 5-element string array
    print("--- StringArray (5 elements) ---")
    str_arr = StringArray(values=["Alpha", "Beta", "Gamma", "Delta", "Epsilon"])

    print(f"Original: {str_arr.values}")

    data = str_arr.serialize()
    print(f"Serialized size: {len(data)} bytes")

    deser = StringArray.deserialize(data)
    print(f"Deserialized: {deser.values}")

    if str_arr == deser:
        print("[OK] StringArray round-trip successful\n")

    # Matrix - 3x3 double array
    print("--- Matrix (3x3) ---")
    matrix = Matrix(values=[
        [1.0, 2.0, 3.0],
        [4.0, 5.0, 6.0],
        [7.0, 8.0, 9.0],
    ])

    print("Original matrix:")
    for i, row in enumerate(matrix.values):
        print(f"  Row {i}: {row}")

    data = matrix.serialize()
    print(f"Serialized size: {len(data)} bytes (9 × 8 = 72)")

    deser = Matrix.deserialize(data)
    print("Deserialized matrix:")
    for i, row in enumerate(deser.values):
        print(f"  Row {i}: {row}")

    if matrix == deser:
        print("[OK] Matrix round-trip successful\n")

    # Identity matrix
    print("--- Identity Matrix ---")
    identity = Matrix.identity()
    print("Identity matrix:")
    for row in identity.values:
        print(f"  {row}")

    id_data = identity.serialize()
    id_deser = Matrix.deserialize(id_data)
    if identity == id_deser:
        print("[OK] Identity matrix round-trip successful\n")

    # Test with zeros
    print("--- Zero-initialized Arrays ---")
    zero_arr = LongArray()
    print(f"Zero LongArray: {zero_arr.values}")

    zero_data = zero_arr.serialize()
    zero_deser = LongArray.deserialize(zero_data)
    if zero_arr == zero_deser:
        print("[OK] Zero array round-trip successful")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
