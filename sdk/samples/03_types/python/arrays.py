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

from generated.Arrays import Arrays


def main():
    print("=== HDDS Array Types Sample ===\n")

    # Numbers array - fixed 10-element array
    print("--- Numbers Array (10 elements) ---")
    long_arr = Arrays(numbers=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], names=[], transform=[])

    print(f"Original: {long_arr.numbers}")

    data = long_arr.encode_cdr2_le()
    print(f"Serialized size: {len(data)} bytes")

    deser, _ = Arrays.decode_cdr2_le(data)
    print(f"Deserialized: {deser.numbers}")

    if long_arr == deser:
        print("[OK] Numbers array round-trip successful\n")

    # Names array - fixed 5-element string array
    print("--- Names Array (5 elements) ---")
    str_arr = Arrays(numbers=[], names=["Alpha", "Beta", "Gamma", "Delta", "Epsilon"], transform=[])

    print(f"Original: {str_arr.names}")

    data = str_arr.encode_cdr2_le()
    print(f"Serialized size: {len(data)} bytes")

    deser, _ = Arrays.decode_cdr2_le(data)
    print(f"Deserialized: {deser.names}")

    if str_arr == deser:
        print("[OK] Names array round-trip successful\n")

    # Transform - 3x3 float array
    print("--- Transform Matrix (3x3) ---")
    matrix = Arrays(numbers=[], names=[], transform=[
        [1.0, 2.0, 3.0],
        [4.0, 5.0, 6.0],
        [7.0, 8.0, 9.0],
    ])

    print("Original matrix:")
    for i, row in enumerate(matrix.transform):
        print(f"  Row {i}: {row}")

    data = matrix.encode_cdr2_le()
    print(f"Serialized size: {len(data)} bytes")

    deser, _ = Arrays.decode_cdr2_le(data)
    print("Deserialized matrix:")
    for i, row in enumerate(deser.transform):
        print(f"  Row {i}: {row}")

    if matrix == deser:
        print("[OK] Transform matrix round-trip successful\n")

    # Identity matrix
    print("--- Identity Matrix ---")
    identity = Arrays(numbers=[], names=[], transform=[
        [1.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
        [0.0, 0.0, 1.0],
    ])
    print("Identity matrix:")
    for row in identity.transform:
        print(f"  {row}")

    id_data = identity.encode_cdr2_le()
    id_deser, _ = Arrays.decode_cdr2_le(id_data)
    if identity == id_deser:
        print("[OK] Identity matrix round-trip successful\n")

    # Test with empty arrays
    print("--- Empty Arrays ---")
    zero_arr = Arrays(numbers=[], names=[], transform=[])
    print(f"Empty numbers: {zero_arr.numbers}")

    zero_data = zero_arr.encode_cdr2_le()
    zero_deser, _ = Arrays.decode_cdr2_le(zero_data)
    if zero_arr == zero_deser:
        print("[OK] Empty array round-trip successful")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
