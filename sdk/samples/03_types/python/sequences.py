#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Sequences Sample - Demonstrates DDS sequence types

This sample shows how to work with sequence types:
- Unbounded sequences (variable length)
- Bounded sequences (with max length)
- Sequences of primitives and strings
"""

import sys
sys.path.insert(0, '.')

from generated.Sequences import LongSeq, StringSeq, BoundedLongSeq


def main():
    print("=== HDDS Sequence Types Sample ===\n")

    # LongSeq - unbounded sequence of integers
    print("--- LongSeq (unbounded) ---")
    long_seq = LongSeq(values=[1, 2, 3, 4, 5, -10, 100, 1000])

    print(f"Original: {long_seq.values}")
    print(f"Length: {len(long_seq.values)}")

    data = long_seq.serialize()
    print(f"Serialized size: {len(data)} bytes")

    deser = LongSeq.deserialize(data)
    print(f"Deserialized: {deser.values}")

    if long_seq == deser:
        print("[OK] LongSeq round-trip successful\n")

    # StringSeq - sequence of strings
    print("--- StringSeq (unbounded) ---")
    string_seq = StringSeq(values=["Hello", "World", "DDS", "Sequences"])

    print(f"Original: {string_seq.values}")
    print(f"Length: {len(string_seq.values)}")

    data = string_seq.serialize()
    print(f"Serialized size: {len(data)} bytes")

    deser = StringSeq.deserialize(data)
    print(f"Deserialized: {deser.values}")

    if string_seq == deser:
        print("[OK] StringSeq round-trip successful\n")

    # BoundedLongSeq - bounded sequence (max 10 elements)
    print("--- BoundedLongSeq (max 10) ---")
    bounded_seq = BoundedLongSeq(values=[10, 20, 30, 40, 50])

    print(f"Original: {bounded_seq.values}")
    print(f"Length: {len(bounded_seq.values)} (max: {BoundedLongSeq.MAX_SIZE})")

    data = bounded_seq.serialize()
    print(f"Serialized size: {len(data)} bytes")

    deser = BoundedLongSeq.deserialize(data)
    print(f"Deserialized: {deser.values}")

    if bounded_seq == deser:
        print("[OK] BoundedLongSeq round-trip successful\n")

    # Test bounds enforcement
    print("--- Bounds Enforcement Test ---")
    try:
        too_many = list(range(15))
        BoundedLongSeq(values=too_many)
        print("[ERROR] Should have rejected oversized sequence")
    except ValueError as e:
        print(f"[OK] Correctly rejected oversized sequence: {e}")

    # Test empty sequences
    print("\n--- Empty Sequence Test ---")
    empty_long = LongSeq(values=[])
    empty_data = empty_long.serialize()
    empty_deser = LongSeq.deserialize(empty_data)

    print(f"Empty sequence length: {len(empty_deser.values)}")
    if empty_long == empty_deser:
        print("[OK] Empty sequence handled correctly")

    # Test large sequence
    print("\n--- Large Sequence Test ---")
    large_values = list(range(1000))
    large_seq = LongSeq(values=large_values)

    print(f"Large sequence length: {len(large_seq.values)}")
    large_data = large_seq.serialize()
    print(f"Serialized size: {len(large_data)} bytes")

    large_deser = LongSeq.deserialize(large_data)
    if large_seq == large_deser:
        print("[OK] Large sequence handled correctly")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
