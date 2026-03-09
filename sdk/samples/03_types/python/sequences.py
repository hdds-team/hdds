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

from generated.Sequences import Sequences


def main():
    print("=== HDDS Sequence Types Sample ===\n")

    # Numbers sequence - unbounded sequence of integers
    print("--- Numbers Sequence (unbounded) ---")
    long_seq = Sequences(
        numbers=[1, 2, 3, 4, 5, -10, 100, 1000],
        names=[],
        bounded_numbers=[],
    )

    print(f"Original: {long_seq.numbers}")
    print(f"Length: {len(long_seq.numbers)}")

    data = long_seq.encode_cdr2_le()
    print(f"Serialized size: {len(data)} bytes")

    deser, _ = Sequences.decode_cdr2_le(data)
    print(f"Deserialized: {deser.numbers}")

    if long_seq == deser:
        print("[OK] Numbers sequence round-trip successful\n")

    # Names sequence - sequence of strings
    print("--- Names Sequence (unbounded) ---")
    string_seq = Sequences(
        numbers=[],
        names=["Hello", "World", "DDS", "Sequences"],
        bounded_numbers=[],
    )

    print(f"Original: {string_seq.names}")
    print(f"Length: {len(string_seq.names)}")

    data = string_seq.encode_cdr2_le()
    print(f"Serialized size: {len(data)} bytes")

    deser, _ = Sequences.decode_cdr2_le(data)
    print(f"Deserialized: {deser.names}")

    if string_seq == deser:
        print("[OK] Names sequence round-trip successful\n")

    # BoundedNumbers sequence - bounded sequence
    print("--- Bounded Numbers Sequence ---")
    bounded_seq = Sequences(
        numbers=[],
        names=[],
        bounded_numbers=[10, 20, 30, 40, 50],
    )

    print(f"Original: {bounded_seq.bounded_numbers}")
    print(f"Length: {len(bounded_seq.bounded_numbers)}")

    data = bounded_seq.encode_cdr2_le()
    print(f"Serialized size: {len(data)} bytes")

    deser, _ = Sequences.decode_cdr2_le(data)
    print(f"Deserialized: {deser.bounded_numbers}")

    if bounded_seq == deser:
        print("[OK] Bounded numbers sequence round-trip successful\n")

    # Test empty sequences
    print("--- Empty Sequence Test ---")
    empty = Sequences(numbers=[], names=[], bounded_numbers=[])
    empty_data = empty.encode_cdr2_le()
    empty_deser, _ = Sequences.decode_cdr2_le(empty_data)

    print(f"Empty numbers length: {len(empty_deser.numbers)}")
    print(f"Empty names length: {len(empty_deser.names)}")
    print(f"Empty bounded_numbers length: {len(empty_deser.bounded_numbers)}")
    if empty == empty_deser:
        print("[OK] Empty sequences handled correctly")

    # Test large sequence
    print("\n--- Large Sequence Test ---")
    large_values = list(range(1000))
    large_seq = Sequences(numbers=large_values, names=[], bounded_numbers=[])

    print(f"Large sequence length: {len(large_seq.numbers)}")
    large_data = large_seq.encode_cdr2_le()
    print(f"Serialized size: {len(large_data)} bytes")

    large_deser, _ = Sequences.decode_cdr2_le(large_data)
    if large_seq == large_deser:
        print("[OK] Large sequence handled correctly")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
