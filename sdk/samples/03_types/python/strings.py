#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Strings Sample - Demonstrates DDS string types

This sample shows how to work with string types:
- Unbounded strings
- Bounded strings (with length limit)
- Wide strings (wstring)
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from generated.Strings import Strings


def main():
    print("=== HDDS String Types Sample ===\n")

    # Create a Strings instance
    original = Strings(
        unbounded_str="This is an unbounded string that can be any length",
        bounded_str="Bounded to 256 chars",
        wide_str="Wide string with UTF-8: H\u00e9llo W\u00f6rld! \u4f60\u597d\u4e16\u754c \U0001f30d",
    )

    print("Original Strings:")
    print(f'  unbounded_str: "{original.unbounded_str}"')
    print(f'  bounded_str:   "{original.bounded_str}" (max 256 chars)')
    print(f'  wide_str:      "{original.wide_str}"')

    # Serialize
    data = original.encode_cdr2_le()
    print(f"\nSerialized size: {len(data)} bytes")

    # Deserialize
    deserialized, _ = Strings.decode_cdr2_le(data)
    print("\nDeserialized:")
    print(f'  unbounded_str: "{deserialized.unbounded_str}"')
    print(f'  bounded_str:   "{deserialized.bounded_str}"')
    print(f'  wide_str:      "{deserialized.wide_str}"')

    # Verify round-trip
    if original == deserialized:
        print("\n[OK] Round-trip serialization successful!")
    else:
        print("\n[ERROR] Round-trip verification failed!")
        return 1

    # Test empty strings
    print("\n--- Empty String Test ---")
    empty = Strings(unbounded_str="", bounded_str="", wide_str="")
    empty_data = empty.encode_cdr2_le()
    empty_deser, _ = Strings.decode_cdr2_le(empty_data)

    if empty == empty_deser:
        print("[OK] Empty strings handled correctly")

    # Test UTF-8 special characters
    print("\n--- UTF-8 Special Characters Test ---")
    utf8_test = Strings(
        unbounded_str="ASCII only: Hello World!",
        bounded_str="Latin-1: caf\u00e9 r\u00e9sum\u00e9 na\u00efve",
        wide_str="Multi-byte: \u65e5\u672c\u8a9e \ud55c\uad6d\uc5b4 \u0627\u0644\u0639\u0631\u0628\u064a\u0629 \u05e2\u05d1\u05e8\u05d9\u05ea \U0001f389\U0001f680\U0001f4bb",
    )
    utf8_data = utf8_test.encode_cdr2_le()
    utf8_deser, _ = Strings.decode_cdr2_le(utf8_data)

    print("UTF-8 strings preserved:")
    print(f'  Latin-1:    "{utf8_deser.bounded_str}"')
    print(f'  Multi-byte: "{utf8_deser.wide_str}"')

    if utf8_test == utf8_deser:
        print("[OK] UTF-8 encoding preserved correctly")

    # Test long string
    print("\n--- Long String Test ---")
    long_content = ''.join(chr(ord('A') + (i % 26)) for i in range(1000))
    long_str = Strings(unbounded_str=long_content, bounded_str="short", wide_str="also short")
    long_data = long_str.encode_cdr2_le()
    long_deser, _ = Strings.decode_cdr2_le(long_data)

    print(f"Long string length: {len(long_deser.unbounded_str)} chars")
    if long_str == long_deser:
        print("[OK] Long string handled correctly")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
