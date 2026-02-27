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

import sys
sys.path.insert(0, '.')

from generated.Strings import Strings


def main():
    print("=== HDDS String Types Sample ===\n")

    # Create a Strings instance
    original = Strings(
        unbounded_str="This is an unbounded string that can be any length",
        bounded_str="Bounded to 256 chars",
        wide_str="Wide string with UTF-8: Héllo Wörld! 你好世界 🌍",
    )

    print("Original Strings:")
    print(f'  unbounded_str: "{original.unbounded_str}"')
    print(f'  bounded_str:   "{original.bounded_str}" (max 256 chars)')
    print(f'  wide_str:      "{original.wide_str}"')

    # Serialize
    data = original.serialize()
    print(f"\nSerialized size: {len(data)} bytes")

    # Deserialize
    deserialized = Strings.deserialize(data)
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
    empty_data = empty.serialize()
    empty_deser = Strings.deserialize(empty_data)

    if empty == empty_deser:
        print("[OK] Empty strings handled correctly")

    # Test UTF-8 special characters
    print("\n--- UTF-8 Special Characters Test ---")
    utf8_test = Strings(
        unbounded_str="ASCII only: Hello World!",
        bounded_str="Latin-1: café résumé naïve",
        wide_str="Multi-byte: 日本語 한국어 العربية עברית 🎉🚀💻",
    )
    utf8_data = utf8_test.serialize()
    utf8_deser = Strings.deserialize(utf8_data)

    print("UTF-8 strings preserved:")
    print(f'  Latin-1:    "{utf8_deser.bounded_str}"')
    print(f'  Multi-byte: "{utf8_deser.wide_str}"')

    if utf8_test == utf8_deser:
        print("[OK] UTF-8 encoding preserved correctly")

    # Test long string
    print("\n--- Long String Test ---")
    long_content = ''.join(chr(ord('A') + (i % 26)) for i in range(1000))
    long_str = Strings(unbounded_str=long_content, bounded_str="short", wide_str="also short")
    long_data = long_str.serialize()
    long_deser = Strings.deserialize(long_data)

    print(f"Long string length: {len(long_deser.unbounded_str)} chars")
    if long_str == long_deser:
        print("[OK] Long string handled correctly")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
