#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Unions Sample - Demonstrates DDS discriminated union types

This sample shows how to work with union types:
- Discriminated unions with different value types
- Integer, float, and string variants
"""

import sys
sys.path.insert(0, '.')

from generated.Unions import DataKind, DataValue


def main():
    print("=== HDDS Union Types Sample ===\n")

    # Integer variant
    print("--- Integer Variant ---")
    int_value = DataValue.integer(42)

    print(f"Original: kind={int_value.kind.name}, value={int_value.value}")
    print(f"Kind: {int_value.kind.name} ({int_value.kind.value})")

    data = int_value.serialize()
    print(f"Serialized size: {len(data)} bytes")
    print(f"Serialized: {data.hex().upper()}")

    deser = DataValue.deserialize(data)
    print(f"Deserialized: kind={deser.kind.name}, value={deser.value}")

    if int_value == deser:
        print("[OK] Integer variant round-trip successful\n")

    # Float variant
    print("--- Float Variant ---")
    float_value = DataValue.float_val(3.14159265359)

    print(f"Original: kind={float_value.kind.name}, value={float_value.value}")
    print(f"Kind: {float_value.kind.name}")

    data = float_value.serialize()
    print(f"Serialized size: {len(data)} bytes")

    deser = DataValue.deserialize(data)
    print(f"Deserialized: kind={deser.kind.name}, value={deser.value}")

    if float_value == deser:
        print("[OK] Float variant round-trip successful\n")

    # Text variant
    print("--- Text Variant ---")
    text_value = DataValue.text("Hello, DDS Unions!")

    print(f"Original: kind={text_value.kind.name}, value=\"{text_value.value}\"")
    print(f"Kind: {text_value.kind.name}")

    data = text_value.serialize()
    print(f"Serialized size: {len(data)} bytes")

    deser = DataValue.deserialize(data)
    print(f"Deserialized: kind={deser.kind.name}, value=\"{deser.value}\"")

    if text_value == deser:
        print("[OK] Text variant round-trip successful\n")

    # Pattern matching on union
    print("--- Pattern Matching ---")
    values = [
        DataValue.integer(-100),
        DataValue.float_val(2.718),
        DataValue.text("Pattern"),
    ]

    for value in values:
        if value.kind == DataKind.INTEGER:
            print(f"  Integer value: {value.value}")
        elif value.kind == DataKind.FLOAT:
            print(f"  Float value: {value.value:.3f}")
        elif value.kind == DataKind.TEXT:
            print(f'  Text value: "{value.value}"')
    print()

    # Test edge cases
    print("--- Edge Cases ---")

    # Empty string
    empty_text = DataValue.text("")
    empty_data = empty_text.serialize()
    empty_deser = DataValue.deserialize(empty_data)
    print(f'Empty string: kind={empty_deser.kind.name}, value="{empty_deser.value}"')

    # Zero values
    zero_int = DataValue.integer(0)
    zero_data = zero_int.serialize()
    zero_deser = DataValue.deserialize(zero_data)
    print(f"Zero integer: kind={zero_deser.kind.name}, value={zero_deser.value}")

    # Negative float
    neg_float = DataValue.float_val(-999.999)
    neg_data = neg_float.serialize()
    neg_deser = DataValue.deserialize(neg_data)
    print(f"Negative float: kind={neg_deser.kind.name}, value={neg_deser.value}")

    print("[OK] Edge cases handled correctly")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
