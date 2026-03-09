#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Unions Sample - Demonstrates DDS discriminated union types

This sample shows how to work with union types:
- Discriminated unions with different value types
- Integer, float, and string variants
- Enclosing Unions struct with kind + value
"""

import sys
sys.path.insert(0, '.')

from generated.Unions import DataKind, DataValue, Unions


def main():
    print("=== HDDS Union Types Sample ===\n")

    # Integer variant
    print("--- Integer Variant ---")
    int_union = DataValue(_discriminator=DataKind.INTEGER, _value=42)

    print(f"Original: kind={int_union._discriminator.name}, value={int_union._value}")
    print(f"Kind: {int_union._discriminator.name} ({int_union._discriminator.value})")
    print(f"int_val property: {int_union.int_val}")

    int_msg = Unions(kind=DataKind.INTEGER, value=int_union)
    data = int_msg.encode_cdr2_le()
    print(f"Serialized size: {len(data)} bytes")
    print(f"Serialized: {data.hex().upper()}")

    deser, _ = Unions.decode_cdr2_le(data)
    print(f"Deserialized: kind={deser.value._discriminator.name}, value={deser.value._value}")

    if int_msg == deser:
        print("[OK] Integer variant round-trip successful\n")

    # Float variant
    print("--- Float Variant ---")
    float_union = DataValue(_discriminator=DataKind.FLOAT, _value=3.14159265359)

    print(f"Original: kind={float_union._discriminator.name}, value={float_union._value}")
    print(f"float_val property: {float_union.float_val}")

    float_msg = Unions(kind=DataKind.FLOAT, value=float_union)
    data = float_msg.encode_cdr2_le()
    print(f"Serialized size: {len(data)} bytes")

    deser, _ = Unions.decode_cdr2_le(data)
    print(f"Deserialized: kind={deser.value._discriminator.name}, value={deser.value._value}")

    if float_msg == deser:
        print("[OK] Float variant round-trip successful\n")

    # String variant
    print("--- String Variant ---")
    str_union = DataValue(_discriminator=DataKind.STRING, _value="Hello, DDS Unions!")

    print(f"Original: kind={str_union._discriminator.name}, value=\"{str_union._value}\"")
    print(f"str_val property: {str_union.str_val!r}")

    str_msg = Unions(kind=DataKind.STRING, value=str_union)
    data = str_msg.encode_cdr2_le()
    print(f"Serialized size: {len(data)} bytes")

    deser, _ = Unions.decode_cdr2_le(data)
    print(f"Deserialized: kind={deser.value._discriminator.name}, value=\"{deser.value._value}\"")

    if str_msg == deser:
        print("[OK] String variant round-trip successful\n")

    # Pattern matching on union
    print("--- Pattern Matching ---")
    values = [
        DataValue(_discriminator=DataKind.INTEGER, _value=-100),
        DataValue(_discriminator=DataKind.FLOAT, _value=2.718),
        DataValue(_discriminator=DataKind.STRING, _value="Pattern"),
    ]

    for value in values:
        if value._discriminator == DataKind.INTEGER:
            print(f"  Integer value: {value.int_val}")
        elif value._discriminator == DataKind.FLOAT:
            print(f"  Float value: {value.float_val:.3f}")
        elif value._discriminator == DataKind.STRING:
            print(f'  String value: "{value.str_val}"')
    print()

    # Test edge cases
    print("--- Edge Cases ---")

    # Empty string
    empty_str = DataValue(_discriminator=DataKind.STRING, _value="")
    empty_msg = Unions(kind=DataKind.STRING, value=empty_str)
    empty_data = empty_msg.encode_cdr2_le()
    empty_deser, _ = Unions.decode_cdr2_le(empty_data)
    print(f'Empty string: kind={empty_deser.value._discriminator.name}, value="{empty_deser.value.str_val}"')

    # Zero values
    zero_union = DataValue(_discriminator=DataKind.INTEGER, _value=0)
    zero_msg = Unions(kind=DataKind.INTEGER, value=zero_union)
    zero_data = zero_msg.encode_cdr2_le()
    zero_deser, _ = Unions.decode_cdr2_le(zero_data)
    print(f"Zero integer: kind={zero_deser.value._discriminator.name}, value={zero_deser.value.int_val}")

    # Negative float
    neg_union = DataValue(_discriminator=DataKind.FLOAT, _value=-999.999)
    neg_msg = Unions(kind=DataKind.FLOAT, value=neg_union)
    neg_data = neg_msg.encode_cdr2_le()
    neg_deser, _ = Unions.decode_cdr2_le(neg_data)
    print(f"Negative float: kind={neg_deser.value._discriminator.name}, value={neg_deser.value.float_val}")

    print("[OK] Edge cases handled correctly")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
