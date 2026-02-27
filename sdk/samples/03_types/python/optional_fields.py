#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Optional Fields Sample - Demonstrates DDS optional field types

This sample shows how to work with optional fields:
- Required fields (always present)
- Optional fields (may be absent)
- Presence checking
"""

import sys
sys.path.insert(0, '.')

from generated.Optional import OptionalFields


def main():
    print("=== HDDS Optional Fields Sample ===\n")

    # All fields present
    print("--- All Fields Present ---")
    full = OptionalFields(
        required_id=42,
        optional_name="Complete",
        optional_value=3.14159,
        optional_count=100,
    )

    print("Original:")
    print(f"  required_id:    {full.required_id}")
    print(f"  optional_name:  {full.optional_name!r}")
    print(f"  optional_value: {full.optional_value!r}")
    print(f"  optional_count: {full.optional_count!r}")

    data = full.serialize()
    print(f"Serialized size: {len(data)} bytes")

    deser = OptionalFields.deserialize(data)
    print("Deserialized:")
    print(f"  required_id:    {deser.required_id}")
    print(f"  optional_name:  {deser.optional_name!r}")
    print(f"  optional_value: {deser.optional_value!r}")
    print(f"  optional_count: {deser.optional_count!r}")

    if full == deser:
        print("[OK] Full struct round-trip successful\n")

    # Only required field
    print("--- Only Required Field ---")
    minimal = OptionalFields(required_id=1)

    print("Original:")
    print(f"  required_id:    {minimal.required_id}")
    print(f"  optional_name:  {minimal.optional_name!r}")
    print(f"  optional_value: {minimal.optional_value!r}")
    print(f"  optional_count: {minimal.optional_count!r}")

    data = minimal.serialize()
    print(f"Serialized size: {len(data)} bytes (minimal)")

    deser = OptionalFields.deserialize(data)
    print("Deserialized:")
    all_none = (deser.optional_name is None and
                deser.optional_value is None and
                deser.optional_count is None)
    print(f"  all optionals are None: {all_none}")

    if minimal == deser:
        print("[OK] Minimal struct round-trip successful\n")

    # Partial fields
    print("--- Partial Fields ---")
    partial = OptionalFields(
        required_id=99,
        optional_name="Partial",
        # value and count not set
    )

    print("Original:")
    print(f"  required_id:    {partial.required_id}")
    print(f"  optional_name:  {partial.optional_name!r}")
    print(f"  optional_value: {partial.optional_value!r}")
    print(f"  optional_count: {partial.optional_count!r}")

    data = partial.serialize()
    print(f"Serialized size: {len(data)} bytes")

    deser = OptionalFields.deserialize(data)

    if partial == deser:
        print("[OK] Partial struct round-trip successful\n")

    # Pattern matching on optionals
    print("--- Pattern Matching ---")
    structs = [
        OptionalFields(required_id=1),
        OptionalFields(required_id=2, optional_name="Named"),
        OptionalFields(required_id=3, optional_value=2.718),
        OptionalFields(required_id=4, optional_count=-50),
        OptionalFields(required_id=5, optional_name="All",
                      optional_value=1.0, optional_count=999),
    ]

    for s in structs:
        parts = []
        if s.optional_name is not None:
            parts.append("name")
        if s.optional_value is not None:
            parts.append("value")
        if s.optional_count is not None:
            parts.append("count")

        if not parts:
            print(f"  ID {s.required_id}: (no optional fields)")
        else:
            print(f"  ID {s.required_id}: has {', '.join(parts)}")
    print()

    # Size comparison
    print("--- Size Comparison ---")
    minimal = OptionalFields(required_id=1)
    full = OptionalFields(
        required_id=1,
        optional_name="Test Name",
        optional_value=123.456,
        optional_count=42,
    )

    print(f"Minimal (required only): {len(minimal.serialize())} bytes")
    print(f"Full (all fields):       {len(full.serialize())} bytes")
    print(f"Space saved when optional fields absent: "
          f"{len(full.serialize()) - len(minimal.serialize())} bytes")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
