#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Bitsets and Bitmasks Sample - Demonstrates DDS bit types

This sample shows how to work with bit types:
- Bitmask types (Permissions: READ, WRITE, EXECUTE, DELETE)
- Bitset types (StatusFlags: priority[4], active[1], error[1], warning[1])
"""

import sys
sys.path.insert(0, '.')

from generated.Bits import Permissions, StatusFlags, Bits


def main():
    print("=== HDDS Bitsets and Bitmasks Sample ===\n")

    # Permissions bitmask
    print("--- Permissions Bitmask ---")
    print("Permission flags:")
    print(f"  READ    = 0x{Permissions.READ:02X} ({Permissions.READ})")
    print(f"  WRITE   = 0x{Permissions.WRITE:02X} ({Permissions.WRITE})")
    print(f"  EXECUTE = 0x{Permissions.EXECUTE:02X} ({Permissions.EXECUTE})")
    print(f"  DELETE  = 0x{Permissions.DELETE:02X} ({Permissions.DELETE})")

    # Create permissions with multiple flags
    perms = Permissions(Permissions.READ | Permissions.WRITE)

    print(f"\nPermissions with READ | WRITE:")
    print(f"  bits: 0x{int(perms):02X}")
    print(f"  has READ:    {bool(perms & Permissions.READ)}")
    print(f"  has WRITE:   {bool(perms & Permissions.WRITE)}")
    print(f"  has EXECUTE: {bool(perms & Permissions.EXECUTE)}")
    print(f"  has DELETE:  {bool(perms & Permissions.DELETE)}")

    # StatusFlags bitset (dataclass with bit fields)
    print("\n--- StatusFlags Bitset ---")
    print("Bitset fields: priority[4 bits], active[1], error[1], warning[1]")

    status = StatusFlags()
    status.priority = 5
    status.active = 1
    status.warning = 1

    print(f"\nStatusFlags with priority=5, active=1, warning=1:")
    print(f"  raw bits: 0x{status.bits:02X}")
    print(f"  priority: {status.priority}")
    print(f"  active:   {status.active}")
    print(f"  error:    {status.error}")
    print(f"  warning:  {status.warning}")

    # Bits struct serialization
    print("\n--- Bits Serialization ---")
    demo = Bits(
        perms=Permissions(Permissions.READ | Permissions.EXECUTE),
        flags=status,
    )

    print("Original:")
    print(f"  perms: 0x{int(demo.perms):02X}")
    print(f"  flags.bits: 0x{demo.flags.bits:02X}")
    print(f"  flags.priority: {demo.flags.priority}")
    print(f"  flags.active: {demo.flags.active}")

    data = demo.encode_cdr2_le()
    print(f"Serialized size: {len(data)} bytes")
    print(f"Serialized: {data.hex().upper()}")

    deser, _ = Bits.decode_cdr2_le(data)
    print("Deserialized:")
    print(f"  perms: 0x{int(deser.perms):02X}")
    print(f"  flags.bits: 0x{deser.flags.bits:02X}")
    print(f"  flags.priority: {deser.flags.priority}")
    print(f"  flags.active: {deser.flags.active}")

    if demo == deser:
        print("[OK] Bits round-trip successful\n")

    # Test flag operations
    print("--- Flag Operations ---")

    flags = Permissions(0)
    print(f"Initial:      0x{int(flags):02X}")

    flags = flags | Permissions.READ
    print(f"After +READ:  0x{int(flags):02X}")

    flags = flags | Permissions.WRITE
    print(f"After +WRITE: 0x{int(flags):02X}")

    flags = flags ^ Permissions.EXECUTE
    print(f"After ^EXEC:  0x{int(flags):02X}")

    flags = flags & ~Permissions.READ
    print(f"After -READ:  0x{int(flags):02X}")

    # All permissions
    print("\n--- All Permissions ---")
    all_perms = Permissions(Permissions.READ | Permissions.WRITE | Permissions.EXECUTE | Permissions.DELETE)
    print(f"All permissions: 0x{int(all_perms):02X}")

    all_flags = StatusFlags()
    all_flags.priority = 15
    all_flags.active = 1
    all_flags.error = 1
    all_flags.warning = 1

    all_demo = Bits(perms=all_perms, flags=all_flags)
    all_data = all_demo.encode_cdr2_le()
    all_deser, _ = Bits.decode_cdr2_le(all_data)
    print(f"Round-trip perms: 0x{int(all_deser.perms):02X}")
    print(f"Round-trip flags: priority={all_deser.flags.priority}, active={all_deser.flags.active}, "
          f"error={all_deser.flags.error}, warning={all_deser.flags.warning}")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
