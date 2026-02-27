#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Bitsets and Bitmasks Sample - Demonstrates DDS bit types

This sample shows how to work with bit types:
- Bitmask types (Permissions)
- Bitset types (StatusFlags)
"""

import sys
sys.path.insert(0, '.')

from generated.Bits import Permissions, StatusFlags, BitsDemo


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
    perms = Permissions.READ | Permissions.WRITE

    print(f"\nPermissions with READ | WRITE:")
    print(f"  bits: 0x{int(perms):02X}")
    print(f"  has READ:    {bool(perms & Permissions.READ)}")
    print(f"  has WRITE:   {bool(perms & Permissions.WRITE)}")
    print(f"  has EXECUTE: {bool(perms & Permissions.EXECUTE)}")
    print(f"  has DELETE:  {bool(perms & Permissions.DELETE)}")

    # StatusFlags bitset
    print("\n--- StatusFlags Bitset ---")
    print("Status flags:")
    print(f"  ENABLED  = 0x{StatusFlags.ENABLED:02X}")
    print(f"  VISIBLE  = 0x{StatusFlags.VISIBLE:02X}")
    print(f"  SELECTED = 0x{StatusFlags.SELECTED:02X}")
    print(f"  FOCUSED  = 0x{StatusFlags.FOCUSED:02X}")
    print(f"  ERROR    = 0x{StatusFlags.ERROR:02X}")
    print(f"  WARNING  = 0x{StatusFlags.WARNING:02X}")

    status = StatusFlags.ENABLED | StatusFlags.VISIBLE | StatusFlags.WARNING

    print(f"\nStatus with ENABLED | VISIBLE | WARNING:")
    print(f"  bits: 0x{int(status):02X}")
    print(f"  is_enabled:  {bool(status & StatusFlags.ENABLED)}")
    print(f"  is_visible:  {bool(status & StatusFlags.VISIBLE)}")
    print(f"  has_error:   {bool(status & StatusFlags.ERROR)}")
    print(f"  has_warning: {bool(status & StatusFlags.WARNING)}")

    # BitsDemo serialization
    print("\n--- BitsDemo Serialization ---")
    demo = BitsDemo(
        permissions=Permissions.READ | Permissions.EXECUTE,
        status=StatusFlags.ENABLED | StatusFlags.FOCUSED,
    )

    print("Original:")
    print(f"  permissions: 0x{int(demo.permissions):02X}")
    print(f"  status:      0x{int(demo.status):02X}")

    data = demo.serialize()
    print(f"Serialized size: {len(data)} bytes")
    print(f"Serialized: {data.hex().upper()}")

    deser = BitsDemo.deserialize(data)
    print("Deserialized:")
    print(f"  permissions: 0x{int(deser.permissions):02X}")
    print(f"  status:      0x{int(deser.status):02X}")

    if demo == deser:
        print("[OK] BitsDemo round-trip successful\n")

    # Test flag operations
    print("--- Flag Operations ---")

    flags = Permissions.NONE
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
    all_perms = Permissions.READ | Permissions.WRITE | Permissions.EXECUTE | Permissions.DELETE
    print(f"All permissions: 0x{int(all_perms):02X}")

    all_demo = BitsDemo(permissions=all_perms, status=StatusFlags.NONE)
    all_data = all_demo.serialize()
    all_deser = BitsDemo.deserialize(all_data)
    print(f"Round-trip:      0x{int(all_deser.permissions):02X}")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
