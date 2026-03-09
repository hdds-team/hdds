// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Bitsets and Bitmasks Sample - Demonstrates DDS bit types
 *
 * This sample shows how to work with bit types:
 * - Bitmask: Permissions (READ, WRITE, EXECUTE, DELETE)
 * - Bitset: StatusFlags (priority:4, active:1, error:1, warning:1)
 * - Bits struct wrapping both
 */

#include <iostream>
#include <iomanip>
#include <cstdint>
#include "generated/Bits.hpp"

using namespace hdds_samples;

int main() {
    std::cout << "=== HDDS Bitsets and Bitmasks Sample ===\n\n";

    // Permissions bitmask
    std::cout << "--- Permissions Bitmask ---\n";
    std::cout << "Permission flags:\n";
    std::cout << std::hex << std::uppercase;
    std::cout << "  READ    = 0x" << std::setw(2) << std::setfill('0')
              << static_cast<uint64_t>(Permissions::READ) << std::dec
              << " (" << static_cast<uint64_t>(Permissions::READ) << ")\n";
    std::cout << std::hex;
    std::cout << "  WRITE   = 0x" << std::setw(2)
              << static_cast<uint64_t>(Permissions::WRITE) << std::dec
              << " (" << static_cast<uint64_t>(Permissions::WRITE) << ")\n";
    std::cout << std::hex;
    std::cout << "  EXECUTE = 0x" << std::setw(2)
              << static_cast<uint64_t>(Permissions::EXECUTE) << std::dec
              << " (" << static_cast<uint64_t>(Permissions::EXECUTE) << ")\n";
    std::cout << std::hex;
    std::cout << "  DELETE  = 0x" << std::setw(2)
              << static_cast<uint64_t>(Permissions::DELETE) << std::dec
              << " (" << static_cast<uint64_t>(Permissions::DELETE) << ")\n";

    // Create permissions with multiple flags
    Permissions perms = Permissions::READ | Permissions::WRITE;

    std::cout << "\nPermissions with READ | WRITE:\n";
    std::cout << std::hex;
    std::cout << "  bits: 0x" << std::setw(2) << static_cast<uint64_t>(perms) << std::dec << "\n";
    std::cout << "  has READ:    " << std::boolalpha
              << (static_cast<uint64_t>(perms & Permissions::READ) != 0) << "\n";
    std::cout << "  has WRITE:   "
              << (static_cast<uint64_t>(perms & Permissions::WRITE) != 0) << "\n";
    std::cout << "  has EXECUTE: "
              << (static_cast<uint64_t>(perms & Permissions::EXECUTE) != 0) << "\n";
    std::cout << "  has DELETE:  "
              << (static_cast<uint64_t>(perms & Permissions::DELETE) != 0) << "\n";

    // StatusFlags bitset
    std::cout << "\n--- StatusFlags Bitset ---\n";
    StatusFlags flags{};
    flags.set_priority(5);
    flags.set_active(1);
    flags.set_error(0);
    flags.set_warning(1);

    std::cout << "StatusFlags:\n";
    std::cout << "  priority: " << flags.get_priority() << "\n";
    std::cout << "  active:   " << flags.get_active() << "\n";
    std::cout << "  error:    " << flags.get_error() << "\n";
    std::cout << "  warning:  " << flags.get_warning() << "\n";
    std::cout << std::hex;
    std::cout << "  packed:   0x" << std::setw(4) << flags.to_uint64() << std::dec << "\n";

    // Bits struct serialization
    std::cout << "\n--- Bits Serialization ---\n";
    Bits demo;
    demo.perms = Permissions::READ | Permissions::EXECUTE;
    demo.flags = StatusFlags{};
    demo.flags.set_priority(3);
    demo.flags.set_active(1);
    demo.flags.set_warning(0);

    std::cout << "Original:\n";
    std::cout << std::hex;
    std::cout << "  permissions: 0x" << std::setw(2) << static_cast<uint64_t>(demo.perms) << "\n";
    std::cout << "  flags packed: 0x" << std::setw(4) << demo.flags.to_uint64() << "\n";
    std::cout << std::dec;

    std::uint8_t buf[4096];
    int len = demo.encode_cdr2_le(buf, sizeof(buf));
    std::cout << "Serialized size: " << len << " bytes\n";
    std::cout << "Serialized: ";
    for (int i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(buf[i]);
    }
    std::cout << std::dec << "\n";

    Bits deser;
    deser.decode_cdr2_le(buf, (std::size_t)len);
    std::cout << "Deserialized:\n";
    std::cout << std::hex;
    std::cout << "  permissions: 0x" << std::setw(2) << static_cast<uint64_t>(deser.perms) << "\n";
    std::cout << "  flags packed: 0x" << std::setw(4) << deser.flags.to_uint64() << "\n";
    std::cout << std::dec;

    if (static_cast<uint64_t>(demo.perms) == static_cast<uint64_t>(deser.perms) &&
        demo.flags.to_uint64() == deser.flags.to_uint64()) {
        std::cout << "[OK] Bits round-trip successful\n\n";
    }

    // Test flag operations
    std::cout << "--- Flag Operations ---\n";
    Permissions p = static_cast<Permissions>(0);
    std::cout << std::hex;
    std::cout << "Initial:      0x" << std::setw(2) << static_cast<uint64_t>(p) << "\n";

    p = p | Permissions::READ;
    std::cout << "After +READ:  0x" << std::setw(2) << static_cast<uint64_t>(p) << "\n";

    p = p | Permissions::WRITE;
    std::cout << "After +WRITE: 0x" << std::setw(2) << static_cast<uint64_t>(p) << "\n";

    p = p ^ Permissions::EXECUTE;
    std::cout << "After ^EXEC:  0x" << std::setw(2) << static_cast<uint64_t>(p) << "\n";

    p = p & ~Permissions::READ;
    std::cout << "After -READ:  0x" << std::setw(2) << static_cast<uint64_t>(p) << "\n";
    std::cout << std::dec;

    // All permissions
    std::cout << "\n--- All Permissions ---\n";
    Permissions all_perms = Permissions::READ | Permissions::WRITE |
                            Permissions::EXECUTE | Permissions::DELETE;
    std::cout << std::hex;
    std::cout << "All permissions: 0x" << std::setw(2) << static_cast<uint64_t>(all_perms) << "\n";

    Bits all_demo;
    all_demo.perms = all_perms;
    all_demo.flags = StatusFlags{};
    std::uint8_t abuf[4096];
    int alen = all_demo.encode_cdr2_le(abuf, sizeof(abuf));
    Bits all_deser;
    all_deser.decode_cdr2_le(abuf, (std::size_t)alen);
    std::cout << "Round-trip:      0x" << std::setw(2) << static_cast<uint64_t>(all_deser.perms) << "\n";
    std::cout << std::dec;

    std::cout << "\n=== Sample Complete ===\n";
    return 0;
}
