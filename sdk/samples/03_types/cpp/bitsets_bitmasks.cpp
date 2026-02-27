// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Bitsets and Bitmasks Sample - Demonstrates DDS bit types
 *
 * This sample shows how to work with bit types:
 * - Bitmask types (Permissions)
 * - Bitset types (StatusFlags)
 */

#include <iostream>
#include <iomanip>
#include "generated/Bits.hpp"

using namespace hdds_samples;

int main() {
    std::cout << "=== HDDS Bitsets and Bitmasks Sample ===\n\n";

    // Permissions bitmask
    std::cout << "--- Permissions Bitmask ---\n";
    std::cout << "Permission flags:\n";
    std::cout << std::hex << std::uppercase;
    std::cout << "  READ    = 0x" << std::setw(2) << std::setfill('0')
              << Permissions::Read << " (" << std::dec << Permissions::Read << ")\n";
    std::cout << std::hex;
    std::cout << "  WRITE   = 0x" << std::setw(2) << Permissions::Write
              << " (" << std::dec << Permissions::Write << ")\n";
    std::cout << std::hex;
    std::cout << "  EXECUTE = 0x" << std::setw(2) << Permissions::Execute
              << " (" << std::dec << Permissions::Execute << ")\n";
    std::cout << std::hex;
    std::cout << "  DELETE  = 0x" << std::setw(2) << Permissions::Delete
              << " (" << std::dec << Permissions::Delete << ")\n";

    // Create permissions with multiple flags
    Permissions perms(Permissions::Read | Permissions::Write);

    std::cout << "\nPermissions with READ | WRITE:\n";
    std::cout << std::hex;
    std::cout << "  bits: 0x" << std::setw(2) << perms.bits() << std::dec << "\n";
    std::cout << "  can_read:    " << std::boolalpha << perms.can_read() << "\n";
    std::cout << "  can_write:   " << perms.can_write() << "\n";
    std::cout << "  can_execute: " << perms.can_execute() << "\n";
    std::cout << "  can_delete:  " << perms.can_delete() << "\n";
    std::cout << "  display:     " << perms.to_string() << "\n";

    // StatusFlags bitset
    std::cout << "\n--- StatusFlags Bitset ---\n";
    std::cout << "Status flags:\n";
    std::cout << std::hex;
    std::cout << "  ENABLED  = 0x" << std::setw(2) << static_cast<int>(StatusFlags::Enabled) << "\n";
    std::cout << "  VISIBLE  = 0x" << std::setw(2) << static_cast<int>(StatusFlags::Visible) << "\n";
    std::cout << "  SELECTED = 0x" << std::setw(2) << static_cast<int>(StatusFlags::Selected) << "\n";
    std::cout << "  FOCUSED  = 0x" << std::setw(2) << static_cast<int>(StatusFlags::Focused) << "\n";
    std::cout << "  ERROR    = 0x" << std::setw(2) << static_cast<int>(StatusFlags::Error) << "\n";
    std::cout << "  WARNING  = 0x" << std::setw(2) << static_cast<int>(StatusFlags::Warning) << "\n";
    std::cout << std::dec;

    StatusFlags status(StatusFlags::Enabled | StatusFlags::Visible | StatusFlags::Warning);

    std::cout << "\nStatus with ENABLED | VISIBLE | WARNING:\n";
    std::cout << std::hex;
    std::cout << "  bits: 0x" << std::setw(2) << static_cast<int>(status.bits()) << std::dec << "\n";
    std::cout << "  is_enabled:  " << status.is_enabled() << "\n";
    std::cout << "  is_visible:  " << status.is_visible() << "\n";
    std::cout << "  has_error:   " << status.has_error() << "\n";
    std::cout << "  has_warning: " << status.has_warning() << "\n";

    // BitsDemo serialization
    std::cout << "\n--- BitsDemo Serialization ---\n";
    BitsDemo demo(
        Permissions(Permissions::Read | Permissions::Execute),
        StatusFlags(StatusFlags::Enabled | StatusFlags::Focused)
    );

    std::cout << "Original:\n";
    std::cout << std::hex;
    std::cout << "  permissions: 0x" << std::setw(2) << demo.permissions.bits()
              << " (" << demo.permissions.to_string() << ")\n";
    std::cout << "  status:      0x" << std::setw(2) << static_cast<int>(demo.status.bits()) << "\n";
    std::cout << std::dec;

    auto bytes = demo.serialize();
    std::cout << "Serialized size: " << bytes.size() << " bytes\n";
    std::cout << "Serialized: ";
    for (auto b : bytes) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(b);
    }
    std::cout << std::dec << "\n";

    auto deser = BitsDemo::deserialize(bytes.data(), bytes.size());
    std::cout << "Deserialized:\n";
    std::cout << std::hex;
    std::cout << "  permissions: 0x" << std::setw(2) << deser.permissions.bits() << "\n";
    std::cout << "  status:      0x" << std::setw(2) << static_cast<int>(deser.status.bits()) << "\n";
    std::cout << std::dec;

    if (demo.permissions == deser.permissions && demo.status == deser.status) {
        std::cout << "[OK] BitsDemo round-trip successful\n\n";
    }

    // Test flag operations
    std::cout << "--- Flag Operations ---\n";

    Permissions flags;
    std::cout << std::hex;
    std::cout << "Initial:      0x" << std::setw(2) << flags.bits() << "\n";

    flags.set(Permissions::Read);
    std::cout << "After +READ:  0x" << std::setw(2) << flags.bits() << "\n";

    flags.set(Permissions::Write);
    std::cout << "After +WRITE: 0x" << std::setw(2) << flags.bits() << "\n";

    flags.toggle(Permissions::Execute);
    std::cout << "After ^EXEC:  0x" << std::setw(2) << flags.bits() << "\n";

    flags.clear(Permissions::Read);
    std::cout << "After -READ:  0x" << std::setw(2) << flags.bits() << "\n";
    std::cout << std::dec;

    // All permissions
    std::cout << "\n--- All Permissions ---\n";
    Permissions all_perms(Permissions::Read | Permissions::Write |
                          Permissions::Execute | Permissions::Delete);
    std::cout << std::hex;
    std::cout << "All permissions: 0x" << std::setw(2) << all_perms.bits() << "\n";

    BitsDemo all_demo(all_perms, StatusFlags());
    auto all_bytes = all_demo.serialize();
    auto all_deser = BitsDemo::deserialize(all_bytes.data(), all_bytes.size());
    std::cout << "Round-trip:      0x" << std::setw(2) << all_deser.permissions.bits() << "\n";
    std::cout << std::dec;

    std::cout << "\n=== Sample Complete ===\n";
    return 0;
}
