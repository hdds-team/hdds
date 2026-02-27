// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Primitives Sample - Demonstrates all DDS primitive types
 *
 * This sample shows how to work with all basic DDS primitive types:
 * - bool, octet (uint8_t), char
 * - short (int16_t), unsigned short (uint16_t)
 * - long (int32_t), unsigned long (uint32_t)
 * - long long (int64_t), unsigned long long (uint64_t)
 * - float, double
 */

#include <iostream>
#include <iomanip>
#include <cstdint>
#include <limits>
#include "generated/Primitives.hpp"

using namespace hdds_samples;

int main() {
    std::cout << "=== HDDS Primitives Type Sample ===\n\n";

    // Create a Primitives instance with all types
    Primitives original(
        true,           // bool
        0xAB,           // octet
        'X',            // char
        -1234,          // short
        5678,           // unsigned short
        -123456,        // long
        789012,         // unsigned long
        -9876543210LL,  // long long
        12345678901ULL, // unsigned long long
        3.14159f,       // float
        2.718281828     // double
    );

    std::cout << "Original Primitives:\n";
    std::cout << "  bool_val:   " << std::boolalpha << original.bool_val << "\n";
    std::cout << "  octet_val:  0x" << std::hex << std::uppercase
              << static_cast<int>(original.octet_val) << std::dec
              << " (" << static_cast<int>(original.octet_val) << ")\n";
    std::cout << "  char_val:   '" << original.char_val << "'\n";
    std::cout << "  short_val:  " << original.short_val << "\n";
    std::cout << "  ushort_val: " << original.ushort_val << "\n";
    std::cout << "  long_val:   " << original.long_val << "\n";
    std::cout << "  ulong_val:  " << original.ulong_val << "\n";
    std::cout << "  llong_val:  " << original.llong_val << "\n";
    std::cout << "  ullong_val: " << original.ullong_val << "\n";
    std::cout << std::fixed << std::setprecision(5);
    std::cout << "  float_val:  " << original.float_val << "\n";
    std::cout << std::setprecision(9);
    std::cout << "  double_val: " << original.double_val << "\n";

    // Serialize
    auto bytes = original.serialize();
    std::cout << "\nSerialized size: " << bytes.size() << " bytes\n";
    std::cout << "Serialized bytes (hex):\n";
    for (size_t i = 0; i < bytes.size(); i += 16) {
        std::cout << "  " << std::hex << std::setfill('0') << std::setw(4) << i << ": ";
        for (size_t j = i; j < std::min(i + 16, bytes.size()); ++j) {
            std::cout << std::setw(2) << static_cast<int>(bytes[j]) << " ";
        }
        std::cout << std::dec << "\n";
    }

    // Deserialize
    auto deserialized = Primitives::deserialize(bytes.data(), bytes.size());
    std::cout << "\nDeserialized:\n";
    std::cout << "  bool_val:   " << std::boolalpha << deserialized.bool_val << "\n";
    std::cout << "  octet_val:  0x" << std::hex << std::uppercase
              << static_cast<int>(deserialized.octet_val) << std::dec << "\n";
    std::cout << "  char_val:   '" << deserialized.char_val << "'\n";
    std::cout << "  short_val:  " << deserialized.short_val << "\n";
    std::cout << "  ushort_val: " << deserialized.ushort_val << "\n";
    std::cout << "  long_val:   " << deserialized.long_val << "\n";
    std::cout << "  ulong_val:  " << deserialized.ulong_val << "\n";
    std::cout << "  llong_val:  " << deserialized.llong_val << "\n";
    std::cout << "  ullong_val: " << deserialized.ullong_val << "\n";
    std::cout << std::fixed << std::setprecision(5);
    std::cout << "  float_val:  " << deserialized.float_val << "\n";
    std::cout << std::setprecision(9);
    std::cout << "  double_val: " << deserialized.double_val << "\n";

    // Verify round-trip
    bool match = (original.bool_val == deserialized.bool_val &&
                  original.octet_val == deserialized.octet_val &&
                  original.char_val == deserialized.char_val &&
                  original.short_val == deserialized.short_val &&
                  original.ushort_val == deserialized.ushort_val &&
                  original.long_val == deserialized.long_val &&
                  original.ulong_val == deserialized.ulong_val &&
                  original.llong_val == deserialized.llong_val &&
                  original.ullong_val == deserialized.ullong_val);

    if (match) {
        std::cout << "\n[OK] Round-trip serialization successful!\n";
    } else {
        std::cout << "\n[ERROR] Round-trip verification failed!\n";
        return 1;
    }

    // Test edge cases
    std::cout << "\n--- Edge Case Tests ---\n";

    Primitives edge_cases(
        false,
        std::numeric_limits<uint8_t>::min(),
        '\0',
        std::numeric_limits<int16_t>::min(),
        std::numeric_limits<uint16_t>::max(),
        std::numeric_limits<int32_t>::min(),
        std::numeric_limits<uint32_t>::max(),
        std::numeric_limits<int64_t>::min(),
        std::numeric_limits<uint64_t>::max(),
        std::numeric_limits<float>::min(),
        std::numeric_limits<double>::max()
    );

    auto edge_bytes = edge_cases.serialize();
    auto edge_deserialized = Primitives::deserialize(edge_bytes.data(), edge_bytes.size());

    std::cout << "Edge case values:\n";
    std::cout << "  i16 min = " << edge_deserialized.short_val << "\n";
    std::cout << "  u16 max = " << edge_deserialized.ushort_val << "\n";
    std::cout << "  i32 min = " << edge_deserialized.long_val << "\n";
    std::cout << "  u32 max = " << edge_deserialized.ulong_val << "\n";
    std::cout << "  i64 min = " << edge_deserialized.llong_val << "\n";
    std::cout << "  u64 max = " << edge_deserialized.ullong_val << "\n";

    std::cout << "\n[OK] Edge case round-trip successful!\n";

    std::cout << "\n=== Sample Complete ===\n";
    return 0;
}
