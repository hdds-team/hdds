// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Enums Sample - Demonstrates DDS enumeration types
 *
 * This sample shows how to work with enum types:
 * - Simple enums (Color)
 * - Enums with explicit values (Status)
 */

#include <iostream>
#include <iomanip>
#include "generated/Enums.hpp"

using namespace hdds_samples;

int main() {
    std::cout << "=== HDDS Enum Types Sample ===\n\n";

    // Color enum
    std::cout << "--- Color Enum ---\n";
    std::cout << "Color values:\n";
    std::cout << "  Red   = " << static_cast<uint32_t>(Color::Red) << "\n";
    std::cout << "  Green = " << static_cast<uint32_t>(Color::Green) << "\n";
    std::cout << "  Blue  = " << static_cast<uint32_t>(Color::Blue) << "\n";

    // Status enum with explicit values
    std::cout << "\n--- Status Enum (explicit values) ---\n";
    std::cout << "Status values:\n";
    std::cout << "  Unknown   = " << static_cast<uint32_t>(Status::Unknown) << "\n";
    std::cout << "  Pending   = " << static_cast<uint32_t>(Status::Pending) << "\n";
    std::cout << "  Active    = " << static_cast<uint32_t>(Status::Active) << "\n";
    std::cout << "  Completed = " << static_cast<uint32_t>(Status::Completed) << "\n";
    std::cout << "  Failed    = " << static_cast<uint32_t>(Status::Failed) << "\n";

    // EnumDemo with both enums
    std::cout << "\n--- EnumDemo Serialization ---\n";
    EnumDemo demo(Color::Green, Status::Active);

    std::cout << "Original:\n";
    std::cout << "  color:  " << color_to_string(demo.color)
              << " (" << static_cast<uint32_t>(demo.color) << ")\n";
    std::cout << "  status: " << status_to_string(demo.status)
              << " (" << static_cast<uint32_t>(demo.status) << ")\n";

    auto bytes = demo.serialize();
    std::cout << "Serialized size: " << bytes.size() << " bytes\n";
    std::cout << "Serialized bytes: ";
    for (auto b : bytes) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<int>(b);
    }
    std::cout << std::dec << "\n";

    auto deser = EnumDemo::deserialize(bytes.data(), bytes.size());
    std::cout << "Deserialized:\n";
    std::cout << "  color:  " << color_to_string(deser.color) << "\n";
    std::cout << "  status: " << status_to_string(deser.status) << "\n";

    if (demo.color == deser.color && demo.status == deser.status) {
        std::cout << "[OK] EnumDemo round-trip successful\n\n";
    }

    // Test all color values
    std::cout << "--- All Color Values Test ---\n";
    for (auto color : {Color::Red, Color::Green, Color::Blue}) {
        EnumDemo test(color, Status::Unknown);
        auto test_bytes = test.serialize();
        auto test_deser = EnumDemo::deserialize(test_bytes.data(), test_bytes.size());
        std::cout << "  " << color_to_string(color) << ": "
                  << static_cast<uint32_t>(color) << " -> "
                  << color_to_string(test_deser.color) << "\n";
    }
    std::cout << "[OK] All colors round-trip correctly\n\n";

    // Test all status values
    std::cout << "--- All Status Values Test ---\n";
    for (auto status : {Status::Unknown, Status::Pending, Status::Active,
                        Status::Completed, Status::Failed}) {
        EnumDemo test(Color::Red, status);
        auto test_bytes = test.serialize();
        auto test_deser = EnumDemo::deserialize(test_bytes.data(), test_bytes.size());
        std::cout << "  " << status_to_string(status) << ": "
                  << static_cast<uint32_t>(status) << " -> "
                  << status_to_string(test_deser.status) << "\n";
    }
    std::cout << "[OK] All statuses round-trip correctly\n\n";

    // Default values
    std::cout << "--- Default Values ---\n";
    EnumDemo default_demo;
    std::cout << "Default color:  " << color_to_string(default_demo.color) << "\n";
    std::cout << "Default status: " << status_to_string(default_demo.status) << "\n";

    std::cout << "\n=== Sample Complete ===\n";
    return 0;
}
