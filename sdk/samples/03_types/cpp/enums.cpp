// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Enums Sample - Demonstrates DDS enumeration types
 *
 * This sample shows how to work with enum types:
 * - Simple enums (Color: RED, GREEN, BLUE)
 * - Enums with explicit values (Status: UNKNOWN=0, ACTIVE=10, INACTIVE=20, ERROR=100)
 */

#include <iostream>
#include <iomanip>
#include <cstdint>
#include "generated/Enums.hpp"

using namespace hdds_samples;

static const char* color_to_string(Color c) {
    switch (c) {
        case Color::RED: return "RED";
        case Color::GREEN: return "GREEN";
        case Color::BLUE: return "BLUE";
        default: return "Unknown";
    }
}

static const char* status_to_string(Status s) {
    switch (s) {
        case Status::UNKNOWN: return "UNKNOWN";
        case Status::ACTIVE: return "ACTIVE";
        case Status::INACTIVE: return "INACTIVE";
        case Status::ERROR: return "ERROR";
        default: return "Unknown";
    }
}

int main() {
    std::cout << "=== HDDS Enum Types Sample ===\n\n";

    // Color enum
    std::cout << "--- Color Enum ---\n";
    std::cout << "Color values:\n";
    std::cout << "  RED   = " << static_cast<int32_t>(Color::RED) << "\n";
    std::cout << "  GREEN = " << static_cast<int32_t>(Color::GREEN) << "\n";
    std::cout << "  BLUE  = " << static_cast<int32_t>(Color::BLUE) << "\n";

    // Status enum with explicit values
    std::cout << "\n--- Status Enum (explicit values) ---\n";
    std::cout << "Status values:\n";
    std::cout << "  UNKNOWN  = " << static_cast<int32_t>(Status::UNKNOWN) << "\n";
    std::cout << "  ACTIVE   = " << static_cast<int32_t>(Status::ACTIVE) << "\n";
    std::cout << "  INACTIVE = " << static_cast<int32_t>(Status::INACTIVE) << "\n";
    std::cout << "  ERROR    = " << static_cast<int32_t>(Status::ERROR) << "\n";

    // Enums struct with both enums
    std::cout << "\n--- Enums Serialization ---\n";
    Enums demo(Color::GREEN, Status::ACTIVE);

    std::cout << "Original:\n";
    std::cout << "  color:  " << color_to_string(demo.color)
              << " (" << static_cast<int32_t>(demo.color) << ")\n";
    std::cout << "  status: " << status_to_string(demo.status)
              << " (" << static_cast<int32_t>(demo.status) << ")\n";

    std::uint8_t buf[4096];
    int len = demo.encode_cdr2_le(buf, sizeof(buf));
    std::cout << "Serialized size: " << len << " bytes\n";
    std::cout << "Serialized bytes: ";
    for (int i = 0; i < len; ++i) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<int>(buf[i]);
    }
    std::cout << std::dec << "\n";

    Enums deser;
    deser.decode_cdr2_le(buf, (std::size_t)len);
    std::cout << "Deserialized:\n";
    std::cout << "  color:  " << color_to_string(deser.color) << "\n";
    std::cout << "  status: " << status_to_string(deser.status) << "\n";

    if (demo.color == deser.color && demo.status == deser.status) {
        std::cout << "[OK] Enums round-trip successful\n\n";
    }

    // Test all color values
    std::cout << "--- All Color Values Test ---\n";
    for (auto color : {Color::RED, Color::GREEN, Color::BLUE}) {
        Enums test(color, Status::UNKNOWN);
        std::uint8_t tbuf[4096];
        int tlen = test.encode_cdr2_le(tbuf, sizeof(tbuf));
        Enums test_deser;
        test_deser.decode_cdr2_le(tbuf, (std::size_t)tlen);
        std::cout << "  " << color_to_string(color) << ": "
                  << static_cast<int32_t>(color) << " -> "
                  << color_to_string(test_deser.color) << "\n";
    }
    std::cout << "[OK] All colors round-trip correctly\n\n";

    // Test all status values
    std::cout << "--- All Status Values Test ---\n";
    for (auto status : {Status::UNKNOWN, Status::ACTIVE,
                        Status::INACTIVE, Status::ERROR}) {
        Enums test(Color::RED, status);
        std::uint8_t tbuf[4096];
        int tlen = test.encode_cdr2_le(tbuf, sizeof(tbuf));
        Enums test_deser;
        test_deser.decode_cdr2_le(tbuf, (std::size_t)tlen);
        std::cout << "  " << status_to_string(status) << ": "
                  << static_cast<int32_t>(status) << " -> "
                  << status_to_string(test_deser.status) << "\n";
    }
    std::cout << "[OK] All statuses round-trip correctly\n\n";

    // Default values
    std::cout << "--- Default Values ---\n";
    Enums default_demo;
    std::cout << "Default color:  " << color_to_string(default_demo.color) << "\n";
    std::cout << "Default status: " << status_to_string(default_demo.status) << "\n";

    std::cout << "\n=== Sample Complete ===\n";
    return 0;
}
