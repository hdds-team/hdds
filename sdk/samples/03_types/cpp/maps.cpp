// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Maps Sample - Demonstrates DDS map types
 *
 * This sample shows how to work with map types:
 * - String to long maps
 * - Long to string maps
 */

#include <iostream>
#include <map>
#include "generated/Maps.hpp"

using namespace hdds_samples;

int main() {
    std::cout << "=== HDDS Map Types Sample ===\n\n";

    // StringLongMap
    std::cout << "--- StringLongMap ---\n";
    StringLongMap str_long_map({
        {"alpha", 1},
        {"beta", 2},
        {"gamma", 3},
        {"delta", 4},
    });

    std::cout << "Original map:\n";
    for (const auto& [k, v] : str_long_map.entries) {
        std::cout << "  \"" << k << "\" => " << v << "\n";
    }

    auto bytes = str_long_map.serialize();
    std::cout << "Serialized size: " << bytes.size() << " bytes\n";

    auto deser = StringLongMap::deserialize(bytes.data(), bytes.size());
    std::cout << "Deserialized map:\n";
    for (const auto& [k, v] : deser.entries) {
        std::cout << "  \"" << k << "\" => " << v << "\n";
    }

    if (str_long_map.entries == deser.entries) {
        std::cout << "[OK] StringLongMap round-trip successful\n\n";
    }

    // LongStringMap
    std::cout << "--- LongStringMap ---\n";
    LongStringMap long_str_map({
        {100, "one hundred"},
        {200, "two hundred"},
        {300, "three hundred"},
    });

    std::cout << "Original map:\n";
    for (const auto& [k, v] : long_str_map.entries) {
        std::cout << "  " << k << " => \"" << v << "\"\n";
    }

    bytes = long_str_map.serialize();
    std::cout << "Serialized size: " << bytes.size() << " bytes\n";

    auto ls_deser = LongStringMap::deserialize(bytes.data(), bytes.size());
    std::cout << "Deserialized map:\n";
    for (const auto& [k, v] : ls_deser.entries) {
        std::cout << "  " << k << " => \"" << v << "\"\n";
    }

    if (long_str_map.entries == ls_deser.entries) {
        std::cout << "[OK] LongStringMap round-trip successful\n\n";
    }

    // Empty map
    std::cout << "--- Empty Map Test ---\n";
    StringLongMap empty_map;
    auto empty_bytes = empty_map.serialize();
    auto empty_deser = StringLongMap::deserialize(empty_bytes.data(), empty_bytes.size());

    std::cout << "Empty map size: " << empty_deser.entries.size() << "\n";
    if (empty_map.entries == empty_deser.entries) {
        std::cout << "[OK] Empty map handled correctly\n\n";
    }

    // Map with special characters
    std::cout << "--- Special Characters Test ---\n";
    StringLongMap special_map({
        {"café", 42},
        {"日本語", 100},
        {"emoji 🎉", 999},
    });

    auto special_bytes = special_map.serialize();
    auto special_deser = StringLongMap::deserialize(special_bytes.data(), special_bytes.size());

    std::cout << "Special character keys:\n";
    for (const auto& [k, v] : special_deser.entries) {
        std::cout << "  \"" << k << "\" => " << v << "\n";
    }

    if (special_map.entries == special_deser.entries) {
        std::cout << "[OK] Special characters handled correctly\n";
    }

    std::cout << "\n=== Sample Complete ===\n";
    return 0;
}
