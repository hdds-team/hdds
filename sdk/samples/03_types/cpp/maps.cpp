// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Maps Sample - Demonstrates DDS map types
 *
 * This sample shows how to work with the Maps struct:
 * - scores: map<string, int32_t> (StringLongMap)
 * - labels: map<int32_t, string> (LongStringMap)
 */

#include <iostream>
#include <map>
#include <cstdint>
#include "generated/Maps.hpp"

using namespace hdds_samples;

int main() {
    std::cout << "=== HDDS Map Types Sample ===\n\n";

    // Create a Maps instance with both map fields
    Maps original;
    original.scores = {
        {"alpha", 1},
        {"beta", 2},
        {"gamma", 3},
        {"delta", 4},
    };
    original.labels = {
        {100, "one hundred"},
        {200, "two hundred"},
        {300, "three hundred"},
    };

    // Print scores (StringLongMap)
    std::cout << "--- Scores (string -> long) ---\n";
    std::cout << "Original map:\n";
    for (const auto& [k, v] : original.scores) {
        std::cout << "  \"" << k << "\" => " << v << "\n";
    }

    // Print labels (LongStringMap)
    std::cout << "\n--- Labels (long -> string) ---\n";
    std::cout << "Original map:\n";
    for (const auto& [k, v] : original.labels) {
        std::cout << "  " << k << " => \"" << v << "\"\n";
    }

    // Serialize
    std::uint8_t buf[4096];
    int len = original.encode_cdr2_le(buf, sizeof(buf));
    std::cout << "\nSerialized size: " << len << " bytes\n";

    // Deserialize
    Maps deserialized;
    deserialized.decode_cdr2_le(buf, (std::size_t)len);

    std::cout << "\nDeserialized scores:\n";
    for (const auto& [k, v] : deserialized.scores) {
        std::cout << "  \"" << k << "\" => " << v << "\n";
    }
    std::cout << "Deserialized labels:\n";
    for (const auto& [k, v] : deserialized.labels) {
        std::cout << "  " << k << " => \"" << v << "\"\n";
    }

    if (original.scores == deserialized.scores &&
        original.labels == deserialized.labels) {
        std::cout << "[OK] Maps round-trip successful\n\n";
    } else {
        std::cout << "[ERROR] Maps round-trip failed!\n";
        return 1;
    }

    // Empty map
    std::cout << "--- Empty Map Test ---\n";
    Maps empty_maps;
    std::uint8_t ebuf[4096];
    int elen = empty_maps.encode_cdr2_le(ebuf, sizeof(ebuf));
    Maps empty_deser;
    empty_deser.decode_cdr2_le(ebuf, (std::size_t)elen);

    std::cout << "Empty scores size: " << empty_deser.scores.size() << "\n";
    std::cout << "Empty labels size: " << empty_deser.labels.size() << "\n";
    if (empty_maps.scores == empty_deser.scores &&
        empty_maps.labels == empty_deser.labels) {
        std::cout << "[OK] Empty maps handled correctly\n\n";
    }

    // Map with special characters
    std::cout << "--- Special Characters Test ---\n";
    Maps special;
    special.scores = {
        {"cafe", 42},
        {"hello", 100},
        {"world", 999},
    };

    std::uint8_t sbuf[4096];
    int slen = special.encode_cdr2_le(sbuf, sizeof(sbuf));
    Maps special_deser;
    special_deser.decode_cdr2_le(sbuf, (std::size_t)slen);

    std::cout << "Special character keys:\n";
    for (const auto& [k, v] : special_deser.scores) {
        std::cout << "  \"" << k << "\" => " << v << "\n";
    }

    if (special.scores == special_deser.scores) {
        std::cout << "[OK] Special characters handled correctly\n";
    }

    std::cout << "\n=== Sample Complete ===\n";
    return 0;
}
