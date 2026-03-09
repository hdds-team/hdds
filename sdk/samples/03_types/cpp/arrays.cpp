// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Arrays Sample - Demonstrates DDS fixed-size array types
 *
 * This sample shows how to work with the Arrays struct:
 * - Fixed-size integer array (numbers: array<int32_t, 10>)
 * - Fixed-size string array (names: array<string, 5>)
 * - 2D float array (transform: array<array<float, 3>, 3>)
 */

#include <iostream>
#include <iomanip>
#include <cstdint>
#include "generated/Arrays.hpp"

using namespace hdds_samples;

int main() {
    std::cout << "=== HDDS Array Types Sample ===\n\n";

    // Create an Arrays instance with all fields
    Arrays original;
    original.numbers = {{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}};
    original.names = {{"Alpha", "Beta", "Gamma", "Delta", "Epsilon"}};
    original.transform = {{
        {{1.0f, 0.0f, 0.0f}},
        {{0.0f, 1.0f, 0.0f}},
        {{0.0f, 0.0f, 1.0f}}
    }};

    // Print numbers
    std::cout << "--- Numbers (10 elements) ---\n";
    std::cout << "Original: [";
    for (size_t i = 0; i < original.numbers.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << original.numbers[i];
    }
    std::cout << "]\n";

    // Print names
    std::cout << "\n--- Names (5 elements) ---\n";
    std::cout << "Original: [";
    for (size_t i = 0; i < original.names.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << "\"" << original.names[i] << "\"";
    }
    std::cout << "]\n";

    // Print transform matrix
    std::cout << "\n--- Transform (3x3) ---\n";
    std::cout << "Original matrix:\n";
    for (size_t i = 0; i < 3; ++i) {
        std::cout << "  Row " << i << ": [";
        for (size_t j = 0; j < 3; ++j) {
            if (j > 0) std::cout << ", ";
            std::cout << original.transform[i][j];
        }
        std::cout << "]\n";
    }

    // Serialize
    std::uint8_t buf[4096];
    int len = original.encode_cdr2_le(buf, sizeof(buf));
    std::cout << "\nSerialized size: " << len << " bytes\n";

    // Deserialize
    Arrays deserialized;
    deserialized.decode_cdr2_le(buf, (std::size_t)len);

    std::cout << "Deserialized numbers: [";
    for (size_t i = 0; i < deserialized.numbers.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << deserialized.numbers[i];
    }
    std::cout << "]\n";

    std::cout << "Deserialized names: [";
    for (size_t i = 0; i < deserialized.names.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << "\"" << deserialized.names[i] << "\"";
    }
    std::cout << "]\n";

    std::cout << "Deserialized matrix:\n";
    for (size_t i = 0; i < 3; ++i) {
        std::cout << "  Row " << i << ": [";
        for (size_t j = 0; j < 3; ++j) {
            if (j > 0) std::cout << ", ";
            std::cout << deserialized.transform[i][j];
        }
        std::cout << "]\n";
    }

    // Verify round-trip
    if (original.numbers == deserialized.numbers &&
        original.names == deserialized.names &&
        original.transform == deserialized.transform) {
        std::cout << "[OK] Arrays round-trip successful\n\n";
    } else {
        std::cout << "[ERROR] Arrays round-trip failed!\n";
        return 1;
    }

    // Test with zeros
    std::cout << "--- Zero-initialized Arrays ---\n";
    Arrays zero_arr;
    std::cout << "Zero arrays: all defaults\n";

    std::uint8_t zero_buf[4096];
    int zero_len = zero_arr.encode_cdr2_le(zero_buf, sizeof(zero_buf));
    Arrays zero_deser;
    zero_deser.decode_cdr2_le(zero_buf, (std::size_t)zero_len);
    if (zero_arr.numbers == zero_deser.numbers) {
        std::cout << "[OK] Zero array round-trip successful\n";
    }

    std::cout << "\n=== Sample Complete ===\n";
    return 0;
}
