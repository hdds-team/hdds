// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Arrays Sample - Demonstrates DDS fixed-size array types
 *
 * This sample shows how to work with array types:
 * - Fixed-size integer arrays
 * - Fixed-size string arrays
 * - Multi-dimensional arrays (matrices)
 */

#include <iostream>
#include <iomanip>
#include "generated/Arrays.hpp"

using namespace hdds_samples;

int main() {
    std::cout << "=== HDDS Array Types Sample ===\n\n";

    // LongArray - fixed 10-element array
    std::cout << "--- LongArray (10 elements) ---\n";
    LongArray long_arr({{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}});

    std::cout << "Original: [";
    for (size_t i = 0; i < 10; ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << long_arr.values[i];
    }
    std::cout << "]\n";

    auto bytes = long_arr.serialize();
    std::cout << "Serialized size: " << bytes.size() << " bytes (10 × 4 = 40)\n";

    auto deser = LongArray::deserialize(bytes.data(), bytes.size());
    std::cout << "Deserialized: [";
    for (size_t i = 0; i < 10; ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << deser.values[i];
    }
    std::cout << "]\n";

    if (long_arr.values == deser.values) {
        std::cout << "[OK] LongArray round-trip successful\n\n";
    }

    // StringArray - fixed 5-element string array
    std::cout << "--- StringArray (5 elements) ---\n";
    StringArray str_arr({{"Alpha", "Beta", "Gamma", "Delta", "Epsilon"}});

    std::cout << "Original: [";
    for (size_t i = 0; i < 5; ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << "\"" << str_arr.values[i] << "\"";
    }
    std::cout << "]\n";

    bytes = str_arr.serialize();
    std::cout << "Serialized size: " << bytes.size() << " bytes\n";

    auto str_deser = StringArray::deserialize(bytes.data(), bytes.size());
    std::cout << "Deserialized: [";
    for (size_t i = 0; i < 5; ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << "\"" << str_deser.values[i] << "\"";
    }
    std::cout << "]\n";

    if (str_arr.values == str_deser.values) {
        std::cout << "[OK] StringArray round-trip successful\n\n";
    }

    // Matrix - 3x3 double array
    std::cout << "--- Matrix (3x3) ---\n";
    Matrix matrix({{
        {{1.0, 2.0, 3.0}},
        {{4.0, 5.0, 6.0}},
        {{7.0, 8.0, 9.0}}
    }});

    std::cout << "Original matrix:\n";
    for (size_t i = 0; i < 3; ++i) {
        std::cout << "  Row " << i << ": [";
        for (size_t j = 0; j < 3; ++j) {
            if (j > 0) std::cout << ", ";
            std::cout << matrix.values[i][j];
        }
        std::cout << "]\n";
    }

    bytes = matrix.serialize();
    std::cout << "Serialized size: " << bytes.size() << " bytes (9 × 8 = 72)\n";

    auto mat_deser = Matrix::deserialize(bytes.data(), bytes.size());
    std::cout << "Deserialized matrix:\n";
    for (size_t i = 0; i < 3; ++i) {
        std::cout << "  Row " << i << ": [";
        for (size_t j = 0; j < 3; ++j) {
            if (j > 0) std::cout << ", ";
            std::cout << mat_deser.values[i][j];
        }
        std::cout << "]\n";
    }

    if (matrix.values == mat_deser.values) {
        std::cout << "[OK] Matrix round-trip successful\n\n";
    }

    // Identity matrix
    std::cout << "--- Identity Matrix ---\n";
    auto identity = Matrix::identity();
    std::cout << "Identity matrix:\n";
    for (size_t i = 0; i < 3; ++i) {
        std::cout << "  [";
        for (size_t j = 0; j < 3; ++j) {
            if (j > 0) std::cout << ", ";
            std::cout << identity.values[i][j];
        }
        std::cout << "]\n";
    }

    auto id_bytes = identity.serialize();
    auto id_deser = Matrix::deserialize(id_bytes.data(), id_bytes.size());
    if (identity.values == id_deser.values) {
        std::cout << "[OK] Identity matrix round-trip successful\n\n";
    }

    // Test with zeros
    std::cout << "--- Zero-initialized Arrays ---\n";
    LongArray zero_arr;
    std::cout << "Zero LongArray: all zeros\n";

    auto zero_bytes = zero_arr.serialize();
    auto zero_deser = LongArray::deserialize(zero_bytes.data(), zero_bytes.size());
    if (zero_arr.values == zero_deser.values) {
        std::cout << "[OK] Zero array round-trip successful\n";
    }

    std::cout << "\n=== Sample Complete ===\n";
    return 0;
}
