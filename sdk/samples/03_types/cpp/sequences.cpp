// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Sequences Sample - Demonstrates DDS sequence types
 *
 * This sample shows how to work with sequence types:
 * - Unbounded sequences (variable length)
 * - Bounded sequences (with max length)
 * - Sequences of primitives and strings
 */

#include <iostream>
#include <vector>
#include "generated/Sequences.hpp"

using namespace hdds_samples;

template<typename T>
void print_vector(const std::vector<T>& v) {
    std::cout << "[";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << v[i];
    }
    std::cout << "]";
}

int main() {
    std::cout << "=== HDDS Sequence Types Sample ===\n\n";

    // LongSeq - unbounded sequence of integers
    std::cout << "--- LongSeq (unbounded) ---\n";
    LongSeq long_seq({1, 2, 3, 4, 5, -10, 100, 1000});

    std::cout << "Original: ";
    print_vector(long_seq.values);
    std::cout << "\nLength: " << long_seq.values.size() << "\n";

    auto bytes = long_seq.serialize();
    std::cout << "Serialized size: " << bytes.size() << " bytes\n";

    auto deser = LongSeq::deserialize(bytes.data(), bytes.size());
    std::cout << "Deserialized: ";
    print_vector(deser.values);
    std::cout << "\n";

    if (long_seq.values == deser.values) {
        std::cout << "[OK] LongSeq round-trip successful\n\n";
    }

    // StringSeq - sequence of strings
    std::cout << "--- StringSeq (unbounded) ---\n";
    StringSeq string_seq({"Hello", "World", "DDS", "Sequences"});

    std::cout << "Original: ";
    print_vector(string_seq.values);
    std::cout << "\nLength: " << string_seq.values.size() << "\n";

    bytes = string_seq.serialize();
    std::cout << "Serialized size: " << bytes.size() << " bytes\n";

    auto str_deser = StringSeq::deserialize(bytes.data(), bytes.size());
    std::cout << "Deserialized: ";
    print_vector(str_deser.values);
    std::cout << "\n";

    if (string_seq.values == str_deser.values) {
        std::cout << "[OK] StringSeq round-trip successful\n\n";
    }

    // BoundedLongSeq - bounded sequence (max 10 elements)
    std::cout << "--- BoundedLongSeq (max 10) ---\n";
    BoundedLongSeq bounded_seq({10, 20, 30, 40, 50});

    std::cout << "Original: ";
    print_vector(bounded_seq.values);
    std::cout << "\nLength: " << bounded_seq.values.size()
              << " (max: " << BoundedLongSeq::MAX_SIZE << ")\n";

    bytes = bounded_seq.serialize();
    std::cout << "Serialized size: " << bytes.size() << " bytes\n";

    auto bounded_deser = BoundedLongSeq::deserialize(bytes.data(), bytes.size());
    std::cout << "Deserialized: ";
    print_vector(bounded_deser.values);
    std::cout << "\n";

    if (bounded_seq.values == bounded_deser.values) {
        std::cout << "[OK] BoundedLongSeq round-trip successful\n\n";
    }

    // Test bounds enforcement
    std::cout << "--- Bounds Enforcement Test ---\n";
    try {
        std::vector<int32_t> too_many(15);
        BoundedLongSeq bad_seq(too_many);
        std::cout << "[ERROR] Should have rejected oversized sequence\n";
    } catch (const std::runtime_error& e) {
        std::cout << "[OK] Correctly rejected oversized sequence: " << e.what() << "\n";
    }

    // Test empty sequences
    std::cout << "\n--- Empty Sequence Test ---\n";
    LongSeq empty_long({});
    auto empty_bytes = empty_long.serialize();
    auto empty_deser = LongSeq::deserialize(empty_bytes.data(), empty_bytes.size());

    std::cout << "Empty sequence length: " << empty_deser.values.size() << "\n";
    if (empty_long.values == empty_deser.values) {
        std::cout << "[OK] Empty sequence handled correctly\n";
    }

    // Test large sequence
    std::cout << "\n--- Large Sequence Test ---\n";
    std::vector<int32_t> large_values(1000);
    for (int i = 0; i < 1000; ++i) large_values[i] = i;
    LongSeq large_seq(large_values);

    std::cout << "Large sequence length: " << large_seq.values.size() << "\n";
    auto large_bytes = large_seq.serialize();
    std::cout << "Serialized size: " << large_bytes.size() << " bytes\n";

    auto large_deser = LongSeq::deserialize(large_bytes.data(), large_bytes.size());
    if (large_seq.values == large_deser.values) {
        std::cout << "[OK] Large sequence handled correctly\n";
    }

    std::cout << "\n=== Sample Complete ===\n";
    return 0;
}
