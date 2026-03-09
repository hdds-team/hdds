// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Sequences Sample - Demonstrates DDS sequence types
 *
 * This sample shows how to work with the Sequences struct:
 * - numbers: unbounded sequence of int32 (vector<int32_t>)
 * - names: unbounded sequence of strings (vector<string>)
 * - bounded_numbers: bounded sequence (array<int32_t, 10>)
 */

#include <iostream>
#include <vector>
#include <cstdint>
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

template<typename T, std::size_t N>
void print_array(const std::array<T, N>& a) {
    std::cout << "[";
    for (size_t i = 0; i < N; ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << a[i];
    }
    std::cout << "]";
}

int main() {
    std::cout << "=== HDDS Sequence Types Sample ===\n\n";

    // Create a Sequences instance with all fields
    Sequences original;
    original.numbers = {1, 2, 3, 4, 5, -10, 100, 1000};
    original.names = {"Hello", "World", "DDS", "Sequences"};
    original.bounded_numbers = {{10, 20, 30, 40, 50, 0, 0, 0, 0, 0}};

    // Print numbers (unbounded sequence)
    std::cout << "--- Numbers (unbounded) ---\n";
    std::cout << "Original: ";
    print_vector(original.numbers);
    std::cout << "\nLength: " << original.numbers.size() << "\n";

    // Print names (unbounded string sequence)
    std::cout << "\n--- Names (unbounded) ---\n";
    std::cout << "Original: ";
    print_vector(original.names);
    std::cout << "\nLength: " << original.names.size() << "\n";

    // Print bounded_numbers
    std::cout << "\n--- BoundedNumbers (max 10) ---\n";
    std::cout << "Original: ";
    print_array(original.bounded_numbers);
    std::cout << "\n";

    // Serialize
    std::uint8_t buf[4096];
    int len = original.encode_cdr2_le(buf, sizeof(buf));
    std::cout << "\nSerialized size: " << len << " bytes\n";

    // Deserialize
    Sequences deserialized;
    deserialized.decode_cdr2_le(buf, (std::size_t)len);

    std::cout << "Deserialized numbers: ";
    print_vector(deserialized.numbers);
    std::cout << "\n";
    std::cout << "Deserialized names: ";
    print_vector(deserialized.names);
    std::cout << "\n";
    std::cout << "Deserialized bounded: ";
    print_array(deserialized.bounded_numbers);
    std::cout << "\n";

    if (original.numbers == deserialized.numbers &&
        original.names == deserialized.names &&
        original.bounded_numbers == deserialized.bounded_numbers) {
        std::cout << "[OK] Sequences round-trip successful\n\n";
    } else {
        std::cout << "[ERROR] Sequences round-trip failed!\n";
        return 1;
    }

    // Test empty sequences
    std::cout << "--- Empty Sequence Test ---\n";
    Sequences empty;
    // numbers and names default to empty vectors
    std::uint8_t empty_buf[4096];
    int empty_len = empty.encode_cdr2_le(empty_buf, sizeof(empty_buf));
    Sequences empty_deser;
    empty_deser.decode_cdr2_le(empty_buf, (std::size_t)empty_len);

    std::cout << "Empty numbers length: " << empty_deser.numbers.size() << "\n";
    std::cout << "Empty names length: " << empty_deser.names.size() << "\n";
    if (empty.numbers == empty_deser.numbers) {
        std::cout << "[OK] Empty sequence handled correctly\n";
    }

    // Test large sequence
    std::cout << "\n--- Large Sequence Test ---\n";
    Sequences large;
    large.numbers.resize(1000);
    for (int i = 0; i < 1000; ++i) large.numbers[i] = i;

    std::cout << "Large sequence length: " << large.numbers.size() << "\n";
    std::uint8_t large_buf[16384];
    int large_len = large.encode_cdr2_le(large_buf, sizeof(large_buf));
    std::cout << "Serialized size: " << large_len << " bytes\n";

    Sequences large_deser;
    large_deser.decode_cdr2_le(large_buf, (std::size_t)large_len);
    if (large.numbers == large_deser.numbers) {
        std::cout << "[OK] Large sequence handled correctly\n";
    }

    std::cout << "\n=== Sample Complete ===\n";
    return 0;
}
