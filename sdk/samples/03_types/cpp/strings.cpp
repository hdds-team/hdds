// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Strings Sample - Demonstrates DDS string types
 *
 * This sample shows how to work with string types:
 * - Unbounded strings
 * - Bounded strings (sequence<char, 256>)
 * - Wide strings (wstring)
 */

#include <iostream>
#include <string>
#include <cstdint>
#include <algorithm>
#include "generated/Strings.hpp"

using namespace hdds_samples;

// Helper to fill a bounded_str array from a C string
static std::array<char, 256> make_bounded(const char* src) {
    std::array<char, 256> arr{};
    std::size_t n = std::min(std::strlen(src), (std::size_t)255);
    std::copy(src, src + n, arr.begin());
    return arr;
}

int main() {
    std::cout << "=== HDDS String Types Sample ===\n\n";

    // Create a Strings instance
    Strings original;
    original.unbounded_str = "This is an unbounded string that can be any length";
    original.bounded_str = make_bounded("Bounded to 256 chars");
    original.wide_str = L"Wide string";

    std::cout << "Original Strings:\n";
    std::cout << "  unbounded_str: \"" << original.unbounded_str << "\"\n";
    std::cout << "  bounded_str:   \"" << original.bounded_str.data() << "\" (max 256 chars)\n";
    std::cout << "  wide_str:      (wstring, " << original.wide_str.size() << " chars)\n";

    // Serialize
    std::uint8_t buf[8192];
    int len = original.encode_cdr2_le(buf, sizeof(buf));
    std::cout << "\nSerialized size: " << len << " bytes\n";

    // Deserialize
    Strings deserialized;
    deserialized.decode_cdr2_le(buf, (std::size_t)len);
    std::cout << "\nDeserialized:\n";
    std::cout << "  unbounded_str: \"" << deserialized.unbounded_str << "\"\n";
    std::cout << "  bounded_str:   \"" << deserialized.bounded_str.data() << "\"\n";
    std::cout << "  wide_str:      (wstring, " << deserialized.wide_str.size() << " chars)\n";

    // Verify round-trip
    if (original.unbounded_str == deserialized.unbounded_str &&
        original.bounded_str == deserialized.bounded_str &&
        original.wide_str == deserialized.wide_str) {
        std::cout << "\n[OK] Round-trip serialization successful!\n";
    } else {
        std::cout << "\n[ERROR] Round-trip verification failed!\n";
        return 1;
    }

    // Test empty strings
    std::cout << "\n--- Empty String Test ---\n";
    Strings empty;
    empty.unbounded_str = "";
    empty.bounded_str = {};
    empty.wide_str = L"";

    std::uint8_t empty_buf[4096];
    int empty_len = empty.encode_cdr2_le(empty_buf, sizeof(empty_buf));
    Strings empty_deser;
    empty_deser.decode_cdr2_le(empty_buf, (std::size_t)empty_len);

    if (empty.unbounded_str == empty_deser.unbounded_str) {
        std::cout << "[OK] Empty strings handled correctly\n";
    }

    // Test long string
    std::cout << "\n--- Long String Test ---\n";
    Strings long_str;
    std::string long_content;
    for (int i = 0; i < 1000; ++i) {
        long_content += static_cast<char>('A' + (i % 26));
    }
    long_str.unbounded_str = long_content;
    long_str.bounded_str = make_bounded("short");
    long_str.wide_str = L"also short";

    std::uint8_t long_buf[8192];
    int long_len = long_str.encode_cdr2_le(long_buf, sizeof(long_buf));
    Strings long_deser;
    long_deser.decode_cdr2_le(long_buf, (std::size_t)long_len);

    std::cout << "Long string length: " << long_deser.unbounded_str.length() << " chars\n";
    if (long_str.unbounded_str == long_deser.unbounded_str) {
        std::cout << "[OK] Long string handled correctly\n";
    }

    std::cout << "\n=== Sample Complete ===\n";
    return 0;
}
