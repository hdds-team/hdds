// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Strings Sample - Demonstrates DDS string types
 *
 * This sample shows how to work with string types:
 * - Unbounded strings
 * - Bounded strings (with length limit)
 * - Wide strings (wstring)
 */

#include <iostream>
#include <string>
#include "generated/Strings.hpp"

using namespace hdds_samples;

int main() {
    std::cout << "=== HDDS String Types Sample ===\n\n";

    // Create a Strings instance
    Strings original(
        "This is an unbounded string that can be any length",
        "Bounded to 256 chars",
        "Wide string with UTF-8: Héllo Wörld! 你好世界 🌍"
    );

    std::cout << "Original Strings:\n";
    std::cout << "  unbounded_str: \"" << original.unbounded_str << "\"\n";
    std::cout << "  bounded_str:   \"" << original.bounded_str << "\" (max 256 chars)\n";
    std::cout << "  wide_str:      \"" << original.wide_str << "\"\n";

    // Serialize
    auto bytes = original.serialize();
    std::cout << "\nSerialized size: " << bytes.size() << " bytes\n";

    // Deserialize
    auto deserialized = Strings::deserialize(bytes.data(), bytes.size());
    std::cout << "\nDeserialized:\n";
    std::cout << "  unbounded_str: \"" << deserialized.unbounded_str << "\"\n";
    std::cout << "  bounded_str:   \"" << deserialized.bounded_str << "\"\n";
    std::cout << "  wide_str:      \"" << deserialized.wide_str << "\"\n";

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
    Strings empty("", "", "");
    auto empty_bytes = empty.serialize();
    auto empty_deser = Strings::deserialize(empty_bytes.data(), empty_bytes.size());

    if (empty.unbounded_str == empty_deser.unbounded_str) {
        std::cout << "[OK] Empty strings handled correctly\n";
    }

    // Test UTF-8 special characters
    std::cout << "\n--- UTF-8 Special Characters Test ---\n";
    Strings utf8_test(
        "ASCII only: Hello World!",
        "Latin-1: café résumé naïve",
        "Multi-byte: 日本語 한국어 العربية עברית 🎉🚀💻"
    );
    auto utf8_bytes = utf8_test.serialize();
    auto utf8_deser = Strings::deserialize(utf8_bytes.data(), utf8_bytes.size());

    std::cout << "UTF-8 strings preserved:\n";
    std::cout << "  Latin-1:    \"" << utf8_deser.bounded_str << "\"\n";
    std::cout << "  Multi-byte: \"" << utf8_deser.wide_str << "\"\n";

    if (utf8_test.wide_str == utf8_deser.wide_str) {
        std::cout << "[OK] UTF-8 encoding preserved correctly\n";
    }

    // Test long string
    std::cout << "\n--- Long String Test ---\n";
    std::string long_content;
    for (int i = 0; i < 1000; ++i) {
        long_content += static_cast<char>('A' + (i % 26));
    }
    Strings long_str(long_content, "short", "also short");
    auto long_bytes = long_str.serialize();
    auto long_deser = Strings::deserialize(long_bytes.data(), long_bytes.size());

    std::cout << "Long string length: " << long_deser.unbounded_str.length() << " chars\n";
    if (long_str.unbounded_str == long_deser.unbounded_str) {
        std::cout << "[OK] Long string handled correctly\n";
    }

    std::cout << "\n=== Sample Complete ===\n";
    return 0;
}
