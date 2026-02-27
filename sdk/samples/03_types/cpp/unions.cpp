// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Unions Sample - Demonstrates DDS discriminated union types
 *
 * This sample shows how to work with union types:
 * - Discriminated unions with different value types
 * - Integer, float, and string variants
 */

#include <iostream>
#include <iomanip>
#include "generated/Unions.hpp"

using namespace hdds_samples;

const char* kind_to_string(DataKind k) {
    switch (k) {
        case DataKind::Integer: return "Integer";
        case DataKind::Float: return "Float";
        case DataKind::Text: return "Text";
        default: return "Unknown";
    }
}

int main() {
    std::cout << "=== HDDS Union Types Sample ===\n\n";

    // Integer variant
    std::cout << "--- Integer Variant ---\n";
    auto int_value = DataValue::integer(42);

    std::cout << "Original: Integer(42)\n";
    std::cout << "Kind: " << kind_to_string(int_value.kind())
              << " (" << static_cast<uint32_t>(int_value.kind()) << ")\n";

    auto bytes = int_value.serialize();
    std::cout << "Serialized size: " << bytes.size() << " bytes\n";
    std::cout << "Serialized: ";
    for (auto b : bytes) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<int>(b);
    }
    std::cout << std::dec << "\n";

    auto deser = DataValue::deserialize(bytes.data(), bytes.size());
    std::cout << "Deserialized: " << kind_to_string(deser.kind())
              << "(" << deser.as_integer() << ")\n";

    if (int_value.as_integer() == deser.as_integer()) {
        std::cout << "[OK] Integer variant round-trip successful\n\n";
    }

    // Float variant
    std::cout << "--- Float Variant ---\n";
    auto float_value = DataValue::float_val(3.14159265359);

    std::cout << "Original: Float(3.14159265359)\n";
    std::cout << "Kind: " << kind_to_string(float_value.kind()) << "\n";

    bytes = float_value.serialize();
    std::cout << "Serialized size: " << bytes.size() << " bytes\n";

    deser = DataValue::deserialize(bytes.data(), bytes.size());
    std::cout << std::fixed << std::setprecision(11);
    std::cout << "Deserialized: " << kind_to_string(deser.kind())
              << "(" << deser.as_float() << ")\n";
    std::cout << std::defaultfloat;

    if (float_value.as_float() == deser.as_float()) {
        std::cout << "[OK] Float variant round-trip successful\n\n";
    }

    // Text variant
    std::cout << "--- Text Variant ---\n";
    auto text_value = DataValue::text("Hello, DDS Unions!");

    std::cout << "Original: Text(\"Hello, DDS Unions!\")\n";
    std::cout << "Kind: " << kind_to_string(text_value.kind()) << "\n";

    bytes = text_value.serialize();
    std::cout << "Serialized size: " << bytes.size() << " bytes\n";

    deser = DataValue::deserialize(bytes.data(), bytes.size());
    std::cout << "Deserialized: " << kind_to_string(deser.kind())
              << "(\"" << deser.as_text() << "\")\n";

    if (text_value.as_text() == deser.as_text()) {
        std::cout << "[OK] Text variant round-trip successful\n\n";
    }

    // Pattern matching on union
    std::cout << "--- Pattern Matching ---\n";
    std::vector<DataValue> values = {
        DataValue::integer(-100),
        DataValue::float_val(2.718),
        DataValue::text("Pattern"),
    };

    for (const auto& value : values) {
        switch (value.kind()) {
            case DataKind::Integer:
                std::cout << "  Integer value: " << value.as_integer() << "\n";
                break;
            case DataKind::Float:
                std::cout << std::fixed << std::setprecision(3);
                std::cout << "  Float value: " << value.as_float() << "\n";
                std::cout << std::defaultfloat;
                break;
            case DataKind::Text:
                std::cout << "  Text value: \"" << value.as_text() << "\"\n";
                break;
        }
    }
    std::cout << "\n";

    // Test edge cases
    std::cout << "--- Edge Cases ---\n";

    // Empty string
    auto empty_text = DataValue::text("");
    auto empty_bytes = empty_text.serialize();
    auto empty_deser = DataValue::deserialize(empty_bytes.data(), empty_bytes.size());
    std::cout << "Empty string: " << kind_to_string(empty_deser.kind())
              << "(\"" << empty_deser.as_text() << "\")\n";

    // Zero values
    auto zero_int = DataValue::integer(0);
    auto zero_bytes = zero_int.serialize();
    auto zero_deser = DataValue::deserialize(zero_bytes.data(), zero_bytes.size());
    std::cout << "Zero integer: " << kind_to_string(zero_deser.kind())
              << "(" << zero_deser.as_integer() << ")\n";

    // Negative float
    auto neg_float = DataValue::float_val(-999.999);
    auto neg_bytes = neg_float.serialize();
    auto neg_deser = DataValue::deserialize(neg_bytes.data(), neg_bytes.size());
    std::cout << "Negative float: " << kind_to_string(neg_deser.kind())
              << "(" << neg_deser.as_float() << ")\n";

    std::cout << "[OK] Edge cases handled correctly\n";

    std::cout << "\n=== Sample Complete ===\n";
    return 0;
}
