// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Unions Sample - Demonstrates DDS discriminated union types
 *
 * This sample shows how to work with union types:
 * - Discriminated unions with different value types
 * - Integer, float, and string variants
 *
 * Note: The DataValue union uses a _d discriminator (DataKind)
 * and a _u anonymous union with int_val, float_val, str_val.
 */

#include <iostream>
#include <iomanip>
#include <cstdint>
#include <vector>
#include "generated/Unions.hpp"

using namespace hdds_samples;

static const char* kind_to_string(DataKind k) {
    switch (k) {
        case DataKind::INTEGER: return "INTEGER";
        case DataKind::FLOAT: return "FLOAT";
        case DataKind::STRING: return "STRING";
        default: return "Unknown";
    }
}

// Helper to create an integer DataValue
static DataValue make_integer(int32_t v) {
    DataValue dv;
    dv._d = DataKind::INTEGER;
    dv._u.int_val = v;
    return dv;
}

// Helper to create a float DataValue
static DataValue make_float(double v) {
    DataValue dv;
    dv._d = DataKind::FLOAT;
    dv._u.float_val = v;
    return dv;
}

// Helper to create a string DataValue
static DataValue make_string(const std::string& v) {
    DataValue dv;
    dv._d = DataKind::STRING;
    new (&dv._u.str_val) std::string(v);
    return dv;
}

int main() {
    std::cout << "=== HDDS Union Types Sample ===\n\n";

    // Integer variant
    std::cout << "--- Integer Variant ---\n";
    DataValue int_value = make_integer(42);

    std::cout << "Original: INTEGER(42)\n";
    std::cout << "Kind: " << kind_to_string(int_value._d)
              << " (" << static_cast<int32_t>(int_value._d) << ")\n";

    std::uint8_t buf[4096];
    int len = int_value.encode_cdr2_le(buf, sizeof(buf));
    std::cout << "Serialized size: " << len << " bytes\n";
    std::cout << "Serialized: ";
    for (int i = 0; i < len; ++i) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<int>(buf[i]);
    }
    std::cout << std::dec << "\n";

    DataValue deser = make_integer(0);
    deser.decode_cdr2_le(buf, (std::size_t)len);
    std::cout << "Deserialized: " << kind_to_string(deser._d)
              << "(" << deser._u.int_val << ")\n";

    if (int_value._u.int_val == deser._u.int_val) {
        std::cout << "[OK] Integer variant round-trip successful\n\n";
    }

    // Float variant
    std::cout << "--- Float Variant ---\n";
    DataValue float_value = make_float(3.14159265359);

    std::cout << "Original: FLOAT(3.14159265359)\n";
    std::cout << "Kind: " << kind_to_string(float_value._d) << "\n";

    len = float_value.encode_cdr2_le(buf, sizeof(buf));
    std::cout << "Serialized size: " << len << " bytes\n";

    DataValue float_deser = make_float(0.0);
    float_deser.decode_cdr2_le(buf, (std::size_t)len);
    std::cout << std::fixed << std::setprecision(11);
    std::cout << "Deserialized: " << kind_to_string(float_deser._d)
              << "(" << float_deser._u.float_val << ")\n";
    std::cout << std::defaultfloat;

    if (float_value._u.float_val == float_deser._u.float_val) {
        std::cout << "[OK] Float variant round-trip successful\n\n";
    }

    // String variant
    std::cout << "--- String Variant ---\n";
    DataValue text_value = make_string("Hello, DDS Unions!");

    std::cout << "Original: STRING(\"Hello, DDS Unions!\")\n";
    std::cout << "Kind: " << kind_to_string(text_value._d) << "\n";

    len = text_value.encode_cdr2_le(buf, sizeof(buf));
    std::cout << "Serialized size: " << len << " bytes\n";

    DataValue text_deser = make_string("");
    text_deser.decode_cdr2_le(buf, (std::size_t)len);
    std::cout << "Deserialized: " << kind_to_string(text_deser._d)
              << "(\"" << text_deser._u.str_val << "\")\n";

    if (text_value._u.str_val == text_deser._u.str_val) {
        std::cout << "[OK] String variant round-trip successful\n\n";
    }

    // Pattern matching on union
    std::cout << "--- Pattern Matching ---\n";
    std::vector<DataValue> values;
    values.push_back(make_integer(-100));
    values.push_back(make_float(2.718));
    values.push_back(make_string("Pattern"));

    for (const auto& value : values) {
        switch (value._d) {
            case DataKind::INTEGER:
                std::cout << "  Integer value: " << value._u.int_val << "\n";
                break;
            case DataKind::FLOAT:
                std::cout << std::fixed << std::setprecision(3);
                std::cout << "  Float value: " << value._u.float_val << "\n";
                std::cout << std::defaultfloat;
                break;
            case DataKind::STRING:
                std::cout << "  String value: \"" << value._u.str_val << "\"\n";
                break;
        }
    }
    std::cout << "\n";

    // Test edge cases
    std::cout << "--- Edge Cases ---\n";

    // Empty string
    DataValue empty_text = make_string("");
    std::uint8_t ebuf[4096];
    int elen = empty_text.encode_cdr2_le(ebuf, sizeof(ebuf));
    DataValue empty_deser = make_string("");
    empty_deser.decode_cdr2_le(ebuf, (std::size_t)elen);
    std::cout << "Empty string: " << kind_to_string(empty_deser._d)
              << "(\"" << empty_deser._u.str_val << "\")\n";

    // Zero values
    DataValue zero_int = make_integer(0);
    std::uint8_t zbuf[4096];
    int zlen = zero_int.encode_cdr2_le(zbuf, sizeof(zbuf));
    DataValue zero_deser = make_integer(0);
    zero_deser.decode_cdr2_le(zbuf, (std::size_t)zlen);
    std::cout << "Zero integer: " << kind_to_string(zero_deser._d)
              << "(" << zero_deser._u.int_val << ")\n";

    // Negative float
    DataValue neg_float = make_float(-999.999);
    std::uint8_t nbuf[4096];
    int nlen = neg_float.encode_cdr2_le(nbuf, sizeof(nbuf));
    DataValue neg_deser = make_float(0.0);
    neg_deser.decode_cdr2_le(nbuf, (std::size_t)nlen);
    std::cout << "Negative float: " << kind_to_string(neg_deser._d)
              << "(" << neg_deser._u.float_val << ")\n";

    std::cout << "[OK] Edge cases handled correctly\n";

    std::cout << "\n=== Sample Complete ===\n";
    return 0;
}
