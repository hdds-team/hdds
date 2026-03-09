// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Optional Fields Sample - Demonstrates DDS optional field types
 *
 * This sample shows how to work with optional fields:
 * - required_id (int32_t, always present)
 * - optional_name (optional<string>)
 * - optional_value (optional<double>)
 * - optional_data (optional<vector<int32_t>>)
 */

#include <iostream>
#include <iomanip>
#include <vector>
#include <cstdint>
#include "generated/Optional.hpp"

using namespace hdds_samples;

template<typename T>
void print_optional(const char* name, const std::optional<T>& opt) {
    std::cout << "  " << name << ": ";
    if (opt.has_value()) {
        std::cout << opt.value();
    } else {
        std::cout << "None";
    }
    std::cout << "\n";
}

void print_optional_string(const char* name, const std::optional<std::string>& opt) {
    std::cout << "  " << name << ": ";
    if (opt.has_value()) {
        std::cout << "\"" << opt.value() << "\"";
    } else {
        std::cout << "None";
    }
    std::cout << "\n";
}

int main() {
    std::cout << "=== HDDS Optional Fields Sample ===\n\n";

    // All fields present
    std::cout << "--- All Fields Present ---\n";
    OptionalFields full;
    full.required_id = 42;
    full.optional_name = "Complete";
    full.optional_value = 3.14159;
    full.optional_data = std::vector<int32_t>{10, 20, 30, 40, 50};

    std::cout << "Original:\n";
    std::cout << "  required_id:    " << full.required_id << "\n";
    print_optional_string("optional_name", full.optional_name);
    print_optional("optional_value", full.optional_value);
    std::cout << "  optional_data:  ";
    if (full.optional_data.has_value()) {
        std::cout << "[";
        for (size_t i = 0; i < full.optional_data->size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << (*full.optional_data)[i];
        }
        std::cout << "]\n";
    } else {
        std::cout << "None\n";
    }

    std::uint8_t buf[4096];
    int len = full.encode_cdr2_le(buf, sizeof(buf));
    std::cout << "Serialized size: " << len << " bytes\n";

    OptionalFields deser;
    deser.decode_cdr2_le(buf, (std::size_t)len);
    std::cout << "Deserialized:\n";
    std::cout << "  required_id:    " << deser.required_id << "\n";
    print_optional_string("optional_name", deser.optional_name);
    print_optional("optional_value", deser.optional_value);
    std::cout << "  optional_data:  ";
    if (deser.optional_data.has_value()) {
        std::cout << "[" << deser.optional_data->size() << " elements]\n";
    } else {
        std::cout << "None\n";
    }

    if (full.required_id == deser.required_id &&
        full.optional_name == deser.optional_name) {
        std::cout << "[OK] Full struct round-trip successful\n\n";
    }

    // Only required field
    std::cout << "--- Only Required Field ---\n";
    OptionalFields minimal;
    minimal.required_id = 1;
    // optional_name, optional_value, optional_data all default to nullopt

    std::cout << "Original:\n";
    std::cout << "  required_id:    " << minimal.required_id << "\n";
    print_optional_string("optional_name", minimal.optional_name);
    print_optional("optional_value", minimal.optional_value);
    std::cout << "  optional_data:  None\n";

    std::uint8_t min_buf[4096];
    int min_len = minimal.encode_cdr2_le(min_buf, sizeof(min_buf));
    std::cout << "Serialized size: " << min_len << " bytes (minimal)\n";

    OptionalFields min_deser;
    min_deser.decode_cdr2_le(min_buf, (std::size_t)min_len);
    std::cout << "Deserialized:\n";
    bool all_empty = !min_deser.optional_name.has_value() &&
                     !min_deser.optional_value.has_value() &&
                     !min_deser.optional_data.has_value();
    std::cout << "  all optionals are None: " << std::boolalpha << all_empty << "\n";

    if (minimal.required_id == min_deser.required_id && all_empty) {
        std::cout << "[OK] Minimal struct round-trip successful\n\n";
    }

    // Partial fields
    std::cout << "--- Partial Fields ---\n";
    OptionalFields partial;
    partial.required_id = 99;
    partial.optional_name = "Partial";
    // optional_value and optional_data not set

    std::cout << "Original:\n";
    std::cout << "  required_id:    " << partial.required_id << "\n";
    print_optional_string("optional_name", partial.optional_name);
    print_optional("optional_value", partial.optional_value);
    std::cout << "  optional_data:  None\n";

    std::uint8_t part_buf[4096];
    int part_len = partial.encode_cdr2_le(part_buf, sizeof(part_buf));
    std::cout << "Serialized size: " << part_len << " bytes\n";

    OptionalFields part_deser;
    part_deser.decode_cdr2_le(part_buf, (std::size_t)part_len);

    if (partial.optional_name == part_deser.optional_name) {
        std::cout << "[OK] Partial struct round-trip successful\n\n";
    }

    // Pattern matching on optionals
    std::cout << "--- Pattern Matching ---\n";
    std::vector<OptionalFields> structs;

    OptionalFields s1;
    s1.required_id = 1;
    structs.push_back(s1);

    OptionalFields s2;
    s2.required_id = 2;
    s2.optional_name = "Named";
    structs.push_back(s2);

    OptionalFields s3;
    s3.required_id = 3;
    s3.optional_value = 2.718;
    structs.push_back(s3);

    OptionalFields s4;
    s4.required_id = 4;
    s4.optional_data = std::vector<int32_t>{1, 2, 3};
    structs.push_back(s4);

    OptionalFields s5;
    s5.required_id = 5;
    s5.optional_name = "All";
    s5.optional_value = 1.0;
    s5.optional_data = std::vector<int32_t>{999};
    structs.push_back(s5);

    for (const auto& s : structs) {
        std::cout << "  ID " << s.required_id << ": ";

        std::vector<std::string> parts;
        if (s.optional_name.has_value()) parts.push_back("name");
        if (s.optional_value.has_value()) parts.push_back("value");
        if (s.optional_data.has_value()) parts.push_back("data");

        if (parts.empty()) {
            std::cout << "(no optional fields)\n";
        } else {
            std::cout << "has ";
            for (size_t i = 0; i < parts.size(); ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << parts[i];
            }
            std::cout << "\n";
        }
    }
    std::cout << "\n";

    // Size comparison
    std::cout << "--- Size Comparison ---\n";
    OptionalFields min_struct;
    min_struct.required_id = 1;

    OptionalFields full_struct;
    full_struct.required_id = 1;
    full_struct.optional_name = "Test Name";
    full_struct.optional_value = 123.456;
    full_struct.optional_data = std::vector<int32_t>{42};

    std::uint8_t mbuf[4096], fbuf[4096];
    int mlen = min_struct.encode_cdr2_le(mbuf, sizeof(mbuf));
    int flen = full_struct.encode_cdr2_le(fbuf, sizeof(fbuf));

    std::cout << "Minimal (required only): " << mlen << " bytes\n";
    std::cout << "Full (all fields):       " << flen << " bytes\n";
    std::cout << "Space saved when optional fields absent: "
              << (flen - mlen) << " bytes\n";

    std::cout << "\n=== Sample Complete ===\n";
    return 0;
}
