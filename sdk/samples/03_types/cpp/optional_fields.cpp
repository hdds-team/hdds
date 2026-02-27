// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Optional Fields Sample - Demonstrates DDS optional field types
 *
 * This sample shows how to work with optional fields:
 * - Required fields (always present)
 * - Optional fields (may be absent)
 * - Presence checking
 */

#include <iostream>
#include <iomanip>
#include <vector>
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
    OptionalFields full(42);
    full.with_name("Complete").with_value(3.14159).with_count(100);

    std::cout << "Original:\n";
    std::cout << "  required_id:    " << full.required_id << "\n";
    print_optional_string("optional_name", full.optional_name);
    print_optional("optional_value", full.optional_value);
    print_optional("optional_count", full.optional_count);

    auto bytes = full.serialize();
    std::cout << "Serialized size: " << bytes.size() << " bytes\n";

    auto deser = OptionalFields::deserialize(bytes.data(), bytes.size());
    std::cout << "Deserialized:\n";
    std::cout << "  required_id:    " << deser.required_id << "\n";
    print_optional_string("optional_name", deser.optional_name);
    print_optional("optional_value", deser.optional_value);
    print_optional("optional_count", deser.optional_count);

    if (full.required_id == deser.required_id &&
        full.optional_name == deser.optional_name) {
        std::cout << "[OK] Full struct round-trip successful\n\n";
    }

    // Only required field
    std::cout << "--- Only Required Field ---\n";
    OptionalFields minimal(1);

    std::cout << "Original:\n";
    std::cout << "  required_id:    " << minimal.required_id << "\n";
    print_optional_string("optional_name", minimal.optional_name);
    print_optional("optional_value", minimal.optional_value);
    print_optional("optional_count", minimal.optional_count);

    bytes = minimal.serialize();
    std::cout << "Serialized size: " << bytes.size() << " bytes (minimal)\n";

    deser = OptionalFields::deserialize(bytes.data(), bytes.size());
    std::cout << "Deserialized:\n";
    bool all_empty = !deser.optional_name.has_value() &&
                     !deser.optional_value.has_value() &&
                     !deser.optional_count.has_value();
    std::cout << "  all optionals are None: " << std::boolalpha << all_empty << "\n";

    if (minimal.required_id == deser.required_id && all_empty) {
        std::cout << "[OK] Minimal struct round-trip successful\n\n";
    }

    // Partial fields
    std::cout << "--- Partial Fields ---\n";
    OptionalFields partial(99);
    partial.with_name("Partial");
    // value and count not set

    std::cout << "Original:\n";
    std::cout << "  required_id:    " << partial.required_id << "\n";
    print_optional_string("optional_name", partial.optional_name);
    print_optional("optional_value", partial.optional_value);
    print_optional("optional_count", partial.optional_count);

    bytes = partial.serialize();
    std::cout << "Serialized size: " << bytes.size() << " bytes\n";

    deser = OptionalFields::deserialize(bytes.data(), bytes.size());

    if (partial.optional_name == deser.optional_name) {
        std::cout << "[OK] Partial struct round-trip successful\n\n";
    }

    // Pattern matching on optionals
    std::cout << "--- Pattern Matching ---\n";
    std::vector<OptionalFields> structs;

    structs.push_back(OptionalFields(1));

    OptionalFields s2(2);
    s2.with_name("Named");
    structs.push_back(s2);

    OptionalFields s3(3);
    s3.with_value(2.718);
    structs.push_back(s3);

    OptionalFields s4(4);
    s4.with_count(-50);
    structs.push_back(s4);

    OptionalFields s5(5);
    s5.with_name("All").with_value(1.0).with_count(999);
    structs.push_back(s5);

    for (const auto& s : structs) {
        std::cout << "  ID " << s.required_id << ": ";

        std::vector<std::string> parts;
        if (s.optional_name.has_value()) parts.push_back("name");
        if (s.optional_value.has_value()) parts.push_back("value");
        if (s.optional_count.has_value()) parts.push_back("count");

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
    OptionalFields min_struct(1);
    OptionalFields full_struct(1);
    full_struct.with_name("Test Name").with_value(123.456).with_count(42);

    auto min_bytes = min_struct.serialize();
    auto full_bytes = full_struct.serialize();

    std::cout << "Minimal (required only): " << min_bytes.size() << " bytes\n";
    std::cout << "Full (all fields):       " << full_bytes.size() << " bytes\n";
    std::cout << "Space saved when optional fields absent: "
              << (full_bytes.size() - min_bytes.size()) << " bytes\n";

    std::cout << "\n=== Sample Complete ===\n";
    return 0;
}
