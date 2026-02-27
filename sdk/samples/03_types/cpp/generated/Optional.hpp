// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Optional.idl
 * Demonstrates optional field types
 */
#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <cstring>
#include <stdexcept>

namespace hdds_samples {

/// Struct with optional fields
struct OptionalFields {
    uint32_t required_id = 0;
    std::optional<std::string> optional_name;
    std::optional<double> optional_value;
    std::optional<int32_t> optional_count;

    OptionalFields() = default;
    explicit OptionalFields(uint32_t id) : required_id(id) {}

    OptionalFields& with_name(std::string name) {
        optional_name = std::move(name);
        return *this;
    }

    OptionalFields& with_value(double value) {
        optional_value = value;
        return *this;
    }

    OptionalFields& with_count(int32_t count) {
        optional_count = count;
        return *this;
    }

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf;

        // Required ID
        buf.insert(buf.end(), reinterpret_cast<const uint8_t*>(&required_id),
                   reinterpret_cast<const uint8_t*>(&required_id) + 4);

        // Presence flags
        uint8_t flags = 0;
        if (optional_name.has_value()) flags |= 1 << 0;
        if (optional_value.has_value()) flags |= 1 << 1;
        if (optional_count.has_value()) flags |= 1 << 2;
        buf.push_back(flags);

        // Optional name
        if (optional_name.has_value()) {
            const auto& name = optional_name.value();
            uint32_t len = static_cast<uint32_t>(name.size());
            buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&len),
                       reinterpret_cast<uint8_t*>(&len) + 4);
            buf.insert(buf.end(), name.begin(), name.end());
            buf.push_back(0);
        }

        // Optional value
        if (optional_value.has_value()) {
            double v = optional_value.value();
            buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&v),
                       reinterpret_cast<uint8_t*>(&v) + 8);
        }

        // Optional count
        if (optional_count.has_value()) {
            int32_t v = optional_count.value();
            buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&v),
                       reinterpret_cast<uint8_t*>(&v) + 4);
        }

        return buf;
    }

    static OptionalFields deserialize(const uint8_t* data, size_t len) {
        OptionalFields of;
        size_t pos = 0;

        // Required ID
        if (pos + 4 > len) throw std::runtime_error("Buffer too small for required_id");
        std::memcpy(&of.required_id, &data[pos], 4);
        pos += 4;

        // Presence flags
        if (pos >= len) throw std::runtime_error("Buffer too small for presence flags");
        uint8_t flags = data[pos++];

        bool has_name = (flags & (1 << 0)) != 0;
        bool has_value = (flags & (1 << 1)) != 0;
        bool has_count = (flags & (1 << 2)) != 0;

        // Optional name
        if (has_name) {
            if (pos + 4 > len) throw std::runtime_error("Buffer too small for name length");
            uint32_t name_len;
            std::memcpy(&name_len, &data[pos], 4);
            pos += 4;
            if (pos + name_len + 1 > len) throw std::runtime_error("Buffer too small for name data");
            of.optional_name = std::string(reinterpret_cast<const char*>(&data[pos]), name_len);
            pos += name_len + 1;
        }

        // Optional value
        if (has_value) {
            if (pos + 8 > len) throw std::runtime_error("Buffer too small for optional_value");
            double v;
            std::memcpy(&v, &data[pos], 8);
            of.optional_value = v;
            pos += 8;
        }

        // Optional count
        if (has_count) {
            if (pos + 4 > len) throw std::runtime_error("Buffer too small for optional_count");
            int32_t v;
            std::memcpy(&v, &data[pos], 4);
            of.optional_count = v;
            pos += 4;
        }

        return of;
    }
};

} // namespace hdds_samples
