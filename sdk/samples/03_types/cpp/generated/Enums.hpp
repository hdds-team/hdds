// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Enums.idl
 * Demonstrates enum types
 */
#pragma once

#include <vector>
#include <cstdint>
#include <cstring>
#include <stdexcept>

namespace hdds_samples {

/// Color enum
enum class Color : uint32_t {
    Red = 0,
    Green = 1,
    Blue = 2,
};

/// Status enum with explicit values
enum class Status : uint32_t {
    Unknown = 0,
    Pending = 10,
    Active = 20,
    Completed = 30,
    Failed = 100,
};

/// Container for enum values
struct EnumDemo {
    Color color = Color::Red;
    Status status = Status::Unknown;

    EnumDemo() = default;
    EnumDemo(Color c, Status s) : color(c), status(s) {}

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(8);
        uint32_t c = static_cast<uint32_t>(color);
        uint32_t s = static_cast<uint32_t>(status);
        std::memcpy(&buf[0], &c, 4);
        std::memcpy(&buf[4], &s, 4);
        return buf;
    }

    static EnumDemo deserialize(const uint8_t* data, size_t len) {
        if (len < 8) throw std::runtime_error("Buffer too small for enums");
        EnumDemo e;
        uint32_t c, s;
        std::memcpy(&c, &data[0], 4);
        std::memcpy(&s, &data[4], 4);
        e.color = static_cast<Color>(c);
        e.status = static_cast<Status>(s);
        return e;
    }
};

inline const char* color_to_string(Color c) {
    switch (c) {
        case Color::Red: return "Red";
        case Color::Green: return "Green";
        case Color::Blue: return "Blue";
        default: return "Unknown";
    }
}

inline const char* status_to_string(Status s) {
    switch (s) {
        case Status::Unknown: return "Unknown";
        case Status::Pending: return "Pending";
        case Status::Active: return "Active";
        case Status::Completed: return "Completed";
        case Status::Failed: return "Failed";
        default: return "Unknown";
    }
}

} // namespace hdds_samples
