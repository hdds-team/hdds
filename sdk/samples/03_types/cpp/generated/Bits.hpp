// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Bits.idl
 * Demonstrates bitmask and bitset types
 */
#pragma once

#include <vector>
#include <cstdint>
#include <cstring>
#include <string>
#include <stdexcept>

namespace hdds_samples {

/// Permission bitmask
class Permissions {
public:
    static constexpr uint32_t None = 0;
    static constexpr uint32_t Read = 1 << 0;
    static constexpr uint32_t Write = 1 << 1;
    static constexpr uint32_t Execute = 1 << 2;
    static constexpr uint32_t Delete = 1 << 3;

private:
    uint32_t bits_ = 0;

public:
    Permissions() = default;
    explicit Permissions(uint32_t bits) : bits_(bits) {}

    uint32_t bits() const { return bits_; }
    bool has(uint32_t flag) const { return (bits_ & flag) != 0; }
    void set(uint32_t flag) { bits_ |= flag; }
    void clear(uint32_t flag) { bits_ &= ~flag; }
    void toggle(uint32_t flag) { bits_ ^= flag; }

    bool can_read() const { return has(Read); }
    bool can_write() const { return has(Write); }
    bool can_execute() const { return has(Execute); }
    bool can_delete() const { return has(Delete); }

    std::string to_string() const {
        std::string result;
        if (can_read()) result += "READ";
        if (can_write()) { if (!result.empty()) result += " | "; result += "WRITE"; }
        if (can_execute()) { if (!result.empty()) result += " | "; result += "EXECUTE"; }
        if (can_delete()) { if (!result.empty()) result += " | "; result += "DELETE"; }
        return result.empty() ? "NONE" : result;
    }

    bool operator==(const Permissions& other) const { return bits_ == other.bits_; }
    bool operator!=(const Permissions& other) const { return bits_ != other.bits_; }
};

/// Status flags bitset (8 bits)
class StatusFlags {
public:
    static constexpr uint8_t Enabled = 1 << 0;
    static constexpr uint8_t Visible = 1 << 1;
    static constexpr uint8_t Selected = 1 << 2;
    static constexpr uint8_t Focused = 1 << 3;
    static constexpr uint8_t Error = 1 << 4;
    static constexpr uint8_t Warning = 1 << 5;

private:
    uint8_t bits_ = 0;

public:
    StatusFlags() = default;
    explicit StatusFlags(uint8_t bits) : bits_(bits) {}

    uint8_t bits() const { return bits_; }
    bool has(uint8_t flag) const { return (bits_ & flag) != 0; }
    void set(uint8_t flag) { bits_ |= flag; }
    void clear(uint8_t flag) { bits_ &= ~flag; }

    bool is_enabled() const { return has(Enabled); }
    bool is_visible() const { return has(Visible); }
    bool is_selected() const { return has(Selected); }
    bool is_focused() const { return has(Focused); }
    bool has_error() const { return has(Error); }
    bool has_warning() const { return has(Warning); }

    bool operator==(const StatusFlags& other) const { return bits_ == other.bits_; }
    bool operator!=(const StatusFlags& other) const { return bits_ != other.bits_; }
};

/// Container for bit types
struct BitsDemo {
    Permissions permissions;
    StatusFlags status;

    BitsDemo() = default;
    BitsDemo(Permissions p, StatusFlags s) : permissions(p), status(s) {}

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(5);
        uint32_t p = permissions.bits();
        std::memcpy(&buf[0], &p, 4);
        buf[4] = status.bits();
        return buf;
    }

    static BitsDemo deserialize(const uint8_t* data, size_t len) {
        if (len < 5) throw std::runtime_error("Buffer too small for bits");
        BitsDemo b;
        uint32_t p;
        std::memcpy(&p, &data[0], 4);
        b.permissions = Permissions(p);
        b.status = StatusFlags(data[4]);
        return b;
    }
};

} // namespace hdds_samples
