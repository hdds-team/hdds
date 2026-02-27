// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Primitives.idl
 * Demonstrates all DDS primitive types
 */
#pragma once

#include <cstdint>
#include <vector>
#include <cstring>

namespace hdds_samples {

struct Primitives {
    bool bool_val = false;
    uint8_t octet_val = 0;
    char char_val = '\0';
    int16_t short_val = 0;
    uint16_t ushort_val = 0;
    int32_t long_val = 0;
    uint32_t ulong_val = 0;
    int64_t llong_val = 0;
    uint64_t ullong_val = 0;
    float float_val = 0.0f;
    double double_val = 0.0;

    Primitives() = default;

    Primitives(bool b, uint8_t o, char c, int16_t s, uint16_t us,
               int32_t l, uint32_t ul, int64_t ll, uint64_t ull,
               float f, double d)
        : bool_val(b), octet_val(o), char_val(c), short_val(s), ushort_val(us),
          long_val(l), ulong_val(ul), llong_val(ll), ullong_val(ull),
          float_val(f), double_val(d) {}

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(43);
        size_t pos = 0;

        buf[pos++] = bool_val ? 1 : 0;
        buf[pos++] = octet_val;
        buf[pos++] = static_cast<uint8_t>(char_val);

        std::memcpy(&buf[pos], &short_val, 2); pos += 2;
        std::memcpy(&buf[pos], &ushort_val, 2); pos += 2;
        std::memcpy(&buf[pos], &long_val, 4); pos += 4;
        std::memcpy(&buf[pos], &ulong_val, 4); pos += 4;
        std::memcpy(&buf[pos], &llong_val, 8); pos += 8;
        std::memcpy(&buf[pos], &ullong_val, 8); pos += 8;
        std::memcpy(&buf[pos], &float_val, 4); pos += 4;
        std::memcpy(&buf[pos], &double_val, 8); pos += 8;

        return buf;
    }

    static Primitives deserialize(const uint8_t* buf, size_t len) {
        Primitives msg;
        if (len < 43) return msg;
        size_t pos = 0;

        msg.bool_val = buf[pos++] != 0;
        msg.octet_val = buf[pos++];
        msg.char_val = static_cast<char>(buf[pos++]);

        std::memcpy(&msg.short_val, &buf[pos], 2); pos += 2;
        std::memcpy(&msg.ushort_val, &buf[pos], 2); pos += 2;
        std::memcpy(&msg.long_val, &buf[pos], 4); pos += 4;
        std::memcpy(&msg.ulong_val, &buf[pos], 4); pos += 4;
        std::memcpy(&msg.llong_val, &buf[pos], 8); pos += 8;
        std::memcpy(&msg.ullong_val, &buf[pos], 8); pos += 8;
        std::memcpy(&msg.float_val, &buf[pos], 4); pos += 4;
        std::memcpy(&msg.double_val, &buf[pos], 8); pos += 8;

        return msg;
    }
};

} // namespace hdds_samples
