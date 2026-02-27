// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Strings.idl
 * Demonstrates string types
 */
#pragma once

#include <string>
#include <vector>
#include <cstring>
#include <cstdint>

namespace hdds_samples {

struct Strings {
    std::string unbounded_str;
    std::string bounded_str;     // max 256 chars
    std::string wide_str;        // wstring stored as UTF-8

    Strings() = default;

    Strings(const std::string& unbounded, const std::string& bounded, const std::string& wide)
        : unbounded_str(unbounded), bounded_str(bounded), wide_str(wide) {}

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf;
        buf.reserve(12 + unbounded_str.size() + bounded_str.size() + wide_str.size() + 3);

        auto write_string = [&buf](const std::string& s) {
            uint32_t len = static_cast<uint32_t>(s.size());
            buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&len),
                       reinterpret_cast<uint8_t*>(&len) + 4);
            buf.insert(buf.end(), s.begin(), s.end());
            buf.push_back(0);  // null terminator
        };

        write_string(unbounded_str);
        write_string(bounded_str);
        write_string(wide_str);

        return buf;
    }

    static Strings deserialize(const uint8_t* buf, size_t len) {
        Strings msg;
        size_t pos = 0;

        auto read_string = [&](std::string& s) -> bool {
            if (pos + 4 > len) return false;
            uint32_t slen;
            std::memcpy(&slen, &buf[pos], 4); pos += 4;
            if (pos + slen + 1 > len) return false;
            s.assign(reinterpret_cast<const char*>(&buf[pos]), slen);
            pos += slen + 1;
            return true;
        };

        read_string(msg.unbounded_str);
        read_string(msg.bounded_str);
        read_string(msg.wide_str);

        return msg;
    }
};

} // namespace hdds_samples
