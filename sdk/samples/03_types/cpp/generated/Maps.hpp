// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Maps.idl
 * Demonstrates map types
 */
#pragma once

#include <map>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <stdexcept>

namespace hdds_samples {

/// String to long map
struct StringLongMap {
    std::map<std::string, int32_t> entries;

    StringLongMap() = default;
    explicit StringLongMap(std::map<std::string, int32_t> e) : entries(std::move(e)) {}

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf;

        uint32_t count = static_cast<uint32_t>(entries.size());
        buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&count),
                   reinterpret_cast<uint8_t*>(&count) + 4);

        for (const auto& [key, value] : entries) {
            uint32_t key_len = static_cast<uint32_t>(key.size());
            buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&key_len),
                       reinterpret_cast<uint8_t*>(&key_len) + 4);
            buf.insert(buf.end(), key.begin(), key.end());
            buf.push_back(0);
            buf.insert(buf.end(), reinterpret_cast<const uint8_t*>(&value),
                       reinterpret_cast<const uint8_t*>(&value) + 4);
        }
        return buf;
    }

    static StringLongMap deserialize(const uint8_t* data, size_t len) {
        StringLongMap m;
        if (len < 4) throw std::runtime_error("Buffer too small");

        uint32_t count;
        std::memcpy(&count, data, 4);
        size_t pos = 4;

        for (uint32_t i = 0; i < count; ++i) {
            if (pos + 4 > len) throw std::runtime_error("Buffer too small");
            uint32_t key_len;
            std::memcpy(&key_len, &data[pos], 4);
            pos += 4;

            if (pos + key_len + 1 + 4 > len) throw std::runtime_error("Buffer too small");
            std::string key(reinterpret_cast<const char*>(&data[pos]), key_len);
            pos += key_len + 1;

            int32_t value;
            std::memcpy(&value, &data[pos], 4);
            pos += 4;

            m.entries[key] = value;
        }
        return m;
    }
};

/// Long to string map
struct LongStringMap {
    std::map<int32_t, std::string> entries;

    LongStringMap() = default;
    explicit LongStringMap(std::map<int32_t, std::string> e) : entries(std::move(e)) {}

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf;

        uint32_t count = static_cast<uint32_t>(entries.size());
        buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&count),
                   reinterpret_cast<uint8_t*>(&count) + 4);

        for (const auto& [key, value] : entries) {
            buf.insert(buf.end(), reinterpret_cast<const uint8_t*>(&key),
                       reinterpret_cast<const uint8_t*>(&key) + 4);
            uint32_t val_len = static_cast<uint32_t>(value.size());
            buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&val_len),
                       reinterpret_cast<uint8_t*>(&val_len) + 4);
            buf.insert(buf.end(), value.begin(), value.end());
            buf.push_back(0);
        }
        return buf;
    }

    static LongStringMap deserialize(const uint8_t* data, size_t len) {
        LongStringMap m;
        if (len < 4) throw std::runtime_error("Buffer too small");

        uint32_t count;
        std::memcpy(&count, data, 4);
        size_t pos = 4;

        for (uint32_t i = 0; i < count; ++i) {
            if (pos + 4 > len) throw std::runtime_error("Buffer too small");
            int32_t key;
            std::memcpy(&key, &data[pos], 4);
            pos += 4;

            if (pos + 4 > len) throw std::runtime_error("Buffer too small");
            uint32_t val_len;
            std::memcpy(&val_len, &data[pos], 4);
            pos += 4;

            if (pos + val_len + 1 > len) throw std::runtime_error("Buffer too small");
            std::string value(reinterpret_cast<const char*>(&data[pos]), val_len);
            pos += val_len + 1;

            m.entries[key] = value;
        }
        return m;
    }
};

} // namespace hdds_samples
