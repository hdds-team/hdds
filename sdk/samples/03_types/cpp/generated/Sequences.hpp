// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Sequences.idl
 * Demonstrates sequence types
 */
#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <stdexcept>

namespace hdds_samples {

/// Long sequence (unbounded)
struct LongSeq {
    std::vector<int32_t> values;

    LongSeq() = default;
    explicit LongSeq(std::vector<int32_t> vals) : values(std::move(vals)) {}

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf;
        buf.reserve(4 + values.size() * 4);

        uint32_t count = static_cast<uint32_t>(values.size());
        buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&count),
                   reinterpret_cast<uint8_t*>(&count) + 4);

        for (int32_t v : values) {
            buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&v),
                       reinterpret_cast<uint8_t*>(&v) + 4);
        }
        return buf;
    }

    static LongSeq deserialize(const uint8_t* data, size_t len) {
        LongSeq seq;
        if (len < 4) throw std::runtime_error("Buffer too small");

        uint32_t count;
        std::memcpy(&count, data, 4);
        size_t pos = 4;

        if (pos + count * 4 > len) throw std::runtime_error("Buffer too small");

        seq.values.reserve(count);
        for (uint32_t i = 0; i < count; ++i) {
            int32_t v;
            std::memcpy(&v, &data[pos], 4);
            seq.values.push_back(v);
            pos += 4;
        }
        return seq;
    }
};

/// String sequence (unbounded)
struct StringSeq {
    std::vector<std::string> values;

    StringSeq() = default;
    explicit StringSeq(std::vector<std::string> vals) : values(std::move(vals)) {}

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf;

        uint32_t count = static_cast<uint32_t>(values.size());
        buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&count),
                   reinterpret_cast<uint8_t*>(&count) + 4);

        for (const auto& s : values) {
            uint32_t slen = static_cast<uint32_t>(s.size());
            buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&slen),
                       reinterpret_cast<uint8_t*>(&slen) + 4);
            buf.insert(buf.end(), s.begin(), s.end());
            buf.push_back(0);
        }
        return buf;
    }

    static StringSeq deserialize(const uint8_t* data, size_t len) {
        StringSeq seq;
        if (len < 4) throw std::runtime_error("Buffer too small");

        uint32_t count;
        std::memcpy(&count, data, 4);
        size_t pos = 4;

        seq.values.reserve(count);
        for (uint32_t i = 0; i < count; ++i) {
            if (pos + 4 > len) throw std::runtime_error("Buffer too small");
            uint32_t slen;
            std::memcpy(&slen, &data[pos], 4);
            pos += 4;
            if (pos + slen + 1 > len) throw std::runtime_error("Buffer too small");
            seq.values.emplace_back(reinterpret_cast<const char*>(&data[pos]), slen);
            pos += slen + 1;
        }
        return seq;
    }
};

/// Bounded long sequence (max 10 elements)
struct BoundedLongSeq {
    static constexpr size_t MAX_SIZE = 10;
    std::vector<int32_t> values;

    BoundedLongSeq() = default;
    explicit BoundedLongSeq(std::vector<int32_t> vals) : values(std::move(vals)) {
        if (values.size() > MAX_SIZE) {
            throw std::runtime_error("Sequence exceeds maximum size");
        }
    }

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf;
        buf.reserve(4 + values.size() * 4);

        uint32_t count = static_cast<uint32_t>(values.size());
        buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&count),
                   reinterpret_cast<uint8_t*>(&count) + 4);

        for (int32_t v : values) {
            buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&v),
                       reinterpret_cast<uint8_t*>(&v) + 4);
        }
        return buf;
    }

    static BoundedLongSeq deserialize(const uint8_t* data, size_t len) {
        if (len < 4) throw std::runtime_error("Buffer too small");

        uint32_t count;
        std::memcpy(&count, data, 4);
        if (count > MAX_SIZE) throw std::runtime_error("Sequence exceeds maximum size");

        size_t pos = 4;
        if (pos + count * 4 > len) throw std::runtime_error("Buffer too small");

        std::vector<int32_t> values;
        values.reserve(count);
        for (uint32_t i = 0; i < count; ++i) {
            int32_t v;
            std::memcpy(&v, &data[pos], 4);
            values.push_back(v);
            pos += 4;
        }
        return BoundedLongSeq(std::move(values));
    }
};

} // namespace hdds_samples
