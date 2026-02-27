// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Arrays.idl
 * Demonstrates array types
 */
#pragma once

#include <array>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <stdexcept>

namespace hdds_samples {

/// Fixed-size long array (10 elements)
struct LongArray {
    std::array<int32_t, 10> values{};

    LongArray() = default;
    explicit LongArray(const std::array<int32_t, 10>& vals) : values(vals) {}

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(40);
        std::memcpy(buf.data(), values.data(), 40);
        return buf;
    }

    static LongArray deserialize(const uint8_t* data, size_t len) {
        if (len < 40) throw std::runtime_error("Buffer too small for array");
        LongArray arr;
        std::memcpy(arr.values.data(), data, 40);
        return arr;
    }
};

/// Fixed-size string array (5 elements)
struct StringArray {
    std::array<std::string, 5> values;

    StringArray() = default;
    explicit StringArray(const std::array<std::string, 5>& vals) : values(vals) {}

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf;
        for (const auto& s : values) {
            uint32_t slen = static_cast<uint32_t>(s.size());
            buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&slen),
                       reinterpret_cast<uint8_t*>(&slen) + 4);
            buf.insert(buf.end(), s.begin(), s.end());
            buf.push_back(0);
        }
        return buf;
    }

    static StringArray deserialize(const uint8_t* data, size_t len) {
        StringArray arr;
        size_t pos = 0;
        for (size_t i = 0; i < 5; ++i) {
            if (pos + 4 > len) throw std::runtime_error("Buffer too small");
            uint32_t slen;
            std::memcpy(&slen, &data[pos], 4);
            pos += 4;
            if (pos + slen + 1 > len) throw std::runtime_error("Buffer too small");
            arr.values[i].assign(reinterpret_cast<const char*>(&data[pos]), slen);
            pos += slen + 1;
        }
        return arr;
    }
};

/// 2D matrix (3x3)
struct Matrix {
    std::array<std::array<double, 3>, 3> values{};

    Matrix() = default;
    explicit Matrix(const std::array<std::array<double, 3>, 3>& vals) : values(vals) {}

    static Matrix identity() {
        Matrix m;
        m.values[0] = {1.0, 0.0, 0.0};
        m.values[1] = {0.0, 1.0, 0.0};
        m.values[2] = {0.0, 0.0, 1.0};
        return m;
    }

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(72);
        size_t pos = 0;
        for (const auto& row : values) {
            for (double v : row) {
                std::memcpy(&buf[pos], &v, 8);
                pos += 8;
            }
        }
        return buf;
    }

    static Matrix deserialize(const uint8_t* data, size_t len) {
        if (len < 72) throw std::runtime_error("Buffer too small for matrix");
        Matrix m;
        size_t pos = 0;
        for (auto& row : m.values) {
            for (double& v : row) {
                std::memcpy(&v, &data[pos], 8);
                pos += 8;
            }
        }
        return m;
    }
};

} // namespace hdds_samples
