// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Unions.idl
 * Demonstrates union types
 */
#pragma once

#include <string>
#include <vector>
#include <variant>
#include <cstdint>
#include <cstring>
#include <stdexcept>

namespace hdds_samples {

/// Discriminator for DataValue union
enum class DataKind : uint32_t {
    Integer = 0,
    Float = 1,
    Text = 2,
};

/// Union type with discriminator
class DataValue {
public:
    using ValueType = std::variant<int32_t, double, std::string>;

private:
    DataKind kind_;
    ValueType value_;

public:
    DataValue() : kind_(DataKind::Integer), value_(int32_t{0}) {}

    static DataValue integer(int32_t v) {
        DataValue dv;
        dv.kind_ = DataKind::Integer;
        dv.value_ = v;
        return dv;
    }

    static DataValue float_val(double v) {
        DataValue dv;
        dv.kind_ = DataKind::Float;
        dv.value_ = v;
        return dv;
    }

    static DataValue text(std::string v) {
        DataValue dv;
        dv.kind_ = DataKind::Text;
        dv.value_ = std::move(v);
        return dv;
    }

    DataKind kind() const { return kind_; }

    int32_t as_integer() const { return std::get<int32_t>(value_); }
    double as_float() const { return std::get<double>(value_); }
    const std::string& as_text() const { return std::get<std::string>(value_); }

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf;
        uint32_t k = static_cast<uint32_t>(kind_);
        buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&k),
                   reinterpret_cast<uint8_t*>(&k) + 4);

        switch (kind_) {
            case DataKind::Integer: {
                int32_t v = std::get<int32_t>(value_);
                buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&v),
                           reinterpret_cast<uint8_t*>(&v) + 4);
                break;
            }
            case DataKind::Float: {
                double v = std::get<double>(value_);
                buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&v),
                           reinterpret_cast<uint8_t*>(&v) + 8);
                break;
            }
            case DataKind::Text: {
                const auto& s = std::get<std::string>(value_);
                uint32_t len = static_cast<uint32_t>(s.size());
                buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&len),
                           reinterpret_cast<uint8_t*>(&len) + 4);
                buf.insert(buf.end(), s.begin(), s.end());
                buf.push_back(0);
                break;
            }
        }
        return buf;
    }

    static DataValue deserialize(const uint8_t* data, size_t len) {
        if (len < 4) throw std::runtime_error("Buffer too small for discriminator");

        uint32_t k;
        std::memcpy(&k, data, 4);
        DataKind kind = static_cast<DataKind>(k);

        switch (kind) {
            case DataKind::Integer: {
                if (len < 8) throw std::runtime_error("Buffer too small for integer");
                int32_t v;
                std::memcpy(&v, &data[4], 4);
                return DataValue::integer(v);
            }
            case DataKind::Float: {
                if (len < 12) throw std::runtime_error("Buffer too small for float");
                double v;
                std::memcpy(&v, &data[4], 8);
                return DataValue::float_val(v);
            }
            case DataKind::Text: {
                if (len < 8) throw std::runtime_error("Buffer too small for string length");
                uint32_t slen;
                std::memcpy(&slen, &data[4], 4);
                if (len < 8 + slen + 1) throw std::runtime_error("Buffer too small for string");
                std::string s(reinterpret_cast<const char*>(&data[8]), slen);
                return DataValue::text(std::move(s));
            }
            default:
                throw std::runtime_error("Unknown discriminator");
        }
    }
};

} // namespace hdds_samples
