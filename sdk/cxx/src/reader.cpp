// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file reader.cpp
 * @brief HDDS C++ DataReader implementation
 */

#include <hdds.hpp>

extern "C" {
#include <hdds.h>
}

namespace hdds {

DataReader::DataReader(const std::string& topic, HddsDataReader* handle)
    : topic_name_(topic), handle_(handle) {}

DataReader::~DataReader() {
    if (cached_status_condition_) {
        hdds_status_condition_release(cached_status_condition_);
        cached_status_condition_ = nullptr;
    }
    if (handle_) {
        hdds_reader_destroy(handle_);
        handle_ = nullptr;
    }
}

DataReader::DataReader(DataReader&& other) noexcept
    : topic_name_(std::move(other.topic_name_)),
      handle_(other.handle_),
      cached_status_condition_(other.cached_status_condition_) {
    other.handle_ = nullptr;
    other.cached_status_condition_ = nullptr;
}

DataReader& DataReader::operator=(DataReader&& other) noexcept {
    if (this != &other) {
        if (cached_status_condition_) {
            hdds_status_condition_release(cached_status_condition_);
        }
        if (handle_) {
            hdds_reader_destroy(handle_);
        }
        topic_name_ = std::move(other.topic_name_);
        handle_ = other.handle_;
        cached_status_condition_ = other.cached_status_condition_;
        other.handle_ = nullptr;
        other.cached_status_condition_ = nullptr;
    }
    return *this;
}

std::optional<std::vector<uint8_t>> DataReader::take_raw() {
    if (!handle_) {
        throw Error("Reader has been destroyed");
    }

    // Allocate buffer
    constexpr size_t BUFFER_SIZE = 65536;
    std::vector<uint8_t> buffer(BUFFER_SIZE);
    size_t actual_size = 0;

    HddsError err = hdds_reader_take(handle_, buffer.data(), BUFFER_SIZE, &actual_size);

    if (err == HDDS_NOT_FOUND) {
        return std::nullopt;  // No data
    }
    if (err != HDDS_OK) {
        throw Error("Take failed with error: " + std::to_string(err));
    }

    buffer.resize(actual_size);
    return buffer;
}

std::string DataReader::get_topic_name_ffi() const {
    if (!handle_) {
        throw Error("Reader has been destroyed");
    }

    char buf[256];
    size_t out_len = 0;
    HddsError err = hdds_reader_topic_name(handle_, buf, sizeof(buf), &out_len);
    if (err != HDDS_OK) {
        throw Error("Failed to get reader topic name");
    }
    return std::string(buf, out_len);
}

HddsStatusCondition* DataReader::get_status_condition() {
    if (!handle_) {
        throw Error("Reader has been destroyed");
    }

    // Release previous handle if we already acquired one
    if (cached_status_condition_) {
        hdds_status_condition_release(cached_status_condition_);
    }

    // Acquire new handle (refcounted in FFI layer)
    cached_status_condition_ = const_cast<HddsStatusCondition*>(
        hdds_reader_get_status_condition(handle_));
    return cached_status_condition_;
}

} // namespace hdds
