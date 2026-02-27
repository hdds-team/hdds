// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file writer.cpp
 * @brief HDDS C++ DataWriter implementation
 */

#include <hdds.hpp>

extern "C" {
#include <hdds.h>
}

namespace hdds {

DataWriter::DataWriter(const std::string& topic, HddsDataWriter* handle)
    : topic_name_(topic), handle_(handle) {}

DataWriter::~DataWriter() {
    if (handle_) {
        hdds_writer_destroy(handle_);
        handle_ = nullptr;
    }
}

DataWriter::DataWriter(DataWriter&& other) noexcept
    : topic_name_(std::move(other.topic_name_)),
      handle_(other.handle_) {
    other.handle_ = nullptr;
}

DataWriter& DataWriter::operator=(DataWriter&& other) noexcept {
    if (this != &other) {
        if (handle_) {
            hdds_writer_destroy(handle_);
        }
        topic_name_ = std::move(other.topic_name_);
        handle_ = other.handle_;
        other.handle_ = nullptr;
    }
    return *this;
}

void DataWriter::write_raw(const uint8_t* data, size_t size) {
    if (!handle_) {
        throw Error("Writer has been destroyed");
    }

    HddsError err = hdds_writer_write(handle_, data, size);
    if (err != HDDS_OK) {
        throw Error("Write failed with error: " + std::to_string(err));
    }
}

void DataWriter::write_raw(const std::vector<uint8_t>& data) {
    write_raw(data.data(), data.size());
}

std::string DataWriter::get_topic_name_ffi() const {
    if (!handle_) {
        throw Error("Writer has been destroyed");
    }

    char buf[256];
    size_t out_len = 0;
    HddsError err = hdds_writer_topic_name(handle_, buf, sizeof(buf), &out_len);
    if (err != HDDS_OK) {
        throw Error("Failed to get writer topic name");
    }
    return std::string(buf, out_len);
}

} // namespace hdds
