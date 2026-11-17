// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file writer.cpp
 * @brief HDDS C++ DataWriter implementation
 */

#include <hdds.hpp>
#include <algorithm>

extern "C" {
#include <hdds.h>
}

namespace hdds {

InstanceHandle DataWriter::keyed_operation(const uint8_t* data, size_t size,
                                           const detail::SerializedKey& identity,
                                           unsigned operation, uint64_t timestamp) {
    if (!handle_) throw Error("writer has been destroyed");
    HddsSerializedKey key{};
    std::copy(identity.hash.begin(), identity.hash.end(), key.HASH);
    std::copy(identity.protected_hash.begin(), identity.protected_hash.end(), key.PROTECTED_HASH);
    key.PAYLOAD = identity.payload.data();
    key.PAYLOAD_LEN = identity.payload.size();
    key.REPRESENTATION = 2;
    HddsInstanceHandle handle{};
    HddsError error;
    switch (operation) {
    case 0: error = hdds_writer_write_keyed(handle_, data, size, &key); break;
    case 1: error = hdds_writer_write_w_timestamp_keyed(handle_, data, size, &key, timestamp); break;
    case 2: error = hdds_writer_dispose_keyed(handle_, data, size, &key); break;
    case 3: error = hdds_writer_dispose_w_timestamp_keyed(handle_, data, size, &key, timestamp); break;
    case 4: error = hdds_writer_unregister_instance_keyed(handle_, data, size, &key); break;
    case 5: error = hdds_writer_unregister_instance_w_timestamp_keyed(handle_, data, size, &key, timestamp); break;
    case 6: error = hdds_writer_register_instance_keyed(handle_, data, size, &key, &handle); break;
    case 7: error = hdds_writer_register_instance_w_timestamp_keyed(handle_, data, size, &key, timestamp, &handle); break;
    default: throw Error("unknown writer operation");
    }
    if (error != HDDS_OK) throw Error("keyed writer operation failed: " + std::to_string(error));
    InstanceHandle result{};
    std::copy(std::begin(handle.VALUE), std::end(handle.VALUE), result.begin());
    return result;
}

DataWriter::DataWriter(const std::string& topic, HddsDataWriter* handle, bool keyed)
    : topic_name_(topic), handle_(handle), keyed_(keyed) {}

DataWriter::~DataWriter() {
    if (cached_status_condition_) {
        hdds_status_condition_release(cached_status_condition_);
        cached_status_condition_ = nullptr;
    }
    if (handle_) {
        hdds_writer_destroy(handle_);
        handle_ = nullptr;
    }
}

DataWriter::DataWriter(DataWriter&& other) noexcept
    : topic_name_(std::move(other.topic_name_)),
      handle_(other.handle_),
      keyed_(other.keyed_),
      key_from_bytes_(std::move(other.key_from_bytes_)),
      cached_status_condition_(other.cached_status_condition_) {
    std::lock_guard<std::mutex> guard(other.listener_mu_);
    listener_states_ = std::move(other.listener_states_);
    other.handle_ = nullptr;
    other.cached_status_condition_ = nullptr;
}

DataWriter& DataWriter::operator=(DataWriter&& other) noexcept {
    if (this != &other) {
        if (cached_status_condition_) {
            hdds_status_condition_release(cached_status_condition_);
        }
        if (handle_) {
            hdds_writer_destroy(handle_);
        }
        // The old writer is gone (its callbacks with it): its listener
        // states can go now.
        {
            std::vector<std::shared_ptr<void>> moved;
            {
                std::lock_guard<std::mutex> guard(other.listener_mu_);
                moved = std::move(other.listener_states_);
            }
            std::lock_guard<std::mutex> guard(listener_mu_);
            listener_states_ = std::move(moved);
        }
        topic_name_ = std::move(other.topic_name_);
        handle_ = other.handle_;
        keyed_ = other.keyed_;
        key_from_bytes_ = std::move(other.key_from_bytes_);
        cached_status_condition_ = other.cached_status_condition_;
        other.handle_ = nullptr;
        other.cached_status_condition_ = nullptr;
    }
    return *this;
}

void DataWriter::write_raw(const uint8_t* data, size_t size) {
    if (!handle_) {
        throw Error("Writer has been destroyed");
    }

    if (keyed_ && !key_from_bytes_) throw Error("raw keyed operations require a decoding codec");
    if (key_from_bytes_) { keyed_operation(data, size, key_from_bytes_(data, size), 0); return; }
    HddsError err = hdds_writer_write(handle_, data, size);
    if (err != HDDS_OK) {
        throw Error("Write failed with error: " + std::to_string(err));
    }
}

void DataWriter::write_raw(const std::vector<uint8_t>& data) {
    write_raw(data.data(), data.size());
}

void DataWriter::assert_liveliness() {
    if (!handle_) {
        throw Error("Writer has been destroyed");
    }

    HddsError err = hdds_writer_assert_liveliness(handle_);
    if (err != HDDS_OK) {
        throw Error("assert_liveliness failed with error: " + std::to_string(err));
    }
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

HddsStatusCondition* DataWriter::get_status_condition() {
    if (!handle_) {
        throw Error("Writer has been destroyed");
    }

    // Release previous handle if we already acquired one
    if (cached_status_condition_) {
        hdds_status_condition_release(cached_status_condition_);
    }

    // Acquire new handle (refcounted in FFI layer)
    cached_status_condition_ = const_cast<HddsStatusCondition*>(
        hdds_writer_get_status_condition(handle_));
    return cached_status_condition_;
}

PublicationMatchedStatus DataWriter::get_publication_matched_status() {
    if (!handle_) throw Error("DataWriter has been destroyed");
    HddsPublicationMatchedStatus status{};
    auto err = hdds_writer_get_publication_matched_status(handle_, &status);
    if (err != HDDS_OK) throw Error("get_publication_matched_status failed: " + std::to_string(err));
    return {status.TOTAL_COUNT, status.TOTAL_COUNT_CHANGE, status.CURRENT_COUNT, status.CURRENT_COUNT_CHANGE};
}

DeadlineMissedStatus DataWriter::get_offered_deadline_missed_status() {
    if (!handle_) throw Error("DataWriter has been destroyed");
    HddsDeadlineMissedStatus status{};
    auto err = hdds_writer_get_offered_deadline_missed_status(handle_, &status);
    if (err != HDDS_OK) throw Error("get_offered_deadline_missed_status failed: " + std::to_string(err));
    return {status.TOTAL_COUNT, status.TOTAL_COUNT_CHANGE};
}

IncompatibleQosStatus DataWriter::get_offered_incompatible_qos_status() {
    if (!handle_) throw Error("DataWriter has been destroyed");
    HddsIncompatibleQosStatus status{};
    auto err = hdds_writer_get_offered_incompatible_qos_status(handle_, &status);
    if (err != HDDS_OK) throw Error("get_offered_incompatible_qos_status failed: " + std::to_string(err));
    return {status.TOTAL_COUNT, status.TOTAL_COUNT_CHANGE, status.LAST_POLICY_ID};
}

LivelinessLostStatus DataWriter::get_liveliness_lost_status() {
    if (!handle_) throw Error("DataWriter has been destroyed");
    HddsLivelinessLostStatus status{};
    auto err = hdds_writer_get_liveliness_lost_status(handle_, &status);
    if (err != HDDS_OK) throw Error("get_liveliness_lost_status failed: " + std::to_string(err));
    return {status.TOTAL_COUNT, status.TOTAL_COUNT_CHANGE};
}

void DataWriter::write_w_timestamp(const uint8_t* data, size_t size, uint64_t source_timestamp_ns) {
    if (!handle_) throw Error("Writer has been destroyed");
    if (keyed_ && !key_from_bytes_) throw Error("raw keyed operations require a decoding codec");
    if (key_from_bytes_) { keyed_operation(data, size, key_from_bytes_(data, size), 1, source_timestamp_ns); return; }
    auto err = hdds_writer_write_w_timestamp(handle_, data, size, source_timestamp_ns);
    if (err != HDDS_OK) throw Error("write_w_timestamp failed: " + std::to_string(err));
}

void DataWriter::dispose(const uint8_t* data, size_t size) {
    if (!handle_) throw Error("Writer has been destroyed");
    if (keyed_ && !key_from_bytes_) throw Error("raw keyed operations require a decoding codec");
    if (key_from_bytes_) { keyed_operation(data, size, key_from_bytes_(data, size), 2); return; }
    auto err = hdds_writer_dispose(handle_, data, size);
    if (err != HDDS_OK) throw Error("dispose failed: " + std::to_string(err));
}

void DataWriter::dispose_w_timestamp(const uint8_t* data, size_t size, uint64_t source_timestamp_ns) {
    if (!handle_) throw Error("Writer has been destroyed");
    if (keyed_ && !key_from_bytes_) throw Error("raw keyed operations require a decoding codec");
    if (key_from_bytes_) { keyed_operation(data, size, key_from_bytes_(data, size), 3, source_timestamp_ns); return; }
    auto err = hdds_writer_dispose_w_timestamp(handle_, data, size, source_timestamp_ns);
    if (err != HDDS_OK) throw Error("dispose_w_timestamp failed: " + std::to_string(err));
}

void DataWriter::unregister_instance(const uint8_t* data, size_t size) {
    if (!handle_) throw Error("Writer has been destroyed");
    if (keyed_ && !key_from_bytes_) throw Error("raw keyed operations require a decoding codec");
    if (key_from_bytes_) { keyed_operation(data, size, key_from_bytes_(data, size), 4); return; }
    auto err = hdds_writer_unregister_instance(handle_, data, size);
    if (err != HDDS_OK) throw Error("unregister_instance failed: " + std::to_string(err));
}

void DataWriter::unregister_instance_w_timestamp(const uint8_t* data, size_t size, uint64_t source_timestamp_ns) {
    if (!handle_) throw Error("Writer has been destroyed");
    if (keyed_ && !key_from_bytes_) throw Error("raw keyed operations require a decoding codec");
    if (key_from_bytes_) { keyed_operation(data, size, key_from_bytes_(data, size), 5, source_timestamp_ns); return; }
    auto err = hdds_writer_unregister_instance_w_timestamp(handle_, data, size, source_timestamp_ns);
    if (err != HDDS_OK) throw Error("unregister_instance_w_timestamp failed: " + std::to_string(err));
}

InstanceHandle DataWriter::register_instance(const uint8_t* data, size_t size) {
    if (!handle_) throw Error("Writer has been destroyed");
    HddsInstanceHandle handle{};
    if (keyed_ && !key_from_bytes_) throw Error("raw keyed operations require a decoding codec");
    if (key_from_bytes_) return keyed_operation(data, size, key_from_bytes_(data, size), 6);
    auto err = hdds_writer_register_instance(handle_, data, size, &handle);
    if (err != HDDS_OK) throw Error("register_instance failed: " + std::to_string(err));
    InstanceHandle result{};
    std::copy(std::begin(handle.VALUE), std::end(handle.VALUE), result.begin());
    return result;
}

InstanceHandle DataWriter::register_instance_w_timestamp(const uint8_t* data, size_t size, uint64_t source_timestamp_ns) {
    if (!handle_) throw Error("Writer has been destroyed");
    HddsInstanceHandle handle{};
    if (keyed_ && !key_from_bytes_) throw Error("raw keyed operations require a decoding codec");
    if (key_from_bytes_) return keyed_operation(data, size, key_from_bytes_(data, size), 7, source_timestamp_ns);
    auto err = hdds_writer_register_instance_w_timestamp(handle_, data, size, source_timestamp_ns, &handle);
    if (err != HDDS_OK) throw Error("register_instance_w_timestamp failed: " + std::to_string(err));
    InstanceHandle result{};
    std::copy(std::begin(handle.VALUE), std::end(handle.VALUE), result.begin());
    return result;
}

bool DataWriter::wait_for_acknowledgments(std::chrono::milliseconds timeout) {
    if (!handle_) throw Error("Writer has been destroyed");
    if (timeout.count() < 0) throw Error("timeout must be nonnegative");
    auto err = hdds_writer_wait_for_acknowledgments(handle_, static_cast<uint64_t>(timeout.count()));
    if (err == HDDS_TIMEOUT) return false;
    if (err != HDDS_OK) throw Error("wait_for_acknowledgments failed: " + std::to_string(err));
    return true;
}

} // namespace hdds
