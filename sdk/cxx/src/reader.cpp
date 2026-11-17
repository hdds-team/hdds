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
    std::lock_guard<std::mutex> guard(other.listener_mu_);
    listener_states_ = std::move(other.listener_states_);
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
        // The old reader is gone (its callbacks with it): its listener
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

    // A sample longer than the buffer is refused and stays in the reader: take
    // it again at the length the reader reported (a few attempts; a newer
    // sample may take its place meanwhile).
    HddsError err = HDDS_OK;
    for (int attempt = 0; attempt < 4; ++attempt) {
        err = hdds_reader_take(handle_, buffer.data(), buffer.size(), &actual_size);
        if (err != HDDS_OUT_OF_MEMORY) {
            break;
        }
        buffer.resize(actual_size);
    }

    if (err == HDDS_NOT_FOUND) {
        return std::nullopt;  // No data
    }
    if (err == HDDS_INVALID_STATE) {
        throw Error("Take outside an access bracket of a GROUP-scope Subscriber "
                    "(PRECONDITION_NOT_MET): see Subscriber::access()");
    }
    if (err != HDDS_OK) {
        throw Error("Take failed with error: " + std::to_string(err));
    }

    buffer.resize(actual_size);
    return buffer;
}

std::optional<DataReader::RawSample> DataReader::take_raw_sample() {
    if (!handle_) {
        throw Error("Reader has been destroyed");
    }

    constexpr size_t BUFFER_SIZE = 65536;
    RawSample sample;
    sample.data.resize(BUFFER_SIZE);
    size_t actual_size = 0;

    // Same retry as take_raw(): a sample longer than the buffer stays in the
    // reader and is taken again at the length the reader reported.
    HddsError err = HDDS_OK;
    for (int attempt = 0; attempt < 4; ++attempt) {
        err = hdds_reader_take_ex(handle_, sample.data.data(), sample.data.size(),
                                  &actual_size, &sample.encapsulation_id);
        if (err != HDDS_OUT_OF_MEMORY) {
            break;
        }
        sample.data.resize(actual_size);
    }

    if (err == HDDS_NOT_FOUND) {
        return std::nullopt;
    }
    if (err == HDDS_INVALID_STATE) {
        throw Error("Take outside an access bracket of a GROUP-scope Subscriber "
                    "(PRECONDITION_NOT_MET): see Subscriber::access()");
    }
    if (err != HDDS_OK) {
        throw Error("Take failed with error: " + std::to_string(err));
    }

    sample.data.resize(actual_size);
    return sample;
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

SubscriptionMatchedStatus DataReader::get_subscription_matched_status() {
    if (!handle_) throw Error("DataReader has been destroyed");
    HddsSubscriptionMatchedStatus status{};
    auto err = hdds_reader_get_subscription_matched_status(handle_, &status);
    if (err != HDDS_OK) throw Error("get_subscription_matched_status failed: " + std::to_string(err));
    return {status.TOTAL_COUNT, status.TOTAL_COUNT_CHANGE, status.CURRENT_COUNT, status.CURRENT_COUNT_CHANGE};
}

DeadlineMissedStatus DataReader::get_requested_deadline_missed_status() {
    if (!handle_) throw Error("DataReader has been destroyed");
    HddsDeadlineMissedStatus status{};
    auto err = hdds_reader_get_requested_deadline_missed_status(handle_, &status);
    if (err != HDDS_OK) throw Error("get_requested_deadline_missed_status failed: " + std::to_string(err));
    return {status.TOTAL_COUNT, status.TOTAL_COUNT_CHANGE};
}

IncompatibleQosStatus DataReader::get_requested_incompatible_qos_status() {
    if (!handle_) throw Error("DataReader has been destroyed");
    HddsIncompatibleQosStatus status{};
    auto err = hdds_reader_get_requested_incompatible_qos_status(handle_, &status);
    if (err != HDDS_OK) throw Error("get_requested_incompatible_qos_status failed: " + std::to_string(err));
    return {status.TOTAL_COUNT, status.TOTAL_COUNT_CHANGE, status.LAST_POLICY_ID};
}

LivelinessChangedStatus DataReader::get_liveliness_changed_status() {
    if (!handle_) throw Error("DataReader has been destroyed");
    HddsLivelinessChangedStatus status{};
    auto err = hdds_reader_get_liveliness_changed_status(handle_, &status);
    if (err != HDDS_OK) throw Error("get_liveliness_changed_status failed: " + std::to_string(err));
    return {status.ALIVE_COUNT, status.ALIVE_COUNT_CHANGE, status.NOT_ALIVE_COUNT, status.NOT_ALIVE_COUNT_CHANGE};
}

SampleLostStatus DataReader::get_sample_lost_status() {
    if (!handle_) throw Error("DataReader has been destroyed");
    HddsSampleLostStatus status{};
    auto err = hdds_reader_get_sample_lost_status(handle_, &status);
    if (err != HDDS_OK) throw Error("get_sample_lost_status failed: " + std::to_string(err));
    return {status.TOTAL_COUNT, status.TOTAL_COUNT_CHANGE};
}

SampleRejectedStatus DataReader::get_sample_rejected_status() {
    if (!handle_) throw Error("DataReader has been destroyed");
    HddsSampleRejectedStatus status{};
    auto err = hdds_reader_get_sample_rejected_status(handle_, &status);
    if (err != HDDS_OK) throw Error("get_sample_rejected_status failed: " + std::to_string(err));
    return {status.TOTAL_COUNT, status.TOTAL_COUNT_CHANGE, status.LAST_REASON};
}

} // namespace hdds
