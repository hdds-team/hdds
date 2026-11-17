// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file pubsub.cpp
 * @brief HDDS C++ Publisher/Subscriber implementation
 */

#include <hdds.hpp>

extern "C" {
#include <hdds.h>
}

namespace hdds {

// =============================================================================
// Publisher
// =============================================================================

Publisher::Publisher(HddsPublisher* handle) : handle_(handle) {}

Publisher::~Publisher() {
    if (handle_) {
        hdds_publisher_destroy(handle_);
        handle_ = nullptr;
    }
}

Publisher::Publisher(Publisher&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
}

Publisher& Publisher::operator=(Publisher&& other) noexcept {
    if (this != &other) {
        if (handle_) {
            hdds_publisher_destroy(handle_);
        }
        handle_ = other.handle_;
        other.handle_ = nullptr;
    }
    return *this;
}

bool Publisher::wait_for_acknowledgments(std::chrono::milliseconds timeout) {
    if (!handle_) throw Error("Publisher has been destroyed");
    if (timeout.count() < 0) throw Error("timeout must be nonnegative");
    auto err = hdds_publisher_wait_for_acknowledgments(handle_, static_cast<uint64_t>(timeout.count()));
    if (err == HDDS_TIMEOUT) return false;
    if (err != HDDS_OK) throw Error("wait_for_acknowledgments failed: " + std::to_string(err));
    return true;
}

// =============================================================================
// Subscriber
// =============================================================================

Subscriber::Subscriber(HddsSubscriber* handle) : handle_(handle) {}

Subscriber::~Subscriber() {
    if (handle_) {
        hdds_subscriber_destroy(handle_);
        handle_ = nullptr;
    }
}

Subscriber::Subscriber(Subscriber&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
}

Subscriber& Subscriber::operator=(Subscriber&& other) noexcept {
    if (this != &other) {
        if (handle_) {
            hdds_subscriber_destroy(handle_);
        }
        handle_ = other.handle_;
        other.handle_ = nullptr;
    }
    return *this;
}

// =============================================================================
// Publisher -> DataWriter
// =============================================================================

// A NULL type_name is a genuinely raw endpoint: it announces the name its
// topic's other endpoints already announce, else the placeholder "RawBytes"
// (XTypes 1.3 Sec.7.6.3.4.2 Step 2). A typed endpoint passes its own name,
// through the _with_type entry points.

std::unique_ptr<DataWriter> Publisher::create_writer_raw(
    const std::string& topic_name, const char* type_name) {
    if (!handle_) {
        throw Error("Publisher has been destroyed");
    }

    HddsDataWriter* h = type_name
        ? hdds_publisher_create_writer_with_type(
              handle_, topic_name.c_str(), type_name, nullptr, HDDS_EXTENSIBILITY_FINAL)
        : hdds_publisher_create_writer(handle_, topic_name.c_str());
    if (!h) {
        throw Error("Failed to create writer from publisher for topic: " + topic_name);
    }

    return std::unique_ptr<DataWriter>(new DataWriter(topic_name, h));
}

std::unique_ptr<DataWriter> Publisher::create_writer_raw(
    const std::string& topic_name, const QoS& qos, const char* type_name) {
    if (!handle_) {
        throw Error("Publisher has been destroyed");
    }

    HddsDataWriter* h = type_name
        ? hdds_publisher_create_writer_with_type(
              handle_, topic_name.c_str(), type_name, qos.c_handle(), HDDS_EXTENSIBILITY_FINAL)
        : hdds_publisher_create_writer_with_qos(handle_, topic_name.c_str(), qos.c_handle());
    if (!h) {
        throw Error("Failed to create writer from publisher for topic: " + topic_name);
    }

    return std::unique_ptr<DataWriter>(new DataWriter(topic_name, h));
}

std::unique_ptr<DataWriter> Publisher::create_writer_raw(
    const std::string& topic_name, const QoS& qos, Extensibility extensibility,
    const char* type_name) {
    if (!handle_) {
        throw Error("Publisher has been destroyed");
    }

    HddsDataWriter* h = hdds_publisher_create_writer_with_type(
        handle_, topic_name.c_str(), type_name, qos.c_handle(),
        static_cast<uint32_t>(extensibility));
    if (!h) {
        throw Error("Failed to create writer from publisher for topic: " + topic_name);
    }

    return std::unique_ptr<DataWriter>(new DataWriter(topic_name, h));
}

std::unique_ptr<DataWriter> Publisher::create_writer_raw(
    const std::string& topic_name, Extensibility extensibility, const char* type_name) {
    if (!handle_) {
        throw Error("Publisher has been destroyed");
    }

    HddsDataWriter* h = hdds_publisher_create_writer_with_type(
        handle_, topic_name.c_str(), type_name, nullptr,
        static_cast<uint32_t>(extensibility));
    if (!h) {
        throw Error("Failed to create writer from publisher for topic: " + topic_name);
    }

    return std::unique_ptr<DataWriter>(new DataWriter(topic_name, h));
}

// =============================================================================
// Subscriber -> DataReader
// =============================================================================

std::unique_ptr<DataReader> Subscriber::create_reader_raw(
    const std::string& topic_name, const char* type_name) {
    if (!handle_) {
        throw Error("Subscriber has been destroyed");
    }

    HddsDataReader* h = type_name
        ? hdds_subscriber_create_reader_with_type(
              handle_, topic_name.c_str(), type_name, nullptr)
        : hdds_subscriber_create_reader(handle_, topic_name.c_str());
    if (!h) {
        throw Error("Failed to create reader from subscriber for topic: " + topic_name);
    }

    return std::unique_ptr<DataReader>(new DataReader(topic_name, h));
}

std::unique_ptr<DataReader> Subscriber::create_reader_raw(
    const std::string& topic_name, const QoS& qos, const char* type_name) {
    if (!handle_) {
        throw Error("Subscriber has been destroyed");
    }

    HddsDataReader* h = type_name
        ? hdds_subscriber_create_reader_with_type(
              handle_, topic_name.c_str(), type_name, qos.c_handle())
        : hdds_subscriber_create_reader_with_qos(handle_, topic_name.c_str(), qos.c_handle());
    if (!h) {
        throw Error("Failed to create reader from subscriber for topic: " + topic_name);
    }

    return std::unique_ptr<DataReader>(new DataReader(topic_name, h));
}

std::unique_ptr<DataReader> Subscriber::create_reader_raw_decoding_xcdr1(
    const std::string& topic_name, const QoS* qos, const char* type_name) {
    if (!handle_) {
        throw Error("Subscriber has been destroyed");
    }

    HddsQoS* h = detail::qos_requesting_xcdr1(qos);
    HddsDataReader* r = hdds_subscriber_create_reader_with_type(
        handle_, topic_name.c_str(), type_name, h);
    hdds_qos_destroy(h);
    if (!r) {
        throw Error("Failed to create reader from subscriber for topic: " + topic_name);
    }

    return std::unique_ptr<DataReader>(new DataReader(topic_name, r));
}

void Subscriber::begin_access() {
    if (!handle_) {
        throw Error("Subscriber has been destroyed");
    }
    HddsError err = hdds_subscriber_begin_access(handle_);
    if (err != HDDS_OK) {
        throw Error("begin_access failed with error: " + std::to_string(err));
    }
}

void Subscriber::end_access() {
    if (!handle_) {
        throw Error("Subscriber has been destroyed");
    }
    HddsError err = hdds_subscriber_end_access(handle_);
    if (err == HDDS_INVALID_STATE) {
        throw Error("end_access without begin_access (PRECONDITION_NOT_MET)");
    }
    if (err != HDDS_OK) {
        throw Error("end_access failed with error: " + std::to_string(err));
    }
}

// =============================================================================
// Participant extensions
// =============================================================================

std::unique_ptr<Publisher> Participant::create_publisher() {
    if (!handle_) {
        throw Error("Participant has been destroyed");
    }

    HddsPublisher* pub = hdds_publisher_create(handle_);
    if (!pub) {
        throw Error("Failed to create publisher");
    }

    return std::unique_ptr<Publisher>(new Publisher(pub));
}

std::unique_ptr<Publisher> Participant::create_publisher(const QoS& qos) {
    if (!handle_) {
        throw Error("Participant has been destroyed");
    }

    HddsPublisher* pub = hdds_publisher_create_with_qos(handle_, qos.c_handle());
    if (!pub) {
        throw Error("Failed to create publisher");
    }

    return std::unique_ptr<Publisher>(new Publisher(pub));
}

std::unique_ptr<Subscriber> Participant::create_subscriber() {
    if (!handle_) {
        throw Error("Participant has been destroyed");
    }

    HddsSubscriber* sub = hdds_subscriber_create(handle_);
    if (!sub) {
        throw Error("Failed to create subscriber");
    }

    return std::unique_ptr<Subscriber>(new Subscriber(sub));
}

std::unique_ptr<Subscriber> Participant::create_subscriber(const QoS& qos) {
    if (!handle_) {
        throw Error("Participant has been destroyed");
    }

    HddsSubscriber* sub = hdds_subscriber_create_with_qos(handle_, qos.c_handle());
    if (!sub) {
        throw Error("Failed to create subscriber");
    }

    return std::unique_ptr<Subscriber>(new Subscriber(sub));
}

uint8_t Participant::participant_id() const {
    if (!handle_) {
        return 0xFF;
    }
    return hdds_participant_id(handle_);
}


std::unique_ptr<DataWriter> Publisher::create_keyed_writer_raw(const std::string& topic_name, Extensibility extensibility, const char* type_name) {
    if (!handle_) throw Error("participant or publisher has been destroyed");
    auto h = hdds_publisher_create_writer_keyed(handle_, topic_name.c_str(), type_name, nullptr, static_cast<uint32_t>(extensibility));
    if (!h) throw Error("failed to create keyed writer");
    return std::unique_ptr<DataWriter>(new DataWriter(topic_name, h, true));
}

std::unique_ptr<DataWriter> Publisher::create_keyed_writer_raw(const std::string& topic_name, const QoS& qos, Extensibility extensibility, const char* type_name) {
    if (!handle_) throw Error("participant or publisher has been destroyed");
    auto h = hdds_publisher_create_writer_keyed(handle_, topic_name.c_str(), type_name, qos.c_handle(), static_cast<uint32_t>(extensibility));
    if (!h) throw Error("failed to create keyed writer");
    return std::unique_ptr<DataWriter>(new DataWriter(topic_name, h, true));
}

} // namespace hdds
