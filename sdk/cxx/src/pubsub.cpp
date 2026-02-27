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

std::unique_ptr<DataWriter> Publisher::create_writer_raw(const std::string& topic_name) {
    if (!handle_) {
        throw Error("Publisher has been destroyed");
    }

    HddsDataWriter* h = hdds_publisher_create_writer(handle_, topic_name.c_str());
    if (!h) {
        throw Error("Failed to create writer from publisher for topic: " + topic_name);
    }

    return std::unique_ptr<DataWriter>(new DataWriter(topic_name, h));
}

std::unique_ptr<DataWriter> Publisher::create_writer_raw(
    const std::string& topic_name, const QoS& qos) {
    if (!handle_) {
        throw Error("Publisher has been destroyed");
    }

    HddsDataWriter* h = hdds_publisher_create_writer_with_qos(
        handle_, topic_name.c_str(), qos.c_handle());
    if (!h) {
        throw Error("Failed to create writer from publisher for topic: " + topic_name);
    }

    return std::unique_ptr<DataWriter>(new DataWriter(topic_name, h));
}

// =============================================================================
// Subscriber -> DataReader
// =============================================================================

std::unique_ptr<DataReader> Subscriber::create_reader_raw(const std::string& topic_name) {
    if (!handle_) {
        throw Error("Subscriber has been destroyed");
    }

    HddsDataReader* h = hdds_subscriber_create_reader(handle_, topic_name.c_str());
    if (!h) {
        throw Error("Failed to create reader from subscriber for topic: " + topic_name);
    }

    return std::unique_ptr<DataReader>(new DataReader(topic_name, h));
}

std::unique_ptr<DataReader> Subscriber::create_reader_raw(
    const std::string& topic_name, const QoS& qos) {
    if (!handle_) {
        throw Error("Subscriber has been destroyed");
    }

    HddsDataReader* h = hdds_subscriber_create_reader_with_qos(
        handle_, topic_name.c_str(), qos.c_handle());
    if (!h) {
        throw Error("Failed to create reader from subscriber for topic: " + topic_name);
    }

    return std::unique_ptr<DataReader>(new DataReader(topic_name, h));
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

} // namespace hdds
