// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file participant.cpp
 * @brief HDDS C++ Participant implementation
 */

#include <hdds.hpp>

extern "C" {
#include <hdds.h>
}

namespace hdds {

std::string version() {
    const char* v = hdds_version();
    return v ? std::string(v) : std::string();
}

Participant::Participant(const std::string& name, uint32_t domain_id)
    : name_(name), domain_id_(domain_id) {
    handle_ = hdds_participant_create(name.c_str());
    if (!handle_) {
        throw Error("Failed to create participant: " + name);
    }
}

Participant::Participant(const std::string& name, TransportMode transport, uint32_t domain_id)
    : name_(name), domain_id_(domain_id) {
    handle_ = hdds_participant_create_with_transport(
        name.c_str(), static_cast<HddsTransportMode>(transport));
    if (!handle_) {
        throw Error("Failed to create participant with transport: " + name);
    }
}

Participant::~Participant() {
    if (handle_) {
        hdds_participant_destroy(handle_);
        handle_ = nullptr;
    }
}

Participant::Participant(Participant&& other) noexcept
    : name_(std::move(other.name_)),
      domain_id_(other.domain_id_),
      handle_(other.handle_) {
    other.handle_ = nullptr;
}

Participant& Participant::operator=(Participant&& other) noexcept {
    if (this != &other) {
        if (handle_) {
            hdds_participant_destroy(handle_);
        }
        name_ = std::move(other.name_);
        domain_id_ = other.domain_id_;
        handle_ = other.handle_;
        other.handle_ = nullptr;
    }
    return *this;
}

std::unique_ptr<DataWriter> Participant::create_writer_raw(
    const std::string& topic_name) {

    HddsDataWriter* h = hdds_writer_create(handle_, topic_name.c_str());

    if (!h) {
        throw Error("Failed to create writer for topic: " + topic_name);
    }

    return std::unique_ptr<DataWriter>(new DataWriter(topic_name, h));
}

std::unique_ptr<DataWriter> Participant::create_writer_raw(
    const std::string& topic_name,
    const QoS& qos) {

    HddsDataWriter* h = hdds_writer_create_with_qos(
        handle_, topic_name.c_str(), qos.c_handle());

    if (!h) {
        throw Error("Failed to create writer for topic: " + topic_name);
    }

    return std::unique_ptr<DataWriter>(new DataWriter(topic_name, h));
}

std::unique_ptr<DataReader> Participant::create_reader_raw(
    const std::string& topic_name) {

    HddsDataReader* h = hdds_reader_create(handle_, topic_name.c_str());

    if (!h) {
        throw Error("Failed to create reader for topic: " + topic_name);
    }

    return std::unique_ptr<DataReader>(new DataReader(topic_name, h));
}

std::unique_ptr<DataReader> Participant::create_reader_raw(
    const std::string& topic_name,
    const QoS& qos) {

    HddsDataReader* h = hdds_reader_create_with_qos(
        handle_, topic_name.c_str(), qos.c_handle());

    if (!h) {
        throw Error("Failed to create reader for topic: " + topic_name);
    }

    return std::unique_ptr<DataReader>(new DataReader(topic_name, h));
}

std::string Participant::get_name() const {
    if (!handle_) {
        throw Error("Participant has been destroyed");
    }
    const char* name = hdds_participant_name(handle_);
    if (!name) {
        throw Error("Failed to get participant name");
    }
    return std::string(name);
}

uint32_t Participant::get_domain_id() const {
    if (!handle_) {
        return 0xFFFFFFFF;
    }
    return hdds_participant_domain_id(handle_);
}

HddsGuardCondition* Participant::graph_guard_condition() {
    if (!handle_) {
        throw Error("Participant has been destroyed");
    }
    const HddsGuardCondition* gc = hdds_participant_graph_guard_condition(handle_);
    if (!gc) {
        throw Error("Failed to get graph guard condition");
    }
    return const_cast<HddsGuardCondition*>(gc);
}

#ifdef HDDS_WITH_ROS2
const void* Participant::register_type_support(uint32_t distro, const void* type_support) {
    if (!handle_) {
        throw Error("Participant has been destroyed");
    }

    const HddsTypeObject* out_handle = nullptr;
    HddsError err = hdds_participant_register_type_support(
        handle_, distro,
        reinterpret_cast<const rosidl_message_type_support_t*>(type_support),
        &out_handle);

    if (err != HDDS_OK || !out_handle) {
        throw Error("Failed to register type support");
    }

    return out_handle;
}

void release_type_object(const void* handle) {
    if (handle) {
        hdds_type_object_release(reinterpret_cast<const HddsTypeObject*>(handle));
    }
}

bool get_type_object_hash(const void* handle, uint8_t* out_version,
                          uint8_t* out_value, size_t value_len) {
    if (!handle) {
        return false;
    }
    HddsError err = hdds_type_object_hash(
        reinterpret_cast<const HddsTypeObject*>(handle),
        out_version, out_value, value_len);
    return err == HDDS_OK;
}
#endif

} // namespace hdds
