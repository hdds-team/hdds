// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file participant.cpp
 * @brief HDDS C++ Participant implementation
 */

#include <hdds.hpp>

#include <cstdlib>

extern "C" {
#include <hdds.h>
}

namespace hdds {

namespace {

// Suffix for the participant error when the domain came from HDDS_DOMAIN_ID
// and that variable does not parse. The C side returns NULL with no reason, so
// the wrapper names the variable itself. Mirrors the core rule: unset or empty
// is no domain, otherwise decimal digits naming 0..232. Empty when there is
// nothing to report (valid value, or unset: the failure has another cause).
std::string bad_domain_env_suffix() {
    const char* raw = std::getenv("HDDS_DOMAIN_ID");
    if (raw == nullptr || *raw == '\0') return std::string();
    bool valid = true;
    unsigned long value = 0;
    for (const char* p = raw; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') {
            valid = false;
            break;
        }
        value = value * 10 + static_cast<unsigned long>(*p - '0');
        if (value > 232) {
            valid = false;
            break;
        }
    }
    if (valid) return std::string();
    return std::string(": HDDS_DOMAIN_ID=") + raw +
           " is not a valid domain id (0..232)";
}

}  // namespace

std::string version() {
    const char* v = hdds_version();
    return v ? std::string(v) : std::string();
}

Participant::Participant(const std::string& name, std::optional<uint32_t> domain_id)
    : name_(name), domain_id_(0) {
    if (domain_id) {
        auto* cfg = hdds_config_create(name.c_str());
        if (!cfg) throw Error("Failed to create config: " + name);
        hdds_config_set_domain_id(cfg, *domain_id);
        hdds_config_set_transport_mode(cfg,
            static_cast<HddsTransportMode>(TransportMode::UdpMulticast));
        handle_ = hdds_config_build(cfg);
    } else {
        handle_ = hdds_participant_create(name.c_str());
    }
    if (!handle_) {
        // An explicit domain_id never reads HDDS_DOMAIN_ID, so only the
        // env-chosen path can be blamed on it.
        throw Error("Failed to create participant: " + name +
                    (domain_id ? std::string() : bad_domain_env_suffix()));
    }
    domain_id_ = hdds_participant_domain_id(handle_);
}

Participant::Participant(const std::string& name, TransportMode transport,
                         std::optional<uint32_t> domain_id)
    : name_(name), domain_id_(0) {
    if (domain_id) {
        auto* cfg = hdds_config_create(name.c_str());
        if (!cfg) throw Error("Failed to create config: " + name);
        hdds_config_set_domain_id(cfg, *domain_id);
        hdds_config_set_transport_mode(cfg,
            static_cast<HddsTransportMode>(transport));
        handle_ = hdds_config_build(cfg);
    } else {
        handle_ = hdds_participant_create_with_transport(
            name.c_str(), static_cast<HddsTransportMode>(transport));
    }
    if (!handle_) {
        throw Error("Failed to create participant: " + name +
                    (domain_id ? std::string() : bad_domain_env_suffix()));
    }
    domain_id_ = hdds_participant_domain_id(handle_);
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
    const std::string& topic_name,
    const char* type_name) {

    // Mirror create_reader_raw: always go through the same C entry point so
    // raw writers and raw readers agree on the type name for SEDP matching
    // regardless of which side is created first. A NULL type_name is a
    // genuinely raw endpoint: it announces the name the topic's readers
    // already announce, else the placeholder "RawBytes" (XTypes 1.3
    // Sec.7.6.3.4.2 Step 2). A typed endpoint passes its own name.
    HddsDataWriter* h = hdds_writer_create_with_type(
        handle_, topic_name.c_str(), type_name, nullptr);

    if (!h) {
        throw Error("Failed to create writer for topic: " + topic_name);
    }

    return std::unique_ptr<DataWriter>(new DataWriter(topic_name, h));
}

std::unique_ptr<DataWriter> Participant::create_writer_raw(
    const std::string& topic_name,
    const QoS& qos,
    const char* type_name) {

    HddsDataWriter* h = hdds_writer_create_with_type(
        handle_, topic_name.c_str(), type_name, qos.c_handle());

    if (!h) {
        throw Error("Failed to create writer for topic: " + topic_name);
    }

    return std::unique_ptr<DataWriter>(new DataWriter(topic_name, h));
}

std::unique_ptr<DataWriter> Participant::create_writer_raw(
    const std::string& topic_name,
    const QoS& qos,
    Extensibility extensibility,
    const char* type_name) {

    HddsDataWriter* h = hdds_writer_create_with_extensibility(
        handle_, topic_name.c_str(), type_name, qos.c_handle(),
        static_cast<uint32_t>(extensibility));

    if (!h) {
        throw Error("Failed to create writer for topic: " + topic_name);
    }

    return std::unique_ptr<DataWriter>(new DataWriter(topic_name, h));
}

std::unique_ptr<DataWriter> Participant::create_writer_raw(
    const std::string& topic_name,
    Extensibility extensibility,
    const char* type_name) {

    HddsDataWriter* h = hdds_writer_create_with_extensibility(
        handle_, topic_name.c_str(), type_name, nullptr,
        static_cast<uint32_t>(extensibility));

    if (!h) {
        throw Error("Failed to create writer for topic: " + topic_name);
    }

    return std::unique_ptr<DataWriter>(new DataWriter(topic_name, h));
}

std::unique_ptr<DataReader> Participant::create_reader_raw(
    const std::string& topic_name,
    const char* type_name) {

    // Route through hdds_reader_create_with_type so the SEDP announcement
    // carries the same type as raw writers do. A NULL type_name is a
    // genuinely raw endpoint: the name the topic's writers already announce,
    // else the placeholder "RawBytes". A typed endpoint passes its own name.
    HddsDataReader* h = hdds_reader_create_with_type(
        handle_, topic_name.c_str(), type_name, nullptr);

    if (!h) {
        throw Error("Failed to create reader for topic: " + topic_name);
    }

    return std::unique_ptr<DataReader>(new DataReader(topic_name, h));
}

std::unique_ptr<DataReader> Participant::create_reader_raw(
    const std::string& topic_name,
    const QoS& qos,
    const char* type_name) {

    // See the note above on create_reader_raw(topic_name).
    HddsDataReader* h = hdds_reader_create_with_type(
        handle_, topic_name.c_str(), type_name, qos.c_handle());

    if (!h) {
        throw Error("Failed to create reader for topic: " + topic_name);
    }

    return std::unique_ptr<DataReader>(new DataReader(topic_name, h));
}

HddsQoS* detail::qos_requesting_xcdr1(const QoS* qos) {
    HddsQoS* h = qos ? hdds_qos_clone(qos->c_handle()) : hdds_qos_default();
    if (!h) {
        throw Error("Failed to build the reader QoS");
    }
    if (!qos || qos->get_data_representation().empty()) {
        const int16_t both[2] = {HDDS_XCDR_DATA_REPRESENTATION,
                                 HDDS_XCDR2_DATA_REPRESENTATION};
        if (hdds_qos_set_data_representation(h, both, 2) != HDDS_OK) {
            hdds_qos_destroy(h);
            throw Error("Failed to request XCDR and XCDR2");
        }
    }
    return h;
}

std::unique_ptr<DataReader> Participant::create_reader_raw_decoding_xcdr1(
    const std::string& topic_name,
    const QoS* qos,
    const char* type_name) {
    HddsQoS* h = detail::qos_requesting_xcdr1(qos);
    // Same type-name rule as create_reader_raw.
    HddsDataReader* r = hdds_reader_create_with_type(
        handle_, topic_name.c_str(), type_name, h);
    hdds_qos_destroy(h);
    if (!r) {
        throw Error("Failed to create reader for topic: " + topic_name);
    }
    return std::unique_ptr<DataReader>(new DataReader(topic_name, r));
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

void Participant::assert_liveliness() {
    if (!handle_) {
        throw Error("Participant has been destroyed");
    }
    HddsError err = hdds_participant_assert_liveliness(handle_);
    if (err != HDDS_OK) {
        throw Error("assert_liveliness failed with error: " + std::to_string(err));
    }
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


std::unique_ptr<DataWriter> Participant::create_keyed_writer_raw(const std::string& topic_name, Extensibility extensibility, const char* type_name) {
    if (!handle_) throw Error("participant or publisher has been destroyed");
    auto h = hdds_writer_create_keyed(handle_, topic_name.c_str(), type_name, nullptr, static_cast<uint32_t>(extensibility));
    if (!h) throw Error("failed to create keyed writer");
    return std::unique_ptr<DataWriter>(new DataWriter(topic_name, h, true));
}

std::unique_ptr<DataWriter> Participant::create_keyed_writer_raw(const std::string& topic_name, const QoS& qos, Extensibility extensibility, const char* type_name) {
    if (!handle_) throw Error("participant or publisher has been destroyed");
    auto h = hdds_writer_create_keyed(handle_, topic_name.c_str(), type_name, qos.c_handle(), static_cast<uint32_t>(extensibility));
    if (!h) throw Error("failed to create keyed writer");
    return std::unique_ptr<DataWriter>(new DataWriter(topic_name, h, true));
}

} // namespace hdds
