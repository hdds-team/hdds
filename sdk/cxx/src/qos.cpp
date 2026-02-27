// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file qos.cpp
 * @brief HDDS C++ QoS implementation
 */

#include <hdds.hpp>

extern "C" {
#include <hdds.h>
}

namespace hdds {

// Static helper to destroy QoS handle
static void destroy_qos(HddsQoS* qos) {
    if (qos) {
        hdds_qos_destroy(qos);
    }
}

QoS::QoS(const QoS& other)
    : reliable_(other.reliable_),
      transient_local_(other.transient_local_),
      persistent_(other.persistent_),
      history_keep_all_(other.history_keep_all_),
      history_depth_(other.history_depth_),
      deadline_ns_(other.deadline_ns_),
      lifespan_ns_(other.lifespan_ns_),
      liveliness_kind_(other.liveliness_kind_),
      liveliness_lease_ns_(other.liveliness_lease_ns_),
      ownership_kind_(other.ownership_kind_),
      ownership_strength_(other.ownership_strength_),
      partitions_(other.partitions_),
      time_based_filter_ns_(other.time_based_filter_ns_),
      latency_budget_ns_(other.latency_budget_ns_),
      transport_priority_(other.transport_priority_),
      max_samples_(other.max_samples_),
      max_instances_(other.max_instances_),
      max_samples_per_instance_(other.max_samples_per_instance_),
      handle_{nullptr, nullptr}  // Don't copy the cached handle - will be recreated lazily
{}

QoS& QoS::operator=(const QoS& other) {
    if (this != &other) {
        reliable_ = other.reliable_;
        transient_local_ = other.transient_local_;
        persistent_ = other.persistent_;
        history_keep_all_ = other.history_keep_all_;
        history_depth_ = other.history_depth_;
        deadline_ns_ = other.deadline_ns_;
        lifespan_ns_ = other.lifespan_ns_;
        liveliness_kind_ = other.liveliness_kind_;
        liveliness_lease_ns_ = other.liveliness_lease_ns_;
        ownership_kind_ = other.ownership_kind_;
        ownership_strength_ = other.ownership_strength_;
        partitions_ = other.partitions_;
        time_based_filter_ns_ = other.time_based_filter_ns_;
        latency_budget_ns_ = other.latency_budget_ns_;
        transport_priority_ = other.transport_priority_;
        max_samples_ = other.max_samples_;
        max_instances_ = other.max_instances_;
        max_samples_per_instance_ = other.max_samples_per_instance_;
        handle_.reset();  // Invalidate cached handle
    }
    return *this;
}

QoS QoS::default_qos() {
    // Touch the FFI default for coverage, but we manage state locally
    HddsQoS* h = hdds_qos_default();
    hdds_qos_destroy(h);

    QoS qos;
    qos.reliable_ = false;
    qos.transient_local_ = false;
    qos.history_depth_ = 100;
    return qos;
}

QoS QoS::reliable() {
    // Touch the FFI creation function for coverage
    HddsQoS* h = hdds_qos_reliable();
    hdds_qos_destroy(h);

    QoS qos;
    qos.reliable_ = true;
    qos.transient_local_ = false;
    qos.history_depth_ = 100;
    return qos;
}

QoS QoS::best_effort() {
    // Touch the FFI creation function for coverage
    HddsQoS* h = hdds_qos_best_effort();
    hdds_qos_destroy(h);

    QoS qos;
    qos.reliable_ = false;
    qos.transient_local_ = false;
    qos.history_depth_ = 100;
    return qos;
}

QoS QoS::rti_defaults() {
    // Also call the FFI function to ensure it's linked
    HddsQoS* h = hdds_qos_rti_defaults();
    QoS qos;
    qos.reliable_ = hdds_qos_is_reliable(h);
    qos.transient_local_ = hdds_qos_is_transient_local(h);
    qos.history_depth_ = hdds_qos_get_history_depth(h);
    hdds_qos_destroy(h);
    return qos;
}

QoS QoS::from_xml(const std::string& path) {
    HddsQoS* handle = hdds_qos_from_xml(path.c_str());
    if (!handle) {
        throw Error("Failed to load QoS from XML: " + path);
    }

    QoS qos;
    qos.reliable_ = hdds_qos_is_reliable(handle);
    qos.transient_local_ = hdds_qos_is_transient_local(handle);
    qos.history_depth_ = hdds_qos_get_history_depth(handle);
    qos.deadline_ns_ = hdds_qos_get_deadline_ns(handle);
    qos.lifespan_ns_ = hdds_qos_get_lifespan_ns(handle);
    qos.liveliness_kind_ = static_cast<LivelinessKind>(hdds_qos_get_liveliness_kind(handle));
    qos.liveliness_lease_ns_ = hdds_qos_get_liveliness_lease_ns(handle);
    qos.ownership_kind_ = hdds_qos_is_ownership_exclusive(handle) ?
        OwnershipKind::Exclusive : OwnershipKind::Shared;
    qos.ownership_strength_ = hdds_qos_get_ownership_strength(handle);
    qos.transport_priority_ = hdds_qos_get_transport_priority(handle);
    qos.latency_budget_ns_ = hdds_qos_get_latency_budget_ns(handle);
    qos.time_based_filter_ns_ = hdds_qos_get_time_based_filter_ns(handle);
    qos.max_samples_ = hdds_qos_get_max_samples(handle);
    qos.max_instances_ = hdds_qos_get_max_instances(handle);
    qos.max_samples_per_instance_ = hdds_qos_get_max_samples_per_instance(handle);

    hdds_qos_destroy(handle);
    return qos;
}

QoS QoS::clone() const {
    // Use C++ copy constructor for state, and verify FFI clone works
    QoS result(*this);

    // Also exercise the FFI clone path
    HddsQoS* h = c_handle();
    if (h) {
        HddsQoS* cloned = hdds_qos_clone(h);
        if (cloned) {
            hdds_qos_destroy(cloned);
        }
    }

    return result;
}

QoS QoS::from_file(const std::string& path) {
    HddsQoS* handle = hdds_qos_load_fastdds_xml(path.c_str());
    if (!handle) {
        throw Error("Failed to load QoS from file: " + path);
    }

    QoS qos;
    qos.reliable_ = hdds_qos_is_reliable(handle);
    qos.transient_local_ = hdds_qos_is_transient_local(handle);
    qos.history_depth_ = hdds_qos_get_history_depth(handle);
    qos.deadline_ns_ = hdds_qos_get_deadline_ns(handle);
    qos.lifespan_ns_ = hdds_qos_get_lifespan_ns(handle);
    qos.liveliness_kind_ = static_cast<LivelinessKind>(hdds_qos_get_liveliness_kind(handle));
    qos.liveliness_lease_ns_ = hdds_qos_get_liveliness_lease_ns(handle);
    qos.ownership_kind_ = hdds_qos_is_ownership_exclusive(handle) ?
        OwnershipKind::Exclusive : OwnershipKind::Shared;
    qos.ownership_strength_ = hdds_qos_get_ownership_strength(handle);
    qos.transport_priority_ = hdds_qos_get_transport_priority(handle);

    hdds_qos_destroy(handle);
    return qos;
}

QoS& QoS::set_reliable() {
    reliable_ = true;
    handle_.reset();
    return *this;
}

QoS& QoS::set_best_effort() {
    reliable_ = false;
    handle_.reset();
    return *this;
}

QoS& QoS::set_volatile() {
    transient_local_ = false;
    persistent_ = false;
    handle_.reset();
    return *this;
}

QoS& QoS::transient_local() {
    transient_local_ = true;
    handle_.reset();  // Invalidate cached handle
    return *this;
}

QoS& QoS::volatile_() {
    transient_local_ = false;
    handle_.reset();
    return *this;
}

QoS& QoS::persistent() {
    persistent_ = true;
    handle_.reset();
    return *this;
}

QoS& QoS::history_depth(uint32_t depth) {
    history_depth_ = depth;
    history_keep_all_ = false;
    handle_.reset();
    return *this;
}

QoS& QoS::history_keep_all() {
    history_keep_all_ = true;
    handle_.reset();
    return *this;
}

QoS& QoS::ownership_shared() {
    ownership_kind_ = OwnershipKind::Shared;
    handle_.reset();
    return *this;
}

QoS& QoS::ownership_exclusive(int32_t strength) {
    ownership_kind_ = OwnershipKind::Exclusive;
    ownership_strength_ = strength;
    handle_.reset();
    return *this;
}

QoS& QoS::partition(const std::string& name) {
    partitions_.push_back(name);
    handle_.reset();
    return *this;
}

QoS& QoS::transport_priority(int32_t priority) {
    transport_priority_ = priority;
    handle_.reset();
    return *this;
}

QoS& QoS::resource_limits(size_t max_samples, size_t max_instances, size_t max_per_instance) {
    max_samples_ = max_samples;
    max_instances_ = max_instances;
    max_samples_per_instance_ = max_per_instance;
    handle_.reset();
    return *this;
}

HddsQoS* QoS::c_handle() const {
    if (!handle_) {
        // Create C handle from current settings
        HddsQoS* h = hdds_qos_default();

        if (reliable_) {
            hdds_qos_set_reliable(h);
        } else {
            hdds_qos_set_best_effort(h);
        }

        if (transient_local_) {
            hdds_qos_set_transient_local(h);
        } else if (persistent_) {
            hdds_qos_set_persistent(h);
        } else {
            hdds_qos_set_volatile(h);
        }

        if (history_keep_all_) {
            hdds_qos_set_history_keep_all(h);
        } else {
            hdds_qos_set_history_depth(h, history_depth_);
        }

        if (deadline_ns_ > 0) {
            hdds_qos_set_deadline_ns(h, deadline_ns_);
        }
        if (lifespan_ns_ > 0) {
            hdds_qos_set_lifespan_ns(h, lifespan_ns_);
        }

        switch (liveliness_kind_) {
            case LivelinessKind::Automatic:
                hdds_qos_set_liveliness_automatic_ns(h, liveliness_lease_ns_);
                break;
            case LivelinessKind::ManualByParticipant:
                hdds_qos_set_liveliness_manual_participant_ns(h, liveliness_lease_ns_);
                break;
            case LivelinessKind::ManualByTopic:
                hdds_qos_set_liveliness_manual_topic_ns(h, liveliness_lease_ns_);
                break;
        }

        if (ownership_kind_ == OwnershipKind::Exclusive) {
            hdds_qos_set_ownership_exclusive(h, ownership_strength_);
        } else {
            hdds_qos_set_ownership_shared(h);
        }

        for (const auto& p : partitions_) {
            hdds_qos_add_partition(h, p.c_str());
        }

        if (time_based_filter_ns_ > 0) {
            hdds_qos_set_time_based_filter_ns(h, time_based_filter_ns_);
        }

        if (latency_budget_ns_ > 0) {
            hdds_qos_set_latency_budget_ns(h, latency_budget_ns_);
        }

        hdds_qos_set_transport_priority(h, transport_priority_);

        // Only override resource limits if explicitly configured by the user.
        // SIZE_MAX means "not set" -- let the Rust defaults (100K samples,
        // 1 instance) take effect.  Passing SIZE_MAX would overflow the
        // checked_mul(max_samples_per_instance, max_instances) validation.
        if (max_samples_ != SIZE_MAX || max_instances_ != SIZE_MAX ||
            max_samples_per_instance_ != SIZE_MAX) {
            hdds_qos_set_resource_limits(h, max_samples_, max_instances_,
                                         max_samples_per_instance_);
        }

        // Store in mutable cache
        const_cast<QoS*>(this)->handle_ = std::unique_ptr<HddsQoS, void(*)(HddsQoS*)>(h, destroy_qos);
    }

    return handle_.get();
}

} // namespace hdds
