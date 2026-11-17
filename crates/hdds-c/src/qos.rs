// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! QoS C FFI bindings for HDDS.
//!
//! Provides C-compatible functions to create, configure, and load QoS profiles.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;

use hdds::api::QoS;

use crate::HddsError;

/// Opaque handle to a QoS profile.
pub struct HddsQoS {
    _private: [u8; 0],
}

// =============================================================================
// QoS Creation
// =============================================================================

/// Create a default QoS profile (best-effort, volatile).
///
/// # Safety
/// The returned pointer must be freed with `hdds_qos_destroy`.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_default() -> *mut HddsQoS {
    let qos = Box::new(QoS::default());
    Box::into_raw(qos).cast::<HddsQoS>()
}

/// Create a best-effort QoS profile.
///
/// Best-effort QoS does not guarantee delivery but has lower overhead.
///
/// # Safety
/// The returned pointer must be freed with `hdds_qos_destroy`.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_best_effort() -> *mut HddsQoS {
    let qos = Box::new(QoS::best_effort());
    Box::into_raw(qos).cast::<HddsQoS>()
}

/// Create a reliable QoS profile.
///
/// Reliable QoS guarantees delivery with NACK-driven retransmission.
///
/// # Safety
/// The returned pointer must be freed with `hdds_qos_destroy`.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_reliable() -> *mut HddsQoS {
    let qos = Box::new(QoS::reliable());
    Box::into_raw(qos).cast::<HddsQoS>()
}

/// Create the interoperability QoS preset.
///
/// Sets RELIABLE, VOLATILE, KEEP_LAST(10); every other policy is at its
/// default (same as `hdds_qos_reliable` with a history depth of 10).
///
/// The name is kept for ABI stability; the values are an HDDS preset, not
/// any vendor's defaults.
///
/// # Safety
/// The returned pointer must be freed with `hdds_qos_destroy`.
#[no_mangle]
#[allow(deprecated)] // `QoS::rti_defaults`: this symbol is the C ABI's name for it
pub unsafe extern "C" fn hdds_qos_rti_defaults() -> *mut HddsQoS {
    let qos = Box::new(QoS::rti_defaults());
    Box::into_raw(qos).cast::<HddsQoS>()
}

/// Destroy a QoS profile.
///
/// # Safety
/// - `qos` must be a valid pointer returned from a `hdds_qos_*` creation function.
/// - Must not be called more than once with the same pointer.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_destroy(qos: *mut HddsQoS) {
    if !qos.is_null() {
        let _ = Box::from_raw(qos.cast::<QoS>());
    }
}

// =============================================================================
// QoS Loading from XML
// =============================================================================

/// Load QoS from a FastDDS XML profile file.
///
/// Parses the XML file and extracts the default profile's QoS settings.
/// Supports all 22 DDS QoS policies.
///
/// # Arguments
/// - `path`: Path to the FastDDS XML profile file (null-terminated C string).
///
/// # Returns
/// - Valid pointer on success.
/// - NULL if the file cannot be read or parsed.
///
/// # Safety
/// - `path` must be a valid null-terminated C string.
/// - The returned pointer must be freed with `hdds_qos_destroy`.
#[cfg(feature = "qos-loaders")]
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_load_fastdds_xml(path: *const c_char) -> *mut HddsQoS {
    if path.is_null() {
        return ptr::null_mut();
    }

    let Ok(path_str) = CStr::from_ptr(path).to_str() else {
        return ptr::null_mut();
    };

    match QoS::load_fastdds(path_str) {
        Ok(qos) => Box::into_raw(Box::new(qos)).cast::<HddsQoS>(),
        Err(err) => {
            eprintln!("[hdds_c] Failed to load FastDDS XML: {}", err);
            ptr::null_mut()
        }
    }
}

/// Load QoS from a vendor XML file (auto-detect vendor).
///
/// Automatically detects the vendor format and parses accordingly.
/// Currently supports: FastDDS (eProsima).
///
/// # Arguments
/// - `path`: Path to the XML profile file (null-terminated C string).
///
/// # Returns
/// - Valid pointer on success.
/// - NULL if the file cannot be read or parsed.
///
/// # Safety
/// - `path` must be a valid null-terminated C string.
/// - The returned pointer must be freed with `hdds_qos_destroy`.
#[cfg(feature = "qos-loaders")]
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_from_xml(path: *const c_char) -> *mut HddsQoS {
    if path.is_null() {
        return ptr::null_mut();
    }

    let Ok(path_str) = CStr::from_ptr(path).to_str() else {
        return ptr::null_mut();
    };

    match QoS::from_xml(path_str) {
        Ok(qos) => Box::into_raw(Box::new(qos)).cast::<HddsQoS>(),
        Err(err) => {
            eprintln!("[hdds_c] Failed to load QoS from XML: {}", err);
            ptr::null_mut()
        }
    }
}

// =============================================================================
// QoS Builder Methods (Fluent API via mutation)
// =============================================================================

/// Set history depth (KEEP_LAST) on a QoS profile.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_history_depth(qos: *mut HddsQoS, depth: u32) -> HddsError {
    if qos.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.history = hdds::dds::qos::History::KeepLast(depth);
    HddsError::HddsOk
}

/// Set history policy to KEEP_ALL.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_history_keep_all(qos: *mut HddsQoS) -> HddsError {
    if qos.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.history = hdds::dds::qos::History::KeepAll;
    HddsError::HddsOk
}

/// Set durability to VOLATILE.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_volatile(qos: *mut HddsQoS) -> HddsError {
    if qos.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.durability = hdds::dds::qos::Durability::Volatile;
    HddsError::HddsOk
}

/// Set durability to TRANSIENT_LOCAL.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_transient_local(qos: *mut HddsQoS) -> HddsError {
    if qos.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.durability = hdds::dds::qos::Durability::TransientLocal;
    HddsError::HddsOk
}

/// Set durability to PERSISTENT.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_persistent(qos: *mut HddsQoS) -> HddsError {
    if qos.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.durability = hdds::dds::qos::Durability::Persistent;
    HddsError::HddsOk
}

/// Set reliability to RELIABLE.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_reliable(qos: *mut HddsQoS) -> HddsError {
    if qos.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.reliability = hdds::dds::qos::Reliability::Reliable;
    HddsError::HddsOk
}

/// Set reliability to BEST_EFFORT.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_best_effort(qos: *mut HddsQoS) -> HddsError {
    if qos.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.reliability = hdds::dds::qos::Reliability::BestEffort;
    HddsError::HddsOk
}

/// Set deadline period in nanoseconds.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_deadline_ns(qos: *mut HddsQoS, period_ns: u64) -> HddsError {
    if qos.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.deadline = hdds::dds::qos::Deadline::new(std::time::Duration::from_nanos(period_ns));
    HddsError::HddsOk
}

/// Set lifespan duration in nanoseconds.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_lifespan_ns(
    qos: *mut HddsQoS,
    duration_ns: u64,
) -> HddsError {
    if qos.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.lifespan = hdds::dds::qos::Lifespan::new(std::time::Duration::from_nanos(duration_ns));
    HddsError::HddsOk
}

/// Set RELIABILITY `max_blocking_time` in nanoseconds (DDS v1.4 Sec.2.2.3.14):
/// how long a RELIABLE writer's `write()` may block for room before it
/// returns TIMEOUT. Default 100 ms; ignored by BEST_EFFORT writers.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_max_blocking_time_ns(
    qos: *mut HddsQoS,
    duration_ns: u64,
) -> HddsError {
    if qos.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.reliability_max_blocking_time = std::time::Duration::from_nanos(duration_ns);
    HddsError::HddsOk
}

/// Set ownership to SHARED.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_ownership_shared(qos: *mut HddsQoS) -> HddsError {
    if qos.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.ownership = hdds::dds::qos::Ownership::shared();
    HddsError::HddsOk
}

/// Set ownership to EXCLUSIVE with given strength.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_ownership_exclusive(
    qos: *mut HddsQoS,
    strength: i32,
) -> HddsError {
    if qos.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.ownership = hdds::dds::qos::Ownership::exclusive();
    qos_ref.ownership_strength = hdds::dds::qos::OwnershipStrength::new(strength);
    HddsError::HddsOk
}

/// Add a partition name to the QoS.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
/// - `partition` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_add_partition(
    qos: *mut HddsQoS,
    partition: *const c_char,
) -> HddsError {
    if qos.is_null() || partition.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let Ok(part_str) = CStr::from_ptr(partition).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let qos_ref = &mut *qos.cast::<QoS>();

    // Add new partition using the add() method
    qos_ref.partition.add(part_str);

    HddsError::HddsOk
}

// =============================================================================
// QoS Getters (for inspection/debugging)
// =============================================================================

/// Check if QoS is reliable.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_is_reliable(qos: *const HddsQoS) -> bool {
    if qos.is_null() {
        return false;
    }

    let qos_ref = &*qos.cast::<QoS>();
    matches!(qos_ref.reliability, hdds::dds::qos::Reliability::Reliable)
}

/// Check if QoS is transient-local.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_is_transient_local(qos: *const HddsQoS) -> bool {
    if qos.is_null() {
        return false;
    }

    let qos_ref = &*qos.cast::<QoS>();
    matches!(
        qos_ref.durability,
        hdds::dds::qos::Durability::TransientLocal
    )
}

/// Get history depth.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_get_history_depth(qos: *const HddsQoS) -> u32 {
    if qos.is_null() {
        return 0;
    }

    let qos_ref = &*qos.cast::<QoS>();
    match qos_ref.history {
        hdds::dds::qos::History::KeepLast(depth) => depth,
        hdds::dds::qos::History::KeepAll => 0,
    }
}

/// Get deadline period in nanoseconds.
///
/// Returns `u64::MAX` if infinite.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_get_deadline_ns(qos: *const HddsQoS) -> u64 {
    if qos.is_null() {
        return u64::MAX;
    }

    let qos_ref = &*qos.cast::<QoS>();
    qos_ref.deadline.period.as_nanos() as u64
}

/// Get lifespan duration in nanoseconds.
///
/// Returns `u64::MAX` if infinite.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_get_lifespan_ns(qos: *const HddsQoS) -> u64 {
    if qos.is_null() {
        return u64::MAX;
    }

    let qos_ref = &*qos.cast::<QoS>();
    qos_ref.lifespan.duration.as_nanos() as u64
}

/// Get RELIABILITY `max_blocking_time` in nanoseconds (DDS v1.4
/// Sec.2.2.3.14). Default 100 ms (100_000_000); `u64::MAX` if set to
/// infinite.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_get_max_blocking_time_ns(qos: *const HddsQoS) -> u64 {
    if qos.is_null() {
        return u64::MAX;
    }

    let qos_ref = &*qos.cast::<QoS>();
    qos_ref.reliability_max_blocking_time.as_nanos() as u64
}

/// Check if ownership is exclusive.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_is_ownership_exclusive(qos: *const HddsQoS) -> bool {
    if qos.is_null() {
        return false;
    }

    let qos_ref = &*qos.cast::<QoS>();
    matches!(
        qos_ref.ownership.kind,
        hdds::dds::qos::OwnershipKind::Exclusive
    )
}

/// Get ownership strength value.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_get_ownership_strength(qos: *const HddsQoS) -> i32 {
    if qos.is_null() {
        return 0;
    }

    let qos_ref = &*qos.cast::<QoS>();
    qos_ref.ownership_strength.value
}

/// Liveliness kind enumeration for C FFI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)] // C FFI: prefix required (no namespaces in C)
pub enum HddsLivelinessKind {
    /// DDS infrastructure automatically asserts liveliness.
    HddsLivelinessAutomatic = 0,
    /// Application must assert per participant.
    HddsLivelinessManualByParticipant = 1,
    /// Application must assert per writer/topic.
    HddsLivelinessManualByTopic = 2,
}

/// Get liveliness kind.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_get_liveliness_kind(qos: *const HddsQoS) -> HddsLivelinessKind {
    if qos.is_null() {
        return HddsLivelinessKind::HddsLivelinessAutomatic;
    }

    let qos_ref = &*qos.cast::<QoS>();
    match qos_ref.liveliness.kind {
        hdds::dds::qos::LivelinessKind::Automatic => HddsLivelinessKind::HddsLivelinessAutomatic,
        hdds::dds::qos::LivelinessKind::ManualByParticipant => {
            HddsLivelinessKind::HddsLivelinessManualByParticipant
        }
        hdds::dds::qos::LivelinessKind::ManualByTopic => {
            HddsLivelinessKind::HddsLivelinessManualByTopic
        }
    }
}

/// Get liveliness lease duration in nanoseconds.
///
/// Returns `u64::MAX` if infinite.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_get_liveliness_lease_ns(qos: *const HddsQoS) -> u64 {
    if qos.is_null() {
        return u64::MAX;
    }

    let qos_ref = &*qos.cast::<QoS>();
    qos_ref.liveliness.lease_duration.as_nanos() as u64
}

/// Get time-based filter minimum separation in nanoseconds.
///
/// Returns 0 if no filtering (all samples delivered).
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_get_time_based_filter_ns(qos: *const HddsQoS) -> u64 {
    if qos.is_null() {
        return 0;
    }

    let qos_ref = &*qos.cast::<QoS>();
    qos_ref.time_based_filter.minimum_separation.as_nanos() as u64
}

/// Get latency budget in nanoseconds.
///
/// Returns 0 if no latency budget (best effort delivery).
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_get_latency_budget_ns(qos: *const HddsQoS) -> u64 {
    if qos.is_null() {
        return 0;
    }

    let qos_ref = &*qos.cast::<QoS>();
    qos_ref.latency_budget.duration.as_nanos() as u64
}

/// Get transport priority.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_get_transport_priority(qos: *const HddsQoS) -> i32 {
    if qos.is_null() {
        return 0;
    }

    let qos_ref = &*qos.cast::<QoS>();
    qos_ref.transport_priority.value
}

/// Get max samples resource limit.
///
/// Returns `usize::MAX` for unlimited.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_get_max_samples(qos: *const HddsQoS) -> usize {
    if qos.is_null() {
        return usize::MAX;
    }

    let qos_ref = &*qos.cast::<QoS>();
    qos_ref.resource_limits.max_samples
}

/// Get max instances resource limit.
///
/// Returns `usize::MAX` for unlimited.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_get_max_instances(qos: *const HddsQoS) -> usize {
    if qos.is_null() {
        return usize::MAX;
    }

    let qos_ref = &*qos.cast::<QoS>();
    qos_ref.resource_limits.max_instances
}

/// Get max samples per instance resource limit.
///
/// Returns `usize::MAX` for unlimited.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_get_max_samples_per_instance(qos: *const HddsQoS) -> usize {
    if qos.is_null() {
        return usize::MAX;
    }

    let qos_ref = &*qos.cast::<QoS>();
    qos_ref.resource_limits.max_samples_per_instance
}

// =============================================================================
// QoS Setters (additional)
// =============================================================================

/// Set liveliness to automatic with given lease duration in nanoseconds.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_liveliness_automatic_ns(
    qos: *mut HddsQoS,
    lease_ns: u64,
) -> HddsError {
    if qos.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.liveliness =
        hdds::dds::qos::Liveliness::automatic(std::time::Duration::from_nanos(lease_ns));
    HddsError::HddsOk
}

/// Set liveliness to manual-by-participant with given lease duration in nanoseconds.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_liveliness_manual_participant_ns(
    qos: *mut HddsQoS,
    lease_ns: u64,
) -> HddsError {
    if qos.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.liveliness = hdds::dds::qos::Liveliness::manual_by_participant(
        std::time::Duration::from_nanos(lease_ns),
    );
    HddsError::HddsOk
}

/// Set liveliness to manual-by-topic with given lease duration in nanoseconds.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_liveliness_manual_topic_ns(
    qos: *mut HddsQoS,
    lease_ns: u64,
) -> HddsError {
    if qos.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.liveliness =
        hdds::dds::qos::Liveliness::manual_by_topic(std::time::Duration::from_nanos(lease_ns));
    HddsError::HddsOk
}

/// Set time-based filter minimum separation in nanoseconds.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_time_based_filter_ns(
    qos: *mut HddsQoS,
    min_separation_ns: u64,
) -> HddsError {
    if qos.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.time_based_filter =
        hdds::dds::qos::TimeBasedFilter::new(std::time::Duration::from_nanos(min_separation_ns));
    HddsError::HddsOk
}

/// Set latency budget in nanoseconds.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_latency_budget_ns(
    qos: *mut HddsQoS,
    budget_ns: u64,
) -> HddsError {
    if qos.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.latency_budget =
        hdds::dds::qos::LatencyBudget::new(std::time::Duration::from_nanos(budget_ns));
    HddsError::HddsOk
}

/// Set transport priority.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_transport_priority(
    qos: *mut HddsQoS,
    priority: i32,
) -> HddsError {
    if qos.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.transport_priority.value = priority;
    HddsError::HddsOk
}

/// Set resource limits.
///
/// Use `usize::MAX` for any value to indicate unlimited.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_resource_limits(
    qos: *mut HddsQoS,
    max_samples: usize,
    max_instances: usize,
    max_samples_per_instance: usize,
) -> HddsError {
    if qos.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.resource_limits.max_samples = max_samples;
    qos_ref.resource_limits.max_instances = max_instances;
    qos_ref.resource_limits.max_samples_per_instance = max_samples_per_instance;
    HddsError::HddsOk
}

/// `XCDR_DATA_REPRESENTATION` (DDS-XTypes v1.3 Sec.7.6.3.1.1): XCDR
/// encoding version 1.
pub const HDDS_XCDR_DATA_REPRESENTATION: i16 = 0;
/// `XCDR2_DATA_REPRESENTATION`: XCDR encoding version 2.
pub const HDDS_XCDR2_DATA_REPRESENTATION: i16 = 2;

/// Set DATA_REPRESENTATION (DDS-XTypes v1.3 Sec.7.6.3.1.1) to the `count`
/// identifiers at `ids`, in order.
///
/// A writer offers the first one and labels every sample with it; a reader
/// requests them all and is matched with a writer whose offer is among
/// them. Request XCDR (`HDDS_XCDR_DATA_REPRESENTATION`) only when the code
/// that decodes the samples reads XCDR1, and then request XCDR2 as well
/// (the spec's rule for a reader that "can deserialize version 1
/// encodings"): a reader whose decoders `hdds_gen` emitted with XCDR1
/// support (`HDDSGEN_C_DECODES_XCDR1` defined) sets
/// `{HDDS_XCDR_DATA_REPRESENTATION, HDDS_XCDR2_DATA_REPRESENTATION}`, takes
/// with `hdds_reader_take_ex` and decodes with
/// `_decode_by_encapsulation_alloc`. A writer whose bytes come from
/// `hdds_gen` encoders, which serialize XCDR2, sets XCDR2 or nothing.
///
/// `count == 0` clears the list: an endpoint created through this ABI with
/// an empty list offers and requests XCDR2 (`hdds_writer_create*`,
/// `hdds_reader_create*`). Only XCDR (0) and XCDR2 (2) are accepted; any
/// other identifier (XML, a vendor one) returns `HDDS_INVALID_ARGUMENT` and
/// leaves the QoS unchanged.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
/// - `ids` must point to `count` readable `int16_t`, or be NULL when
///   `count` is 0.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_set_data_representation(
    qos: *mut HddsQoS,
    ids: *const i16,
    count: usize,
) -> HddsError {
    if qos.is_null() || (ids.is_null() && count != 0) {
        return HddsError::HddsInvalidArgument;
    }
    let ids = if count == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(ids, count)
    };
    let mut list = Vec::with_capacity(ids.len());
    for &id in ids {
        match id {
            HDDS_XCDR_DATA_REPRESENTATION | HDDS_XCDR2_DATA_REPRESENTATION => {
                list.push(id.unsigned_abs());
            }
            _ => return HddsError::HddsInvalidArgument,
        }
    }
    let qos_ref = &mut *qos.cast::<QoS>();
    qos_ref.data_representation = list;
    HddsError::HddsOk
}

/// Read DATA_REPRESENTATION: the number of identifiers in the list is
/// written to `*count_out`, and the first `min(count, capacity)` of them to
/// `ids_out` (which may be NULL when `capacity` is 0). An empty list (the
/// default) reports 0.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
/// - `ids_out` must point to `capacity` writable `int16_t`, or be NULL when
///   `capacity` is 0.
/// - `count_out` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_get_data_representation(
    qos: *const HddsQoS,
    ids_out: *mut i16,
    capacity: usize,
    count_out: *mut usize,
) -> HddsError {
    if qos.is_null() || count_out.is_null() || (ids_out.is_null() && capacity != 0) {
        return HddsError::HddsInvalidArgument;
    }
    let qos_ref = &*qos.cast::<QoS>();
    let list = &qos_ref.data_representation;
    *count_out = list.len();
    for (i, &id) in list.iter().take(capacity).enumerate() {
        // The list holds representation identifiers, signed 16-bit on the
        // wire (DDS-XTypes v1.3 Sec.7.6.3.1.1); the QoS keeps their bits.
        *ids_out.add(i) = i16::from_ne_bytes(id.to_ne_bytes());
    }
    HddsError::HddsOk
}

// =============================================================================
// Clone QoS
// =============================================================================

/// Clone a QoS profile.
///
/// # Safety
/// - `qos` must be a valid pointer from `hdds_qos_*` functions.
/// - The returned pointer must be freed with `hdds_qos_destroy`.
#[no_mangle]
pub unsafe extern "C" fn hdds_qos_clone(qos: *const HddsQoS) -> *mut HddsQoS {
    if qos.is_null() {
        return ptr::null_mut();
    }

    let qos_ref = &*qos.cast::<QoS>();
    let cloned = Box::new(qos_ref.clone());
    Box::into_raw(cloned).cast::<HddsQoS>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_qos_creation_and_destroy() {
        unsafe {
            let qos = hdds_qos_default();
            assert!(!qos.is_null());
            hdds_qos_destroy(qos);

            let qos = hdds_qos_reliable();
            assert!(!qos.is_null());
            assert!(hdds_qos_is_reliable(qos));
            hdds_qos_destroy(qos);

            let qos = hdds_qos_best_effort();
            assert!(!qos.is_null());
            assert!(!hdds_qos_is_reliable(qos));
            hdds_qos_destroy(qos);
        }
    }

    #[test]
    fn test_qos_setters() {
        unsafe {
            let qos = hdds_qos_default();

            // Test history depth
            assert_eq!(hdds_qos_set_history_depth(qos, 50), HddsError::HddsOk);
            assert_eq!(hdds_qos_get_history_depth(qos), 50);

            // Test transient local
            assert_eq!(hdds_qos_set_transient_local(qos), HddsError::HddsOk);
            assert!(hdds_qos_is_transient_local(qos));

            // Test reliable
            assert_eq!(hdds_qos_set_reliable(qos), HddsError::HddsOk);
            assert!(hdds_qos_is_reliable(qos));

            // Test partition
            let part = CString::new("test_partition").unwrap();
            assert_eq!(
                hdds_qos_add_partition(qos, part.as_ptr()),
                HddsError::HddsOk
            );

            hdds_qos_destroy(qos);
        }
    }

    #[test]
    fn test_qos_max_blocking_time_round_trip() {
        unsafe {
            let qos = hdds_qos_reliable();

            // DDS v1.4 Sec.2.2.3.14 default is 100 ms, applied by every
            // constructor.
            assert_eq!(hdds_qos_get_max_blocking_time_ns(qos), 100_000_000);

            assert_eq!(
                hdds_qos_set_max_blocking_time_ns(qos, 300_000_000),
                HddsError::HddsOk
            );
            assert_eq!(hdds_qos_get_max_blocking_time_ns(qos), 300_000_000);

            hdds_qos_destroy(qos);
        }
    }

    #[test]
    fn test_qos_clone() {
        unsafe {
            let qos = hdds_qos_reliable();
            hdds_qos_set_history_depth(qos, 42);
            hdds_qos_set_transient_local(qos);

            let cloned = hdds_qos_clone(qos);
            assert!(!cloned.is_null());
            assert!(hdds_qos_is_reliable(cloned));
            assert!(hdds_qos_is_transient_local(cloned));
            assert_eq!(hdds_qos_get_history_depth(cloned), 42);

            hdds_qos_destroy(qos);
            hdds_qos_destroy(cloned);
        }
    }
}
