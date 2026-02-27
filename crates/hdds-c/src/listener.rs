// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS Listener FFI Bindings
//!
//! C-compatible callback-based listener API for DataReader and DataWriter events.
//! These structs and functions wrap the Rust listener traits defined in
//! `hdds::dds::listener` for consumption by C, C++, and Python SDKs.
//!
//! # Usage from C
//!
//! ```c
//! void my_on_data(const uint8_t* data, size_t len, void* user_data) {
//!     // process data
//! }
//!
//! HddsReaderListener listener = {0};
//! listener.on_data_available = my_on_data;
//! listener.user_data = my_context;
//! hdds_reader_set_listener(reader, &listener);
//! ```
//!
//! # Thread Safety
//!
//! The C caller is responsible for ensuring that callback functions and
//! user_data pointers remain valid for the lifetime of the listener.

use std::os::raw::{c_char, c_void};

use super::{HddsDataReader, HddsDataWriter, HddsError};

// =============================================================================
// C-compatible status structs
// =============================================================================

/// Subscription matched status (C-compatible mirror of Rust SubscriptionMatchedStatus).
///
/// Reports the number of publications matched with this reader.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HddsSubscriptionMatchedStatus {
    /// Total cumulative count of matched publications.
    pub total_count: u32,
    /// Change in total_count since last callback.
    pub total_count_change: i32,
    /// Current number of matched publications.
    pub current_count: u32,
    /// Change in current_count since last callback.
    pub current_count_change: i32,
}

/// Publication matched status (C-compatible mirror of Rust PublicationMatchedStatus).
///
/// Reports the number of subscriptions matched with this writer.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HddsPublicationMatchedStatus {
    /// Total cumulative count of matched subscriptions.
    pub total_count: u32,
    /// Change in total_count since last callback.
    pub total_count_change: i32,
    /// Current number of matched subscriptions.
    pub current_count: u32,
    /// Change in current_count since last callback.
    pub current_count_change: i32,
}

/// Liveliness changed status (C-compatible mirror of Rust LivelinessChangedStatus).
///
/// Reports changes in liveliness of matched writers.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HddsLivelinessChangedStatus {
    /// Number of publications currently asserting liveliness.
    pub alive_count: u32,
    /// Change in alive_count since last callback.
    pub alive_count_change: i32,
    /// Number of publications that have lost liveliness.
    pub not_alive_count: u32,
    /// Change in not_alive_count since last callback.
    pub not_alive_count_change: i32,
}

/// Sample lost status (C-compatible mirror of Rust SampleLostStatus).
///
/// Reports samples lost due to gaps in sequence numbers.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HddsSampleLostStatus {
    /// Total cumulative count of lost samples.
    pub total_count: u32,
    /// Change in total_count since last callback.
    pub total_count_change: i32,
}

/// Sample rejected status (C-compatible mirror of Rust SampleRejectedStatus).
///
/// Reports samples rejected due to resource limits.
/// `last_reason` values: 0=NotRejected, 1=ResourceLimit, 2=InstanceLimit,
/// 3=SamplesPerInstanceLimit.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HddsSampleRejectedStatus {
    /// Total cumulative count of rejected samples.
    pub total_count: u32,
    /// Change in total_count since last callback.
    pub total_count_change: i32,
    /// Reason for rejection (0=NotRejected, 1=ResourceLimit, 2=InstanceLimit, 3=SamplesPerInstanceLimit).
    pub last_reason: u32,
}

/// Deadline missed status (C-compatible mirror of Rust RequestedDeadlineMissedStatus).
///
/// Reports missed deadlines on a reader or writer.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HddsDeadlineMissedStatus {
    /// Total cumulative count of missed deadlines.
    pub total_count: u32,
    /// Change in total_count since last callback.
    pub total_count_change: i32,
}

/// Incompatible QoS status (C-compatible mirror of Rust RequestedIncompatibleQosStatus).
///
/// Reports QoS incompatibility between matched endpoints.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HddsIncompatibleQosStatus {
    /// Total cumulative count of incompatible QoS offers.
    pub total_count: u32,
    /// Change in total_count since last callback.
    pub total_count_change: i32,
    /// ID of the last incompatible QoS policy.
    pub last_policy_id: u32,
}

// =============================================================================
// Callback type aliases (C function pointers)
// =============================================================================

/// Callback for data available events.
///
/// # Parameters
/// - `data`: Pointer to serialized sample bytes
/// - `len`: Length of the serialized data in bytes
/// - `user_data`: User-provided context pointer
pub type HddsOnDataAvailable =
    Option<unsafe extern "C" fn(data: *const u8, len: usize, user_data: *mut c_void)>;

/// Callback for subscription matched events.
pub type HddsOnSubscriptionMatched = Option<
    unsafe extern "C" fn(status: *const HddsSubscriptionMatchedStatus, user_data: *mut c_void),
>;

/// Callback for publication matched events.
pub type HddsOnPublicationMatched = Option<
    unsafe extern "C" fn(status: *const HddsPublicationMatchedStatus, user_data: *mut c_void),
>;

/// Callback for liveliness changed events.
pub type HddsOnLivelinessChanged = Option<
    unsafe extern "C" fn(status: *const HddsLivelinessChangedStatus, user_data: *mut c_void),
>;

/// Callback for sample lost events.
pub type HddsOnSampleLost =
    Option<unsafe extern "C" fn(status: *const HddsSampleLostStatus, user_data: *mut c_void)>;

/// Callback for sample rejected events.
pub type HddsOnSampleRejected =
    Option<unsafe extern "C" fn(status: *const HddsSampleRejectedStatus, user_data: *mut c_void)>;

/// Callback for deadline missed events (reader side).
pub type HddsOnDeadlineMissed =
    Option<unsafe extern "C" fn(status: *const HddsDeadlineMissedStatus, user_data: *mut c_void)>;

/// Callback for incompatible QoS events (reader side).
pub type HddsOnIncompatibleQos =
    Option<unsafe extern "C" fn(status: *const HddsIncompatibleQosStatus, user_data: *mut c_void)>;

/// Callback for sample written events (writer confirmation).
///
/// # Parameters
/// - `data`: Pointer to serialized sample bytes
/// - `len`: Length of the serialized data in bytes
/// - `sequence_number`: Assigned RTPS sequence number
/// - `user_data`: User-provided context pointer
pub type HddsOnSampleWritten = Option<
    unsafe extern "C" fn(data: *const u8, len: usize, sequence_number: u64, user_data: *mut c_void),
>;

/// Callback for offered deadline missed events (writer side).
///
/// # Parameters
/// - `instance_handle`: Handle of the instance that missed the deadline (0 if none)
/// - `user_data`: User-provided context pointer
pub type HddsOnOfferedDeadlineMissed =
    Option<unsafe extern "C" fn(instance_handle: u64, user_data: *mut c_void)>;

/// Callback for offered incompatible QoS events (writer side).
///
/// # Parameters
/// - `policy_id`: ID of the incompatible QoS policy
/// - `policy_name`: Null-terminated policy name string (e.g., "RELIABILITY")
/// - `user_data`: User-provided context pointer
pub type HddsOnOfferedIncompatibleQos = Option<
    unsafe extern "C" fn(policy_id: u32, policy_name: *const c_char, user_data: *mut c_void),
>;

/// Callback for liveliness lost events (writer side).
pub type HddsOnLivelinessLost = Option<unsafe extern "C" fn(user_data: *mut c_void)>;

// =============================================================================
// Listener structs
// =============================================================================

/// C-compatible DataReader listener.
///
/// Set callback fields to receive events. Any callback set to `None` (NULL)
/// will be silently ignored. The `user_data` pointer is passed through to
/// every callback invocation.
///
/// # Example (C)
///
/// ```c
/// HddsReaderListener listener = {0};
/// listener.on_data_available = my_data_callback;
/// listener.on_subscription_matched = my_match_callback;
/// listener.user_data = my_context;
/// hdds_reader_set_listener(reader, &listener);
/// ```
#[repr(C)]
pub struct HddsReaderListener {
    /// Called when new data is available to read.
    pub on_data_available: HddsOnDataAvailable,
    /// Called when the reader matches/unmatches with a writer.
    pub on_subscription_matched: HddsOnSubscriptionMatched,
    /// Called when liveliness of a matched writer changes.
    pub on_liveliness_changed: HddsOnLivelinessChanged,
    /// Called when samples are lost (gap in sequence numbers).
    pub on_sample_lost: HddsOnSampleLost,
    /// Called when samples are rejected due to resource limits.
    pub on_sample_rejected: HddsOnSampleRejected,
    /// Called when the requested deadline is missed.
    pub on_deadline_missed: HddsOnDeadlineMissed,
    /// Called when QoS is incompatible with a matched writer.
    pub on_incompatible_qos: HddsOnIncompatibleQos,
    /// User-provided context pointer, passed to all callbacks.
    pub user_data: *mut c_void,
}

// Safety: The C caller is responsible for thread safety of user_data and callbacks.
// Listeners are stored internally and invoked from background threads.
unsafe impl Send for HddsReaderListener {}
unsafe impl Sync for HddsReaderListener {}

/// C-compatible DataWriter listener.
///
/// Set callback fields to receive events. Any callback set to `None` (NULL)
/// will be silently ignored. The `user_data` pointer is passed through to
/// every callback invocation.
///
/// # Example (C)
///
/// ```c
/// HddsWriterListener listener = {0};
/// listener.on_publication_matched = my_match_callback;
/// listener.user_data = my_context;
/// hdds_writer_set_listener(writer, &listener);
/// ```
#[repr(C)]
pub struct HddsWriterListener {
    /// Called after a sample is successfully written.
    pub on_sample_written: HddsOnSampleWritten,
    /// Called when the writer matches/unmatches with a reader.
    pub on_publication_matched: HddsOnPublicationMatched,
    /// Called when an offered deadline is missed.
    pub on_offered_deadline_missed: HddsOnOfferedDeadlineMissed,
    /// Called when QoS is incompatible with a matched reader.
    pub on_offered_incompatible_qos: HddsOnOfferedIncompatibleQos,
    /// Called when liveliness is lost (MANUAL_BY_* only).
    pub on_liveliness_lost: HddsOnLivelinessLost,
    /// User-provided context pointer, passed to all callbacks.
    pub user_data: *mut c_void,
}

// Safety: The C caller is responsible for thread safety of user_data and callbacks.
unsafe impl Send for HddsWriterListener {}
unsafe impl Sync for HddsWriterListener {}

// =============================================================================
// FFI functions
// =============================================================================

/// Install a listener on a DataReader.
///
/// The listener struct is copied internally. The caller must ensure that
/// any `user_data` pointer and callback functions remain valid until the
/// listener is cleared or the reader is destroyed.
///
/// # Safety
///
/// - `reader` must be a valid pointer returned from `hdds_reader_create` or similar.
/// - `listener` must be a valid pointer to a properly initialized `HddsReaderListener`.
///
/// # Returns
///
/// `HddsOk` on success, `HddsInvalidArgument` if either pointer is null.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_set_listener(
    reader: *mut HddsDataReader,
    listener: *const HddsReaderListener,
) -> HddsError {
    if reader.is_null() || listener.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    // Listener bridging not yet implemented -- core DataReader does not
    // expose set_listener(). Return Unsupported so callers know this is
    // a no-op rather than silently ignoring callbacks.
    let _ = listener;
    log::warn!("hdds_reader_set_listener: not yet implemented");
    HddsError::HddsUnsupported
}

/// Remove the listener from a DataReader.
///
/// After this call, no more callbacks will be invoked for this reader.
///
/// # Safety
///
/// - `reader` must be a valid pointer returned from `hdds_reader_create` or similar.
///
/// # Returns
///
/// `HddsOk` on success, `HddsInvalidArgument` if the pointer is null.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_clear_listener(reader: *mut HddsDataReader) -> HddsError {
    if reader.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    // No-op until listener bridging is implemented.
    log::warn!("hdds_reader_clear_listener: not yet implemented");
    HddsError::HddsUnsupported
}

/// Install a listener on a DataWriter.
///
/// The listener struct is copied internally. The caller must ensure that
/// any `user_data` pointer and callback functions remain valid until the
/// listener is cleared or the writer is destroyed.
///
/// # Safety
///
/// - `writer` must be a valid pointer returned from `hdds_writer_create` or similar.
/// - `listener` must be a valid pointer to a properly initialized `HddsWriterListener`.
///
/// # Returns
///
/// `HddsOk` on success, `HddsInvalidArgument` if either pointer is null.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_set_listener(
    writer: *mut HddsDataWriter,
    listener: *const HddsWriterListener,
) -> HddsError {
    if writer.is_null() || listener.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    // Listener bridging not yet implemented -- core DataWriter does not
    // expose set_listener(). Return Unsupported so callers know.
    let _ = listener;
    log::warn!("hdds_writer_set_listener: not yet implemented");
    HddsError::HddsUnsupported
}

/// Remove the listener from a DataWriter.
///
/// After this call, no more callbacks will be invoked for this writer.
///
/// # Safety
///
/// - `writer` must be a valid pointer returned from `hdds_writer_create` or similar.
///
/// # Returns
///
/// `HddsOk` on success, `HddsInvalidArgument` if the pointer is null.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_clear_listener(writer: *mut HddsDataWriter) -> HddsError {
    if writer.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    // No-op until listener bridging is implemented.
    log::warn!("hdds_writer_clear_listener: not yet implemented");
    HddsError::HddsUnsupported
}
