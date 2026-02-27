// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS C FFI Bindings
//!
//! This crate provides C-compatible FFI bindings for the HDDS DDS implementation.
//!
//! # Safety
//!
//! All public functions are `unsafe` and require the caller to uphold the
//! invariants documented in each function's safety comment.

mod info;
mod listener;
mod logging;
mod pubsub;
mod qos;
#[cfg(feature = "rmw")]
mod rmw;
mod telemetry;
mod waitset;

// Re-export new modules
pub use info::*;
pub use listener::*;
pub use logging::*;
pub use pubsub::*;
pub use telemetry::*;

// Re-export QoS types
pub use qos::HddsQoS;

use std::collections::HashMap;
use std::convert::TryFrom;
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use waitset::ForeignWaitSet;

use hdds::api::{DataReader, DataWriter, GuardCondition, Participant, QoS, StatusCondition, DDS};
use hdds::core::types::{Distro, TypeDescriptor, TypeObjectHandle, ROS_HASH_SIZE};
use hdds::dds::Condition;
use serde::{Deserialize, Serialize};

// XTypes imports (for type support registration)
#[cfg(feature = "xtypes")]
use hdds::xtypes::{rosidl_message_type_support_t, RosidlError};

// RMW-only imports
#[cfg(feature = "rmw")]
use hdds::api::Error as ApiError;
#[cfg(feature = "rmw")]
use rmw::{
    decode_special, deserialize_dynamic_to_ros, encode_special, map_api_error,
    ros2_type_to_descriptor, serialize_from_ros, ForeignRmwContext, ForeignRmwWaitSet,
    Ros2CodecKind,
};
#[cfg(feature = "rmw")]
use std::ffi::CString;
#[cfg(feature = "rmw")]
use std::slice;

#[cfg(feature = "rmw")]
type HddsNodeVisitor = Option<unsafe extern "C" fn(*const c_char, *const c_char, *mut c_void)>;
#[cfg(feature = "rmw")]
type HddsNodeEnclaveVisitor =
    Option<unsafe extern "C" fn(*const c_char, *const c_char, *const c_char, *mut c_void)>;
#[cfg(feature = "rmw")]
type HddsEndpointVisitor = Option<
    unsafe extern "C" fn(
        *const c_char,
        *const c_char,
        *const u8,
        *const HddsRmwQosProfile,
        *mut c_void,
    ),
>;

#[cfg(feature = "rmw")]
fn normalize_ros_type_name(type_name: &str) -> String {
    if type_name.contains("::") {
        type_name.replace("::", "/")
    } else {
        type_name.to_string()
    }
}

/// Opaque handle to a Participant
#[repr(C)]
pub struct HddsParticipant {
    _private: [u8; 0],
}

/// Opaque handle to a `DataWriter`
#[repr(C)]
pub struct HddsDataWriter {
    _private: [u8; 0],
}

/// Opaque handle to a `DataReader`
#[repr(C)]
pub struct HddsDataReader {
    _private: [u8; 0],
}

/// Opaque handle to a WaitSet
#[repr(C)]
pub struct HddsWaitSet {
    _private: [u8; 0],
}

/// Opaque handle to a GuardCondition
#[repr(C)]
pub struct HddsGuardCondition {
    _private: [u8; 0],
}

/// Opaque handle to a StatusCondition
#[repr(C)]
pub struct HddsStatusCondition {
    _private: [u8; 0],
}

/// Opaque handle to an rmw context
#[cfg(feature = "rmw")]
#[repr(C)]
pub struct HddsRmwContext {
    _private: [u8; 0],
}

#[cfg(feature = "rmw")]
pub const HDDS_RMW_GID_SIZE: usize = hdds::rmw::graph::RMW_GID_STORAGE_SIZE;

#[cfg(feature = "rmw")]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HddsRmwQosProfile {
    pub history: u8,
    pub depth: u32,
    pub reliability: u8,
    pub durability: u8,
    pub deadline_ns: u64,
    pub lifespan_ns: u64,
    pub liveliness: u8,
    pub liveliness_lease_ns: u64,
    pub avoid_ros_namespace_conventions: bool,
}

/// Opaque handle to an rmw waitset
#[cfg(feature = "rmw")]
#[repr(C)]
pub struct HddsRmwWaitSet {
    _private: [u8; 0],
}

#[cfg(feature = "rmw")]
pub type HddsTopicVisitor =
    unsafe extern "C" fn(*const c_char, *const c_char, u32, u32, *mut c_void);

#[cfg(feature = "rmw")]
pub type HddsLocatorVisitor = unsafe extern "C" fn(*const c_char, u16, *mut c_void);

#[cfg(feature = "xtypes")]
#[repr(C)]
pub struct HddsTypeObject {
    _private: [u8; 0],
}

struct GuardRegistryEntry {
    guard: Arc<GuardCondition>,
    handles: usize,
}

struct StatusRegistryEntry {
    status: Arc<StatusCondition>,
    handles: usize,
}

fn guard_registry() -> &'static Mutex<HashMap<usize, GuardRegistryEntry>> {
    static REGISTRY: OnceLock<Mutex<HashMap<usize, GuardRegistryEntry>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn status_registry() -> &'static Mutex<HashMap<usize, StatusRegistryEntry>> {
    static REGISTRY: OnceLock<Mutex<HashMap<usize, StatusRegistryEntry>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn guard_registry_add_handle(raw: *const HddsGuardCondition, guard: Arc<GuardCondition>) {
    if raw.is_null() {
        return;
    }

    let mut registry = guard_registry()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let entry = registry
        .entry(raw as usize)
        .or_insert_with(|| GuardRegistryEntry { guard, handles: 0 });
    entry.handles = entry.handles.saturating_add(1);
}

fn guard_registry_clone(raw: *const HddsGuardCondition) -> Option<Arc<GuardCondition>> {
    if raw.is_null() {
        return None;
    }

    let registry = guard_registry()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    registry
        .get(&(raw as usize))
        .map(|entry| entry.guard.clone())
}

fn guard_registry_release(raw: *const HddsGuardCondition) -> bool {
    if raw.is_null() {
        return false;
    }

    let mut registry = guard_registry()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let Some(entry) = registry.get_mut(&(raw as usize)) else {
        return false;
    };

    if entry.handles == 0 {
        return false;
    }

    entry.handles -= 1;
    if entry.handles == 0 {
        registry.remove(&(raw as usize));
    }

    true
}

fn status_registry_add_handle(raw: *const HddsStatusCondition, status: Arc<StatusCondition>) {
    if raw.is_null() {
        return;
    }

    let mut registry = status_registry()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let entry = registry
        .entry(raw as usize)
        .or_insert_with(|| StatusRegistryEntry { status, handles: 0 });
    entry.handles = entry.handles.saturating_add(1);
}

fn status_registry_clone(raw: *const HddsStatusCondition) -> Option<Arc<StatusCondition>> {
    if raw.is_null() {
        return None;
    }

    let registry = status_registry()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    registry
        .get(&(raw as usize))
        .map(|entry| entry.status.clone())
}

fn status_registry_release(raw: *const HddsStatusCondition) -> bool {
    if raw.is_null() {
        return false;
    }

    let mut registry = status_registry()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let Some(entry) = registry.get_mut(&(raw as usize)) else {
        return false;
    };

    if entry.handles == 0 {
        return false;
    }

    entry.handles -= 1;
    if entry.handles == 0 {
        registry.remove(&(raw as usize));
    }

    true
}

#[cfg(feature = "xtypes")]
fn distro_from_u32(value: u32) -> Option<Distro> {
    match value {
        0 => Some(Distro::Humble),
        1 => Some(Distro::Iron),
        2 => Some(Distro::Jazzy),
        _ => None,
    }
}

#[cfg(feature = "xtypes")]
fn map_rosidl_error(err: &RosidlError) -> HddsError {
    match err {
        RosidlError::NullTypeSupport
        | RosidlError::NullMembers
        | RosidlError::InvalidUtf8(_)
        | RosidlError::BoundOverflow { .. }
        | RosidlError::UnsupportedType(_) => HddsError::HddsInvalidArgument,
        RosidlError::MissingHash | RosidlError::Builder(_) => HddsError::HddsOperationFailed,
    }
}

/// Generic payload wrapper for serialization
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct BytePayload {
    data: Vec<u8>,
}

/// Implement DDS trait for `BytePayload`
impl BytePayload {
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl DDS for BytePayload {
    fn type_descriptor() -> &'static TypeDescriptor {
        // Simple type descriptor for opaque byte array
        // type_name MUST be "RawBytes" to match hdds-ws (create_raw_writer/reader)
        // so that SEDP type matching succeeds in cross-process communication.
        static DESCRIPTOR: TypeDescriptor = TypeDescriptor {
            type_id: 0x0000_0000, // Special ID for opaque data
            type_name: "RawBytes",
            size_bytes: 0, // Variable size
            alignment: 1,  // Raw byte alignment
            is_variable_size: true,
            fields: &[],
        };
        &DESCRIPTOR
    }

    fn encode_cdr2(&self, buf: &mut [u8]) -> hdds::api::Result<usize> {
        // Raw byte payload (no length prefix)
        if buf.len() < self.data.len() {
            return Err(hdds::api::Error::BufferTooSmall);
        }

        buf[..self.data.len()].copy_from_slice(&self.data);
        Ok(self.data.len())
    }

    fn decode_cdr2(buf: &[u8]) -> hdds::api::Result<Self> {
        Ok(BytePayload { data: buf.to_vec() })
    }
}

/// Error codes (C-compatible enum)
///
/// # Error Code Categories
///
/// - **0-9**: Success and generic errors
/// - **10-19**: Configuration errors
/// - **20-29**: I/O and transport errors
/// - **30-39**: Type and serialization errors
/// - **40-49**: QoS and resource errors
/// - **50-59**: Security errors
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HddsError {
    /// Operation completed successfully
    HddsOk = 0,
    /// Invalid argument provided (null pointer, invalid value)
    HddsInvalidArgument = 1,
    /// Requested resource not found
    HddsNotFound = 2,
    /// Generic operation failure
    HddsOperationFailed = 3,
    /// Memory allocation failed
    HddsOutOfMemory = 4,

    // === Configuration errors (10-19) ===
    /// Invalid configuration settings
    HddsConfigError = 10,
    /// Invalid domain ID (must be 0-232)
    HddsInvalidDomainId = 11,
    /// Invalid participant ID (must be 0-119)
    HddsInvalidParticipantId = 12,
    /// No available participant ID (all 120 ports occupied)
    HddsNoAvailableParticipantId = 13,
    /// Invalid entity state for requested operation
    HddsInvalidState = 14,

    // === I/O and transport errors (20-29) ===
    /// Generic I/O error
    HddsIoError = 20,
    /// UDP transport send/receive failed
    HddsTransportError = 21,
    /// Topic registration failed
    HddsRegistrationFailed = 22,
    /// Operation would block but non-blocking mode requested
    HddsWouldBlock = 23,

    // === Type and serialization errors (30-39) ===
    /// Type mismatch between writer and reader
    HddsTypeMismatch = 30,
    /// CDR serialization failed
    HddsSerializationError = 31,
    /// Buffer too small for encoding
    HddsBufferTooSmall = 32,
    /// CDR endianness mismatch
    HddsEndianMismatch = 33,

    // === QoS and resource errors (40-49) ===
    /// QoS policies are incompatible between endpoints
    HddsQosIncompatible = 40,
    /// Requested feature or operation is not supported
    HddsUnsupported = 41,

    // === Security errors (50-59) ===
    /// Permission denied by access control (DDS Security)
    HddsPermissionDenied = 50,
    /// Authentication failed
    HddsAuthenticationFailed = 51,
}

/// Transport mode for participant creation
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HddsTransportMode {
    /// Intra-process only (no network, fastest for same-process communication)
    HddsTransportIntraProcess = 0,
    /// UDP multicast for network discovery and communication (default for DDS interop)
    HddsTransportUdpMulticast = 1,
}

/// Create a new DDS Participant with default settings (UdpMulticast transport)
///
/// For network DDS communication, this is the recommended function.
/// Use `hdds_participant_create_with_transport` if you need intra-process mode.
///
/// # Safety
/// - `name` must be a valid null-terminated C string.
/// - The returned handle must be released with `hdds_participant_destroy`.
#[no_mangle]
pub unsafe extern "C" fn hdds_participant_create(name: *const c_char) -> *mut HddsParticipant {
    hdds_participant_create_with_transport(name, HddsTransportMode::HddsTransportUdpMulticast)
}

/// Create a new DDS Participant with specified transport mode
///
/// # Safety
/// - `name` must be a valid null-terminated C string.
/// - The returned handle must be released with `hdds_participant_destroy`.
///
/// # Arguments
/// * `name` - Participant name (null-terminated C string)
/// * `transport` - Transport mode:
///   - `HddsTransportMode::HddsTransportIntraProcess` (0): No network, intra-process only
///   - `HddsTransportMode::HddsTransportUdpMulticast` (1): UDP multicast for network discovery
///
/// # Returns
/// Opaque participant handle, or NULL on failure
#[no_mangle]
pub unsafe extern "C" fn hdds_participant_create_with_transport(
    name: *const c_char,
    transport: HddsTransportMode,
) -> *mut HddsParticipant {
    // Initialize logger (only once, subsequent calls are no-op)
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = env_logger::try_init();
    });

    if name.is_null() {
        return ptr::null_mut();
    }

    let Ok(name_str) = CStr::from_ptr(name).to_str() else {
        return ptr::null_mut();
    };

    use hdds::TransportMode;
    let mode = match transport {
        HddsTransportMode::HddsTransportIntraProcess => TransportMode::IntraProcess,
        HddsTransportMode::HddsTransportUdpMulticast => TransportMode::UdpMulticast,
    };

    // Port assignment evolution:
    // - v0.8.1: Added explicit .with_discovery_ports(7400, 7410, 7411) for RTPS compliance
    // - v1.0.6: REMOVED with_discovery_ports() to enable multi-process support
    //
    // The builder now handles port assignment via (in priority order):
    //   1. Code: .participant_id(Some(X))
    //   2. Env:  HDDS_PARTICIPANT_ID=X
    //   3. Auto: probe ports 7410+pid*2, 7411+pid*2 until free pair found
    //
    // For multi-process on same machine, set HDDS_REUSEPORT=1 and unique HDDS_PARTICIPANT_ID:
    //   HDDS_REUSEPORT=1 HDDS_PARTICIPANT_ID=0 ./daemon   # ports 7410, 7411
    //   HDDS_REUSEPORT=1 HDDS_PARTICIPANT_ID=1 ./alpha    # ports 7412, 7413
    //   HDDS_REUSEPORT=1 HDDS_PARTICIPANT_ID=2 ./beta     # ports 7414, 7415
    // Domain ID: check HDDS_DOMAIN_ID env var (same as rmw-hdds), default to 0
    let domain_id = std::env::var("HDDS_DOMAIN_ID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);

    if domain_id != 0 {
        log::info!(
            "[HDDS-C] Using domain_id={} from HDDS_DOMAIN_ID env",
            domain_id
        );
    }

    let Ok(participant) = Participant::builder(name_str)
        .domain_id(domain_id)
        .with_transport(mode)
        .build()
    else {
        return ptr::null_mut();
    };

    // Store Arc<Participant> in a Box so we can get a stable pointer to the Arc itself
    Box::into_raw(Box::new(participant)).cast::<HddsParticipant>()
}

/// Destroy a Participant
///
/// # Safety
/// - `participant` must be a valid handle from `hdds_participant_create`, or NULL (no-op).
/// - Must not be called more than once with the same pointer.
#[no_mangle]
pub unsafe extern "C" fn hdds_participant_destroy(participant: *mut HddsParticipant) {
    if !participant.is_null() {
        // Participant was stored as Box<Arc<Participant>>
        let _ = Box::from_raw(participant.cast::<Arc<Participant>>());
    }
}

/// Get the participant-level graph guard condition.
///
/// # Safety
/// - `participant` must be a valid handle from `hdds_participant_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_participant_graph_guard_condition(
    participant: *mut HddsParticipant,
) -> *const HddsGuardCondition {
    if participant.is_null() {
        return ptr::null();
    }

    let participant_ref = &*participant.cast::<Arc<Participant>>();
    let guard = participant_ref.graph_guard();
    let raw = Arc::into_raw(guard.clone()) as *const HddsGuardCondition;
    guard_registry_add_handle(raw, guard);
    raw
}

/// Register a ROS 2 type support with the participant.
///
/// # Safety
/// - `participant` must be a valid handle from `hdds_participant_create`.
/// - `type_support` must be a valid `rosidl_message_type_support_t` pointer.
/// - `out_handle` must be a valid pointer to write the result.
#[cfg(feature = "xtypes")]
#[no_mangle]
pub unsafe extern "C" fn hdds_participant_register_type_support(
    participant: *mut HddsParticipant,
    distro: u32,
    type_support: *const rosidl_message_type_support_t,
    out_handle: *mut *const HddsTypeObject,
) -> HddsError {
    if participant.is_null() || type_support.is_null() || out_handle.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let Some(distro) = distro_from_u32(distro) else {
        return HddsError::HddsInvalidArgument;
    };

    let participant_ref = &*participant.cast::<Arc<Participant>>();
    out_handle.write(std::ptr::null());

    match unsafe { participant_ref.register_type_from_type_support(distro, type_support) } {
        Ok(handle) => {
            let raw: *const TypeObjectHandle = Arc::into_raw(handle);
            out_handle.write(raw.cast::<HddsTypeObject>());
            HddsError::HddsOk
        }
        Err(err) => map_rosidl_error(&err),
    }
}

/// Release a type object handle.
///
/// # Safety
/// - `handle` must be a valid handle from `hdds_participant_register_type_support`, or NULL.
#[cfg(feature = "xtypes")]
#[no_mangle]
pub unsafe extern "C" fn hdds_type_object_release(handle: *const HddsTypeObject) {
    if !handle.is_null() {
        let _ = Arc::from_raw(handle.cast::<TypeObjectHandle>());
    }
}

/// Get the type hash from a type object handle.
///
/// # Safety
/// - `handle` must be a valid handle from `hdds_participant_register_type_support`.
/// - `out_value` must point to a buffer of at least `value_len` bytes.
#[cfg(feature = "xtypes")]
#[no_mangle]
pub unsafe extern "C" fn hdds_type_object_hash(
    handle: *const HddsTypeObject,
    out_version: *mut u8,
    out_value: *mut u8,
    value_len: usize,
) -> HddsError {
    if handle.is_null() || out_value.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    if value_len < ROS_HASH_SIZE {
        return HddsError::HddsInvalidArgument;
    }

    let arc = Arc::from_raw(handle.cast::<TypeObjectHandle>());
    if !out_version.is_null() {
        *out_version = arc.ros_hash_version;
    }
    ptr::copy_nonoverlapping(arc.ros_hash.as_ref().as_ptr(), out_value, ROS_HASH_SIZE);
    let _ = Arc::into_raw(arc);
    HddsError::HddsOk
}

/// Get HDDS library version string
///
/// # Safety
/// The returned pointer is valid for the lifetime of the process (static storage).
#[no_mangle]
pub unsafe extern "C" fn hdds_version() -> *const c_char {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr().cast::<c_char>()
}

/// Create a `DataWriter` for a topic
///
/// # Safety
/// - `participant` must be a valid pointer returned from `hdds_participant_create`
/// - `topic_name` must be a valid null-terminated C string
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_create(
    participant: *mut HddsParticipant,
    topic_name: *const c_char,
) -> *mut HddsDataWriter {
    if participant.is_null() || topic_name.is_null() {
        return ptr::null_mut();
    }

    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return ptr::null_mut();
    };

    let participant_ref = &*participant.cast::<Arc<Participant>>();

    let Ok(writer) = participant_ref.create_writer::<BytePayload>(topic_str, QoS::default()) else {
        return ptr::null_mut();
    };

    Box::into_raw(Box::new(writer)).cast::<HddsDataWriter>()
}

/// Write data to a topic
///
/// # Safety
/// - `writer` must be a valid pointer returned from `hdds_writer_create`
/// - `data` must point to valid memory of at least `len` bytes
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_write(
    writer: *mut HddsDataWriter,
    data: *const c_void,
    len: usize,
) -> HddsError {
    if writer.is_null() || data.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let writer_ref = &*writer.cast::<DataWriter<BytePayload>>();
    let data_slice = std::slice::from_raw_parts(data.cast::<u8>(), len);

    let payload = BytePayload {
        data: data_slice.to_vec(),
    };

    match writer_ref.write(&payload) {
        Ok(()) => HddsError::HddsOk,
        Err(_) => HddsError::HddsOperationFailed,
    }
}

/// Destroy a `DataWriter`
///
/// # Safety
/// - `writer` must be a valid pointer returned from `hdds_writer_create`
/// - Must not be called more than once with the same pointer
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_destroy(writer: *mut HddsDataWriter) {
    if !writer.is_null() {
        let _ = Box::from_raw(writer.cast::<DataWriter<BytePayload>>());
    }
}

/// Create a `DataWriter` for a topic with custom QoS
///
/// # Safety
/// - `participant` must be a valid pointer returned from `hdds_participant_create`
/// - `topic_name` must be a valid null-terminated C string
/// - `qos` must be a valid pointer returned from `hdds_qos_*` functions (or NULL for default)
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_create_with_qos(
    participant: *mut HddsParticipant,
    topic_name: *const c_char,
    qos: *const HddsQoS,
) -> *mut HddsDataWriter {
    if participant.is_null() || topic_name.is_null() {
        return ptr::null_mut();
    }

    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return ptr::null_mut();
    };

    let participant_ref = &*participant.cast::<Arc<Participant>>();

    // Use provided QoS or default
    let qos_value = if qos.is_null() {
        QoS::default()
    } else {
        (*qos.cast::<QoS>()).clone()
    };

    let Ok(writer) = participant_ref.create_writer::<BytePayload>(topic_str, qos_value) else {
        return ptr::null_mut();
    };

    Box::into_raw(Box::new(writer)).cast::<HddsDataWriter>()
}

/// Create a `DataWriter` for a topic with custom QoS and explicit type name.
///
/// The `type_name` is announced via SEDP and must match the remote endpoint's
/// type name for topic matching (e.g. `"P_Mount_PSM::C_Rotational_Mount_setPosition"`).
/// If `type_name` is NULL, falls back to the default `"RawBytes"` type name.
///
/// # Safety
/// - `participant` must be a valid pointer returned from `hdds_participant_create`
/// - `topic_name` must be a valid null-terminated C string
/// - `type_name` must be a valid null-terminated C string (or NULL for default)
/// - `qos` must be a valid pointer returned from `hdds_qos_*` functions (or NULL for default)
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_create_with_type(
    participant: *mut HddsParticipant,
    topic_name: *const c_char,
    type_name: *const c_char,
    qos: *const HddsQoS,
) -> *mut HddsDataWriter {
    if participant.is_null() || topic_name.is_null() {
        return ptr::null_mut();
    }

    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return ptr::null_mut();
    };

    let participant_ref = &*participant.cast::<Arc<Participant>>();

    let qos_value = if qos.is_null() {
        QoS::default()
    } else {
        (*qos.cast::<QoS>()).clone()
    };

    // If type_name is provided, use create_writer_with_type for SEDP type matching
    if !type_name.is_null() {
        if let Ok(type_str) = CStr::from_ptr(type_name).to_str() {
            if !type_str.is_empty() {
                log::info!(
                    "[HDDS-C] Creating writer topic='{}' type='{}'",
                    topic_str,
                    type_str
                );
                let Ok(writer) = participant_ref
                    .create_writer_with_type::<BytePayload>(topic_str, qos_value, type_str, None)
                else {
                    return ptr::null_mut();
                };
                return Box::into_raw(Box::new(writer)).cast::<HddsDataWriter>();
            }
        }
    }

    // Fallback: no type override
    let Ok(writer) = participant_ref.create_writer::<BytePayload>(topic_str, qos_value) else {
        return ptr::null_mut();
    };

    Box::into_raw(Box::new(writer)).cast::<HddsDataWriter>()
}

/// Create a `DataReader` for a topic
///
/// # Safety
/// - `participant` must be a valid pointer returned from `hdds_participant_create`
/// - `topic_name` must be a valid null-terminated C string
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_create(
    participant: *mut HddsParticipant,
    topic_name: *const c_char,
) -> *mut HddsDataReader {
    if participant.is_null() || topic_name.is_null() {
        return ptr::null_mut();
    }

    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return ptr::null_mut();
    };

    let participant_ref = &*participant.cast::<Arc<Participant>>();

    let Ok(reader) = participant_ref.create_reader::<BytePayload>(topic_str, QoS::default()) else {
        return ptr::null_mut();
    };

    Box::into_raw(Box::new(reader)).cast::<HddsDataReader>()
}

/// Create a `DataReader` for a topic with custom QoS
///
/// # Safety
/// - `participant` must be a valid pointer returned from `hdds_participant_create`
/// - `topic_name` must be a valid null-terminated C string
/// - `qos` must be a valid pointer returned from `hdds_qos_*` functions (or NULL for default)
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_create_with_qos(
    participant: *mut HddsParticipant,
    topic_name: *const c_char,
    qos: *const HddsQoS,
) -> *mut HddsDataReader {
    if participant.is_null() || topic_name.is_null() {
        return ptr::null_mut();
    }

    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return ptr::null_mut();
    };

    let participant_ref = &*participant.cast::<Arc<Participant>>();

    // Use provided QoS or default
    let qos_value = if qos.is_null() {
        QoS::default()
    } else {
        (*qos.cast::<QoS>()).clone()
    };

    let Ok(reader) = participant_ref.create_reader::<BytePayload>(topic_str, qos_value) else {
        return ptr::null_mut();
    };

    Box::into_raw(Box::new(reader)).cast::<HddsDataReader>()
}

/// Create a `DataReader` for a topic with custom QoS and explicit type name.
///
/// The `type_name` is announced via SEDP and must match the remote endpoint's
/// type name for topic matching (e.g. `"P_Mount_PSM::C_Rotational_Mount_setPosition"`).
/// If `type_name` is NULL, falls back to the default `"RawBytes"` type name.
///
/// # Safety
/// - `participant` must be a valid pointer returned from `hdds_participant_create`
/// - `topic_name` must be a valid null-terminated C string
/// - `type_name` must be a valid null-terminated C string (or NULL for default)
/// - `qos` must be a valid pointer returned from `hdds_qos_*` functions (or NULL for default)
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_create_with_type(
    participant: *mut HddsParticipant,
    topic_name: *const c_char,
    type_name: *const c_char,
    qos: *const HddsQoS,
) -> *mut HddsDataReader {
    if participant.is_null() || topic_name.is_null() {
        return ptr::null_mut();
    }

    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return ptr::null_mut();
    };

    let participant_ref = &*participant.cast::<Arc<Participant>>();

    let qos_value = if qos.is_null() {
        QoS::default()
    } else {
        (*qos.cast::<QoS>()).clone()
    };

    // If type_name is provided, use create_reader_with_type for SEDP type matching
    if !type_name.is_null() {
        if let Ok(type_str) = CStr::from_ptr(type_name).to_str() {
            if !type_str.is_empty() {
                log::info!(
                    "[HDDS-C] Creating reader topic='{}' type='{}'",
                    topic_str,
                    type_str
                );
                let Ok(reader) = participant_ref
                    .create_reader_with_type::<BytePayload>(topic_str, qos_value, type_str, None)
                else {
                    return ptr::null_mut();
                };
                return Box::into_raw(Box::new(reader)).cast::<HddsDataReader>();
            }
        }
    }

    // Fallback: no type override
    let Ok(reader) = participant_ref.create_reader::<BytePayload>(topic_str, qos_value) else {
        return ptr::null_mut();
    };

    Box::into_raw(Box::new(reader)).cast::<HddsDataReader>()
}

/// Take data from a topic (non-blocking)
///
/// # Safety
/// - `reader` must be a valid pointer returned from `hdds_reader_create`
/// - `data_out` must point to a valid buffer of at least `max_len` bytes
/// - `len_out` must be a valid pointer to write the actual data length
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_take(
    reader: *mut HddsDataReader,
    data_out: *mut c_void,
    max_len: usize,
    len_out: *mut usize,
) -> HddsError {
    if reader.is_null() || data_out.is_null() || len_out.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let reader_ref = &*reader.cast::<DataReader<BytePayload>>();

    match reader_ref.take() {
        Ok(Some(payload)) => {
            let required = payload.data.len();
            *len_out = required;
            if required > max_len {
                return HddsError::HddsOutOfMemory;
            }

            std::ptr::copy_nonoverlapping(payload.data.as_ptr(), data_out.cast::<u8>(), required);
            HddsError::HddsOk
        }
        Ok(None) => HddsError::HddsNotFound,
        Err(_) => HddsError::HddsOperationFailed,
    }
}

/// Destroy a `DataReader`
///
/// # Safety
/// - `reader` must be a valid pointer returned from `hdds_reader_create`
/// - Must not be called more than once with the same pointer
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_destroy(reader: *mut HddsDataReader) {
    if !reader.is_null() {
        let _ = Box::from_raw(reader.cast::<DataReader<BytePayload>>());
    }
}

/// Get the status condition associated with a reader.
///
/// # Safety
/// - `reader` must be a valid handle from `hdds_reader_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_get_status_condition(
    reader: *mut HddsDataReader,
) -> *const HddsStatusCondition {
    if reader.is_null() {
        return ptr::null();
    }

    let reader_ref = &*reader.cast::<DataReader<BytePayload>>();
    let condition = reader_ref.get_status_condition();
    let raw = Arc::into_raw(condition.clone()) as *const HddsStatusCondition;
    status_registry_add_handle(raw, condition);
    raw
}

/// Release a previously acquired status condition.
///
/// # Safety
/// - `condition` must be a valid handle from `hdds_reader_get_status_condition`.
#[no_mangle]
pub unsafe extern "C" fn hdds_status_condition_release(condition: *const HddsStatusCondition) {
    if status_registry_release(condition) {
        let _ = Arc::from_raw(condition.cast::<StatusCondition>());
    }
}

/// Create a new guard condition.
///
/// # Safety
/// The returned handle must be released with `hdds_guard_condition_release`.
#[no_mangle]
pub unsafe extern "C" fn hdds_guard_condition_create() -> *const HddsGuardCondition {
    let guard = Arc::new(GuardCondition::new());
    let raw = Arc::into_raw(guard.clone()) as *const HddsGuardCondition;
    guard_registry_add_handle(raw, guard);
    raw
}

/// Release a guard condition.
///
/// # Safety
/// - `condition` must be a valid handle from `hdds_guard_condition_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_guard_condition_release(condition: *const HddsGuardCondition) {
    if guard_registry_release(condition) {
        let _ = Arc::from_raw(condition.cast::<GuardCondition>());
    }
}

/// Set a guard condition's trigger value.
///
/// # Safety
/// - `condition` must be a valid handle from `hdds_guard_condition_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_guard_condition_set_trigger(
    condition: *const HddsGuardCondition,
    active: bool,
) {
    let Some(guard) = guard_registry_clone(condition) else {
        return;
    };
    guard.set_trigger_value(active);
}

/// Read a guard condition's current trigger value without modifying it.
///
/// # Safety
/// - `condition` must be a valid handle from `hdds_guard_condition_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_guard_condition_get_trigger(
    condition: *const HddsGuardCondition,
) -> bool {
    let Some(guard) = guard_registry_clone(condition) else {
        return false;
    };
    guard.get_trigger_value()
}

/// Create a waitset.
///
/// # Safety
/// The returned handle must be released with `hdds_waitset_destroy`.
#[no_mangle]
pub unsafe extern "C" fn hdds_waitset_create() -> *mut HddsWaitSet {
    Box::into_raw(Box::new(ForeignWaitSet::new())) as *mut HddsWaitSet
}

/// Destroy a waitset.
///
/// # Safety
/// - `waitset` must be a valid handle from `hdds_waitset_create`, or NULL (no-op).
#[no_mangle]
pub unsafe extern "C" fn hdds_waitset_destroy(waitset: *mut HddsWaitSet) {
    if !waitset.is_null() {
        let _ = Box::from_raw(waitset.cast::<ForeignWaitSet>());
    }
}

/// Attach a status condition to a waitset.
///
/// # Safety
/// - `waitset` must be a valid handle from `hdds_waitset_create`.
/// - `condition` must be a valid handle from `hdds_reader_get_status_condition`.
#[no_mangle]
pub unsafe extern "C" fn hdds_waitset_attach_status_condition(
    waitset: *mut HddsWaitSet,
    condition: *const HddsStatusCondition,
) -> HddsError {
    if waitset.is_null() || condition.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let waitset_ref = &*waitset.cast::<ForeignWaitSet>();
    let Some(clone) = status_registry_clone(condition) else {
        return HddsError::HddsInvalidArgument;
    };

    match waitset_ref.attach_status(clone, condition.cast()) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => err.into(),
    }
}

/// Attach a guard condition to a waitset.
///
/// # Safety
/// - `waitset` must be a valid handle from `hdds_waitset_create`.
/// - `condition` must be a valid handle from `hdds_guard_condition_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_waitset_attach_guard_condition(
    waitset: *mut HddsWaitSet,
    condition: *const HddsGuardCondition,
) -> HddsError {
    if waitset.is_null() || condition.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let waitset_ref = &*waitset.cast::<ForeignWaitSet>();
    let Some(clone) = guard_registry_clone(condition) else {
        return HddsError::HddsInvalidArgument;
    };

    match waitset_ref.attach_guard(clone, condition.cast()) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => err.into(),
    }
}

/// Detach a condition (status or guard) from a waitset.
///
/// # Safety
/// - `waitset` must be a valid handle from `hdds_waitset_create`.
/// - `condition` must be a handle previously attached to this waitset.
#[no_mangle]
pub unsafe extern "C" fn hdds_waitset_detach_condition(
    waitset: *mut HddsWaitSet,
    condition: *const c_void,
) -> HddsError {
    if waitset.is_null() || condition.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let waitset_ref = &*waitset.cast::<ForeignWaitSet>();
    match waitset_ref.detach(condition) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => err.into(),
    }
}

/// Wait for any attached condition to trigger.
///
/// # Safety
/// - `waitset` must be a valid handle from `hdds_waitset_create`.
/// - `out_conditions` must point to an array of at least `max_conditions` pointers.
/// - `out_len` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn hdds_waitset_wait(
    waitset: *mut HddsWaitSet,
    timeout_ns: i64,
    out_conditions: *mut *const c_void,
    max_conditions: usize,
    out_len: *mut usize,
) -> HddsError {
    if waitset.is_null() || out_conditions.is_null() || out_len.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    *out_len = 0;

    let waitset_ref = &*waitset.cast::<ForeignWaitSet>();
    let timeout = if timeout_ns < 0 {
        None
    } else {
        match u64::try_from(timeout_ns) {
            Ok(nanos) => Some(Duration::from_nanos(nanos)),
            Err(_) => None,
        }
    };

    let triggered = match waitset_ref.wait(timeout) {
        Ok(list) => list,
        Err(err) => return err.into(),
    };

    if triggered.len() > max_conditions {
        return HddsError::HddsOperationFailed;
    }

    for (idx, ptr_value) in triggered.iter().enumerate() {
        *out_conditions.add(idx) = *ptr_value;
    }

    *out_len = triggered.len();
    HddsError::HddsOk
}

// =============================================================================
// RMW (ROS Middleware) API - only available with "rmw" feature
// =============================================================================

/// Create a new rmw context.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_create(name: *const c_char) -> *mut HddsRmwContext {
    if name.is_null() {
        return ptr::null_mut();
    }

    let Ok(name_str) = CStr::from_ptr(name).to_str() else {
        return ptr::null_mut();
    };

    match ForeignRmwContext::create(name_str) {
        Ok(ctx) => {
            #[allow(clippy::arc_with_non_send_sync)]
            let arc = Arc::new(ctx);
            Box::into_raw(Box::new(arc)).cast::<HddsRmwContext>()
        }
        Err(_err) => ptr::null_mut(),
    }
}

/// Destroy an rmw context.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_destroy(ctx: *mut HddsRmwContext) {
    if !ctx.is_null() {
        let _ = Box::from_raw(ctx.cast::<Arc<ForeignRmwContext>>());
    }
}

/// Get the graph guard key associated with the context.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_graph_guard_key(ctx: *mut HddsRmwContext) -> u64 {
    if ctx.is_null() {
        return 0;
    }
    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    ctx_ref.as_ref().graph_guard_key()
}

/// Copy the participant GUID prefix (12 bytes) into `out_prefix`.
///
/// Returns the participant's stable GUID prefix, suitable for building
/// cross-process unique GIDs (rmw_gid_t).
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_guid_prefix(
    ctx: *mut HddsRmwContext,
    out_prefix: *mut u8,
) -> HddsError {
    if ctx.is_null() || out_prefix.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    let prefix = ctx_ref.guid_prefix();
    std::ptr::copy_nonoverlapping(prefix.as_ptr(), out_prefix, 12);
    HddsError::HddsOk
}

/// Get the graph guard condition associated with the context.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_graph_guard_condition(
    ctx: *mut HddsRmwContext,
) -> *const HddsGuardCondition {
    if ctx.is_null() {
        return ptr::null();
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    let guard = ctx_ref.as_ref().graph_guard_condition();
    let raw = Arc::into_raw(guard.clone());
    guard_registry_add_handle(raw.cast::<HddsGuardCondition>(), guard);
    ctx_ref.as_ref().register_graph_guard_ptr(raw);
    raw.cast::<HddsGuardCondition>()
}

/// Attach a guard condition to the rmw waitset.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_attach_guard_condition(
    ctx: *mut HddsRmwContext,
    guard: *const HddsGuardCondition,
    out_key: *mut u64,
) -> HddsError {
    if ctx.is_null() || guard.is_null() || out_key.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    let Some(guard_clone) = guard_registry_clone(guard) else {
        return HddsError::HddsInvalidArgument;
    };

    match ctx_ref
        .as_ref()
        .attach_guard(guard_clone, guard.cast::<GuardCondition>())
    {
        Ok(key) => {
            *out_key = key;
            HddsError::HddsOk
        }
        Err(err) => map_api_error(err),
    }
}

/// Attach a status condition to the rmw waitset.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_attach_status_condition(
    ctx: *mut HddsRmwContext,
    status: *const HddsStatusCondition,
    out_key: *mut u64,
) -> HddsError {
    if ctx.is_null() || status.is_null() || out_key.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    let Some(status_clone) = status_registry_clone(status) else {
        return HddsError::HddsInvalidArgument;
    };

    match ctx_ref
        .as_ref()
        .attach_status(status_clone, status.cast::<StatusCondition>())
    {
        Ok(key) => {
            *out_key = key;
            HddsError::HddsOk
        }
        Err(err) => map_api_error(err),
    }
}

/// Attach a reader to the rmw waitset (convenience helper).
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_attach_reader(
    ctx: *mut HddsRmwContext,
    reader: *mut HddsDataReader,
    out_key: *mut u64,
) -> HddsError {
    if ctx.is_null() || reader.is_null() || out_key.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    let reader_ptr = reader.cast::<c_void>();
    let status_arc = match ctx_ref.status_for_reader(reader_ptr) {
        Ok(status) => status,
        Err(err) => return map_api_error(err),
    };
    let raw_status = Arc::as_ptr(&status_arc);

    match ctx_ref.attach_reader(reader_ptr, status_arc, raw_status) {
        Ok(key) => {
            *out_key = key;
            HddsError::HddsOk
        }
        Err(err) => map_api_error(err),
    }
}

/// Create a DataReader bound to the rmw context participant.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_create_reader(
    ctx: *mut HddsRmwContext,
    topic_name: *const c_char,
    out_reader: *mut *mut HddsDataReader,
) -> HddsError {
    if ctx.is_null() || topic_name.is_null() || out_reader.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    match ctx_ref.create_reader_raw(topic_str) {
        Ok(reader_ptr) => {
            out_reader.write(reader_ptr.cast::<HddsDataReader>());
            HddsError::HddsOk
        }
        Err(err) => map_api_error(err),
    }
}

#[cfg(feature = "rmw")]
/// Create a DataReader bound to the rmw context participant with custom QoS.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_create_reader_with_qos(
    ctx: *mut HddsRmwContext,
    topic_name: *const c_char,
    qos: *const HddsQoS,
    out_reader: *mut *mut HddsDataReader,
) -> HddsError {
    if ctx.is_null() || topic_name.is_null() || out_reader.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let qos_ref = if qos.is_null() {
        QoS::default()
    } else {
        (*qos.cast::<QoS>()).clone()
    };

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    match ctx_ref.create_reader_raw_with_qos(topic_str, &qos_ref) {
        Ok(reader_ptr) => {
            out_reader.write(reader_ptr.cast::<HddsDataReader>());
            HddsError::HddsOk
        }
        Err(err) => map_api_error(err),
    }
}

/// Destroy a DataReader created via the rmw context.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_destroy_reader(
    ctx: *mut HddsRmwContext,
    reader: *mut HddsDataReader,
) -> HddsError {
    if ctx.is_null() || reader.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    match ctx_ref.destroy_reader_raw(reader.cast::<c_void>()) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => map_api_error(err),
    }
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_create_writer(
    ctx: *mut HddsRmwContext,
    topic_name: *const c_char,
    out_writer: *mut *mut HddsDataWriter,
) -> HddsError {
    if ctx.is_null() || topic_name.is_null() || out_writer.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    match ctx_ref.create_writer_raw(topic_str) {
        Ok(writer_ptr) => {
            out_writer.write(writer_ptr.cast::<HddsDataWriter>());
            HddsError::HddsOk
        }
        Err(err) => map_api_error(err),
    }
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_create_writer_with_qos(
    ctx: *mut HddsRmwContext,
    topic_name: *const c_char,
    qos: *const HddsQoS,
    out_writer: *mut *mut HddsDataWriter,
) -> HddsError {
    if ctx.is_null() || topic_name.is_null() || out_writer.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let qos_ref = if qos.is_null() {
        QoS::default()
    } else {
        (*qos.cast::<QoS>()).clone()
    };

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    match ctx_ref.create_writer_raw_with_qos(topic_str, &qos_ref) {
        Ok(writer_ptr) => {
            out_writer.write(writer_ptr.cast::<HddsDataWriter>());
            HddsError::HddsOk
        }
        Err(err) => map_api_error(err),
    }
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_bind_topic_type(
    ctx: *mut HddsRmwContext,
    topic_name: *const c_char,
    type_support: *const rosidl_message_type_support_t,
) -> HddsError {
    if ctx.is_null() || topic_name.is_null() || type_support.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    match ctx_ref.bind_topic_type(topic_str, type_support) {
        Ok(()) => HddsError::HddsOk,
        Err(ApiError::Config) => HddsError::HddsOk,
        Err(ApiError::Unsupported) => HddsError::HddsOk,
        Err(err) => map_api_error(err),
    }
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_destroy_writer(
    ctx: *mut HddsRmwContext,
    writer: *mut HddsDataWriter,
) -> HddsError {
    if ctx.is_null() || writer.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    match ctx_ref.destroy_writer_raw(writer.cast::<c_void>()) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => map_api_error(err),
    }
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_register_node(
    ctx: *mut HddsRmwContext,
    node_name: *const c_char,
    node_namespace: *const c_char,
    node_enclave: *const c_char,
) -> HddsError {
    if ctx.is_null() || node_name.is_null() || node_namespace.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let Ok(name_str) = CStr::from_ptr(node_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let Ok(namespace_str) = CStr::from_ptr(node_namespace).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let enclave_str = if node_enclave.is_null() {
        ""
    } else {
        match CStr::from_ptr(node_enclave).to_str() {
            Ok(value) => value,
            Err(_) => return HddsError::HddsInvalidArgument,
        }
    };

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    ctx_ref.register_node_info(name_str, namespace_str, enclave_str);
    HddsError::HddsOk
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_unregister_node(
    ctx: *mut HddsRmwContext,
    node_name: *const c_char,
    node_namespace: *const c_char,
) -> HddsError {
    if ctx.is_null() || node_name.is_null() || node_namespace.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let Ok(name_str) = CStr::from_ptr(node_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let Ok(namespace_str) = CStr::from_ptr(node_namespace).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    ctx_ref.unregister_node_info(name_str, namespace_str);
    HddsError::HddsOk
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_register_publisher_endpoint(
    ctx: *mut HddsRmwContext,
    node_name: *const c_char,
    node_namespace: *const c_char,
    topic_name: *const c_char,
    type_support: *const rosidl_message_type_support_t,
    endpoint_gid: *const u8,
    qos_profile: *const HddsRmwQosProfile,
) -> HddsError {
    if ctx.is_null() || node_name.is_null() || node_namespace.is_null() || topic_name.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let Ok(name_str) = CStr::from_ptr(node_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let Ok(namespace_str) = CStr::from_ptr(node_namespace).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let mut gid = [0u8; HDDS_RMW_GID_SIZE];
    if !endpoint_gid.is_null() {
        let src = slice::from_raw_parts(endpoint_gid, gid.len());
        gid.copy_from_slice(src);
    }

    let qos = if qos_profile.is_null() {
        hdds::rmw::graph::EndpointQos::default()
    } else {
        hdds::rmw::graph::EndpointQos::from(*qos_profile)
    };

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    match ctx_ref.register_publisher_endpoint(
        name_str,
        namespace_str,
        topic_str,
        type_support,
        gid,
        qos,
    ) {
        Ok(()) => HddsError::HddsOk,
        Err(ApiError::Config) => HddsError::HddsOk,
        Err(ApiError::Unsupported) => HddsError::HddsOk,
        Err(err) => map_api_error(err),
    }
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_unregister_publisher_endpoint(
    ctx: *mut HddsRmwContext,
    node_name: *const c_char,
    node_namespace: *const c_char,
    topic_name: *const c_char,
    endpoint_gid: *const u8,
) -> HddsError {
    if ctx.is_null() || node_name.is_null() || node_namespace.is_null() || topic_name.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let Ok(name_str) = CStr::from_ptr(node_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let Ok(namespace_str) = CStr::from_ptr(node_namespace).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let mut gid = [0u8; HDDS_RMW_GID_SIZE];
    if !endpoint_gid.is_null() {
        let src = slice::from_raw_parts(endpoint_gid, gid.len());
        gid.copy_from_slice(src);
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    ctx_ref.unregister_publisher_endpoint(name_str, namespace_str, topic_str, &gid);
    HddsError::HddsOk
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_register_subscription_endpoint(
    ctx: *mut HddsRmwContext,
    node_name: *const c_char,
    node_namespace: *const c_char,
    topic_name: *const c_char,
    type_support: *const rosidl_message_type_support_t,
    endpoint_gid: *const u8,
    qos_profile: *const HddsRmwQosProfile,
) -> HddsError {
    if ctx.is_null() || node_name.is_null() || node_namespace.is_null() || topic_name.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let Ok(name_str) = CStr::from_ptr(node_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let Ok(namespace_str) = CStr::from_ptr(node_namespace).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let mut gid = [0u8; HDDS_RMW_GID_SIZE];
    if !endpoint_gid.is_null() {
        let src = slice::from_raw_parts(endpoint_gid, gid.len());
        gid.copy_from_slice(src);
    }

    let qos = if qos_profile.is_null() {
        hdds::rmw::graph::EndpointQos::default()
    } else {
        hdds::rmw::graph::EndpointQos::from(*qos_profile)
    };

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    match ctx_ref.register_subscription_endpoint(
        name_str,
        namespace_str,
        topic_str,
        type_support,
        gid,
        qos,
    ) {
        Ok(()) => HddsError::HddsOk,
        Err(ApiError::Config) => HddsError::HddsOk,
        Err(ApiError::Unsupported) => HddsError::HddsOk,
        Err(err) => map_api_error(err),
    }
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_unregister_subscription_endpoint(
    ctx: *mut HddsRmwContext,
    node_name: *const c_char,
    node_namespace: *const c_char,
    topic_name: *const c_char,
    endpoint_gid: *const u8,
) -> HddsError {
    if ctx.is_null() || node_name.is_null() || node_namespace.is_null() || topic_name.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let Ok(name_str) = CStr::from_ptr(node_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let Ok(namespace_str) = CStr::from_ptr(node_namespace).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let mut gid = [0u8; HDDS_RMW_GID_SIZE];
    if !endpoint_gid.is_null() {
        let src = slice::from_raw_parts(endpoint_gid, gid.len());
        gid.copy_from_slice(src);
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    ctx_ref.unregister_subscription_endpoint(name_str, namespace_str, topic_str, &gid);
    HddsError::HddsOk
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_for_each_node(
    ctx: *mut HddsRmwContext,
    visitor: HddsNodeVisitor,
    user_data: *mut c_void,
    out_version: *mut u64,
    out_count: *mut usize,
) -> HddsError {
    if ctx.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    let mut error: Option<HddsError> = None;

    let (version, count) = ctx_ref.list_nodes_with(|name, namespace_| {
        if error.is_some() {
            return;
        }

        if let Some(cb) = visitor {
            let Ok(name_cstr) = CString::new(name) else {
                error = Some(HddsError::HddsInvalidArgument);
                return;
            };
            let Ok(namespace_cstr) = CString::new(namespace_) else {
                error = Some(HddsError::HddsInvalidArgument);
                return;
            };

            unsafe {
                cb(name_cstr.as_ptr(), namespace_cstr.as_ptr(), user_data);
            }
        }
    });

    if !out_version.is_null() {
        out_version.write(version);
    }

    if !out_count.is_null() {
        out_count.write(count);
    }

    if let Some(err) = error {
        err
    } else {
        HddsError::HddsOk
    }
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_for_each_node_with_enclave(
    ctx: *mut HddsRmwContext,
    visitor: HddsNodeEnclaveVisitor,
    user_data: *mut c_void,
    out_version: *mut u64,
    out_count: *mut usize,
) -> HddsError {
    if ctx.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    let mut error: Option<HddsError> = None;

    let (version, count) = ctx_ref.list_nodes_with_enclave(|name, namespace_, enclave| {
        if error.is_some() {
            return;
        }

        if let Some(cb) = visitor {
            let Ok(name_cstr) = CString::new(name) else {
                error = Some(HddsError::HddsInvalidArgument);
                return;
            };
            let Ok(namespace_cstr) = CString::new(namespace_) else {
                error = Some(HddsError::HddsInvalidArgument);
                return;
            };
            let Ok(enclave_cstr) = CString::new(enclave) else {
                error = Some(HddsError::HddsInvalidArgument);
                return;
            };

            unsafe {
                cb(
                    name_cstr.as_ptr(),
                    namespace_cstr.as_ptr(),
                    enclave_cstr.as_ptr(),
                    user_data,
                );
            }
        }
    });

    if !out_version.is_null() {
        out_version.write(version);
    }

    if !out_count.is_null() {
        out_count.write(count);
    }

    if let Some(err) = error {
        err
    } else {
        HddsError::HddsOk
    }
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_for_each_publisher_endpoint(
    ctx: *mut HddsRmwContext,
    node_name: *const c_char,
    node_namespace: *const c_char,
    visitor: HddsEndpointVisitor,
    user_data: *mut c_void,
    out_version: *mut u64,
    out_count: *mut usize,
) -> HddsError {
    if ctx.is_null() || node_name.is_null() || node_namespace.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    let Ok(name_str) = CStr::from_ptr(node_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let Ok(namespace_str) = CStr::from_ptr(node_namespace).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let mut error: Option<HddsError> = None;
    let visit_result = ctx_ref.visit_publishers_with(name_str, namespace_str, |endpoint| {
        if error.is_some() {
            return;
        }

        if let Some(cb) = visitor {
            let Ok(topic_cstr) = CString::new(endpoint.topic.as_str()) else {
                error = Some(HddsError::HddsInvalidArgument);
                return;
            };
            let type_name = normalize_ros_type_name(endpoint.type_name.as_str());
            let Ok(type_cstr) = CString::new(type_name.as_str()) else {
                error = Some(HddsError::HddsInvalidArgument);
                return;
            };

            let qos_profile = HddsRmwQosProfile::from(&endpoint.qos);
            unsafe {
                cb(
                    topic_cstr.as_ptr(),
                    type_cstr.as_ptr(),
                    endpoint.gid.as_ptr(),
                    &qos_profile,
                    user_data,
                );
            }
        }
    });

    match visit_result {
        Ok((version, count)) => {
            if !out_version.is_null() {
                out_version.write(version);
            }
            if !out_count.is_null() {
                out_count.write(count);
            }

            if let Some(err) = error {
                err
            } else {
                HddsError::HddsOk
            }
        }
        Err(err) => map_api_error(err),
    }
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_for_each_subscription_endpoint(
    ctx: *mut HddsRmwContext,
    node_name: *const c_char,
    node_namespace: *const c_char,
    visitor: HddsEndpointVisitor,
    user_data: *mut c_void,
    out_version: *mut u64,
    out_count: *mut usize,
) -> HddsError {
    if ctx.is_null() || node_name.is_null() || node_namespace.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    let Ok(name_str) = CStr::from_ptr(node_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let Ok(namespace_str) = CStr::from_ptr(node_namespace).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let mut error: Option<HddsError> = None;
    let visit_result = ctx_ref.visit_subscriptions_with(name_str, namespace_str, |endpoint| {
        if error.is_some() {
            return;
        }

        if let Some(cb) = visitor {
            let Ok(topic_cstr) = CString::new(endpoint.topic.as_str()) else {
                error = Some(HddsError::HddsInvalidArgument);
                return;
            };
            let type_name = normalize_ros_type_name(endpoint.type_name.as_str());
            let Ok(type_cstr) = CString::new(type_name.as_str()) else {
                error = Some(HddsError::HddsInvalidArgument);
                return;
            };

            let qos_profile = HddsRmwQosProfile::from(&endpoint.qos);
            unsafe {
                cb(
                    topic_cstr.as_ptr(),
                    type_cstr.as_ptr(),
                    endpoint.gid.as_ptr(),
                    &qos_profile,
                    user_data,
                );
            }
        }
    });

    match visit_result {
        Ok((version, count)) => {
            if !out_version.is_null() {
                out_version.write(version);
            }
            if !out_count.is_null() {
                out_count.write(count);
            }

            if let Some(err) = error {
                err
            } else {
                HddsError::HddsOk
            }
        }
        Err(err) => map_api_error(err),
    }
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_for_each_topic(
    ctx: *mut HddsRmwContext,
    visitor: Option<HddsTopicVisitor>,
    user_data: *mut c_void,
    out_version: *mut u64,
) -> HddsError {
    if ctx.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let Some(callback) = visitor else {
        return HddsError::HddsInvalidArgument;
    };

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    let mut status = HddsError::HddsOk;
    let version = ctx_ref.for_each_topic(|topic, type_name, writers, readers| {
        if status != HddsError::HddsOk {
            return;
        }

        let topic_c = match CString::new(topic) {
            Ok(value) => value,
            Err(_) => {
                status = HddsError::HddsInvalidArgument;
                return;
            }
        };

        let type_c = match CString::new(type_name) {
            Ok(value) => value,
            Err(_) => {
                status = HddsError::HddsInvalidArgument;
                return;
            }
        };

        unsafe {
            callback(
                topic_c.as_ptr(),
                type_c.as_ptr(),
                writers,
                readers,
                user_data,
            );
        }
    });

    if !out_version.is_null() {
        out_version.write(version);
    }

    status
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_for_each_user_locator(
    ctx: *mut HddsRmwContext,
    visitor: Option<HddsLocatorVisitor>,
    user_data: *mut c_void,
    out_count: *mut usize,
) -> HddsError {
    if ctx.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    let locators = ctx_ref.user_unicast_locators();
    if !out_count.is_null() {
        out_count.write(locators.len());
    }

    let Some(callback) = visitor else {
        return HddsError::HddsOk;
    };

    for locator in locators {
        let addr = locator.ip().to_string();
        let Ok(addr_cstr) = CString::new(addr.as_str()) else {
            return HddsError::HddsInvalidArgument;
        };
        callback(addr_cstr.as_ptr(), locator.port(), user_data);
    }

    HddsError::HddsOk
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_publish(
    ctx: *mut HddsRmwContext,
    writer: *mut HddsDataWriter,
    type_support: *const rosidl_message_type_support_t,
    ros_message: *const c_void,
) -> HddsError {
    if ctx.is_null() || writer.is_null() || type_support.is_null() || ros_message.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    let payload = match serialize_from_ros(type_support, ros_message) {
        Ok(p) => Some(p),
        Err(ApiError::Config) => None,
        Err(err) => return map_api_error(err),
    };

    if let Some(payload) = payload {
        match ctx_ref.publish_writer(writer.cast::<c_void>(), &payload) {
            Ok(()) => HddsError::HddsOk,
            Err(err) => map_api_error(err),
        }
    } else {
        HddsError::HddsOk
    }
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_publish_with_codec(
    ctx: *mut HddsRmwContext,
    writer: *mut HddsDataWriter,
    codec_kind: u8,
    ros_message: *const c_void,
) -> HddsError {
    if ctx.is_null() || writer.is_null() || ros_message.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let Some(codec) = Ros2CodecKind::try_from(codec_kind) else {
        return HddsError::HddsInvalidArgument;
    };

    if codec == Ros2CodecKind::None {
        return HddsError::HddsInvalidArgument;
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    match encode_special(codec, ros_message) {
        Ok(Some(payload)) => match ctx_ref.publish_writer(writer.cast(), &payload) {
            Ok(()) => HddsError::HddsOk,
            Err(err) => {
                // No subscribers or backpressure is not a hard error for rmw publish.
                if matches!(err, ApiError::WouldBlock) {
                    HddsError::HddsOk
                } else {
                    map_api_error(err)
                }
            }
        },
        Ok(None) => HddsError::HddsOperationFailed,
        Err(err) => map_api_error(err),
    }
}

/// Try to read from SHM ring buffer for a topic (inter-process fast path).
///
/// Returns OK with `*len_out > 0` if data was read from SHM.
/// Returns NOT_FOUND if no SHM data available (caller should fall back to RTPS).
///
/// # Safety
/// - `ctx` must be a valid `HddsRmwContext`
/// - `topic` must be a valid C string
/// - `data_out` must point to a buffer of at least `max_len` bytes
/// - `len_out` must be a valid pointer
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_shm_try_take(
    ctx: *mut HddsRmwContext,
    topic: *const c_char,
    data_out: *mut c_void,
    max_len: usize,
    len_out: *mut usize,
) -> HddsError {
    if ctx.is_null() || topic.is_null() || data_out.is_null() || len_out.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    let topic_str = match CStr::from_ptr(topic).to_str() {
        Ok(s) => s,
        Err(_) => return HddsError::HddsInvalidArgument,
    };

    let buf = std::slice::from_raw_parts_mut(data_out.cast::<u8>(), max_len);
    match ctx_ref.try_shm_take(topic_str, buf) {
        Some(len) => {
            *len_out = len;
            HddsError::HddsOk
        }
        None => {
            *len_out = 0;
            HddsError::HddsNotFound
        }
    }
}

/// Check if SHM data is available for a topic (non-blocking).
///
/// Returns `true` (1) if data is available, `false` (0) otherwise.
///
/// # Safety
/// - `ctx` must be a valid `HddsRmwContext`
/// - `topic` must be a valid C string
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_shm_has_data(
    ctx: *mut HddsRmwContext,
    topic: *const c_char,
) -> bool {
    if ctx.is_null() || topic.is_null() {
        return false;
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    let Ok(topic_str) = CStr::from_ptr(topic).to_str() else {
        return false;
    };

    ctx_ref.shm_has_data(topic_str)
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_deserialize_with_codec(
    codec_kind: u8,
    data: *const u8,
    data_len: usize,
    ros_message: *mut c_void,
) -> HddsError {
    if ros_message.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let Some(codec) = Ros2CodecKind::try_from(codec_kind) else {
        return HddsError::HddsInvalidArgument;
    };

    if codec == Ros2CodecKind::None {
        return HddsError::HddsInvalidArgument;
    }

    let slice = if data_len == 0 {
        &[]
    } else if data.is_null() {
        return HddsError::HddsInvalidArgument;
    } else {
        slice::from_raw_parts(data, data_len)
    };

    match decode_special(codec, slice, ros_message) {
        Ok(true) => HddsError::HddsOk,
        Ok(false) => HddsError::HddsOperationFailed,
        Err(err) => map_api_error(err),
    }
}

/// Check if a ROS2 type has a dynamic TypeDescriptor available.
/// Returns true if the type is supported for dynamic deserialization.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_has_type_descriptor(type_name: *const c_char) -> bool {
    if type_name.is_null() {
        return false;
    }

    let type_str = match CStr::from_ptr(type_name).to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };

    ros2_type_to_descriptor(type_str).is_some()
}

/// Deserialize CDR data to a ROS2 message using dynamic types.
/// Returns Ok if successful, InvalidArgument if type not supported.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_deserialize_dynamic(
    type_name: *const c_char,
    data: *const u8,
    data_len: usize,
    ros_message: *mut c_void,
) -> HddsError {
    if type_name.is_null() || ros_message.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let type_str = match CStr::from_ptr(type_name).to_str() {
        Ok(s) => s,
        Err(_) => return HddsError::HddsInvalidArgument,
    };

    let slice = if data_len == 0 {
        &[]
    } else if data.is_null() {
        return HddsError::HddsInvalidArgument;
    } else {
        slice::from_raw_parts(data, data_len)
    };

    match deserialize_dynamic_to_ros(type_str, slice, ros_message) {
        Ok(()) => HddsError::HddsOk,
        Err(_) => HddsError::HddsOperationFailed,
    }
}

/// Detach a condition previously attached to the rmw waitset.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_detach_condition(
    ctx: *mut HddsRmwContext,
    key: u64,
) -> HddsError {
    if ctx.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    match ctx_ref.detach_condition(key) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => map_api_error(err),
    }
}

/// Detach a reader previously attached to the rmw waitset.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_detach_reader(
    ctx: *mut HddsRmwContext,
    reader: *mut HddsDataReader,
) -> HddsError {
    if ctx.is_null() || reader.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    match ctx_ref.as_ref().detach_reader(reader.cast::<c_void>()) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => map_api_error(err),
    }
}

/// Wait for the rmw context waitset.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_wait(
    ctx: *mut HddsRmwContext,
    timeout_ns: i64,
    out_keys: *mut u64,
    out_conditions: *mut *const c_void,
    max_conditions: usize,
    out_len: *mut usize,
) -> HddsError {
    if ctx.is_null() || out_len.is_null() || out_keys.is_null() || out_conditions.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    *out_len = 0;

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    let ctx_ref = Arc::clone(ctx_ref);
    let timeout = if timeout_ns < 0 {
        None
    } else {
        match u64::try_from(timeout_ns) {
            Ok(nanos) => Some(Duration::from_nanos(nanos)),
            Err(_) => None,
        }
    };

    let hits = match ctx_ref.wait(timeout) {
        Ok(list) => list,
        Err(err) => return map_api_error(err),
    };

    if hits.len() > max_conditions {
        return HddsError::HddsOperationFailed;
    }

    for (idx, hit) in hits.iter().enumerate() {
        *out_keys.add(idx) = hit.key;
        *out_conditions.add(idx) = hit.condition_ptr;
    }

    *out_len = hits.len();
    HddsError::HddsOk
}

/// Wait for reader notifications and report guard hits.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_wait_readers(
    ctx: *mut HddsRmwContext,
    timeout_ns: i64,
    out_readers: *mut *mut HddsDataReader,
    max_readers: usize,
    out_len: *mut usize,
    out_guard_triggered: *mut bool,
) -> HddsError {
    if ctx.is_null() || out_readers.is_null() || out_len.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    if !out_guard_triggered.is_null() {
        *out_guard_triggered = false;
    }

    *out_len = 0;

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    let ctx_ref = Arc::clone(ctx_ref);
    let timeout = if timeout_ns < 0 {
        None
    } else {
        match u64::try_from(timeout_ns) {
            Ok(nanos) => Some(Duration::from_nanos(nanos)),
            Err(_) => None,
        }
    };

    let hits = match ctx_ref.wait(timeout) {
        Ok(list) => list,
        Err(err) => return map_api_error(err),
    };

    let mut reader_count = 0usize;

    for hit in hits {
        if hit.key == ctx_ref.graph_guard_key() {
            if !out_guard_triggered.is_null() {
                *out_guard_triggered = true;
            }
            continue;
        }

        if let Some(reader_ptr) = hit.reader_ptr {
            if reader_count >= max_readers {
                return HddsError::HddsOperationFailed;
            }
            *out_readers.add(reader_count) =
                reader_ptr.cast::<HddsDataReader>() as *mut HddsDataReader;
            reader_count += 1;
        }
    }

    *out_len = reader_count;
    HddsError::HddsOk
}

/// Create an rmw waitset bound to a context.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_waitset_create(ctx: *mut HddsRmwContext) -> *mut HddsRmwWaitSet {
    if ctx.is_null() {
        return ptr::null_mut();
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    let waitset = ForeignRmwWaitSet::new(Arc::clone(ctx_ref));
    Box::into_raw(Box::new(waitset)).cast::<HddsRmwWaitSet>()
}

/// Destroy an rmw waitset.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_waitset_destroy(waitset: *mut HddsRmwWaitSet) {
    if !waitset.is_null() {
        let boxed = Box::from_raw(waitset.cast::<ForeignRmwWaitSet>());
        boxed.detach_all();
    }
}

/// Attach a reader to an rmw waitset.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_waitset_attach_reader(
    waitset: *mut HddsRmwWaitSet,
    reader: *mut HddsDataReader,
) -> HddsError {
    if waitset.is_null() || reader.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let waitset_ref = &*waitset.cast::<ForeignRmwWaitSet>();
    match waitset_ref.attach_reader(reader.cast::<c_void>()) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => map_api_error(err),
    }
}

/// Detach a reader from an rmw waitset.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_waitset_detach_reader(
    waitset: *mut HddsRmwWaitSet,
    reader: *mut HddsDataReader,
) -> HddsError {
    if waitset.is_null() || reader.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let waitset_ref = &*waitset.cast::<ForeignRmwWaitSet>();
    match waitset_ref.detach_reader(reader.cast::<c_void>()) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => map_api_error(err),
    }
}

/// Wait on an rmw waitset and report triggered readers and guard state.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_waitset_wait(
    waitset: *mut HddsRmwWaitSet,
    timeout_ns: i64,
    out_readers: *mut *mut HddsDataReader,
    max_readers: usize,
    out_len: *mut usize,
    out_guard_triggered: *mut bool,
) -> HddsError {
    // Allow out_readers to be NULL when max_readers is 0 (no subscriptions case)
    if waitset.is_null() || out_len.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    if out_readers.is_null() && max_readers > 0 {
        return HddsError::HddsInvalidArgument;
    }

    if !out_guard_triggered.is_null() {
        *out_guard_triggered = false;
    }

    *out_len = 0;

    let waitset_ref = &*waitset.cast::<ForeignRmwWaitSet>();
    let timeout = if timeout_ns < 0 {
        None
    } else {
        match u64::try_from(timeout_ns) {
            Ok(nanos) => Some(Duration::from_nanos(nanos)),
            Err(_) => None,
        }
    };

    let (readers, guard_hit) = match waitset_ref.wait(timeout) {
        Ok(result) => result,
        Err(err) => return map_api_error(err),
    };

    if readers.len() > max_readers {
        return HddsError::HddsOperationFailed;
    }

    for (idx, reader_ptr) in readers.iter().enumerate() {
        *out_readers.add(idx) = (*reader_ptr).cast::<HddsDataReader>() as *mut HddsDataReader;
    }

    if !out_guard_triggered.is_null() {
        *out_guard_triggered = guard_hit;
    }

    *out_len = readers.len();
    HddsError::HddsOk
}

#[cfg(test)]
mod tests {
    #![allow(clippy::all)]
    use super::*;
    use std::ffi::CString;
    use std::ptr;

    #[cfg(feature = "xtypes")]
    use hdds::core::types::ROS_HASH_SIZE;
    #[cfg(feature = "xtypes")]
    use hdds::xtypes::{
        rosidl_message_type_support_t, rosidl_type_hash_t,
        rosidl_typesupport_introspection_c__MessageMember,
        rosidl_typesupport_introspection_c__MessageMembers,
    };

    #[cfg(feature = "xtypes")]
    #[allow(clippy::cast_possible_truncation)]
    const fn hash_bytes() -> [u8; ROS_HASH_SIZE] {
        let mut arr = [0u8; ROS_HASH_SIZE];
        let mut i = 0;
        while i < ROS_HASH_SIZE {
            arr[i] = i as u8;
            i += 1;
        }
        arr
    }

    #[cfg(feature = "xtypes")]
    const HASH_BYTES: [u8; ROS_HASH_SIZE] = hash_bytes();

    #[cfg(feature = "xtypes")]
    static HASH: rosidl_type_hash_t = rosidl_type_hash_t {
        version: 1,
        value: hash_bytes(),
    };

    #[cfg(feature = "xtypes")]
    unsafe extern "C" fn stub_hash(
        _: *const rosidl_message_type_support_t,
    ) -> *const rosidl_type_hash_t {
        std::ptr::from_ref(&HASH)
    }

    #[test]
    fn test_participant_create_destroy() {
        unsafe {
            let name = CString::new("test_participant").unwrap();
            let participant = hdds_participant_create(name.as_ptr());
            assert!(!participant.is_null());
            hdds_participant_destroy(participant);
        }
    }

    #[cfg(feature = "rmw")]
    #[test]
    fn test_rmw_context_graph_guard_wait() {
        unsafe {
            let name = CString::new("rmw_ctx_guard").unwrap();
            let ctx = hdds_rmw_context_create(name.as_ptr());
            assert!(!ctx.is_null());

            let guard = hdds_rmw_context_graph_guard_condition(ctx);
            assert!(!guard.is_null());

            hdds_guard_condition_set_trigger(guard, true);

            let mut keys = [0u64; 4];
            let mut ptrs = [ptr::null(); 4];
            let mut len = 0usize;

            let ret = hdds_rmw_context_wait(
                ctx,
                1_000_000,
                keys.as_mut_ptr(),
                ptrs.as_mut_ptr(),
                keys.len(),
                &mut len,
            );

            assert_eq!(ret, HddsError::HddsOk);
            assert_eq!(len, 1);
            assert_eq!(keys[0], hdds_rmw_context_graph_guard_key(ctx));
            assert_eq!(ptrs[0], guard.cast());

            let mut readers = [ptr::null_mut(); 4];
            let mut reader_len = 0usize;
            let mut guard_hit = false;
            let ret = hdds_rmw_context_wait_readers(
                ctx,
                1,
                readers.as_mut_ptr(),
                readers.len(),
                &mut reader_len,
                &mut guard_hit,
            );
            assert_eq!(ret, HddsError::HddsOk);
            assert_eq!(reader_len, 0);
            assert!(guard_hit);

            hdds_guard_condition_release(guard);
            hdds_rmw_context_destroy(ctx);
        }
    }

    #[cfg(feature = "rmw")]
    #[test]
    fn test_rmw_context_attach_reader_lifecycle() {
        unsafe {
            let ctx_name = CString::new("rmw_ctx_reader").unwrap();
            let ctx = hdds_rmw_context_create(ctx_name.as_ptr());
            assert!(!ctx.is_null());

            let topic = CString::new("rmw_ctx_reader_topic").unwrap();
            let mut reader = ptr::null_mut();
            let create_ret = hdds_rmw_context_create_reader(ctx, topic.as_ptr(), &mut reader);
            assert_eq!(create_ret, HddsError::HddsOk);
            assert!(!reader.is_null());

            let mut key = 0u64;
            let ret = hdds_rmw_context_attach_reader(ctx, reader, &mut key);
            assert_eq!(ret, HddsError::HddsOk);
            assert_ne!(key, 0);

            // Duplicate attach should fail
            let ret_dup = hdds_rmw_context_attach_reader(ctx, reader, &mut key);
            assert_eq!(ret_dup, HddsError::HddsInvalidArgument);

            // Detach the reader and ensure it can be re-attached
            let ret = hdds_rmw_context_detach_reader(ctx, reader);
            assert_eq!(ret, HddsError::HddsOk);

            let mut new_key = 0u64;
            let ret = hdds_rmw_context_attach_reader(ctx, reader, &mut new_key);
            assert_eq!(ret, HddsError::HddsOk);
            assert_ne!(new_key, 0);

            let ret = hdds_rmw_context_detach_reader(ctx, reader);
            assert_eq!(ret, HddsError::HddsOk);

            let destroy_ret = hdds_rmw_context_destroy_reader(ctx, reader);
            assert_eq!(destroy_ret, HddsError::HddsOk);
            hdds_rmw_context_destroy(ctx);
        }
    }

    #[cfg(feature = "rmw")]
    #[test]
    fn test_rmw_waitset_basic_flow() {
        unsafe {
            let ctx_name = CString::new("rmw_waitset_ctx").unwrap();
            let ctx = hdds_rmw_context_create(ctx_name.as_ptr());
            assert!(!ctx.is_null());

            let topic = CString::new("rmw_waitset_topic").unwrap();
            let mut reader = ptr::null_mut();
            let create_ret = hdds_rmw_context_create_reader(ctx, topic.as_ptr(), &mut reader);
            assert_eq!(create_ret, HddsError::HddsOk);
            assert!(!reader.is_null());

            let waitset = hdds_rmw_waitset_create(ctx);
            assert!(!waitset.is_null());

            let guard = hdds_rmw_context_graph_guard_condition(ctx);
            hdds_guard_condition_set_trigger(guard, true);

            let mut readers = [ptr::null_mut(); 4];
            let mut reader_len = 0usize;
            let mut guard_hit = false;
            let ret = hdds_rmw_waitset_wait(
                waitset,
                1_000_000,
                readers.as_mut_ptr(),
                readers.len(),
                &mut reader_len,
                &mut guard_hit,
            );
            assert_eq!(ret, HddsError::HddsOk);
            assert_eq!(reader_len, 0);
            assert!(guard_hit);

            let attach_ret = hdds_rmw_waitset_attach_reader(waitset, reader);
            assert_eq!(attach_ret, HddsError::HddsOk);

            let detach_ret = hdds_rmw_waitset_detach_reader(waitset, reader);
            assert_eq!(detach_ret, HddsError::HddsOk);

            hdds_guard_condition_release(guard);
            hdds_rmw_waitset_destroy(waitset);
            let destroy_ret = hdds_rmw_context_destroy_reader(ctx, reader);
            assert_eq!(destroy_ret, HddsError::HddsOk);
            hdds_rmw_context_destroy(ctx);
        }
    }

    #[test]
    fn test_participant_graph_guard_waitset_integration() {
        unsafe {
            let name = CString::new("graph_guard").unwrap();
            let participant = hdds_participant_create(name.as_ptr());
            assert!(!participant.is_null());

            let guard = hdds_participant_graph_guard_condition(participant);
            assert!(!guard.is_null());

            let waitset = hdds_waitset_create();
            assert!(!waitset.is_null());

            assert_eq!(
                hdds_waitset_attach_guard_condition(waitset, guard),
                HddsError::HddsOk
            );

            hdds_guard_condition_set_trigger(guard, true);

            let mut triggered = [ptr::null(); 4];
            let mut len = 0usize;
            let ret = hdds_waitset_wait(
                waitset,
                1_000_000,
                triggered.as_mut_ptr(),
                triggered.len(),
                &mut len,
            );
            assert_eq!(ret, HddsError::HddsOk);
            assert_eq!(len, 1);
            assert_eq!(triggered[0], guard.cast());

            assert_eq!(
                hdds_waitset_detach_condition(waitset, guard.cast()),
                HddsError::HddsOk
            );
            hdds_waitset_destroy(waitset);
            hdds_guard_condition_release(guard);
            hdds_participant_destroy(participant);
        }
    }

    #[test]
    #[cfg(feature = "xtypes")]
    fn test_register_type_support_and_hash() {
        unsafe {
            let members_vec = vec![
                rosidl_typesupport_introspection_c__MessageMember {
                    name_: b"x\0".as_ptr().cast(),
                    type_id_: 1,
                    string_upper_bound_: 0,
                    members_: ptr::null(),
                    is_array_: false,
                    array_size_: 0,
                    is_upper_bound_: false,
                    offset_: 0,
                    default_value_: ptr::null(),
                    size_function: None,
                    get_const_function: None,
                    get_function: None,
                    fetch_function: None,
                    assign_function: None,
                    resize_function: None,
                },
                rosidl_typesupport_introspection_c__MessageMember {
                    name_: b"labels\0".as_ptr().cast(),
                    type_id_: 16,
                    string_upper_bound_: 0,
                    members_: ptr::null(),
                    is_array_: true,
                    array_size_: 0,
                    is_upper_bound_: true,
                    offset_: 0,
                    default_value_: ptr::null(),
                    size_function: None,
                    get_const_function: None,
                    get_function: None,
                    fetch_function: None,
                    assign_function: None,
                    resize_function: None,
                },
            ];

            let members_box = members_vec.into_boxed_slice();
            let members_ptr = members_box.as_ptr();
            let members_slice = Box::leak(members_box);

            let descriptor = Box::leak(Box::new(
                rosidl_typesupport_introspection_c__MessageMembers {
                    message_namespace_: b"test_pkg__msg\0".as_ptr().cast(),
                    message_name_: b"TaggedPoint\0".as_ptr().cast(),
                    member_count_: u32::try_from(members_slice.len())
                        .expect("member count fits in u32"),
                    size_of_: 0,
                    members_: members_ptr,
                    init_function: None,
                    fini_function: None,
                },
            ));

            let type_support = Box::leak(Box::new(rosidl_message_type_support_t {
                typesupport_identifier: b"rosidl_typesupport_introspection_c\0".as_ptr().cast(),
                data: std::ptr::from_ref(&*descriptor).cast::<c_void>(),
                func: None,
                get_type_hash_func: Some(stub_hash),
                get_type_description_func: None,
                get_type_description_sources_func: None,
            }));

            let name = CString::new("ffi_register").unwrap();
            let participant = hdds_participant_create(name.as_ptr());
            assert!(!participant.is_null());

            let mut handle: *const HddsTypeObject = ptr::null();
            let err = hdds_participant_register_type_support(
                participant,
                0,
                type_support,
                std::ptr::addr_of_mut!(handle),
            );
            assert_eq!(err, HddsError::HddsOk);
            assert!(!handle.is_null());

            let mut version = 0u8;
            let mut buf = [0u8; ROS_HASH_SIZE];
            let err = hdds_type_object_hash(
                handle,
                std::ptr::addr_of_mut!(version),
                buf.as_mut_ptr(),
                buf.len(),
            );
            assert_eq!(err, HddsError::HddsOk);
            assert_eq!(version, 1);
            assert_eq!(buf, HASH_BYTES);

            hdds_type_object_release(handle);
            hdds_participant_destroy(participant);
        }
    }

    #[test]
    fn test_participant_create_null_name() {
        unsafe {
            let participant = hdds_participant_create(ptr::null());
            assert!(participant.is_null());
        }
    }

    #[test]
    fn test_writer_reader_lifecycle() {
        unsafe {
            // Create participant
            let name = CString::new("test_participant_ffi").unwrap();
            let participant = hdds_participant_create(name.as_ptr());
            assert!(!participant.is_null());

            // Create writer and reader
            let topic = CString::new("test_topic_ffi").unwrap();
            let writer = hdds_writer_create(participant, topic.as_ptr());
            let reader = hdds_reader_create(participant, topic.as_ptr());
            assert!(!writer.is_null());
            assert!(!reader.is_null());

            // Note: We don't test actual data transmission here because
            // writer/reader need time to discover each other via SPDP/SEDP.
            // For FFI correctness testing, we just verify creation/destruction works.

            // Cleanup
            hdds_writer_destroy(writer);
            hdds_reader_destroy(reader);
            hdds_participant_destroy(participant);
        }
    }

    #[test]
    fn test_writer_write_null_checks() {
        unsafe {
            // Test null writer
            let test_data = b"test";
            let result = hdds_writer_write(
                ptr::null_mut(),
                test_data.as_ptr().cast::<c_void>(),
                test_data.len(),
            );
            assert_eq!(result, HddsError::HddsInvalidArgument);

            // Test null data
            let name = CString::new("test_participant").unwrap();
            let participant = hdds_participant_create(name.as_ptr());
            let topic = CString::new("test_topic").unwrap();
            let writer = hdds_writer_create(participant, topic.as_ptr());

            let result = hdds_writer_write(writer, ptr::null(), 10);
            assert_eq!(result, HddsError::HddsInvalidArgument);

            hdds_writer_destroy(writer);
            hdds_participant_destroy(participant);
        }
    }
}
