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

#[cfg(test)]
mod adopt_tests;
mod condition_ffi;
#[cfg(test)]
mod datarep_ex_tests;
#[cfg(test)]
mod datarep_tests;
#[cfg(test)]
mod dispose_take_tests;
#[cfg(test)]
mod domain_env_tests;
mod dynamic_ffi;
mod filter_ffi;
mod info;
mod key_ffi;
#[cfg(test)]
mod key_tests;
mod listener;
#[cfg(test)]
mod listener_notify_tests;
mod logging;
#[cfg(test)]
mod participant_destroy_tests;
mod pubsub;
mod qos;
#[cfg(feature = "rmw")]
mod rmw;
#[cfg(feature = "rpc")]
mod rpc_ffi;
#[cfg(feature = "rpc")]
mod rpc_runtime;
mod security_config;
mod status_ffi;
#[cfg(test)]
mod status_timestamp_tests;
#[cfg(test)]
mod take_size_tests;
mod telemetry;
mod timestamp_ffi;
mod transport_config;
mod waitset;

// Re-export new modules
pub use condition_ffi::*;
pub use dynamic_ffi::*;
pub use filter_ffi::*;
pub use info::*;
pub use key_ffi::*;
pub use listener::*;
pub use logging::*;
pub use pubsub::*;
#[cfg(feature = "rpc")]
pub use rpc_ffi::*;
pub use status_ffi::*;
pub use telemetry::*;
pub use timestamp_ffi::*;

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
pub struct HddsParticipant {
    _private: [u8; 0],
}

/// Opaque handle to a `DataWriter`
pub struct HddsDataWriter {
    _private: [u8; 0],
}

/// Opaque handle to a `DataReader`
pub struct HddsDataReader {
    _private: [u8; 0],
}

/// Opaque handle to a WaitSet
pub struct HddsWaitSet {
    _private: [u8; 0],
}

/// Opaque handle to a GuardCondition
pub struct HddsGuardCondition {
    _private: [u8; 0],
}

/// Opaque handle to a StatusCondition
pub struct HddsStatusCondition {
    _private: [u8; 0],
}

/// Every `HddsDataReader` handle is the raw pointer of an
/// `Arc<DataReader<BytePayload>>` (`Arc::into_raw`), never a `Box`: the
/// ReadCondition / QueryCondition surface keeps a weak link to the reader
/// and needs an `Arc` to clone from the handle. The pointer points at the
/// `DataReader` itself, so the read-only casts
/// (`&*reader.cast::<DataReader<BytePayload>>()`) work directly.
pub(crate) fn reader_into_handle(reader: DataReader<BytePayload>) -> *mut HddsDataReader {
    Arc::into_raw(Arc::new(reader))
        .cast_mut()
        .cast::<HddsDataReader>()
}

/// Clone the `Arc` behind a reader handle without consuming it.
///
/// # Safety
/// - `reader` must be a live handle produced by [`reader_into_handle`].
pub(crate) unsafe fn reader_arc_from_handle(
    reader: *mut HddsDataReader,
) -> Arc<DataReader<BytePayload>> {
    let raw = reader.cast::<DataReader<BytePayload>>().cast_const();
    Arc::increment_strong_count(raw);
    Arc::from_raw(raw)
}

/// Take the handle's own reference back (the destroy path).
///
/// # Safety
/// - `reader` must be a live handle produced by [`reader_into_handle`],
///   and must not be used afterwards.
pub(crate) unsafe fn reader_release_handle(reader: *mut HddsDataReader) {
    drop(Arc::from_raw(
        reader.cast::<DataReader<BytePayload>>().cast_const(),
    ));
}

/// Opaque handle to an rmw context
#[cfg(feature = "rmw")]
pub struct HddsRmwContext {
    _private: [u8; 0],
}

#[cfg(feature = "rmw")]
pub const HDDS_RMW_GID_SIZE: usize = hdds::rmw::graph::RMW_GID_STORAGE_SIZE;

/// Number of GID bytes an rmw caller actually owns and this crate may read.
///
/// `RMW_GID_STORAGE_SIZE` in `rmw/types.h` is 24 on Humble but 16 on Iron and
/// Jazzy, and the caller's buffer is that wide. `rmw_hdds_gid_from_ptr`
/// (rmw_hdds/include/rmw_hdds/types.h) only ever writes 16 meaningful bytes -
/// a 12-byte participant GUID prefix plus a 4-byte entity id - so 16 is the
/// contract on every distro. The graph key stays [`HDDS_RMW_GID_SIZE`] wide
/// and is zero-padded; reading `HDDS_RMW_GID_SIZE` bytes from the caller
/// pointer over-reads by 8 bytes on every Iron and Jazzy node.
#[cfg(feature = "rmw")]
pub const HDDS_RMW_GID_WIRE: usize = 16;

/// Bring the Rust logger up on the rmw path.
///
/// `hdds_participant_create_with_transport` does this, but no ROS 2 node goes
/// through it: rmw_hdds enters at `hdds_rmw_context_create[_with_domain]`.
/// Without this call `RUST_LOG` would have no effect inside a ROS 2 process
/// (`rmw_hdds` sets `RUST_LOG` from `HDDS_LOG_LEVEL`), leaving the engine
/// undebuggable from a node. Idempotent: `try_init` after the first call is a
/// no-op.
#[cfg(feature = "rmw")]
fn rmw_init_logger() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = env_logger::try_init();
    });
}

/// One-time per-process setup every rmw context constructor performs before
/// anything registers a ROS type.
///
/// The introspection layout resolved here is only a FALLBACK: every type
/// support carries its own detected layout on its `RosMessageMetadata`. What
/// this call does is keep the environment lookup on the ROS 2 entry path, so a
/// process that is not a ROS 2 node never reads those variables and the walker
/// cannot race a `set_var` in another thread.
#[cfg(feature = "rmw")]
fn rmw_process_init() {
    rmw_init_logger();
    let layout = hdds::xtypes::builder::resolve_ros_introspection_layout_from_env();
    log::debug!("[rmw] rosidl introspection fallback layout: {layout:?}");
}

/// Copy the GID an rmw caller handed us into the graph key, reading exactly
/// [`HDDS_RMW_GID_WIRE`] bytes and zero-padding the rest.
///
/// # Safety
/// `endpoint_gid` must be NULL or point to at least [`HDDS_RMW_GID_WIRE`]
/// readable bytes.
#[cfg(feature = "rmw")]
unsafe fn copy_rmw_gid(endpoint_gid: *const u8) -> [u8; HDDS_RMW_GID_SIZE] {
    let mut gid = [0u8; HDDS_RMW_GID_SIZE];
    if !endpoint_gid.is_null() {
        let src = slice::from_raw_parts(endpoint_gid, HDDS_RMW_GID_WIRE);
        gid[..HDDS_RMW_GID_WIRE].copy_from_slice(src);
    }
    gid
}

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
pub struct HddsRmwWaitSet {
    _private: [u8; 0],
}

#[cfg(feature = "rmw")]
pub type HddsTopicVisitor =
    unsafe extern "C" fn(*const c_char, *const c_char, u32, u32, *mut c_void);

#[cfg(feature = "rmw")]
pub type HddsLocatorVisitor = unsafe extern "C" fn(*const c_char, u16, *mut c_void);

#[cfg(feature = "xtypes")]
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
    #[serde(skip)]
    key: Option<key_ffi::SerializedKey>,
    /// The representation the bytes are in, as the encapsulation identifier
    /// of the received sample named it. Set by `decode` on every delivery;
    /// a payload built to be written carries `Xcdr2` and the field is not
    /// read (`encode` copies the bytes, the writer labels them with the
    /// representation it offers).
    #[serde(skip, default = "xcdr2")]
    version: hdds::CdrVersion,
}

fn xcdr2() -> hdds::CdrVersion {
    hdds::CdrVersion::Xcdr2
}

impl BytePayload {
    /// A payload to write: the caller's bytes, unchanged.
    pub(crate) fn to_write(data: Vec<u8>) -> Self {
        Self {
            data,
            key: None,
            version: hdds::CdrVersion::Xcdr2,
        }
    }

    /// The encapsulation identifier of the representation the received
    /// bytes are in (DDS-XTypes v1.3 Sec.7.6.3.1.2, Table 60): `CDR_LE`
    /// (0x0001) for XCDR1, `CDR2_LE` (0x0007) for XCDR2.
    ///
    /// The reader keeps the encoding version of a sample, not the
    /// identifier's extensibility framing: a `PL_CDR_LE` sample reports
    /// 0x0001 and a `D_CDR2_LE` or `PL_CDR2_LE` one 0x0007. The decoders
    /// `hdds_gen` emits (`_decode_by_encapsulation`) select by encoding
    /// version, so they decode either value as the original one.
    pub(crate) fn encapsulation_id(&self) -> u16 {
        encapsulation_id_of(self.version)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

/// `CDR_LE` (0x0001) for XCDR1, `CDR2_LE` (0x0007) for XCDR2: see
/// [`BytePayload::encapsulation_id`].
pub(crate) const fn encapsulation_id_of(version: hdds::CdrVersion) -> u16 {
    match version {
        hdds::CdrVersion::Xcdr1 => 0x0001,
        hdds::CdrVersion::Xcdr2 => 0x0007,
    }
}

impl DDS for BytePayload {
    fn type_descriptor() -> &'static TypeDescriptor {
        // Simple type descriptor for opaque byte array
        // The placeholder name "RawBytes" is what hdds-ws (create_raw_writer/reader)
        // announces, so a byte endpoint with no name of its own meets it in
        // cross-process SEDP matching. An endpoint created without a type name
        // may announce the name of its topic's peers instead (see
        // `Participant::adopt_type_name`); this is the name it keeps otherwise.
        static DESCRIPTOR: TypeDescriptor = TypeDescriptor {
            type_id: 0x0000_0000, // Special ID for opaque data
            type_name: hdds::PLACEHOLDER_TYPE_NAME,
            size_bytes: 0, // Variable size
            alignment: 1,  // Raw byte alignment
            is_variable_size: true,
            fields: &[],
        };
        &DESCRIPTOR
    }

    fn encode(&self, buf: &mut [u8], _version: hdds::CdrVersion) -> hdds::api::Result<usize> {
        // Raw byte payload (no length prefix)
        if buf.len() < self.data.len() {
            return Err(hdds::api::Error::BufferTooSmall);
        }

        buf[..self.data.len()].copy_from_slice(&self.data);
        Ok(self.data.len())
    }

    fn decode(buf: &[u8], version: hdds::CdrVersion) -> hdds::api::Result<Self> {
        Ok(BytePayload {
            data: buf.to_vec(),
            key: None,
            version,
        })
    }

    /// The bytes are the caller's, unchanged; the representation they are
    /// in is the one the endpoint's DATA_REPRESENTATION names (XCDR2 for an
    /// SDK endpoint, `sdk_writer_qos` / `sdk_reader_qos`; XCDR for an rmw
    /// one, `rmw::classic_cdr_qos`). Nothing here re-encodes them, so an
    /// XCDR1 pair is not refused for the type.
    fn encodes_xcdr1_natively() -> bool {
        true
    }

    fn instance_key(&self) -> Option<[u8; 16]> {
        self.key.as_ref().map(|key| key.hash)
    }

    fn compute_key(&self) -> [u8; 16] {
        self.instance_key().unwrap_or_default()
    }

    fn protected_key(&self) -> Option<[u8; 16]> {
        self.key.as_ref().map(|key| key.protected_hash)
    }

    fn encode_key(&self, _version: hdds::CdrVersion) -> Vec<u8> {
        self.key
            .as_ref()
            .map_or_else(Vec::new, |key| key.payload.clone())
    }
}

/// The QoS of a writer created through the C ABI: `qos`, with
/// DATA_REPRESENTATION set to XCDR2 when the caller set none.
///
/// Such a writer is a `DataWriter<BytePayload>`: it puts the caller's bytes
/// on the wire unchanged, under the encapsulation identifier of the
/// representation the writer offers. The codecs `hdds_gen` emits for the
/// C, C++, Python and TypeScript SDKs serialize XCDR2 only (8-byte members
/// aligned at 4, DHEADER and EMHEADER), so the representation these writers
/// offer and announce is XCDR2. Left empty, a writer offers XCDR
/// (DDS-XTypes v1.3 Sec.7.6.3.1.1) and those XCDR2 bytes would travel under
/// CDR_LE. A list the caller set (`hdds_qos_set_data_representation`) is
/// kept, as is the XCDR an rmw endpoint sets (`rmw::classic_cdr_qos`).
pub(crate) fn sdk_writer_qos(qos: QoS) -> QoS {
    if qos.data_representation.is_empty() {
        qos.data_representation_xcdr2()
    } else {
        qos
    }
}

/// The QoS of a reader created through the C ABI: `qos`, with
/// DATA_REPRESENTATION set to XCDR2 when the caller set none.
///
/// Such a reader is a `DataReader<BytePayload>`: it hands the caller the
/// sample bytes unchanged, and the caller decodes them with a codec
/// `hdds_gen` emits for the C, C++, Python or TypeScript SDK, or with
/// `hdds_dynamic_data_decode`. Code that reads XCDR2 only (the codecs of
/// `hdds_gen` 1.2 and earlier, `hdds_dynamic_data_decode`) must not receive
/// XCDR1, so the default is XCDR2 alone; code that also reads XCDR1 sets
/// `[XCDR, XCDR2]` (`hdds_qos_set_data_representation`) and learns the
/// representation of each sample from the `_ex` takes.
/// DDS-XTypes v1.3 Sec.7.6.3.1.1 asks a reader to request what it can
/// deserialize ("Shall request XCDR2 encoding"; XCDR only when it can
/// "deserialize version 1 encodings"). Left empty, a reader announces
/// `[XCDR, XCDR2]` (`announced_data_representation`), is matched with a
/// writer that offers XCDR (the default of any writer, of HDDS or of a
/// foreign implementation) and hands its caller XCDR1 bytes to read as
/// XCDR2: an 8-byte member at the wrong offset, without an error. Requesting
/// XCDR2 makes that pair a visible REQUESTED_INCOMPATIBLE_QOS (policy 23).
/// A list the caller set is kept, as is the XCDR an rmw endpoint sets
/// (`rmw::classic_cdr_qos`).
pub(crate) fn sdk_reader_qos(qos: QoS) -> QoS {
    if qos.data_representation.is_empty() {
        qos.data_representation_xcdr2()
    } else {
        qos
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
    /// Operation did not complete before the requested timeout
    HddsTimeout = 24,

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

    // Port assignment is left to the builder (no fixed discovery ports, so
    // several processes can share a host), in priority order:
    //   1. Code: .participant_id(Some(X))
    //   2. Env:  HDDS_PARTICIPANT_ID=X
    //   3. Auto: bind ports 7410+pid*2, 7411+pid*2 exclusively until a free pair is found
    //
    // For multi-process on same machine, leave HDDS_PARTICIPANT_ID unset (each process
    // gets a free id), or give each process its own:
    //   HDDS_PARTICIPANT_ID=0 ./daemon   # ports 7410, 7411
    //   HDDS_PARTICIPANT_ID=1 ./alpha    # ports 7412, 7413
    //   HDDS_PARTICIPANT_ID=2 ./beta     # ports 7414, 7415
    // The unicast ports are exclusive: a second process on the same id fails to create
    // its participant. HDDS_REUSEPORT=1 only concerns the shared multicast ports.
    // No domain is set here, so the core applies the one domain rule: HDDS_DOMAIN_ID
    // when set and valid, else 0. A malformed value makes build() fail (NULL below).
    let Ok(participant) = Participant::builder(name_str).with_transport(mode).build() else {
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

/// Manually assert the participant's liveliness (DDS v1.4 Sec.2.2.3.11,
/// Sec.2.2.2.2.4.19): renews the lease every MANUAL_BY_PARTICIPANT writer
/// of this participant shares, with nothing to write. A no-op on a
/// participant with no liveliness thread or no such writer yet.
///
/// # Safety
/// - `participant` must be a valid handle from `hdds_participant_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_participant_assert_liveliness(
    participant: *mut HddsParticipant,
) -> HddsError {
    if participant.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let participant_ref = &*participant.cast::<Arc<Participant>>();
    participant_ref.assert_liveliness();
    HddsError::HddsOk
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

/// Get the source commit the HDDS core was built from (short git hash), or
/// `"unknown"` when the build had no git checkout and no
/// `HDDS_BUILD_GIT_SHA` in its environment. Lets a shipped `libhdds_c` be
/// tied back to its source, like `hdds::BUILD_GIT_SHA` for Rust users.
///
/// # Safety
/// The returned pointer is valid for the lifetime of the process (static storage).
#[no_mangle]
pub unsafe extern "C" fn hdds_build_git_sha() -> *const c_char {
    // Fully qualified on purpose: the `CString` import above is gated on the
    // `rmw` feature, and this function is part of the default ABI.
    static SHA: std::sync::OnceLock<std::ffi::CString> = std::sync::OnceLock::new();
    SHA.get_or_init(|| std::ffi::CString::new(hdds::BUILD_GIT_SHA).unwrap_or_default())
        .as_ptr()
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

    let writer = match nameless_writer(
        participant_ref,
        topic_str,
        sdk_writer_qos(QoS::best_effort()),
    ) {
        Ok(writer) => writer,
        Err(e) => {
            // The C ABI can only return NULL: log the reason so a caller
            // (or a binding built on this ABI) has somewhere to find it.
            log::error!("Failed to create writer for topic '{topic_str}': {e}");
            return ptr::null_mut();
        }
    };

    writer_into_handle(writer)
}

/// Write data to a topic.
///
/// A writer created keyed (`hdds_writer_create_keyed`) needs the key with
/// every sample: this call fails on it (`HDDS_OPERATION_FAILED`, logged),
/// use `hdds_writer_write_keyed`.
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
    // A keyed writer needs the key with every sample: refuse the keyless
    // call with a log naming the right one, not a silent failure.
    if writer_ref.accepts_serialized_keys() {
        log::error!("hdds_writer_write on a keyed writer: use hdds_writer_write_keyed");
        return HddsError::HddsOperationFailed;
    }
    let data_slice = std::slice::from_raw_parts(data.cast::<u8>(), len);

    let payload = BytePayload::to_write(data_slice.to_vec());

    match writer_ref.write(&payload) {
        Ok(()) => HddsError::HddsOk,
        Err(_) => HddsError::HddsOperationFailed,
    }
}

/// Manually assert the writer's liveliness (DDS v1.4 Sec.2.2.3.11,
/// Sec.2.2.2.4.2.22): renews its LIVELINESS lease without writing a
/// sample. A no-op for AUTOMATIC or an infinite lease.
///
/// # Safety
/// - `writer` must be a valid pointer returned from `hdds_writer_create`
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_assert_liveliness(writer: *mut HddsDataWriter) -> HddsError {
    if writer.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let writer_ref = &*writer.cast::<DataWriter<BytePayload>>();

    match writer_ref.assert_liveliness() {
        Ok(()) => HddsError::HddsOk,
        Err(_) => HddsError::HddsOperationFailed,
    }
}

/// Get the number of remote readers currently matched with a writer.
///
/// # Safety
/// - `writer` must be a valid pointer returned from an HDDS writer constructor
/// - `out_count` must point to writable storage for one `u32`
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_matched_reader_count(
    writer: *mut HddsDataWriter,
    out_count: *mut u32,
) -> HddsError {
    if writer.is_null() || out_count.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let writer_ref = &*writer.cast::<DataWriter<BytePayload>>();
    *out_count = writer_ref.matched_reader_count();
    HddsError::HddsOk
}

/// Wait until at least `min_count` remote readers are matched with a writer.
///
/// This is a bounded polling helper intended for deterministic test and
/// startup orchestration. A zero timeout performs a single non-blocking check.
///
/// # Safety
/// - `writer` must be a valid pointer returned from an HDDS writer constructor
/// - the writer must not be destroyed or used concurrently for writing while
///   this function is running
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_wait_for_matched_readers(
    writer: *mut HddsDataWriter,
    min_count: u32,
    timeout_ms: u64,
) -> HddsError {
    if writer.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    if min_count == 0 {
        return HddsError::HddsOk;
    }

    let writer_ref = &*writer.cast::<DataWriter<BytePayload>>();
    let timeout = Duration::from_millis(timeout_ms);
    let started = std::time::Instant::now();
    loop {
        if writer_ref.matched_reader_count() >= min_count {
            return HddsError::HddsOk;
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return HddsError::HddsTimeout;
        }
        std::thread::sleep(Duration::from_millis(10).min(timeout.saturating_sub(elapsed)));
    }
}

/// Block until every sample written by `writer` has been acknowledged by
/// every matched RELIABLE reader, or `timeout_ms` elapses (DDS v1.4
/// Sec.2.2.2.4.2.15 `wait_for_acknowledgments`). Returns `HddsOk` once
/// acknowledged, `HddsTimeout` if `timeout_ms` elapses first. A writer
/// whose RELIABILITY QoS is BEST_EFFORT returns `HddsOk` at once, per the
/// same spec section.
///
/// No busy-wait on the Rust side: blocked on the writer's history cache
/// condition variable, the same one an ACKNACK wakes.
///
/// # Safety
/// - `writer` must be a valid pointer returned from an HDDS writer constructor
/// - the writer must not be destroyed concurrently while this function is running
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_wait_for_acknowledgments(
    writer: *mut HddsDataWriter,
    timeout_ms: u64,
) -> HddsError {
    if writer.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let writer_ref = &*writer.cast::<DataWriter<BytePayload>>();
    acknowledgment_status(writer_ref.wait_for_acknowledgments(Duration::from_millis(timeout_ms)))
}

/// The C status of a `wait_for_acknowledgments`: `HddsOk` once acknowledged,
/// `HddsTimeout` when the wait ran out (DDS v1.4 TIMEOUT).
pub(crate) fn acknowledgment_status(result: hdds::dds::Result<()>) -> HddsError {
    match result {
        Ok(()) => HddsError::HddsOk,
        Err(hdds::dds::Error::AcknowledgmentTimeout) => HddsError::HddsTimeout,
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
        // A C listener's callbacks must be over before the caller frees
        // their user_data: detach waits for them. From inside one of the
        // writer's own callbacks the writer cannot be freed (see Detached).
        if let listener::Detached::Free = listener::writer_listener_detach(writer) {
            let _ = Box::from_raw(writer.cast::<DataWriter<BytePayload>>());
        }
    }
}

/// Get the status condition associated with a writer.
///
/// # Safety
/// - `writer` must be a valid handle from an HDDS writer constructor.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_get_status_condition(
    writer: *mut HddsDataWriter,
) -> *const HddsStatusCondition {
    if writer.is_null() {
        return ptr::null();
    }

    let writer_ref = &*writer.cast::<DataWriter<BytePayload>>();
    let condition = writer_ref.get_status_condition();
    let raw = Arc::into_raw(condition.clone()) as *const HddsStatusCondition;
    status_registry_add_handle(raw, condition);
    raw
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

    let writer = match nameless_writer(participant_ref, topic_str, sdk_writer_qos(qos_value)) {
        Ok(writer) => writer,
        Err(e) => {
            // The C ABI can only return NULL: log the reason so a caller
            // (or a binding built on this ABI) has somewhere to find it.
            log::error!("Failed to create writer for topic '{topic_str}': {e}");
            return ptr::null_mut();
        }
    };

    writer_into_handle(writer)
}

/// Create a `DataWriter` for a topic with custom QoS and explicit type name.
///
/// The `type_name` is announced via SEDP and must match the remote endpoint's
/// type name for topic matching (e.g. `"P_Mount_PSM::C_Rotational_Mount_setPosition"`).
/// If `type_name` is NULL or empty, the endpoint has no type of its own: it announces
/// the type registered for the topic, else the type name its topic's opposite endpoints
/// already announce (one name, discovered or local), else the placeholder `"RawBytes"`
/// (a live raw endpoint beside a typed one makes the topic ambiguous: the placeholder
/// stays). The choice is made once, at creation, and logged at info; the endpoint is not
/// re-announced if a name is discovered later. When `HDDS_TYPE_ADOPT_WAIT_MS` is set
/// and no name is known yet, the call BLOCKS the calling thread for up to that many
/// milliseconds (at most 10000): never call it from a listener callback. The
/// variable is read once per process, at the first endpoint creation that needs it
/// (set it before creating any endpoint; unset, empty and 0 mean no wait).
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
    let requested = match requested_type_name(type_name) {
        Ok(requested) => requested,
        Err(()) => return ptr::null_mut(),
    };
    if let Some(type_str) = requested {
        log::info!(
            "[HDDS-C] Creating writer topic='{}' type='{}'",
            topic_str,
            type_str
        );
        let Ok(writer) = participant_ref.create_writer_with_type::<BytePayload>(
            topic_str,
            sdk_writer_qos(qos_value),
            type_str,
            None,
        ) else {
            return ptr::null_mut();
        };
        return writer_into_handle(writer);
    }

    // No type name: the endpoint has no type of its own
    let writer = match nameless_writer(participant_ref, topic_str, sdk_writer_qos(qos_value)) {
        Ok(writer) => writer,
        Err(e) => {
            // The C ABI can only return NULL: log the reason so a caller
            // (or a binding built on this ABI) has somewhere to find it.
            log::error!("Failed to create writer for topic '{topic_str}': {e}");
            return ptr::null_mut();
        }
    };

    writer_into_handle(writer)
}

/// The type name a C caller asked for: `Ok(None)` for NULL or an empty
/// string (an endpoint with no type of its own, which adopts one), `Ok(Some)`
/// for a name, `Err(())` for bytes that are not UTF-8 (logged; the caller
/// returns NULL, as for every other invalid string of this ABI).
///
/// # Safety
/// A non-NULL `ptr` must point to a readable NUL-terminated string.
pub(crate) unsafe fn requested_type_name<'a>(
    ptr: *const c_char,
) -> std::result::Result<Option<&'a str>, ()> {
    if ptr.is_null() {
        return Ok(None);
    }
    match CStr::from_ptr(ptr).to_str() {
        Ok("") => Ok(None),
        Ok(name) => Ok(Some(name)),
        Err(e) => {
            log::error!("type_name is not valid UTF-8: {e}");
            Err(())
        }
    }
}

/// A writer with no type of its own: it announces the type registered for
/// its topic, else the name its topic's readers announce, else the placeholder
/// (XTypes 1.3 Sec.7.6.3.4.2 Step 2).
pub(crate) fn nameless_writer(
    participant: &Arc<Participant>,
    topic: &str,
    qos: QoS,
) -> hdds::dds::Result<DataWriter<BytePayload>> {
    participant
        .topic::<BytePayload>(topic)?
        .writer()
        .qos(qos)
        .adopting_type_name()
        .build()
}

/// A reader with no type of its own: it announces the type registered for
/// its topic, else the name its topic's writers announce, else the placeholder.
pub(crate) fn nameless_reader(
    participant: &Arc<Participant>,
    topic: &str,
    qos: QoS,
) -> hdds::dds::Result<DataReader<BytePayload>> {
    participant
        .topic::<BytePayload>(topic)?
        .reader()
        .qos(qos)
        .adopting_type_name()
        .build()
}

/// The C handle of a writer this ABI created.
///
/// A build with the `test-support` feature (never a shipped library: the
/// SDK wire tests build one of their own) sends the writer's DATA to the
/// address `HDDS_TEST_CAPTURE_DATA` names (`127.0.0.1:port`), in place of
/// its matched readers, so a test in any SDK language reads back what a
/// writer it created puts on the wire
/// (`hdds::test_support::wire::send_data_to`).
#[allow(unused_mut)]
pub(crate) fn writer_into_handle(mut writer: DataWriter<BytePayload>) -> *mut HddsDataWriter {
    #[cfg(feature = "test-support")]
    if let Some(addr) = std::env::var("HDDS_TEST_CAPTURE_DATA")
        .ok()
        .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
    {
        hdds::test_support::wire::send_data_to(&mut writer, addr);
    }
    Box::into_raw(Box::new(writer)).cast::<HddsDataWriter>()
}

/// The extensibility `HDDS_EXTENSIBILITY_FINAL`, `_APPENDABLE` or
/// `_MUTABLE` names, `None` for any other value.
pub(crate) const fn extensibility_from_c(
    extensibility: u32,
) -> Option<hdds::dynamic::Extensibility> {
    match extensibility {
        HDDS_EXTENSIBILITY_FINAL => Some(hdds::dynamic::Extensibility::Final),
        HDDS_EXTENSIBILITY_APPENDABLE => Some(hdds::dynamic::Extensibility::Appendable),
        HDDS_EXTENSIBILITY_MUTABLE => Some(hdds::dynamic::Extensibility::Mutable),
        _ => None,
    }
}

/// `@final`: the encapsulation identifier of every sample is `CDR2_LE`
/// (0x0007) under XCDR2, `CDR_LE` (0x0001) under XCDR1.
pub const HDDS_EXTENSIBILITY_FINAL: u32 = 0;
/// `@appendable`: `D_CDR2_LE` (0x0009) under XCDR2 (the body starts with a
/// DHEADER), `CDR_LE` (0x0001) under XCDR1.
pub const HDDS_EXTENSIBILITY_APPENDABLE: u32 = 1;
/// `@mutable`: `PL_CDR2_LE` (0x000b) under XCDR2, `PL_CDR_LE` (0x0003)
/// under XCDR1.
pub const HDDS_EXTENSIBILITY_MUTABLE: u32 = 2;

/// `hdds_writer_create_with_type`, for bodies of a type whose extensibility
/// is `extensibility` (`HDDS_EXTENSIBILITY_FINAL`, `_APPENDABLE` or
/// `_MUTABLE`).
///
/// The encapsulation identifier of a sample names its type's extensibility
/// (DDS-XTypes v1.3 Sec.7.6.3.1.2, Table 60). A writer of this ABI is handed
/// encoded bodies and has no TypeObject to read it from, so the other
/// constructors label every body FINAL (`CDR2_LE`, 0x0007), which is wrong
/// for an APPENDABLE or MUTABLE body: a peer that frames by identifier
/// rejects or misreads it. Use this one with the extensibility of the IDL
/// type the bodies were encoded from (an `hdds_gen` type without an
/// annotation is APPENDABLE, the DDS-XTypes default). The C code `hdds_gen`
/// generates says it and names its type: `hdds_writer_create_with_extensibility(
/// participant, topic, "<IDL qualified name>", qos, <name>_extensibility())` for the
/// type whose functions are `<name>_encode_cdr2_le` (also the macro
/// `<NAME>_EXTENSIBILITY` and `<name>_type_name()`); from a Publisher it calls
/// `hdds_publisher_create_writer_with_type`. Pass the IDL qualified name
/// (module scopes joined with "::") of the type the bodies were encoded from.
/// `type_name` NULL or empty is for a tool with no type of its own: the writer adopts
/// the name its topic's readers announce, else "RawBytes" (see
/// `hdds_writer_create_with_type`; creation blocks the calling thread when
/// `HDDS_TYPE_ADOPT_WAIT_MS` is set). Code that knows its type must pass the name: a
/// NULL announces a peer's name, not the type's.
///
/// Returns NULL (with the reason logged) on an unknown `extensibility` or
/// any failure of `hdds_writer_create_with_type`.
///
/// # Safety
/// Same as `hdds_writer_create_with_type`.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_create_with_extensibility(
    participant: *mut HddsParticipant,
    topic_name: *const c_char,
    type_name: *const c_char,
    qos: *const HddsQoS,
    extensibility: u32,
) -> *mut HddsDataWriter {
    if participant.is_null() || topic_name.is_null() {
        return ptr::null_mut();
    }
    let Some(extensibility) = extensibility_from_c(extensibility) else {
        log::error!("hdds_writer_create_with_extensibility: unknown extensibility {extensibility}");
        return ptr::null_mut();
    };
    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return ptr::null_mut();
    };
    let requested = match requested_type_name(type_name) {
        Ok(requested) => requested,
        Err(()) => return ptr::null_mut(),
    };
    let participant_ref = &*participant.cast::<Arc<Participant>>();
    let qos_value = if qos.is_null() {
        QoS::default()
    } else {
        (*qos.cast::<QoS>()).clone()
    };
    let created = match requested {
        Some(type_str) => participant_ref.create_writer_with_type_and_extensibility::<BytePayload>(
            topic_str,
            sdk_writer_qos(qos_value),
            type_str,
            None,
            Some(extensibility),
        ),
        None => participant_ref.create_adopting_writer::<BytePayload>(
            topic_str,
            sdk_writer_qos(qos_value),
            Some(extensibility),
            false,
        ),
    };
    match created {
        Ok(writer) => writer_into_handle(writer),
        Err(e) => {
            log::error!("Failed to create writer for topic '{topic_str}': {e}");
            ptr::null_mut()
        }
    }
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

    let reader = match nameless_reader(participant_ref, topic_str, sdk_reader_qos(QoS::default())) {
        Ok(reader) => reader,
        Err(e) => {
            // The C ABI can only return NULL: log the reason so a caller
            // (or a binding built on this ABI) has somewhere to find it.
            log::error!("Failed to create reader for topic '{topic_str}': {e}");
            return ptr::null_mut();
        }
    };

    reader_into_handle(reader)
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

    let reader = match nameless_reader(participant_ref, topic_str, sdk_reader_qos(qos_value)) {
        Ok(reader) => reader,
        Err(e) => {
            // The C ABI can only return NULL: log the reason so a caller
            // (or a binding built on this ABI) has somewhere to find it.
            log::error!("Failed to create reader for topic '{topic_str}': {e}");
            return ptr::null_mut();
        }
    };

    reader_into_handle(reader)
}

/// Create a `DataReader` for a topic with custom QoS and explicit type name.
///
/// The `type_name` is announced via SEDP and must match the remote endpoint's
/// type name for topic matching (e.g. `"P_Mount_PSM::C_Rotational_Mount_setPosition"`).
/// If `type_name` is NULL or empty, the endpoint has no type of its own: it announces
/// the type registered for the topic, else the type name its topic's opposite endpoints
/// already announce (one name, discovered or local), else the placeholder `"RawBytes"`
/// (a live raw endpoint beside a typed one makes the topic ambiguous: the placeholder
/// stays). The choice is made once, at creation, and logged at info; the endpoint is not
/// re-announced if a name is discovered later. When `HDDS_TYPE_ADOPT_WAIT_MS` is set
/// and no name is known yet, the call BLOCKS the calling thread for up to that many
/// milliseconds (at most 10000): never call it from a listener callback. The
/// variable is read once per process, at the first endpoint creation that needs it
/// (set it before creating any endpoint; unset, empty and 0 mean no wait).
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
    let requested = match requested_type_name(type_name) {
        Ok(requested) => requested,
        Err(()) => return ptr::null_mut(),
    };
    if let Some(type_str) = requested {
        log::info!(
            "[HDDS-C] Creating reader topic='{}' type='{}'",
            topic_str,
            type_str
        );
        let Ok(reader) = participant_ref.create_reader_with_type::<BytePayload>(
            topic_str,
            sdk_reader_qos(qos_value),
            type_str,
            None,
        ) else {
            return ptr::null_mut();
        };
        return reader_into_handle(reader);
    }

    // No type name: the endpoint has no type of its own
    let reader = match nameless_reader(participant_ref, topic_str, sdk_reader_qos(qos_value)) {
        Ok(reader) => reader,
        Err(e) => {
            // The C ABI can only return NULL: log the reason so a caller
            // (or a binding built on this ABI) has somewhere to find it.
            log::error!("Failed to create reader for topic '{topic_str}': {e}");
            return ptr::null_mut();
        }
    };

    reader_into_handle(reader)
}

/// Take data from a topic (non-blocking)
///
/// The bytes are the body of the sample, without its encapsulation header.
/// `hdds_reader_take_ex` also reports the representation they are in.
///
/// When `max_len` is smaller than the next sample, the call returns
/// `HDDS_OUT_OF_MEMORY` with the required size in `*len_out`. A refused take
/// removes nothing; the check and the take are one step under the reader's
/// consumer gate. A later take returns the head of the reader at that time:
/// normally the refused sample, unless another taker took it first, a newer
/// sample of its instance evicted it (KEEP_LAST reached), or the SHM ring was
/// lapped. Read `*len_out` again on the retry instead of assuming the size you
/// were told.
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
    reader_take_into(reader, data_out, max_len, len_out, ptr::null_mut())
}

/// `hdds_reader_take`, and the encapsulation identifier of the
/// representation the taken bytes are in.
///
/// `*encapsulation_id_out` receives `CDR_LE` (0x0001) when the sample is in
/// XCDR1 and `CDR2_LE` (0x0007) when it is in XCDR2 (DDS-XTypes v1.3
/// Sec.7.6.3.1.2, Table 60); it is written whenever `*len_out` is, including
/// on `HDDS_OUT_OF_MEMORY`, where it names the refused sample's
/// representation. The value names the encoding version, not the
/// extensibility framing of the original identifier (a `PL_CDR_LE` sample
/// reports 0x0001, a `D_CDR2_LE` or `PL_CDR2_LE` one 0x0007). Pass it to the
/// `_decode_by_encapsulation` decoders `hdds_gen` emits, which select the
/// XCDR1 or XCDR2 decoder from it. A reader receives XCDR1 samples only when
/// its DATA_REPRESENTATION requests XCDR (`hdds_qos_set_data_representation`);
/// a reader that requests nothing requests XCDR2.
///
/// # Safety
/// Same as `hdds_reader_take`; `encapsulation_id_out` must be a valid
/// pointer.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_take_ex(
    reader: *mut HddsDataReader,
    data_out: *mut c_void,
    max_len: usize,
    len_out: *mut usize,
    encapsulation_id_out: *mut u16,
) -> HddsError {
    if encapsulation_id_out.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    reader_take_into(reader, data_out, max_len, len_out, encapsulation_id_out)
}

/// The body of `hdds_reader_take` / `hdds_reader_take_ex`;
/// `encapsulation_id_out` may be NULL.
///
/// The size check happens inside the take (`take_if`), under the reader's
/// consumer gate: a sample that does not fit is refused and stays in the
/// reader, so a retry with a bigger buffer gets that same sample.
///
/// # Safety
/// Pointer contract of `hdds_reader_take_ex`, `encapsulation_id_out` NULL
/// or valid.
unsafe fn reader_take_into(
    reader: *mut HddsDataReader,
    data_out: *mut c_void,
    max_len: usize,
    len_out: *mut usize,
    encapsulation_id_out: *mut u16,
) -> HddsError {
    if reader.is_null() || data_out.is_null() || len_out.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let reader_ref = &*reader.cast::<DataReader<BytePayload>>();

    match reader_ref.take_if(fits_in(max_len)) {
        Ok(Ok(Some(payload))) => {
            copy_payload_out(&payload, data_out, max_len, len_out, encapsulation_id_out)
        }
        Ok(Ok(None)) => HddsError::HddsNotFound,
        Ok(Err(too_big)) => report_too_big(too_big, len_out, encapsulation_id_out),
        // PRECONDITION_NOT_MET: a reader of a GROUP-scope Subscriber read
        // outside an access bracket (DDS v1.4 Sec.2.2.2.5.2.8), as the
        // `_w_condition` forms map it.
        Err(hdds::api::Error::InvalidState(_)) => HddsError::HddsInvalidState,
        Err(_) => HddsError::HddsOperationFailed,
    }
}

/// A sample a sized take refused: its size and its representation, for the
/// `HDDS_OUT_OF_MEMORY` report. The sample itself stays in the reader.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TooBig {
    len: usize,
    encapsulation_id: u16,
}

/// The size gate of the take forms: a payload of at most `max_len` bytes is
/// taken, a longer one is refused with its size (see `take_if`).
pub(crate) fn fits_in(max_len: usize) -> impl Fn(&BytePayload) -> Result<(), TooBig> {
    move |payload| {
        if payload.data.len() <= max_len {
            Ok(())
        } else {
            Err(TooBig {
                len: payload.data.len(),
                encapsulation_id: payload.encapsulation_id(),
            })
        }
    }
}

/// The report of a refused sized take: `*len_out` is the required size and,
/// when `encapsulation_id_out` is not NULL, it names the refused sample's
/// representation. Nothing was taken.
///
/// # Safety
/// - `len_out` must be a valid pointer
/// - `encapsulation_id_out` must be NULL or a valid pointer
pub(crate) unsafe fn report_too_big(
    too_big: TooBig,
    len_out: *mut usize,
    encapsulation_id_out: *mut u16,
) -> HddsError {
    *len_out = too_big.len;
    if !encapsulation_id_out.is_null() {
        *encapsulation_id_out = too_big.encapsulation_id;
    }
    HddsError::HddsOutOfMemory
}

/// Copy a taken payload to the caller: its length into `*len_out` (always),
/// its encapsulation identifier into `*encapsulation_id_out` (when not
/// NULL, always), its bytes into `data_out` when `max_len` holds them
/// (`HDDS_OUT_OF_MEMORY` otherwise).
///
/// # Safety
/// - `data_out` must point to at least `max_len` writable bytes
/// - `len_out` must be a valid pointer
/// - `encapsulation_id_out` must be NULL or a valid pointer
pub(crate) unsafe fn copy_payload_out(
    payload: &BytePayload,
    data_out: *mut c_void,
    max_len: usize,
    len_out: *mut usize,
    encapsulation_id_out: *mut u16,
) -> HddsError {
    let required = payload.data.len();
    *len_out = required;
    if !encapsulation_id_out.is_null() {
        *encapsulation_id_out = payload.encapsulation_id();
    }
    if required > max_len {
        return HddsError::HddsOutOfMemory;
    }
    ptr::copy_nonoverlapping(payload.data.as_ptr(), data_out.cast::<u8>(), required);
    HddsError::HddsOk
}

/// Destroy a `DataReader`
///
/// # Safety
/// - `reader` must be a valid pointer returned from `hdds_reader_create`
/// - Must not be called more than once with the same pointer
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_destroy(reader: *mut HddsDataReader) {
    if !reader.is_null() {
        // A C listener's callbacks must be over before the caller frees
        // their user_data: detach waits for them. From inside one of the
        // reader's own callbacks the reader cannot be freed (see Detached).
        if let listener::Detached::Free = listener::reader_listener_detach(reader) {
            reader_release_handle(reader);
        }
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
    rmw_process_init();
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

/// Create a new rmw context on an explicit DDS domain.
///
/// `rmw_init` resolves the ROS domain (`init_options.domain_id`, filled by
/// `rcl` from `ROS_DOMAIN_ID`) before the middleware is reached; this is the
/// entry point that carries it down to the participant. The domain-less
/// [`hdds_rmw_context_create`] is kept and behaves as domain 0.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_create_with_domain(
    name: *const c_char,
    domain_id: u32,
) -> *mut HddsRmwContext {
    rmw_process_init();
    if name.is_null() {
        return ptr::null_mut();
    }

    let Ok(name_str) = CStr::from_ptr(name).to_str() else {
        return ptr::null_mut();
    };

    match ForeignRmwContext::create_with_domain(name_str, domain_id) {
        Ok(ctx) => {
            #[allow(clippy::arc_with_non_send_sync)]
            let arc = Arc::new(ctx);
            Box::into_raw(Box::new(arc)).cast::<HddsRmwContext>()
        }
        Err(_err) => ptr::null_mut(),
    }
}

/// DDS domain the context's participant joined.
///
/// Returns `u32::MAX` when `ctx` is NULL, so a caller that ignores the null
/// case cannot mistake the answer for domain 0.
///
/// # Safety
/// `ctx` must be NULL or a valid `HddsRmwContext`.
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_domain_id(ctx: *mut HddsRmwContext) -> u32 {
    if ctx.is_null() {
        return u32::MAX;
    }
    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    ctx_ref.domain_id()
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
        Err(ApiError::Config(_)) => HddsError::HddsOk,
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

    let gid = copy_rmw_gid(endpoint_gid);

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
        Err(ApiError::Config(_)) => HddsError::HddsOk,
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

    let gid = copy_rmw_gid(endpoint_gid);

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

    let gid = copy_rmw_gid(endpoint_gid);

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
        Err(ApiError::Config(_)) => HddsError::HddsOk,
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

    let gid = copy_rmw_gid(endpoint_gid);

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
        Err(ApiError::Config(_)) => None,
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
/// Returns OUT_OF_MEMORY when the next SHM message is longer than `max_len`,
/// with its length in `*len_out`: nothing was consumed, so the caller grows
/// its buffer to that length and calls again. A caller that falls back to
/// RTPS instead leaves that message in the ring and gets OUT_OF_MEMORY again.
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
        Ok(Some(len)) => {
            *len_out = len;
            HddsError::HddsOk
        }
        Ok(None) => {
            *len_out = 0;
            HddsError::HddsNotFound
        }
        Err(needed) => {
            *len_out = needed;
            HddsError::HddsOutOfMemory
        }
    }
}

/// Consume the next SHM message of `topic` that is longer than `max_len`,
/// without copying it: the caller's buffer cannot hold it, so it is out of
/// contract for that caller and must not stay at the head of the ring.
/// Returns OK with `*len_out` set to its length when one was consumed, and
/// NOT_FOUND when no SHM message is longer than `max_len`. A message that fits
/// is never touched.
///
/// # Safety
/// - `ctx` must be a valid `HddsRmwContext`
/// - `topic` must be a valid C string
/// - `len_out` must be a valid pointer
#[cfg(feature = "rmw")]
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_context_shm_skip_oversize(
    ctx: *mut HddsRmwContext,
    topic: *const c_char,
    max_len: usize,
    len_out: *mut usize,
) -> HddsError {
    if ctx.is_null() || topic.is_null() || len_out.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let ctx_ref = &*ctx.cast::<Arc<ForeignRmwContext>>();
    let topic_str = match CStr::from_ptr(topic).to_str() {
        Ok(s) => s,
        Err(_) => return HddsError::HddsInvalidArgument,
    };

    match ctx_ref.shm_skip_oversize(topic_str, max_len) {
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
    let mut dropped = 0usize;

    for hit in hits {
        if hit.key == ctx_ref.graph_guard_key() {
            if !out_guard_triggered.is_null() {
                *out_guard_triggered = true;
            }
            continue;
        }

        if let Some(reader_ptr) = hit.reader_ptr {
            // `max_readers` is the capacity of the CALLER'S buffer. It is not
            // a statement about how many readers the context has, so an
            // overflow is not a failed wait: report what fits, keep scanning
            // for the guard hit (which may come after the readers in this
            // list, and losing it would lose a graph event), and say so.
            // Readers left out stay ready, so the next wait picks them up.
            if reader_count >= max_readers {
                dropped += 1;
                continue;
            }
            *out_readers.add(reader_count) =
                reader_ptr.cast::<HddsDataReader>() as *mut HddsDataReader;
            reader_count += 1;
        }
    }

    if dropped > 0 {
        log::warn!(
            "[rmw] wait reported {reader_count} ready readers and dropped {dropped} more: \
             the caller's buffer holds {max_readers}"
        );
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

/// Bounds proof for the rmw GID copy: the caller's buffer is 16 bytes wide on
/// Iron and Jazzy, and the copy must not read past it.
#[cfg(all(test, feature = "rmw", target_os = "linux"))]
mod rmw_gid_bounds_tests {
    use super::{copy_rmw_gid, HDDS_RMW_GID_SIZE, HDDS_RMW_GID_WIRE};

    /// Read exactly `HDDS_RMW_GID_WIRE` bytes from a caller buffer that is
    /// exactly that wide, and zero-pad the rest of the graph key.
    ///
    /// The buffer is placed at the very end of a mapped page whose successor
    /// page is `PROT_NONE`, so any read past byte 16 faults. The copy runs in
    /// a forked child: a fault there is an abnormal child exit this test can
    /// observe, instead of taking the whole test binary down. Copying
    /// `HDDS_RMW_GID_SIZE` (24) bytes would die on SIGSEGV here: this is the
    /// 8-byte over-read on Iron and Jazzy in memory terms.
    #[test]
    fn gid_copy_reads_16_bytes_only() {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        assert!(page >= HDDS_RMW_GID_SIZE, "page smaller than a GID key");

        // Two pages: [0] readable and writable, [1] unreadable guard.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page * 2,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED, "mmap of the probe pages failed");
        let guard = unsafe { base.cast::<u8>().add(page) };
        assert_eq!(
            unsafe { libc::mprotect(guard.cast(), page, libc::PROT_NONE) },
            0,
            "mprotect of the guard page failed"
        );

        // The caller's 16-byte GID sits flush against the guard page.
        let gid_ptr = unsafe { guard.sub(HDDS_RMW_GID_WIRE) };
        for i in 0..HDDS_RMW_GID_WIRE {
            unsafe { gid_ptr.add(i).write(0xA0 + i as u8) };
        }

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // Child: perform the copy and check the result, then _exit with a
            // code the parent can read. A fault never reaches this exit.
            let gid = unsafe { copy_rmw_gid(gid_ptr) };
            let mut ok = true;
            for (i, byte) in gid.iter().enumerate().take(HDDS_RMW_GID_WIRE) {
                ok &= *byte == 0xA0 + i as u8;
            }
            for byte in gid.iter().skip(HDDS_RMW_GID_WIRE) {
                ok &= *byte == 0;
            }
            unsafe { libc::_exit(if ok { 0 } else { 3 }) };
        }

        let mut status: libc::c_int = 0;
        assert!(
            unsafe { libc::waitpid(pid, &mut status, 0) } == pid,
            "waitpid failed"
        );
        assert!(
            libc::WIFEXITED(status),
            "the GID copy faulted (signal {}): it read past the caller's \
             {HDDS_RMW_GID_WIRE}-byte buffer into the guard page",
            libc::WTERMSIG(status)
        );
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "the GID copy produced the wrong key (16 source bytes then zero padding)"
        );

        unsafe { libc::munmap(base, page * 2) };
    }
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

    /// The `distro` argument of `hdds_participant_register_type_support` is a
    /// public C entry point that never goes through an rmw context: no
    /// `rmw_process_init`, no `ROS_DISTRO`, no process-global. The layout
    /// must therefore be detected from the object itself: otherwise a
    /// Jazzy-shaped type support would have `has_any_key_member_` plus padding
    /// read as the member array pointer.
    #[test]
    #[cfg(feature = "xtypes")]
    fn jazzy_type_support_registers_through_the_plain_c_abi() {
        /// The Jazzy C structs, declared by hand. `has_any_key_member_` sits
        /// where the pre-Jazzy layout declares `members_`.
        #[repr(C)]
        struct JazzyMessageMember {
            name_: *const c_char,
            type_id_: u8,
            string_upper_bound_: usize,
            members_: *const c_void,
            is_key_: bool,
            is_array_: bool,
            array_size_: usize,
            is_upper_bound_: bool,
            offset_: u32,
            default_value_: *const c_void,
            size_function: Option<unsafe extern "C" fn(*const c_void) -> usize>,
            get_const_function: Option<unsafe extern "C" fn(*const c_void, usize) -> *const c_void>,
            get_function: Option<unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void>,
            fetch_function: Option<unsafe extern "C" fn(*const c_void, usize, *mut c_void)>,
            assign_function: Option<unsafe extern "C" fn(*mut c_void, usize, *const c_void)>,
            resize_function: Option<unsafe extern "C" fn(*mut c_void, usize) -> bool>,
        }

        #[repr(C)]
        struct JazzyMessageMembers {
            message_namespace_: *const c_char,
            message_name_: *const c_char,
            member_count_: u32,
            size_of_: usize,
            has_any_key_member_: bool,
            /// Explicit padding, zeroed by the fixture. `RosIntrospectionLayout
            /// ::detect` reads this whole slot as one `usize` and decides the
            /// layout from the value, so these bytes are input, not slack.
            /// Left implicit they are uninitialised and the fixture rides on
            /// whatever the allocator handed back; a real Jazzy typesupport
            /// object is a C `static` whose padding is emitted as zero.
            _pad: [u8; std::mem::align_of::<*const c_void>() - 1],
            members_: *const JazzyMessageMember,
            init_function: Option<unsafe extern "C" fn(*mut c_void, i32)>,
            fini_function: Option<unsafe extern "C" fn(*mut c_void)>,
        }

        unsafe {
            let member = Box::leak(Box::new(JazzyMessageMember {
                name_: b"x\0".as_ptr().cast(),
                type_id_: 1,
                string_upper_bound_: 0,
                members_: ptr::null(),
                is_key_: false,
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
            }));

            let descriptor = Box::leak(Box::new(JazzyMessageMembers {
                message_namespace_: b"test_pkg__msg\0".as_ptr().cast(),
                message_name_: b"JazzyPoint\0".as_ptr().cast(),
                member_count_: 1,
                size_of_: 4,
                // false, so a pre-Jazzy read gets a NULL member array and a
                // clean error instead of a segfault: the point of the test is
                // the layout, not the crash.
                has_any_key_member_: false,
                _pad: [0u8; std::mem::align_of::<*const c_void>() - 1],
                members_: std::ptr::from_ref(&*member),
                init_function: None,
                fini_function: None,
            }));

            let type_support = Box::leak(Box::new(rosidl_message_type_support_t {
                typesupport_identifier: b"rosidl_typesupport_introspection_c\0".as_ptr().cast(),
                data: std::ptr::from_ref(&*descriptor).cast::<c_void>(),
                func: None,
                get_type_hash_func: Some(stub_hash),
                get_type_description_func: None,
                get_type_description_sources_func: None,
            }));

            let name = CString::new("ffi_register_jazzy").unwrap();
            let participant = hdds_participant_create(name.as_ptr());
            assert!(!participant.is_null());

            let mut handle: *const HddsTypeObject = ptr::null();
            // 2 == Distro::Jazzy. No rmw context exists in this process, so
            // there is no process-global layout to fall back on.
            let err = hdds_participant_register_type_support(
                participant,
                2,
                type_support,
                std::ptr::addr_of_mut!(handle),
            );
            assert_eq!(
                err,
                HddsError::HddsOk,
                "a Jazzy type support must register through the plain C ABI; \
                 reading it with the pre-Jazzy layout yields a NULL member array"
            );
            assert!(!handle.is_null());

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

    /// A writer created through the C ABI with no DATA_REPRESENTATION offers
    /// XCDR2, the representation the SDK codecs serialize (`sdk_writer_qos`),
    /// by every creation path; one that set a list keeps it.
    #[test]
    fn a_c_writer_that_set_no_representation_offers_xcdr2() {
        unsafe {
            let name = CString::new("test_c_writer_representation").unwrap();
            let participant = hdds_participant_create_with_transport(
                name.as_ptr(),
                HddsTransportMode::HddsTransportIntraProcess,
            );
            assert!(!participant.is_null());
            let topic = CString::new("test_c_writer_representation").unwrap();
            let type_name = CString::new("CWriterRepresentationT").unwrap();
            let explicit = Box::into_raw(Box::new(QoS::default().data_representation_xcdr1()));
            let writers = [
                (
                    hdds_writer_create(participant, topic.as_ptr()),
                    vec![0x0002],
                ),
                (
                    hdds_writer_create_with_qos(participant, topic.as_ptr(), ptr::null()),
                    vec![0x0002],
                ),
                (
                    hdds_writer_create_with_type(
                        participant,
                        topic.as_ptr(),
                        type_name.as_ptr(),
                        ptr::null(),
                    ),
                    vec![0x0002],
                ),
                (
                    hdds_writer_create_with_qos(
                        participant,
                        topic.as_ptr(),
                        explicit.cast::<HddsQoS>(),
                    ),
                    vec![0x0000],
                ),
            ];
            for (writer, expected) in writers {
                assert!(!writer.is_null());
                let writer_ref = &*writer.cast::<DataWriter<BytePayload>>();
                assert_eq!(writer_ref.qos().data_representation, expected);
                hdds_writer_destroy(writer);
            }
            drop(Box::from_raw(explicit));
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

    /// A RELIABLE writer's `write()` blocks for at most its QoS
    /// `max_blocking_time` (DDS v1.4 Sec.2.2.3.14) before returning an
    /// error, once a matched RELIABLE KEEP_ALL reader's resource limits are
    /// full and it never calls `take()`. The writer and reader are created
    /// on the same intra-process participant, so they auto-bind through the
    /// domain registry with no discovery delay (see
    /// `hdds::dds::domain_registry`); this exercises the whole C ABI path
    /// (`hdds_qos_set_max_blocking_time_ns` through `hdds_writer_write`),
    /// not just the getter/setter round trip.
    #[test]
    fn test_writer_write_blocks_for_its_qos_max_blocking_time() {
        unsafe {
            let name = CString::new("test_max_blocking_time_participant").unwrap();
            let participant = hdds_participant_create_with_transport(
                name.as_ptr(),
                HddsTransportMode::HddsTransportIntraProcess,
            );
            assert!(!participant.is_null());

            let topic = CString::new("test_max_blocking_time_topic").unwrap();

            // RELIABLE, KEEP_ALL, exactly one sample of room: the second
            // write has nowhere to go once the reader never takes the first.
            let make_qos = || {
                let q = qos::hdds_qos_reliable();
                assert_eq!(qos::hdds_qos_set_history_keep_all(q), HddsError::HddsOk);
                assert_eq!(
                    qos::hdds_qos_set_resource_limits(q, 1, 1, 1),
                    HddsError::HddsOk
                );
                q
            };

            let reader_qos = make_qos();
            let reader = hdds_reader_create_with_qos(participant, topic.as_ptr(), reader_qos);
            assert!(!reader.is_null());
            qos::hdds_qos_destroy(reader_qos);

            let writer_qos = make_qos();
            const MAX_BLOCKING_NS: u64 = 300_000_000; // 300 ms
            assert_eq!(
                qos::hdds_qos_set_max_blocking_time_ns(writer_qos, MAX_BLOCKING_NS),
                HddsError::HddsOk
            );
            let writer = hdds_writer_create_with_qos(participant, topic.as_ptr(), writer_qos);
            assert!(!writer.is_null());
            qos::hdds_qos_destroy(writer_qos);

            // Fills the reader's one slot of room; the reader never takes it.
            let first = b"first";
            assert_eq!(
                hdds_writer_write(writer, first.as_ptr().cast::<c_void>(), first.len()),
                HddsError::HddsOk
            );

            let second = b"second";
            let start = std::time::Instant::now();
            let result = hdds_writer_write(writer, second.as_ptr().cast::<c_void>(), second.len());
            let waited = start.elapsed();

            assert_ne!(
                result,
                HddsError::HddsOk,
                "a full reader must refuse the second write"
            );
            // A tight band around the configured 300 ms proves the QoS value
            // was actually used, not the DDS default of 100 ms (a mutated or
            // ignored setter would come back around 100 ms instead).
            assert!(
                waited >= Duration::from_millis(250),
                "returned too early: waited {waited:?}, expected >= 250ms"
            );
            assert!(
                waited < Duration::from_millis(600),
                "returned too late: waited {waited:?}, expected < 600ms"
            );

            hdds_writer_destroy(writer);
            hdds_reader_destroy(reader);
            hdds_participant_destroy(participant);
        }
    }

    /// `hdds_writer_wait_for_acknowledgments` when NO reader is matched
    /// at all: `HddsOk` at once (DDS v1.4 2.2.2.4.2.15's own case over
    /// an empty set of matched RELIABLE readers is vacuously true -- the
    /// same case
    /// `wait_for_acknowledgments_is_vacuous_for_a_same_participant_reader`
    /// pins at the Rust level). A genuine matched-but-not-yet-acknowledged
    /// probe is not possible here: the writer's match callback fires its
    /// first HEARTBEAT as part of the SAME event that confirms the match, so
    /// there is no race-free window to demonstrate `HddsTimeout` through this
    /// black-box C surface alone. The
    /// timeout branch itself is pinned deterministically at the Rust
    /// level instead:
    /// `dds::writer::acknowledgement_tests::wait_for_acknowledgments_times_out_when_nobody_acks`
    /// drives `ack_track` directly, with no real network race to win.
    #[test]
    fn test_writer_wait_for_acknowledgments_returns_ok_with_no_matched_reader() {
        unsafe {
            let name = CString::new("wait_for_ack_no_reader_c_test").unwrap();
            let participant = hdds_participant_create(name.as_ptr());
            assert!(!participant.is_null());

            let topic = CString::new("WaitForAckNoReaderCTopic").unwrap();
            let q = qos::hdds_qos_reliable();
            let writer = hdds_writer_create_with_qos(participant, topic.as_ptr(), q);
            assert!(!writer.is_null());

            let payload = [1u8, 2, 3, 4];
            assert_eq!(
                hdds_writer_write(writer, payload.as_ptr().cast::<c_void>(), payload.len()),
                HddsError::HddsOk
            );

            assert_eq!(
                hdds_writer_wait_for_acknowledgments(writer, 150),
                HddsError::HddsOk,
                "no RELIABLE reader is matched: vacuously true over an empty set"
            );

            qos::hdds_qos_destroy(q);
            hdds_writer_destroy(writer);
            hdds_participant_destroy(participant);
        }
    }

    /// `hdds_writer_wait_for_acknowledgments`, the real ack-then-return
    /// path: a writer and reader on SEPARATE participants (so a real
    /// SEDP match and a real ACKNACK over UDP are what this test
    /// exercises, not the same-participant path, which never populates
    /// the writer's ACKNACK watermark map -- see
    /// `wait_for_acknowledgments_is_vacuous_for_a_same_participant_reader`
    /// in `crates/hdds/tests/reliable_readers_acknowledge_under_their_own_name.rs`).
    /// TRANSIENT_LOCAL so the reader is owed the write whichever order
    /// match and write land in.
    #[test]
    fn test_writer_wait_for_acknowledgments_real_ack_path() {
        unsafe {
            let writer_name = CString::new("wait_for_ack_real_c_writer").unwrap();
            let writer_participant = hdds_participant_create(writer_name.as_ptr());
            assert!(!writer_participant.is_null());
            let reader_name = CString::new("wait_for_ack_real_c_reader").unwrap();
            let reader_participant = hdds_participant_create(reader_name.as_ptr());
            assert!(!reader_participant.is_null());

            let topic = CString::new("WaitForAckRealCTopic").unwrap();
            let q = qos::hdds_qos_reliable();
            assert_eq!(qos::hdds_qos_set_transient_local(q), HddsError::HddsOk);

            let writer = hdds_writer_create_with_qos(writer_participant, topic.as_ptr(), q);
            assert!(!writer.is_null());

            let payload = [5u8, 6, 7, 8];
            assert_eq!(
                hdds_writer_write(writer, payload.as_ptr().cast::<c_void>(), payload.len()),
                HddsError::HddsOk
            );

            let reader = hdds_reader_create_with_qos(reader_participant, topic.as_ptr(), q);
            assert!(!reader.is_null());

            assert_eq!(
                hdds_writer_wait_for_matched_readers(writer, 1, 10_000),
                HddsError::HddsOk,
                "the reader must match within 10s"
            );
            assert_eq!(
                hdds_writer_wait_for_acknowledgments(writer, 10_000),
                HddsError::HddsOk,
                "a real matched RELIABLE reader must acknowledge within 10s"
            );

            qos::hdds_qos_destroy(q);
            hdds_reader_destroy(reader);
            hdds_writer_destroy(writer);
            hdds_participant_destroy(writer_participant);
            hdds_participant_destroy(reader_participant);
        }
    }
}
