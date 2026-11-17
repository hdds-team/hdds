// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! FFI bindings for ContentFilteredTopic, ReadCondition, and QueryCondition
//! (DDS v1.4 Sec.2.2.2.5.8, 2.2.2.5.9, 2.2.4.5).
//!
//! The C reader carries an opaque byte payload, so anything that has to
//! look INSIDE a sample (a content filter, a query) needs the sample's
//! schema from the application: a dynamic type descriptor built with
//! `hdds_type_builder_*`. The payload is decoded with it and every
//! top-level primitive or string field becomes a query field under its
//! own name. The bytes are the XCDR2 little-endian body
//! `hdds_dynamic_data_encode` produces, without an encapsulation header,
//! which is what `hdds_writer_write` sends as-is and the representation a
//! reader of this ABI requests (`sdk_reader_qos`). A payload the descriptor
//! cannot decode is rejected by a content filter and matched by no query,
//! whatever the expression.
//!
//! Handles: a ReadCondition or QueryCondition handle is a strong reference
//! to a condition the reader created; `hdds_*_condition_delete` detaches
//! the condition from its reader (DDS `delete_readcondition`: silent from
//! then on) and releases the handle. A WaitSet keeps its own reference
//! while the condition is attached, so the handle may be deleted before it
//! is detached and the handle value remains a valid detach key.
//!
//! Handle refcounting: the handle IS the address of an `Arc::into_raw`
//! allocation, and a per-condition registry (`read_condition_registry` /
//! `query_condition_registry`) tracks how many outstanding C handles refer
//! to it, exactly like `hdds_guard_condition_create` in `lib.rs`. That
//! makes a repeated `hdds_*_condition_delete` call on the same pointer a
//! safe no-op instead of a double-free: the first call detaches from the
//! reader and drops the registry's own reference, and every later call
//! finds no entry left. `hdds_waitset_attach_*` clones the `Arc` out of
//! this registry rather than incrementing the raw pointer's strong count
//! directly, so attaching a handle that was already deleted fails closed
//! (`HDDS_INVALID_ARGUMENT`) instead of touching freed memory.

use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::slice;
use std::sync::{Arc, Mutex, OnceLock};

use hdds::api::{Participant, QoS};
use hdds::dds::filter::{ContentFilter, FieldValue};
use hdds::dds::{
    Condition, DataReader, Error as ApiError, FieldExtractor, InstanceState, InstanceStateMask,
    QueryCondition, ReadCondition, SampleInfo, SampleState, SampleStateMask, ViewState,
    ViewStateMask,
};
use hdds::dynamic::{decode_dynamic_with_version, DynamicValue, TypeDescriptor};

use crate::waitset::ForeignWaitSet;
use crate::{
    copy_payload_out, fits_in, reader_arc_from_handle, reader_into_handle, report_too_big,
    BytePayload, HddsDataReader, HddsError, HddsParticipant, HddsQoS, HddsTypeDescriptor,
    HddsWaitSet,
};

// =============================================================================
// ReadCondition / QueryCondition handle registries
// =============================================================================
//
// ReadCondition and QueryCondition are created attached to a reader (unlike
// StatusCondition, which is retrieved from an entity that already owns an
// Arc), so they follow the same pattern `hdds_guard_condition_create` uses in
// lib.rs: the handle IS the address of an `Arc::into_raw` allocation, and a
// registry keyed on that address tracks how many outstanding C handles refer
// to it. `hdds_waitset_attach_*` clones the Arc out of this registry and
// hands the clone to `ForeignWaitSet`, so the waitset keeps the condition
// alive on its own even if the C caller deletes its handle first -- see the
// ownership note in `crate::waitset`.

struct ReadConditionRegistryEntry {
    condition: Arc<ReadCondition>,
    handles: usize,
}

struct QueryConditionRegistryEntry {
    condition: Arc<QueryCondition>,
    handles: usize,
}

fn read_condition_registry() -> &'static Mutex<HashMap<usize, ReadConditionRegistryEntry>> {
    static REGISTRY: OnceLock<Mutex<HashMap<usize, ReadConditionRegistryEntry>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn query_condition_registry() -> &'static Mutex<HashMap<usize, QueryConditionRegistryEntry>> {
    static REGISTRY: OnceLock<Mutex<HashMap<usize, QueryConditionRegistryEntry>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn read_condition_registry_add_handle(
    raw: *const HddsReadCondition,
    condition: Arc<ReadCondition>,
) {
    if raw.is_null() {
        return;
    }
    let mut registry = read_condition_registry()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let entry = registry
        .entry(raw as usize)
        .or_insert_with(|| ReadConditionRegistryEntry {
            condition,
            handles: 0,
        });
    entry.handles = entry.handles.saturating_add(1);
}

fn read_condition_registry_clone(raw: *const HddsReadCondition) -> Option<Arc<ReadCondition>> {
    if raw.is_null() {
        return None;
    }
    let registry = read_condition_registry()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    registry
        .get(&(raw as usize))
        .map(|entry| entry.condition.clone())
}

fn read_condition_registry_release(raw: *const HddsReadCondition) -> bool {
    if raw.is_null() {
        return false;
    }
    let mut registry = read_condition_registry()
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

fn query_condition_registry_add_handle(
    raw: *const HddsQueryCondition,
    condition: Arc<QueryCondition>,
) {
    if raw.is_null() {
        return;
    }
    let mut registry = query_condition_registry()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let entry = registry
        .entry(raw as usize)
        .or_insert_with(|| QueryConditionRegistryEntry {
            condition,
            handles: 0,
        });
    entry.handles = entry.handles.saturating_add(1);
}

fn query_condition_registry_clone(raw: *const HddsQueryCondition) -> Option<Arc<QueryCondition>> {
    if raw.is_null() {
        return None;
    }
    let registry = query_condition_registry()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    registry
        .get(&(raw as usize))
        .map(|entry| entry.condition.clone())
}

fn query_condition_registry_release(raw: *const HddsQueryCondition) -> bool {
    if raw.is_null() {
        return false;
    }
    let mut registry = query_condition_registry()
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

// =============================================================================
// Opaque handle types
// =============================================================================

/// Opaque handle to a ContentFilteredTopic (untyped, using BytePayload)
pub struct HddsContentFilteredTopic {
    _private: [u8; 0],
}

/// Opaque handle to a ReadCondition
pub struct HddsReadCondition {
    _private: [u8; 0],
}

/// Opaque handle to a QueryCondition
pub struct HddsQueryCondition {
    _private: [u8; 0],
}

// =============================================================================
// State kinds (the bit values of the DDS masks)
// =============================================================================

/// Sample state bits (DDS v1.4 Sec.2.2.2.5.4). A mask is an OR of these.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HddsSampleStateKind {
    /// The sample has been returned by a read.
    HddsSampleStateRead = 1,
    /// The sample has not been read yet.
    HddsSampleStateNotRead = 2,
    /// READ | NOT_READ.
    HddsSampleStateAny = 3,
}

/// View state bits (DDS v1.4 Sec.2.2.2.5.4). A mask is an OR of these.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HddsViewStateKind {
    /// No sample of the instance has been read or taken yet.
    HddsViewStateNew = 1,
    /// The reader already handed out a sample of the instance.
    HddsViewStateNotNew = 2,
    /// NEW | NOT_NEW.
    HddsViewStateAny = 3,
}

/// Instance state bits (DDS v1.4 Sec.2.2.2.5.4). A mask is an OR of these.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HddsInstanceStateKind {
    /// The instance has a live writer.
    HddsInstanceStateAlive = 1,
    /// A writer disposed the instance.
    HddsInstanceStateNotAliveDisposed = 2,
    /// Every writer of the instance is gone.
    HddsInstanceStateNotAliveNoWriters = 4,
    /// ALIVE | NOT_ALIVE_DISPOSED | NOT_ALIVE_NO_WRITERS.
    HddsInstanceStateAny = 7,
}

/// Per-sample metadata returned by `hdds_reader_take_w_condition` and
/// `hdds_reader_read_w_condition` (DDS v1.4 Sec.2.2.2.5.5, reduced to what
/// the engine carries).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HddsSampleInfo {
    /// One `HddsSampleStateKind` bit: the state BEFORE this access.
    pub sample_state: u32,
    /// One `HddsViewStateKind` bit: the instance's state at this access.
    pub view_state: u32,
    /// One `HddsInstanceStateKind` bit.
    pub instance_state: u32,
    /// False for an instance-state transition, which carries no data.
    pub valid_data: bool,
    /// 16-byte instance handle (key hash; all zero for a keyless topic).
    pub instance_handle: [u8; 16],
    /// Writer timestamp in nanoseconds since the Unix epoch, 0 when the
    /// writer sent none.
    pub source_timestamp_ns: u64,
    /// When this reader observed the sample, nanoseconds since the epoch.
    pub reception_timestamp_ns: u64,
    /// Writer sequence number.
    pub sequence_number: u64,
}

fn sample_info_out(info: &SampleInfo) -> HddsSampleInfo {
    HddsSampleInfo {
        sample_state: match info.sample_state {
            SampleState::Read => HddsSampleStateKind::HddsSampleStateRead as u32,
            SampleState::NotRead => HddsSampleStateKind::HddsSampleStateNotRead as u32,
        },
        view_state: match info.view_state {
            ViewState::New => HddsViewStateKind::HddsViewStateNew as u32,
            ViewState::NotNew => HddsViewStateKind::HddsViewStateNotNew as u32,
        },
        instance_state: match info.instance_state {
            InstanceState::Alive => HddsInstanceStateKind::HddsInstanceStateAlive as u32,
            InstanceState::NotAliveDisposed => {
                HddsInstanceStateKind::HddsInstanceStateNotAliveDisposed as u32
            }
            InstanceState::NotAliveNoWriters => {
                HddsInstanceStateKind::HddsInstanceStateNotAliveNoWriters as u32
            }
        },
        valid_data: info.valid_data,
        instance_handle: *info.instance_handle.as_bytes(),
        source_timestamp_ns: info.source_timestamp_ns.unwrap_or(0),
        reception_timestamp_ns: info.reception_timestamp_ns,
        sequence_number: info.sequence_number,
    }
}

fn map_error(error: &ApiError) -> HddsError {
    match error {
        ApiError::InvalidState(_) => HddsError::HddsInvalidState,
        ApiError::Config(_) | ApiError::InvalidQos(_) => HddsError::HddsInvalidArgument,
        _ => HddsError::HddsOperationFailed,
    }
}

// =============================================================================
// Dynamic-type field extraction
// =============================================================================

/// One query field per top-level primitive, enum or string member of the
/// decoded struct. Nested structs, sequences, arrays and unions are not
/// addressable by the filter grammar and are skipped.
fn field_value(value: &DynamicValue) -> Option<FieldValue> {
    Some(match value {
        DynamicValue::Bool(v) => FieldValue::Boolean(*v),
        DynamicValue::U8(v) => FieldValue::Unsigned(u64::from(*v)),
        DynamicValue::U16(v) => FieldValue::Unsigned(u64::from(*v)),
        DynamicValue::U32(v) => FieldValue::Unsigned(u64::from(*v)),
        DynamicValue::U64(v) => FieldValue::Unsigned(*v),
        DynamicValue::I8(v) => FieldValue::Integer(i64::from(*v)),
        DynamicValue::I16(v) => FieldValue::Integer(i64::from(*v)),
        DynamicValue::I32(v) => FieldValue::Integer(i64::from(*v)),
        DynamicValue::I64(v) => FieldValue::Integer(*v),
        DynamicValue::F32(v) => FieldValue::Float(f64::from(*v)),
        DynamicValue::F64(v) => FieldValue::Float(*v),
        DynamicValue::Char(c) => FieldValue::String(c.to_string()),
        DynamicValue::String(s) | DynamicValue::WString(s) => FieldValue::String(s.clone()),
        DynamicValue::Enum(v, _) => FieldValue::Integer(*v),
        _ => return None,
    })
}

/// Decode a raw payload with `descriptor` into the field map a filter or a
/// query is evaluated against, in the representation the sample was
/// received in (`BytePayload::version`: a reader that requests XCDR receives
/// XCDR1 samples, whose 8-byte members sit at 8 where XCDR2 puts them at 4).
/// A payload that does not decode has no field map (`None`): a content
/// filter rejects it whatever the expression, and no query matches it.
fn dynamic_extractor(descriptor: Arc<TypeDescriptor>) -> FieldExtractor<BytePayload> {
    Arc::new(move |payload: &BytePayload| {
        let data = match decode_dynamic_with_version(&payload.data, &descriptor, payload.version) {
            Ok(data) => data,
            Err(error) => {
                log::debug!(
                    "dynamic field extraction: payload of {} bytes does not decode as '{}': {error:?}",
                    payload.data.len(),
                    descriptor.name
                );
                return None;
            }
        };
        let mut fields = HashMap::new();
        for (name, value) in data.fields() {
            if let Some(value) = field_value(value) {
                fields.insert(name.to_string(), value);
            }
        }
        Some(fields)
    })
}

/// # Safety
/// - `desc` must be a valid pointer returned by `hdds_type_builder_build`.
unsafe fn descriptor_arc(desc: *const HddsTypeDescriptor) -> Arc<TypeDescriptor> {
    Arc::clone(&*desc.cast::<Arc<TypeDescriptor>>())
}

// =============================================================================
// Internal wrapper for untyped ContentFilteredTopic
// =============================================================================

/// C FFI-friendly wrapper that stores the CFT data without generics.
///
/// Since the C layer operates on raw bytes (BytePayload), we store the
/// filter, topic names and the type descriptor the filter reads the bytes
/// with. The participant is passed again at reader creation, as every
/// other reader constructor does.
struct ForeignContentFilteredTopic {
    name: String,
    related_topic_name: String,
    filter: ContentFilter,
    descriptor: Arc<TypeDescriptor>,
}

// =============================================================================
// ContentFilteredTopic FFI
// =============================================================================

/// Create a ContentFilteredTopic with a SQL-like filter expression.
///
/// `type_desc` describes the samples of `related_topic`: the filter is
/// evaluated on the payload decoded with it (see the module docs). The
/// expression grammar is the `filter` module's subset (field op value,
/// AND / OR / NOT, `%n` parameters). Returns NULL when the expression does
/// not parse, the parameters do not fit it, or `type_desc` is NULL.
///
/// # Safety
///
/// - `participant` must be a valid pointer returned by `hdds_participant_create`
/// - `name`, `related_topic` and `filter_expression` must be valid
///   null-terminated C strings
/// - `type_desc` must be a valid pointer returned by `hdds_type_builder_build`
/// - `params` must be a valid array of `param_count` null-terminated C strings,
///   or NULL if `param_count` is 0
#[no_mangle]
pub unsafe extern "C" fn hdds_create_content_filtered_topic(
    participant: *mut HddsParticipant,
    name: *const c_char,
    related_topic: *const c_char,
    type_desc: *const HddsTypeDescriptor,
    filter_expression: *const c_char,
    params: *const *const c_char,
    param_count: usize,
) -> *mut HddsContentFilteredTopic {
    if participant.is_null()
        || name.is_null()
        || related_topic.is_null()
        || type_desc.is_null()
        || filter_expression.is_null()
    {
        return ptr::null_mut();
    }

    let Ok(name_str) = CStr::from_ptr(name).to_str() else {
        return ptr::null_mut();
    };
    let Ok(related_str) = CStr::from_ptr(related_topic).to_str() else {
        return ptr::null_mut();
    };
    let Ok(filter_str) = CStr::from_ptr(filter_expression).to_str() else {
        return ptr::null_mut();
    };

    let parameters = collect_string_params(params, param_count);

    let filter = match ContentFilter::with_parameters(filter_str, parameters) {
        Ok(f) => f,
        Err(e) => {
            log::error!(
                "Failed to parse filter expression '{}': {:?}",
                filter_str,
                e
            );
            return ptr::null_mut();
        }
    };

    // The participant is validated for non-null above like every other
    // constructor; nothing of it is kept.
    let cft = ForeignContentFilteredTopic {
        name: name_str.to_string(),
        related_topic_name: related_str.to_string(),
        filter,
        descriptor: descriptor_arc(type_desc),
    };

    Box::into_raw(Box::new(cft)).cast::<HddsContentFilteredTopic>()
}

/// Create a DataReader from a ContentFilteredTopic.
///
/// The reader only receives samples matching the CFT's filter expression:
/// the filter runs before the sample reaches the reader (on the writer's
/// thread for intra-process delivery, on the receive path for the network),
/// so a rejected sample takes no room and raises no DATA_AVAILABLE. The
/// reader has no type of its own and announces the type name its topic's
/// writers announce, else `RawBytes`, like `hdds_reader_create`; use
/// `hdds_create_reader_filtered_with_type` to choose the name.
///
/// # Safety
///
/// - `participant` must be a valid pointer returned by `hdds_participant_create`
/// - `cft` must be a valid pointer returned by `hdds_create_content_filtered_topic`
/// - `qos` can be NULL for default QoS
#[no_mangle]
pub unsafe extern "C" fn hdds_create_reader_filtered(
    participant: *mut HddsParticipant,
    cft: *mut HddsContentFilteredTopic,
    qos: *const HddsQoS,
) -> *mut HddsDataReader {
    hdds_create_reader_filtered_with_type(participant, cft, ptr::null(), qos)
}

/// `hdds_create_reader_filtered` announcing `type_name` in discovery
/// (NULL or empty: the name its topic's writers announce, else `RawBytes`).
///
/// # Safety
///
/// - `participant` must be a valid pointer returned by `hdds_participant_create`
/// - `cft` must be a valid pointer returned by `hdds_create_content_filtered_topic`
/// - `type_name` must be a valid null-terminated C string, or NULL
/// - `qos` can be NULL for default QoS
#[no_mangle]
pub unsafe extern "C" fn hdds_create_reader_filtered_with_type(
    participant: *mut HddsParticipant,
    cft: *mut HddsContentFilteredTopic,
    type_name: *const c_char,
    qos: *const HddsQoS,
) -> *mut HddsDataReader {
    if participant.is_null() || cft.is_null() {
        return ptr::null_mut();
    }

    let participant_ref = &*participant.cast::<Arc<Participant>>();
    let cft_ref = &*cft.cast::<ForeignContentFilteredTopic>();

    let qos_value = if qos.is_null() {
        QoS::default()
    } else {
        (*qos.cast::<QoS>()).clone()
    };

    let type_override = match crate::requested_type_name(type_name) {
        Ok(requested) => requested,
        Err(()) => return ptr::null_mut(),
    };

    let extractor = dynamic_extractor(Arc::clone(&cft_ref.descriptor));
    let built = participant_ref
        .topic::<BytePayload>(&cft_ref.related_topic_name)
        .and_then(|topic| {
            let mut builder = topic
                .reader()
                .qos(crate::sdk_reader_qos(qos_value))
                .with_content_filter(cft_ref.filter.evaluator())
                .with_field_extractor(extractor);
            // No type name given: a reader with no type of its own.
            builder = match type_override {
                Some(name) => builder.with_type_name(name),
                None => builder.adopting_type_name(),
            };
            builder.build()
        });
    match built {
        Ok(reader) => reader_into_handle(reader),
        Err(e) => {
            log::error!(
                "Failed to create filtered reader for topic '{}' (cft '{}'): {:?}",
                cft_ref.related_topic_name,
                cft_ref.name,
                e
            );
            ptr::null_mut()
        }
    }
}

/// Set new expression parameters on a ContentFilteredTopic.
///
/// Every reader created from the topic evaluates with the new values from
/// its next sample on. A parameter list that does not fit the expression
/// is rejected (`HDDS_INVALID_ARGUMENT`) and the previous values stay.
///
/// # Safety
///
/// - `cft` must be a valid pointer returned by `hdds_create_content_filtered_topic`
/// - `params` must be a valid array of `count` null-terminated C strings,
///   or NULL if `count` is 0
#[no_mangle]
pub unsafe extern "C" fn hdds_content_filtered_topic_set_params(
    cft: *mut HddsContentFilteredTopic,
    params: *const *const c_char,
    count: usize,
) -> HddsError {
    if cft.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let cft_ref = &*cft.cast::<ForeignContentFilteredTopic>();
    let parameters = collect_string_params(params, count);
    match cft_ref.filter.try_set_parameters(parameters) {
        Ok(()) => HddsError::HddsOk,
        Err(error) => {
            log::warn!("ContentFilteredTopic parameter update rejected: {error}");
            HddsError::HddsInvalidArgument
        }
    }
}

/// Delete a ContentFilteredTopic and free its resources. Readers created
/// from it keep their filter.
///
/// # Safety
///
/// - `cft` must be a valid pointer returned by `hdds_create_content_filtered_topic`,
///   or NULL (no-op)
/// - Must not be called more than once with the same pointer
#[no_mangle]
pub unsafe extern "C" fn hdds_content_filtered_topic_delete(cft: *mut HddsContentFilteredTopic) {
    if !cft.is_null() {
        let _ = Box::from_raw(cft.cast::<ForeignContentFilteredTopic>());
    }
}

// =============================================================================
// ContentFilteredTopic Getters
// =============================================================================

/// Get the filter expression string from a ContentFilteredTopic.
///
/// Copies the expression into the caller-provided buffer.
/// Returns the number of bytes needed (excluding null terminator); the copy
/// is truncated when `capacity` is too small.
///
/// # Safety
///
/// - `cft` must be a valid pointer returned by `hdds_create_content_filtered_topic`
/// - `out_buf` must point to at least `capacity` writable bytes
#[no_mangle]
pub unsafe extern "C" fn hdds_content_filtered_topic_get_expression(
    cft: *const HddsContentFilteredTopic,
    out_buf: *mut c_char,
    capacity: usize,
) -> usize {
    if cft.is_null() {
        return 0;
    }
    let cft_ref = &*cft.cast::<ForeignContentFilteredTopic>();
    copy_str_out(cft_ref.filter.expression(), out_buf, capacity)
}

/// Copy `text` into a C buffer, null-terminated and truncated to
/// `capacity`; returns the length `text` needs (without terminator).
///
/// # Safety
/// - `out_buf` must point to at least `capacity` writable bytes, or be NULL.
unsafe fn copy_str_out(text: &str, out_buf: *mut c_char, capacity: usize) -> usize {
    let bytes = text.as_bytes();
    let needed = bytes.len();
    if out_buf.is_null() || capacity == 0 {
        return needed;
    }
    let copy_len = needed.min(capacity - 1);
    if copy_len > 0 {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf.cast::<u8>(), copy_len);
    }
    *out_buf.add(copy_len) = 0;
    needed
}

// =============================================================================
// ReadCondition FFI
// =============================================================================

/// Create a ReadCondition attached to `reader` (DDS v1.4 Sec.2.2.2.5.3.5).
///
/// Its trigger is true while the reader holds a sample whose sample, view
/// and instance states are in the three masks (ORs of the
/// `Hdds*StateKind` bits). Read it with `hdds_read_condition_get_trigger`,
/// wait on it through `hdds_waitset_attach_read_condition`, and take the
/// matching samples with `hdds_reader_take_w_condition`.
///
/// # Safety
///
/// - `reader` must be a valid pointer returned by `hdds_reader_create` or similar
#[no_mangle]
pub unsafe extern "C" fn hdds_create_read_condition(
    reader: *mut HddsDataReader,
    sample_state_mask: u32,
    view_state_mask: u32,
    instance_state_mask: u32,
) -> *mut HddsReadCondition {
    if reader.is_null() {
        return ptr::null_mut();
    }
    let reader = reader_arc_from_handle(reader);
    match reader.create_readcondition(
        SampleStateMask::from_bits(sample_state_mask),
        ViewStateMask::from_bits(view_state_mask),
        InstanceStateMask::from_bits(instance_state_mask),
    ) {
        Ok(condition) => {
            let raw = Arc::into_raw(condition.clone())
                .cast_mut()
                .cast::<HddsReadCondition>();
            read_condition_registry_add_handle(raw as *const HddsReadCondition, condition);
            raw
        }
        Err(e) => {
            log::error!("Failed to create read condition: {:?}", e);
            ptr::null_mut()
        }
    }
}

/// Get the trigger value of a ReadCondition: true when the reader holds a
/// matching sample right now (DDS v1.4 Sec.2.2.4.5). Evaluating moves the
/// reader's pending samples into its cache, so this is a reader access,
/// subject to the reader's single-consumer contract.
///
/// # Safety
///
/// - `cond` must be a valid pointer returned by `hdds_create_read_condition`
#[no_mangle]
pub unsafe extern "C" fn hdds_read_condition_get_trigger(cond: *const HddsReadCondition) -> bool {
    if cond.is_null() {
        return false;
    }
    (*cond.cast::<ReadCondition>()).get_trigger_value()
}

/// Get the sample state mask of a ReadCondition.
///
/// # Safety
/// - `cond` must be a valid pointer returned by `hdds_create_read_condition`
#[no_mangle]
pub unsafe extern "C" fn hdds_read_condition_get_sample_state_mask(
    cond: *const HddsReadCondition,
) -> u32 {
    if cond.is_null() {
        return 0;
    }
    (*cond.cast::<ReadCondition>())
        .get_sample_state_mask()
        .bits()
}

/// Get the view state mask of a ReadCondition.
///
/// # Safety
/// - `cond` must be a valid pointer returned by `hdds_create_read_condition`
#[no_mangle]
pub unsafe extern "C" fn hdds_read_condition_get_view_state_mask(
    cond: *const HddsReadCondition,
) -> u32 {
    if cond.is_null() {
        return 0;
    }
    (*cond.cast::<ReadCondition>()).get_view_state_mask().bits()
}

/// Get the instance state mask of a ReadCondition.
///
/// # Safety
/// - `cond` must be a valid pointer returned by `hdds_create_read_condition`
#[no_mangle]
pub unsafe extern "C" fn hdds_read_condition_get_instance_state_mask(
    cond: *const HddsReadCondition,
) -> u32 {
    if cond.is_null() {
        return 0;
    }
    (*cond.cast::<ReadCondition>())
        .get_instance_state_mask()
        .bits()
}

/// Delete a ReadCondition (DDS v1.4 Sec.2.2.2.5.3.7): it is detached from
/// its reader at once (never evaluated or returned by a wait again, even
/// while a WaitSet still holds it) and the handle is released. Detach it
/// from its WaitSets with `hdds_waitset_detach_condition` to free the
/// WaitSet's own reference; the handle value stays a valid detach key.
///
/// Arc-backed and registry-refcounted, matching `hdds_guard_condition_release`:
/// a repeated call with the same pointer (or a NULL pointer) is a safe
/// no-op, not a double-free.
///
/// # Safety
///
/// - `cond` must be a valid pointer returned by `hdds_create_read_condition`,
///   or NULL (no-op)
#[no_mangle]
pub unsafe extern "C" fn hdds_read_condition_delete(cond: *mut HddsReadCondition) {
    if cond.is_null() {
        return;
    }
    if let Some(condition) = read_condition_registry_clone(cond as *const HddsReadCondition) {
        condition.detach();
    }
    if read_condition_registry_release(cond as *const HddsReadCondition) {
        drop(Arc::from_raw(cond.cast::<ReadCondition>().cast_const()));
    }
}

// =============================================================================
// QueryCondition FFI
// =============================================================================

/// Create a QueryCondition attached to `reader` (DDS v1.4 Sec.2.2.2.5.3.6):
/// a ReadCondition whose trigger also needs the sample's data to satisfy
/// `query`, evaluated on the payload decoded with `type_desc` (see the
/// module docs). `query` uses the `filter` module's SQL subset with `%n`
/// parameters taken from `params`. Returns NULL when the expression does
/// not parse, the parameters do not fit it, or `type_desc` is NULL.
///
/// # Safety
///
/// - `reader` must be a valid pointer returned by `hdds_reader_create` or similar
/// - `type_desc` must be a valid pointer returned by `hdds_type_builder_build`
/// - `query` must be a valid null-terminated C string
/// - `params` must be a valid array of `param_count` null-terminated C strings,
///   or NULL if `param_count` is 0
#[no_mangle]
pub unsafe extern "C" fn hdds_create_query_condition(
    reader: *mut HddsDataReader,
    sample_state_mask: u32,
    view_state_mask: u32,
    instance_state_mask: u32,
    type_desc: *const HddsTypeDescriptor,
    query: *const c_char,
    params: *const *const c_char,
    param_count: usize,
) -> *mut HddsQueryCondition {
    if reader.is_null() || type_desc.is_null() || query.is_null() {
        return ptr::null_mut();
    }

    let Ok(query_str) = CStr::from_ptr(query).to_str() else {
        return ptr::null_mut();
    };
    let parameters = collect_string_params(params, param_count);
    let extractor = dynamic_extractor(descriptor_arc(type_desc));

    let reader = reader_arc_from_handle(reader);
    match reader.create_querycondition_with_fields(
        SampleStateMask::from_bits(sample_state_mask),
        ViewStateMask::from_bits(view_state_mask),
        InstanceStateMask::from_bits(instance_state_mask),
        query_str,
        parameters,
        extractor,
    ) {
        Ok(condition) => {
            let raw = Arc::into_raw(condition.clone())
                .cast_mut()
                .cast::<HddsQueryCondition>();
            query_condition_registry_add_handle(raw as *const HddsQueryCondition, condition);
            raw
        }
        Err(e) => {
            log::error!("Failed to create query condition '{}': {:?}", query_str, e);
            ptr::null_mut()
        }
    }
}

/// Get the trigger value of a QueryCondition: true when the reader holds a
/// sample matching the masks whose data satisfies the query. Same reader
/// access note as `hdds_read_condition_get_trigger`.
///
/// # Safety
///
/// - `cond` must be a valid pointer returned by `hdds_create_query_condition`
#[no_mangle]
pub unsafe extern "C" fn hdds_query_condition_get_trigger(cond: *const HddsQueryCondition) -> bool {
    if cond.is_null() {
        return false;
    }
    (*cond.cast::<QueryCondition>()).get_trigger_value()
}

/// Get the query expression from a QueryCondition.
///
/// Copies the expression into the caller-provided buffer.
/// Returns the number of bytes needed (excluding null terminator).
///
/// # Safety
/// - `cond` must be a valid pointer returned by `hdds_create_query_condition`
/// - `out_buf` must point to at least `capacity` writable bytes
#[no_mangle]
pub unsafe extern "C" fn hdds_query_condition_get_expression(
    cond: *const HddsQueryCondition,
    out_buf: *mut c_char,
    capacity: usize,
) -> usize {
    if cond.is_null() {
        return 0;
    }
    let cond_ref = &*cond.cast::<QueryCondition>();
    copy_str_out(cond_ref.get_query_expression(), out_buf, capacity)
}

/// Set new query parameters on a QueryCondition (DDS v1.4
/// Sec.2.2.2.5.9.3). A list that does not fit the expression is rejected
/// (`HDDS_INVALID_ARGUMENT`) and the previous parameters stay in force.
///
/// # Safety
/// - `cond` must be a valid pointer returned by `hdds_create_query_condition`
/// - `params` must be a valid array of `count` null-terminated C strings,
///   or NULL if `count` is 0
#[no_mangle]
pub unsafe extern "C" fn hdds_query_condition_set_parameters(
    cond: *mut HddsQueryCondition,
    params: *const *const c_char,
    count: usize,
) -> HddsError {
    if cond.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let cond_ref = &*cond.cast::<QueryCondition>();
    let parameters = collect_string_params(params, count);
    match cond_ref.try_set_query_parameters(parameters) {
        Ok(()) => HddsError::HddsOk,
        Err(error) => {
            log::warn!("QueryCondition parameter update rejected: {error}");
            HddsError::HddsInvalidArgument
        }
    }
}

/// Delete a QueryCondition; see `hdds_read_condition_delete`.
///
/// # Safety
///
/// - `cond` must be a valid pointer returned by `hdds_create_query_condition`,
///   or NULL (no-op)
#[no_mangle]
pub unsafe extern "C" fn hdds_query_condition_delete(cond: *mut HddsQueryCondition) {
    if cond.is_null() {
        return;
    }
    if let Some(condition) = query_condition_registry_clone(cond as *const HddsQueryCondition) {
        condition.detach();
    }
    if query_condition_registry_release(cond as *const HddsQueryCondition) {
        drop(Arc::from_raw(cond.cast::<QueryCondition>().cast_const()));
    }
}

// =============================================================================
// WaitSet integration
// =============================================================================

/// Attach a ReadCondition to a WaitSet.
///
/// `hdds_waitset_wait` returns once the condition's trigger is true, and
/// reports the condition by this handle. Detach it with
/// `hdds_waitset_detach_condition`.
///
/// # Safety
///
/// - `ws` must be a valid pointer returned by `hdds_waitset_create`
/// - `cond` must be a valid pointer returned by `hdds_create_read_condition`
#[no_mangle]
pub unsafe extern "C" fn hdds_waitset_attach_read_condition(
    ws: *mut HddsWaitSet,
    cond: *mut HddsReadCondition,
) -> HddsError {
    if ws.is_null() || cond.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let waitset = &*ws.cast::<ForeignWaitSet>();
    let Some(condition) = read_condition_registry_clone(cond as *const HddsReadCondition) else {
        return HddsError::HddsInvalidArgument;
    };
    match waitset.attach_read(condition, cond.cast::<c_void>().cast_const()) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => err.into(),
    }
}

/// Attach a QueryCondition to a WaitSet; see
/// `hdds_waitset_attach_read_condition`.
///
/// # Safety
///
/// - `ws` must be a valid pointer returned by `hdds_waitset_create`
/// - `cond` must be a valid pointer returned by `hdds_create_query_condition`
#[no_mangle]
pub unsafe extern "C" fn hdds_waitset_attach_query_condition(
    ws: *mut HddsWaitSet,
    cond: *mut HddsQueryCondition,
) -> HddsError {
    if ws.is_null() || cond.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let waitset = &*ws.cast::<ForeignWaitSet>();
    let Some(condition) = query_condition_registry_clone(cond as *const HddsQueryCondition) else {
        return HddsError::HddsInvalidArgument;
    };
    match waitset.attach_query(condition, cond.cast::<c_void>().cast_const()) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => err.into(),
    }
}

// =============================================================================
// read_w_condition / take_w_condition
// =============================================================================

/// Take ONE sample matching `cond` (DDS v1.4 Sec.2.2.2.5.3.11). Loop until
/// `HDDS_NOT_FOUND` (NO_DATA) to drain every match.
///
/// Data samples come first, then, for a condition whose instance mask
/// admits a NOT_ALIVE state, the instance-state transitions: those return
/// `HDDS_OK` with `*len_out == 0` and `info_out->valid_data == false`.
/// `info_out` may be NULL. A payload longer than `max_len` returns
/// `HDDS_OUT_OF_MEMORY` with the required size in `*len_out`; the refused
/// take removes nothing and `info_out` is not written (`hdds_reader_take`'s
/// contract: a later take returns the head of the reader, normally this
/// sample).
/// `HDDS_INVALID_STATE` when the condition is not attached to this reader
/// (PRECONDITION_NOT_MET).
///
/// # Safety
/// - `reader` must be a valid pointer returned by `hdds_reader_create` or similar
/// - `cond` must be a valid pointer returned by `hdds_create_read_condition`
/// - `data_out` must point to at least `max_len` writable bytes
/// - `len_out` must be a valid pointer
/// - `info_out` must be a valid pointer or NULL
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_take_w_condition(
    reader: *mut HddsDataReader,
    cond: *const HddsReadCondition,
    data_out: *mut c_void,
    max_len: usize,
    len_out: *mut usize,
    info_out: *mut HddsSampleInfo,
) -> HddsError {
    if reader.is_null() || cond.is_null() || data_out.is_null() || len_out.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    take_one(
        &*reader.cast::<DataReader<BytePayload>>(),
        &*cond.cast::<ReadCondition>(),
        data_out,
        max_len,
        len_out,
        info_out,
        ptr::null_mut(),
    )
}

/// `hdds_reader_take_w_condition` for a QueryCondition: only a sample whose
/// data satisfies the query is taken. Transitions never match a query.
///
/// # Safety
/// Same as `hdds_reader_take_w_condition`, with `cond` from
/// `hdds_create_query_condition`.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_take_w_query_condition(
    reader: *mut HddsDataReader,
    cond: *const HddsQueryCondition,
    data_out: *mut c_void,
    max_len: usize,
    len_out: *mut usize,
    info_out: *mut HddsSampleInfo,
) -> HddsError {
    if reader.is_null() || cond.is_null() || data_out.is_null() || len_out.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    take_one(
        &*reader.cast::<DataReader<BytePayload>>(),
        &*cond.cast::<QueryCondition>(),
        data_out,
        max_len,
        len_out,
        info_out,
        ptr::null_mut(),
    )
}

/// Read ONE sample matching `cond` without removing it (DDS v1.4
/// Sec.2.2.2.5.3.10); the sample is READ afterwards, so with a NOT_READ
/// mask repeated calls walk the unread matches and a READ or ANY mask
/// returns the same first match again. `info_out->sample_state` is the
/// state before this call. An instance-state transition the condition
/// admits is read in place too: `HDDS_OK`, `*len_out == 0`,
/// `info_out->valid_data == false`. Same return codes as the take variant.
/// A payload longer than `max_len` returns `HDDS_OUT_OF_MEMORY` with the
/// required size in `*len_out`, and the sample is then NOT marked READ: a later
/// read (same caveats as `hdds_reader_take`) returns it, under a NOT_READ mask
/// too.
///
/// # Safety
/// Same as `hdds_reader_take_w_condition`.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_read_w_condition(
    reader: *mut HddsDataReader,
    cond: *const HddsReadCondition,
    data_out: *mut c_void,
    max_len: usize,
    len_out: *mut usize,
    info_out: *mut HddsSampleInfo,
) -> HddsError {
    if reader.is_null() || cond.is_null() || data_out.is_null() || len_out.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    read_one(
        &*reader.cast::<DataReader<BytePayload>>(),
        &*cond.cast::<ReadCondition>(),
        data_out,
        max_len,
        len_out,
        info_out,
        ptr::null_mut(),
    )
}

/// `hdds_reader_read_w_condition` for a QueryCondition.
///
/// # Safety
/// Same as `hdds_reader_take_w_condition`, with `cond` from
/// `hdds_create_query_condition`.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_read_w_query_condition(
    reader: *mut HddsDataReader,
    cond: *const HddsQueryCondition,
    data_out: *mut c_void,
    max_len: usize,
    len_out: *mut usize,
    info_out: *mut HddsSampleInfo,
) -> HddsError {
    if reader.is_null() || cond.is_null() || data_out.is_null() || len_out.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    read_one(
        &*reader.cast::<DataReader<BytePayload>>(),
        &*cond.cast::<QueryCondition>(),
        data_out,
        max_len,
        len_out,
        info_out,
        ptr::null_mut(),
    )
}

/// `hdds_reader_take_w_condition`, and the encapsulation identifier of the
/// representation the taken bytes are in, as `hdds_reader_take_ex` reports
/// it (0x0001 XCDR1, 0x0007 XCDR2). An instance-state transition, which
/// carries no data, reports 0.
///
/// # Safety
/// Same as `hdds_reader_take_w_condition`; `encapsulation_id_out` must be a
/// valid pointer.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_take_w_condition_ex(
    reader: *mut HddsDataReader,
    cond: *const HddsReadCondition,
    data_out: *mut c_void,
    max_len: usize,
    len_out: *mut usize,
    info_out: *mut HddsSampleInfo,
    encapsulation_id_out: *mut u16,
) -> HddsError {
    if reader.is_null()
        || cond.is_null()
        || data_out.is_null()
        || len_out.is_null()
        || encapsulation_id_out.is_null()
    {
        return HddsError::HddsInvalidArgument;
    }
    take_one(
        &*reader.cast::<DataReader<BytePayload>>(),
        &*cond.cast::<ReadCondition>(),
        data_out,
        max_len,
        len_out,
        info_out,
        encapsulation_id_out,
    )
}

/// `hdds_reader_take_w_query_condition` with the encapsulation identifier
/// of `hdds_reader_take_w_condition_ex`.
///
/// # Safety
/// Same as `hdds_reader_take_w_condition_ex`, with `cond` from
/// `hdds_create_query_condition`.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_take_w_query_condition_ex(
    reader: *mut HddsDataReader,
    cond: *const HddsQueryCondition,
    data_out: *mut c_void,
    max_len: usize,
    len_out: *mut usize,
    info_out: *mut HddsSampleInfo,
    encapsulation_id_out: *mut u16,
) -> HddsError {
    if reader.is_null()
        || cond.is_null()
        || data_out.is_null()
        || len_out.is_null()
        || encapsulation_id_out.is_null()
    {
        return HddsError::HddsInvalidArgument;
    }
    take_one(
        &*reader.cast::<DataReader<BytePayload>>(),
        &*cond.cast::<QueryCondition>(),
        data_out,
        max_len,
        len_out,
        info_out,
        encapsulation_id_out,
    )
}

/// `hdds_reader_read_w_condition` with the encapsulation identifier of
/// `hdds_reader_take_w_condition_ex`.
///
/// # Safety
/// Same as `hdds_reader_take_w_condition_ex`.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_read_w_condition_ex(
    reader: *mut HddsDataReader,
    cond: *const HddsReadCondition,
    data_out: *mut c_void,
    max_len: usize,
    len_out: *mut usize,
    info_out: *mut HddsSampleInfo,
    encapsulation_id_out: *mut u16,
) -> HddsError {
    if reader.is_null()
        || cond.is_null()
        || data_out.is_null()
        || len_out.is_null()
        || encapsulation_id_out.is_null()
    {
        return HddsError::HddsInvalidArgument;
    }
    read_one(
        &*reader.cast::<DataReader<BytePayload>>(),
        &*cond.cast::<ReadCondition>(),
        data_out,
        max_len,
        len_out,
        info_out,
        encapsulation_id_out,
    )
}

/// `hdds_reader_read_w_query_condition` with the encapsulation identifier
/// of `hdds_reader_take_w_condition_ex`.
///
/// # Safety
/// Same as `hdds_reader_take_w_condition_ex`, with `cond` from
/// `hdds_create_query_condition`.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_read_w_query_condition_ex(
    reader: *mut HddsDataReader,
    cond: *const HddsQueryCondition,
    data_out: *mut c_void,
    max_len: usize,
    len_out: *mut usize,
    info_out: *mut HddsSampleInfo,
    encapsulation_id_out: *mut u16,
) -> HddsError {
    if reader.is_null()
        || cond.is_null()
        || data_out.is_null()
        || len_out.is_null()
        || encapsulation_id_out.is_null()
    {
        return HddsError::HddsInvalidArgument;
    }
    read_one(
        &*reader.cast::<DataReader<BytePayload>>(),
        &*cond.cast::<QueryCondition>(),
        data_out,
        max_len,
        len_out,
        info_out,
        encapsulation_id_out,
    )
}

/// # Safety
/// Pointer contract of `hdds_reader_take_w_condition`.
unsafe fn take_one(
    reader: &DataReader<BytePayload>,
    condition: &ReadCondition,
    data_out: *mut c_void,
    max_len: usize,
    len_out: *mut usize,
    info_out: *mut HddsSampleInfo,
    encapsulation_id_out: *mut u16,
) -> HddsError {
    // The size check is part of the take (`take_w_condition_if`): a refused
    // sample is not removed, and no info is written for it.
    match reader.take_w_condition_if(condition, 1, fits_in(max_len)) {
        Ok(Ok(samples)) => match samples.into_iter().next() {
            None => HddsError::HddsNotFound,
            Some((data, info)) => {
                if !info_out.is_null() {
                    info_out.write(sample_info_out(&info));
                }
                match data {
                    Some(payload) => {
                        copy_payload_out(&payload, data_out, max_len, len_out, encapsulation_id_out)
                    }
                    None => {
                        *len_out = 0;
                        if !encapsulation_id_out.is_null() {
                            *encapsulation_id_out = 0;
                        }
                        HddsError::HddsOk
                    }
                }
            }
        },
        Ok(Err(too_big)) => report_too_big(too_big, len_out, encapsulation_id_out),
        Err(error) => map_error(&error),
    }
}

/// # Safety
/// Pointer contract of `hdds_reader_read_w_condition`.
unsafe fn read_one(
    reader: &DataReader<BytePayload>,
    condition: &ReadCondition,
    data_out: *mut c_void,
    max_len: usize,
    len_out: *mut usize,
    info_out: *mut HddsSampleInfo,
    encapsulation_id_out: *mut u16,
) -> HddsError {
    // The size check is part of the read (`read_w_condition_if`): a refused
    // sample is neither copied nor marked READ, so it stays unread.
    match reader.read_w_condition_if(condition, 1, fits_in(max_len)) {
        Ok(Ok(samples)) => match samples.into_iter().next() {
            None => HddsError::HddsNotFound,
            Some((data, info)) => {
                if !info_out.is_null() {
                    info_out.write(sample_info_out(&info));
                }
                match data {
                    Some(payload) => {
                        copy_payload_out(&payload, data_out, max_len, len_out, encapsulation_id_out)
                    }
                    None => {
                        *len_out = 0;
                        if !encapsulation_id_out.is_null() {
                            *encapsulation_id_out = 0;
                        }
                        HddsError::HddsOk
                    }
                }
            }
        },
        Ok(Err(too_big)) => report_too_big(too_big, len_out, encapsulation_id_out),
        Err(error) => map_error(&error),
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Collect C string array into Vec<String>.
///
/// # Safety
///
/// - `params` must be a valid array of `count` null-terminated C strings,
///   or NULL if `count` is 0
unsafe fn collect_string_params(params: *const *const c_char, count: usize) -> Vec<String> {
    if params.is_null() || count == 0 {
        return Vec::new();
    }

    let param_ptrs = slice::from_raw_parts(params, count);
    let mut result = Vec::with_capacity(count);
    for &ptr in param_ptrs {
        if ptr.is_null() {
            result.push(String::new());
        } else if let Ok(s) = CStr::from_ptr(ptr).to_str() {
            result.push(s.to_string());
        } else {
            result.push(String::new());
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hdds_dynamic_data_destroy, hdds_dynamic_data_encode, hdds_dynamic_data_new,
        hdds_dynamic_data_set_i32, hdds_participant_create_with_transport,
        hdds_participant_destroy, hdds_reader_create, hdds_reader_destroy, hdds_reader_take,
        hdds_type_builder_add_field, hdds_type_builder_build, hdds_type_builder_new,
        hdds_type_descriptor_destroy, hdds_waitset_create, hdds_waitset_destroy,
        hdds_waitset_detach_condition, hdds_waitset_wait, hdds_writer_create, hdds_writer_destroy,
        hdds_writer_write, HddsPrimitiveKind, HddsTransportMode,
    };
    use std::ffi::CString;

    const SAMPLE_ANY: u32 = HddsSampleStateKind::HddsSampleStateAny as u32;
    const VIEW_ANY: u32 = HddsViewStateKind::HddsViewStateAny as u32;
    const INSTANCE_ANY: u32 = HddsInstanceStateKind::HddsInstanceStateAny as u32;

    /// A `{ int32 id; int32 value; }` descriptor and the encoded body of one
    /// sample of it.
    unsafe fn reading_type() -> *mut HddsTypeDescriptor {
        let name = CString::new("Reading").unwrap();
        let builder = hdds_type_builder_new(name.as_ptr());
        let id = CString::new("id").unwrap();
        let value = CString::new("value").unwrap();
        assert_eq!(
            hdds_type_builder_add_field(
                builder,
                id.as_ptr(),
                HddsPrimitiveKind::HddsPrimI32 as u32
            ),
            HddsError::HddsOk
        );
        assert_eq!(
            hdds_type_builder_add_field(
                builder,
                value.as_ptr(),
                HddsPrimitiveKind::HddsPrimI32 as u32
            ),
            HddsError::HddsOk
        );
        hdds_type_builder_build(builder)
    }

    unsafe fn encode_reading(desc: *const HddsTypeDescriptor, id: i32, value: i32) -> Vec<u8> {
        let data = hdds_dynamic_data_new(desc);
        let id_name = CString::new("id").unwrap();
        let value_name = CString::new("value").unwrap();
        assert_eq!(
            hdds_dynamic_data_set_i32(data, id_name.as_ptr(), id),
            HddsError::HddsOk
        );
        assert_eq!(
            hdds_dynamic_data_set_i32(data, value_name.as_ptr(), value),
            HddsError::HddsOk
        );
        let mut buf = vec![0u8; 64];
        let mut len = 0usize;
        assert_eq!(
            hdds_dynamic_data_encode(data, buf.as_mut_ptr(), buf.len(), &mut len),
            HddsError::HddsOk
        );
        hdds_dynamic_data_destroy(data);
        buf.truncate(len);
        buf
    }

    #[test]
    fn test_null_safety() {
        unsafe {
            assert!(hdds_create_content_filtered_topic(
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0
            )
            .is_null());
            assert!(hdds_create_read_condition(ptr::null_mut(), 0, 0, 0).is_null());
            assert!(hdds_create_query_condition(
                ptr::null_mut(),
                0,
                0,
                0,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0
            )
            .is_null());
            assert!(!hdds_read_condition_get_trigger(ptr::null()));
            assert!(!hdds_query_condition_get_trigger(ptr::null()));
            assert_eq!(hdds_read_condition_get_sample_state_mask(ptr::null()), 0);

            hdds_content_filtered_topic_delete(ptr::null_mut());
            hdds_read_condition_delete(ptr::null_mut());
            hdds_query_condition_delete(ptr::null_mut());

            assert_eq!(
                hdds_waitset_attach_read_condition(ptr::null_mut(), ptr::null_mut()),
                HddsError::HddsInvalidArgument
            );
            assert_eq!(
                hdds_waitset_attach_query_condition(ptr::null_mut(), ptr::null_mut()),
                HddsError::HddsInvalidArgument
            );
            let mut len = 0usize;
            let mut byte = 0u8;
            assert_eq!(
                hdds_reader_take_w_condition(
                    ptr::null_mut(),
                    ptr::null(),
                    (&mut byte as *mut u8).cast(),
                    1,
                    &mut len,
                    ptr::null_mut()
                ),
                HddsError::HddsInvalidArgument
            );
            assert_eq!(
                hdds_content_filtered_topic_set_params(ptr::null_mut(), ptr::null(), 0),
                HddsError::HddsInvalidArgument
            );
        }
    }

    /// One intra-process participant for the three families: a
    /// QueryCondition with a parameter on a plain reader, a ReadCondition
    /// on a WaitSet, and a CFT reader that only sees matching samples.
    #[test]
    fn conditions_and_cft_on_an_intra_process_participant() {
        unsafe {
            let name = CString::new("CondFfiTest").unwrap();
            let participant = hdds_participant_create_with_transport(
                name.as_ptr(),
                HddsTransportMode::HddsTransportIntraProcess,
            );
            assert!(!participant.is_null());
            let topic = CString::new("CondFfiTopic").unwrap();
            let desc = reading_type();

            // --- QueryCondition with a parameter -------------------------
            let writer = hdds_writer_create(participant, topic.as_ptr());
            let reader = hdds_reader_create(participant, topic.as_ptr());
            assert!(!writer.is_null() && !reader.is_null());

            let query = CString::new("value > %0").unwrap();
            let threshold = CString::new("10").unwrap();
            let params = [threshold.as_ptr()];
            let hot = hdds_create_query_condition(
                reader,
                SAMPLE_ANY,
                VIEW_ANY,
                INSTANCE_ANY,
                desc,
                query.as_ptr(),
                params.as_ptr(),
                1,
            );
            assert!(!hot.is_null());
            let any = hdds_create_read_condition(reader, SAMPLE_ANY, VIEW_ANY, INSTANCE_ANY);
            assert!(!any.is_null());
            assert!(!hdds_query_condition_get_trigger(hot));
            assert!(!hdds_read_condition_get_trigger(any));

            let cold = encode_reading(desc, 1, 5);
            assert_eq!(
                hdds_writer_write(writer, cold.as_ptr().cast(), cold.len()),
                HddsError::HddsOk
            );
            assert!(hdds_read_condition_get_trigger(any));
            assert!(!hdds_query_condition_get_trigger(hot), "5 > 10 is false");

            let warm = encode_reading(desc, 2, 20);
            assert_eq!(
                hdds_writer_write(writer, warm.as_ptr().cast(), warm.len()),
                HddsError::HddsOk
            );
            assert!(hdds_query_condition_get_trigger(hot), "20 > 10");

            let mut out = [0u8; 64];
            let mut len = 0usize;
            let mut info = HddsSampleInfo {
                sample_state: 0,
                view_state: 0,
                instance_state: 0,
                valid_data: false,
                instance_handle: [0; 16],
                source_timestamp_ns: 0,
                reception_timestamp_ns: 0,
                sequence_number: 0,
            };
            assert_eq!(
                hdds_reader_take_w_query_condition(
                    reader,
                    hot,
                    out.as_mut_ptr().cast(),
                    out.len(),
                    &mut len,
                    &mut info
                ),
                HddsError::HddsOk
            );
            assert_eq!(&out[..len], warm.as_slice(), "only the hot sample is taken");
            assert!(info.valid_data);
            assert_eq!(
                info.sample_state,
                HddsSampleStateKind::HddsSampleStateNotRead as u32
            );
            assert_eq!(info.view_state, HddsViewStateKind::HddsViewStateNew as u32);
            assert_eq!(
                info.instance_state,
                HddsInstanceStateKind::HddsInstanceStateAlive as u32
            );
            assert_eq!(
                hdds_reader_take_w_query_condition(
                    reader,
                    hot,
                    out.as_mut_ptr().cast(),
                    out.len(),
                    &mut len,
                    ptr::null_mut()
                ),
                HddsError::HddsNotFound
            );

            // Lower the threshold: the cold sample now satisfies the query.
            let lower = CString::new("1").unwrap();
            let params = [lower.as_ptr()];
            assert_eq!(
                hdds_query_condition_set_parameters(hot, params.as_ptr(), 1),
                HddsError::HddsOk
            );
            assert_eq!(
                hdds_query_condition_set_parameters(hot, ptr::null(), 0),
                HddsError::HddsInvalidArgument,
                "a list that does not fit the expression is refused"
            );
            assert!(hdds_query_condition_get_trigger(hot));
            assert_eq!(
                hdds_reader_read_w_query_condition(
                    reader,
                    hot,
                    out.as_mut_ptr().cast(),
                    out.len(),
                    &mut len,
                    &mut info
                ),
                HddsError::HddsOk
            );
            assert_eq!(&out[..len], cold.as_slice());
            assert!(
                hdds_query_condition_get_trigger(hot),
                "read leaves it in place"
            );
            assert_eq!(
                hdds_reader_take_w_query_condition(
                    reader,
                    hot,
                    out.as_mut_ptr().cast(),
                    out.len(),
                    &mut len,
                    &mut info
                ),
                HddsError::HddsOk
            );
            assert_eq!(
                info.sample_state,
                HddsSampleStateKind::HddsSampleStateRead as u32,
                "the read marked it"
            );
            assert!(!hdds_read_condition_get_trigger(any));

            // --- ReadCondition on a WaitSet -----------------------------
            let waitset = hdds_waitset_create();
            assert_eq!(
                hdds_waitset_attach_read_condition(waitset, any),
                HddsError::HddsOk
            );
            let mut triggered: [*const c_void; 4] = [ptr::null(); 4];
            let mut count = 0usize;
            assert_eq!(
                hdds_waitset_wait(waitset, 50_000_000, triggered.as_mut_ptr(), 4, &mut count),
                HddsError::HddsOk
            );
            assert_eq!(count, 0, "nothing to read: the wait times out");

            let writer_thread = {
                let writer_addr = writer as usize;
                let bytes = encode_reading(desc, 3, 30);
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    let writer = writer_addr as *mut crate::HddsDataWriter;
                    assert_eq!(
                        hdds_writer_write(writer, bytes.as_ptr().cast(), bytes.len()),
                        HddsError::HddsOk
                    );
                })
            };
            assert_eq!(
                hdds_waitset_wait(
                    waitset,
                    3_000_000_000,
                    triggered.as_mut_ptr(),
                    4,
                    &mut count
                ),
                HddsError::HddsOk
            );
            writer_thread.join().unwrap();
            assert_eq!(count, 1, "the arrival wakes the WaitSet");
            assert_eq!(triggered[0], any.cast::<c_void>().cast_const());
            assert_eq!(
                hdds_reader_take_w_condition(
                    reader,
                    any,
                    out.as_mut_ptr().cast(),
                    out.len(),
                    &mut len,
                    ptr::null_mut()
                ),
                HddsError::HddsOk
            );
            assert_eq!(
                hdds_waitset_detach_condition(waitset, any.cast::<c_void>().cast_const()),
                HddsError::HddsOk
            );

            // A deleted condition is detached from its reader even while a
            // WaitSet still holds it: a later arrival must not return it.
            let doomed = hdds_create_read_condition(reader, SAMPLE_ANY, VIEW_ANY, INSTANCE_ANY);
            assert!(!doomed.is_null());
            assert_eq!(
                hdds_waitset_attach_read_condition(waitset, doomed),
                HddsError::HddsOk
            );
            let doomed_key = doomed.cast::<c_void>().cast_const();
            hdds_read_condition_delete(doomed);
            let late = encode_reading(desc, 8, 80);
            assert_eq!(
                hdds_writer_write(writer, late.as_ptr().cast(), late.len()),
                HddsError::HddsOk
            );
            assert_eq!(
                hdds_waitset_wait(waitset, 200_000_000, triggered.as_mut_ptr(), 4, &mut count),
                HddsError::HddsOk
            );
            assert_eq!(count, 0, "a deleted condition is never returned by a wait");
            assert_eq!(
                hdds_waitset_detach_condition(waitset, doomed_key),
                HddsError::HddsOk
            );
            assert_eq!(
                hdds_reader_take_w_condition(
                    reader,
                    any,
                    out.as_mut_ptr().cast(),
                    out.len(),
                    &mut len,
                    ptr::null_mut()
                ),
                HddsError::HddsOk,
                "the late sample is still in the reader"
            );
            hdds_waitset_destroy(waitset);

            // --- CFT reader ---------------------------------------------
            let cft_name = CString::new("HotReadings").unwrap();
            let expr = CString::new("value >= %0").unwrap();
            let params = [threshold.as_ptr()];
            let cft = hdds_create_content_filtered_topic(
                participant,
                cft_name.as_ptr(),
                topic.as_ptr(),
                desc,
                expr.as_ptr(),
                params.as_ptr(),
                1,
            );
            assert!(!cft.is_null());
            let mut expr_out = [0 as c_char; 32];
            assert_eq!(
                hdds_content_filtered_topic_get_expression(cft, expr_out.as_mut_ptr(), 32),
                "value >= %0".len()
            );
            let filtered = hdds_create_reader_filtered(participant, cft, ptr::null());
            assert!(!filtered.is_null());

            for (id, value) in [(4, 1), (5, 15), (6, 3)] {
                let bytes = encode_reading(desc, id, value);
                assert_eq!(
                    hdds_writer_write(writer, bytes.as_ptr().cast(), bytes.len()),
                    HddsError::HddsOk
                );
            }
            let mut got = Vec::new();
            while hdds_reader_take(filtered, out.as_mut_ptr().cast(), out.len(), &mut len)
                == HddsError::HddsOk
            {
                got.push(out[..len].to_vec());
            }
            assert_eq!(
                got,
                vec![encode_reading(desc, 5, 15)],
                "only value >= 10 arrives"
            );
            // A payload the descriptor cannot decode is REJECTED by a filter,
            // even a tautology on a real field: `id > -1` admits every
            // well-formed sample of this fixture (id is always positive) and
            // no malformed one. Annex B requires at least one operand of a
            // comparison to be a field name (formal/17-04-01 Sec.8), so a
            // literal-vs-literal `1 = 1` is not a legal expression here.
            let tautology_name = CString::new("Everything").unwrap();
            let tautology = CString::new("id > -1").unwrap();
            let all_cft = hdds_create_content_filtered_topic(
                participant,
                tautology_name.as_ptr(),
                topic.as_ptr(),
                desc,
                tautology.as_ptr(),
                ptr::null(),
                0,
            );
            assert!(!all_cft.is_null());
            let all_filtered = hdds_create_reader_filtered(participant, all_cft, ptr::null());
            assert!(!all_filtered.is_null());
            let truncated = [0x01u8, 0x00];
            assert_eq!(
                hdds_writer_write(writer, truncated.as_ptr().cast(), truncated.len()),
                HddsError::HddsOk
            );
            let whole = encode_reading(desc, 7, 70);
            assert_eq!(
                hdds_writer_write(writer, whole.as_ptr().cast(), whole.len()),
                HddsError::HddsOk
            );
            let mut through = Vec::new();
            while hdds_reader_take(all_filtered, out.as_mut_ptr().cast(), out.len(), &mut len)
                == HddsError::HddsOk
            {
                through.push(out[..len].to_vec());
            }
            assert_eq!(
                through,
                vec![whole.clone()],
                "a payload that does not decode must not pass a content filter"
            );
            hdds_reader_destroy(all_filtered);
            hdds_content_filtered_topic_delete(all_cft);

            // The unfiltered reader saw everything: three readings, the
            // truncated payload and the whole one.
            let mut plain = 0;
            while hdds_reader_take(reader, out.as_mut_ptr().cast(), out.len(), &mut len)
                == HddsError::HddsOk
            {
                plain += 1;
            }
            assert_eq!(plain, 5);

            hdds_read_condition_delete(any);
            hdds_query_condition_delete(hot);
            hdds_content_filtered_topic_delete(cft);
            hdds_reader_destroy(filtered);
            hdds_reader_destroy(reader);
            hdds_writer_destroy(writer);
            hdds_type_descriptor_destroy(desc);
            hdds_participant_destroy(participant);
        }
    }
}
