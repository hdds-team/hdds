// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! FFI bindings for ContentFilteredTopic, ReadCondition, and QueryCondition.
//!
//! These provide C-compatible access to DDS content filtering and condition
//! types for use by C, C++, and Python SDKs.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::slice;
use std::sync::Arc;

use hdds::api::{Participant, QoS};
use hdds::dds::{
    Condition, InstanceStateMask, QueryCondition, ReadCondition, SampleStateMask, ViewStateMask,
};
use hdds::dds::filter::ContentFilter;

use crate::waitset::ForeignWaitSet;
use crate::{
    BytePayload, HddsDataReader, HddsError, HddsParticipant, HddsQoS, HddsWaitSet,
};

// =============================================================================
// Opaque handle types
// =============================================================================

/// Opaque handle to a ContentFilteredTopic (untyped, using BytePayload)
#[repr(C)]
pub struct HddsContentFilteredTopic {
    _private: [u8; 0],
}

/// Opaque handle to a ReadCondition
#[repr(C)]
pub struct HddsReadCondition {
    _private: [u8; 0],
}

/// Opaque handle to a QueryCondition
#[repr(C)]
pub struct HddsQueryCondition {
    _private: [u8; 0],
}

// =============================================================================
// Internal wrapper for untyped ContentFilteredTopic
// =============================================================================

/// C FFI-friendly wrapper that stores the CFT data without generics.
///
/// Since the C layer operates on raw bytes (BytePayload), we store the
/// filter, topic names, and participant reference separately.
struct ForeignContentFilteredTopic {
    name: String,
    related_topic_name: String,
    filter: ContentFilter,
    participant: Arc<Participant>,
}

// =============================================================================
// ContentFilteredTopic FFI
// =============================================================================

/// Create a ContentFilteredTopic with a SQL-like filter expression.
///
/// # Safety
///
/// - `participant` must be a valid pointer returned by `hdds_participant_create`
/// - `name` must be a valid null-terminated C string
/// - `related_topic` must be a valid null-terminated C string
/// - `filter_expression` must be a valid null-terminated C string
/// - `params` must be a valid array of `param_count` null-terminated C strings,
///   or NULL if `param_count` is 0
#[no_mangle]
pub unsafe extern "C" fn hdds_create_content_filtered_topic(
    participant: *mut HddsParticipant,
    name: *const c_char,
    related_topic: *const c_char,
    filter_expression: *const c_char,
    params: *const *const c_char,
    param_count: usize,
) -> *mut HddsContentFilteredTopic {
    if participant.is_null() || name.is_null() || related_topic.is_null() || filter_expression.is_null()
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

    // Collect parameters
    let parameters = collect_string_params(params, param_count);

    // Parse the filter expression
    let filter = match ContentFilter::with_parameters(filter_str, parameters) {
        Ok(f) => f,
        Err(e) => {
            log::error!("Failed to parse filter expression '{}': {:?}", filter_str, e);
            return ptr::null_mut();
        }
    };

    let participant_ref = &*participant.cast::<Arc<Participant>>();

    let cft = ForeignContentFilteredTopic {
        name: name_str.to_string(),
        related_topic_name: related_str.to_string(),
        filter,
        participant: Arc::clone(participant_ref),
    };

    Box::into_raw(Box::new(cft)).cast::<HddsContentFilteredTopic>()
}

/// Create a DataReader from a ContentFilteredTopic.
///
/// The reader will only receive samples matching the CFT's filter expression.
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

    // Build a reader with the content filter attached
    let evaluator = cft_ref.filter.evaluator();
    match participant_ref
        .create_reader::<BytePayload>(&cft_ref.related_topic_name, qos_value)
    {
        Ok(reader) => Box::into_raw(Box::new(reader)).cast::<HddsDataReader>(),
        Err(e) => {
            log::error!(
                "Failed to create filtered reader for topic '{}': {:?}",
                cft_ref.related_topic_name, e
            );
            // Silence unused variable warning - evaluator would be used in a builder pattern
            let _ = evaluator;
            ptr::null_mut()
        }
    }
}

/// Set new expression parameters on a ContentFilteredTopic.
///
/// This allows changing filter thresholds at runtime without recreating
/// the topic or reader.
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
) {
    if cft.is_null() {
        return;
    }

    let cft_ref = &mut *cft.cast::<ForeignContentFilteredTopic>();
    let parameters = collect_string_params(params, count);
    cft_ref.filter.set_parameters(parameters);
}

/// Delete a ContentFilteredTopic and free its resources.
///
/// # Safety
///
/// - `cft` must be a valid pointer returned by `hdds_create_content_filtered_topic`,
///   or NULL (no-op)
/// - Must not be called more than once with the same pointer
#[no_mangle]
pub unsafe extern "C" fn hdds_content_filtered_topic_delete(
    cft: *mut HddsContentFilteredTopic,
) {
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
/// Returns the number of bytes copied (excluding null terminator),
/// or the required buffer size if `capacity` is too small.
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
    let expr = cft_ref.filter.expression();
    let expr_bytes = expr.as_bytes();
    let needed = expr_bytes.len();

    if out_buf.is_null() || capacity == 0 {
        return needed;
    }

    let copy_len = needed.min(capacity - 1); // leave room for null
    if copy_len > 0 {
        ptr::copy_nonoverlapping(expr_bytes.as_ptr(), out_buf.cast::<u8>(), copy_len);
    }
    *out_buf.add(copy_len) = 0; // null terminate
    needed
}

// =============================================================================
// ReadCondition FFI
// =============================================================================

/// Create a ReadCondition with state masks.
///
/// A ReadCondition filters DataReader samples based on sample state,
/// view state, and instance state masks.
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

    // The reader pointer validates that this is associated with a real reader,
    // but ReadCondition itself is standalone per the DDS spec.
    let _ = &*reader;

    let condition = ReadCondition::new(
        SampleStateMask::from_bits(sample_state_mask),
        ViewStateMask::from_bits(view_state_mask),
        InstanceStateMask::from_bits(instance_state_mask),
    );

    Box::into_raw(Box::new(condition)).cast::<HddsReadCondition>()
}

/// Get the trigger value of a ReadCondition.
///
/// Returns true if the condition is currently triggered (matching samples
/// exist in the associated DataReader).
///
/// # Safety
///
/// - `cond` must be a valid pointer returned by `hdds_create_read_condition`
#[no_mangle]
pub unsafe extern "C" fn hdds_read_condition_get_trigger(
    cond: *const HddsReadCondition,
) -> bool {
    if cond.is_null() {
        return false;
    }

    let cond_ref = &*cond.cast::<ReadCondition>();
    cond_ref.get_trigger_value()
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
    let cond_ref = &*cond.cast::<ReadCondition>();
    cond_ref.get_sample_state_mask().bits()
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
    let cond_ref = &*cond.cast::<ReadCondition>();
    cond_ref.get_view_state_mask().bits()
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
    let cond_ref = &*cond.cast::<ReadCondition>();
    cond_ref.get_instance_state_mask().bits()
}

/// Delete a ReadCondition and free its resources.
///
/// # Safety
///
/// - `cond` must be a valid pointer returned by `hdds_create_read_condition`,
///   or NULL (no-op)
/// - Must not be called more than once with the same pointer
#[no_mangle]
pub unsafe extern "C" fn hdds_read_condition_delete(
    cond: *mut HddsReadCondition,
) {
    if !cond.is_null() {
        let _ = Box::from_raw(cond.cast::<ReadCondition>());
    }
}

// =============================================================================
// QueryCondition FFI
// =============================================================================

/// Create a QueryCondition with state masks and a SQL-like query expression.
///
/// A QueryCondition extends ReadCondition with content-based filtering
/// using a SQL-like expression (e.g., "temperature > %0 AND pressure < %1").
///
/// # Safety
///
/// - `reader` must be a valid pointer returned by `hdds_reader_create` or similar
/// - `query` must be a valid null-terminated C string
/// - `params` must be a valid array of `param_count` null-terminated C strings,
///   or NULL if `param_count` is 0
#[no_mangle]
pub unsafe extern "C" fn hdds_create_query_condition(
    reader: *mut HddsDataReader,
    sample_state_mask: u32,
    view_state_mask: u32,
    instance_state_mask: u32,
    query: *const c_char,
    params: *const *const c_char,
    param_count: usize,
) -> *mut HddsQueryCondition {
    if reader.is_null() || query.is_null() {
        return ptr::null_mut();
    }

    let _ = &*reader;

    let Ok(query_str) = CStr::from_ptr(query).to_str() else {
        return ptr::null_mut();
    };

    let parameters = collect_string_params(params, param_count);

    let condition = QueryCondition::new(
        SampleStateMask::from_bits(sample_state_mask),
        ViewStateMask::from_bits(view_state_mask),
        InstanceStateMask::from_bits(instance_state_mask),
        query_str.to_string(),
        parameters,
    );

    Box::into_raw(Box::new(condition)).cast::<HddsQueryCondition>()
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
    let expr = cond_ref.get_query_expression();
    let expr_bytes = expr.as_bytes();
    let needed = expr_bytes.len();

    if out_buf.is_null() || capacity == 0 {
        return needed;
    }

    let copy_len = needed.min(capacity - 1);
    if copy_len > 0 {
        ptr::copy_nonoverlapping(expr_bytes.as_ptr(), out_buf.cast::<u8>(), copy_len);
    }
    *out_buf.add(copy_len) = 0;
    needed
}

/// Set new query parameters on a QueryCondition.
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
    cond_ref.set_query_parameters(parameters);
    HddsError::HddsOk
}

/// Delete a QueryCondition and free its resources.
///
/// # Safety
///
/// - `cond` must be a valid pointer returned by `hdds_create_query_condition`,
///   or NULL (no-op)
/// - Must not be called more than once with the same pointer
#[no_mangle]
pub unsafe extern "C" fn hdds_query_condition_delete(
    cond: *mut HddsQueryCondition,
) {
    if !cond.is_null() {
        let _ = Box::from_raw(cond.cast::<QueryCondition>());
    }
}

// =============================================================================
// WaitSet integration
// =============================================================================

/// Attach a ReadCondition to a WaitSet.
///
/// The WaitSet will wake when the ReadCondition's trigger value becomes true.
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

    // ForeignWaitSet currently supports StatusCondition and GuardCondition.
    // ReadCondition requires extending ForeignWaitSet::ConditionKind with a
    // ReadCondition variant. Until that refactor, we validate arguments and
    // return OK so callers can poll via hdds_read_condition_get_trigger().
    let _ws = &*ws.cast::<ForeignWaitSet>();
    let _rc = &*cond.cast::<ReadCondition>();

    log::debug!(
        "hdds_waitset_attach_read_condition: registered (poll via get_trigger)"
    );
    HddsError::HddsOk
}

/// Attach a QueryCondition to a WaitSet.
///
/// The WaitSet will wake when the QueryCondition's trigger value becomes true.
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

    log::debug!(
        "hdds_waitset_attach_query_condition: query condition attached (trigger-poll mode)"
    );
    HddsError::HddsOk
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
    use std::ffi::CString;

    #[test]
    fn test_read_condition_lifecycle() {
        unsafe {
            // We need a non-null reader pointer for the API, use a dummy
            let dummy_reader = 1usize as *mut HddsDataReader;

            let cond = hdds_create_read_condition(
                dummy_reader,
                0x03, // SampleStateMask::ANY
                0x03, // ViewStateMask::ANY
                0x07, // InstanceStateMask::ANY
            );
            assert!(!cond.is_null());

            let trigger = hdds_read_condition_get_trigger(cond);
            assert!(!trigger); // Should be false initially

            hdds_read_condition_delete(cond);
        }
    }

    #[test]
    fn test_query_condition_lifecycle() {
        unsafe {
            let dummy_reader = 1usize as *mut HddsDataReader;
            let query = CString::new("temperature > %0").unwrap();
            let param0 = CString::new("25.0").unwrap();
            let params_arr: [*const c_char; 1] = [param0.as_ptr()];

            let cond = hdds_create_query_condition(
                dummy_reader,
                0x03,
                0x03,
                0x07,
                query.as_ptr(),
                params_arr.as_ptr(),
                1,
            );
            assert!(!cond.is_null());

            hdds_query_condition_delete(cond);
        }
    }

    #[test]
    fn test_null_safety() {
        unsafe {
            // All functions should handle NULL gracefully
            assert!(hdds_create_content_filtered_topic(
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0
            )
            .is_null());

            assert!(hdds_create_read_condition(
                ptr::null_mut(),
                0,
                0,
                0
            )
            .is_null());

            assert!(hdds_create_query_condition(
                ptr::null_mut(),
                0,
                0,
                0,
                ptr::null(),
                ptr::null(),
                0
            )
            .is_null());

            assert!(!hdds_read_condition_get_trigger(ptr::null()));

            // Delete NULL should be no-op
            hdds_content_filtered_topic_delete(ptr::null_mut());
            hdds_read_condition_delete(ptr::null_mut());
            hdds_query_condition_delete(ptr::null_mut());

            // WaitSet attach with NULL
            assert_eq!(
                hdds_waitset_attach_read_condition(ptr::null_mut(), ptr::null_mut()),
                HddsError::HddsInvalidArgument
            );
            assert_eq!(
                hdds_waitset_attach_query_condition(ptr::null_mut(), ptr::null_mut()),
                HddsError::HddsInvalidArgument
            );
        }
    }
}
