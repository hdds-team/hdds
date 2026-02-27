// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Content filter C FFI bindings.
//!
//! SQL-like filter expressions for topic data filtering.
//!
//! # Usage from C
//!
//! ```c
//! HddsFilter* f = hdds_filter_create("temperature > %0 AND humidity < %1");
//! const char* params[] = {"25.0", "80"};
//! hdds_filter_set_parameters(f, params, 2);
//!
//! HddsFieldMap* m = hdds_field_map_create();
//! hdds_field_map_set_f64(m, "temperature", 30.0);
//! hdds_field_map_set_f64(m, "humidity", 60.0);
//!
//! int result = hdds_filter_evaluate(f, m); // 1 = match
//!
//! hdds_field_map_destroy(m);
//! hdds_filter_destroy(f);
//! ```

use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;

use hdds::dds::filter::{ContentFilter, FieldValue};

use crate::HddsError;

// =============================================================================
// Opaque handles
// =============================================================================

/// Opaque handle to a content filter.
#[repr(C)]
pub struct HddsFilter {
    _private: [u8; 0],
}

/// Opaque handle to a field value map (for filter evaluation).
#[repr(C)]
pub struct HddsFieldMap {
    _private: [u8; 0],
}

// =============================================================================
// Filter lifecycle
// =============================================================================

/// Create a new content filter from a SQL-like expression.
///
/// Supports: `>`, `<`, `>=`, `<=`, `=`, `!=`, `<>`, `LIKE`, `AND`, `OR`, `NOT`.
/// Parameters: `%0`, `%1`, etc. (set via `hdds_filter_set_parameters`).
///
/// Returns NULL if the expression is invalid.
///
/// # Safety
/// - `expression` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn hdds_filter_create(
    expression: *const c_char,
) -> *mut HddsFilter {
    if expression.is_null() {
        return ptr::null_mut();
    }
    let Ok(expr) = CStr::from_ptr(expression).to_str() else {
        return ptr::null_mut();
    };
    match ContentFilter::new(expr) {
        Ok(filter) => Box::into_raw(Box::new(filter)).cast::<HddsFilter>(),
        Err(e) => {
            log::error!("hdds_filter_create: {:?}", e);
            ptr::null_mut()
        }
    }
}

/// Create a filter with initial parameters.
///
/// Returns NULL if the expression is invalid.
///
/// # Safety
/// - `expression` must be null-terminated.
/// - `params` must point to `param_count` valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn hdds_filter_create_with_params(
    expression: *const c_char,
    params: *const *const c_char,
    param_count: usize,
) -> *mut HddsFilter {
    if expression.is_null() {
        return ptr::null_mut();
    }
    let Ok(expr) = CStr::from_ptr(expression).to_str() else {
        return ptr::null_mut();
    };
    let param_vec = collect_params(params, param_count);
    match ContentFilter::with_parameters(expr, param_vec) {
        Ok(filter) => Box::into_raw(Box::new(filter)).cast::<HddsFilter>(),
        Err(e) => {
            log::error!("hdds_filter_create_with_params: {:?}", e);
            ptr::null_mut()
        }
    }
}

/// Set or update filter parameters.
///
/// # Safety
/// - `filter` must be valid.
/// - `params` must point to `count` valid null-terminated C strings, or be NULL if count is 0.
#[no_mangle]
pub unsafe extern "C" fn hdds_filter_set_parameters(
    filter: *mut HddsFilter,
    params: *const *const c_char,
    count: usize,
) -> HddsError {
    if filter.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let f = &mut *filter.cast::<ContentFilter>();
    let param_vec = collect_params(params, count);
    f.set_parameters(param_vec);
    HddsError::HddsOk
}

/// Get the filter expression string. Returns bytes needed (excluding null).
///
/// # Safety
/// - `filter` must be valid.
#[no_mangle]
pub unsafe extern "C" fn hdds_filter_get_expression(
    filter: *const HddsFilter,
    out_buf: *mut c_char,
    capacity: usize,
) -> usize {
    if filter.is_null() {
        return 0;
    }
    let f = &*filter.cast::<ContentFilter>();
    let expr = f.expression();
    let needed = expr.as_bytes().len();
    if !out_buf.is_null() && capacity > 0 {
        let copy_len = needed.min(capacity - 1);
        ptr::copy_nonoverlapping(expr.as_bytes().as_ptr(), out_buf.cast::<u8>(), copy_len);
        *out_buf.add(copy_len) = 0;
    }
    needed
}

/// Destroy a filter.
///
/// # Safety
/// - `filter` must be valid or NULL.
#[no_mangle]
pub unsafe extern "C" fn hdds_filter_destroy(filter: *mut HddsFilter) {
    if !filter.is_null() {
        let _ = Box::from_raw(filter.cast::<ContentFilter>());
    }
}

// =============================================================================
// Field Map (for evaluation)
// =============================================================================

/// Create a new empty field map.
#[no_mangle]
pub unsafe extern "C" fn hdds_field_map_create() -> *mut HddsFieldMap {
    let map: HashMap<String, FieldValue> = HashMap::new();
    Box::into_raw(Box::new(map)).cast::<HddsFieldMap>()
}

/// Set an integer field value.
///
/// # Safety
/// - `map` must be valid. `name` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn hdds_field_map_set_i64(
    map: *mut HddsFieldMap,
    name: *const c_char,
    value: i64,
) -> HddsError {
    field_map_set(map, name, FieldValue::Integer(value))
}

/// Set an unsigned integer field value.
///
/// # Safety
/// - `map` must be valid. `name` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn hdds_field_map_set_u64(
    map: *mut HddsFieldMap,
    name: *const c_char,
    value: u64,
) -> HddsError {
    field_map_set(map, name, FieldValue::Unsigned(value))
}

/// Set a float field value.
///
/// # Safety
/// - `map` must be valid. `name` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn hdds_field_map_set_f64(
    map: *mut HddsFieldMap,
    name: *const c_char,
    value: f64,
) -> HddsError {
    field_map_set(map, name, FieldValue::Float(value))
}

/// Set a boolean field value.
///
/// # Safety
/// - `map` must be valid. `name` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn hdds_field_map_set_bool(
    map: *mut HddsFieldMap,
    name: *const c_char,
    value: bool,
) -> HddsError {
    field_map_set(map, name, FieldValue::Boolean(value))
}

/// Set a string field value.
///
/// # Safety
/// - `map` must be valid. `name` and `value` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn hdds_field_map_set_string(
    map: *mut HddsFieldMap,
    name: *const c_char,
    value: *const c_char,
) -> HddsError {
    if value.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Ok(val) = CStr::from_ptr(value).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    field_map_set(map, name, FieldValue::String(val.to_string()))
}

/// Clear all entries in the field map.
///
/// # Safety
/// - `map` must be valid.
#[no_mangle]
pub unsafe extern "C" fn hdds_field_map_clear(map: *mut HddsFieldMap) {
    if !map.is_null() {
        let m = &mut *map.cast::<HashMap<String, FieldValue>>();
        m.clear();
    }
}

/// Destroy a field map.
///
/// # Safety
/// - `map` must be valid or NULL.
#[no_mangle]
pub unsafe extern "C" fn hdds_field_map_destroy(map: *mut HddsFieldMap) {
    if !map.is_null() {
        let _ = Box::from_raw(map.cast::<HashMap<String, FieldValue>>());
    }
}

// =============================================================================
// Evaluation
// =============================================================================

/// Evaluate a filter against a field map.
///
/// Returns 1 if the filter matches, 0 if it doesn't, -1 on error.
///
/// # Safety
/// - `filter` and `map` must be valid.
#[no_mangle]
pub unsafe extern "C" fn hdds_filter_evaluate(
    filter: *const HddsFilter,
    map: *const HddsFieldMap,
) -> i32 {
    if filter.is_null() || map.is_null() {
        return -1;
    }
    let f = &*filter.cast::<ContentFilter>();
    let m = &*map.cast::<HashMap<String, FieldValue>>();
    let evaluator = f.evaluator();
    match evaluator.matches(m) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => {
            log::error!("hdds_filter_evaluate: {:?}", e);
            -1
        }
    }
}

// =============================================================================
// Helpers
// =============================================================================

unsafe fn field_map_set(
    map: *mut HddsFieldMap,
    name: *const c_char,
    value: FieldValue,
) -> HddsError {
    if map.is_null() || name.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Ok(name_str) = CStr::from_ptr(name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let m = &mut *map.cast::<HashMap<String, FieldValue>>();
    m.insert(name_str.to_string(), value);
    HddsError::HddsOk
}

unsafe fn collect_params(params: *const *const c_char, count: usize) -> Vec<String> {
    if params.is_null() || count == 0 {
        return Vec::new();
    }
    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let p = *params.add(i);
        if !p.is_null() {
            if let Ok(s) = CStr::from_ptr(p).to_str() {
                result.push(s.to_string());
            }
        }
    }
    result
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_filter_create_and_destroy() {
        unsafe {
            let expr = CString::new("x > 10").unwrap();
            let filter = hdds_filter_create(expr.as_ptr());
            assert!(!filter.is_null());
            hdds_filter_destroy(filter);
        }
    }

    #[test]
    fn test_filter_invalid_expression() {
        unsafe {
            let expr = CString::new("???!!!").unwrap();
            let filter = hdds_filter_create(expr.as_ptr());
            assert!(filter.is_null());
        }
    }

    #[test]
    fn test_filter_evaluate_simple() {
        unsafe {
            let expr = CString::new("temperature > 25").unwrap();
            let filter = hdds_filter_create(expr.as_ptr());
            assert!(!filter.is_null());

            let map = hdds_field_map_create();
            let fname = CString::new("temperature").unwrap();

            // 30 > 25 = true
            hdds_field_map_set_f64(map, fname.as_ptr(), 30.0);
            assert_eq!(hdds_filter_evaluate(filter, map), 1);

            // 20 > 25 = false
            hdds_field_map_clear(map);
            hdds_field_map_set_f64(map, fname.as_ptr(), 20.0);
            assert_eq!(hdds_filter_evaluate(filter, map), 0);

            hdds_field_map_destroy(map);
            hdds_filter_destroy(filter);
        }
    }

    #[test]
    fn test_filter_with_parameters() {
        unsafe {
            let expr = CString::new("value > %0").unwrap();
            let p0 = CString::new("42").unwrap();
            let params = [p0.as_ptr()];
            let filter = hdds_filter_create_with_params(expr.as_ptr(), params.as_ptr(), 1);
            assert!(!filter.is_null());

            let map = hdds_field_map_create();
            let fname = CString::new("value").unwrap();
            hdds_field_map_set_i64(map, fname.as_ptr(), 50);
            assert_eq!(hdds_filter_evaluate(filter, map), 1);

            // Update parameter to 100
            let p_new = CString::new("100").unwrap();
            let new_params = [p_new.as_ptr()];
            hdds_filter_set_parameters(filter, new_params.as_ptr(), 1);
            assert_eq!(hdds_filter_evaluate(filter, map), 0); // 50 > 100 = false

            hdds_field_map_destroy(map);
            hdds_filter_destroy(filter);
        }
    }

    #[test]
    fn test_filter_get_expression() {
        unsafe {
            let expr = CString::new("x > 10").unwrap();
            let filter = hdds_filter_create(expr.as_ptr());

            let mut buf = [0u8; 64];
            let len = hdds_filter_get_expression(filter, buf.as_mut_ptr().cast(), 64);
            assert_eq!(len, 6);

            hdds_filter_destroy(filter);
        }
    }

    #[test]
    fn test_null_safety() {
        unsafe {
            assert!(hdds_filter_create(ptr::null()).is_null());
            hdds_filter_destroy(ptr::null_mut());
            hdds_field_map_destroy(ptr::null_mut());
            assert_eq!(hdds_filter_evaluate(ptr::null(), ptr::null()), -1);
            assert_eq!(
                hdds_filter_set_parameters(ptr::null_mut(), ptr::null(), 0),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_field_map_set_f64(ptr::null_mut(), ptr::null(), 0.0),
                HddsError::HddsInvalidArgument,
            );
        }
    }
}
