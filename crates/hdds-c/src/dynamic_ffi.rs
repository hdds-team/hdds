// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Dynamic Types C FFI bindings.
//!
//! Provides runtime type construction and data manipulation without
//! compile-time type knowledge. Enables generic C/C++ tools, bridges, and
//! introspection.
//!
//! Handles must not be destroyed while in use. Mutating calls require exclusive
//! access to the handle; immutable calls may share live descriptors and data.
//!
//! # Usage from C
//!
//! ```c
//! // Build type
//! struct HddsTypeBuilder* tb = hdds_type_builder_new("SensorReading");
//! hdds_type_builder_add_field(tb, "sensor_id", HDDS_PRIM_U32);
//! hdds_type_builder_add_field(tb, "temperature", HDDS_PRIM_F64);
//! struct HddsTypeDescriptor* desc = hdds_type_builder_build(tb);
//!
//! // Create data
//! struct HddsDynamicData* data = hdds_dynamic_data_new(desc);
//! hdds_dynamic_data_set_u32(data, "sensor_id", 42);
//! hdds_dynamic_data_set_f64(data, "temperature", 23.5);
//!
//! // Encode to CDR
//! uint8_t buf[256];
//! size_t len = 0;
//! hdds_dynamic_data_encode(data, buf, 256, &len);
//!
//! hdds_dynamic_data_destroy(data);
//! hdds_type_descriptor_destroy(desc);
//! ```

use std::collections::HashSet;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::sync::Arc;

use hdds::dynamic::{
    decode_dynamic_with_version, encode_dynamic_with_version, DynamicData, PrimitiveKind,
    TypeDescriptor, TypeDescriptorBuilder,
};

use crate::HddsError;
use hdds::CdrVersion;

// =============================================================================
// Primitive Kind enum for C
// =============================================================================

/// Primitive type kinds for the dynamic type builder.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HddsPrimitiveKind {
    HddsPrimBool = 0,
    HddsPrimU8 = 1,
    HddsPrimU16 = 2,
    HddsPrimU32 = 3,
    HddsPrimU64 = 4,
    HddsPrimI8 = 5,
    HddsPrimI16 = 6,
    HddsPrimI32 = 7,
    HddsPrimI64 = 8,
    HddsPrimF32 = 9,
    HddsPrimF64 = 10,
    HddsPrimString = 11,
}

fn to_primitive_kind(kind: u32) -> Option<PrimitiveKind> {
    Some(match kind {
        0 => PrimitiveKind::Bool,
        1 => PrimitiveKind::U8,
        2 => PrimitiveKind::U16,
        3 => PrimitiveKind::U32,
        4 => PrimitiveKind::U64,
        5 => PrimitiveKind::I8,
        6 => PrimitiveKind::I16,
        7 => PrimitiveKind::I32,
        8 => PrimitiveKind::I64,
        9 => PrimitiveKind::F32,
        10 => PrimitiveKind::F64,
        11 => PrimitiveKind::String { max_length: None },
        _ => return None,
    })
}

// =============================================================================
// Opaque handles
// =============================================================================

/// Opaque handle to a type descriptor builder.
pub struct HddsTypeBuilder {
    _private: [u8; 0],
}

/// Opaque handle to a type descriptor.
pub struct HddsTypeDescriptor {
    _private: [u8; 0],
}

/// Opaque handle to dynamic data.
pub struct HddsDynamicData {
    _private: [u8; 0],
}

/// Internal wrapper for the builder (uses Option to support consuming methods).
struct TypeBuilderWrapper {
    builder: Option<TypeDescriptorBuilder>,
    names: HashSet<String>,
}

// =============================================================================
// Type Builder
// =============================================================================

/// Create a new type descriptor builder.
///
/// # Safety
/// - `name` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn hdds_type_builder_new(name: *const c_char) -> *mut HddsTypeBuilder {
    if name.is_null() {
        return ptr::null_mut();
    }
    let Ok(name_str) = CStr::from_ptr(name).to_str() else {
        return ptr::null_mut();
    };
    let wrapper = TypeBuilderWrapper {
        builder: Some(TypeDescriptorBuilder::new(name_str)),
        names: HashSet::new(),
    };
    Box::into_raw(Box::new(wrapper)).cast::<HddsTypeBuilder>()
}

/// Add a primitive field to the type builder.
///
/// # Safety
/// - `builder` must be valid. `name` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn hdds_type_builder_add_field(
    builder: *mut HddsTypeBuilder,
    name: *const c_char,
    kind: u32,
) -> HddsError {
    if builder.is_null() || name.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Ok(name_str) = CStr::from_ptr(name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let Some(kind) = to_primitive_kind(kind) else {
        return HddsError::HddsInvalidArgument;
    };
    let wrapper = &mut *builder.cast::<TypeBuilderWrapper>();
    if name_str.is_empty() || !wrapper.names.insert(name_str.to_owned()) {
        return HddsError::HddsInvalidArgument;
    }
    let Some(b) = wrapper.builder.take() else {
        return HddsError::HddsInvalidArgument;
    };
    wrapper.builder = Some(b.field(name_str, kind));
    HddsError::HddsOk
}

/// Add a string field to the type builder.
///
/// # Safety
/// - `builder` must be valid. `name` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn hdds_type_builder_add_string_field(
    builder: *mut HddsTypeBuilder,
    name: *const c_char,
) -> HddsError {
    if builder.is_null() || name.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Ok(name_str) = CStr::from_ptr(name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let wrapper = &mut *builder.cast::<TypeBuilderWrapper>();
    if name_str.is_empty() || !wrapper.names.insert(name_str.to_owned()) {
        return HddsError::HddsInvalidArgument;
    }
    let Some(b) = wrapper.builder.take() else {
        return HddsError::HddsInvalidArgument;
    };
    wrapper.builder = Some(b.string_field(name_str));
    HddsError::HddsOk
}

/// Add a sequence field to the type builder.
///
/// # Safety
/// - `builder` must be valid. `name` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn hdds_type_builder_add_sequence_field(
    builder: *mut HddsTypeBuilder,
    name: *const c_char,
    element_kind: u32,
) -> HddsError {
    if builder.is_null() || name.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Ok(name_str) = CStr::from_ptr(name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let Some(element_kind) = to_primitive_kind(element_kind) else {
        return HddsError::HddsInvalidArgument;
    };
    let wrapper = &mut *builder.cast::<TypeBuilderWrapper>();
    if name_str.is_empty() || !wrapper.names.insert(name_str.to_owned()) {
        return HddsError::HddsInvalidArgument;
    }
    let Some(b) = wrapper.builder.take() else {
        return HddsError::HddsInvalidArgument;
    };
    wrapper.builder = Some(b.sequence_field(name_str, element_kind));
    HddsError::HddsOk
}

/// Add an array field to the type builder.
///
/// # Safety
/// - `builder` must be valid. `name` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn hdds_type_builder_add_array_field(
    builder: *mut HddsTypeBuilder,
    name: *const c_char,
    element_kind: u32,
    length: usize,
) -> HddsError {
    if builder.is_null() || name.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Ok(name_str) = CStr::from_ptr(name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let Some(element_kind) = to_primitive_kind(element_kind) else {
        return HddsError::HddsInvalidArgument;
    };
    if length == 0
        || length > (isize::MAX as usize) / std::mem::size_of::<hdds::dynamic::DynamicValue>()
    {
        return HddsError::HddsInvalidArgument;
    }
    let wrapper = &mut *builder.cast::<TypeBuilderWrapper>();
    if name_str.is_empty() || !wrapper.names.insert(name_str.to_owned()) {
        return HddsError::HddsInvalidArgument;
    }
    let Some(b) = wrapper.builder.take() else {
        return HddsError::HddsInvalidArgument;
    };
    wrapper.builder = Some(b.array_field(name_str, element_kind, length));
    HddsError::HddsOk
}

/// Build the type descriptor (consumes the builder).
///
/// Returns NULL for a NULL builder. A non-NULL builder is consumed even on failure.
/// Never reuse or destroy a consumed builder.
///
/// # Safety
/// - `builder` must be valid. After this call, `builder` is invalid.
#[no_mangle]
pub unsafe extern "C" fn hdds_type_builder_build(
    builder: *mut HddsTypeBuilder,
) -> *mut HddsTypeDescriptor {
    if builder.is_null() {
        return ptr::null_mut();
    }
    let mut wrapper = *Box::from_raw(builder.cast::<TypeBuilderWrapper>());
    let Some(b) = wrapper.builder.take() else {
        return ptr::null_mut();
    };
    let desc = Arc::new(b.build());
    Box::into_raw(Box::new(desc)).cast::<HddsTypeDescriptor>()
}

/// Destroy a type builder without building.
///
/// # Safety
/// - `builder` must be valid or NULL.
#[no_mangle]
pub unsafe extern "C" fn hdds_type_builder_destroy(builder: *mut HddsTypeBuilder) {
    if !builder.is_null() {
        let _ = Box::from_raw(builder.cast::<TypeBuilderWrapper>());
    }
}

// =============================================================================
// Type Descriptor
// =============================================================================

/// Get the type name. Returns the number of bytes needed (excluding null).
///
/// # Safety
/// - `desc` must be valid. `out_buf` and `capacity` must be valid.
#[no_mangle]
pub unsafe extern "C" fn hdds_type_descriptor_get_name(
    desc: *const HddsTypeDescriptor,
    out_buf: *mut c_char,
    capacity: usize,
) -> usize {
    if desc.is_null() {
        return 0;
    }
    let arc = &*desc.cast::<Arc<TypeDescriptor>>();
    let name = &arc.name;
    let needed = name.len();
    if !out_buf.is_null() && capacity > 0 {
        let copy_len = needed.min(capacity - 1);
        ptr::copy_nonoverlapping(name.as_bytes().as_ptr(), out_buf.cast::<u8>(), copy_len);
        *out_buf.add(copy_len) = 0;
    }
    needed
}

/// Get the number of fields (for struct types). Returns 0 for non-struct types.
///
/// # Safety
/// - `desc` must be valid.
#[no_mangle]
pub unsafe extern "C" fn hdds_type_descriptor_get_field_count(
    desc: *const HddsTypeDescriptor,
) -> usize {
    if desc.is_null() {
        return 0;
    }
    let arc = &*desc.cast::<Arc<TypeDescriptor>>();
    arc.fields().map(|f| f.len()).unwrap_or(0)
}

/// Destroy a type descriptor.
///
/// # Safety
/// - `desc` must be valid or NULL.
#[no_mangle]
pub unsafe extern "C" fn hdds_type_descriptor_destroy(desc: *mut HddsTypeDescriptor) {
    if !desc.is_null() {
        let _ = Box::from_raw(desc.cast::<Arc<TypeDescriptor>>());
    }
}

// =============================================================================
// Dynamic Data - Create / Destroy
// =============================================================================

/// Create new dynamic data with default values.
///
/// # Safety
/// - `desc` must be valid (not consumed, still valid after this call).
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_new(
    desc: *const HddsTypeDescriptor,
) -> *mut HddsDynamicData {
    if desc.is_null() {
        return ptr::null_mut();
    }
    let arc = &*desc.cast::<Arc<TypeDescriptor>>();
    let data = DynamicData::new(arc);
    Box::into_raw(Box::new(data)).cast::<HddsDynamicData>()
}

/// Destroy dynamic data.
///
/// # Safety
/// - `data` must be valid or NULL.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_destroy(data: *mut HddsDynamicData) {
    if !data.is_null() {
        let _ = Box::from_raw(data.cast::<DynamicData>());
    }
}

// =============================================================================
// Dynamic Data - Setters
// =============================================================================

// Keep public signatures explicit: cbindgen does not expand Rust macros.
macro_rules! set_primitive {
    ($data:ident, $field:ident, $value:ident, $kind:ident) => {{
        if $data.is_null() || $field.is_null() {
            return HddsError::HddsInvalidArgument;
        }
        let Ok(name) = CStr::from_ptr($field).to_str() else {
            return HddsError::HddsInvalidArgument;
        };
        let dd = &mut *$data.cast::<DynamicData>();
        if !matches!(
            dd.descriptor().field(name).map(|f| &f.type_desc.kind),
            Some(hdds::dynamic::TypeKind::Primitive(PrimitiveKind::$kind))
        ) {
            return HddsError::HddsInvalidArgument;
        }
        match dd.set(name, $value) {
            Ok(()) => HddsError::HddsOk,
            Err(_) => HddsError::HddsInvalidArgument,
        }
    }};
}

/// Set a bool field. A different declared field type is rejected.
///
/// # Safety
/// `data` must be live and exclusively accessible during this call.
/// `field_name` must point to a null-terminated string.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_set_bool(
    data: *mut HddsDynamicData,
    field_name: *const c_char,
    value: bool,
) -> HddsError {
    set_primitive!(data, field_name, value, Bool)
}

/// Set a u8 field. A different declared field type is rejected.
///
/// # Safety
/// `data` must be live and exclusively accessible during this call.
/// `field_name` must point to a null-terminated string.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_set_u8(
    data: *mut HddsDynamicData,
    field_name: *const c_char,
    value: u8,
) -> HddsError {
    set_primitive!(data, field_name, value, U8)
}

/// Set a u16 field. A different declared field type is rejected.
///
/// # Safety
/// `data` must be live and exclusively accessible during this call.
/// `field_name` must point to a null-terminated string.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_set_u16(
    data: *mut HddsDynamicData,
    field_name: *const c_char,
    value: u16,
) -> HddsError {
    set_primitive!(data, field_name, value, U16)
}

/// Set a u32 field. A different declared field type is rejected.
///
/// # Safety
/// `data` must be live and exclusively accessible during this call.
/// `field_name` must point to a null-terminated string.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_set_u32(
    data: *mut HddsDynamicData,
    field_name: *const c_char,
    value: u32,
) -> HddsError {
    set_primitive!(data, field_name, value, U32)
}

/// Set a u64 field. A different declared field type is rejected.
///
/// # Safety
/// `data` must be live and exclusively accessible during this call.
/// `field_name` must point to a null-terminated string.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_set_u64(
    data: *mut HddsDynamicData,
    field_name: *const c_char,
    value: u64,
) -> HddsError {
    set_primitive!(data, field_name, value, U64)
}

/// Set a i8 field. A different declared field type is rejected.
///
/// # Safety
/// `data` must be live and exclusively accessible during this call.
/// `field_name` must point to a null-terminated string.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_set_i8(
    data: *mut HddsDynamicData,
    field_name: *const c_char,
    value: i8,
) -> HddsError {
    set_primitive!(data, field_name, value, I8)
}

/// Set a i16 field. A different declared field type is rejected.
///
/// # Safety
/// `data` must be live and exclusively accessible during this call.
/// `field_name` must point to a null-terminated string.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_set_i16(
    data: *mut HddsDynamicData,
    field_name: *const c_char,
    value: i16,
) -> HddsError {
    set_primitive!(data, field_name, value, I16)
}

/// Set a i32 field. A different declared field type is rejected.
///
/// # Safety
/// `data` must be live and exclusively accessible during this call.
/// `field_name` must point to a null-terminated string.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_set_i32(
    data: *mut HddsDynamicData,
    field_name: *const c_char,
    value: i32,
) -> HddsError {
    set_primitive!(data, field_name, value, I32)
}

/// Set a i64 field. A different declared field type is rejected.
///
/// # Safety
/// `data` must be live and exclusively accessible during this call.
/// `field_name` must point to a null-terminated string.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_set_i64(
    data: *mut HddsDynamicData,
    field_name: *const c_char,
    value: i64,
) -> HddsError {
    set_primitive!(data, field_name, value, I64)
}

/// Set a f32 field. A different declared field type is rejected.
///
/// # Safety
/// `data` must be live and exclusively accessible during this call.
/// `field_name` must point to a null-terminated string.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_set_f32(
    data: *mut HddsDynamicData,
    field_name: *const c_char,
    value: f32,
) -> HddsError {
    set_primitive!(data, field_name, value, F32)
}

/// Set a f64 field. A different declared field type is rejected.
///
/// # Safety
/// `data` must be live and exclusively accessible during this call.
/// `field_name` must point to a null-terminated string.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_set_f64(
    data: *mut HddsDynamicData,
    field_name: *const c_char,
    value: f64,
) -> HddsError {
    set_primitive!(data, field_name, value, F64)
}

/// Set a string field value.
///
/// # Safety
/// - `data` must be valid. `field_name` and `value` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_set_string(
    data: *mut HddsDynamicData,
    field_name: *const c_char,
    value: *const c_char,
) -> HddsError {
    if data.is_null() || field_name.is_null() || value.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Ok(name) = CStr::from_ptr(field_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let Ok(val) = CStr::from_ptr(value).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let dd = &mut *data.cast::<DynamicData>();
    if !matches!(
        dd.descriptor().field(name).map(|f| &f.type_desc.kind),
        Some(hdds::dynamic::TypeKind::Primitive(
            PrimitiveKind::String { .. }
        ))
    ) {
        return HddsError::HddsInvalidArgument;
    }
    match dd.set(name, val) {
        Ok(()) => HddsError::HddsOk,
        Err(_) => HddsError::HddsInvalidArgument,
    }
}

// =============================================================================
// Dynamic Data - Getters
// =============================================================================

macro_rules! get_primitive {
    ($data:ident, $field:ident, $out:ident, $ty:ty) => {{
        if $data.is_null() || $field.is_null() || $out.is_null() {
            return HddsError::HddsInvalidArgument;
        }
        let Ok(name) = CStr::from_ptr($field).to_str() else {
            return HddsError::HddsInvalidArgument;
        };
        let dd = &*$data.cast::<DynamicData>();
        match dd.get::<$ty>(name) {
            Ok(value) => {
                *$out = value;
                HddsError::HddsOk
            }
            Err(_) => HddsError::HddsInvalidArgument,
        }
    }};
}

/// Read a bool field. Leaves the output unchanged on error.
///
/// # Safety
/// `data` must be live and must not be mutated during this call.
/// `field_name` must be null-terminated and `out_value` must be writable.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_get_bool(
    data: *const HddsDynamicData,
    field_name: *const c_char,
    out_value: *mut bool,
) -> HddsError {
    get_primitive!(data, field_name, out_value, bool)
}

/// Read a u8 field. Leaves the output unchanged on error.
///
/// # Safety
/// `data` must be live and must not be mutated during this call.
/// `field_name` must be null-terminated and `out_value` must be writable.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_get_u8(
    data: *const HddsDynamicData,
    field_name: *const c_char,
    out_value: *mut u8,
) -> HddsError {
    get_primitive!(data, field_name, out_value, u8)
}

/// Read a u16 field. Leaves the output unchanged on error.
///
/// # Safety
/// `data` must be live and must not be mutated during this call.
/// `field_name` must be null-terminated and `out_value` must be writable.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_get_u16(
    data: *const HddsDynamicData,
    field_name: *const c_char,
    out_value: *mut u16,
) -> HddsError {
    get_primitive!(data, field_name, out_value, u16)
}

/// Read a u32 field. Leaves the output unchanged on error.
///
/// # Safety
/// `data` must be live and must not be mutated during this call.
/// `field_name` must be null-terminated and `out_value` must be writable.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_get_u32(
    data: *const HddsDynamicData,
    field_name: *const c_char,
    out_value: *mut u32,
) -> HddsError {
    get_primitive!(data, field_name, out_value, u32)
}

/// Read a u64 field. Leaves the output unchanged on error.
///
/// # Safety
/// `data` must be live and must not be mutated during this call.
/// `field_name` must be null-terminated and `out_value` must be writable.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_get_u64(
    data: *const HddsDynamicData,
    field_name: *const c_char,
    out_value: *mut u64,
) -> HddsError {
    get_primitive!(data, field_name, out_value, u64)
}

/// Read a i8 field. Leaves the output unchanged on error.
///
/// # Safety
/// `data` must be live and must not be mutated during this call.
/// `field_name` must be null-terminated and `out_value` must be writable.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_get_i8(
    data: *const HddsDynamicData,
    field_name: *const c_char,
    out_value: *mut i8,
) -> HddsError {
    get_primitive!(data, field_name, out_value, i8)
}

/// Read a i16 field. Leaves the output unchanged on error.
///
/// # Safety
/// `data` must be live and must not be mutated during this call.
/// `field_name` must be null-terminated and `out_value` must be writable.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_get_i16(
    data: *const HddsDynamicData,
    field_name: *const c_char,
    out_value: *mut i16,
) -> HddsError {
    get_primitive!(data, field_name, out_value, i16)
}

/// Read a i32 field. Leaves the output unchanged on error.
///
/// # Safety
/// `data` must be live and must not be mutated during this call.
/// `field_name` must be null-terminated and `out_value` must be writable.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_get_i32(
    data: *const HddsDynamicData,
    field_name: *const c_char,
    out_value: *mut i32,
) -> HddsError {
    get_primitive!(data, field_name, out_value, i32)
}

/// Read a i64 field. Leaves the output unchanged on error.
///
/// # Safety
/// `data` must be live and must not be mutated during this call.
/// `field_name` must be null-terminated and `out_value` must be writable.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_get_i64(
    data: *const HddsDynamicData,
    field_name: *const c_char,
    out_value: *mut i64,
) -> HddsError {
    get_primitive!(data, field_name, out_value, i64)
}

/// Read a f32 field. Leaves the output unchanged on error.
///
/// # Safety
/// `data` must be live and must not be mutated during this call.
/// `field_name` must be null-terminated and `out_value` must be writable.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_get_f32(
    data: *const HddsDynamicData,
    field_name: *const c_char,
    out_value: *mut f32,
) -> HddsError {
    get_primitive!(data, field_name, out_value, f32)
}

/// Read a f64 field. Leaves the output unchanged on error.
///
/// # Safety
/// `data` must be live and must not be mutated during this call.
/// `field_name` must be null-terminated and `out_value` must be writable.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_get_f64(
    data: *const HddsDynamicData,
    field_name: *const c_char,
    out_value: *mut f64,
) -> HddsError {
    get_primitive!(data, field_name, out_value, f64)
}

/// Get a string field value. Returns the number of bytes needed (excluding null).
///
/// # Safety
/// - `data` must be valid. `field_name` must be null-terminated.
/// - `out_buf` can be NULL to query the required size.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_get_string(
    data: *const HddsDynamicData,
    field_name: *const c_char,
    out_buf: *mut c_char,
    capacity: usize,
) -> usize {
    if data.is_null() || field_name.is_null() {
        return 0;
    }
    let Ok(name) = CStr::from_ptr(field_name).to_str() else {
        return 0;
    };
    let dd = &*data.cast::<DynamicData>();
    let Ok(val) = dd.get::<String>(name) else {
        return 0;
    };
    let needed = val.len();
    if !out_buf.is_null() && capacity > 0 {
        let copy_len = needed.min(capacity - 1);
        ptr::copy_nonoverlapping(val.as_bytes().as_ptr(), out_buf.cast::<u8>(), copy_len);
        *out_buf.add(copy_len) = 0;
    }
    needed
}

// =============================================================================
// CDR Encode / Decode
// =============================================================================

/// Encode an XCDR2 little-endian body, without an encapsulation header.
///
/// XCDR2 is the representation a writer created through this ABI offers
/// and labels its samples with when its QoS names none (`sdk_writer_qos`),
/// so these bytes go to `hdds_writer_write` as they are (create the writer
/// with `hdds_writer_create_with_extensibility` and the descriptor's
/// extensibility so the identifier names it too). A reader created through
/// this ABI requests XCDR2 alone unless its QoS asks for XCDR as well;
/// decode what it takes with `hdds_dynamic_data_decode_ex`, which reads
/// both. DDS-XTypes v1.3 7.4.3: an 8-byte
/// primitive is aligned at 4, an APPENDABLE struct starts with a DHEADER,
/// a MUTABLE one carries an EMHEADER per member.
///
/// Writes the required byte count to `out_len`. Returns HddsBufferTooSmall
/// when capacity is insufficient. Pass NULL with capacity zero to query size.
///
/// # Safety
/// - `data` must be valid. `buf` must point to `capacity` writable bytes,
///   or be NULL when `capacity` is zero.
/// - `out_len` must be valid.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_encode(
    data: *const HddsDynamicData,
    buf: *mut u8,
    capacity: usize,
    out_len: *mut usize,
) -> HddsError {
    if data.is_null() || (buf.is_null() && capacity != 0) || out_len.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let dd = &*data.cast::<DynamicData>();
    match encode_dynamic_with_version(dd, CdrVersion::Xcdr2) {
        Ok(encoded) => {
            *out_len = encoded.len();
            if encoded.len() > capacity {
                return HddsError::HddsBufferTooSmall;
            }
            if !encoded.is_empty() {
                ptr::copy_nonoverlapping(encoded.as_ptr(), buf, encoded.len());
            }
            HddsError::HddsOk
        }
        Err(e) => {
            log::error!("hdds_dynamic_data_encode: {:?}", e);
            HddsError::HddsInvalidArgument
        }
    }
}

/// Decode an XCDR2 little-endian body, without an encapsulation header:
/// what `hdds_dynamic_data_encode` produces and what a reader created
/// through this ABI receives when it requests XCDR2 only (its default). A
/// reader that also requests XCDR can receive XCDR1 samples: decode those
/// with `hdds_dynamic_data_decode_ex` and the identifier the take reports.
///
/// Returns NULL on failure.
///
/// # Safety
/// - `desc` must be valid. `buf` must point to `len` readable bytes,
///   or be NULL when `len` is zero.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_decode(
    desc: *const HddsTypeDescriptor,
    buf: *const u8,
    len: usize,
) -> *mut HddsDynamicData {
    decode_with_version(desc, buf, len, CdrVersion::Xcdr2)
}

/// Decode the body of a sample whose encapsulation identifier is
/// `encapsulation_id`, without its encapsulation header: what
/// `hdds_reader_take_ex` (and the other `_ex` takes) hand over with the
/// identifier they report.
///
/// `CDR_LE` (0x0001) and `PL_CDR_LE` (0x0003) are decoded as XCDR1, `CDR2_LE`
/// (0x0007), `D_CDR2_LE` (0x0009) and `PL_CDR2_LE` (0x000b) as XCDR2
/// (DDS-XTypes v1.3 Sec.7.6.3.1.2, Table 60); any other identifier (a
/// big-endian one included) is refused. `hdds_dynamic_data_decode` is this
/// call with 0x0007.
///
/// Returns NULL on failure.
///
/// # Safety
/// Same as `hdds_dynamic_data_decode`.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_decode_ex(
    desc: *const HddsTypeDescriptor,
    buf: *const u8,
    len: usize,
    encapsulation_id: u16,
) -> *mut HddsDynamicData {
    let version = match encapsulation_id {
        0x0001 | 0x0003 => CdrVersion::Xcdr1,
        0x0007 | 0x0009 | 0x000b => CdrVersion::Xcdr2,
        other => {
            log::error!(
                "hdds_dynamic_data_decode_ex: encapsulation 0x{other:04x} is not a \
                 little-endian XCDR1 or XCDR2 identifier"
            );
            return ptr::null_mut();
        }
    };
    decode_with_version(desc, buf, len, version)
}

/// # Safety
/// Pointer contract of `hdds_dynamic_data_decode`.
unsafe fn decode_with_version(
    desc: *const HddsTypeDescriptor,
    buf: *const u8,
    len: usize,
    version: CdrVersion,
) -> *mut HddsDynamicData {
    if desc.is_null() || (buf.is_null() && len != 0) {
        return ptr::null_mut();
    }
    let arc = &*desc.cast::<Arc<TypeDescriptor>>();
    let slice = if len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(buf, len)
    };
    match decode_dynamic_with_version(slice, arc, version) {
        Ok(dd) => Box::into_raw(Box::new(dd)).cast::<HddsDynamicData>(),
        Err(e) => {
            log::error!("hdds_dynamic_data_decode: {:?}", e);
            ptr::null_mut()
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_type_builder_lifecycle() {
        unsafe {
            let name = CString::new("TestType").unwrap();
            let builder = hdds_type_builder_new(name.as_ptr());
            assert!(!builder.is_null());

            let f1 = CString::new("x").unwrap();
            let f2 = CString::new("y").unwrap();
            assert_eq!(
                hdds_type_builder_add_field(
                    builder,
                    f1.as_ptr(),
                    HddsPrimitiveKind::HddsPrimI32 as u32
                ),
                HddsError::HddsOk,
            );
            assert_eq!(
                hdds_type_builder_add_field(
                    builder,
                    f2.as_ptr(),
                    HddsPrimitiveKind::HddsPrimF64 as u32
                ),
                HddsError::HddsOk,
            );

            let desc = hdds_type_builder_build(builder);
            assert!(!desc.is_null());
            assert_eq!(hdds_type_descriptor_get_field_count(desc), 2);

            let mut buf = [0u8; 64];
            let len = hdds_type_descriptor_get_name(desc, buf.as_mut_ptr().cast(), 64);
            assert_eq!(len, 8); // "TestType"

            hdds_type_descriptor_destroy(desc);
        }
    }

    #[test]
    fn test_dynamic_data_setters_getters() {
        unsafe {
            let name = CString::new("Sensor").unwrap();
            let builder = hdds_type_builder_new(name.as_ptr());

            let f_id = CString::new("id").unwrap();
            let f_temp = CString::new("temp").unwrap();
            let f_label = CString::new("label").unwrap();
            let f_active = CString::new("active").unwrap();

            hdds_type_builder_add_field(
                builder,
                f_id.as_ptr(),
                HddsPrimitiveKind::HddsPrimU32 as u32,
            );
            hdds_type_builder_add_field(
                builder,
                f_temp.as_ptr(),
                HddsPrimitiveKind::HddsPrimF64 as u32,
            );
            hdds_type_builder_add_string_field(builder, f_label.as_ptr());
            hdds_type_builder_add_field(
                builder,
                f_active.as_ptr(),
                HddsPrimitiveKind::HddsPrimBool as u32,
            );

            let desc = hdds_type_builder_build(builder);
            let data = hdds_dynamic_data_new(desc);
            assert!(!data.is_null());

            // Set values
            assert_eq!(
                hdds_dynamic_data_set_u32(data, f_id.as_ptr(), 42),
                HddsError::HddsOk
            );
            assert_eq!(
                hdds_dynamic_data_set_f64(data, f_temp.as_ptr(), 23.5),
                HddsError::HddsOk
            );
            let label_val = CString::new("living_room").unwrap();
            assert_eq!(
                hdds_dynamic_data_set_string(data, f_label.as_ptr(), label_val.as_ptr()),
                HddsError::HddsOk,
            );
            assert_eq!(
                hdds_dynamic_data_set_bool(data, f_active.as_ptr(), true),
                HddsError::HddsOk
            );

            // Get values
            let mut id_out: u32 = 0;
            assert_eq!(
                hdds_dynamic_data_get_u32(data, f_id.as_ptr(), &mut id_out),
                HddsError::HddsOk
            );
            assert_eq!(id_out, 42);

            let mut temp_out: f64 = 0.0;
            assert_eq!(
                hdds_dynamic_data_get_f64(data, f_temp.as_ptr(), &mut temp_out),
                HddsError::HddsOk,
            );
            assert!((temp_out - 23.5).abs() < f64::EPSILON);

            let mut bool_out = false;
            assert_eq!(
                hdds_dynamic_data_get_bool(data, f_active.as_ptr(), &mut bool_out),
                HddsError::HddsOk,
            );
            assert!(bool_out);

            let mut str_buf = [0u8; 64];
            let str_len = hdds_dynamic_data_get_string(
                data,
                f_label.as_ptr(),
                str_buf.as_mut_ptr().cast(),
                64,
            );
            assert_eq!(str_len, 11); // "living_room"

            hdds_dynamic_data_destroy(data);
            hdds_type_descriptor_destroy(desc);
        }
    }

    #[test]
    fn test_cdr_roundtrip() {
        unsafe {
            let name = CString::new("Point").unwrap();
            let builder = hdds_type_builder_new(name.as_ptr());
            let fx = CString::new("x").unwrap();
            let fy = CString::new("y").unwrap();
            hdds_type_builder_add_field(
                builder,
                fx.as_ptr(),
                HddsPrimitiveKind::HddsPrimF32 as u32,
            );
            hdds_type_builder_add_field(
                builder,
                fy.as_ptr(),
                HddsPrimitiveKind::HddsPrimF32 as u32,
            );
            let desc = hdds_type_builder_build(builder);

            let data = hdds_dynamic_data_new(desc);
            hdds_dynamic_data_set_f32(data, fx.as_ptr(), 1.5);
            hdds_dynamic_data_set_f32(data, fy.as_ptr(), 2.5);

            // Encode
            let mut buf = [0u8; 256];
            let mut len: usize = 0;
            assert_eq!(
                hdds_dynamic_data_encode(data, buf.as_mut_ptr(), 256, &mut len),
                HddsError::HddsOk,
            );
            assert!(len > 0);

            // Decode
            let data2 = hdds_dynamic_data_decode(desc, buf.as_ptr(), len);
            assert!(!data2.is_null());

            let mut x_out: f32 = 0.0;
            let mut y_out: f32 = 0.0;
            assert_eq!(
                hdds_dynamic_data_get_f32(data2, fx.as_ptr(), &mut x_out),
                HddsError::HddsOk
            );
            assert_eq!(
                hdds_dynamic_data_get_f32(data2, fy.as_ptr(), &mut y_out),
                HddsError::HddsOk
            );
            assert!((x_out - 1.5).abs() < f32::EPSILON);
            assert!((y_out - 2.5).abs() < f32::EPSILON);

            hdds_dynamic_data_destroy(data2);
            hdds_dynamic_data_destroy(data);
            hdds_type_descriptor_destroy(desc);
        }
    }

    #[test]
    fn test_null_safety() {
        unsafe {
            assert!(hdds_type_builder_new(ptr::null()).is_null());
            hdds_type_builder_destroy(ptr::null_mut());

            assert_eq!(
                hdds_type_builder_add_field(
                    ptr::null_mut(),
                    ptr::null(),
                    HddsPrimitiveKind::HddsPrimI32 as u32
                ),
                HddsError::HddsInvalidArgument,
            );

            assert!(hdds_type_builder_build(ptr::null_mut()).is_null());
            assert!(hdds_dynamic_data_new(ptr::null()).is_null());
            hdds_dynamic_data_destroy(ptr::null_mut());
            hdds_type_descriptor_destroy(ptr::null_mut());

            assert_eq!(
                hdds_dynamic_data_set_i32(ptr::null_mut(), ptr::null(), 0),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_dynamic_data_get_i32(ptr::null(), ptr::null(), ptr::null_mut()),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_dynamic_data_encode(ptr::null(), ptr::null_mut(), 0, ptr::null_mut()),
                HddsError::HddsInvalidArgument,
            );
            assert!(hdds_dynamic_data_decode(ptr::null(), ptr::null(), 0).is_null());
        }
    }
}
