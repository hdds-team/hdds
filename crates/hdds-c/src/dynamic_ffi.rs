// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Dynamic Types C FFI bindings.
//!
//! Provides runtime type construction and data manipulation without
//! compile-time type knowledge. Enables generic C/C++ tools, bridges, and
//! introspection.
//!
//! # Usage from C
//!
//! ```c
//! // Build type
//! HddsTypeBuilder* tb = hdds_type_builder_new("SensorReading");
//! hdds_type_builder_add_field(tb, "sensor_id", HDDS_PRIM_U32);
//! hdds_type_builder_add_field(tb, "temperature", HDDS_PRIM_F64);
//! HddsTypeDescriptor* desc = hdds_type_builder_build(tb);
//!
//! // Create data
//! HddsDynamicData* data = hdds_dynamic_data_new(desc);
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

use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::sync::Arc;

use hdds::dynamic::{
    DynamicData, PrimitiveKind, TypeDescriptor, TypeDescriptorBuilder,
    encode_dynamic, decode_dynamic,
};

use crate::HddsError;

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

fn to_primitive_kind(kind: HddsPrimitiveKind) -> PrimitiveKind {
    match kind {
        HddsPrimitiveKind::HddsPrimBool => PrimitiveKind::Bool,
        HddsPrimitiveKind::HddsPrimU8 => PrimitiveKind::U8,
        HddsPrimitiveKind::HddsPrimU16 => PrimitiveKind::U16,
        HddsPrimitiveKind::HddsPrimU32 => PrimitiveKind::U32,
        HddsPrimitiveKind::HddsPrimU64 => PrimitiveKind::U64,
        HddsPrimitiveKind::HddsPrimI8 => PrimitiveKind::I8,
        HddsPrimitiveKind::HddsPrimI16 => PrimitiveKind::I16,
        HddsPrimitiveKind::HddsPrimI32 => PrimitiveKind::I32,
        HddsPrimitiveKind::HddsPrimI64 => PrimitiveKind::I64,
        HddsPrimitiveKind::HddsPrimF32 => PrimitiveKind::F32,
        HddsPrimitiveKind::HddsPrimF64 => PrimitiveKind::F64,
        HddsPrimitiveKind::HddsPrimString => PrimitiveKind::String { max_length: None },
    }
}

// =============================================================================
// Opaque handles
// =============================================================================

/// Opaque handle to a type descriptor builder.
#[repr(C)]
pub struct HddsTypeBuilder {
    _private: [u8; 0],
}

/// Opaque handle to a type descriptor.
#[repr(C)]
pub struct HddsTypeDescriptor {
    _private: [u8; 0],
}

/// Opaque handle to dynamic data.
#[repr(C)]
pub struct HddsDynamicData {
    _private: [u8; 0],
}

/// Internal wrapper for the builder (uses Option to support consuming methods).
struct TypeBuilderWrapper {
    builder: Option<TypeDescriptorBuilder>,
}

// =============================================================================
// Type Builder
// =============================================================================

/// Create a new type descriptor builder.
///
/// # Safety
/// - `name` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn hdds_type_builder_new(
    name: *const c_char,
) -> *mut HddsTypeBuilder {
    if name.is_null() {
        return ptr::null_mut();
    }
    let Ok(name_str) = CStr::from_ptr(name).to_str() else {
        return ptr::null_mut();
    };
    let wrapper = TypeBuilderWrapper {
        builder: Some(TypeDescriptorBuilder::new(name_str)),
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
    kind: HddsPrimitiveKind,
) -> HddsError {
    if builder.is_null() || name.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Ok(name_str) = CStr::from_ptr(name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let wrapper = &mut *builder.cast::<TypeBuilderWrapper>();
    let Some(b) = wrapper.builder.take() else {
        return HddsError::HddsInvalidArgument;
    };
    wrapper.builder = Some(b.field(name_str, to_primitive_kind(kind)));
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
    element_kind: HddsPrimitiveKind,
) -> HddsError {
    if builder.is_null() || name.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Ok(name_str) = CStr::from_ptr(name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let wrapper = &mut *builder.cast::<TypeBuilderWrapper>();
    let Some(b) = wrapper.builder.take() else {
        return HddsError::HddsInvalidArgument;
    };
    wrapper.builder = Some(b.sequence_field(name_str, to_primitive_kind(element_kind)));
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
    element_kind: HddsPrimitiveKind,
    length: usize,
) -> HddsError {
    if builder.is_null() || name.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Ok(name_str) = CStr::from_ptr(name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let wrapper = &mut *builder.cast::<TypeBuilderWrapper>();
    let Some(b) = wrapper.builder.take() else {
        return HddsError::HddsInvalidArgument;
    };
    wrapper.builder = Some(b.array_field(name_str, to_primitive_kind(element_kind), length));
    HddsError::HddsOk
}

/// Build the type descriptor (consumes the builder).
///
/// Returns NULL if the builder was already consumed or invalid.
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
    let needed = name.as_bytes().len();
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

macro_rules! dynamic_setter {
    ($fn_name:ident, $ty:ty, $set_ty:ty) => {
        #[no_mangle]
        pub unsafe extern "C" fn $fn_name(
            data: *mut HddsDynamicData,
            field_name: *const c_char,
            value: $ty,
        ) -> HddsError {
            if data.is_null() || field_name.is_null() {
                return HddsError::HddsInvalidArgument;
            }
            let Ok(name) = CStr::from_ptr(field_name).to_str() else {
                return HddsError::HddsInvalidArgument;
            };
            let dd = &mut *data.cast::<DynamicData>();
            match dd.set(name, value as $set_ty) {
                Ok(()) => HddsError::HddsOk,
                Err(_) => HddsError::HddsInvalidArgument,
            }
        }
    };
}

dynamic_setter!(hdds_dynamic_data_set_bool, bool, bool);
dynamic_setter!(hdds_dynamic_data_set_u8, u8, u8);
dynamic_setter!(hdds_dynamic_data_set_u16, u16, u16);
dynamic_setter!(hdds_dynamic_data_set_u32, u32, u32);
dynamic_setter!(hdds_dynamic_data_set_u64, u64, u64);
dynamic_setter!(hdds_dynamic_data_set_i8, i8, i8);
dynamic_setter!(hdds_dynamic_data_set_i16, i16, i16);
dynamic_setter!(hdds_dynamic_data_set_i32, i32, i32);
dynamic_setter!(hdds_dynamic_data_set_i64, i64, i64);
dynamic_setter!(hdds_dynamic_data_set_f32, f32, f32);
dynamic_setter!(hdds_dynamic_data_set_f64, f64, f64);

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
    match dd.set(name, val) {
        Ok(()) => HddsError::HddsOk,
        Err(_) => HddsError::HddsInvalidArgument,
    }
}

// =============================================================================
// Dynamic Data - Getters
// =============================================================================

macro_rules! dynamic_getter {
    ($fn_name:ident, $ty:ty) => {
        #[no_mangle]
        pub unsafe extern "C" fn $fn_name(
            data: *const HddsDynamicData,
            field_name: *const c_char,
            out_value: *mut $ty,
        ) -> HddsError {
            if data.is_null() || field_name.is_null() || out_value.is_null() {
                return HddsError::HddsInvalidArgument;
            }
            let Ok(name) = CStr::from_ptr(field_name).to_str() else {
                return HddsError::HddsInvalidArgument;
            };
            let dd = &*data.cast::<DynamicData>();
            match dd.get::<$ty>(name) {
                Ok(v) => {
                    *out_value = v;
                    HddsError::HddsOk
                }
                Err(_) => HddsError::HddsInvalidArgument,
            }
        }
    };
}

dynamic_getter!(hdds_dynamic_data_get_bool, bool);
dynamic_getter!(hdds_dynamic_data_get_u8, u8);
dynamic_getter!(hdds_dynamic_data_get_u16, u16);
dynamic_getter!(hdds_dynamic_data_get_u32, u32);
dynamic_getter!(hdds_dynamic_data_get_u64, u64);
dynamic_getter!(hdds_dynamic_data_get_i8, i8);
dynamic_getter!(hdds_dynamic_data_get_i16, i16);
dynamic_getter!(hdds_dynamic_data_get_i32, i32);
dynamic_getter!(hdds_dynamic_data_get_i64, i64);
dynamic_getter!(hdds_dynamic_data_get_f32, f32);
dynamic_getter!(hdds_dynamic_data_get_f64, f64);

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
    let needed = val.as_bytes().len();
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

/// Encode dynamic data to CDR2 format.
///
/// Returns HddsOk on success, writes the number of bytes to `out_len`.
///
/// # Safety
/// - `data` must be valid. `buf` must point to `capacity` writable bytes.
/// - `out_len` must be valid.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_encode(
    data: *const HddsDynamicData,
    buf: *mut u8,
    capacity: usize,
    out_len: *mut usize,
) -> HddsError {
    if data.is_null() || buf.is_null() || out_len.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let dd = &*data.cast::<DynamicData>();
    match encode_dynamic(dd) {
        Ok(encoded) => {
            if encoded.len() > capacity {
                return HddsError::HddsInvalidArgument;
            }
            ptr::copy_nonoverlapping(encoded.as_ptr(), buf, encoded.len());
            *out_len = encoded.len();
            HddsError::HddsOk
        }
        Err(e) => {
            log::error!("hdds_dynamic_data_encode: {:?}", e);
            HddsError::HddsInvalidArgument
        }
    }
}

/// Decode CDR2 data into a new dynamic data instance.
///
/// Returns NULL on failure.
///
/// # Safety
/// - `desc` must be valid. `buf` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn hdds_dynamic_data_decode(
    desc: *const HddsTypeDescriptor,
    buf: *const u8,
    len: usize,
) -> *mut HddsDynamicData {
    if desc.is_null() || buf.is_null() || len == 0 {
        return ptr::null_mut();
    }
    let arc = &*desc.cast::<Arc<TypeDescriptor>>();
    let slice = std::slice::from_raw_parts(buf, len);
    match decode_dynamic(slice, arc) {
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
                hdds_type_builder_add_field(builder, f1.as_ptr(), HddsPrimitiveKind::HddsPrimI32),
                HddsError::HddsOk,
            );
            assert_eq!(
                hdds_type_builder_add_field(builder, f2.as_ptr(), HddsPrimitiveKind::HddsPrimF64),
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

            hdds_type_builder_add_field(builder, f_id.as_ptr(), HddsPrimitiveKind::HddsPrimU32);
            hdds_type_builder_add_field(builder, f_temp.as_ptr(), HddsPrimitiveKind::HddsPrimF64);
            hdds_type_builder_add_string_field(builder, f_label.as_ptr());
            hdds_type_builder_add_field(builder, f_active.as_ptr(), HddsPrimitiveKind::HddsPrimBool);

            let desc = hdds_type_builder_build(builder);
            let data = hdds_dynamic_data_new(desc);
            assert!(!data.is_null());

            // Set values
            assert_eq!(hdds_dynamic_data_set_u32(data, f_id.as_ptr(), 42), HddsError::HddsOk);
            assert_eq!(hdds_dynamic_data_set_f64(data, f_temp.as_ptr(), 23.5), HddsError::HddsOk);
            let label_val = CString::new("living_room").unwrap();
            assert_eq!(
                hdds_dynamic_data_set_string(data, f_label.as_ptr(), label_val.as_ptr()),
                HddsError::HddsOk,
            );
            assert_eq!(hdds_dynamic_data_set_bool(data, f_active.as_ptr(), true), HddsError::HddsOk);

            // Get values
            let mut id_out: u32 = 0;
            assert_eq!(hdds_dynamic_data_get_u32(data, f_id.as_ptr(), &mut id_out), HddsError::HddsOk);
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
            hdds_type_builder_add_field(builder, fx.as_ptr(), HddsPrimitiveKind::HddsPrimF32);
            hdds_type_builder_add_field(builder, fy.as_ptr(), HddsPrimitiveKind::HddsPrimF32);
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
            assert_eq!(hdds_dynamic_data_get_f32(data2, fx.as_ptr(), &mut x_out), HddsError::HddsOk);
            assert_eq!(hdds_dynamic_data_get_f32(data2, fy.as_ptr(), &mut y_out), HddsError::HddsOk);
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
                hdds_type_builder_add_field(ptr::null_mut(), ptr::null(), HddsPrimitiveKind::HddsPrimI32),
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
