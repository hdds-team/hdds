// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
// Dynamic data to ROS2 message conversion for generic subscriptions.

use super::ros2_types::ros2_type_to_descriptor;
use super::{rosidl_runtime_c__String, rosidl_runtime_c__U16String};
use hdds::dynamic::{decode_dynamic, DynamicValue, PrimitiveKind, TypeKind};
use std::ffi::CString;
use std::os::raw::c_void;
use std::ptr;

#[cfg(target_os = "windows")]
const LONG_DOUBLE_SIZE: usize = 8;
#[cfg(not(target_os = "windows"))]
const LONG_DOUBLE_SIZE: usize = 16;

#[cfg(target_os = "windows")]
const LONG_DOUBLE_ALIGN: usize = 8;
#[cfg(not(target_os = "windows"))]
const LONG_DOUBLE_ALIGN: usize = 16;

#[cfg(not(test))]
extern "C" {
    fn rosidl_runtime_c__String__assign(
        str_: *mut rosidl_runtime_c__String,
        value: *const std::os::raw::c_char,
    ) -> bool;
    fn rosidl_runtime_c__U16String__assignn(
        str_: *mut rosidl_runtime_c__U16String,
        value: *const u16,
        len: usize,
    ) -> bool;
}

#[cfg(test)]
use super::{rosidl_runtime_c__String__assign, rosidl_runtime_c__U16String__assignn};

/// Error type for dynamic to ROS conversion.
#[derive(Debug)]
pub enum DynamicToRosError {
    TypeNotSupported(String),
    DecodeFailed(String),
    WriteFailed(String),
}

impl std::fmt::Display for DynamicToRosError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TypeNotSupported(t) => write!(f, "Type not supported: {}", t),
            Self::DecodeFailed(msg) => write!(f, "Decode failed: {}", msg),
            Self::WriteFailed(msg) => write!(f, "Write failed: {}", msg),
        }
    }
}

impl std::error::Error for DynamicToRosError {}

/// Deserialize CDR data to a ROS2 message using dynamic types.
/// Returns true if successful, false if the type is not supported.
pub unsafe fn deserialize_dynamic_to_ros(
    type_name: &str,
    data: &[u8],
    ros_message: *mut c_void,
) -> Result<(), DynamicToRosError> {
    // Get the type descriptor for this ROS2 type
    let descriptor = ros2_type_to_descriptor(type_name)
        .ok_or_else(|| DynamicToRosError::TypeNotSupported(type_name.to_string()))?;

    // Decode the CDR data using dynamic types
    let dynamic_data = decode_dynamic(data, &descriptor)
        .map_err(|e| DynamicToRosError::DecodeFailed(e.to_string()))?;

    // Write the dynamic data to the ROS2 message buffer
    write_dynamic_to_ros(dynamic_data.value(), &descriptor.kind, ros_message)?;

    Ok(())
}

/// Write a DynamicValue to a ROS2 message buffer.
unsafe fn write_dynamic_to_ros(
    value: &DynamicValue,
    kind: &TypeKind,
    ros_message: *mut c_void,
) -> Result<(), DynamicToRosError> {
    match kind {
        TypeKind::Struct(fields) => {
            if let DynamicValue::Struct(map) = value {
                let mut offset = 0usize;
                for field in fields {
                    // Calculate field offset (simplified - assumes packed layout)
                    offset = align_offset(offset, field_alignment(&field.type_desc.kind));
                    let field_ptr = (ros_message as *mut u8).add(offset) as *mut c_void;

                    if let Some(field_value) = map.get(&field.name) {
                        write_field_to_ros(field_value, &field.type_desc.kind, field_ptr)?;
                    }

                    offset += field_size(&field.type_desc.kind);
                }
                Ok(())
            } else {
                Err(DynamicToRosError::WriteFailed(
                    "Expected struct value".into(),
                ))
            }
        }
        TypeKind::Primitive(p) => write_primitive_to_ros(value, *p, ros_message),
        TypeKind::Sequence(seq_desc) => {
            if let DynamicValue::Sequence(items) = value {
                write_sequence_to_ros(items, &seq_desc.element_type.kind, ros_message)
            } else {
                Err(DynamicToRosError::WriteFailed(
                    "Expected sequence value".into(),
                ))
            }
        }
        TypeKind::Array(arr_desc) => {
            if let DynamicValue::Array(items) = value {
                write_array_to_ros(
                    items,
                    &arr_desc.element_type.kind,
                    arr_desc.length,
                    ros_message,
                )
            } else {
                Err(DynamicToRosError::WriteFailed(
                    "Expected array value".into(),
                ))
            }
        }
        TypeKind::Enum(enum_desc) => {
            if let DynamicValue::Enum(val, _) = value {
                write_enum_to_ros(*val, enum_desc.underlying, ros_message)
            } else {
                Err(DynamicToRosError::WriteFailed("Expected enum value".into()))
            }
        }
        TypeKind::Nested(inner) => write_dynamic_to_ros(value, &inner.kind, ros_message),
        _ => Err(DynamicToRosError::WriteFailed(format!(
            "Unsupported type kind: {:?}",
            kind
        ))),
    }
}

/// Write a single field value to the ROS2 message buffer.
unsafe fn write_field_to_ros(
    value: &DynamicValue,
    kind: &TypeKind,
    field_ptr: *mut c_void,
) -> Result<(), DynamicToRosError> {
    match kind {
        TypeKind::Primitive(p) => write_primitive_to_ros(value, *p, field_ptr),
        TypeKind::Struct(fields) => {
            if let DynamicValue::Struct(map) = value {
                let mut offset = 0usize;
                for field in fields {
                    offset = align_offset(offset, field_alignment(&field.type_desc.kind));
                    let nested_ptr = (field_ptr as *mut u8).add(offset) as *mut c_void;

                    if let Some(field_value) = map.get(&field.name) {
                        write_field_to_ros(field_value, &field.type_desc.kind, nested_ptr)?;
                    }

                    offset += field_size(&field.type_desc.kind);
                }
                Ok(())
            } else {
                Err(DynamicToRosError::WriteFailed(
                    "Expected struct value".into(),
                ))
            }
        }
        TypeKind::Sequence(seq_desc) => {
            if let DynamicValue::Sequence(items) = value {
                write_sequence_to_ros(items, &seq_desc.element_type.kind, field_ptr)?;
                Ok(())
            } else {
                Err(DynamicToRosError::WriteFailed(
                    "Expected sequence value".into(),
                ))
            }
        }
        TypeKind::Array(arr_desc) => {
            if let DynamicValue::Array(items) = value {
                write_array_to_ros(
                    items,
                    &arr_desc.element_type.kind,
                    arr_desc.length,
                    field_ptr,
                )?;
                Ok(())
            } else {
                Err(DynamicToRosError::WriteFailed(
                    "Expected array value".into(),
                ))
            }
        }
        TypeKind::Enum(enum_desc) => {
            if let DynamicValue::Enum(val, _) = value {
                write_enum_to_ros(*val, enum_desc.underlying, field_ptr)
            } else {
                Err(DynamicToRosError::WriteFailed("Expected enum value".into()))
            }
        }
        TypeKind::Nested(inner) => write_field_to_ros(value, &inner.kind, field_ptr),
        _ => Err(DynamicToRosError::WriteFailed(format!(
            "Unsupported field kind: {:?}",
            kind
        ))),
    }
}

/// Write a primitive value to the ROS2 message buffer.
unsafe fn write_primitive_to_ros(
    value: &DynamicValue,
    kind: PrimitiveKind,
    field_ptr: *mut c_void,
) -> Result<(), DynamicToRosError> {
    match kind {
        PrimitiveKind::Bool => {
            if let DynamicValue::Bool(v) = value {
                *(field_ptr as *mut bool) = *v;
                Ok(())
            } else {
                Err(DynamicToRosError::WriteFailed("Expected bool".into()))
            }
        }
        PrimitiveKind::I8 => {
            if let DynamicValue::I8(v) = value {
                *(field_ptr as *mut i8) = *v;
                Ok(())
            } else {
                Err(DynamicToRosError::WriteFailed("Expected i8".into()))
            }
        }
        PrimitiveKind::U8 => {
            if let DynamicValue::U8(v) = value {
                *(field_ptr as *mut u8) = *v;
                Ok(())
            } else {
                Err(DynamicToRosError::WriteFailed("Expected u8".into()))
            }
        }
        PrimitiveKind::I16 => {
            if let DynamicValue::I16(v) = value {
                *(field_ptr as *mut i16) = *v;
                Ok(())
            } else {
                Err(DynamicToRosError::WriteFailed("Expected i16".into()))
            }
        }
        PrimitiveKind::U16 => {
            if let DynamicValue::U16(v) = value {
                *(field_ptr as *mut u16) = *v;
                Ok(())
            } else {
                Err(DynamicToRosError::WriteFailed("Expected u16".into()))
            }
        }
        PrimitiveKind::I32 => {
            if let DynamicValue::I32(v) = value {
                *(field_ptr as *mut i32) = *v;
                Ok(())
            } else {
                Err(DynamicToRosError::WriteFailed("Expected i32".into()))
            }
        }
        PrimitiveKind::U32 => {
            if let DynamicValue::U32(v) = value {
                *(field_ptr as *mut u32) = *v;
                Ok(())
            } else {
                Err(DynamicToRosError::WriteFailed("Expected u32".into()))
            }
        }
        PrimitiveKind::I64 => {
            if let DynamicValue::I64(v) = value {
                *(field_ptr as *mut i64) = *v;
                Ok(())
            } else {
                Err(DynamicToRosError::WriteFailed("Expected i64".into()))
            }
        }
        PrimitiveKind::U64 => {
            if let DynamicValue::U64(v) = value {
                *(field_ptr as *mut u64) = *v;
                Ok(())
            } else {
                Err(DynamicToRosError::WriteFailed("Expected u64".into()))
            }
        }
        PrimitiveKind::F32 => {
            if let DynamicValue::F32(v) = value {
                *(field_ptr as *mut f32) = *v;
                Ok(())
            } else {
                Err(DynamicToRosError::WriteFailed("Expected f32".into()))
            }
        }
        PrimitiveKind::F64 => {
            if let DynamicValue::F64(v) = value {
                *(field_ptr as *mut f64) = *v;
                Ok(())
            } else {
                Err(DynamicToRosError::WriteFailed("Expected f64".into()))
            }
        }
        PrimitiveKind::Char => {
            if let DynamicValue::Char(v) = value {
                *(field_ptr as *mut u8) = *v as u8;
                Ok(())
            } else {
                Err(DynamicToRosError::WriteFailed("Expected char".into()))
            }
        }
        PrimitiveKind::LongDouble => {
            if let DynamicValue::LongDouble(bytes) = value {
                ptr::copy_nonoverlapping(bytes.as_ptr(), field_ptr.cast::<u8>(), bytes.len());
                Ok(())
            } else {
                Err(DynamicToRosError::WriteFailed(
                    "Expected long double".into(),
                ))
            }
        }
        PrimitiveKind::String { max_length } => {
            if let DynamicValue::String(s) = value {
                write_string_to_ros(s, field_ptr, max_length)?;
                Ok(())
            } else {
                Err(DynamicToRosError::WriteFailed("Expected string".into()))
            }
        }
        PrimitiveKind::WString { max_length } => {
            if let DynamicValue::WString(s) = value {
                write_wstring_to_ros(s, field_ptr, max_length)?;
                Ok(())
            } else {
                Err(DynamicToRosError::WriteFailed("Expected wstring".into()))
            }
        }
    }
}

/// Write a fixed-size array to the ROS2 message buffer.
unsafe fn write_array_to_ros(
    items: &[DynamicValue],
    element_kind: &TypeKind,
    expected_len: usize,
    field_ptr: *mut c_void,
) -> Result<(), DynamicToRosError> {
    if items.len() != expected_len {
        return Err(DynamicToRosError::WriteFailed(format!(
            "Array length mismatch: expected {}, got {}",
            expected_len,
            items.len()
        )));
    }
    let elem_size = field_size(element_kind);
    for (i, item) in items.iter().enumerate() {
        let elem_ptr = (field_ptr as *mut u8).add(i * elem_size) as *mut c_void;
        write_field_to_ros(item, element_kind, elem_ptr)?;
    }
    Ok(())
}

/// Write a UTF-16 string to a rosidl_runtime_c__U16String field.
unsafe fn write_wstring_to_ros(
    value: &str,
    field_ptr: *mut c_void,
    max_length: Option<usize>,
) -> Result<(), DynamicToRosError> {
    let ros_wstring = field_ptr as *mut rosidl_runtime_c__U16String;
    let utf16: Vec<u16> = value.encode_utf16().collect();
    if let Some(max) = max_length {
        if utf16.len() > max {
            return Err(DynamicToRosError::WriteFailed(
                "WString exceeds bound".into(),
            ));
        }
    }

    static EMPTY_U16: [u16; 1] = [0];
    let (ptr, len) = if utf16.is_empty() {
        (EMPTY_U16.as_ptr(), 0)
    } else {
        (utf16.as_ptr(), utf16.len())
    };

    if !rosidl_runtime_c__U16String__assignn(ros_wstring, ptr, len) {
        return Err(DynamicToRosError::WriteFailed(
            "WString assign failed".into(),
        ));
    }

    Ok(())
}

/// Write an enum value to the ROS2 message buffer using the declared underlying type.
unsafe fn write_enum_to_ros(
    value: i64,
    underlying: PrimitiveKind,
    field_ptr: *mut c_void,
) -> Result<(), DynamicToRosError> {
    match underlying {
        PrimitiveKind::U8 => {
            *(field_ptr as *mut u8) = value as u8;
            Ok(())
        }
        PrimitiveKind::U16 => {
            *(field_ptr as *mut u16) = value as u16;
            Ok(())
        }
        PrimitiveKind::U32 => {
            *(field_ptr as *mut u32) = value as u32;
            Ok(())
        }
        PrimitiveKind::U64 => {
            *(field_ptr as *mut u64) = value as u64;
            Ok(())
        }
        PrimitiveKind::I8 => {
            *(field_ptr as *mut i8) = value as i8;
            Ok(())
        }
        PrimitiveKind::I16 => {
            *(field_ptr as *mut i16) = value as i16;
            Ok(())
        }
        PrimitiveKind::I32 => {
            *(field_ptr as *mut i32) = value as i32;
            Ok(())
        }
        PrimitiveKind::I64 => {
            *(field_ptr as *mut i64) = value;
            Ok(())
        }
        _ => Err(DynamicToRosError::WriteFailed(
            "Unsupported enum underlying type".into(),
        )),
    }
}

/// Write a string to a rosidl_runtime_c__String field.
unsafe fn write_string_to_ros(
    value: &str,
    field_ptr: *mut c_void,
    max_length: Option<usize>,
) -> Result<(), DynamicToRosError> {
    let ros_string = field_ptr as *mut rosidl_runtime_c__String;

    if let Some(max) = max_length {
        if value.len() > max {
            return Err(DynamicToRosError::WriteFailed(
                "String exceeds bound".into(),
            ));
        }
    }

    // Create a null-terminated C string
    let c_str =
        CString::new(value).map_err(|_| DynamicToRosError::WriteFailed("Invalid string".into()))?;

    // Use ROS2 runtime to assign the string
    if !rosidl_runtime_c__String__assign(ros_string, c_str.as_ptr()) {
        return Err(DynamicToRosError::WriteFailed(
            "String assign failed".into(),
        ));
    }

    Ok(())
}

/// Write a sequence to the ROS2 message buffer.
/// For primitive sequences like int32[], this writes to a rosidl sequence struct.
unsafe fn write_sequence_to_ros(
    items: &[DynamicValue],
    element_kind: &TypeKind,
    field_ptr: *mut c_void,
) -> Result<(), DynamicToRosError> {
    // ROS2 sequences have the layout:
    // struct {
    //     T* data;
    //     size_t size;
    //     size_t capacity;
    // }

    #[repr(C)]
    struct GenericSequence {
        data: *mut c_void,
        size: usize,
        capacity: usize,
    }

    let seq = field_ptr as *mut GenericSequence;

    // Get element size
    let elem_size = field_size(element_kind);

    // Allocate memory for the sequence data
    let total_size = items.len() * elem_size;
    let data_ptr = if total_size > 0 {
        libc::malloc(total_size)
    } else {
        ptr::null_mut()
    };

    if !data_ptr.is_null() || items.is_empty() {
        if !data_ptr.is_null() {
            ptr::write_bytes(data_ptr, 0, total_size);
        }
        // Write each element
        for (i, item) in items.iter().enumerate() {
            let elem_ptr = (data_ptr as *mut u8).add(i * elem_size) as *mut c_void;
            write_field_to_ros(item, element_kind, elem_ptr)?;
        }

        // Update the sequence struct
        (*seq).data = data_ptr;
        (*seq).size = items.len();
        (*seq).capacity = items.len();

        Ok(())
    } else {
        Err(DynamicToRosError::WriteFailed("Allocation failed".into()))
    }
}

/// Get the alignment requirement for a type.
fn field_alignment(kind: &TypeKind) -> usize {
    match kind {
        TypeKind::Primitive(p) => primitive_alignment(*p),
        TypeKind::Struct(fields) => {
            // Struct alignment is the max of all field alignments
            fields
                .iter()
                .map(|f| field_alignment(&f.type_desc.kind))
                .max()
                .unwrap_or(1)
        }
        TypeKind::Sequence(_) => 8, // pointer alignment
        TypeKind::Array(arr) => field_alignment(&arr.element_type.kind),
        TypeKind::Enum(enum_desc) => primitive_alignment(enum_desc.underlying),
        TypeKind::Nested(inner) => field_alignment(&inner.kind),
        _ => 8,
    }
}

/// Get the size of a type in the ROS2 C layout.
fn field_size(kind: &TypeKind) -> usize {
    match kind {
        TypeKind::Primitive(p) => primitive_size(*p),
        TypeKind::Struct(fields) => {
            let mut size = 0usize;
            for field in fields {
                size = align_offset(size, field_alignment(&field.type_desc.kind));
                size += field_size(&field.type_desc.kind);
            }
            // Pad to struct alignment
            let struct_align = field_alignment(kind);
            align_offset(size, struct_align)
        }
        TypeKind::Sequence(_) => 3 * std::mem::size_of::<usize>(), // data, size, capacity
        TypeKind::Array(arr) => field_size(&arr.element_type.kind) * arr.length,
        TypeKind::Enum(enum_desc) => primitive_size(enum_desc.underlying),
        TypeKind::Nested(inner) => field_size(&inner.kind),
        _ => 8,
    }
}

fn primitive_alignment(kind: PrimitiveKind) -> usize {
    match kind {
        PrimitiveKind::Bool | PrimitiveKind::I8 | PrimitiveKind::U8 | PrimitiveKind::Char => 1,
        PrimitiveKind::I16 | PrimitiveKind::U16 => 2,
        PrimitiveKind::I32 | PrimitiveKind::U32 | PrimitiveKind::F32 => 4,
        PrimitiveKind::I64 | PrimitiveKind::U64 | PrimitiveKind::F64 => 8,
        PrimitiveKind::LongDouble => LONG_DOUBLE_ALIGN,
        PrimitiveKind::String { .. } => 8, // pointer alignment
        PrimitiveKind::WString { .. } => 8,
    }
}

fn primitive_size(kind: PrimitiveKind) -> usize {
    match kind {
        PrimitiveKind::Bool | PrimitiveKind::I8 | PrimitiveKind::U8 | PrimitiveKind::Char => 1,
        PrimitiveKind::I16 | PrimitiveKind::U16 => 2,
        PrimitiveKind::I32 | PrimitiveKind::U32 | PrimitiveKind::F32 => 4,
        PrimitiveKind::I64 | PrimitiveKind::U64 | PrimitiveKind::F64 => 8,
        PrimitiveKind::LongDouble => LONG_DOUBLE_SIZE,
        PrimitiveKind::String { .. } => std::mem::size_of::<rosidl_runtime_c__String>(),
        PrimitiveKind::WString { .. } => std::mem::size_of::<rosidl_runtime_c__U16String>(),
    }
}

/// Align an offset to a given alignment.
fn align_offset(offset: usize, alignment: usize) -> usize {
    if alignment <= 1 {
        offset
    } else {
        (offset + alignment - 1) & !(alignment - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hdds::dynamic::{encode_dynamic, DynamicData};

    #[test]
    fn test_deserialize_std_msgs_int32() {
        // Create a std_msgs/Int32 with value 42
        let descriptor = ros2_type_to_descriptor("std_msgs/msg/Int32").unwrap();
        let mut data = DynamicData::new(&descriptor);
        data.set("data", 42i32).unwrap();

        // Encode to CDR
        let encoded = encode_dynamic(&data).unwrap();

        // Create ROS2 message buffer (std_msgs/Int32 is just an i32)
        #[repr(C)]
        struct StdMsgsInt32 {
            data: i32,
        }
        let mut ros_msg = StdMsgsInt32 { data: 0 };

        // Deserialize
        unsafe {
            deserialize_dynamic_to_ros(
                "std_msgs/msg/Int32",
                &encoded,
                &mut ros_msg as *mut _ as *mut c_void,
            )
            .unwrap();
        }

        assert_eq!(ros_msg.data, 42);
    }

    #[test]
    fn test_deserialize_geometry_msgs_point() {
        // Create a geometry_msgs/Point
        let descriptor = ros2_type_to_descriptor("geometry_msgs/msg/Point").unwrap();
        let mut data = DynamicData::new(&descriptor);
        data.set("x", 1.0f64).unwrap();
        data.set("y", 2.0f64).unwrap();
        data.set("z", 3.0f64).unwrap();

        // Encode to CDR
        let encoded = encode_dynamic(&data).unwrap();

        // Create ROS2 message buffer
        #[repr(C)]
        struct GeometryMsgsPoint {
            x: f64,
            y: f64,
            z: f64,
        }
        let mut ros_msg = GeometryMsgsPoint {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        };

        // Deserialize
        unsafe {
            deserialize_dynamic_to_ros(
                "geometry_msgs/msg/Point",
                &encoded,
                &mut ros_msg as *mut _ as *mut c_void,
            )
            .unwrap();
        }

        assert!((ros_msg.x - 1.0).abs() < 1e-10);
        assert!((ros_msg.y - 2.0).abs() < 1e-10);
        assert!((ros_msg.z - 3.0).abs() < 1e-10);
    }
}
