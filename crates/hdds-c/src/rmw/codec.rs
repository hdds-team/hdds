// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
// Specialized ROS 2 message codecs for rmw_hdds fast paths.

use super::{
    map_deserialize_error, map_serialize_error, ApiError, BytePayload, CdrCursor, CdrWriter,
    DeserializeError, SerializeError,
};
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::slice;

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Ros2CodecKind {
    None = 0,
    String = 1,
    Log = 2,
    ParameterEvent = 3,
}

impl Ros2CodecKind {
    pub fn try_from(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::String),
            2 => Some(Self::Log),
            3 => Some(Self::ParameterEvent),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct RosString {
    pub(crate) data: *mut c_char,
    pub(crate) size: usize,
    pub(crate) capacity: usize,
}

#[repr(C)]
pub(crate) struct RosStringSequence {
    pub(crate) data: *mut RosString,
    pub(crate) size: usize,
    pub(crate) capacity: usize,
}

#[repr(C)]
pub(crate) struct RosOctetSequence {
    pub(crate) data: *mut u8,
    pub(crate) size: usize,
    pub(crate) capacity: usize,
}

#[repr(C)]
pub(crate) struct RosBoolSequence {
    pub(crate) data: *mut bool,
    pub(crate) size: usize,
    pub(crate) capacity: usize,
}

#[repr(C)]
pub(crate) struct RosInt64Sequence {
    pub(crate) data: *mut i64,
    pub(crate) size: usize,
    pub(crate) capacity: usize,
}

#[repr(C)]
pub(crate) struct RosDoubleSequence {
    pub(crate) data: *mut f64,
    pub(crate) size: usize,
    pub(crate) capacity: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct BuiltinTime {
    pub(crate) sec: i32,
    pub(crate) nanosec: u32,
}

#[repr(C)]
pub(crate) struct StdMsgsString {
    pub(crate) data: RosString,
}

#[repr(C)]
pub(crate) struct RclLog {
    pub(crate) stamp: BuiltinTime,
    pub(crate) level: u8,
    pub(crate) name: RosString,
    pub(crate) msg: RosString,
    pub(crate) file: RosString,
    pub(crate) function: RosString,
    pub(crate) line: u32,
}

#[repr(C)]
pub(crate) struct ParameterValue {
    pub(crate) type_: u8,
    pub(crate) bool_value: bool,
    pub(crate) integer_value: i64,
    pub(crate) double_value: f64,
    pub(crate) string_value: RosString,
    pub(crate) byte_array_value: RosOctetSequence,
    pub(crate) bool_array_value: RosBoolSequence,
    pub(crate) integer_array_value: RosInt64Sequence,
    pub(crate) double_array_value: RosDoubleSequence,
    pub(crate) string_array_value: RosStringSequence,
}

#[repr(C)]
pub(crate) struct Parameter {
    pub(crate) name: RosString,
    pub(crate) value: ParameterValue,
}

#[repr(C)]
pub(crate) struct ParameterSequence {
    pub(crate) data: *mut Parameter,
    pub(crate) size: usize,
    pub(crate) capacity: usize,
}

#[repr(C)]
pub(crate) struct ParameterEvent {
    pub(crate) stamp: BuiltinTime,
    pub(crate) node: RosString,
    pub(crate) new_parameters: ParameterSequence,
    pub(crate) changed_parameters: ParameterSequence,
    pub(crate) deleted_parameters: ParameterSequence,
}

extern "C" {
    fn rosidl_runtime_c__String__assignn(
        str_: *mut RosString,
        value: *const c_char,
        size: usize,
    ) -> bool;
    fn rosidl_runtime_c__String__Sequence__init(seq: *mut RosStringSequence, size: usize) -> bool;
    fn rosidl_runtime_c__String__Sequence__fini(seq: *mut RosStringSequence);
    fn rosidl_runtime_c__octet__Sequence__init(seq: *mut RosOctetSequence, size: usize) -> bool;
    fn rosidl_runtime_c__octet__Sequence__fini(seq: *mut RosOctetSequence);
    fn rosidl_runtime_c__boolean__Sequence__init(seq: *mut RosBoolSequence, size: usize) -> bool;
    fn rosidl_runtime_c__boolean__Sequence__fini(seq: *mut RosBoolSequence);
    fn rosidl_runtime_c__int64__Sequence__init(seq: *mut RosInt64Sequence, size: usize) -> bool;
    fn rosidl_runtime_c__int64__Sequence__fini(seq: *mut RosInt64Sequence);
    fn rosidl_runtime_c__double__Sequence__init(seq: *mut RosDoubleSequence, size: usize) -> bool;
    fn rosidl_runtime_c__double__Sequence__fini(seq: *mut RosDoubleSequence);
    fn rcl_interfaces__msg__Parameter__Sequence__init(
        seq: *mut ParameterSequence,
        size: usize,
    ) -> bool;
    fn rcl_interfaces__msg__Parameter__Sequence__fini(seq: *mut ParameterSequence);
}

pub unsafe fn encode(
    codec: Ros2CodecKind,
    ros_message: *const c_void,
) -> Result<Option<BytePayload>, ApiError> {
    match codec {
        Ros2CodecKind::None => Ok(None),
        Ros2CodecKind::String => encode_string_message(ros_message).map(Some),
        Ros2CodecKind::Log => encode_log_message(ros_message).map(Some),
        Ros2CodecKind::ParameterEvent => encode_parameter_event(ros_message).map(Some),
    }
}

pub unsafe fn decode(
    codec: Ros2CodecKind,
    data: &[u8],
    ros_message: *mut c_void,
) -> Result<bool, ApiError> {
    match codec {
        Ros2CodecKind::None => Ok(false),
        Ros2CodecKind::String => {
            decode_string_message(data, ros_message)?;
            Ok(true)
        }
        Ros2CodecKind::Log => {
            decode_log_message(data, ros_message)?;
            Ok(true)
        }
        Ros2CodecKind::ParameterEvent => {
            decode_parameter_event(data, ros_message)?;
            Ok(true)
        }
    }
}

unsafe fn encode_string_message(ros_message: *const c_void) -> Result<BytePayload, ApiError> {
    let msg = &*(ros_message as *const StdMsgsString);
    let data = read_ros_string(&msg.data)?;
    let mut writer = CdrWriter::new();
    write_cdr_string(&mut writer, data).map_err(map_serialize_error)?;
    Ok(writer.into_payload())
}

unsafe fn decode_string_message(data: &[u8], ros_message: *mut c_void) -> Result<(), ApiError> {
    let mut cursor = CdrCursor::new(data);
    let msg = &mut *(ros_message as *mut StdMsgsString);
    let bytes = read_cdr_string(&mut cursor).map_err(map_deserialize_error)?;
    assign_ros_string(&mut msg.data, &bytes)?;
    Ok(())
}

unsafe fn encode_log_message(ros_message: *const c_void) -> Result<BytePayload, ApiError> {
    let msg = &*(ros_message as *const RclLog);
    let mut writer = CdrWriter::new();
    write_time(&mut writer, &msg.stamp).map_err(map_serialize_error)?;
    writer.write_u8(msg.level);
    write_cdr_string(&mut writer, read_ros_string(&msg.name)?).map_err(map_serialize_error)?;
    write_cdr_string(&mut writer, read_ros_string(&msg.msg)?).map_err(map_serialize_error)?;
    write_cdr_string(&mut writer, read_ros_string(&msg.file)?).map_err(map_serialize_error)?;
    write_cdr_string(&mut writer, read_ros_string(&msg.function)?).map_err(map_serialize_error)?;
    writer.align(4);
    writer.write_u32(msg.line);
    Ok(writer.into_payload())
}

unsafe fn decode_log_message(data: &[u8], ros_message: *mut c_void) -> Result<(), ApiError> {
    let mut cursor = CdrCursor::new(data);
    let msg = &mut *(ros_message as *mut RclLog);
    read_time(&mut cursor, &mut msg.stamp).map_err(map_deserialize_error)?;
    msg.level = cursor.read_u8().map_err(map_deserialize_error)?;
    let name_bytes = read_cdr_string(&mut cursor).map_err(map_deserialize_error)?;
    assign_ros_string(&mut msg.name, &name_bytes)?;
    let msg_bytes = read_cdr_string(&mut cursor).map_err(map_deserialize_error)?;
    assign_ros_string(&mut msg.msg, &msg_bytes)?;
    let file_bytes = read_cdr_string(&mut cursor).map_err(map_deserialize_error)?;
    assign_ros_string(&mut msg.file, &file_bytes)?;
    let function_bytes = read_cdr_string(&mut cursor).map_err(map_deserialize_error)?;
    assign_ros_string(&mut msg.function, &function_bytes)?;
    cursor.align(4).map_err(map_deserialize_error)?;
    msg.line = cursor.read_u32().map_err(map_deserialize_error)?;
    Ok(())
}

unsafe fn encode_parameter_event(ros_message: *const c_void) -> Result<BytePayload, ApiError> {
    let event = &*(ros_message as *const ParameterEvent);
    let mut writer = CdrWriter::new();
    write_time(&mut writer, &event.stamp).map_err(map_serialize_error)?;
    write_cdr_string(&mut writer, read_ros_string(&event.node)?).map_err(map_serialize_error)?;
    write_parameter_sequence(&mut writer, &event.new_parameters).map_err(map_serialize_error)?;
    write_parameter_sequence(&mut writer, &event.changed_parameters)
        .map_err(map_serialize_error)?;
    write_parameter_sequence(&mut writer, &event.deleted_parameters)
        .map_err(map_serialize_error)?;
    Ok(writer.into_payload())
}

unsafe fn decode_parameter_event(data: &[u8], ros_message: *mut c_void) -> Result<(), ApiError> {
    let mut cursor = CdrCursor::new(data);
    let event = &mut *(ros_message as *mut ParameterEvent);
    read_time(&mut cursor, &mut event.stamp).map_err(map_deserialize_error)?;
    let node_bytes = read_cdr_string(&mut cursor).map_err(map_deserialize_error)?;
    assign_ros_string(&mut event.node, &node_bytes)?;
    read_parameter_sequence(&mut cursor, &mut event.new_parameters)?;
    read_parameter_sequence(&mut cursor, &mut event.changed_parameters)?;
    read_parameter_sequence(&mut cursor, &mut event.deleted_parameters)?;
    Ok(())
}

unsafe fn write_parameter_sequence(
    writer: &mut CdrWriter,
    seq: &ParameterSequence,
) -> Result<(), SerializeError> {
    writer.align(4);
    let len = seq.size;
    let len_u32 = u32::try_from(len).map_err(|_| SerializeError::BufferOverflow)?;
    writer.write_u32(len_u32);
    if len == 0 {
        return Ok(());
    }
    let params = slice::from_raw_parts(seq.data, len);
    for param in params {
        let name_bytes = read_ros_string(&param.name)
            .map_err(|_| SerializeError::UnsupportedType("invalid parameter name"))?;
        write_cdr_string(writer, name_bytes)?;
        write_parameter_value(writer, &param.value)?;
    }
    Ok(())
}

unsafe fn read_parameter_sequence(
    cursor: &mut CdrCursor<'_>,
    seq: *mut ParameterSequence,
) -> Result<(), ApiError> {
    cursor.align(4).map_err(map_deserialize_error)?;
    let len = cursor.read_u32().map_err(map_deserialize_error)? as usize;
    rcl_interfaces__msg__Parameter__Sequence__fini(seq);
    if !rcl_interfaces__msg__Parameter__Sequence__init(seq, len) {
        return Err(ApiError::SerializationError);
    }
    if len == 0 {
        return Ok(());
    }

    let params = slice::from_raw_parts_mut((*seq).data, len);
    for param in params {
        let name = read_cdr_string(cursor).map_err(map_deserialize_error)?;
        assign_ros_string(&mut param.name, &name)?;
        read_parameter_value(cursor, &mut param.value)?;
    }

    Ok(())
}

unsafe fn write_parameter_value(
    writer: &mut CdrWriter,
    value: &ParameterValue,
) -> Result<(), SerializeError> {
    writer.write_u8(value.type_);
    writer.write_u8(u8::from(value.bool_value));
    writer.align(8);
    writer.write_i64(value.integer_value);
    writer.align(8);
    writer.write_f64(value.double_value);
    let string_bytes = read_ros_string(&value.string_value)
        .map_err(|_| SerializeError::UnsupportedType("invalid parameter string"))?;
    write_cdr_string(writer, string_bytes)?;
    write_octet_sequence(writer, &value.byte_array_value)?;
    write_bool_sequence(writer, &value.bool_array_value)?;
    write_int64_sequence(writer, &value.integer_array_value)?;
    write_double_sequence(writer, &value.double_array_value)?;
    write_string_sequence(writer, &value.string_array_value)?;
    Ok(())
}

unsafe fn read_parameter_value(
    cursor: &mut CdrCursor<'_>,
    value: &mut ParameterValue,
) -> Result<(), ApiError> {
    value.type_ = cursor.read_u8().map_err(map_deserialize_error)?;
    value.bool_value = cursor.read_u8().map_err(map_deserialize_error)? != 0;
    cursor.align(8).map_err(map_deserialize_error)?;
    value.integer_value = cursor.read_i64().map_err(map_deserialize_error)?;
    cursor.align(8).map_err(map_deserialize_error)?;
    value.double_value = cursor.read_f64().map_err(map_deserialize_error)?;
    let string_bytes = read_cdr_string(cursor).map_err(map_deserialize_error)?;
    assign_ros_string(&mut value.string_value, &string_bytes)?;
    read_octet_sequence(cursor, &mut value.byte_array_value)?;
    read_bool_sequence(cursor, &mut value.bool_array_value)?;
    read_int64_sequence(cursor, &mut value.integer_array_value)?;
    read_double_sequence(cursor, &mut value.double_array_value)?;
    read_string_sequence(cursor, &mut value.string_array_value)?;
    Ok(())
}

fn write_cdr_string(writer: &mut CdrWriter, data: &[u8]) -> Result<(), SerializeError> {
    writer.align(4);
    let total = data
        .len()
        .checked_add(1)
        .ok_or(SerializeError::BufferOverflow)?;
    let len = u32::try_from(total).map_err(|_| SerializeError::BufferOverflow)?;
    writer.write_u32(len);
    writer.write_bytes(data);
    writer.write_u8(0);
    Ok(())
}

fn write_time(writer: &mut CdrWriter, stamp: &BuiltinTime) -> Result<(), SerializeError> {
    writer.align(4);
    writer.write_i32(stamp.sec);
    writer.write_u32(stamp.nanosec);
    Ok(())
}

fn read_time(cursor: &mut CdrCursor<'_>, stamp: &mut BuiltinTime) -> Result<(), DeserializeError> {
    cursor.align(4)?;
    stamp.sec = cursor.read_i32()?;
    stamp.nanosec = cursor.read_u32()?;
    Ok(())
}

unsafe fn read_ros_string(string: &RosString) -> Result<&[u8], ApiError> {
    if string.size == 0 || string.data.is_null() {
        return Ok(&[]);
    }
    let slice = slice::from_raw_parts(string.data as *const u8, string.size);
    Ok(slice)
}

unsafe fn assign_ros_string(string: *mut RosString, data: &[u8]) -> Result<(), ApiError> {
    if !rosidl_runtime_c__String__assignn(string, data.as_ptr() as *const c_char, data.len()) {
        return Err(ApiError::SerializationError);
    }
    Ok(())
}

fn read_cdr_string(cursor: &mut CdrCursor<'_>) -> Result<Vec<u8>, DeserializeError> {
    cursor.align(4)?;
    let total = cursor.read_u32()? as usize;
    if total == 0 {
        return Ok(Vec::new());
    }
    let len = total
        .checked_sub(1)
        .ok_or(DeserializeError::BufferUnderflow)?;
    let bytes = cursor.read_bytes(len)?;
    let terminator = cursor.read_u8()?;
    if terminator != 0 {
        return Err(DeserializeError::UnsupportedType(
            "string missing null terminator",
        ));
    }
    Ok(bytes.to_vec())
}

unsafe fn write_octet_sequence(
    writer: &mut CdrWriter,
    seq: &RosOctetSequence,
) -> Result<(), SerializeError> {
    writer.align(4);
    let len = seq.size;
    let len_u32 = u32::try_from(len).map_err(|_| SerializeError::BufferOverflow)?;
    writer.write_u32(len_u32);
    if len == 0 {
        return Ok(());
    }
    let data = slice::from_raw_parts(seq.data, len);
    writer.write_bytes(data);
    Ok(())
}

unsafe fn read_octet_sequence(
    cursor: &mut CdrCursor<'_>,
    seq: *mut RosOctetSequence,
) -> Result<(), ApiError> {
    cursor.align(4).map_err(map_deserialize_error)?;
    let len = cursor.read_u32().map_err(map_deserialize_error)? as usize;
    rosidl_runtime_c__octet__Sequence__fini(seq);
    if !rosidl_runtime_c__octet__Sequence__init(seq, len) {
        return Err(ApiError::SerializationError);
    }
    if len > 0 {
        let bytes = cursor.read_bytes(len).map_err(map_deserialize_error)?;
        ptr::copy_nonoverlapping(bytes.as_ptr(), (*seq).data, len);
    }
    Ok(())
}

unsafe fn write_bool_sequence(
    writer: &mut CdrWriter,
    seq: &RosBoolSequence,
) -> Result<(), SerializeError> {
    writer.align(4);
    let len = seq.size;
    let len_u32 = u32::try_from(len).map_err(|_| SerializeError::BufferOverflow)?;
    writer.write_u32(len_u32);
    if len == 0 {
        return Ok(());
    }
    let data = slice::from_raw_parts(seq.data, len);
    for value in data {
        writer.write_u8(u8::from(*value));
    }
    Ok(())
}

unsafe fn read_bool_sequence(
    cursor: &mut CdrCursor<'_>,
    seq: *mut RosBoolSequence,
) -> Result<(), ApiError> {
    cursor.align(4).map_err(map_deserialize_error)?;
    let len = cursor.read_u32().map_err(map_deserialize_error)? as usize;
    rosidl_runtime_c__boolean__Sequence__fini(seq);
    if !rosidl_runtime_c__boolean__Sequence__init(seq, len) {
        return Err(ApiError::SerializationError);
    }
    if len > 0 {
        let bytes = cursor.read_bytes(len).map_err(map_deserialize_error)?;
        let dest = slice::from_raw_parts_mut((*seq).data, len);
        for (dst, value) in dest.iter_mut().zip(bytes.iter()) {
            *dst = *value != 0;
        }
    }
    Ok(())
}

unsafe fn write_int64_sequence(
    writer: &mut CdrWriter,
    seq: &RosInt64Sequence,
) -> Result<(), SerializeError> {
    writer.align(4);
    let len = seq.size;
    let len_u32 = u32::try_from(len).map_err(|_| SerializeError::BufferOverflow)?;
    writer.write_u32(len_u32);
    if len == 0 {
        return Ok(());
    }
    writer.align(8);
    let data = slice::from_raw_parts(seq.data, len);
    for value in data {
        writer.write_i64(*value);
    }
    Ok(())
}

unsafe fn read_int64_sequence(
    cursor: &mut CdrCursor<'_>,
    seq: *mut RosInt64Sequence,
) -> Result<(), ApiError> {
    cursor.align(4).map_err(map_deserialize_error)?;
    let len = cursor.read_u32().map_err(map_deserialize_error)? as usize;
    rosidl_runtime_c__int64__Sequence__fini(seq);
    if !rosidl_runtime_c__int64__Sequence__init(seq, len) {
        return Err(ApiError::SerializationError);
    }
    if len > 0 {
        cursor.align(8).map_err(map_deserialize_error)?;
        let dest = slice::from_raw_parts_mut((*seq).data, len);
        for value in dest.iter_mut() {
            *value = cursor.read_i64().map_err(map_deserialize_error)?;
        }
    }
    Ok(())
}

unsafe fn write_double_sequence(
    writer: &mut CdrWriter,
    seq: &RosDoubleSequence,
) -> Result<(), SerializeError> {
    writer.align(4);
    let len = seq.size;
    let len_u32 = u32::try_from(len).map_err(|_| SerializeError::BufferOverflow)?;
    writer.write_u32(len_u32);
    if len == 0 {
        return Ok(());
    }
    writer.align(8);
    let data = slice::from_raw_parts(seq.data, len);
    for value in data {
        writer.write_f64(*value);
    }
    Ok(())
}

unsafe fn read_double_sequence(
    cursor: &mut CdrCursor<'_>,
    seq: *mut RosDoubleSequence,
) -> Result<(), ApiError> {
    cursor.align(4).map_err(map_deserialize_error)?;
    let len = cursor.read_u32().map_err(map_deserialize_error)? as usize;
    rosidl_runtime_c__double__Sequence__fini(seq);
    if !rosidl_runtime_c__double__Sequence__init(seq, len) {
        return Err(ApiError::SerializationError);
    }
    if len > 0 {
        cursor.align(8).map_err(map_deserialize_error)?;
        let dest = slice::from_raw_parts_mut((*seq).data, len);
        for value in dest.iter_mut() {
            *value = cursor.read_f64().map_err(map_deserialize_error)?;
        }
    }
    Ok(())
}

unsafe fn write_string_sequence(
    writer: &mut CdrWriter,
    seq: &RosStringSequence,
) -> Result<(), SerializeError> {
    writer.align(4);
    let len = seq.size;
    let len_u32 = u32::try_from(len).map_err(|_| SerializeError::BufferOverflow)?;
    writer.write_u32(len_u32);
    if len == 0 {
        return Ok(());
    }
    let data = slice::from_raw_parts(seq.data, len);
    for string in data {
        let bytes = read_ros_string(string)
            .map_err(|_| SerializeError::UnsupportedType("invalid string sequence entry"))?;
        write_cdr_string(writer, bytes)?;
    }
    Ok(())
}

unsafe fn read_string_sequence(
    cursor: &mut CdrCursor<'_>,
    seq: *mut RosStringSequence,
) -> Result<(), ApiError> {
    cursor.align(4).map_err(map_deserialize_error)?;
    let len = cursor.read_u32().map_err(map_deserialize_error)? as usize;
    rosidl_runtime_c__String__Sequence__fini(seq);
    if !rosidl_runtime_c__String__Sequence__init(seq, len) {
        return Err(ApiError::SerializationError);
    }
    if len > 0 {
        let entries = slice::from_raw_parts_mut((*seq).data, len);
        for entry in entries.iter_mut() {
            let bytes = read_cdr_string(cursor).map_err(map_deserialize_error)?;
            if !rosidl_runtime_c__String__assignn(
                entry,
                bytes.as_ptr() as *const c_char,
                bytes.len(),
            ) {
                return Err(ApiError::SerializationError);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod stubs {
    use super::*;
    use hdds::xtypes::builder::rosidl_message_type_support_t;
    use libc::{calloc, free, malloc, realloc};
    use std::mem::size_of;
    use std::ptr;

    unsafe fn allocate_zeroed<T>(count: usize) -> *mut T {
        if count == 0 {
            return ptr::null_mut();
        }
        let ptr = calloc(count, size_of::<T>());
        ptr.cast::<T>()
    }

    #[no_mangle]
    pub unsafe extern "C" fn rosidl_runtime_c__String__assignn(
        str_: *mut RosString,
        value: *const c_char,
        size: usize,
    ) -> bool {
        if str_.is_null() {
            return false;
        }

        let required = match size.checked_add(1) {
            Some(len) => len,
            None => return false,
        };

        let new_ptr = if (*str_).data.is_null() {
            malloc(required)
        } else {
            realloc((*str_).data.cast(), required)
        };

        if new_ptr.is_null() {
            return false;
        }

        if !value.is_null() && size > 0 {
            ptr::copy_nonoverlapping(value as *const u8, new_ptr as *mut u8, size);
        }
        *(new_ptr as *mut u8).add(size) = 0;
        (*str_).data = new_ptr.cast::<c_char>();
        (*str_).size = size;
        (*str_).capacity = required;
        true
    }

    #[no_mangle]
    pub unsafe extern "C" fn rosidl_runtime_c__String__Sequence__init(
        seq: *mut RosStringSequence,
        size: usize,
    ) -> bool {
        if seq.is_null() {
            return false;
        }

        let ptr = allocate_zeroed::<RosString>(size);
        if size > 0 && ptr.is_null() {
            return false;
        }

        (*seq).data = ptr;
        (*seq).size = size;
        (*seq).capacity = size;
        true
    }

    #[no_mangle]
    pub unsafe extern "C" fn rosidl_runtime_c__String__Sequence__fini(seq: *mut RosStringSequence) {
        if seq.is_null() {
            return;
        }
        if !(*seq).data.is_null() {
            for index in 0..(*seq).size {
                let item = (*seq).data.add(index);
                if !(*item).data.is_null() {
                    free((*item).data.cast());
                }
                (*item).data = ptr::null_mut();
                (*item).size = 0;
                (*item).capacity = 0;
            }
            free((*seq).data.cast());
        }
        (*seq).data = ptr::null_mut();
        (*seq).size = 0;
        (*seq).capacity = 0;
    }

    #[no_mangle]
    pub unsafe extern "C" fn rosidl_runtime_c__octet__Sequence__init(
        seq: *mut RosOctetSequence,
        size: usize,
    ) -> bool {
        if seq.is_null() {
            return false;
        }
        let ptr = allocate_zeroed::<u8>(size);
        if size > 0 && ptr.is_null() {
            return false;
        }
        (*seq).data = ptr;
        (*seq).size = size;
        (*seq).capacity = size;
        true
    }

    #[no_mangle]
    pub unsafe extern "C" fn rosidl_runtime_c__octet__Sequence__fini(seq: *mut RosOctetSequence) {
        if seq.is_null() {
            return;
        }
        if !(*seq).data.is_null() {
            free((*seq).data.cast());
        }
        (*seq).data = ptr::null_mut();
        (*seq).size = 0;
        (*seq).capacity = 0;
    }

    #[no_mangle]
    pub unsafe extern "C" fn rosidl_runtime_c__boolean__Sequence__init(
        seq: *mut RosBoolSequence,
        size: usize,
    ) -> bool {
        if seq.is_null() {
            return false;
        }
        let ptr = allocate_zeroed::<bool>(size);
        if size > 0 && ptr.is_null() {
            return false;
        }
        (*seq).data = ptr;
        (*seq).size = size;
        (*seq).capacity = size;
        true
    }

    #[no_mangle]
    pub unsafe extern "C" fn rosidl_runtime_c__boolean__Sequence__fini(seq: *mut RosBoolSequence) {
        if seq.is_null() {
            return;
        }
        if !(*seq).data.is_null() {
            free((*seq).data.cast());
        }
        (*seq).data = ptr::null_mut();
        (*seq).size = 0;
        (*seq).capacity = 0;
    }

    #[no_mangle]
    pub unsafe extern "C" fn rosidl_runtime_c__int64__Sequence__init(
        seq: *mut RosInt64Sequence,
        size: usize,
    ) -> bool {
        if seq.is_null() {
            return false;
        }
        let ptr = allocate_zeroed::<i64>(size);
        if size > 0 && ptr.is_null() {
            return false;
        }
        (*seq).data = ptr;
        (*seq).size = size;
        (*seq).capacity = size;
        true
    }

    #[no_mangle]
    pub unsafe extern "C" fn rosidl_runtime_c__int64__Sequence__fini(seq: *mut RosInt64Sequence) {
        if seq.is_null() {
            return;
        }
        if !(*seq).data.is_null() {
            free((*seq).data.cast());
        }
        (*seq).data = ptr::null_mut();
        (*seq).size = 0;
        (*seq).capacity = 0;
    }

    #[no_mangle]
    pub unsafe extern "C" fn rosidl_runtime_c__double__Sequence__init(
        seq: *mut RosDoubleSequence,
        size: usize,
    ) -> bool {
        if seq.is_null() {
            return false;
        }
        let ptr = allocate_zeroed::<f64>(size);
        if size > 0 && ptr.is_null() {
            return false;
        }
        (*seq).data = ptr;
        (*seq).size = size;
        (*seq).capacity = size;
        true
    }

    #[no_mangle]
    pub unsafe extern "C" fn rosidl_runtime_c__double__Sequence__fini(seq: *mut RosDoubleSequence) {
        if seq.is_null() {
            return;
        }
        if !(*seq).data.is_null() {
            free((*seq).data.cast());
        }
        (*seq).data = ptr::null_mut();
        (*seq).size = 0;
        (*seq).capacity = 0;
    }

    #[no_mangle]
    pub unsafe extern "C" fn rcl_interfaces__msg__Parameter__Sequence__init(
        seq: *mut ParameterSequence,
        size: usize,
    ) -> bool {
        if seq.is_null() {
            return false;
        }

        let ptr = allocate_zeroed::<Parameter>(size);
        if size > 0 && ptr.is_null() {
            return false;
        }
        (*seq).data = ptr;
        (*seq).size = size;
        (*seq).capacity = size;
        true
    }

    #[no_mangle]
    pub unsafe extern "C" fn rcl_interfaces__msg__Parameter__Sequence__fini(
        seq: *mut ParameterSequence,
    ) {
        if seq.is_null() {
            return;
        }
        if !(*seq).data.is_null() {
            for index in 0..(*seq).size {
                let parameter = (*seq).data.add(index);
                if !(*parameter).name.data.is_null() {
                    free((*parameter).name.data.cast());
                }
                rosidl_runtime_c__String__Sequence__fini(
                    &mut (*parameter).value.string_array_value,
                );
                rosidl_runtime_c__octet__Sequence__fini(&mut (*parameter).value.byte_array_value);
                rosidl_runtime_c__boolean__Sequence__fini(&mut (*parameter).value.bool_array_value);
                rosidl_runtime_c__int64__Sequence__fini(
                    &mut (*parameter).value.integer_array_value,
                );
                rosidl_runtime_c__double__Sequence__fini(
                    &mut (*parameter).value.double_array_value,
                );
                if !(*parameter).value.string_value.data.is_null() {
                    free((*parameter).value.string_value.data.cast());
                }
            }
            free((*seq).data.cast());
        }
        (*seq).data = ptr::null_mut();
        (*seq).size = 0;
        (*seq).capacity = 0;
    }

    #[no_mangle]
    pub unsafe extern "C" fn rcl_interfaces__msg__Log__init(log: *mut RclLog) -> bool {
        if log.is_null() {
            return false;
        }
        (*log).stamp = BuiltinTime { sec: 0, nanosec: 0 };
        (*log).level = 0;
        (*log).line = 0;
        (*log).name = RosString::default();
        (*log).msg = RosString::default();
        (*log).file = RosString::default();
        (*log).function = RosString::default();
        true
    }

    #[no_mangle]
    pub unsafe extern "C" fn rcl_interfaces__msg__Log__fini(log: *mut RclLog) {
        if log.is_null() {
            return;
        }
        if !(*log).name.data.is_null() {
            free((*log).name.data.cast());
        }
        if !(*log).msg.data.is_null() {
            free((*log).msg.data.cast());
        }
        if !(*log).file.data.is_null() {
            free((*log).file.data.cast());
        }
        if !(*log).function.data.is_null() {
            free((*log).function.data.cast());
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn rcl_interfaces__msg__ParameterEvent__init(
        event: *mut ParameterEvent,
    ) -> bool {
        if event.is_null() {
            return false;
        }
        (*event).stamp = BuiltinTime { sec: 0, nanosec: 0 };
        (*event).node = RosString::default();
        (*event).new_parameters = ParameterSequence {
            data: ptr::null_mut(),
            size: 0,
            capacity: 0,
        };
        (*event).changed_parameters = ParameterSequence {
            data: ptr::null_mut(),
            size: 0,
            capacity: 0,
        };
        (*event).deleted_parameters = ParameterSequence {
            data: ptr::null_mut(),
            size: 0,
            capacity: 0,
        };
        true
    }

    #[no_mangle]
    pub unsafe extern "C" fn rcl_interfaces__msg__ParameterEvent__fini(event: *mut ParameterEvent) {
        if event.is_null() {
            return;
        }
        if !(*event).node.data.is_null() {
            free((*event).node.data.cast());
        }
        rcl_interfaces__msg__Parameter__Sequence__fini(&mut (*event).new_parameters);
        rcl_interfaces__msg__Parameter__Sequence__fini(&mut (*event).changed_parameters);
        rcl_interfaces__msg__Parameter__Sequence__fini(&mut (*event).deleted_parameters);
    }

    #[no_mangle]
    pub unsafe extern "C" fn std_msgs__msg__String__init(msg: *mut StdMsgsString) -> bool {
        if msg.is_null() {
            return false;
        }
        (*msg).data = RosString::default();
        true
    }

    #[no_mangle]
    pub unsafe extern "C" fn std_msgs__msg__String__fini(msg: *mut StdMsgsString) {
        if msg.is_null() {
            return;
        }
        if !(*msg).data.data.is_null() {
            free((*msg).data.data.cast());
        }
        (*msg).data.data = ptr::null_mut();
        (*msg).data.size = 0;
        (*msg).data.capacity = 0;
    }

    #[no_mangle]
    pub unsafe extern "C" fn rosidl_typesupport_introspection_c__get_message_type_support_handle__std_msgs__msg__String(
    ) -> *const rosidl_message_type_support_t {
        ptr::null()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ros_string(bytes: &'static [u8]) -> RosString {
        RosString {
            data: bytes.as_ptr() as *mut c_char,
            size: bytes.len(),
            capacity: bytes.len(),
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The body Eclipse Cyclone DDS 0.11.0 serializes for
    /// `rcl_interfaces/msg/ParameterEvent` (the ROS 2 IDL, every struct
    /// `@final`) with stamp {1, 2}, node "n", one new parameter "p" whose
    /// value is {type 2, false, -3, 0.5, "", integer_array_value [7]} and
    /// no changed or deleted parameter, with `dds_stream_write_sample` at
    /// encoding version 1 (identifier `{0x00, 0x01}`) and version 2
    /// (`{0x00, 0x07}`) (captured with a probe program built against
    /// Cyclone DDS). Cyclone's output, verbatim:
    ///
    /// ```text
    /// xcdr2 encap=0700 body=0100000002000000020000006e00000044000000010000000200000070000200fdffffffffffffff000000000000e03f0100000000000000000000000000000001000000070000000000000000000000040000000000000004000000000000000400000000000000
    /// xcdr1 encap=0100 body=0100000002000000020000006e00000001000000020000007000020000000000fdffffffffffffff000000000000e03f010000000000000000000000000000000100000000000000070000000000000000000000000000000000000000000000
    /// ```
    ///
    /// The rmw codec writes the version-1 body byte for byte: classic CDR,
    /// whose identifier is `CDR_LE`.
    const CYCLONE_PARAMETER_EVENT_XCDR1: &str = "0100000002000000020000006e000000010000000200000070000200000000\
        00fdffffffffffffff000000000000e03f0100000000000000000000000000000001000000000000000700000000000000\
        00000000000000000000000000000000";
    const CYCLONE_PARAMETER_EVENT_XCDR2: &str = "0100000002000000020000006e00000044000000010000000200000070000200\
        fdffffffffffffff000000000000e03f010000000000000000000000000000000100000007000000000000000000000004\
        0000000000000004000000000000000400000000000000";

    #[test]
    fn the_parameter_event_codec_writes_cyclones_xcdr1_body() {
        let mut ints = [7i64];
        let mut parameter = Parameter {
            name: ros_string(b"p"),
            value: ParameterValue {
                type_: 2,
                bool_value: false,
                integer_value: -3,
                double_value: 0.5,
                string_value: RosString::default(),
                byte_array_value: RosOctetSequence {
                    data: ptr::null_mut(),
                    size: 0,
                    capacity: 0,
                },
                bool_array_value: RosBoolSequence {
                    data: ptr::null_mut(),
                    size: 0,
                    capacity: 0,
                },
                integer_array_value: RosInt64Sequence {
                    data: ints.as_mut_ptr(),
                    size: 1,
                    capacity: 1,
                },
                double_array_value: RosDoubleSequence {
                    data: ptr::null_mut(),
                    size: 0,
                    capacity: 0,
                },
                string_array_value: RosStringSequence {
                    data: ptr::null_mut(),
                    size: 0,
                    capacity: 0,
                },
            },
        };
        let empty = || ParameterSequence {
            data: ptr::null_mut(),
            size: 0,
            capacity: 0,
        };
        let event = ParameterEvent {
            stamp: BuiltinTime { sec: 1, nanosec: 2 },
            node: ros_string(b"n"),
            new_parameters: ParameterSequence {
                data: &mut parameter,
                size: 1,
                capacity: 1,
            },
            changed_parameters: empty(),
            deleted_parameters: empty(),
        };

        let payload = unsafe {
            encode(
                Ros2CodecKind::ParameterEvent,
                (&event as *const ParameterEvent).cast(),
            )
        }
        .unwrap()
        .unwrap();
        assert_eq!(payload.as_slice(), &hex(CYCLONE_PARAMETER_EVENT_XCDR1)[..]);
        assert_ne!(payload.as_slice(), &hex(CYCLONE_PARAMETER_EVENT_XCDR2)[..]);
    }
}
