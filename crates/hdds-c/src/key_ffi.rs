// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Per-sample identity for opaque serialized writers.

use super::*;

/// Identity supplied by the typed codec, copied during each call.
/// `hash` is the RTPS 2.5 9.6.4.8 KeyHash; `protected_hash` is the MD5
/// of CDR big-endian key fields, with natural alignment, regardless of
/// maximum key size (DDS-Security 1.1 7.3.4).
/// `payload` contains only serialized key fields, without encapsulation,
/// with the type's extensibility framing, in little endian. Its encoding
/// (`representation`: 0 = XCDR1, 2 = XCDR2) must match the writer's.
/// The hashes and payload must describe the same instance as `data`.
#[repr(C)]
pub struct HddsSerializedKey {
    pub hash: [u8; 16],
    pub protected_hash: [u8; 16],
    pub payload: *const u8,
    pub payload_len: usize,
    pub representation: u16,
}

#[derive(Clone)]
pub(crate) struct SerializedKey {
    pub hash: [u8; 16],
    pub protected_hash: [u8; 16],
    pub payload: Vec<u8>,
}

unsafe fn keyed_operation(
    writer: *mut HddsDataWriter,
    data: *const c_void,
    len: usize,
    key: *const HddsSerializedKey,
    operation: impl FnOnce(&DataWriter<BytePayload>, &BytePayload) -> hdds::api::Result<()>,
) -> HddsError {
    if writer.is_null()
        || key.is_null()
        || (data.is_null() && len != 0)
        || len > isize::MAX as usize
    {
        return HddsError::HddsInvalidArgument;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let key = &*key;
        if (key.payload.is_null() && key.payload_len != 0) || key.payload_len > isize::MAX as usize
        {
            return HddsError::HddsInvalidArgument;
        }
        let version = match key.representation {
            0 => hdds::CdrVersion::Xcdr1,
            2 => hdds::CdrVersion::Xcdr2,
            _ => return HddsError::HddsInvalidArgument,
        };
        let writer = &*writer.cast::<DataWriter<BytePayload>>();
        if !writer.accepts_serialized_keys() || writer.effective_cdr_version() != version {
            return HddsError::HddsInvalidArgument;
        }
        let mut payload = BytePayload::to_write(if len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(data.cast::<u8>(), len).to_vec()
        });
        payload.key = Some(SerializedKey {
            hash: key.hash,
            protected_hash: key.protected_hash,
            payload: if key.payload_len == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(key.payload, key.payload_len).to_vec()
            },
        });
        match operation(writer, &payload) {
            Ok(()) => HddsError::HddsOk,
            Err(_) => HddsError::HddsOperationFailed,
        }
    }))
    .unwrap_or(HddsError::HddsOperationFailed)
}

/// Write with serialized instance identity.
/// See [`HddsSerializedKey`] for the codec contract.
///
/// # Safety
/// `writer` must be live and exclusively used for writer operations during
/// this call. `data` and `key.payload` must be readable for their lengths
/// (NULL is allowed only for zero length). `key` must be readable and aligned.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_write_keyed(
    writer: *mut HddsDataWriter,
    data: *const c_void,
    len: usize,
    key: *const HddsSerializedKey,
) -> HddsError {
    keyed_operation(writer, data, len, key, |writer, payload| {
        writer.write(payload)
    })
}

/// Write with serialized instance identity.
/// See [`HddsSerializedKey`] for the codec contract.
///
/// # Safety
/// `writer` must be live and exclusively used for writer operations during
/// this call. `data` and `key.payload` must be readable for their lengths
/// (NULL is allowed only for zero length). `key` must be readable and aligned.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_write_w_timestamp_keyed(
    writer: *mut HddsDataWriter,
    data: *const c_void,
    len: usize,
    key: *const HddsSerializedKey,
    source_timestamp_ns: u64,
) -> HddsError {
    keyed_operation(writer, data, len, key, |writer, payload| {
        writer.write_w_timestamp(payload, source_timestamp_ns)
    })
}

/// Dispose with serialized instance identity.
/// See [`HddsSerializedKey`] for the codec contract.
///
/// # Safety
/// `writer` must be live and exclusively used for writer operations during
/// this call. `data` and `key.payload` must be readable for their lengths
/// (NULL is allowed only for zero length). `key` must be readable and aligned.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_dispose_keyed(
    writer: *mut HddsDataWriter,
    data: *const c_void,
    len: usize,
    key: *const HddsSerializedKey,
) -> HddsError {
    keyed_operation(writer, data, len, key, |writer, payload| {
        writer.dispose(payload)
    })
}

/// Dispose with serialized instance identity.
/// See [`HddsSerializedKey`] for the codec contract.
///
/// # Safety
/// `writer` must be live and exclusively used for writer operations during
/// this call. `data` and `key.payload` must be readable for their lengths
/// (NULL is allowed only for zero length). `key` must be readable and aligned.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_dispose_w_timestamp_keyed(
    writer: *mut HddsDataWriter,
    data: *const c_void,
    len: usize,
    key: *const HddsSerializedKey,
    source_timestamp_ns: u64,
) -> HddsError {
    keyed_operation(writer, data, len, key, |writer, payload| {
        writer.dispose_w_timestamp(payload, source_timestamp_ns)
    })
}

/// Unregister instance with serialized instance identity.
/// See [`HddsSerializedKey`] for the codec contract.
///
/// # Safety
/// `writer` must be live and exclusively used for writer operations during
/// this call. `data` and `key.payload` must be readable for their lengths
/// (NULL is allowed only for zero length). `key` must be readable and aligned.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_unregister_instance_keyed(
    writer: *mut HddsDataWriter,
    data: *const c_void,
    len: usize,
    key: *const HddsSerializedKey,
) -> HddsError {
    keyed_operation(writer, data, len, key, |writer, payload| {
        writer.unregister_instance(payload)
    })
}

/// Unregister instance with serialized instance identity.
/// See [`HddsSerializedKey`] for the codec contract.
///
/// # Safety
/// `writer` must be live and exclusively used for writer operations during
/// this call. `data` and `key.payload` must be readable for their lengths
/// (NULL is allowed only for zero length). `key` must be readable and aligned.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_unregister_instance_w_timestamp_keyed(
    writer: *mut HddsDataWriter,
    data: *const c_void,
    len: usize,
    key: *const HddsSerializedKey,
    source_timestamp_ns: u64,
) -> HddsError {
    keyed_operation(writer, data, len, key, |writer, payload| {
        writer.unregister_instance_w_timestamp(payload, source_timestamp_ns)
    })
}

/// Register instance with serialized instance identity.
/// See [`HddsSerializedKey`] for the codec contract.
///
/// # Safety
/// `writer` must be live and exclusively used for writer operations during
/// this call. `data` and `key.payload` must be readable for their lengths
/// (NULL is allowed only for zero length). `key` must be readable and aligned.
/// `out_handle` must point to writable, aligned storage.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_register_instance_keyed(
    writer: *mut HddsDataWriter,
    data: *const c_void,
    len: usize,
    key: *const HddsSerializedKey,
    out_handle: *mut HddsInstanceHandle,
) -> HddsError {
    if out_handle.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    keyed_operation(writer, data, len, key, |writer, payload| {
        let handle = writer.register_instance(payload)?;
        out_handle.write(HddsInstanceHandle {
            value: *handle.as_bytes(),
        });
        Ok(())
    })
}

/// Register instance with serialized instance identity.
/// See [`HddsSerializedKey`] for the codec contract.
///
/// # Safety
/// `writer` must be live and exclusively used for writer operations during
/// this call. `data` and `key.payload` must be readable for their lengths
/// (NULL is allowed only for zero length). `key` must be readable and aligned.
/// `out_handle` must point to writable, aligned storage.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_register_instance_w_timestamp_keyed(
    writer: *mut HddsDataWriter,
    data: *const c_void,
    len: usize,
    key: *const HddsSerializedKey,
    source_timestamp_ns: u64,
    out_handle: *mut HddsInstanceHandle,
) -> HddsError {
    if out_handle.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    keyed_operation(writer, data, len, key, |writer, payload| {
        let handle = writer.register_instance_w_timestamp(payload, source_timestamp_ns)?;
        out_handle.write(HddsInstanceHandle {
            value: *handle.as_bytes(),
        });
        Ok(())
    })
}

/// Create a keyed serialized writer (RTPS 2.5 Table 9.1 WITH_KEY).
/// Use the keyed operations with a matching `HddsSerializedKey` on this writer.
/// The other constructors remain available for keyless byte topics.
///
/// # Safety
/// Same as [`hdds_writer_create_with_extensibility`].
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_create_keyed(
    participant: *mut HddsParticipant,
    topic_name: *const c_char,
    type_name: *const c_char,
    qos: *const HddsQoS,
    extensibility: u32,
) -> *mut HddsDataWriter {
    construct_keyed_writer(|| {
        if participant.is_null() || topic_name.is_null() {
            return ptr::null_mut();
        }
        let Some(extensibility) = extensibility_from_c(extensibility) else {
            log::error!("hdds_writer_create_keyed: unknown extensibility {extensibility}");
            return ptr::null_mut();
        };
        let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
            return ptr::null_mut();
        };
        let requested = match crate::requested_type_name(type_name) {
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
            Some(type_str) => participant_ref.create_serialized_key_writer::<BytePayload>(
                topic_str,
                sdk_writer_qos(qos_value),
                type_str,
                extensibility,
            ),
            None => participant_ref.create_adopting_writer::<BytePayload>(
                topic_str,
                sdk_writer_qos(qos_value),
                Some(extensibility),
                true,
            ),
        };
        match created {
            Ok(writer) => writer_into_handle(writer),
            Err(e) => {
                log::error!("Failed to create writer for topic '{topic_str}': {e}");
                ptr::null_mut()
            }
        }
    })
}

/// Create a keyed serialized writer from a Publisher.
/// See [`hdds_writer_create_keyed`] for the serialization contract.
///
/// # Safety
/// Same as [`hdds_publisher_create_writer_with_extensibility`].
/// A non-NULL `type_name` must point to a readable NUL-terminated string
/// for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn hdds_publisher_create_writer_keyed(
    publisher: *mut HddsPublisher,
    topic_name: *const c_char,
    type_name: *const c_char,
    qos: *const HddsQoS,
    extensibility: u32,
) -> *mut HddsDataWriter {
    construct_keyed_writer(|| {
        if publisher.is_null() || topic_name.is_null() {
            return ptr::null_mut();
        }
        let Some(extensibility) = crate::extensibility_from_c(extensibility) else {
            log::error!(
                "hdds_publisher_create_writer_keyed: unknown extensibility {extensibility}"
            );
            return ptr::null_mut();
        };
        let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
            return ptr::null_mut();
        };
        let requested = match crate::requested_type_name(type_name) {
            Ok(requested) => requested,
            Err(()) => return ptr::null_mut(),
        };
        let publisher_ref = &*publisher.cast::<hdds::dds::Publisher>();
        let qos_value = if qos.is_null() {
            QoS::default()
        } else {
            (*qos.cast::<QoS>()).clone()
        };
        let created = match requested {
            Some(type_str) => publisher_ref.create_serialized_key_writer::<BytePayload>(
                topic_str,
                crate::sdk_writer_qos(qos_value),
                type_str,
                extensibility,
            ),
            None => publisher_ref.create_adopting_writer::<BytePayload>(
                topic_str,
                crate::sdk_writer_qos(qos_value),
                extensibility,
                true,
            ),
        };
        match created {
            Ok(writer) => crate::writer_into_handle(writer),
            Err(e) => {
                log::error!("Failed to create writer from publisher: {e:?}");
                ptr::null_mut()
            }
        }
    })
}

fn construct_keyed_writer(operation: impl FnOnce() -> *mut HddsDataWriter) -> *mut HddsDataWriter {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)).unwrap_or(ptr::null_mut())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyed_constructor_contains_panics() {
        assert!(construct_keyed_writer(|| panic!("constructor failure")).is_null());
        let sentinel = std::ptr::NonNull::<HddsDataWriter>::dangling().as_ptr();
        assert_eq!(construct_keyed_writer(|| sentinel), sentinel);
    }
}
