// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Writer operations with explicit source timestamps and instance registration.
//!
//! Timestamps are nanoseconds since the Unix epoch, as in HddsSampleInfo.
//! Raw-byte writers are keyless: instance registration returns the nil handle.
//! Registration emits no sample; its timestamp is accepted for API symmetry.

use super::*;

fn contain_writer_panic(operation: impl FnOnce() -> HddsError) -> HddsError {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
        .unwrap_or(HddsError::HddsOperationFailed)
}

/// A DDS instance handle (RTPS key hash; zero for raw-byte keyless topics).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HddsInstanceHandle {
    pub value: [u8; 16],
}

/// Write w timestamp (DDS v1.4 Sec.2.2.2.4.2.12).
/// Timestamps, when supplied, are nanoseconds since the Unix epoch.
/// Registration emits no data and returns the nil handle for these keyless topics.
///
/// # Safety
/// `writer` must be a live HDDS writer; `data` must be readable for `len`
/// bytes. The writer must not be destroyed or used concurrently for writing,
/// lifecycle operations or registration during this call.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_write_w_timestamp(
    writer: *mut HddsDataWriter,
    data: *const c_void,
    len: usize,
    source_timestamp_ns: u64,
) -> HddsError {
    if writer.is_null() || data.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    contain_writer_panic(|| {
        let writer_ref = &*writer.cast::<DataWriter<BytePayload>>();
        if writer_ref.accepts_serialized_keys() {
            log::error!(
                "hdds_writer_write_w_timestamp on a keyed writer: use hdds_writer_write_w_timestamp_keyed"
            );
            return HddsError::HddsOperationFailed;
        }
        let payload =
            BytePayload::to_write(std::slice::from_raw_parts(data.cast::<u8>(), len).to_vec());
        match writer_ref.write_w_timestamp(&payload, source_timestamp_ns) {
            Ok(()) => HddsError::HddsOk,
            Err(_) => HddsError::HddsOperationFailed,
        }
    })
}

/// Dispose (DDS v1.4 Sec.2.2.2.4.2.11).
/// Timestamps, when supplied, are nanoseconds since the Unix epoch.
/// Registration emits no data and returns the nil handle for these keyless topics.
///
/// # Safety
/// `writer` must be a live HDDS writer; `data` must be readable for `len`
/// bytes. The writer must not be destroyed or used concurrently for writing,
/// lifecycle operations or registration during this call.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_dispose(
    writer: *mut HddsDataWriter,
    data: *const c_void,
    len: usize,
) -> HddsError {
    if writer.is_null() || data.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    contain_writer_panic(|| {
        let writer_ref = &*writer.cast::<DataWriter<BytePayload>>();
        let payload =
            BytePayload::to_write(std::slice::from_raw_parts(data.cast::<u8>(), len).to_vec());
        match writer_ref.dispose(&payload) {
            Ok(()) => HddsError::HddsOk,
            Err(_) => HddsError::HddsOperationFailed,
        }
    })
}

/// Dispose w timestamp (DDS v1.4 Sec.2.2.2.4.2.13).
/// Timestamps, when supplied, are nanoseconds since the Unix epoch.
/// Registration emits no data and returns the nil handle for these keyless topics.
///
/// # Safety
/// `writer` must be a live HDDS writer; `data` must be readable for `len`
/// bytes. The writer must not be destroyed or used concurrently for writing,
/// lifecycle operations or registration during this call.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_dispose_w_timestamp(
    writer: *mut HddsDataWriter,
    data: *const c_void,
    len: usize,
    source_timestamp_ns: u64,
) -> HddsError {
    if writer.is_null() || data.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    contain_writer_panic(|| {
        let writer_ref = &*writer.cast::<DataWriter<BytePayload>>();
        let payload =
            BytePayload::to_write(std::slice::from_raw_parts(data.cast::<u8>(), len).to_vec());
        match writer_ref.dispose_w_timestamp(&payload, source_timestamp_ns) {
            Ok(()) => HddsError::HddsOk,
            Err(_) => HddsError::HddsOperationFailed,
        }
    })
}

/// Unregister instance (DDS v1.4 Sec.2.2.2.4.2.7).
/// Timestamps, when supplied, are nanoseconds since the Unix epoch.
/// Registration emits no data and returns the nil handle for these keyless topics.
///
/// # Safety
/// `writer` must be a live HDDS writer; `data` must be readable for `len`
/// bytes. The writer must not be destroyed or used concurrently for writing,
/// lifecycle operations or registration during this call.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_unregister_instance(
    writer: *mut HddsDataWriter,
    data: *const c_void,
    len: usize,
) -> HddsError {
    if writer.is_null() || data.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    contain_writer_panic(|| {
        let writer_ref = &*writer.cast::<DataWriter<BytePayload>>();
        let payload =
            BytePayload::to_write(std::slice::from_raw_parts(data.cast::<u8>(), len).to_vec());
        match writer_ref.unregister_instance(&payload) {
            Ok(()) => HddsError::HddsOk,
            Err(_) => HddsError::HddsOperationFailed,
        }
    })
}

/// Unregister instance w timestamp (DDS v1.4 Sec.2.2.2.4.2.8).
/// Timestamps, when supplied, are nanoseconds since the Unix epoch.
/// Registration emits no data and returns the nil handle for these keyless topics.
///
/// # Safety
/// `writer` must be a live HDDS writer; `data` must be readable for `len`
/// bytes. The writer must not be destroyed or used concurrently for writing,
/// lifecycle operations or registration during this call.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_unregister_instance_w_timestamp(
    writer: *mut HddsDataWriter,
    data: *const c_void,
    len: usize,
    source_timestamp_ns: u64,
) -> HddsError {
    if writer.is_null() || data.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    contain_writer_panic(|| {
        let writer_ref = &*writer.cast::<DataWriter<BytePayload>>();
        let payload =
            BytePayload::to_write(std::slice::from_raw_parts(data.cast::<u8>(), len).to_vec());
        match writer_ref.unregister_instance_w_timestamp(&payload, source_timestamp_ns) {
            Ok(()) => HddsError::HddsOk,
            Err(_) => HddsError::HddsOperationFailed,
        }
    })
}

/// Register instance (DDS v1.4 Sec.2.2.2.4.2.5).
/// Timestamps, when supplied, are nanoseconds since the Unix epoch.
/// Registration emits no data and returns the nil handle for these keyless topics.
///
/// # Safety
/// `writer` must be a live HDDS writer; `data` must be readable for `len`
/// bytes. The writer must not be destroyed or used concurrently for writing,
/// lifecycle operations or registration during this call.
/// `out_handle` must point to writable, aligned storage.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_register_instance(
    writer: *mut HddsDataWriter,
    data: *const c_void,
    len: usize,
    out_handle: *mut HddsInstanceHandle,
) -> HddsError {
    if writer.is_null() || data.is_null() || out_handle.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    contain_writer_panic(|| {
        let writer_ref = &*writer.cast::<DataWriter<BytePayload>>();
        let payload =
            BytePayload::to_write(std::slice::from_raw_parts(data.cast::<u8>(), len).to_vec());
        match writer_ref.register_instance(&payload) {
            Ok(handle) => {
                out_handle.write(HddsInstanceHandle {
                    value: *handle.as_bytes(),
                });
                HddsError::HddsOk
            }
            Err(_) => HddsError::HddsOperationFailed,
        }
    })
}

/// Register instance w timestamp (DDS v1.4 Sec.2.2.2.4.2.6).
/// Timestamps, when supplied, are nanoseconds since the Unix epoch.
/// Registration emits no data and returns the nil handle for these keyless topics.
///
/// # Safety
/// `writer` must be a live HDDS writer; `data` must be readable for `len`
/// bytes. The writer must not be destroyed or used concurrently for writing,
/// lifecycle operations or registration during this call.
/// `out_handle` must point to writable, aligned storage.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_register_instance_w_timestamp(
    writer: *mut HddsDataWriter,
    data: *const c_void,
    len: usize,
    source_timestamp_ns: u64,
    out_handle: *mut HddsInstanceHandle,
) -> HddsError {
    if writer.is_null() || data.is_null() || out_handle.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    contain_writer_panic(|| {
        let writer_ref = &*writer.cast::<DataWriter<BytePayload>>();
        let payload =
            BytePayload::to_write(std::slice::from_raw_parts(data.cast::<u8>(), len).to_vec());
        match writer_ref.register_instance_w_timestamp(&payload, source_timestamp_ns) {
            Ok(handle) => {
                out_handle.write(HddsInstanceHandle {
                    value: *handle.as_bytes(),
                });
                HddsError::HddsOk
            }
            Err(_) => HddsError::HddsOperationFailed,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_panic_is_contained() {
        assert_eq!(
            contain_writer_panic(|| panic!("writer operation panicked")),
            HddsError::HddsOperationFailed
        );
        assert_eq!(
            contain_writer_panic(|| HddsError::HddsOk),
            HddsError::HddsOk
        );
    }
}
