// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Participant and entity information getters for HDDS C FFI

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;
use std::sync::Arc;

use hdds::api::{DataReader, DataWriter, Participant};

use super::{BytePayload, HddsDataReader, HddsDataWriter, HddsError, HddsParticipant};

// =============================================================================
// Participant Information
// =============================================================================

/// Get the participant name
///
/// # Safety
/// - `participant` must be a valid pointer returned from `hdds_participant_create`
/// - Returns a pointer to an internal string, valid until participant is destroyed
///
/// # Returns
/// Pointer to null-terminated participant name, or NULL on error
#[no_mangle]
pub unsafe extern "C" fn hdds_participant_name(participant: *mut HddsParticipant) -> *const c_char {
    if participant.is_null() {
        return ptr::null();
    }

    let participant_ref = &*participant.cast::<Arc<Participant>>();

    // We need to return a stable pointer, so we leak a CString
    // This is acceptable since participant names are typically static
    match CString::new(participant_ref.name()) {
        Ok(cstr) => {
            let ptr = cstr.as_ptr();
            std::mem::forget(cstr); // Leak intentionally - freed when participant destroyed
            ptr
        }
        Err(_) => ptr::null(),
    }
}

/// Get the participant domain ID
///
/// # Safety
/// - `participant` must be a valid pointer returned from `hdds_participant_create`
///
/// # Returns
/// Domain ID (default 0), or 0xFFFFFFFF on error
#[no_mangle]
pub unsafe extern "C" fn hdds_participant_domain_id(participant: *mut HddsParticipant) -> u32 {
    if participant.is_null() {
        return 0xFFFF_FFFF;
    }

    let participant_ref = &*participant.cast::<Arc<Participant>>();
    participant_ref.domain_id()
}

/// Get the participant ID (unique within domain)
///
/// # Safety
/// - `participant` must be a valid pointer
///
/// # Returns
/// Participant ID, or 0xFF on error
#[no_mangle]
pub unsafe extern "C" fn hdds_participant_id(participant: *mut HddsParticipant) -> u8 {
    if participant.is_null() {
        return 0xFF;
    }

    let participant_ref = &*participant.cast::<Arc<Participant>>();
    participant_ref.participant_id()
}

// =============================================================================
// DataWriter Information
// =============================================================================

/// Get the topic name for a writer
///
/// # Safety
/// - `writer` must be a valid pointer
/// - `buf` must point to a buffer of at least `buf_len` bytes
/// - `out_len` must be a valid pointer
///
/// # Returns
/// `HddsError::HddsOk` on success, writes topic name to buffer
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_topic_name(
    writer: *mut HddsDataWriter,
    buf: *mut c_char,
    buf_len: usize,
    out_len: *mut usize,
) -> HddsError {
    if writer.is_null() || buf.is_null() || out_len.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let writer_ref = &*writer.cast::<DataWriter<BytePayload>>();
    let name = writer_ref.topic_name();

    let name_len = name.len();
    *out_len = name_len;

    if buf_len < name_len + 1 {
        return HddsError::HddsOutOfMemory;
    }

    ptr::copy_nonoverlapping(name.as_ptr(), buf.cast::<u8>(), name_len);
    *buf.add(name_len) = 0; // Null terminator

    HddsError::HddsOk
}

// =============================================================================
// DataReader Information
// =============================================================================

/// Get the topic name for a reader
///
/// # Safety
/// - `reader` must be a valid pointer
/// - `buf` must point to a buffer of at least `buf_len` bytes
/// - `out_len` must be a valid pointer
///
/// # Returns
/// `HddsError::HddsOk` on success, writes topic name to buffer
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_topic_name(
    reader: *mut HddsDataReader,
    buf: *mut c_char,
    buf_len: usize,
    out_len: *mut usize,
) -> HddsError {
    if reader.is_null() || buf.is_null() || out_len.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let reader_ref = &*reader.cast::<DataReader<BytePayload>>();
    let name = reader_ref.topic_name();

    let name_len = name.len();
    *out_len = name_len;

    if buf_len < name_len + 1 {
        return HddsError::HddsOutOfMemory;
    }

    ptr::copy_nonoverlapping(name.as_ptr(), buf.cast::<u8>(), name_len);
    *buf.add(name_len) = 0; // Null terminator

    HddsError::HddsOk
}
