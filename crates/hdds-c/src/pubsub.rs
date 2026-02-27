// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Publisher and Subscriber APIs for HDDS C FFI
//!
//! These provide the standard DDS entity hierarchy:
//! Participant -> Publisher -> DataWriter
//! Participant -> Subscriber -> DataReader

use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::sync::Arc;

use hdds::api::{Participant, Publisher, QoS, Subscriber};

use super::{BytePayload, HddsDataReader, HddsDataWriter, HddsParticipant, HddsQoS};

/// Opaque handle to a Publisher
#[repr(C)]
pub struct HddsPublisher {
    _private: [u8; 0],
}

/// Opaque handle to a Subscriber
#[repr(C)]
pub struct HddsSubscriber {
    _private: [u8; 0],
}

// =============================================================================
// Publisher
// =============================================================================

/// Create a Publisher with default QoS
///
/// # Safety
/// - `participant` must be a valid pointer
///
/// # Returns
/// Publisher handle, or NULL on error
#[no_mangle]
pub unsafe extern "C" fn hdds_publisher_create(
    participant: *mut HddsParticipant,
) -> *mut HddsPublisher {
    hdds_publisher_create_with_qos(participant, ptr::null())
}

/// Create a Publisher with custom QoS
///
/// # Safety
/// - `participant` must be a valid pointer
/// - `qos` can be NULL for default QoS
///
/// # Returns
/// Publisher handle, or NULL on error
#[no_mangle]
pub unsafe extern "C" fn hdds_publisher_create_with_qos(
    participant: *mut HddsParticipant,
    qos: *const HddsQoS,
) -> *mut HddsPublisher {
    if participant.is_null() {
        return ptr::null_mut();
    }

    let participant_ref = &*participant.cast::<Arc<Participant>>();

    let qos_value = if qos.is_null() {
        QoS::default()
    } else {
        (*qos.cast::<QoS>()).clone()
    };

    match participant_ref.create_publisher(qos_value) {
        Ok(publisher) => Box::into_raw(Box::new(publisher)).cast::<HddsPublisher>(),
        Err(e) => {
            log::error!("Failed to create publisher: {:?}", e);
            ptr::null_mut()
        }
    }
}

/// Destroy a Publisher
///
/// # Safety
/// - `publisher` must be a valid pointer or NULL
#[no_mangle]
pub unsafe extern "C" fn hdds_publisher_destroy(publisher: *mut HddsPublisher) {
    if !publisher.is_null() {
        let _ = Box::from_raw(publisher.cast::<Publisher>());
    }
}

// =============================================================================
// Subscriber
// =============================================================================

/// Create a Subscriber with default QoS
///
/// # Safety
/// - `participant` must be a valid pointer
///
/// # Returns
/// Subscriber handle, or NULL on error
#[no_mangle]
pub unsafe extern "C" fn hdds_subscriber_create(
    participant: *mut HddsParticipant,
) -> *mut HddsSubscriber {
    hdds_subscriber_create_with_qos(participant, ptr::null())
}

/// Create a Subscriber with custom QoS
///
/// # Safety
/// - `participant` must be a valid pointer
/// - `qos` can be NULL for default QoS
///
/// # Returns
/// Subscriber handle, or NULL on error
#[no_mangle]
pub unsafe extern "C" fn hdds_subscriber_create_with_qos(
    participant: *mut HddsParticipant,
    qos: *const HddsQoS,
) -> *mut HddsSubscriber {
    if participant.is_null() {
        return ptr::null_mut();
    }

    let participant_ref = &*participant.cast::<Arc<Participant>>();

    let qos_value = if qos.is_null() {
        QoS::default()
    } else {
        (*qos.cast::<QoS>()).clone()
    };

    match participant_ref.create_subscriber(qos_value) {
        Ok(subscriber) => Box::into_raw(Box::new(subscriber)).cast::<HddsSubscriber>(),
        Err(e) => {
            log::error!("Failed to create subscriber: {:?}", e);
            ptr::null_mut()
        }
    }
}

/// Destroy a Subscriber
///
/// # Safety
/// - `subscriber` must be a valid pointer or NULL
#[no_mangle]
pub unsafe extern "C" fn hdds_subscriber_destroy(subscriber: *mut HddsSubscriber) {
    if !subscriber.is_null() {
        let _ = Box::from_raw(subscriber.cast::<Subscriber>());
    }
}

// =============================================================================
// Publisher -> DataWriter
// =============================================================================

/// Create a DataWriter from a Publisher with default QoS
///
/// # Safety
/// - `publisher` must be a valid pointer returned from `hdds_publisher_create`
/// - `topic_name` must be a valid null-terminated C string
///
/// # Returns
/// DataWriter handle, or NULL on error
#[no_mangle]
pub unsafe extern "C" fn hdds_publisher_create_writer(
    publisher: *mut HddsPublisher,
    topic_name: *const c_char,
) -> *mut HddsDataWriter {
    hdds_publisher_create_writer_with_qos(publisher, topic_name, ptr::null())
}

/// Create a DataWriter from a Publisher with custom QoS
///
/// # Safety
/// - `publisher` must be a valid pointer returned from `hdds_publisher_create`
/// - `topic_name` must be a valid null-terminated C string
/// - `qos` can be NULL for default QoS
///
/// # Returns
/// DataWriter handle, or NULL on error
#[no_mangle]
pub unsafe extern "C" fn hdds_publisher_create_writer_with_qos(
    publisher: *mut HddsPublisher,
    topic_name: *const c_char,
    qos: *const HddsQoS,
) -> *mut HddsDataWriter {
    if publisher.is_null() || topic_name.is_null() {
        return ptr::null_mut();
    }

    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return ptr::null_mut();
    };

    let publisher_ref = &*publisher.cast::<Publisher>();

    let qos_value = if qos.is_null() {
        QoS::default()
    } else {
        (*qos.cast::<QoS>()).clone()
    };

    match publisher_ref.create_writer::<BytePayload>(topic_str, qos_value) {
        Ok(writer) => Box::into_raw(Box::new(writer)).cast::<HddsDataWriter>(),
        Err(e) => {
            log::error!("Failed to create writer from publisher: {:?}", e);
            ptr::null_mut()
        }
    }
}

// =============================================================================
// Subscriber -> DataReader
// =============================================================================

/// Create a DataReader from a Subscriber with default QoS
///
/// # Safety
/// - `subscriber` must be a valid pointer returned from `hdds_subscriber_create`
/// - `topic_name` must be a valid null-terminated C string
///
/// # Returns
/// DataReader handle, or NULL on error
#[no_mangle]
pub unsafe extern "C" fn hdds_subscriber_create_reader(
    subscriber: *mut HddsSubscriber,
    topic_name: *const c_char,
) -> *mut HddsDataReader {
    hdds_subscriber_create_reader_with_qos(subscriber, topic_name, ptr::null())
}

/// Create a DataReader from a Subscriber with custom QoS
///
/// # Safety
/// - `subscriber` must be a valid pointer returned from `hdds_subscriber_create`
/// - `topic_name` must be a valid null-terminated C string
/// - `qos` can be NULL for default QoS
///
/// # Returns
/// DataReader handle, or NULL on error
#[no_mangle]
pub unsafe extern "C" fn hdds_subscriber_create_reader_with_qos(
    subscriber: *mut HddsSubscriber,
    topic_name: *const c_char,
    qos: *const HddsQoS,
) -> *mut HddsDataReader {
    if subscriber.is_null() || topic_name.is_null() {
        return ptr::null_mut();
    }

    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return ptr::null_mut();
    };

    let subscriber_ref = &*subscriber.cast::<Subscriber>();

    let qos_value = if qos.is_null() {
        QoS::default()
    } else {
        (*qos.cast::<QoS>()).clone()
    };

    match subscriber_ref.create_reader::<BytePayload>(topic_str, qos_value) {
        Ok(reader) => Box::into_raw(Box::new(reader)).cast::<HddsDataReader>(),
        Err(e) => {
            log::error!("Failed to create reader from subscriber: {:?}", e);
            ptr::null_mut()
        }
    }
}
