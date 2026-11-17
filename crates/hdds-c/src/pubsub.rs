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

use super::{BytePayload, HddsDataReader, HddsDataWriter, HddsError, HddsParticipant, HddsQoS};

/// Opaque handle to a Publisher
pub struct HddsPublisher {
    _private: [u8; 0],
}

/// Opaque handle to a Subscriber
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

/// Block until the data of every DataWriter of `publisher` has been
/// acknowledged by every matched RELIABLE reader, or `timeout_ms` elapses
/// (DDS v1.4 Sec.2.2.2.4.1.12 `wait_for_acknowledgments`). Returns `HddsOk`
/// once acknowledged and `HddsTimeout` if `timeout_ms` elapses first.
/// `timeout_ms` bounds the whole call: the writers share one deadline.
/// A BEST_EFFORT writer owes nothing (Sec.2.2.2.4.2.15), and a Publisher
/// without a writer returns `HddsOk` at once.
///
/// # Safety
/// - `publisher` must be a valid pointer returned from `hdds_publisher_create`
/// - the publisher must not be destroyed concurrently while this function is running
#[no_mangle]
pub unsafe extern "C" fn hdds_publisher_wait_for_acknowledgments(
    publisher: *mut HddsPublisher,
    timeout_ms: u64,
) -> HddsError {
    if publisher.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let publisher_ref = &*publisher.cast::<Publisher>();
    crate::acknowledgment_status(
        publisher_ref.wait_for_acknowledgments(std::time::Duration::from_millis(timeout_ms)),
    )
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

    match publisher_ref.create_adopting_writer::<BytePayload>(
        topic_str,
        crate::sdk_writer_qos(qos_value),
        hdds::dynamic::Extensibility::Final,
        false,
    ) {
        Ok(writer) => crate::writer_into_handle(writer),
        Err(e) => {
            log::error!("Failed to create writer from publisher: {:?}", e);
            ptr::null_mut()
        }
    }
}

/// `hdds_publisher_create_writer_with_qos`, for bodies of a type whose
/// extensibility is `extensibility` (`HDDS_EXTENSIBILITY_FINAL`,
/// `_APPENDABLE` or `_MUTABLE`): see `hdds_writer_create_with_extensibility`.
/// The writer has no type of its own: it announces the type name its topic's
/// readers announce, else "RawBytes", as the other constructors of this ABI
/// (see `hdds_writer_create_with_type`).
///
/// # Safety
/// Same as `hdds_publisher_create_writer_with_qos`.
///
/// # Returns
/// DataWriter handle, or NULL on an unknown `extensibility` or any other
/// error
#[no_mangle]
pub unsafe extern "C" fn hdds_publisher_create_writer_with_extensibility(
    publisher: *mut HddsPublisher,
    topic_name: *const c_char,
    qos: *const HddsQoS,
    extensibility: u32,
) -> *mut HddsDataWriter {
    if publisher.is_null() || topic_name.is_null() {
        return ptr::null_mut();
    }
    let Some(extensibility) = crate::extensibility_from_c(extensibility) else {
        log::error!(
            "hdds_publisher_create_writer_with_extensibility: unknown extensibility {extensibility}"
        );
        return ptr::null_mut();
    };
    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return ptr::null_mut();
    };
    let publisher_ref = &*publisher.cast::<Publisher>();
    let qos_value = if qos.is_null() {
        QoS::default()
    } else {
        (*qos.cast::<QoS>()).clone()
    };
    match publisher_ref.create_adopting_writer::<BytePayload>(
        topic_str,
        crate::sdk_writer_qos(qos_value),
        extensibility,
        false,
    ) {
        Ok(writer) => crate::writer_into_handle(writer),
        Err(e) => {
            log::error!("Failed to create writer from publisher: {e:?}");
            ptr::null_mut()
        }
    }
}

/// `hdds_publisher_create_writer_with_extensibility` announcing `type_name` in
/// discovery: the entry for a writer created FOR a type (generated code, a typed
/// SDK), which announces its own type's name and never a peer's. `type_name` NULL
/// or empty is the writer with no type of its own of
/// `hdds_publisher_create_writer_with_extensibility`.
///
/// # Safety
/// Same as `hdds_publisher_create_writer_with_extensibility`; a non-NULL
/// `type_name` must be a valid null-terminated C string.
///
/// # Returns
/// DataWriter handle, or NULL on an unknown `extensibility`, a `type_name` that
/// is not UTF-8, or any other error
#[no_mangle]
pub unsafe extern "C" fn hdds_publisher_create_writer_with_type(
    publisher: *mut HddsPublisher,
    topic_name: *const c_char,
    type_name: *const c_char,
    qos: *const HddsQoS,
    extensibility: u32,
) -> *mut HddsDataWriter {
    if publisher.is_null() || topic_name.is_null() {
        return ptr::null_mut();
    }
    let Some(extensibility) = crate::extensibility_from_c(extensibility) else {
        log::error!(
            "hdds_publisher_create_writer_with_type: unknown extensibility {extensibility}"
        );
        return ptr::null_mut();
    };
    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return ptr::null_mut();
    };
    let Ok(requested) = crate::requested_type_name(type_name) else {
        return ptr::null_mut();
    };
    let publisher_ref = &*publisher.cast::<Publisher>();
    let qos_value = if qos.is_null() {
        QoS::default()
    } else {
        (*qos.cast::<QoS>()).clone()
    };
    let created = match requested {
        Some(type_str) => publisher_ref.create_writer_with_extensibility::<BytePayload>(
            topic_str,
            crate::sdk_writer_qos(qos_value),
            type_str,
            extensibility,
        ),
        None => publisher_ref.create_adopting_writer::<BytePayload>(
            topic_str,
            crate::sdk_writer_qos(qos_value),
            extensibility,
            false,
        ),
    };
    match created {
        Ok(writer) => crate::writer_into_handle(writer),
        Err(e) => {
            log::error!("Failed to create writer from publisher: {e:?}");
            ptr::null_mut()
        }
    }
}

// =============================================================================
// Subscriber -> DataReader
// =============================================================================

/// Open an access bracket on a Subscriber (DDS v1.4 Sec.2.2.2.5.2.8).
///
/// When the Subscriber's PRESENTATION access scope is GROUP (a QoS loaded
/// from XML can set it), its readers are read only inside a bracket:
/// outside, a read or take fails. Brackets nest; each is closed by its own
/// `hdds_subscriber_end_access`. For any other access scope a bracket has
/// no effect.
///
/// # Safety
/// - `subscriber` must be a valid pointer returned from `hdds_subscriber_create`
///
/// # Returns
/// `HddsOk`, or `HddsInvalidArgument` for a null `subscriber`
#[no_mangle]
pub unsafe extern "C" fn hdds_subscriber_begin_access(
    subscriber: *mut HddsSubscriber,
) -> HddsError {
    if subscriber.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    match (*subscriber.cast::<Subscriber>()).begin_access() {
        Ok(()) => HddsError::HddsOk,
        Err(_) => HddsError::HddsInvalidState,
    }
}

/// Close the access bracket `hdds_subscriber_begin_access` opened.
///
/// # Safety
/// - `subscriber` must be a valid pointer returned from `hdds_subscriber_create`
///
/// # Returns
/// `HddsOk`; `HddsInvalidState` (PRECONDITION_NOT_MET) when no bracket is
/// open; `HddsInvalidArgument` for a null `subscriber`
#[no_mangle]
pub unsafe extern "C" fn hdds_subscriber_end_access(subscriber: *mut HddsSubscriber) -> HddsError {
    if subscriber.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    match (*subscriber.cast::<Subscriber>()).end_access() {
        Ok(()) => HddsError::HddsOk,
        Err(_) => HddsError::HddsInvalidState,
    }
}

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

    let Some(participant) = subscriber_ref.participant() else {
        log::error!("Subscriber has no parent participant");
        return ptr::null_mut();
    };

    match participant
        .topic::<BytePayload>(topic_str)
        // A reader of this Subscriber (its access brackets, its presentation
        // barrier), as the Rust API builds one with `.subscriber()`.
        .and_then(|t| {
            // A reader with no type of its own (XTypes 1.3
            // Sec.7.6.3.4.2 Step 2): see `adopting_type_name`.
            t.reader()
                .qos(crate::sdk_reader_qos(qos_value))
                .subscriber(subscriber_ref)
                .adopting_type_name()
                .build()
        }) {
        Ok(reader) => super::reader_into_handle(reader),
        Err(e) => {
            log::error!("Failed to create reader from subscriber: {:?}", e);
            ptr::null_mut()
        }
    }
}

/// `hdds_subscriber_create_reader_with_qos` announcing `type_name` in discovery:
/// the entry for a reader created FOR a type (a typed SDK), which announces its
/// own type's name and never a peer's. `type_name` NULL or empty is the reader
/// with no type of its own of `hdds_subscriber_create_reader_with_qos`.
///
/// # Safety
/// Same as `hdds_subscriber_create_reader_with_qos`; a non-NULL `type_name` must
/// be a valid null-terminated C string.
///
/// # Returns
/// DataReader handle, or NULL on a `type_name` that is not UTF-8 or any other
/// error
#[no_mangle]
pub unsafe extern "C" fn hdds_subscriber_create_reader_with_type(
    subscriber: *mut HddsSubscriber,
    topic_name: *const c_char,
    type_name: *const c_char,
    qos: *const HddsQoS,
) -> *mut HddsDataReader {
    if subscriber.is_null() || topic_name.is_null() {
        return ptr::null_mut();
    }
    let Ok(topic_str) = CStr::from_ptr(topic_name).to_str() else {
        return ptr::null_mut();
    };
    let Ok(requested) = crate::requested_type_name(type_name) else {
        return ptr::null_mut();
    };
    let subscriber_ref = &*subscriber.cast::<Subscriber>();
    let qos_value = if qos.is_null() {
        QoS::default()
    } else {
        (*qos.cast::<QoS>()).clone()
    };
    let Some(participant) = subscriber_ref.participant() else {
        log::error!("Subscriber has no parent participant");
        return ptr::null_mut();
    };
    match participant.topic::<BytePayload>(topic_str).and_then(|t| {
        let builder = t
            .reader()
            .qos(crate::sdk_reader_qos(qos_value))
            .subscriber(subscriber_ref);
        match requested {
            Some(type_str) => builder.with_type_name(type_str),
            None => builder.adopting_type_name(),
        }
        .build()
    }) {
        Ok(reader) => super::reader_into_handle(reader),
        Err(e) => {
            log::error!("Failed to create reader from subscriber: {e:?}");
            ptr::null_mut()
        }
    }
}

#[cfg(test)]
mod wait_for_acknowledgments_tests {
    use super::*;
    use std::ffi::CString;

    /// The C status of the wait: TIMEOUT is the DDS return code of a wait
    /// that ran out, anything else that is not acknowledgment a failure.
    #[test]
    fn the_wait_status_names_a_timeout() {
        assert_eq!(crate::acknowledgment_status(Ok(())), HddsError::HddsOk);
        assert_eq!(
            crate::acknowledgment_status(Err(hdds::dds::Error::AcknowledgmentTimeout)),
            HddsError::HddsTimeout
        );
        assert_eq!(
            crate::acknowledgment_status(Err(hdds::dds::Error::Io)),
            HddsError::HddsOperationFailed
        );
    }

    /// `hdds_publisher_wait_for_acknowledgments`: a NULL publisher is an
    /// invalid argument; a Publisher without a writer, and one whose RELIABLE
    /// writer has no matched reader, have nothing to wait for (DDS v1.4
    /// Sec.2.2.2.4.1.12 over an empty set of readers is vacuously true).
    #[test]
    fn a_c_publisher_with_nothing_to_wait_for_is_ok() {
        // SAFETY: handles created and destroyed here, in order.
        unsafe {
            assert_eq!(
                hdds_publisher_wait_for_acknowledgments(ptr::null_mut(), 10),
                HddsError::HddsInvalidArgument
            );

            let name = CString::new("c_publisher_wait_ack").expect("name");
            let participant = crate::hdds_participant_create_with_transport(
                name.as_ptr(),
                crate::HddsTransportMode::HddsTransportIntraProcess,
            );
            assert!(!participant.is_null());
            let publisher = hdds_publisher_create(participant);
            assert!(!publisher.is_null());
            assert_eq!(
                hdds_publisher_wait_for_acknowledgments(publisher, 0),
                HddsError::HddsOk
            );

            let qos = crate::qos::hdds_qos_reliable();
            let topic = CString::new("c_publisher_wait_ack_topic").expect("topic");
            let writer = hdds_publisher_create_writer_with_qos(publisher, topic.as_ptr(), qos);
            assert!(!writer.is_null());
            let payload = [1u8, 2, 3, 4];
            assert_eq!(
                crate::hdds_writer_write(writer, payload.as_ptr().cast(), payload.len()),
                HddsError::HddsOk
            );
            assert_eq!(
                hdds_publisher_wait_for_acknowledgments(publisher, 150),
                HddsError::HddsOk
            );

            crate::qos::hdds_qos_destroy(qos);
            crate::hdds_writer_destroy(writer);
            hdds_publisher_destroy(publisher);
            crate::hdds_participant_destroy(participant);
        }
    }
}

#[cfg(test)]
mod access_tests {
    use super::*;
    use std::ffi::CString;

    /// A reader of a GROUP-scope Subscriber taken from C outside a bracket:
    /// HDDS_INVALID_STATE (PRECONDITION_NOT_MET), inside: nothing to take.
    #[test]
    fn a_c_take_outside_a_group_bracket_is_invalid_state() {
        // SAFETY: handles created and destroyed here, in order; the QoS
        // pointer is a live `QoS`, which `HddsQoS` stands for.
        unsafe {
            let name = CString::new("c_take_bracket").expect("name");
            let participant = crate::hdds_participant_create_with_transport(
                name.as_ptr(),
                crate::HddsTransportMode::HddsTransportIntraProcess,
            );
            assert!(!participant.is_null());
            let qos = QoS::default().presentation(hdds::dds::qos::Presentation::new(
                hdds::dds::qos::PresentationAccessScope::Group,
                false,
                false,
            ));
            let subscriber =
                hdds_subscriber_create_with_qos(participant, (&raw const qos).cast::<HddsQoS>());
            assert!(!subscriber.is_null());
            let topic = CString::new("c_take_bracket_topic").expect("topic");
            let reader = hdds_subscriber_create_reader(subscriber, topic.as_ptr());
            assert!(!reader.is_null());
            let mut buf = [0u8; 64];
            let mut len = 0usize;
            assert_eq!(
                crate::hdds_reader_take(reader, buf.as_mut_ptr().cast(), buf.len(), &mut len),
                HddsError::HddsInvalidState
            );
            assert_eq!(hdds_subscriber_begin_access(subscriber), HddsError::HddsOk);
            assert_eq!(
                crate::hdds_reader_take(reader, buf.as_mut_ptr().cast(), buf.len(), &mut len),
                HddsError::HddsNotFound
            );
            assert_eq!(hdds_subscriber_end_access(subscriber), HddsError::HddsOk);
            crate::hdds_reader_destroy(reader);
            hdds_subscriber_destroy(subscriber);
            crate::hdds_participant_destroy(participant);
        }
    }

    /// A Subscriber's access brackets from C: they nest, and an end with no
    /// begin is PRECONDITION_NOT_MET.
    #[test]
    fn a_subscriber_access_bracket_from_c() {
        // SAFETY: handles created and destroyed here, in order.
        unsafe {
            let name = CString::new("c_access_bracket").expect("name");
            let participant = crate::hdds_participant_create_with_transport(
                name.as_ptr(),
                crate::HddsTransportMode::HddsTransportIntraProcess,
            );
            assert!(!participant.is_null());
            let subscriber = hdds_subscriber_create(participant);
            assert!(!subscriber.is_null());
            assert_eq!(hdds_subscriber_begin_access(subscriber), HddsError::HddsOk);
            assert_eq!(hdds_subscriber_begin_access(subscriber), HddsError::HddsOk);
            assert_eq!(hdds_subscriber_end_access(subscriber), HddsError::HddsOk);
            assert_eq!(hdds_subscriber_end_access(subscriber), HddsError::HddsOk);
            assert_eq!(
                hdds_subscriber_end_access(subscriber),
                HddsError::HddsInvalidState
            );
            assert_eq!(
                hdds_subscriber_begin_access(ptr::null_mut()),
                HddsError::HddsInvalidArgument
            );
            hdds_subscriber_destroy(subscriber);
            crate::hdds_participant_destroy(participant);
        }
    }
}
