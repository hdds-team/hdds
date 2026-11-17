// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Value-returning DDS status accessors.

use super::*;

/// Read subscription matched and reset its change counters.
/// DDS v1.4 Sec.2.2.4.2.1: totals remain cumulative; changes are consumed
/// by this getter or by a listener reporting the same status.
///
/// # Safety
/// `reader` must be a live HDDS reader handle, and `out_status` must
/// point to writable, aligned storage. Neither may be freed during this call.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_get_subscription_matched_status(
    reader: *mut HddsDataReader,
    out_status: *mut HddsSubscriptionMatchedStatus,
) -> HddsError {
    if reader.is_null() || out_status.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let status = (&*reader.cast::<DataReader<BytePayload>>()).get_subscription_matched_status();
    out_status.write(HddsSubscriptionMatchedStatus {
        total_count: status.total_count,
        total_count_change: status.total_count_change,
        current_count: status.current_count,
        current_count_change: status.current_count_change,
    });
    HddsError::HddsOk
}

/// Read publication matched and reset its change counters.
/// DDS v1.4 Sec.2.2.4.2.1: totals remain cumulative; changes are consumed
/// by this getter or by a listener reporting the same status.
///
/// # Safety
/// `writer` must be a live HDDS writer handle, and `out_status` must
/// point to writable, aligned storage. Neither may be freed during this call.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_get_publication_matched_status(
    writer: *mut HddsDataWriter,
    out_status: *mut HddsPublicationMatchedStatus,
) -> HddsError {
    if writer.is_null() || out_status.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let status = (&*writer.cast::<DataWriter<BytePayload>>()).get_publication_matched_status();
    out_status.write(HddsPublicationMatchedStatus {
        total_count: status.total_count,
        total_count_change: status.total_count_change,
        current_count: status.current_count,
        current_count_change: status.current_count_change,
    });
    HddsError::HddsOk
}

/// Read requested deadline missed and reset its change counters.
/// DDS v1.4 Sec.2.2.4.2.1: totals remain cumulative; changes are consumed
/// by this getter or by a listener reporting the same status.
///
/// # Safety
/// `reader` must be a live HDDS reader handle, and `out_status` must
/// point to writable, aligned storage. Neither may be freed during this call.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_get_requested_deadline_missed_status(
    reader: *mut HddsDataReader,
    out_status: *mut HddsDeadlineMissedStatus,
) -> HddsError {
    if reader.is_null() || out_status.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let status =
        (&*reader.cast::<DataReader<BytePayload>>()).get_requested_deadline_missed_status();
    out_status.write(HddsDeadlineMissedStatus {
        total_count: status.total_count,
        total_count_change: status.total_count_change,
    });
    HddsError::HddsOk
}

/// Read offered deadline missed and reset its change counters.
/// DDS v1.4 Sec.2.2.4.2.1: totals remain cumulative; changes are consumed
/// by this getter or by a listener reporting the same status.
///
/// # Safety
/// `writer` must be a live HDDS writer handle, and `out_status` must
/// point to writable, aligned storage. Neither may be freed during this call.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_get_offered_deadline_missed_status(
    writer: *mut HddsDataWriter,
    out_status: *mut HddsDeadlineMissedStatus,
) -> HddsError {
    if writer.is_null() || out_status.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let status = (&*writer.cast::<DataWriter<BytePayload>>()).get_offered_deadline_missed_status();
    out_status.write(HddsDeadlineMissedStatus {
        total_count: status.total_count,
        total_count_change: status.total_count_change,
    });
    HddsError::HddsOk
}

/// Read requested incompatible qos and reset its change counters.
/// DDS v1.4 Sec.2.2.4.2.1: totals remain cumulative; changes are consumed
/// by this getter or by a listener reporting the same status.
///
/// # Safety
/// `reader` must be a live HDDS reader handle, and `out_status` must
/// point to writable, aligned storage. Neither may be freed during this call.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_get_requested_incompatible_qos_status(
    reader: *mut HddsDataReader,
    out_status: *mut HddsIncompatibleQosStatus,
) -> HddsError {
    if reader.is_null() || out_status.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let status =
        (&*reader.cast::<DataReader<BytePayload>>()).get_requested_incompatible_qos_status();
    out_status.write(HddsIncompatibleQosStatus {
        total_count: status.total_count,
        total_count_change: status.total_count_change,
        last_policy_id: status.last_policy_id,
    });
    HddsError::HddsOk
}

/// Read offered incompatible qos and reset its change counters.
/// DDS v1.4 Sec.2.2.4.2.1: totals remain cumulative; changes are consumed
/// by this getter or by a listener reporting the same status.
///
/// # Safety
/// `writer` must be a live HDDS writer handle, and `out_status` must
/// point to writable, aligned storage. Neither may be freed during this call.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_get_offered_incompatible_qos_status(
    writer: *mut HddsDataWriter,
    out_status: *mut HddsIncompatibleQosStatus,
) -> HddsError {
    if writer.is_null() || out_status.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let status = (&*writer.cast::<DataWriter<BytePayload>>()).get_offered_incompatible_qos_status();
    out_status.write(HddsIncompatibleQosStatus {
        total_count: status.total_count,
        total_count_change: status.total_count_change,
        last_policy_id: status.last_policy_id,
    });
    HddsError::HddsOk
}

/// Read liveliness changed and reset its change counters.
/// DDS v1.4 Sec.2.2.4.2.1: totals remain cumulative; changes are consumed
/// by this getter or by a listener reporting the same status.
///
/// # Safety
/// `reader` must be a live HDDS reader handle, and `out_status` must
/// point to writable, aligned storage. Neither may be freed during this call.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_get_liveliness_changed_status(
    reader: *mut HddsDataReader,
    out_status: *mut HddsLivelinessChangedStatus,
) -> HddsError {
    if reader.is_null() || out_status.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let status = (&*reader.cast::<DataReader<BytePayload>>()).get_liveliness_changed_status();
    out_status.write(HddsLivelinessChangedStatus {
        alive_count: status.alive_count,
        alive_count_change: status.alive_count_change,
        not_alive_count: status.not_alive_count,
        not_alive_count_change: status.not_alive_count_change,
    });
    HddsError::HddsOk
}

/// Read liveliness lost and reset its change counters.
/// DDS v1.4 Sec.2.2.4.2.1: totals remain cumulative; changes are consumed
/// by this getter or by a listener reporting the same status.
///
/// # Safety
/// `writer` must be a live HDDS writer handle, and `out_status` must
/// point to writable, aligned storage. Neither may be freed during this call.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_get_liveliness_lost_status(
    writer: *mut HddsDataWriter,
    out_status: *mut HddsLivelinessLostStatus,
) -> HddsError {
    if writer.is_null() || out_status.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let status = (&*writer.cast::<DataWriter<BytePayload>>()).get_liveliness_lost_status();
    out_status.write(HddsLivelinessLostStatus {
        total_count: status.total_count,
        total_count_change: status.total_count_change,
    });
    HddsError::HddsOk
}

/// Read sample lost and reset its change counters.
/// DDS v1.4 Sec.2.2.4.2.1: totals remain cumulative; changes are consumed
/// by this getter or by a listener reporting the same status.
///
/// # Safety
/// `reader` must be a live HDDS reader handle, and `out_status` must
/// point to writable, aligned storage. Neither may be freed during this call.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_get_sample_lost_status(
    reader: *mut HddsDataReader,
    out_status: *mut HddsSampleLostStatus,
) -> HddsError {
    if reader.is_null() || out_status.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let status = (&*reader.cast::<DataReader<BytePayload>>()).get_sample_lost_status();
    out_status.write(HddsSampleLostStatus {
        total_count: status.total_count,
        total_count_change: status.total_count_change,
    });
    HddsError::HddsOk
}

/// Read sample rejected and reset its change counters.
/// DDS v1.4 Sec.2.2.4.2.1: totals remain cumulative; changes are consumed
/// by this getter or by a listener reporting the same status.
///
/// # Safety
/// `reader` must be a live HDDS reader handle, and `out_status` must
/// point to writable, aligned storage. Neither may be freed during this call.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_get_sample_rejected_status(
    reader: *mut HddsDataReader,
    out_status: *mut HddsSampleRejectedStatus,
) -> HddsError {
    if reader.is_null() || out_status.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let status = (&*reader.cast::<DataReader<BytePayload>>()).get_sample_rejected_status();
    out_status.write(HddsSampleRejectedStatus {
        total_count: status.total_count,
        total_count_change: status.total_count_change,
        last_reason: super::listener::rejected_reason_code(status.last_reason),
    });
    HddsError::HddsOk
}
