// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[test]
fn status_and_timestamp_null_arguments() {
    unsafe {
        let mut status = HddsSubscriptionMatchedStatus::default();
        assert_eq!(
            hdds_reader_get_subscription_matched_status(ptr::null_mut(), &mut status),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_reader_get_subscription_matched_status(std::ptr::dangling_mut(), ptr::null_mut()),
            HddsError::HddsInvalidArgument
        );
        let mut status = HddsPublicationMatchedStatus::default();
        assert_eq!(
            hdds_writer_get_publication_matched_status(ptr::null_mut(), &mut status),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_writer_get_publication_matched_status(std::ptr::dangling_mut(), ptr::null_mut()),
            HddsError::HddsInvalidArgument
        );
        let mut status = HddsDeadlineMissedStatus::default();
        assert_eq!(
            hdds_reader_get_requested_deadline_missed_status(ptr::null_mut(), &mut status),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_reader_get_requested_deadline_missed_status(
                std::ptr::dangling_mut(),
                ptr::null_mut()
            ),
            HddsError::HddsInvalidArgument
        );
        let mut status = HddsDeadlineMissedStatus::default();
        assert_eq!(
            hdds_writer_get_offered_deadline_missed_status(ptr::null_mut(), &mut status),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_writer_get_offered_deadline_missed_status(
                std::ptr::dangling_mut(),
                ptr::null_mut()
            ),
            HddsError::HddsInvalidArgument
        );
        let mut status = HddsIncompatibleQosStatus::default();
        assert_eq!(
            hdds_reader_get_requested_incompatible_qos_status(ptr::null_mut(), &mut status),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_reader_get_requested_incompatible_qos_status(
                std::ptr::dangling_mut(),
                ptr::null_mut()
            ),
            HddsError::HddsInvalidArgument
        );
        let mut status = HddsIncompatibleQosStatus::default();
        assert_eq!(
            hdds_writer_get_offered_incompatible_qos_status(ptr::null_mut(), &mut status),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_writer_get_offered_incompatible_qos_status(
                std::ptr::dangling_mut(),
                ptr::null_mut()
            ),
            HddsError::HddsInvalidArgument
        );
        let mut status = HddsLivelinessChangedStatus::default();
        assert_eq!(
            hdds_reader_get_liveliness_changed_status(ptr::null_mut(), &mut status),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_reader_get_liveliness_changed_status(std::ptr::dangling_mut(), ptr::null_mut()),
            HddsError::HddsInvalidArgument
        );
        let mut status = HddsLivelinessLostStatus::default();
        assert_eq!(
            hdds_writer_get_liveliness_lost_status(ptr::null_mut(), &mut status),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_writer_get_liveliness_lost_status(std::ptr::dangling_mut(), ptr::null_mut()),
            HddsError::HddsInvalidArgument
        );
        let mut status = HddsSampleLostStatus::default();
        assert_eq!(
            hdds_reader_get_sample_lost_status(ptr::null_mut(), &mut status),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_reader_get_sample_lost_status(std::ptr::dangling_mut(), ptr::null_mut()),
            HddsError::HddsInvalidArgument
        );
        let mut status = HddsSampleRejectedStatus::default();
        assert_eq!(
            hdds_reader_get_sample_rejected_status(ptr::null_mut(), &mut status),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_reader_get_sample_rejected_status(std::ptr::dangling_mut(), ptr::null_mut()),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_writer_write_w_timestamp(ptr::null_mut(), std::ptr::dangling(), 0, 0),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_writer_write_w_timestamp(std::ptr::dangling_mut(), ptr::null(), 0, 0),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_writer_dispose(ptr::null_mut(), std::ptr::dangling(), 0),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_writer_dispose(std::ptr::dangling_mut(), ptr::null(), 0),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_writer_dispose_w_timestamp(ptr::null_mut(), std::ptr::dangling(), 0, 0),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_writer_dispose_w_timestamp(std::ptr::dangling_mut(), ptr::null(), 0, 0),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_writer_unregister_instance(ptr::null_mut(), std::ptr::dangling(), 0),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_writer_unregister_instance(std::ptr::dangling_mut(), ptr::null(), 0),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_writer_unregister_instance_w_timestamp(
                ptr::null_mut(),
                std::ptr::dangling(),
                0,
                0
            ),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_writer_unregister_instance_w_timestamp(
                std::ptr::dangling_mut(),
                ptr::null(),
                0,
                0
            ),
            HddsError::HddsInvalidArgument
        );
        let mut handle = HddsInstanceHandle::default();
        assert_eq!(
            hdds_writer_register_instance(ptr::null_mut(), std::ptr::dangling(), 0, &mut handle),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_writer_register_instance(std::ptr::dangling_mut(), ptr::null(), 0, &mut handle),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_writer_register_instance(
                std::ptr::dangling_mut(),
                std::ptr::dangling(),
                0,
                ptr::null_mut()
            ),
            HddsError::HddsInvalidArgument
        );
        let mut handle = HddsInstanceHandle::default();
        assert_eq!(
            hdds_writer_register_instance_w_timestamp(
                ptr::null_mut(),
                std::ptr::dangling(),
                0,
                0,
                &mut handle
            ),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_writer_register_instance_w_timestamp(
                std::ptr::dangling_mut(),
                ptr::null(),
                0,
                0,
                &mut handle
            ),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_writer_register_instance_w_timestamp(
                std::ptr::dangling_mut(),
                std::ptr::dangling(),
                0,
                0,
                ptr::null_mut()
            ),
            HddsError::HddsInvalidArgument
        );
    }
}
