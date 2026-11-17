// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A C reader's take announces the instance-state transitions it cannot
//! return. After a dispose, the reader's status condition is raised (the
//! transition is pending); a `hdds_reader_take` that finds no data returns
//! NOT_FOUND and must leave the status lowered, so a WaitSet does not wake
//! on it again (no busy loop). The sized take shares that path with the
//! plain take.

use crate::transport_config::{
    hdds_config_build, hdds_config_create, hdds_config_set_domain_id,
    hdds_config_set_transport_mode,
};
use crate::{
    hdds_participant_destroy, hdds_reader_create, hdds_reader_destroy,
    hdds_reader_get_status_condition, hdds_reader_take, hdds_status_condition_release,
    hdds_waitset_attach_status_condition, hdds_waitset_create, hdds_waitset_destroy,
    hdds_waitset_wait, hdds_writer_create, hdds_writer_destroy, hdds_writer_dispose, HddsError,
    HddsParticipant, HddsTransportMode,
};
use std::ffi::{c_void, CString};

/// Number of conditions a zero-timeout wait reports for the status condition.
unsafe fn woken(waitset: *mut crate::HddsWaitSet) -> usize {
    let mut out: [*const c_void; 4] = [std::ptr::null(); 4];
    let mut len = 0usize;
    assert_eq!(
        hdds_waitset_wait(waitset, 0, out.as_mut_ptr(), out.len(), &mut len),
        HddsError::HddsOk
    );
    len
}

#[test]
fn a_take_on_an_empty_reader_announces_a_pending_dispose() {
    unsafe {
        let name = CString::new("DisposeTake").unwrap();
        let config = hdds_config_create(name.as_ptr());
        assert!(!config.is_null());
        assert_eq!(hdds_config_set_domain_id(config, 217), HddsError::HddsOk);
        assert_eq!(
            hdds_config_set_transport_mode(config, HddsTransportMode::HddsTransportIntraProcess),
            HddsError::HddsOk
        );
        let participant: *mut HddsParticipant = hdds_config_build(config);
        assert!(!participant.is_null());

        let topic = CString::new("DisposeTakeTopic").unwrap();
        let writer = hdds_writer_create(participant, topic.as_ptr());
        let reader = hdds_reader_create(participant, topic.as_ptr());
        assert!(!writer.is_null() && !reader.is_null());

        let status = hdds_reader_get_status_condition(reader);
        assert!(!status.is_null());
        let waitset = hdds_waitset_create();
        assert_eq!(
            hdds_waitset_attach_status_condition(waitset, status),
            HddsError::HddsOk
        );
        assert_eq!(woken(waitset), 0, "nothing happened yet");

        let key = [1u8; 8];
        assert_eq!(
            hdds_writer_dispose(writer, key.as_ptr().cast(), key.len()),
            HddsError::HddsOk
        );
        assert_eq!(woken(waitset), 1, "the dispose is pending: status raised");

        // The take has no sample and cannot return the transition: NOT_FOUND.
        let mut buf = [0u8; 16];
        let mut len = 0usize;
        assert_eq!(
            hdds_reader_take(reader, buf.as_mut_ptr().cast(), buf.len(), &mut len),
            HddsError::HddsNotFound
        );
        // ... and it announced the transition, so the status is lowered.
        assert_eq!(woken(waitset), 0, "the take settled the pending transition");

        hdds_waitset_destroy(waitset);
        hdds_status_condition_release(status);
        hdds_reader_destroy(reader);
        hdds_writer_destroy(writer);
        hdds_participant_destroy(participant);
    }
}
