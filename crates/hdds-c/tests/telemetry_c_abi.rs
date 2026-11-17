// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The C ABI write and read paths feed the same telemetry counters as the
//! Rust API: a sample written through `hdds_writer_write` and taken through
//! `hdds_reader_take` / `hdds_reader_take_ex` shows up in
//! `hdds_telemetry_snapshot` as one message sent, its bytes, and one
//! message received. The file is its own process, so the deltas are exact.

use hdds::test_support::domains::unique_domain;
use hdds_c::{
    hdds_telemetry_init, hdds_telemetry_release, hdds_telemetry_snapshot, HddsMetricsSnapshot,
};
use std::ffi::{c_void, CString};
use std::time::{Duration, Instant};

fn snapshot() -> HddsMetricsSnapshot {
    unsafe {
        let metrics = hdds_telemetry_init();
        assert!(!metrics.is_null());
        let mut snap = HddsMetricsSnapshot::default();
        assert_eq!(
            hdds_telemetry_snapshot(metrics, &mut snap),
            hdds_c::HddsError::HddsOk
        );
        hdds_telemetry_release(metrics);
        snap
    }
}

#[test]
fn a_c_write_and_a_c_take_are_counted_like_any_other() {
    // A domain in the 200..=230 band, leases below it held until one fits.
    let mut skipped = Vec::new();
    let lease = loop {
        let lease = unique_domain();
        if (200..=230).contains(&lease.id()) {
            break lease;
        }
        skipped.push(lease);
    };
    std::env::set_var("HDDS_DOMAIN_ID", lease.id().to_string());

    unsafe {
        let name = CString::new("tc_c_abi").unwrap();
        let participant = hdds_c::hdds_participant_create_with_transport(
            name.as_ptr(),
            hdds_c::HddsTransportMode::HddsTransportIntraProcess,
        );
        assert!(!participant.is_null());
        let topic = CString::new("tc_c_abi_topic").unwrap();
        let reader = hdds_c::hdds_reader_create(participant, topic.as_ptr());
        let writer = hdds_c::hdds_writer_create(participant, topic.as_ptr());
        assert!(!reader.is_null() && !writer.is_null());

        let before = snapshot();
        let payload = [0x5Au8; 24];
        for _ in 0..4 {
            assert_eq!(
                hdds_c::hdds_writer_write(writer, payload.as_ptr().cast::<c_void>(), payload.len()),
                hdds_c::HddsError::HddsOk
            );
        }
        let mut buffer = [0u8; 256];
        let mut taken = 0;
        let deadline = Instant::now() + Duration::from_secs(5);
        while taken < 4 && Instant::now() < deadline {
            let mut len = 0usize;
            match hdds_c::hdds_reader_take(
                reader,
                buffer.as_mut_ptr().cast::<c_void>(),
                buffer.len(),
                &mut len,
            ) {
                hdds_c::HddsError::HddsOk => taken += 1,
                _ => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        assert_eq!(taken, 4, "fixture: the reader got the four samples");

        let after = snapshot();
        assert_eq!(after.messages_sent - before.messages_sent, 4);
        assert_eq!(after.messages_received - before.messages_received, 4);
        let bytes = after.bytes_sent - before.bytes_sent;
        assert!(
            bytes >= 4 * payload.len() as u64 && bytes.is_multiple_of(4),
            "bytes_sent counts the serialized payload of each write, got {bytes}"
        );

        hdds_c::hdds_reader_destroy(reader);
        hdds_c::hdds_writer_destroy(writer);
        hdds_c::hdds_participant_destroy(participant);
    }
}
