// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A take whose buffer is too small returns `HDDS_OUT_OF_MEMORY` with the
//! required size and removes nothing. A later take returns the head of the
//! reader: in these single-taker tests with no eviction, that is the same
//! sample. Checked on the plain form and on the condition form.

use crate::condition_ffi::{
    hdds_create_read_condition, hdds_read_condition_delete, hdds_reader_read_w_condition,
    hdds_reader_take_w_condition, HddsInstanceStateKind, HddsSampleInfo, HddsSampleStateKind,
    HddsViewStateKind,
};
use crate::transport_config::{
    hdds_config_build, hdds_config_create, hdds_config_set_domain_id,
    hdds_config_set_transport_mode,
};
use crate::HddsDataReader;
use crate::{
    hdds_participant_destroy, hdds_reader_create, hdds_reader_destroy, hdds_reader_take,
    hdds_reader_take_ex, hdds_writer_create, hdds_writer_destroy, hdds_writer_write, HddsError,
    HddsParticipant, HddsTransportMode,
};
use std::ffi::CString;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

const SAMPLE_ANY: u32 = HddsSampleStateKind::HddsSampleStateAny as u32;
const VIEW_ANY: u32 = HddsViewStateKind::HddsViewStateAny as u32;
const INSTANCE_ANY: u32 = HddsInstanceStateKind::HddsInstanceStateAny as u32;

/// An intra-process participant on `domain` (200..=230, never 0).
unsafe fn intra_participant_on(domain: u32, name: &str) -> *mut HddsParticipant {
    let name = CString::new(name).unwrap();
    let config = hdds_config_create(name.as_ptr());
    assert!(!config.is_null());
    assert_eq!(hdds_config_set_domain_id(config, domain), HddsError::HddsOk);
    assert_eq!(
        hdds_config_set_transport_mode(config, HddsTransportMode::HddsTransportIntraProcess),
        HddsError::HddsOk
    );
    let participant = hdds_config_build(config);
    assert!(!participant.is_null());
    participant
}

/// The 40-byte sample `A` and the 8-byte sample `B`, written in that order.
const A_LEN: usize = 40;
const B_LEN: usize = 8;

#[test]
fn a_refused_take_leaves_the_sample_for_the_next_take() {
    unsafe {
        let participant = intra_participant_on(211, "TakeSizePlain");
        let topic = CString::new("TakeSizePlainTopic").unwrap();
        let writer = hdds_writer_create(participant, topic.as_ptr());
        let reader = hdds_reader_create(participant, topic.as_ptr());
        assert!(!writer.is_null() && !reader.is_null());

        let a = [1u8; A_LEN];
        let b = [2u8; B_LEN];
        assert_eq!(
            hdds_writer_write(writer, a.as_ptr().cast(), a.len()),
            HddsError::HddsOk
        );
        assert_eq!(
            hdds_writer_write(writer, b.as_ptr().cast(), b.len()),
            HddsError::HddsOk
        );

        let mut buf = [0u8; 64];
        let mut len = 0usize;
        let mut enc_small = 0u16;
        assert_eq!(
            hdds_reader_take_ex(
                reader,
                buf.as_mut_ptr().cast(),
                16,
                &mut len,
                &mut enc_small
            ),
            HddsError::HddsOutOfMemory
        );
        assert_eq!(len, A_LEN, "required size of A");

        // Refused again: still A, not B and not NOT_FOUND.
        assert_eq!(
            hdds_reader_take(reader, buf.as_mut_ptr().cast(), 16, &mut len),
            HddsError::HddsOutOfMemory
        );
        assert_eq!(len, A_LEN, "A is still the head after a second refusal");

        // A big enough buffer gets A, the same bytes, and the same
        // encapsulation identifier the refusal reported.
        let mut enc_big = 0u16;
        assert_eq!(
            hdds_reader_take_ex(reader, buf.as_mut_ptr().cast(), 64, &mut len, &mut enc_big),
            HddsError::HddsOk
        );
        assert_eq!(len, A_LEN);
        assert_eq!(&buf[..A_LEN], &a[..]);
        assert_eq!(
            enc_big, enc_small,
            "the refusal named the same representation"
        );

        // Then B, in order, exactly once.
        assert_eq!(
            hdds_reader_take(reader, buf.as_mut_ptr().cast(), 64, &mut len),
            HddsError::HddsOk
        );
        assert_eq!(len, B_LEN);
        assert_eq!(&buf[..B_LEN], &b[..]);

        // Nothing left: NOT_FOUND, even with a buffer too small for A.
        assert_eq!(
            hdds_reader_take(reader, buf.as_mut_ptr().cast(), 64, &mut len),
            HddsError::HddsNotFound
        );

        hdds_reader_destroy(reader);
        hdds_writer_destroy(writer);
        hdds_participant_destroy(participant);
    }
}

#[test]
fn a_refused_condition_take_leaves_the_sample_for_the_next_take() {
    unsafe {
        let participant = intra_participant_on(212, "TakeSizeCond");
        let topic = CString::new("TakeSizeCondTopic").unwrap();
        let writer = hdds_writer_create(participant, topic.as_ptr());
        let reader = hdds_reader_create(participant, topic.as_ptr());
        assert!(!writer.is_null() && !reader.is_null());
        let cond = hdds_create_read_condition(reader, SAMPLE_ANY, VIEW_ANY, INSTANCE_ANY);
        assert!(!cond.is_null());

        let a = [1u8; A_LEN];
        let b = [2u8; B_LEN];
        assert_eq!(
            hdds_writer_write(writer, a.as_ptr().cast(), a.len()),
            HddsError::HddsOk
        );
        assert_eq!(
            hdds_writer_write(writer, b.as_ptr().cast(), b.len()),
            HddsError::HddsOk
        );

        let mut buf = [0u8; 64];
        let mut len = 0usize;
        assert_eq!(
            hdds_reader_take_w_condition(
                reader,
                cond,
                buf.as_mut_ptr().cast(),
                16,
                &mut len,
                ptr::null_mut()
            ),
            HddsError::HddsOutOfMemory
        );
        assert_eq!(len, A_LEN, "required size of A");

        let mut info = HddsSampleInfo {
            sample_state: 0,
            view_state: 0,
            instance_state: 0,
            valid_data: false,
            instance_handle: [0; 16],
            source_timestamp_ns: 0,
            reception_timestamp_ns: 0,
            sequence_number: 0,
        };
        assert_eq!(
            hdds_reader_take_w_condition(
                reader,
                cond,
                buf.as_mut_ptr().cast(),
                64,
                &mut len,
                &mut info
            ),
            HddsError::HddsOk
        );
        assert_eq!(len, A_LEN);
        assert_eq!(&buf[..A_LEN], &a[..]);
        assert!(info.valid_data);

        assert_eq!(
            hdds_reader_take_w_condition(
                reader,
                cond,
                buf.as_mut_ptr().cast(),
                64,
                &mut len,
                ptr::null_mut()
            ),
            HddsError::HddsOk
        );
        assert_eq!(len, B_LEN);
        assert_eq!(&buf[..B_LEN], &b[..]);

        assert_eq!(
            hdds_reader_take_w_condition(
                reader,
                cond,
                buf.as_mut_ptr().cast(),
                64,
                &mut len,
                ptr::null_mut()
            ),
            HddsError::HddsNotFound
        );

        hdds_read_condition_delete(cond);
        hdds_reader_destroy(reader);
        hdds_writer_destroy(writer);
        hdds_participant_destroy(participant);
    }
}

#[test]
fn a_too_small_take_on_an_empty_reader_is_not_found() {
    unsafe {
        let participant = intra_participant_on(213, "TakeSizeEmpty");
        let topic = CString::new("TakeSizeEmptyTopic").unwrap();
        let reader = hdds_reader_create(participant, topic.as_ptr());
        assert!(!reader.is_null());

        let mut buf = [0u8; 4];
        let mut len = 99usize;
        assert_eq!(
            hdds_reader_take(reader, buf.as_mut_ptr().cast(), buf.len(), &mut len),
            HddsError::HddsNotFound
        );

        hdds_reader_destroy(reader);
        hdds_participant_destroy(participant);
    }
}

/// Two takers on one reader, each with a 16-byte buffer and a retry with a
/// 64-byte one, while the writer sends 200 samples in waves of 20 (so the
/// reader's KEEP_LAST(50) history never overflows). Odd samples are 40 bytes,
/// so about half of the takes are refused. Across both takers every sample
/// comes out exactly once, and each taker's sequence is strictly increasing:
/// a refused sample is never re-queued behind the others.
#[test]
fn concurrent_takers_lose_and_repeat_nothing_across_refusals() {
    const WAVES: u32 = 10;
    const WAVE: u32 = 20;
    const RACE_DEPTH: u32 = 50;
    const _: () = assert!(WAVE <= RACE_DEPTH);
    const TAKERS: usize = 2;
    unsafe {
        let participant = intra_participant_on(214, "TakeSizeRace");
        let topic = CString::new("TakeSizeRaceTopic").unwrap();
        let writer = hdds_writer_create(participant, topic.as_ptr());
        // KEEP_LAST(RACE_DEPTH) pinned explicitly: a wave must fit in the
        // history, or an arrival would evict an unread sample and the test
        // would measure eviction, not the take.
        let qos = crate::qos::hdds_qos_default();
        assert!(!qos.is_null());
        assert_eq!(
            crate::qos::hdds_qos_set_history_depth(qos, RACE_DEPTH),
            HddsError::HddsOk
        );
        assert_eq!(crate::qos::hdds_qos_get_history_depth(qos), RACE_DEPTH);
        let reader = crate::hdds_reader_create_with_qos(participant, topic.as_ptr(), qos);
        crate::qos::hdds_qos_destroy(qos);
        assert!(!writer.is_null() && !reader.is_null());

        let reader_addr = reader as usize;
        let seen = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let takers: Vec<_> = (0..TAKERS)
            .map(|_| {
                let seen = Arc::clone(&seen);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let reader = reader_addr as *mut HddsDataReader;
                    let mut ids = Vec::new();
                    let mut record = |bytes: &[u8]| {
                        ids.push(u32::from_le_bytes(bytes[..4].try_into().unwrap()));
                        seen.fetch_add(1, Ordering::SeqCst);
                    };
                    while !stop.load(Ordering::SeqCst) {
                        let mut small = [0u8; 16];
                        let mut len = 0usize;
                        match hdds_reader_take(reader, small.as_mut_ptr().cast(), 16, &mut len) {
                            HddsError::HddsOk => record(&small[..len]),
                            HddsError::HddsNotFound => std::thread::yield_now(),
                            HddsError::HddsOutOfMemory => {
                                let mut big = [0u8; 64];
                                match hdds_reader_take(
                                    reader,
                                    big.as_mut_ptr().cast(),
                                    64,
                                    &mut len,
                                ) {
                                    HddsError::HddsOk => record(&big[..len]),
                                    // Another taker took the refused sample first.
                                    HddsError::HddsNotFound => {}
                                    other => panic!("retry after refusal: {other:?}"),
                                }
                            }
                            other => panic!("take: {other:?}"),
                        }
                    }
                    ids
                })
            })
            .collect();

        for wave in 0..WAVES {
            for id in wave * WAVE..(wave + 1) * WAVE {
                let len = if id % 2 == 0 { 8 } else { 40 };
                let mut body = vec![0xEEu8; len];
                body[..4].copy_from_slice(&id.to_le_bytes());
                assert_eq!(
                    hdds_writer_write(writer, body.as_ptr().cast(), body.len()),
                    HddsError::HddsOk
                );
            }
            let expected = ((wave + 1) * WAVE) as usize;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while seen.load(Ordering::SeqCst) < expected {
                assert!(
                    std::time::Instant::now() < deadline,
                    "wave {wave}: takers saw {} of {expected}",
                    seen.load(Ordering::SeqCst)
                );
                std::thread::yield_now();
            }
        }
        stop.store(true, Ordering::SeqCst);

        let mut all = Vec::new();
        for taker in takers {
            let ids = taker.join().expect("taker thread");
            assert!(
                ids.windows(2).all(|pair| pair[0] < pair[1]),
                "a taker saw samples out of order: {ids:?}"
            );
            all.extend(ids);
        }
        all.sort_unstable();
        let expected: Vec<u32> = (0..WAVES * WAVE).collect();
        assert_eq!(all, expected, "every sample exactly once, none lost");

        hdds_reader_destroy(reader);
        hdds_writer_destroy(writer);
        hdds_participant_destroy(participant);
    }
}

/// A refused read leaves the sample unread: under a NOT_READ mask the retry
/// with a big enough buffer returns A (not B), and the read marks both READ
/// only once they were copied out. An ANY read still sees both afterwards.
#[test]
fn a_refused_read_leaves_the_sample_unread() {
    unsafe {
        let participant = intra_participant_on(216, "TakeSizeRead");
        let topic = CString::new("TakeSizeReadTopic").unwrap();
        let writer = hdds_writer_create(participant, topic.as_ptr());
        let reader = hdds_reader_create(participant, topic.as_ptr());
        assert!(!writer.is_null() && !reader.is_null());
        let not_read = hdds_create_read_condition(
            reader,
            HddsSampleStateKind::HddsSampleStateNotRead as u32,
            VIEW_ANY,
            INSTANCE_ANY,
        );
        let any = hdds_create_read_condition(reader, SAMPLE_ANY, VIEW_ANY, INSTANCE_ANY);
        assert!(!not_read.is_null() && !any.is_null());

        let a = [1u8; A_LEN];
        let b = [2u8; B_LEN];
        assert_eq!(
            hdds_writer_write(writer, a.as_ptr().cast(), a.len()),
            HddsError::HddsOk
        );
        assert_eq!(
            hdds_writer_write(writer, b.as_ptr().cast(), b.len()),
            HddsError::HddsOk
        );

        let mut buf = [0u8; 64];
        let mut len = 0usize;
        assert_eq!(
            hdds_reader_read_w_condition(
                reader,
                not_read,
                buf.as_mut_ptr().cast(),
                16,
                &mut len,
                ptr::null_mut()
            ),
            HddsError::HddsOutOfMemory
        );
        assert_eq!(len, A_LEN, "required size of A");

        assert_eq!(
            hdds_reader_read_w_condition(
                reader,
                not_read,
                buf.as_mut_ptr().cast(),
                64,
                &mut len,
                ptr::null_mut()
            ),
            HddsError::HddsOk
        );
        assert_eq!(len, A_LEN, "A is still unread, so the retry returns it");
        assert_eq!(&buf[..A_LEN], &a[..]);

        assert_eq!(
            hdds_reader_read_w_condition(
                reader,
                not_read,
                buf.as_mut_ptr().cast(),
                64,
                &mut len,
                ptr::null_mut()
            ),
            HddsError::HddsOk
        );
        assert_eq!(len, B_LEN);
        assert_eq!(&buf[..B_LEN], &b[..]);

        assert_eq!(
            hdds_reader_read_w_condition(
                reader,
                not_read,
                buf.as_mut_ptr().cast(),
                64,
                &mut len,
                ptr::null_mut()
            ),
            HddsError::HddsNotFound
        );

        // Read marks, it does not remove: the ANY mask sees A again.
        assert_eq!(
            hdds_reader_read_w_condition(
                reader,
                any,
                buf.as_mut_ptr().cast(),
                64,
                &mut len,
                ptr::null_mut()
            ),
            HddsError::HddsOk
        );
        assert_eq!(len, A_LEN);
        assert_eq!(&buf[..A_LEN], &a[..]);

        hdds_read_condition_delete(not_read);
        hdds_read_condition_delete(any);
        hdds_reader_destroy(reader);
        hdds_writer_destroy(writer);
        hdds_participant_destroy(participant);
    }
}

/// The documented edge of the retry guarantee: with KEEP_LAST(1), a newer
/// sample of the same instance evicts the refused one, so the retry returns
/// the newer sample. The refused take itself removed nothing.
#[test]
fn a_newer_sample_can_evict_a_refused_one_under_keep_last() {
    unsafe {
        let participant = intra_participant_on(218, "TakeSizeEvict");
        let topic = CString::new("TakeSizeEvictTopic").unwrap();
        let writer = hdds_writer_create(participant, topic.as_ptr());
        let qos = crate::qos::hdds_qos_default();
        assert!(!qos.is_null());
        assert_eq!(
            crate::qos::hdds_qos_set_history_depth(qos, 1),
            HddsError::HddsOk
        );
        let reader = crate::hdds_reader_create_with_qos(participant, topic.as_ptr(), qos);
        crate::qos::hdds_qos_destroy(qos);
        assert!(!writer.is_null() && !reader.is_null());

        let a = [1u8; A_LEN];
        let b = [2u8; B_LEN];
        assert_eq!(
            hdds_writer_write(writer, a.as_ptr().cast(), a.len()),
            HddsError::HddsOk
        );
        let mut buf = [0u8; 64];
        let mut len = 0usize;
        assert_eq!(
            hdds_reader_take(reader, buf.as_mut_ptr().cast(), 16, &mut len),
            HddsError::HddsOutOfMemory
        );
        assert_eq!(len, A_LEN);

        assert_eq!(
            hdds_writer_write(writer, b.as_ptr().cast(), b.len()),
            HddsError::HddsOk
        );
        assert_eq!(
            hdds_reader_take(reader, buf.as_mut_ptr().cast(), 64, &mut len),
            HddsError::HddsOk
        );
        assert_eq!(len, B_LEN, "the newer sample evicted A: the head is B");
        assert_eq!(&buf[..B_LEN], &b[..]);

        hdds_reader_destroy(reader);
        hdds_writer_destroy(writer);
        hdds_participant_destroy(participant);
    }
}
