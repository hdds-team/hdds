// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A C ABI reader that decodes XCDR1 as well as XCDR2 requests both
//! (`hdds_qos_set_data_representation`), is matched with a writer of
//! either, and learns per sample which one the bytes are in (the `_ex`
//! takes and reads, the `_ex` listener, `hdds_dynamic_data_decode_ex`). A C
//! ABI writer labels a body with its type's extensibility
//! (`hdds_writer_create_with_extensibility`). DDS-XTypes v1.3
//! Sec.7.6.3.1.1-2.

use super::*;
use crate::condition_ffi::{
    hdds_create_query_condition, hdds_create_read_condition, hdds_query_condition_delete,
    hdds_read_condition_delete, hdds_reader_read_w_condition_ex, hdds_reader_take_w_condition_ex,
    hdds_reader_take_w_query_condition_ex, HddsSampleInfo,
};
use crate::dynamic_ffi::{
    hdds_dynamic_data_decode, hdds_dynamic_data_decode_ex, hdds_dynamic_data_destroy,
    hdds_dynamic_data_get_f64, hdds_dynamic_data_get_u8, hdds_type_builder_add_field,
    hdds_type_builder_build, hdds_type_builder_new, hdds_type_descriptor_destroy,
    HddsPrimitiveKind,
};
use crate::listener::{
    hdds_reader_clear_listener, hdds_reader_set_listener_ex, HddsReaderListener,
};
use crate::qos::{
    hdds_qos_default, hdds_qos_destroy, hdds_qos_get_data_representation,
    hdds_qos_set_data_representation, HDDS_XCDR2_DATA_REPRESENTATION,
    HDDS_XCDR_DATA_REPRESENTATION,
};
use hdds::test_support::domains::unique_domain;
use hdds::test_support::wire::{capture_data, data_payloads, drain};
use std::ffi::CString;
use std::time::{Duration, Instant};

const CDR_LE: u16 = 0x0001;
const PL_CDR_LE: u16 = 0x0003;
const CDR2_LE: u16 = 0x0007;
const D_CDR2_LE: u16 = 0x0009;
const PL_CDR2_LE: u16 = 0x000b;

fn wait_for(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    done()
}

/// A C ABI QoS (RELIABLE) whose DATA_REPRESENTATION is `ids`.
unsafe fn qos_with(ids: &[i16]) -> *mut HddsQoS {
    let qos = crate::qos::hdds_qos_reliable();
    assert!(!qos.is_null());
    assert_eq!(
        hdds_qos_set_data_representation(qos, ids.as_ptr(), ids.len()),
        HddsError::HddsOk
    );
    qos
}

unsafe fn c_participant(name: &str, domain: u32) -> *mut HddsParticipant {
    let name = CString::new(name).unwrap();
    let config = crate::transport_config::hdds_config_create(name.as_ptr());
    assert!(!config.is_null());
    assert_eq!(
        crate::transport_config::hdds_config_set_domain_id(config, domain),
        HddsError::HddsOk
    );
    let participant = crate::transport_config::hdds_config_build(config);
    assert!(!participant.is_null());
    participant
}

unsafe fn intra_participant(name: &str) -> *mut HddsParticipant {
    let name = CString::new(name).unwrap();
    let participant = hdds_participant_create_with_transport(
        name.as_ptr(),
        HddsTransportMode::HddsTransportIntraProcess,
    );
    assert!(!participant.is_null());
    participant
}

/// The setter takes XCDR and XCDR2 in the order given, clears the list
/// with no element, and refuses any other identifier without touching the
/// QoS; the getter reports what is set.
#[test]
fn the_data_representation_setter_takes_xcdr_and_xcdr2_only() {
    unsafe {
        let qos = hdds_qos_default();
        let get = |qos: *const HddsQoS| {
            let mut ids = [0i16; 4];
            let mut count = 0usize;
            assert_eq!(
                hdds_qos_get_data_representation(qos, ids.as_mut_ptr(), ids.len(), &mut count),
                HddsError::HddsOk
            );
            ids[..count.min(4)].to_vec()
        };
        assert_eq!(get(qos), Vec::<i16>::new(), "the default is an empty list");

        let both = [
            HDDS_XCDR_DATA_REPRESENTATION,
            HDDS_XCDR2_DATA_REPRESENTATION,
        ];
        assert_eq!(
            hdds_qos_set_data_representation(qos, both.as_ptr(), both.len()),
            HddsError::HddsOk
        );
        assert_eq!(get(qos), vec![0, 2]);
        assert_eq!((*qos.cast::<QoS>()).data_representation, vec![0u16, 2]);

        for refused in [[0i16, 1], [2, -1], [3, 0]] {
            assert_eq!(
                hdds_qos_set_data_representation(qos, refused.as_ptr(), refused.len()),
                HddsError::HddsInvalidArgument,
                "{refused:?}"
            );
            assert_eq!(get(qos), vec![0, 2], "{refused:?} left the QoS unchanged");
        }
        assert_eq!(
            hdds_qos_set_data_representation(qos, ptr::null(), 1),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_qos_set_data_representation(qos, ptr::null(), 0),
            HddsError::HddsOk
        );
        assert_eq!(get(qos), Vec::<i16>::new(), "no element clears the list");

        let mut count = 7usize;
        assert_eq!(
            hdds_qos_get_data_representation(qos, ptr::null_mut(), 0, &mut count),
            HddsError::HddsOk
        );
        assert_eq!(count, 0);
        hdds_qos_destroy(qos);
    }
}

/// What the C listener's `_ex` data callback received.
#[derive(Default)]
struct ExSeen {
    samples: Mutex<Vec<(Vec<u8>, u16)>>,
}

unsafe extern "C" fn on_data_ex(data: *const u8, len: usize, id: u16, user: *mut c_void) {
    let seen = &*user.cast::<ExSeen>();
    let bytes = std::slice::from_raw_parts(data, len).to_vec();
    seen.samples
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((bytes, id));
}

/// Must not be called: the `_ex` callback replaces it. Recorded with an
/// identifier no sample has, so the comparison below fails if it is.
unsafe extern "C" fn on_data_plain(data: *const u8, len: usize, user: *mut c_void) {
    let seen = &*user.cast::<ExSeen>();
    let bytes = std::slice::from_raw_parts(data, len).to_vec();
    seen.samples
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((bytes, 0xDEAD));
}

/// A C reader that requests `[XCDR, XCDR2]` is matched with a writer of
/// each, in another participant: every take form reports the sample's
/// representation, XCDR1 bytes as CDR_LE and XCDR2 bytes as CDR2_LE, and so
/// does the `_ex` listener, called instead of `ON_DATA_AVAILABLE`.
#[test]
fn a_reader_requesting_xcdr_and_xcdr2_reports_each_samples_representation() {
    let domain = unique_domain();
    unsafe {
        let c_part = c_participant("c_ex_reader", domain.id());
        let topic = CString::new("c_ex_reader").unwrap();
        let qos = qos_with(&[
            HDDS_XCDR_DATA_REPRESENTATION,
            HDDS_XCDR2_DATA_REPRESENTATION,
        ]);
        let reader = hdds_reader_create_with_qos(c_part, topic.as_ptr(), qos);
        hdds_qos_destroy(qos);
        assert!(!reader.is_null());
        let seen = Box::new(ExSeen::default());
        let listener = HddsReaderListener {
            on_data_available: Some(on_data_plain),
            on_subscription_matched: None,
            on_liveliness_changed: None,
            on_sample_lost: None,
            on_sample_rejected: None,
            on_deadline_missed: None,
            on_incompatible_qos: None,
            user_data: (&*seen as *const ExSeen).cast_mut().cast::<c_void>(),
        };
        assert_eq!(
            hdds_reader_set_listener_ex(reader, &listener, Some(on_data_ex)),
            HddsError::HddsOk
        );

        let peer = Participant::builder("c_ex_reader_peer")
            .domain_id(domain.id())
            .with_transport(hdds::TransportMode::UdpMulticast)
            .build()
            .expect("peer");
        // A writer that set no list offers XCDR (BytePayload encodes it
        // natively); the other one offers XCDR2.
        let w1 = peer
            .topic::<BytePayload>("c_ex_reader")
            .unwrap()
            .writer()
            .qos(QoS::reliable().keep_all())
            .build()
            .unwrap();
        let w2 = peer
            .topic::<BytePayload>("c_ex_reader")
            .unwrap()
            .writer()
            .qos(QoS::reliable().keep_all().data_representation_xcdr2())
            .build()
            .unwrap();
        assert_eq!(w1.qos().data_representation, vec![0]);
        assert_eq!(w2.qos().data_representation, vec![2]);
        let mut matched = 0u32;
        assert!(wait_for(Duration::from_secs(10), || {
            let mut a = 0u32;
            let mut b = 0u32;
            let _ = hdds_writer_matched_reader_count(
                (&w1 as *const DataWriter<BytePayload>).cast_mut().cast(),
                &mut a,
            );
            let _ = hdds_writer_matched_reader_count(
                (&w2 as *const DataWriter<BytePayload>).cast_mut().cast(),
                &mut b,
            );
            matched = a + b;
            matched == 2
        }));

        let expected: Vec<(Vec<u8>, u16)> = vec![
            (vec![0x11, 1, 0, 0], CDR_LE),
            (vec![0x22, 2, 0, 0], CDR2_LE),
            (vec![0x11, 3, 0, 0], CDR_LE),
            (vec![0x22, 4, 0, 0], CDR2_LE),
        ];
        for (bytes, id) in &expected {
            let writer = if *id == CDR_LE { &w1 } else { &w2 };
            writer.write(&BytePayload::to_write(bytes.clone())).unwrap();
            // One at a time: the two writers' samples are not ordered
            // between each other.
            assert!(wait_for(Duration::from_secs(5), || {
                seen.samples.lock().unwrap().iter().any(|(b, _)| b == bytes)
            }));
        }
        assert_eq!(*seen.samples.lock().unwrap(), expected, "the _ex listener");

        // The first two through read/take with a condition, the next one
        // through hdds_reader_take_ex, the last through hdds_reader_take.
        let any = hdds_create_read_condition(
            reader,
            HddsSampleStateKind::HddsSampleStateAny as u32,
            HddsViewStateKind::HddsViewStateAny as u32,
            HddsInstanceStateKind::HddsInstanceStateAny as u32,
        );
        assert!(!any.is_null());
        let mut buf = [0u8; 64];
        let mut len = 0usize;
        let mut id = 0xFFFFu16;
        let mut info: HddsSampleInfo = std::mem::zeroed();
        assert_eq!(
            hdds_reader_read_w_condition_ex(
                reader,
                any,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut len,
                &mut info,
                &mut id
            ),
            HddsError::HddsOk
        );
        assert_eq!(
            (buf[..len].to_vec(), id),
            expected[0],
            "read_w_condition_ex"
        );
        let mut taken = Vec::new();
        for _ in 0..2 {
            id = 0xFFFF;
            assert_eq!(
                hdds_reader_take_w_condition_ex(
                    reader,
                    any,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    &mut len,
                    ptr::null_mut(),
                    &mut id
                ),
                HddsError::HddsOk
            );
            taken.push((buf[..len].to_vec(), id));
        }
        id = 0xFFFF;
        assert_eq!(
            hdds_reader_take_ex(
                reader,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut len,
                &mut id
            ),
            HddsError::HddsOk
        );
        taken.push((buf[..len].to_vec(), id));
        assert_eq!(
            hdds_reader_take(reader, buf.as_mut_ptr().cast(), buf.len(), &mut len),
            HddsError::HddsOk
        );
        taken.push((buf[..len].to_vec(), CDR2_LE));
        assert_eq!(taken, expected, "take_w_condition_ex, take_ex, take");
        assert_eq!(
            hdds_reader_take_ex(
                reader,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut len,
                &mut id
            ),
            HddsError::HddsNotFound
        );
        assert_eq!(
            hdds_reader_take_ex(
                reader,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut len,
                ptr::null_mut()
            ),
            HddsError::HddsInvalidArgument
        );

        hdds_read_condition_delete(any);
        assert_eq!(hdds_reader_clear_listener(reader), HddsError::HddsOk);
        drop(w1);
        drop(w2);
        drop(peer);
        hdds_reader_destroy(reader);
        hdds_participant_destroy(c_part);
    }
}

/// `struct { uint8 b; double d; }`, APPENDABLE (the builder's default).
unsafe fn b_and_d() -> *mut crate::dynamic_ffi::HddsTypeDescriptor {
    let name = CString::new("BAndD").unwrap();
    let builder = hdds_type_builder_new(name.as_ptr());
    let b = CString::new("b").unwrap();
    let d = CString::new("d").unwrap();
    assert_eq!(
        hdds_type_builder_add_field(builder, b.as_ptr(), HddsPrimitiveKind::HddsPrimU8 as u32),
        HddsError::HddsOk
    );
    assert_eq!(
        hdds_type_builder_add_field(builder, d.as_ptr(), HddsPrimitiveKind::HddsPrimF64 as u32),
        HddsError::HddsOk
    );
    let desc = hdds_type_builder_build(builder);
    assert!(!desc.is_null());
    desc
}

/// The XCDR1 body of `{7, 1.0}`: `b`, seven bytes of padding, `d` at 8, no
/// DHEADER (DDS-XTypes v1.3 7.4.1). Read as XCDR2 (a DHEADER, then `d` at
/// 4 after it) it is not that value.
const B_AND_D_XCDR1: [u8; 16] = [7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xf0, 0x3f];

/// `(b, d)` of `bytes` decoded by `hdds_dynamic_data_decode_ex` with `id`,
/// `None` when it does not decode.
unsafe fn decode_b_and_d(
    desc: *const crate::dynamic_ffi::HddsTypeDescriptor,
    bytes: &[u8],
    id: Option<u16>,
) -> Option<(u8, f64)> {
    let data = match id {
        Some(id) => hdds_dynamic_data_decode_ex(desc, bytes.as_ptr(), bytes.len(), id),
        None => hdds_dynamic_data_decode(desc, bytes.as_ptr(), bytes.len()),
    };
    if data.is_null() {
        return None;
    }
    let b = CString::new("b").unwrap();
    let d = CString::new("d").unwrap();
    let (mut b_out, mut d_out) = (0u8, 0f64);
    let ok = hdds_dynamic_data_get_u8(data, b.as_ptr(), &mut b_out) == HddsError::HddsOk
        && hdds_dynamic_data_get_f64(data, d.as_ptr(), &mut d_out) == HddsError::HddsOk;
    hdds_dynamic_data_destroy(data);
    ok.then_some((b_out, d_out))
}

/// A QueryCondition reads an XCDR1 sample's fields in XCDR1, and
/// `hdds_dynamic_data_decode_ex` decodes the bytes by the identifier the
/// take reports. The query `b = 7 AND d > 0.5` holds for `{7, 1.0}`; read
/// as XCDR2 the same bytes are `{0, 1.0}` (the first four bytes taken for a
/// DHEADER), for which it does not.
#[test]
fn dynamic_data_of_an_xcdr1_sample_is_decoded_in_xcdr1() {
    unsafe {
        let participant = intra_participant("c_ex_dynamic");
        let topic = CString::new("c_ex_dynamic").unwrap();
        let desc = b_and_d();
        let qos = qos_with(&[
            HDDS_XCDR_DATA_REPRESENTATION,
            HDDS_XCDR2_DATA_REPRESENTATION,
        ]);
        let reader = hdds_reader_create_with_qos(participant, topic.as_ptr(), qos);
        hdds_qos_destroy(qos);
        assert!(!reader.is_null());
        let query = CString::new("b = 7 AND d > 0.5").unwrap();
        let hot = hdds_create_query_condition(
            reader,
            HddsSampleStateKind::HddsSampleStateAny as u32,
            HddsViewStateKind::HddsViewStateAny as u32,
            HddsInstanceStateKind::HddsInstanceStateAny as u32,
            desc,
            query.as_ptr(),
            ptr::null(),
            0,
        );
        assert!(!hot.is_null());

        // A writer that set no list offers XCDR: the bytes are XCDR1.
        let participant_ref = &*participant.cast::<Arc<Participant>>();
        let writer = participant_ref
            .topic::<BytePayload>("c_ex_dynamic")
            .unwrap()
            .writer()
            .qos(QoS::reliable())
            .build()
            .unwrap();
        assert_eq!(writer.qos().data_representation, vec![0]);
        writer
            .write(&BytePayload::to_write(B_AND_D_XCDR1.to_vec()))
            .unwrap();

        let mut buf = [0u8; 64];
        let mut len = 0usize;
        let mut id = 0u16;
        assert_eq!(
            hdds_reader_take_w_query_condition_ex(
                reader,
                hot,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut len,
                ptr::null_mut(),
                &mut id
            ),
            HddsError::HddsOk,
            "the query holds when the fields are read where XCDR1 puts them"
        );
        assert_eq!((&buf[..len], id), (&B_AND_D_XCDR1[..], CDR_LE));
        assert_eq!(decode_b_and_d(desc, &buf[..len], Some(id)), Some((7, 1.0)));
        assert_eq!(
            decode_b_and_d(desc, &buf[..len], Some(PL_CDR_LE)),
            Some((7, 1.0))
        );
        assert_ne!(
            decode_b_and_d(desc, &buf[..len], None),
            Some((7, 1.0)),
            "the same bytes read as XCDR2"
        );
        assert_ne!(
            decode_b_and_d(desc, &buf[..len], Some(CDR2_LE)),
            Some((7, 1.0))
        );
        for refused in [0x0000u16, 0x0002, 0x0006, 0x8001] {
            assert_eq!(
                decode_b_and_d(desc, &buf[..len], Some(refused)),
                None,
                "{refused:#06x}"
            );
        }

        hdds_query_condition_delete(hot);
        drop(writer);
        hdds_reader_destroy(reader);
        hdds_type_descriptor_destroy(desc);
        hdds_participant_destroy(participant);
    }
}

/// A writer a Publisher creates labels its bodies as one a participant
/// creates: D_CDR2_LE for APPENDABLE, PL_CDR2_LE for MUTABLE, CDR2_LE for
/// FINAL and when not told; an unknown extensibility is refused.
#[test]
fn a_publisher_writer_labels_a_body_with_its_types_extensibility() {
    use crate::pubsub::{
        hdds_publisher_create, hdds_publisher_create_writer_with_extensibility,
        hdds_publisher_create_writer_with_qos, hdds_publisher_destroy,
    };
    use std::cell::Cell;
    let body = [4u8, 0, 0, 0, 0x2a, 0, 0, 0];
    let cases: [(&str, Option<u32>, u16); 4] = [
        ("pub_ext_final", Some(HDDS_EXTENSIBILITY_FINAL), CDR2_LE),
        (
            "pub_ext_appendable",
            Some(HDDS_EXTENSIBILITY_APPENDABLE),
            D_CDR2_LE,
        ),
        (
            "pub_ext_mutable",
            Some(HDDS_EXTENSIBILITY_MUTABLE),
            PL_CDR2_LE,
        ),
        ("pub_ext_untold", None, CDR2_LE),
    ];
    for (name, extensibility, wire) in cases {
        let publisher = Cell::new(ptr::null_mut());
        let got = unsafe {
            first_data_on_the_wire(
                name,
                |participant, topic| {
                    publisher.set(hdds_publisher_create(participant));
                    assert!(!publisher.get().is_null());
                    match extensibility {
                        Some(e) => hdds_publisher_create_writer_with_extensibility(
                            publisher.get(),
                            topic,
                            ptr::null(),
                            e,
                        ),
                        None => hdds_publisher_create_writer_with_qos(
                            publisher.get(),
                            topic,
                            ptr::null(),
                        ),
                    }
                },
                &body,
            )
        };
        unsafe { hdds_publisher_destroy(publisher.get()) };
        assert_eq!(got, Some((wire, body.to_vec())), "{name}");
    }

    unsafe {
        let participant = intra_participant("pub_ext_unknown");
        let publisher = hdds_publisher_create(participant);
        let topic = CString::new("pub_ext_unknown").unwrap();
        assert!(hdds_publisher_create_writer_with_extensibility(
            publisher,
            topic.as_ptr(),
            ptr::null(),
            3
        )
        .is_null());
        hdds_publisher_destroy(publisher);
        hdds_participant_destroy(participant);
    }
}

/// The encapsulation identifier on the wire of the first DATA a C ABI
/// writer created with `create` sends, and its body.
unsafe fn first_data_on_the_wire(
    name: &str,
    create: impl FnOnce(*mut HddsParticipant, *const c_char) -> *mut HddsDataWriter,
    body: &[u8],
) -> Option<(u16, Vec<u8>)> {
    let domain = unique_domain();
    let participant = c_participant(name, domain.id());
    let topic = CString::new(name).unwrap();
    let writer = create(participant, topic.as_ptr());
    assert!(!writer.is_null(), "{name}");
    let capture = capture_data(&mut *writer.cast::<DataWriter<BytePayload>>());
    assert_eq!(
        hdds_writer_write(writer, body.as_ptr().cast(), body.len()),
        HddsError::HddsOk
    );
    let payloads: Vec<(u16, Vec<u8>)> = drain(&capture)
        .iter()
        .flat_map(|datagram| data_payloads(datagram))
        .collect();
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);
    payloads.into_iter().next()
}

/// A C ABI writer labels an APPENDABLE body D_CDR2_LE and a MUTABLE one
/// PL_CDR2_LE when told the extensibility, and their XCDR1 forms CDR_LE and
/// PL_CDR_LE when it offers XCDR; read back from the bytes it sends. The
/// constructors that are not told label every body CDR2_LE.
#[test]
fn a_c_writer_labels_a_body_with_its_types_extensibility() {
    // An APPENDABLE XCDR2 body: DHEADER 4, then a long.
    let body = [4u8, 0, 0, 0, 0x2a, 0, 0, 0];
    let cases: [(&str, u32, &[i16], u16); 6] = [
        ("c_ext_final", HDDS_EXTENSIBILITY_FINAL, &[], CDR2_LE),
        (
            "c_ext_appendable",
            HDDS_EXTENSIBILITY_APPENDABLE,
            &[],
            D_CDR2_LE,
        ),
        ("c_ext_mutable", HDDS_EXTENSIBILITY_MUTABLE, &[], PL_CDR2_LE),
        (
            "c_ext_appendable_x1",
            HDDS_EXTENSIBILITY_APPENDABLE,
            &[HDDS_XCDR_DATA_REPRESENTATION],
            CDR_LE,
        ),
        (
            "c_ext_mutable_x1",
            HDDS_EXTENSIBILITY_MUTABLE,
            &[HDDS_XCDR_DATA_REPRESENTATION],
            PL_CDR_LE,
        ),
        (
            "c_ext_final_x1",
            HDDS_EXTENSIBILITY_FINAL,
            &[HDDS_XCDR_DATA_REPRESENTATION],
            CDR_LE,
        ),
    ];
    for (name, extensibility, ids, wire) in cases {
        let got = unsafe {
            first_data_on_the_wire(
                name,
                |participant, topic| {
                    let qos = if ids.is_empty() {
                        ptr::null_mut()
                    } else {
                        qos_with(ids)
                    };
                    let type_name = CString::new("ExtT").unwrap();
                    let writer = hdds_writer_create_with_extensibility(
                        participant,
                        topic,
                        type_name.as_ptr(),
                        qos,
                        extensibility,
                    );
                    if !qos.is_null() {
                        hdds_qos_destroy(qos);
                    }
                    writer
                },
                &body,
            )
        };
        assert_eq!(got, Some((wire, body.to_vec())), "{name}");
    }

    let untold = unsafe {
        first_data_on_the_wire(
            "c_ext_untold",
            |participant, topic| {
                hdds_writer_create_with_type(participant, topic, ptr::null(), ptr::null())
            },
            &body,
        )
    };
    assert_eq!(
        untold,
        Some((CDR2_LE, body.to_vec())),
        "hdds_writer_create_with_type"
    );

    unsafe {
        let participant = intra_participant("c_ext_unknown");
        let topic = CString::new("c_ext_unknown").unwrap();
        assert!(hdds_writer_create_with_extensibility(
            participant,
            topic.as_ptr(),
            ptr::null(),
            ptr::null(),
            3
        )
        .is_null());
        hdds_participant_destroy(participant);
    }
}
