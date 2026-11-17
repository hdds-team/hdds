// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DATA_REPRESENTATION of the endpoints the C ABI creates, judged through
//! the C ABI and on the wire (DDS-XTypes v1.3 Sec.7.6.3.1.1).
//!
//! The SDK codecs read and write XCDR2 only, so a C ABI reader that set no
//! list requests `[XCDR2]` (`sdk_reader_qos`): a writer that offers XCDR, as
//! a default writer does, is a visible REQUESTED_INCOMPATIBLE_QOS and
//! delivers nothing, instead of handing XCDR1 bytes to an XCDR2 decoder.

use super::*;
use crate::listener::{
    hdds_reader_set_listener, HddsIncompatibleQosStatus, HddsReaderListener,
    HddsSubscriptionMatchedStatus,
};
use hdds::dds::{DataWriterListener, PublicationMatchedStatus};
use hdds::test_support::domains::unique_domain;
use hdds::DiscoveredEndpointKind;
use std::ffi::CString;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::time::{Duration, Instant};

const XCDR1: u16 = 0x0000;
const XCDR2: u16 = 0x0002;
/// DDS v1.4 Table 2.60, DATA_REPRESENTATION.
const POLICY_DATA_REPRESENTATION: u32 = 23;

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

/// A UDP participant created through the C ABI on `domain`.
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

fn rust_participant(name: &str, domain: u32) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain)
        .with_transport(hdds::TransportMode::UdpMulticast)
        .build()
        .expect("participant")
}

/// What a C reader listener reported.
#[derive(Default)]
struct CReaderSeen {
    matched: AtomicU32,
    incompatible: AtomicU32,
    last_policy: AtomicU32,
}

unsafe extern "C" fn on_matched(status: *const HddsSubscriptionMatchedStatus, user: *mut c_void) {
    let seen = &*user.cast::<CReaderSeen>();
    seen.matched
        .store((*status).current_count, Ordering::SeqCst);
}

unsafe extern "C" fn on_incompatible(status: *const HddsIncompatibleQosStatus, user: *mut c_void) {
    let seen = &*user.cast::<CReaderSeen>();
    seen.incompatible
        .store((*status).total_count, Ordering::SeqCst);
    seen.last_policy
        .store((*status).last_policy_id, Ordering::SeqCst);
}

unsafe fn listen(reader: *mut HddsDataReader, seen: &CReaderSeen) {
    let listener = HddsReaderListener {
        on_data_available: None,
        on_subscription_matched: Some(on_matched),
        on_liveliness_changed: None,
        on_sample_lost: None,
        on_sample_rejected: None,
        on_deadline_missed: None,
        on_incompatible_qos: Some(on_incompatible),
        user_data: (seen as *const CReaderSeen).cast_mut().cast::<c_void>(),
    };
    assert_eq!(
        hdds_reader_set_listener(reader, &listener),
        HddsError::HddsOk
    );
}

#[derive(Default)]
struct WriterSeen {
    current: AtomicI32,
    incompatible: AtomicU32,
}

impl DataWriterListener<BytePayload> for WriterSeen {
    fn on_publication_matched(&self, status: PublicationMatchedStatus) {
        self.current
            .store(status.current_count as i32, Ordering::SeqCst);
    }
    fn on_offered_incompatible_qos(&self, _policy_id: u32, _policy_name: &str) {
        self.incompatible.fetch_add(1, Ordering::SeqCst);
    }
}

unsafe fn c_reader_qos<'a>(reader: *mut HddsDataReader) -> &'a [u16] {
    &(*reader.cast::<DataReader<BytePayload>>())
        .qos()
        .data_representation
}

/// Every C ABI reader creation path that takes no list requests XCDR2, the
/// representation the SDK codecs read; one that set a list keeps it. The
/// default reader's announcement is read back from the wire by a second
/// participant (its SEDP PID_DATA_REPRESENTATION as parsed).
#[test]
fn a_c_reader_that_set_no_representation_requests_xcdr2() {
    let domain = unique_domain();
    unsafe {
        let participant = c_participant("c_reader_repr", domain.id());
        let topic = CString::new("c_reader_repr").unwrap();
        let type_name = CString::new("CReaderRepresentationT").unwrap();
        let explicit = Box::into_raw(Box::new(QoS::default().data_representation_xcdr1()));
        let subscriber = crate::pubsub::hdds_subscriber_create(participant);
        assert!(!subscriber.is_null());
        // A content-filtered reader needs the sample's schema.
        let type_builder = crate::dynamic_ffi::hdds_type_builder_new(type_name.as_ptr());
        let field = CString::new("value").unwrap();
        assert_eq!(
            crate::dynamic_ffi::hdds_type_builder_add_field(
                type_builder,
                field.as_ptr(),
                crate::dynamic_ffi::HddsPrimitiveKind::HddsPrimI32 as u32
            ),
            HddsError::HddsOk
        );
        let desc = crate::dynamic_ffi::hdds_type_builder_build(type_builder);
        assert!(!desc.is_null());
        let cft_name = CString::new("c_reader_repr_filtered").unwrap();
        let expr = CString::new("value > 0").unwrap();
        let cft = crate::condition_ffi::hdds_create_content_filtered_topic(
            participant,
            cft_name.as_ptr(),
            topic.as_ptr(),
            desc,
            expr.as_ptr(),
            ptr::null(),
            0,
        );
        assert!(!cft.is_null());
        let readers = [
            (hdds_reader_create(participant, topic.as_ptr()), vec![XCDR2]),
            (
                hdds_reader_create_with_qos(participant, topic.as_ptr(), ptr::null()),
                vec![XCDR2],
            ),
            (
                hdds_reader_create_with_type(
                    participant,
                    topic.as_ptr(),
                    type_name.as_ptr(),
                    ptr::null(),
                ),
                vec![XCDR2],
            ),
            (
                hdds_reader_create_with_type(participant, topic.as_ptr(), ptr::null(), ptr::null()),
                vec![XCDR2],
            ),
            (
                crate::pubsub::hdds_subscriber_create_reader(subscriber, topic.as_ptr()),
                vec![XCDR2],
            ),
            (
                crate::condition_ffi::hdds_create_reader_filtered(participant, cft, ptr::null()),
                vec![XCDR2],
            ),
            (
                hdds_reader_create_with_qos(
                    participant,
                    topic.as_ptr(),
                    explicit.cast::<HddsQoS>(),
                ),
                vec![XCDR1],
            ),
        ];
        for (i, (reader, expected)) in readers.iter().enumerate() {
            assert!(!reader.is_null(), "path {i}");
            assert_eq!(c_reader_qos(*reader), &expected[..], "path {i}");
        }

        // What every one of them puts on the wire, as a peer parses it.
        let peer = rust_participant("c_reader_repr_peer", domain.id());
        let mut announced: Vec<Vec<u16>> = Vec::new();
        assert!(
            wait_for(Duration::from_secs(10), || {
                announced = peer
                    .discover_endpoints()
                    .unwrap()
                    .into_iter()
                    .filter(|e| {
                        e.topic_name == "c_reader_repr" && e.kind == DiscoveredEndpointKind::Reader
                    })
                    .map(|e| e.qos.data_representation)
                    .collect();
                announced.len() == readers.len()
            }),
            "the C readers are discovered: {announced:?}"
        );
        announced.sort();
        let mut expected: Vec<Vec<u16>> = readers.iter().map(|(_, e)| e.clone()).collect();
        expected.sort();
        assert_eq!(announced, expected);

        for (reader, _) in readers {
            hdds_reader_destroy(reader);
        }
        drop(Box::from_raw(explicit));
        crate::condition_ffi::hdds_content_filtered_topic_delete(cft);
        crate::dynamic_ffi::hdds_type_descriptor_destroy(desc);
        crate::pubsub::hdds_subscriber_destroy(subscriber);
        hdds_participant_destroy(participant);
    }
}

/// Where the Rust writer lives relative to the C reader.
#[derive(Clone, Copy, Debug)]
enum Placement {
    /// In the C reader's participant.
    SameParticipant,
    /// In a second UDP participant on the same domain.
    TwoParticipants,
}

/// A Rust writer of `writer_qos`, a default C ABI reader, on one topic:
/// returns (C reader's listener, writer's listener, what the reader took).
fn rust_writer_to_default_c_reader(
    name: &str,
    placement: Placement,
    writer_qos: QoS,
) -> (Arc<CReaderSeen>, Arc<WriterSeen>, Vec<Vec<u8>>, bool) {
    let domain = unique_domain();
    unsafe {
        let c_part = c_participant(&format!("{name}_c"), domain.id());
        let topic = CString::new(name).unwrap();
        let reader = hdds_reader_create_with_qos(c_part, topic.as_ptr(), ptr::null());
        assert!(!reader.is_null());
        let seen = Arc::new(CReaderSeen::default());
        listen(reader, &seen);

        let rust_part = match placement {
            Placement::SameParticipant => Arc::clone(&*c_part.cast::<Arc<Participant>>()),
            Placement::TwoParticipants => rust_participant(&format!("{name}_rust"), domain.id()),
        };
        let writer_seen = Arc::new(WriterSeen::default());
        let writer = rust_part
            .topic::<BytePayload>(name)
            .unwrap()
            .writer()
            .qos(writer_qos)
            .with_listener(Arc::clone(&writer_seen) as Arc<dyn DataWriterListener<BytePayload>>)
            .build()
            .unwrap();

        let matched = wait_for(Duration::from_secs(8), || {
            (seen.matched.load(Ordering::SeqCst) == 1
                && writer_seen.current.load(Ordering::SeqCst) == 1)
                || (seen.incompatible.load(Ordering::SeqCst) > 0
                    && writer_seen.incompatible.load(Ordering::SeqCst) > 0)
        });
        let mut taken = Vec::new();
        for i in 0..5u8 {
            writer
                .write(&BytePayload::to_write(vec![0xC0, i, 0, 0]))
                .unwrap();
        }
        let deadline = Instant::now() + Duration::from_millis(1500);
        let mut buf = [0u8; 64];
        while Instant::now() < deadline && taken.len() < 5 {
            let mut len = 0usize;
            if hdds_reader_take(reader, buf.as_mut_ptr().cast(), buf.len(), &mut len)
                == HddsError::HddsOk
            {
                taken.push(buf[..len].to_vec());
            } else {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        drop(writer);
        hdds_reader_destroy(reader);
        if matches!(placement, Placement::TwoParticipants) {
            drop(rust_part);
        }
        hdds_participant_destroy(c_part);
        (seen, writer_seen, taken, matched)
    }
}

/// A Rust writer that set no list offers XCDR; a default C reader requests
/// XCDR2 only: both ends report the incompatibility (policy 23), nothing is
/// matched, nothing is delivered.
#[test]
fn a_default_rust_writer_and_a_default_c_reader_are_incompatible() {
    for (i, placement) in [Placement::SameParticipant, Placement::TwoParticipants]
        .into_iter()
        .enumerate()
    {
        let (seen, writer_seen, taken, settled) = rust_writer_to_default_c_reader(
            &format!("c_reader_default_writer_{i}"),
            placement,
            QoS::reliable(),
        );
        assert!(settled, "{placement:?}: both ends reported");
        assert!(
            seen.incompatible.load(Ordering::SeqCst) > 0,
            "{placement:?}: REQUESTED_INCOMPATIBLE_QOS"
        );
        assert_eq!(
            seen.last_policy.load(Ordering::SeqCst),
            POLICY_DATA_REPRESENTATION,
            "{placement:?}"
        );
        assert!(
            writer_seen.incompatible.load(Ordering::SeqCst) > 0,
            "{placement:?}: OFFERED_INCOMPATIBLE_QOS"
        );
        assert_eq!(seen.matched.load(Ordering::SeqCst), 0, "{placement:?}");
        assert!(taken.is_empty(), "{placement:?}: nothing delivered");
    }
}

/// A Rust writer that offers XCDR2 is matched with a default C reader and
/// delivers every sample.
#[test]
fn an_xcdr2_rust_writer_delivers_to_a_default_c_reader() {
    for (i, placement) in [Placement::SameParticipant, Placement::TwoParticipants]
        .into_iter()
        .enumerate()
    {
        let (seen, writer_seen, taken, settled) = rust_writer_to_default_c_reader(
            &format!("c_reader_xcdr2_writer_{i}"),
            placement,
            QoS::reliable().data_representation_xcdr2(),
        );
        assert!(settled, "{placement:?}: both ends reported");
        assert_eq!(seen.incompatible.load(Ordering::SeqCst), 0, "{placement:?}");
        assert_eq!(
            writer_seen.incompatible.load(Ordering::SeqCst),
            0,
            "{placement:?}"
        );
        let expected: Vec<Vec<u8>> = (0..5u8).map(|i| vec![0xC0, i, 0, 0]).collect();
        assert_eq!(taken, expected, "{placement:?}");
    }
}

/// A `{ uint8 b; double d; }` descriptor (APPENDABLE, the builder's
/// default) and the body `hdds_dynamic_data_encode` makes of `{7, 1.0}`.
unsafe fn aligned_sample() -> (*mut crate::dynamic_ffi::HddsTypeDescriptor, Vec<u8>) {
    use crate::dynamic_ffi::*;
    let name = CString::new("AlignedDyn").unwrap();
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
    let data = hdds_dynamic_data_new(desc);
    assert_eq!(
        hdds_dynamic_data_set_u8(data, b.as_ptr(), 7),
        HddsError::HddsOk
    );
    assert_eq!(
        hdds_dynamic_data_set_f64(data, d.as_ptr(), 1.0),
        HddsError::HddsOk
    );
    let mut buf = vec![0u8; 64];
    let mut len = 0usize;
    assert_eq!(
        hdds_dynamic_data_encode(data, buf.as_mut_ptr(), buf.len(), &mut len),
        HddsError::HddsOk
    );
    hdds_dynamic_data_destroy(data);
    buf.truncate(len);
    (desc, buf)
}

/// The XCDR2 body of `{7, 1.0}`: DHEADER (12), `b`, three bytes of padding,
/// `d` aligned at 4 (DDS-XTypes v1.3 7.4.3.5.3). The XCDR1 body would be
/// `b`, seven bytes of padding, `d` aligned at 8, with no DHEADER.
const ALIGNED_XCDR2: [u8; 16] = [12, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xf0, 0x3f];

/// What `hdds_dynamic_data_encode` produces is what a C ABI writer told the
/// type's extensibility labels it: XCDR2 (`D_CDR2_LE` for this APPENDABLE
/// struct). Read back on the wire by a raw reader of a second
/// participant, whose version is the one the receive path derives from the
/// serialized payload's encapsulation identifier; and decoded by a default
/// C reader with `hdds_dynamic_data_decode`.
#[test]
fn c_dynamic_data_travels_under_the_representation_it_is_encoded_in() {
    let domain = unique_domain();
    unsafe {
        let (desc, body) = aligned_sample();
        assert_eq!(body, ALIGNED_XCDR2, "the encoder writes XCDR2");

        let writer_part = c_participant("c_dyn_label_w", domain.id());
        let reader_part = c_participant("c_dyn_label_r", domain.id());
        let topic = CString::new("c_dyn_label").unwrap();
        // The builder's struct is APPENDABLE: its body starts with a DHEADER
        // and travels labelled D_CDR2_LE.
        let writer = hdds_writer_create_with_extensibility(
            writer_part,
            topic.as_ptr(),
            ptr::null(),
            ptr::null(),
            HDDS_EXTENSIBILITY_APPENDABLE,
        );
        assert!(!writer.is_null());
        let c_reader = hdds_reader_create_with_qos(reader_part, topic.as_ptr(), ptr::null());
        assert!(!c_reader.is_null());
        let peer = rust_participant("c_dyn_label_raw", domain.id());
        let raw = peer
            .create_raw_reader("c_dyn_label", None)
            .expect("raw reader");

        let mut on_wire = None;
        let mut c_taken = None;
        let mut buf = [0u8; 64];
        assert!(
            wait_for(Duration::from_secs(10), || {
                assert_eq!(
                    hdds_writer_write(writer, body.as_ptr().cast(), body.len()),
                    HddsError::HddsOk
                );
                std::thread::sleep(Duration::from_millis(50));
                if on_wire.is_none() {
                    on_wire = raw.try_take_raw_with_encoding().unwrap().into_iter().next();
                }
                if c_taken.is_none() {
                    let mut len = 0usize;
                    if hdds_reader_take(c_reader, buf.as_mut_ptr().cast(), buf.len(), &mut len)
                        == HddsError::HddsOk
                    {
                        c_taken = Some(buf[..len].to_vec());
                    }
                }
                on_wire.is_some() && c_taken.is_some()
            }),
            "the raw reader and the C reader receive the sample"
        );
        let (sample, version) = on_wire.unwrap();
        assert_eq!(version, hdds::CdrVersion::Xcdr2, "the label on the wire");
        assert_eq!(sample.payload, ALIGNED_XCDR2, "the bytes on the wire");

        let c_bytes = c_taken.unwrap();
        let decoded =
            crate::dynamic_ffi::hdds_dynamic_data_decode(desc, c_bytes.as_ptr(), c_bytes.len());
        assert!(!decoded.is_null());
        let b = CString::new("b").unwrap();
        let d = CString::new("d").unwrap();
        let (mut b_out, mut d_out) = (0u8, 0f64);
        assert_eq!(
            crate::dynamic_ffi::hdds_dynamic_data_get_u8(decoded, b.as_ptr(), &mut b_out),
            HddsError::HddsOk
        );
        assert_eq!(
            crate::dynamic_ffi::hdds_dynamic_data_get_f64(decoded, d.as_ptr(), &mut d_out),
            HddsError::HddsOk
        );
        assert_eq!((b_out, d_out), (7, 1.0));

        crate::dynamic_ffi::hdds_dynamic_data_destroy(decoded);
        drop(raw);
        drop(peer);
        hdds_writer_destroy(writer);
        hdds_reader_destroy(c_reader);
        crate::dynamic_ffi::hdds_type_descriptor_destroy(desc);
        hdds_participant_destroy(writer_part);
        hdds_participant_destroy(reader_part);
    }
}
