// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A DataWriter offers ONE representation, resolved when it is created, and
//! encodes every sample in it, for every reader and for its history.
//!
//! DDS-XTypes v1.3 Sec.7.6.3.1.1: "Writers offer a single representation. A
//! writer will use its offered policy to communicate with its matched
//! readers." and "The default value of the DataRepresentationQosPolicy shall
//! be an empty list of preferences. An empty list of preferences shall be
//! taken to be equivalent to a list containing the single element XCDR." The
//! policy "cannot be changed after the entity in question has been enabled".
//!
//! Before: a writer that set no list announced `[XCDR, XCDR2]` (a peer reads
//! the first element, XCDR) and chose at every write among the readers
//! discovery knew, XCDR2 as soon as one of them accepted it, XCDR2 with no
//! reader at all. A default reader, which requests both, was sent XCDR2; the
//! history kept for a late joiner was XCDR2.
//!
//! What the reader decodes is read through `DDS::decode`'s `version`, which
//! the receive path derives from the encapsulation identifier of the
//! serialized payload (DDS-XTypes v1.3 Sec.7.6.3.1.2): the identifier the
//! writer put on the wire, as the reader read it.

use hdds::api::DDS;
use hdds::core::types::TypeDescriptor;
use hdds::dds::{DataReaderListener, DataWriterListener, PublicationMatchedStatus};
use hdds::dds::{RequestedIncompatibleQosStatus, SubscriptionMatchedStatus};
use hdds::test_support::domains::unique_domain;
use hdds::{CdrVersion, Participant, QoS, TransportMode};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Every (value, version) a reader of this binary decoded.
static DECODED: Mutex<Vec<(i64, CdrVersion)>> = Mutex::new(Vec::new());

/// The versions `value` was decoded as, each once (the receive path may
/// decode one sample more than once, for its key and for `take`).
fn decoded_as(value: i64) -> Vec<CdrVersion> {
    let mut versions: Vec<CdrVersion> = Vec::new();
    for (v, version) in DECODED.lock().unwrap().iter() {
        if *v == value && !versions.contains(version) {
            versions.push(*version);
        }
    }
    versions
}

fn encode_i64(value: i64, buf: &mut [u8]) -> hdds::api::Result<usize> {
    if buf.len() < 8 {
        return Err(hdds::api::Error::BufferTooSmall);
    }
    buf[..8].copy_from_slice(&value.to_le_bytes());
    Ok(8)
}

fn decode_i64(buf: &[u8], version: CdrVersion) -> hdds::api::Result<i64> {
    let bytes: [u8; 8] = buf
        .get(..8)
        .and_then(|b| b.try_into().ok())
        .ok_or(hdds::api::Error::BufferTooSmall)?;
    let value = i64::from_le_bytes(bytes);
    DECODED.lock().unwrap().push((value, version));
    Ok(value)
}

/// One `i64`: the same bytes under XCDR and XCDR2, so the only trace of the
/// version is the encapsulation identifier.
#[derive(Debug, Clone)]
struct Recorded {
    value: i64,
}

impl DDS for Recorded {
    fn type_descriptor() -> &'static TypeDescriptor {
        static DESCRIPTOR: TypeDescriptor = TypeDescriptor {
            type_id: 0x5EC0_0001,
            type_name: "OneRepresentationRecorded",
            size_bytes: 8,
            alignment: 8,
            is_variable_size: false,
            fields: &[],
        };
        &DESCRIPTOR
    }
    fn encode(&self, buf: &mut [u8], _version: CdrVersion) -> hdds::api::Result<usize> {
        encode_i64(self.value, buf)
    }
    fn decode(buf: &[u8], version: CdrVersion) -> hdds::api::Result<Self> {
        decode_i64(buf, version).map(|value| Self { value })
    }
    /// One `i64` at offset 0: the same body under XCDR1 and XCDR2.
    fn encodes_xcdr1_natively() -> bool {
        true
    }
}

/// A hand-written `{ u32 tag; f64 value }` that relies on the `Cdr2Encode`
/// defaults, as docs/api/rust.md shows for a type with one wire format, and
/// says nothing about XCDR1 (`DDS::encodes_xcdr1_natively`). Its
/// `encode_xcdr1_le` delegates to the XCDR2 path: the `f64` at offset 4,
/// where XCDR1 puts it at 8. Fixed size, 8-byte aligned: the descriptor
/// guess takes it for a native XCDR1 encoder, which it is not.
#[derive(Debug, Clone, PartialEq)]
struct SaysNothing {
    tag: u32,
    value: f64,
}

impl hdds::core::ser::Cdr2Encode for SaysNothing {
    fn encode_cdr2_le_at(
        &self,
        dst: &mut [u8],
        offset: &mut usize,
    ) -> Result<(), hdds::core::ser::CdrError> {
        self.tag.encode_cdr2_le_at(dst, offset)?;
        self.value.encode_cdr2_le_at(dst, offset)
    }
    fn max_cdr2_size(&self) -> usize {
        12
    }
}

impl hdds::core::ser::Cdr2Decode for SaysNothing {
    fn decode_cdr2_le_at(
        src: &[u8],
        offset: &mut usize,
    ) -> Result<Self, hdds::core::ser::CdrError> {
        let tag = u32::decode_cdr2_le_at(src, offset)?;
        let value = f64::decode_cdr2_le_at(src, offset)?;
        Ok(Self { tag, value })
    }
}

impl DDS for SaysNothing {
    fn type_descriptor() -> &'static TypeDescriptor {
        static DESCRIPTOR: TypeDescriptor = TypeDescriptor {
            type_id: 0x5EC0_0003,
            type_name: "OneRepresentationSaysNothing",
            size_bytes: 16,
            alignment: 8,
            is_variable_size: false,
            fields: &[],
        };
        &DESCRIPTOR
    }
    fn encode(&self, buf: &mut [u8], version: CdrVersion) -> hdds::api::Result<usize> {
        use hdds::core::ser::Cdr2Encode;
        let written = match version {
            CdrVersion::Xcdr1 => self.encode_xcdr1_le(buf),
            CdrVersion::Xcdr2 => self.encode_xcdr2_le(buf),
        };
        written.map_err(|_| hdds::api::Error::BufferTooSmall)
    }
    fn decode(buf: &[u8], version: CdrVersion) -> hdds::api::Result<Self> {
        use hdds::core::ser::Cdr2Decode;
        let decoded = Self::decode_cdr2_le(buf)
            .map(|(v, _)| v)
            .map_err(|_| hdds::api::Error::SerializationError)?;
        DECODED
            .lock()
            .unwrap()
            .push((i64::from(decoded.tag), version));
        Ok(decoded)
    }
}

/// A type that declares it does not encode XCDR natively
/// (`DDS::encodes_xcdr1_natively`).
#[derive(Debug, Clone)]
struct RefusesXcdr {
    value: i64,
}

impl DDS for RefusesXcdr {
    fn type_descriptor() -> &'static TypeDescriptor {
        static DESCRIPTOR: TypeDescriptor = TypeDescriptor {
            type_id: 0x5EC0_0002,
            type_name: "OneRepresentationRefusesXcdr",
            size_bytes: 8,
            alignment: 8,
            is_variable_size: false,
            fields: &[],
        };
        &DESCRIPTOR
    }
    fn encode(&self, buf: &mut [u8], _version: CdrVersion) -> hdds::api::Result<usize> {
        encode_i64(self.value, buf)
    }
    fn decode(buf: &[u8], version: CdrVersion) -> hdds::api::Result<Self> {
        decode_i64(buf, version).map(|value| Self { value })
    }
    fn encodes_xcdr1_natively() -> bool {
        false
    }
}

#[derive(Default)]
struct Seen {
    current: AtomicI32,
    incompat: AtomicU32,
}

impl<T: DDS> DataWriterListener<T> for Seen {
    fn on_publication_matched(&self, status: PublicationMatchedStatus) {
        self.current
            .store(status.current_count as i32, Ordering::SeqCst);
    }
    fn on_offered_incompatible_qos(&self, _policy_id: u32, _policy_name: &str) {
        self.incompat.fetch_add(1, Ordering::SeqCst);
    }
}

impl<T: DDS> DataReaderListener<T> for Seen {
    fn on_subscription_matched(&self, status: SubscriptionMatchedStatus) {
        self.current
            .store(status.current_count as i32, Ordering::SeqCst);
    }
    fn on_requested_incompatible_qos(&self, _status: RequestedIncompatibleQosStatus) {
        self.incompat.fetch_add(1, Ordering::SeqCst);
    }
}

fn wait_for(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    done()
}

fn participant(name: &str, domain: u32, mode: TransportMode) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain)
        .with_transport(mode)
        .build()
        .expect("participant")
}

#[derive(Clone, Copy, Debug)]
enum Placement {
    /// Writer and reader in two UDP participants.
    TwoParticipants,
    /// Writer and reader in one UDP participant.
    OneParticipant,
    /// Writer and reader in one IntraProcess participant.
    InProcess,
}

const PLACEMENTS: [Placement; 3] = [
    Placement::TwoParticipants,
    Placement::OneParticipant,
    Placement::InProcess,
];

fn pair(name: &str, placement: Placement) -> (Arc<Participant>, Arc<Participant>) {
    let domain = unique_domain();
    let (mode, two) = match placement {
        Placement::TwoParticipants => (TransportMode::UdpMulticast, true),
        Placement::OneParticipant => (TransportMode::UdpMulticast, false),
        Placement::InProcess => (TransportMode::IntraProcess, false),
    };
    let publisher = participant(&format!("{name}_pub"), domain.id(), mode);
    let subscriber = if two {
        participant(&format!("{name}_sub"), domain.id(), mode)
    } else {
        Arc::clone(&publisher)
    };
    // The lease lives as long as the participants need the domain: the
    // test process ends with them.
    std::mem::forget(domain);
    (publisher, subscriber)
}

/// Write `value` from a writer of `writer_qos` to a reader of `reader_qos`
/// and return what the reader decoded it as, after both ends reported
/// what they report.
fn deliver<T: DDS + Clone>(
    name: &str,
    placement: Placement,
    writer_qos: QoS,
    reader_qos: QoS,
    sample: T,
    value: i64,
) -> Vec<CdrVersion> {
    let (publisher, subscriber) = pair(name, placement);
    let writer_seen = Arc::new(Seen::default());
    let reader_seen = Arc::new(Seen::default());
    let writer = publisher
        .topic::<T>(name)
        .unwrap()
        .writer()
        .qos(writer_qos)
        .with_listener(Arc::clone(&writer_seen) as Arc<dyn DataWriterListener<T>>)
        .build()
        .unwrap();
    let reader = subscriber
        .topic::<T>(name)
        .unwrap()
        .reader()
        .qos(reader_qos)
        .with_listener(Arc::clone(&reader_seen) as Arc<dyn DataReaderListener<T>>)
        .build()
        .unwrap();
    if !matches!(placement, Placement::InProcess) {
        assert!(
            wait_for(Duration::from_secs(5), || {
                writer_seen.current.load(Ordering::SeqCst) == 1
                    && reader_seen.current.load(Ordering::SeqCst) == 1
            }),
            "{name} {placement:?}: both ends match"
        );
    }
    writer.write(&sample).unwrap();
    assert!(
        wait_for(Duration::from_secs(3), || reader.take().unwrap().is_some()),
        "{name} {placement:?}: the sample is delivered"
    );
    decoded_as(value)
}

/// A writer that set no list shows the list it offers, `[XCDR]`, from
/// creation on, whoever is or will be matched.
#[test]
fn a_default_writer_shows_the_xcdr_it_offers() {
    let p = participant(
        "one_repr_get_qos",
        unique_domain().id(),
        TransportMode::IntraProcess,
    );
    let writer = p
        .topic::<Recorded>("one_repr_get_qos")
        .unwrap()
        .writer()
        .qos(QoS::reliable())
        .build()
        .unwrap();
    assert_eq!(writer.qos().data_representation, vec![0x0000]);
}

/// A writer that set a list keeps it: the first element is what it offers
/// and encodes, the rest carries no meaning (Sec.7.6.3.1.1).
#[test]
fn a_writer_that_set_a_list_keeps_it() {
    let p = participant(
        "one_repr_explicit",
        unique_domain().id(),
        TransportMode::IntraProcess,
    );
    let mut qos = QoS::reliable();
    qos.data_representation = vec![0x0002, 0x0000];
    let writer = p
        .topic::<Recorded>("one_repr_explicit")
        .unwrap()
        .writer()
        .qos(qos)
        .build()
        .unwrap();
    assert_eq!(writer.qos().data_representation, vec![0x0002, 0x0000]);
}

/// A writer that set no list, of a type that does not encode XCDR natively,
/// offers XCDR2: the one representation it can serialize correctly (a
/// writer of XTYPES 1.2 and later "Shall generate or include run-code that
/// can serialize using version 2 encodings").
#[test]
fn a_default_writer_of_a_type_that_refuses_xcdr_offers_xcdr2() {
    let p = participant(
        "one_repr_refuses",
        unique_domain().id(),
        TransportMode::IntraProcess,
    );
    let writer = p
        .topic::<RefusesXcdr>("one_repr_refuses")
        .unwrap()
        .writer()
        .qos(QoS::reliable())
        .build()
        .unwrap();
    assert_eq!(writer.qos().data_representation, vec![0x0002]);
}

/// A default writer and a default reader: the reader requests both, the
/// writer offers XCDR, the sample travels as XCDR, in every placement.
#[test]
fn a_default_writer_encodes_xcdr_for_a_default_reader() {
    for (i, placement) in PLACEMENTS.into_iter().enumerate() {
        let value = 1_000 + i as i64;
        let versions = deliver(
            &format!("one_repr_default_default_{i}"),
            placement,
            QoS::reliable(),
            QoS::reliable(),
            Recorded { value },
            value,
        );
        assert_eq!(versions, vec![CdrVersion::Xcdr1], "{placement:?}");
    }
}

/// A writer that offers XCDR2 encodes XCDR2 for the same default reader.
#[test]
fn an_xcdr2_writer_encodes_xcdr2_for_a_default_reader() {
    for (i, placement) in PLACEMENTS.into_iter().enumerate() {
        let value = 2_000 + i as i64;
        let versions = deliver(
            &format!("one_repr_x2_default_{i}"),
            placement,
            QoS::reliable().data_representation_xcdr2(),
            QoS::reliable(),
            Recorded { value },
            value,
        );
        assert_eq!(versions, vec![CdrVersion::Xcdr2], "{placement:?}");
    }
}

/// The default writer of a type that refuses XCDR encodes the XCDR2 it
/// offers.
#[test]
fn a_default_writer_of_a_type_that_refuses_xcdr_encodes_xcdr2() {
    for (i, placement) in PLACEMENTS.into_iter().enumerate() {
        let value = 3_000 + i as i64;
        let versions = deliver(
            &format!("one_repr_refuses_default_{i}"),
            placement,
            QoS::reliable(),
            QoS::reliable(),
            RefusesXcdr { value },
            value,
        );
        assert_eq!(versions, vec![CdrVersion::Xcdr2], "{placement:?}");
    }
}

/// What a TRANSIENT_LOCAL writer wrote before any reader existed is
/// replayed to a late reader in the representation the writer offers.
/// Before: with no reader known the writer chose XCDR2, and the history
/// replayed XCDR2.
#[test]
fn history_replayed_to_a_late_reader_is_in_the_offered_representation() {
    let domain = unique_domain();
    let publisher = participant(
        "one_repr_history_pub",
        domain.id(),
        TransportMode::UdpMulticast,
    );
    let subscriber = participant(
        "one_repr_history_sub",
        domain.id(),
        TransportMode::UdpMulticast,
    );
    let topic = "one_repr_history";
    let writer = publisher
        .topic::<Recorded>(topic)
        .unwrap()
        .writer()
        .qos(QoS::reliable().transient_local().keep_last(4))
        .build()
        .unwrap();
    let value = 4_000;
    writer.write(&Recorded { value }).unwrap();
    let reader = subscriber
        .topic::<Recorded>(topic)
        .unwrap()
        .reader()
        .qos(QoS::reliable().transient_local().keep_last(4))
        .build()
        .unwrap();
    assert!(
        wait_for(Duration::from_secs(5), || reader.take().unwrap().is_some()),
        "the history reaches the late reader"
    );
    assert_eq!(decoded_as(value), vec![CdrVersion::Xcdr1]);
}

/// A hand-written type that says nothing about XCDR1 is not taken to encode
/// it: a writer that set no list offers XCDR2, shows it, and the sample
/// travels as XCDR2 in every placement. Before, the descriptor guess took a
/// fixed-size `{u32, f64}` for a native XCDR1 encoder: the writer offered
/// XCDR1 and sent the XCDR2 layout (the `f64` at 4) labelled XCDR1.
#[test]
fn a_type_that_says_nothing_about_xcdr1_offers_and_encodes_xcdr2() {
    let p = participant(
        "one_repr_says_nothing_qos",
        unique_domain().id(),
        TransportMode::IntraProcess,
    );
    let writer = p
        .topic::<SaysNothing>("one_repr_says_nothing_qos")
        .unwrap()
        .writer()
        .qos(QoS::reliable())
        .build()
        .unwrap();
    assert_eq!(writer.qos().data_representation, vec![0x0002]);
    for (i, placement) in PLACEMENTS.into_iter().enumerate() {
        let tag = 5_000 + i as u32;
        let versions = deliver(
            &format!("one_repr_says_nothing_{i}"),
            placement,
            QoS::reliable(),
            QoS::reliable(),
            SaysNothing { tag, value: 1.5 },
            i64::from(tag),
        );
        assert_eq!(versions, vec![CdrVersion::Xcdr2], "{placement:?}");
    }
}

/// A raw reader (hdds_viewer, the gateways, the recorder) carries opaque
/// bytes and keeps the version the encapsulation identifier names: it is
/// matched with an XCDR1 writer and reports XCDR1, in one participant and
/// across two. A raw type that did not declare XCDR1 would refuse the pair.
#[test]
fn a_raw_reader_takes_xcdr1_samples_and_reports_their_version() {
    for (i, placement) in [Placement::TwoParticipants, Placement::OneParticipant]
        .into_iter()
        .enumerate()
    {
        let topic = format!("one_repr_raw_{i}");
        let (publisher, subscriber) = pair(&topic, placement);
        let raw = subscriber
            .create_raw_reader_with_type(
                &topic,
                "OneRepresentationRecorded",
                Some(QoS::reliable()),
                None,
                None,
            )
            .unwrap();
        let writer = publisher
            .topic::<Recorded>(&topic)
            .unwrap()
            .writer()
            .qos(QoS::reliable())
            .build()
            .unwrap();
        let mut taken = Vec::new();
        assert!(
            wait_for(Duration::from_secs(5), || {
                writer.write(&Recorded { value: 6_000 }).unwrap();
                std::thread::sleep(Duration::from_millis(50));
                taken.extend(raw.try_take_raw_with_encoding().unwrap());
                !taken.is_empty()
            }),
            "{placement:?}: the raw reader receives"
        );
        assert!(
            taken.iter().all(|(_, v)| *v == CdrVersion::Xcdr1),
            "{placement:?}"
        );
        assert_eq!(taken[0].0.payload, 6_000i64.to_le_bytes(), "{placement:?}");
    }
}

/// A twin of `SaysNothing` (same type name and layout) that declares XCDR1:
/// a remote writer whose default is XCDR.
#[derive(Debug, Clone)]
struct SaysNothingTwin;

impl DDS for SaysNothingTwin {
    fn type_descriptor() -> &'static TypeDescriptor {
        SaysNothing::type_descriptor()
    }
    fn encode(&self, buf: &mut [u8], _version: CdrVersion) -> hdds::api::Result<usize> {
        encode_i64(0, buf)
    }
    fn decode(_buf: &[u8], _version: CdrVersion) -> hdds::api::Result<Self> {
        Ok(Self)
    }
    fn encodes_xcdr1_natively() -> bool {
        true
    }
}

/// A reader that set no list, of a type that does not decode XCDR natively,
/// requests XCDR2 alone (DDS-XTypes v1.3 Sec.7.6.3.1.1: a reader requests
/// XCDR only when it can deserialize it), shows it, and announces it: a
/// writer of another participant that offers XCDR reports
/// OFFERED_INCOMPATIBLE_QOS as the reader reports REQUESTED_INCOMPATIBLE_QOS.
/// Before, the reader refused the pair alone while announcing
/// `[XCDR, XCDR2]`: the writer counted it matched.
#[test]
fn a_default_reader_of_a_type_that_says_nothing_requests_xcdr2() {
    let domain = unique_domain();
    let publisher = participant(
        "one_repr_reader_x2_pub",
        domain.id(),
        TransportMode::UdpMulticast,
    );
    let subscriber = participant(
        "one_repr_reader_x2_sub",
        domain.id(),
        TransportMode::UdpMulticast,
    );
    let topic = "one_repr_reader_x2";
    let reader_seen = Arc::new(Seen::default());
    let reader = subscriber
        .topic::<SaysNothing>(topic)
        .unwrap()
        .reader()
        .qos(QoS::reliable())
        .with_listener(Arc::clone(&reader_seen) as Arc<dyn DataReaderListener<SaysNothing>>)
        .build()
        .unwrap();
    assert_eq!(reader.qos().data_representation, vec![0x0002]);
    // A reader of a type that says so keeps the default request.
    let native_reader = subscriber
        .topic::<Recorded>("one_repr_reader_native")
        .unwrap()
        .reader()
        .qos(QoS::reliable())
        .build()
        .unwrap();
    assert!(native_reader.qos().data_representation.is_empty());

    let writer_seen = Arc::new(Seen::default());
    let _writer = publisher
        .topic::<SaysNothingTwin>(topic)
        .unwrap()
        .writer()
        .qos(QoS::reliable())
        .with_listener(Arc::clone(&writer_seen) as Arc<dyn DataWriterListener<SaysNothingTwin>>)
        .build()
        .unwrap();
    assert!(
        wait_for(Duration::from_secs(5), || {
            writer_seen.incompat.load(Ordering::SeqCst) > 0
                && reader_seen.incompat.load(Ordering::SeqCst) > 0
        }),
        "both ends report the incompatibility"
    );
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(writer_seen.current.load(Ordering::SeqCst), 0);
    assert_eq!(reader_seen.current.load(Ordering::SeqCst), 0);
}
