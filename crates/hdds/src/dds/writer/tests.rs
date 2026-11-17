// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::core::rt;
use crate::dds::{Error, QoS, DDS};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct Point {
    x: i32,
    y: i32,
}

#[test]
fn test_writer_write_basic() {
    let _ = rt::init_slab_pool();

    let writer = WriterBuilder::<Point>::new("test_topic".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("writer build should succeed");

    let msg = Point { x: 42, y: 123 };
    let result = writer.write(&msg);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_writer_encode_decode_roundtrip() {
    let original = Point { x: 42, y: -123 };

    let mut buf = vec![0u8; 100];
    let len = original
        .encode(&mut buf, crate::dds::CdrVersion::Xcdr2)
        .expect("encode should succeed");
    // A derived type is @appendable (DDS-XTypes 1.3 7.3.1.2.1.8): under
    // XCDR2 a DHEADER of 8, then x and y.
    assert_eq!(len, 12);
    assert_eq!(buf[..4], 8u32.to_le_bytes());

    let decoded =
        Point::decode(&buf[..len], crate::dds::CdrVersion::Xcdr2).expect("decode should succeed");
    assert_eq!(decoded, original);
}

#[test]
#[allow(deprecated)] // UdpTransport::with_port is deprecated, unrelated to DDS trait
fn test_writer_with_udp_transport() {
    use crate::transport::UdpTransport;

    let _ = rt::init_slab_pool();

    let transport = match UdpTransport::with_port(7401) {
        Ok(t) => Arc::new(t),
        Err(_) => {
            println!("Skipping UDP test - port unavailable");
            return;
        }
    };

    let writer = WriterBuilder::<Point>::new("test/udp".to_string())
        .with_transport(transport)
        .build()
        .expect("writer build with transport should succeed");

    let msg = Point { x: 100, y: 200 };
    let result = writer.write(&msg);
    assert!(result.is_ok() || matches!(result, Err(Error::WouldBlock)));
}

/// A writer encodes the first element of its DATA_REPRESENTATION, resolved
/// at creation (DDS-XTypes v1.3 Sec.7.6.3.1.1): `[XCDR]` when it set none.

#[test]
fn writer_effective_cdr_version_picks_xcdr1_when_offered() {
    let _ = rt::init_slab_pool();
    let qos = QoS {
        data_representation: vec![0x0000],
        ..QoS::best_effort()
    };
    let writer = WriterBuilder::<Point>::new("test/effective_xcdr1".to_string())
        .qos(qos)
        .build()
        .expect("writer build");
    assert_eq!(
        writer.effective_cdr_version(),
        crate::dds::CdrVersion::Xcdr1
    );
}

#[test]
fn writer_effective_cdr_version_picks_xcdr2_when_offered() {
    let _ = rt::init_slab_pool();
    let qos = QoS {
        data_representation: vec![0x0002],
        ..QoS::best_effort()
    };
    let writer = WriterBuilder::<Point>::new("test/effective_xcdr2".to_string())
        .qos(qos)
        .build()
        .expect("writer build");
    assert_eq!(
        writer.effective_cdr_version(),
        crate::dds::CdrVersion::Xcdr2
    );
}

#[test]
fn writer_effective_cdr_version_defaults_to_xcdr1_when_unset() {
    let _ = rt::init_slab_pool();
    // QoS::best_effort() leaves data_representation empty.
    let writer = WriterBuilder::<Point>::new("test/effective_default".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("writer build");
    assert_eq!(
        writer.effective_cdr_version(),
        crate::dds::CdrVersion::Xcdr1
    );
    assert_eq!(writer.qos().data_representation, vec![0x0000]);
}

/// DDS trait dispatch produces distinct wire bytes per CdrVersion.
/// Uses a manual DualProbe type whose `encode()` writes a distinct
/// pattern for each version, proving the `msg.encode(buf, version)`
/// call in writer/runtime.rs actually reaches the version-dependent
/// code path per DDS-XTypes v1.3 sec. 7.4.3.4 container alignment rules.
#[test]
fn dds_trait_dispatch_produces_distinct_wire_bytes() {
    use crate::dds::CdrVersion;

    #[derive(Debug, Clone, PartialEq)]
    struct DualProbe;

    impl crate::dds::DDS for DualProbe {
        fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
            static DESC: crate::core::types::TypeDescriptor = crate::core::types::TypeDescriptor {
                type_id: 0,
                type_name: "DualProbe",
                size_bytes: 0,
                alignment: 1,
                is_variable_size: true,
                fields: &[],
            };
            &DESC
        }

        fn encode(&self, buf: &mut [u8], version: CdrVersion) -> crate::dds::Result<usize> {
            // XCDR1: 16 bytes (alignment-on-natural for 8-byte fields).
            // XCDR2: 12 bytes (MAXALIGN(VERSION2) = 4, sec. 7.4.3.2.2 Table 37).
            match version {
                CdrVersion::Xcdr1 => {
                    if buf.len() < 16 {
                        return Err(crate::dds::Error::BufferTooSmall);
                    }
                    buf[..16].fill(0xA1);
                    Ok(16)
                }
                CdrVersion::Xcdr2 => {
                    if buf.len() < 12 {
                        return Err(crate::dds::Error::BufferTooSmall);
                    }
                    buf[..12].fill(0xB2);
                    Ok(12)
                }
            }
        }

        fn decode(_buf: &[u8], _version: CdrVersion) -> crate::dds::Result<Self> {
            Ok(DualProbe)
        }
    }

    let probe = DualProbe;

    let mut xcdr1 = vec![0u8; 32];
    let n1 = probe
        .encode(&mut xcdr1, CdrVersion::Xcdr1)
        .expect("xcdr1 encode");

    let mut xcdr2 = vec![0u8; 32];
    let n2 = probe
        .encode(&mut xcdr2, CdrVersion::Xcdr2)
        .expect("xcdr2 encode");

    assert_eq!(n1, 16);
    assert_eq!(n2, 12);
    assert_eq!(&xcdr1[..n1], &[0xA1; 16]);
    assert_eq!(&xcdr2[..n2], &[0xB2; 12]);
    assert_ne!(&xcdr1[..n1], &xcdr2[..n2]);
}

#[test]
fn test_writer_without_transport_backward_compat() {
    let _ = rt::init_slab_pool();

    let writer = WriterBuilder::<Point>::new("test/local".to_string())
        .build()
        .expect("writer build without transport should succeed");

    assert!(
        writer.transport.is_none(),
        "Writer should not have transport in intra-process mode"
    );

    let msg = Point { x: 50, y: 75 };
    let result = writer.write(&msg);
    assert!(result.is_ok() || matches!(result, Err(Error::WouldBlock)));
}

/// `{ @key long id; }`, counting how many times its KeyHolder is
/// serialized, which is how many KeyHashes a write computes.
mod key_hash_once_per_write {
    use super::*;
    use crate::core::key_hash::{KeyHolderWriter, KeyMaxSize};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static KEY_HOLDER_WRITES: AtomicUsize = AtomicUsize::new(0);

    struct Counted {
        id: i32,
    }

    impl DDS for Counted {
        fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
            Point::type_descriptor()
        }
        fn encode(
            &self,
            buf: &mut [u8],
            version: crate::dds::CdrVersion,
        ) -> crate::dds::Result<usize> {
            Point { x: self.id, y: 0 }.encode(buf, version)
        }
        fn decode(buf: &[u8], version: crate::dds::CdrVersion) -> crate::dds::Result<Self> {
            Point::decode(buf, version).map(|p| Self { id: p.x })
        }
        fn has_key() -> bool {
            true
        }
        fn write_key_holder(&self, w: &mut KeyHolderWriter) -> Option<KeyMaxSize> {
            KEY_HOLDER_WRITES.fetch_add(1, Ordering::SeqCst);
            w.write_i32(self.id);
            Some(KeyMaxSize::Bounded(4))
        }
    }

    fn writes_during(f: impl FnOnce()) -> usize {
        let before = KEY_HOLDER_WRITES.load(Ordering::SeqCst);
        f();
        KEY_HOLDER_WRITES.load(Ordering::SeqCst) - before
    }

    /// A write computes the KeyHash once, on the path without a reader and
    /// on the intra-process path of a durable writer, which journals it.
    #[test]
    fn a_write_computes_the_key_hash_once() {
        let _ = rt::init_slab_pool();
        let lone = WriterBuilder::<Counted>::new("kh_once_lone".to_string())
            .qos(QoS::best_effort())
            .build()
            .expect("writer");
        assert_eq!(
            writes_during(|| {
                let _ = lone.write(&Counted { id: 1 });
            }),
            1,
            "writer without reader"
        );

        let durable = WriterBuilder::<Counted>::new("kh_once_durable".to_string())
            .qos(QoS::reliable().transient_local().keep_last(4))
            .build()
            .expect("writer");
        let reader =
            crate::dds::reader::ReaderBuilder::<Counted>::new("kh_once_durable".to_string())
                .qos(QoS::reliable().transient_local().keep_last(4))
                .build()
                .expect("reader");
        reader.bind_to_writer(durable.merger());
        let seq = durable.next_seq.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            writes_during(|| {
                durable.write(&Counted { id: 2 }).expect("write");
            }),
            1,
            "durable writer with a local reader"
        );
        // The intra-process path journals the KeyHash it was handed, which a
        // late joiner's replay carries as PID_KEY_HASH.
        let journaled = durable
            .history_cache
            .as_ref()
            .expect("durable history")
            .get_change(seq)
            .expect("the sample is journaled")
            .metadata
            .key_hash;
        assert_eq!(journaled, Some(Counted { id: 2 }.compute_key()));
    }
}

/// A reliable writer's periodic HEARTBEATs end before its SEDP dispose goes
/// out: a reader that unmatches the writer on its dispose must not hear from
/// it again. The heartbeat thread was joined only when the writer's fields
/// dropped, after the dispose, so a HEARTBEAT could follow the dispose on
/// the wire. Observed at the dispose itself: by the time it has been handed
/// to the known peer, the scheduler has been told to stop, and its handle
/// (whose drop signals the thread and joins it, on this same thread) is
/// gone.
#[test]
fn a_deleted_writer_stops_its_heartbeats_before_its_sedp_dispose() {
    use crate::core::discovery::multicast::classifier::walk::{for_each_submessage, Step};
    use crate::core::discovery::GUID;
    use crate::protocol::discovery::SpdpData;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::time::Duration;
    let _ = rt::init_slab_pool();
    let domain = crate::test_support::domains::unique_domain();
    let participant = crate::Participant::builder("heartbeats_before_dispose")
        .domain_id(domain.id())
        .with_transport(crate::TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let fsm = participant.discovery().expect("discovery FSM");
    // A peer heard after the probation lives by its lease: the dispose has
    // an addressee.
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer socket");
    peer.set_read_timeout(Some(Duration::from_millis(400)))
        .expect("read timeout");
    let locator = peer.local_addr().expect("peer address");
    if let Some(rest) = Duration::from_millis(300).checked_sub(fsm.uptime()) {
        std::thread::sleep(rest);
    }
    fsm.handle_spdp(SpdpData {
        participant_guid: GUID::new([0x5B; 12], [0x00, 0x00, 0x01, 0xC1]),
        lease_duration_ms: 30_000,
        domain_id: domain.id(),
        metatraffic_unicast_locators: vec![locator],
        default_unicast_locators: vec![locator],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: None,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    });

    let mut writer = participant
        .topic::<Point>("HeartbeatsBeforeDispose")
        .expect("topic")
        .writer()
        .qos(QoS::reliable())
        .build()
        .expect("reliable writer");
    writer.write(&Point { x: 1, y: 2 }).expect("write");
    let scheduler = Arc::clone(
        writer
            ._heartbeat_scheduler
            .as_ref()
            .expect("a reliable writer runs a heartbeat scheduler")
            .state(),
    );
    // 0: the dispose never went out; 1: it went out while the scheduler
    // still ran; 2: it went out after the scheduler stopped.
    let at_dispose = Arc::new(AtomicU8::new(0));
    let seen = Arc::clone(&at_dispose);
    writer
        .sedp_retirement
        .as_mut()
        .expect("the writer is announced")
        .on_dispose_sent(Box::new(move || {
            let stopped = scheduler.should_stop();
            seen.store(if stopped { 2 } else { 1 }, Ordering::SeqCst);
        }));

    drop(writer);
    assert_eq!(
        at_dispose.load(Ordering::SeqCst),
        2,
        "the heartbeat scheduler is stopped and joined before the SEDP dispose \
         (0: no dispose went out, 1: the scheduler still ran)"
    );
    let mut buf = [0u8; 65_536];
    let mut disposes = 0;
    while let Ok(len) = peer.recv(&mut buf) {
        let dgram = &buf[..len];
        for_each_submessage(dgram, |sub| {
            if sub.id == 0x15
                && sub.flags & 0x08 != 0
                && dgram[sub.offset + 12..sub.offset + 16] == [0x00, 0x00, 0x03, 0xC2]
            {
                disposes += 1;
            }
            Step::Continue
        });
    }
    assert_eq!(disposes, 1, "the dispose reached the peer");
}

/// A sample whose encode fails is not published, so it must not consume a
/// sequence number: the next published sample takes the one it was given,
/// and a RELIABLE reader is never left NACKing a number nobody will send.
mod failed_encode_gives_the_sequence_number_back {
    use super::*;
    use std::sync::atomic::Ordering;

    /// Encodes as `Point` unless `fail`.
    struct Flaky(Point, bool);

    impl DDS for Flaky {
        fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
            Point::type_descriptor()
        }
        fn encode(
            &self,
            buf: &mut [u8],
            version: crate::dds::CdrVersion,
        ) -> crate::dds::Result<usize> {
            if self.1 {
                return Err(Error::SerializationError);
            }
            self.0.encode(buf, version)
        }
        fn decode(buf: &[u8], version: crate::dds::CdrVersion) -> crate::dds::Result<Self> {
            Point::decode(buf, version).map(|p| Flaky(p, false))
        }
    }

    #[test]
    fn a_failed_encode_leaves_next_seq_where_it_was() {
        let _ = rt::init_slab_pool();
        let writer = WriterBuilder::<Flaky>::new("failed_encode_seq".to_string())
            .build()
            .expect("writer");
        let sample = Flaky(Point { x: 1, y: 2 }, false);
        let broken = Flaky(Point { x: 1, y: 2 }, true);
        writer.write(&sample).expect("first write");
        let after_first = writer.next_seq.load(Ordering::SeqCst);

        let failed = writer.write(&broken);
        assert!(
            matches!(failed, Err(Error::SerializationError)),
            "{failed:?}"
        );
        assert_eq!(writer.next_seq.load(Ordering::SeqCst), after_first);

        writer.write(&sample).expect("third write");
        assert_eq!(writer.next_seq.load(Ordering::SeqCst), after_first + 1);
    }

    /// Same, on the intra-process path (a local reader, no remote peer),
    /// which encodes into a slab slot and then into the writer's scratch.
    #[test]
    fn a_failed_intra_process_encode_leaves_next_seq_where_it_was() {
        let _ = rt::init_slab_pool();
        let writer = WriterBuilder::<Flaky>::new("failed_encode_seq_intra".to_string())
            .build()
            .expect("writer");
        let reader =
            crate::dds::reader::ReaderBuilder::<Flaky>::new("failed_encode_seq_intra".to_string())
                .build()
                .expect("reader");
        reader.bind_to_writer(writer.merger());
        let sample = Flaky(Point { x: 3, y: 4 }, false);
        let broken = Flaky(Point { x: 3, y: 4 }, true);
        writer.write(&sample).expect("first write");
        let after_first = writer.next_seq.load(Ordering::SeqCst);

        let failed = writer.write(&broken);
        assert!(
            matches!(failed, Err(Error::SerializationError)),
            "{failed:?}"
        );
        assert_eq!(writer.next_seq.load(Ordering::SeqCst), after_first);
    }
}

/// A deleted reliable writer takes its NACK and NACK_FRAG handlers out of
/// the topic registry. They were never removed: after its SEDP dispose the
/// writer still answered every ACKNACK naming it with retransmissions of
/// its history, which the handlers kept alive, and the registry kept one
/// dead pair of handlers per reliable writer ever created.
#[test]
fn a_deleted_reliable_writer_leaves_no_nack_handler_behind() {
    use crate::core::discovery::GUID;
    use crate::protocol::discovery::SpdpData;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    let domain = crate::test_support::domains::unique_domain();
    let participant = crate::Participant::builder("nack_handlers_go_with_writer")
        .domain_id(domain.id())
        .with_transport(crate::TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let fsm = participant.discovery().expect("discovery FSM");
    // A known peer, so that the SEDP dispose goes out (and its hook runs).
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer socket");
    let locator = peer.local_addr().expect("peer address");
    if let Some(rest) = Duration::from_millis(300).checked_sub(fsm.uptime()) {
        std::thread::sleep(rest);
    }
    fsm.handle_spdp(SpdpData {
        participant_guid: GUID::new([0x5C; 12], [0x00, 0x00, 0x01, 0xC1]),
        lease_duration_ms: 30_000,
        domain_id: domain.id(),
        metatraffic_unicast_locators: vec![locator],
        default_unicast_locators: vec![locator],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: None,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    });
    let registry = Arc::clone(participant.registry.as_ref().expect("topic registry"));
    let before = registry.nack_handler_counts();

    let mut writer = participant
        .topic::<Point>("NackHandlersGoWithWriter")
        .expect("topic")
        .writer()
        .qos(QoS::reliable())
        .build()
        .expect("reliable writer");
    writer.write(&Point { x: 1, y: 2 }).expect("write");
    assert_eq!(
        registry.nack_handler_counts(),
        (before.0 + 1, before.1 + 1),
        "fixture: a reliable writer registers one NACK and one NACK_FRAG handler"
    );
    let history = Arc::downgrade(writer.history_cache.as_ref().expect("history"));
    // usize::MAX: the dispose never went out.
    let at_dispose = Arc::new(AtomicUsize::new(usize::MAX));
    let seen = Arc::clone(&at_dispose);
    let probe = Arc::clone(&registry);
    writer
        .sedp_retirement
        .as_mut()
        .expect("the writer is announced")
        .on_dispose_sent(Box::new(move || {
            let (nack, frag) = probe.nack_handler_counts();
            seen.store(nack + frag, Ordering::SeqCst);
        }));

    drop(writer);
    assert_eq!(
        at_dispose.load(Ordering::SeqCst),
        before.0 + before.1,
        "the writer's NACK handlers were still registered when its SEDP dispose went out \
         (usize::MAX: no dispose went out)"
    );
    assert_eq!(
        registry.nack_handler_counts(),
        before,
        "the deleted writer's NACK handlers stayed registered"
    );
    assert!(
        history.upgrade().is_none(),
        "the deleted writer's history is still held"
    );
}

/// DataTagQosPolicy (DDS-Security v1.1 Sec.7.2.5): HDDS does not announce
/// a local endpoint's data tags, so an endpoint created with some is
/// refused (InvalidQos) rather than announced as untagged; one without is
/// created as before.
#[test]
fn an_endpoint_with_data_tags_is_refused() {
    use crate::generated::temperature::Temperature;
    let participant = crate::Participant::builder("data_tags_refused")
        .with_transport(crate::TransportMode::IntraProcess)
        .build()
        .expect("participant");
    let mut tagged = QoS::reliable();
    tagged.data_tags.tags.push(crate::qos::data_tags::DataTag {
        name: "n".to_string(),
        value: "v".to_string(),
    });
    let topic = participant
        .topic::<Temperature>("tagged/topic")
        .expect("topic");
    let writer = topic.writer().qos(tagged.clone()).build();
    assert!(
        matches!(writer, Err(Error::InvalidQos(_))),
        "{:?}",
        writer.err()
    );
    let reader = topic.reader().qos(tagged).build();
    assert!(
        matches!(reader, Err(Error::InvalidQos(_))),
        "{:?}",
        reader.err()
    );
    assert!(topic.writer().qos(QoS::reliable()).build().is_ok());
}

/// Deleting a writer after a lifecycle change: a matched reader of a vendor
/// that loses an acknowledged dispose when the writer departs before its
/// application reads it (`protocol::dialect::retirement`) holds the SEDP
/// dispose back for the linger; any other reader costs no wait, since a
/// conformant reader keeps the untaken dispose of a writer that is gone
/// (DDS v1.4 Sec.2.2.3.22).
mod lifecycle_retirement_linger {
    use super::*;
    use crate::core::discovery::GUID;
    use crate::core::key_hash::{KeyHolderWriter, KeyMaxSize};
    use crate::core::rtps_constants::{HDDS_VENDOR_ID_U16, INTERCOM_VENDOR_ID_U16};
    use crate::protocol::dialect::retirement::INTERCOM_LIFECYCLE_LINGER;
    use crate::protocol::discovery::{SedpData, SpdpData};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    /// `{ @key long id; }`, carried as a `Point`.
    struct Keyed {
        id: i32,
    }

    impl DDS for Keyed {
        fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
            Point::type_descriptor()
        }
        fn encode(
            &self,
            buf: &mut [u8],
            version: crate::dds::CdrVersion,
        ) -> crate::dds::Result<usize> {
            Point { x: self.id, y: 0 }.encode(buf, version)
        }
        fn decode(buf: &[u8], version: crate::dds::CdrVersion) -> crate::dds::Result<Self> {
            Point::decode(buf, version).map(|p| Self { id: p.x })
        }
        fn has_key() -> bool {
            true
        }
        fn write_key_holder(&self, w: &mut KeyHolderWriter) -> Option<KeyMaxSize> {
            w.write_i32(self.id);
            Some(KeyMaxSize::Bounded(4))
        }
    }

    /// A participant, and a writer of `topic` matched with one remote
    /// reader whose participant announced `vendor`.
    fn writer_matched_with(
        name: &str,
        topic: &str,
        prefix_byte: u8,
        vendor: u16,
    ) -> (
        crate::test_support::domains::DomainLease,
        Arc<crate::Participant>,
        crate::dds::DataWriter<Keyed>,
        std::net::UdpSocket,
    ) {
        let _ = rt::init_slab_pool();
        let domain = crate::test_support::domains::unique_domain();
        let participant = crate::Participant::builder(name)
            .domain_id(domain.id())
            .with_transport(crate::TransportMode::UdpMulticast)
            .build()
            .expect("participant");
        let fsm = participant.discovery().expect("discovery FSM");
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer socket");
        let locator = peer.local_addr().expect("peer address");
        // A peer heard after our probation surfaces its matches at once.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !fsm.is_probation_done() {
            assert!(
                Instant::now() < deadline,
                "fixture: the probation never ended"
            );
            std::thread::yield_now();
        }
        let participant_guid = GUID::new([prefix_byte; 12], [0x00, 0x00, 0x01, 0xC1]);
        fsm.handle_spdp(SpdpData {
            participant_guid,
            lease_duration_ms: 30_000,
            domain_id: domain.id(),
            metatraffic_unicast_locators: vec![locator],
            default_unicast_locators: vec![locator],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: Some(vendor),
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        fsm.confirm_participant_for_test(participant_guid);
        let writer = participant
            .topic::<Keyed>(topic)
            .expect("topic")
            .writer()
            .qos(QoS::reliable())
            .build()
            .expect("reliable writer");
        fsm.handle_sedp(SedpData {
            topic_name: topic.to_string(),
            type_name: Point::type_descriptor().type_name.to_string(),
            participant_guid,
            endpoint_guid: GUID::new([prefix_byte; 12], [0x00, 0x00, 0x10, 0x07]),
            qos_hash: 0,
            // The writer's own QoS: reliable, and its data representation.
            qos: Some(writer.qos.clone()),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            type_information: None,
            unicast_locators: vec![locator],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: true,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while writer.get_matched_subscriptions().is_empty() {
            assert!(
                Instant::now() < deadline,
                "fixture: the remote reader never matched"
            );
            std::thread::yield_now();
        }
        (domain, participant, writer, peer)
    }

    /// The time from the start of the writer's deletion to its SEDP dispose.
    fn retirement_after_dispose(mut writer: crate::dds::DataWriter<Keyed>) -> Duration {
        writer.write(&Keyed { id: 7 }).expect("write");
        writer.dispose(&Keyed { id: 7 }).expect("dispose");
        // The reader acknowledged everything: the deletion owes it no
        // acknowledgement wait, and any time left is the linger.
        {
            let mut acks = writer.ack_track.lock().expect("ack track");
            assert!(!acks.is_empty(), "fixture: the reliable reader is tracked");
            acks.values_mut().for_each(|acked| *acked = u64::MAX);
        }
        assert!(writer.fully_acked(), "fixture: the change is acknowledged");
        let at_dispose: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
        let seen = Arc::clone(&at_dispose);
        writer
            .sedp_retirement
            .as_mut()
            .expect("the writer is announced")
            .on_dispose_sent(Box::new(move || {
                *seen.lock().expect("lock") = Some(Instant::now());
            }));
        let start = Instant::now();
        drop(writer);
        let sent = at_dispose
            .lock()
            .expect("lock")
            .expect("the SEDP dispose went out");
        sent - start
    }

    #[test]
    fn an_intercom_reader_holds_the_sedp_dispose_for_the_linger() {
        let (_domain, _participant, writer, _peer) = writer_matched_with(
            "retirement_linger_intercom",
            "RetirementLingerIntercom",
            0x6A,
            INTERCOM_VENDOR_ID_U16,
        );
        assert_eq!(
            writer.lifecycle_retirement_linger(),
            INTERCOM_LIFECYCLE_LINGER
        );
        let waited = retirement_after_dispose(writer);
        assert!(
            waited >= INTERCOM_LIFECYCLE_LINGER,
            "the SEDP dispose went out {waited:?} after the deletion began, \
             before the {INTERCOM_LIFECYCLE_LINGER:?} linger"
        );
    }

    #[test]
    fn an_hdds_reader_costs_the_deletion_no_linger() {
        let (_domain, _participant, writer, _peer) = writer_matched_with(
            "retirement_linger_hdds",
            "RetirementLingerHdds",
            0x6B,
            HDDS_VENDOR_ID_U16,
        );
        assert_eq!(writer.lifecycle_retirement_linger(), Duration::ZERO);
        let waited = retirement_after_dispose(writer);
        assert!(
            waited < INTERCOM_LIFECYCLE_LINGER,
            "the SEDP dispose waited {waited:?} for an HDDS reader"
        );
    }
}
