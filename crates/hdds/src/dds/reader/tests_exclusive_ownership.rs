// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! EXCLUSIVE ownership as one reader arbitrates it (DDS v1.4 Sec.2.2.3.9.2,
//! Sec.2.2.3.10, Sec.2.2.3.23).
//!
//! Every sample and every lifecycle change is classified and enters through
//! `route_data_packet`, as a datagram another implementation would send (an
//! RTPS 2.5 header with a foreign vendor id, little-endian DATA submessages);
//! a writer's departure enters through `TopicRegistry::notify_writer_dispose`
//! (what the SEDP endpoint dispose calls) and a participant's through
//! `TopicRegistry::notify_participant_departed` (what its SPDP dispose and
//! its lease expiry call). What is asserted is what the application takes.

use super::ReaderBuilder;
use crate::core::discovery::multicast::{classify_rtps, PacketKind};
use crate::core::rt;
use crate::dds::{DataReader, InstanceState, QoS, ViewState, DDS};
use crate::engine::subscriber::DisposeKind;
use crate::engine::{route_data_packet, RouterMetrics, Subscriber, TopicRegistry};
use crate::qos::ownership::OwnershipKind;
use std::sync::Arc;

/// Wire twin of [`Instance`]: the derive has no key handling, so the keyed
/// type delegates its codec here and hand-writes the key. The key is a
/// string, first, as ShapeType's color is: the shape the arbitration that
/// lived in the router before the reader did could recognise.
#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct InstanceWire {
    key: String,
    value: i64,
}

fn key_name(key: i64) -> String {
    format!("key-{key}")
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Instance {
    key: i64,
    value: i64,
}

impl DDS for Instance {
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
        InstanceWire::type_descriptor()
    }

    fn encode(&self, buf: &mut [u8], version: crate::dds::CdrVersion) -> crate::dds::Result<usize> {
        InstanceWire {
            key: key_name(self.key),
            value: self.value,
        }
        .encode(buf, version)
    }

    fn decode(buf: &[u8], version: crate::dds::CdrVersion) -> crate::dds::Result<Self> {
        let wire = InstanceWire::decode(buf, version)?;
        let key = wire
            .key
            .strip_prefix("key-")
            .and_then(|k| k.parse().ok())
            .ok_or(crate::dds::Error::SerializationError)?;
        Ok(Self {
            key,
            value: wire.value,
        })
    }

    fn compute_key(&self) -> [u8; 16] {
        key_hash(self.key)
    }

    /// Keyed: a local DataWriter tracks its instances, and its disposes and
    /// unregisters reach the readers of this process.
    fn has_key() -> bool {
        true
    }

    /// The field a content filter reads.
    fn get_fields(&self) -> std::collections::HashMap<String, crate::dds::filter::FieldValue> {
        let mut fields = std::collections::HashMap::new();
        fields.insert(
            "value".to_string(),
            crate::dds::filter::FieldValue::from_i64(self.value),
        );
        fields
    }
}

/// The instance most tests write.
const KEY: i64 = 7;

/// Writers of three participants. The GUIDs order A < B < C.
const A: [u8; 16] = [
    0x01, 0x0f, 0xa1, 0xa1, 0x0e, 0x00, 0xad, 0xef, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x02,
];
const B: [u8; 16] = [
    0x01, 0x0f, 0xb2, 0xb2, 0x0e, 0x00, 0xad, 0xef, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x02,
];
const C: [u8; 16] = [
    0x01, 0x0f, 0xc3, 0xc3, 0x0e, 0x00, 0xad, 0xef, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x02,
];

/// StatusInfo flags (RTPS v2.5 Sec.9.6.4.9).
const DISPOSED: u8 = 0x01;
const UNREGISTERED: u8 = 0x02;

fn key_hash(key: i64) -> [u8; 16] {
    let mut hash = [0u8; 16];
    hash[..8].copy_from_slice(&key.to_le_bytes());
    hash[8..].copy_from_slice(&(key ^ 0x5A5A_5A5A_5A5A_5A5A_i64).to_le_bytes());
    hash
}

/// One DATA submessage of `writer` as change `sn`, little-endian
/// (RTPS v2.5 Sec.9.4.5.3): `flags` beyond E, an inline QoS of StatusInfo
/// `status` and the KeyHash of `key` (Sec.9.6.4.8) when `status` is `Some`,
/// then `payload`.
fn datagram(
    writer: [u8; 16],
    sn: u32,
    flags: u8,
    status: Option<u8>,
    key: i64,
    payload: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0]); // extraFlags
    body.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
    body.extend_from_slice(&[0, 0, 0, 0]); // readerId: ENTITYID_UNKNOWN
    body.extend_from_slice(&writer[12..]);
    body.extend_from_slice(&0u32.to_le_bytes()); // writerSN high
    body.extend_from_slice(&sn.to_le_bytes()); // writerSN low
    if let Some(status) = status {
        body.extend_from_slice(&[0x71, 0x00, 0x04, 0x00, 0, 0, 0, status]);
        body.extend_from_slice(&[0x70, 0x00, 0x10, 0x00]);
        body.extend_from_slice(&key_hash(key));
        body.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // PID_SENTINEL
    }
    body.extend_from_slice(payload);
    assert_eq!(body.len() % 4, 0, "the next header stays aligned");
    let mut packet = Vec::new();
    packet.extend_from_slice(b"RTPS");
    packet.extend_from_slice(&[2, 5, 0x01, 0x0f]);
    packet.extend_from_slice(&writer[..12]);
    packet.extend_from_slice(&[0x15, 0x01 | flags]);
    packet.extend_from_slice(&u16::try_from(body.len()).expect("fits").to_le_bytes());
    packet.extend_from_slice(&body);
    packet
}

/// CDR2_LE encapsulation of the sample `(key, value)`.
fn serialized(key: i64, value: i64) -> Vec<u8> {
    let mut buf = vec![0u8; 64];
    let len = Instance { key, value }
        .encode(&mut buf[4..], crate::dds::CdrVersion::Xcdr2)
        .expect("encode");
    buf[..4].copy_from_slice(&[0x00, 0x07, 0x00, 0x00]);
    buf.truncate(4 + len);
    buf
}

/// One sample as the application takes it: key, value (None for a
/// transition), instance state, view state.
type Taken = (i64, Option<i64>, InstanceState, ViewState);

/// The reader, its subscriber registered on a topic registry that knows the
/// three writers with the strengths given.
struct Fixture {
    /// Unregisters the subscriber from `registry` when the fixture drops
    /// (the subscriber holds the registry and the registry the subscriber).
    _registration: crate::engine::SubscriberToken,
    reader: Arc<DataReader<Instance>>,
    registry: Arc<TopicRegistry>,
}

impl Fixture {
    fn new(topic: &str, kind: OwnershipKind, strengths: [i32; 3]) -> Self {
        Self::with_deadline(topic, kind, strengths, None)
    }

    fn with_deadline(
        topic: &str,
        kind: OwnershipKind,
        strengths: [i32; 3],
        deadline: Option<std::time::Duration>,
    ) -> Self {
        Self::build(topic, kind, strengths, deadline, None)
    }

    /// An EXCLUSIVE reader of a ContentFilteredTopic with `filter`.
    fn filtered(topic: &str, strengths: [i32; 3], filter: &str) -> Self {
        Self::build(
            topic,
            OwnershipKind::Exclusive,
            strengths,
            None,
            Some(filter),
        )
    }

    fn build(
        topic: &str,
        kind: OwnershipKind,
        strengths: [i32; 3],
        deadline: Option<std::time::Duration>,
        filter: Option<&str>,
    ) -> Self {
        let _ = rt::init_slab_pool();
        let mut qos = QoS::best_effort().keep_last(16);
        if kind == OwnershipKind::Exclusive {
            qos = qos.ownership_exclusive();
        }
        if let Some(period) = deadline {
            qos = qos.deadline(crate::qos::deadline::Deadline::new(period));
        }
        let mut builder = ReaderBuilder::<Instance>::new(topic.to_string());
        if let Some(filter) = filter {
            builder = builder.with_content_filter(
                crate::dds::filter::ContentFilter::new(filter)
                    .expect("filter")
                    .evaluator(),
            );
        }
        let reader = Arc::new(
            builder
                .qos(qos)
                .network_ring_for_test()
                .build()
                .expect("reader build should succeed"),
        );
        let network_ring = Arc::clone(reader.network_ring_for_test().expect("network ring"));
        let registry = Arc::new(TopicRegistry::new());
        let mut sub = super::subscriber::ReaderSubscriber::<Instance>::new_with_coherent(
            topic.to_string(),
            network_ring,
            reader.get_status_condition(),
            None,
            None,
            None,
            Arc::clone(reader.dispose_queue_for_test()),
            Arc::new(std::sync::Mutex::new(super::reorder::ReorderGate::new(
                false, false,
            ))),
            super::subscriber::CoherentConfig::default(),
            None,
            None,
            Arc::new(std::sync::Mutex::new(
                crate::dds::listener::SampleRejectedStatus::default(),
            )),
            Vec::new(),
            crate::qos::partition::Partition::default(),
            kind,
            Some(Arc::clone(&registry)),
            None,
            None,
            #[cfg(feature = "security")]
            None,
        );
        sub.room = reader.network_room_for_test().cloned();
        // The reader's own table, which its local bindings arbitrate in too,
        // as the builder shares it with the subscriber it builds.
        let registrations = reader.registrations_for_test();
        registrations.read_strengths_from(&registry);
        sub.writer_instances = Arc::clone(registrations);
        let registration = registry
            .register_subscriber_scoped(Arc::new(sub) as Arc<dyn Subscriber>)
            .expect("register subscriber");
        for (writer, strength) in [A, B, C].into_iter().zip(strengths) {
            registry.register_writer_guid(writer, topic.to_string());
            registry.register_writer_ownership_kind(writer, kind);
            if kind == OwnershipKind::Exclusive {
                registry.register_writer_ownership_strength(writer, strength);
            }
        }
        Self {
            _registration: registration,
            reader,
            registry,
        }
    }

    /// The datagram through the door a received one takes: classified,
    /// then routed at the offset the classifier names.
    fn route(&self, packet: &[u8]) {
        let (kind, offset, _, _) = classify_rtps(packet);
        assert_eq!(kind, PacketKind::Data);
        let _ = route_data_packet(
            packet,
            packet.len(),
            offset,
            &self.registry,
            &RouterMetrics::new(),
        );
    }

    /// `writer` writes instance `key` as its change `sn`.
    fn write_key(&self, writer: [u8; 16], sn: u32, key: i64, value: i64) {
        self.route(&datagram(
            writer,
            sn,
            0x04,
            None,
            key,
            &serialized(key, value),
        ));
    }

    /// `writer` writes instance [`KEY`] as its change `sn`.
    fn write(&self, writer: [u8; 16], sn: u32, value: i64) {
        self.write_key(writer, sn, KEY, value);
    }

    /// `writer` sends a key-only lifecycle change (D=0 K=1 Q=1) of [`KEY`]
    /// as its change `sn`, the serialized key after the inline QoS.
    fn key_only(&self, writer: [u8; 16], sn: u32, status: u8) {
        let name = key_name(KEY);
        let mut key = vec![0x00, 0x01, 0x00, 0x00];
        key.extend_from_slice(&u32::try_from(name.len() + 1).expect("fits").to_le_bytes());
        key.extend_from_slice(name.as_bytes());
        key.push(0);
        key.resize(key.len().next_multiple_of(4), 0);
        self.route(&datagram(writer, sn, 0x0a, Some(status), KEY, &key));
    }

    /// `writer` left (its SEDP endpoint dispose).
    fn depart(&self, writer: [u8; 16]) {
        assert!(self
            .registry
            .notify_writer_dispose(writer, DisposeKind::Unregistered));
    }

    /// `writer`'s LIVELINESS lease on this reader changed (DDS v1.4
    /// Sec.2.2.3.11): alive from now, or not. Unlike [`depart`](Self::depart),
    /// `writer` stays matched - this is what the participant's liveliness
    /// scheduler calls (`dds::liveliness::ReaderLiveliness::transition`),
    /// here called directly since this fixture builds its reader without a
    /// participant (no scheduler thread to drive it).
    fn lose_liveliness(&self, writer: [u8; 16]) {
        super::subscriber::on_writer_alive(
            self.reader.registrations_for_test(),
            self.reader.dispose_queue_for_test(),
            writer,
            false,
        );
    }

    /// `writer` resumed (its LIVELINESS lease was renewed): see
    /// [`lose_liveliness`](Self::lose_liveliness).
    fn regain_liveliness(&self, writer: [u8; 16]) {
        super::subscriber::on_writer_alive(
            self.reader.registrations_for_test(),
            self.reader.dispose_queue_for_test(),
            writer,
            true,
        );
    }

    /// Everything the application can take now.
    fn take_all(&self) -> Vec<Taken> {
        let mut taken = Vec::new();
        while let Some((data, info)) = self.reader.take_with_info().expect("take_with_info") {
            let key = [KEY, 8]
                .into_iter()
                .find(|k| key_hash(*k) == info.instance_handle.0)
                .expect("a known instance");
            taken.push((
                key,
                data.map(|sample| sample.value),
                info.instance_state,
                info.view_state,
            ));
        }
        taken
    }
}

fn alive(value: i64, view: ViewState) -> Taken {
    (KEY, Some(value), InstanceState::Alive, view)
}

/// The strongest writer owns the instance; a weaker writer's samples are
/// not seen while it does (Sec.2.2.3.9.2).
#[test]
fn the_strongest_writer_owns_the_instance() {
    let f = Fixture::new("excl-strongest-owns", OwnershipKind::Exclusive, [1, 10, 0]);
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    f.write(A, 2, 11);
    f.write(B, 2, 21);
    assert_eq!(
        f.take_all(),
        vec![
            alive(10, ViewState::New),
            alive(20, ViewState::NotNew),
            alive(21, ViewState::NotNew),
        ],
        "B, stronger, takes the instance on its first sample and keeps it"
    );
}

/// The owner's unregister relinquishes ownership (Sec.2.2.3.23.3), the
/// weaker writer that kept writing still holds the instance - no
/// NOT_ALIVE_NO_WRITERS (Sec.2.2.2.4.2.7) - and its next sample is seen.
#[test]
fn the_owners_unregister_hands_the_instance_to_the_weaker_writer() {
    let f = Fixture::new(
        "excl-unregister-hands-over",
        OwnershipKind::Exclusive,
        [10, 1, 0],
    );
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    assert_eq!(f.take_all(), vec![alive(10, ViewState::New)]);

    f.key_only(A, 2, UNREGISTERED);
    assert_eq!(f.take_all(), vec![], "B still writes the instance");

    f.write(B, 2, 21);
    assert_eq!(
        f.take_all(),
        vec![alive(21, ViewState::NotNew)],
        "B owns the instance now"
    );
}

/// The owner's unregister riding a dispose (StatusInfo D|U) relinquishes
/// the instance too, after disposing it.
#[test]
fn the_owners_dispose_and_unregister_hands_the_instance_over() {
    let f = Fixture::new(
        "excl-dispose-unregister",
        OwnershipKind::Exclusive,
        [10, 1, 0],
    );
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    assert_eq!(f.take_all(), vec![alive(10, ViewState::New)]);

    f.key_only(A, 2, DISPOSED | UNREGISTERED);
    assert_eq!(
        f.take_all(),
        vec![(
            KEY,
            None,
            InstanceState::NotAliveDisposed,
            ViewState::NotNew
        )]
    );

    f.write(B, 2, 21);
    assert_eq!(f.take_all(), vec![alive(21, ViewState::New)]);
}

/// The owner's SEDP endpoint dispose (the writer was deleted) is an
/// unregister of every instance it wrote (Sec.2.2.3.23.3): the weaker writer
/// takes over.
#[test]
fn the_owners_departure_hands_the_instance_to_the_weaker_writer() {
    let f = Fixture::new(
        "excl-departure-hands-over",
        OwnershipKind::Exclusive,
        [10, 1, 0],
    );
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    assert_eq!(f.take_all(), vec![alive(10, ViewState::New)]);

    f.depart(A);
    assert_eq!(f.take_all(), vec![], "B still writes the instance");

    f.write(B, 2, 21);
    assert_eq!(f.take_all(), vec![alive(21, ViewState::NotNew)]);
}

/// The owner's participant is gone - its SPDP dispose, or its lease expired
/// (both reach `notify_participant_departed`, pinned from the discovery
/// side by `a_removed_participant_takes_its_own_writers_with_it_whatever_removed_it`):
/// the owner is no longer alive (Sec.2.2.3.9.2, Sec.2.2.3.23.1.2) and the
/// weaker writer takes over.
#[test]
fn the_owners_lease_loss_hands_the_instance_to_the_weaker_writer() {
    let f = Fixture::new(
        "excl-lease-hands-over",
        OwnershipKind::Exclusive,
        [10, 1, 0],
    );
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    assert_eq!(f.take_all(), vec![alive(10, ViewState::New)]);

    let mut prefix = [0u8; 12];
    prefix.copy_from_slice(&A[..12]);
    assert_eq!(f.registry.notify_participant_departed(&prefix), 1);
    assert_eq!(f.take_all(), vec![], "B still writes the instance");

    f.write(B, 2, 21);
    assert_eq!(f.take_all(), vec![alive(21, ViewState::NotNew)]);
}

/// A matched writer's own LIVELINESS lease expiring (DDS v1.4
/// Sec.2.2.3.11, Sec.2.2.3.23.1.2) - not its participant's SPDP lease, and
/// not an SEDP departure - makes it no longer alive, and EXCLUSIVE
/// ownership transfers to the next ALIVE writer at once (no DEADLINE
/// wait). The owner's standing is kept, unlike a departure: resuming with
/// a write regains ownership by the normal strength rule.
#[test]
fn the_owners_liveliness_loss_hands_the_instance_to_the_weaker_writer() {
    let f = Fixture::new(
        "excl-liveliness-hands-over",
        OwnershipKind::Exclusive,
        [10, 1, 0],
    );
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    assert_eq!(f.take_all(), vec![alive(10, ViewState::New)]);

    f.lose_liveliness(A);
    assert_eq!(
        f.take_all(),
        vec![],
        "A is not alive, but it did not unregister: no transition of its own"
    );
    f.write(B, 2, 21);
    assert_eq!(
        f.take_all(),
        vec![alive(21, ViewState::NotNew)],
        "B's next sample is accepted at once, no DEADLINE wait"
    );

    // A resumes and writes again: by strength, it takes the instance back.
    f.regain_liveliness(A);
    f.write(A, 2, 11);
    assert_eq!(f.take_all(), vec![alive(11, ViewState::NotNew)]);
}

/// NOT_ALIVE_NO_WRITERS driven by LIVELINESS loss (DDS v1.4
/// Sec.2.2.3.23.2), not only by an explicit unregister or a departure: two
/// SHARED writers of one instance, one losing liveliness keeps it alive,
/// losing the last one moves it to NOT_ALIVE_NO_WRITERS, and a write
/// after it revives it with `no_writers_generation_count` incremented.
#[test]
fn liveliness_loss_of_every_writer_moves_the_instance_to_no_writers() {
    let f = Fixture::new(
        "shared-liveliness-no-writers",
        OwnershipKind::Shared,
        [0; 3],
    );
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    assert_eq!(
        f.take_all(),
        // Same instance (SHARED: every writer's sample is delivered): the
        // first access makes it NOT_NEW, so the second one, even of the
        // same instance, reports that - DDS v1.4 Sec.2.2.2.5.1.8 is a
        // per-INSTANCE view state, not a per-sample one.
        vec![alive(10, ViewState::New), alive(20, ViewState::NotNew)]
    );

    f.lose_liveliness(A);
    assert_eq!(f.take_all(), vec![], "B is still alive and writes it");

    f.lose_liveliness(B);
    assert_eq!(
        f.take_all(),
        vec![(
            KEY,
            None,
            InstanceState::NotAliveNoWriters,
            ViewState::NotNew
        )],
        "neither writer of the instance is alive any more"
    );

    f.write(B, 2, 21);
    let (data, info) = f
        .reader
        .take_with_info()
        .expect("take_with_info")
        .expect("B's revival sample");
    assert_eq!(
        data.expect("valid data").value,
        21,
        "B resumed and wrote: alive again"
    );
    assert_eq!(info.instance_state, InstanceState::Alive);
    assert_eq!(
        info.no_writers_generation_count, 1,
        "the instance became ALIVE again after NO_WRITERS exactly once (DDS v1.4 Sec.2.2.2.5.1.4)"
    );
    assert_eq!(f.take_all(), vec![], "nothing left to take");
}

/// An owner that lets the reader's requested DEADLINE pass without
/// modifying the instance is no longer its owner: the next writer that
/// modifies it takes it (Sec.2.2.3.9.2 (d), Sec.2.2.3.23.1.1). Within the
/// period the owner keeps it, and once it writes again it takes it back by
/// strength.
#[test]
fn an_owner_that_misses_the_deadline_loses_the_instance() {
    let period = std::time::Duration::from_millis(300);
    let f = Fixture::with_deadline(
        "excl-deadline",
        OwnershipKind::Exclusive,
        [10, 1, 0],
        Some(period),
    );
    let two_thirds = period * 2 / 3;
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    std::thread::sleep(two_thirds);
    f.write(A, 2, 11);
    std::thread::sleep(two_thirds);
    f.write(B, 2, 21);
    assert_eq!(
        f.take_all(),
        vec![alive(10, ViewState::New), alive(11, ViewState::NotNew)],
        "A wrote within every period: it keeps the instance"
    );

    std::thread::sleep(period + std::time::Duration::from_millis(100));
    f.write(B, 3, 22);
    assert_eq!(
        f.take_all(),
        vec![alive(22, ViewState::NotNew)],
        "A missed its deadline: B takes the instance"
    );

    f.write(A, 3, 12);
    f.write(B, 4, 23);
    assert_eq!(
        f.take_all(),
        vec![alive(12, ViewState::NotNew)],
        "A writes again and outranks B"
    );
}

/// Samples the owner sent BEFORE its unregister, received after it, are
/// shown (they were the owner's when sent, and it outranks the others) but
/// do not hand the instance back to a writer that let it go: neither while
/// the instance has no owner, nor against the weaker writer that took it.
#[test]
fn samples_sent_before_the_owners_unregister_do_not_hand_it_back() {
    let f = Fixture::new("excl-late-samples", OwnershipKind::Exclusive, [10, 1, 0]);
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    assert_eq!(f.take_all(), vec![alive(10, ViewState::New)]);

    f.key_only(A, 4, UNREGISTERED);
    f.write(A, 2, 12);
    f.write(B, 2, 21);
    f.write(A, 3, 13);
    f.write(B, 3, 22);
    assert_eq!(
        f.take_all(),
        vec![
            alive(12, ViewState::NotNew),
            alive(21, ViewState::NotNew),
            alive(13, ViewState::NotNew),
            alive(22, ViewState::NotNew),
        ],
        "A's changes 2 and 3 precede its unregister 4; B owns the instance from its change 2"
    );
}

/// Under EXCLUSIVE ownership only the owner's dispose moves the instance to
/// NOT_ALIVE_DISPOSED (Sec.2.2.2.5.1.3, Sec.2.2.4.2.2).
#[test]
fn a_dispose_from_a_writer_that_does_not_own_the_instance_is_not_applied() {
    let f = Fixture::new("excl-foreign-dispose", OwnershipKind::Exclusive, [10, 1, 0]);
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    assert_eq!(f.take_all(), vec![alive(10, ViewState::New)]);

    f.key_only(B, 2, DISPOSED);
    assert_eq!(f.take_all(), vec![], "B does not own the instance");

    f.write(A, 2, 11);
    assert_eq!(
        f.take_all(),
        vec![alive(11, ViewState::NotNew)],
        "the same generation: it was never disposed"
    );
}

/// The owner's dispose is applied and the weaker writer's values stay
/// hidden after it (Sec.2.2.3.23.3: the readers "not see the values being
/// written by the weaker writer (even after the stronger one has disposed
/// the instance)").
#[test]
fn the_owners_dispose_is_applied_and_keeps_the_weaker_writer_hidden() {
    let f = Fixture::new("excl-owner-dispose", OwnershipKind::Exclusive, [10, 1, 0]);
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    f.key_only(A, 2, DISPOSED);
    assert_eq!(
        f.take_all(),
        vec![
            (
                KEY,
                Some(10),
                InstanceState::NotAliveDisposed,
                ViewState::New
            ),
            (
                KEY,
                None,
                InstanceState::NotAliveDisposed,
                ViewState::NotNew
            ),
        ]
    );

    f.write(B, 2, 21);
    assert_eq!(f.take_all(), vec![], "A still owns the disposed instance");
}

/// Two writers of the same strength: the owner is the one every reader
/// picks whichever wrote first (Sec.2.2.3.9.2), here the lower GUID.
#[test]
fn equal_strengths_are_broken_by_the_lower_guid_whichever_writes_first() {
    let f = Fixture::new("excl-tie-higher-first", OwnershipKind::Exclusive, [5, 5, 0]);
    f.write(B, 1, 20);
    f.write(A, 1, 10);
    f.write(B, 2, 21);
    f.write(A, 2, 11);
    assert_eq!(
        f.take_all(),
        vec![
            alive(20, ViewState::New),
            alive(10, ViewState::NotNew),
            alive(11, ViewState::NotNew),
        ],
        "A, the lower GUID, takes the instance and keeps it"
    );

    let f = Fixture::new("excl-tie-lower-first", OwnershipKind::Exclusive, [5, 5, 0]);
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    f.write(A, 2, 11);
    assert_eq!(
        f.take_all(),
        vec![alive(10, ViewState::New), alive(11, ViewState::NotNew)],
        "A keeps the instance against B"
    );
}

/// A change in the owner's strength is a change of ownership
/// (Sec.2.2.3.9.2 (b)): a writer it no longer outranks takes over on its
/// next sample.
#[test]
fn an_owner_whose_strength_drops_loses_the_instance() {
    let f = Fixture::new("excl-strength-drops", OwnershipKind::Exclusive, [10, 1, 0]);
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    assert_eq!(f.take_all(), vec![alive(10, ViewState::New)]);

    // A re-announces itself (SEDP) with a lower strength.
    f.registry.register_writer_ownership_strength(A, 0);
    f.write(B, 2, 21);
    assert_eq!(f.take_all(), vec![alive(21, ViewState::NotNew)]);
}

/// Ownership is per instance (Sec.2.2.3.9.2): the weaker writer's samples of
/// an instance the stronger one never wrote are seen.
#[test]
fn ownership_is_per_instance() {
    let f = Fixture::new("excl-per-instance", OwnershipKind::Exclusive, [10, 1, 0]);
    f.write(A, 1, 10);
    f.write_key(B, 1, 8, 80);
    f.write(B, 2, 20);
    assert_eq!(
        f.take_all(),
        vec![
            alive(10, ViewState::New),
            (8, Some(80), InstanceState::Alive, ViewState::New),
        ]
    );
}

/// SHARED ownership filters nothing (Sec.2.2.3.9.1) and any writer's
/// dispose applies.
#[test]
fn shared_ownership_sees_every_writer_and_every_dispose() {
    let f = Fixture::new("shared-unchanged", OwnershipKind::Shared, [0, 0, 0]);
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    f.write(C, 1, 30);
    assert_eq!(
        f.take_all(),
        vec![
            alive(10, ViewState::New),
            alive(20, ViewState::NotNew),
            alive(30, ViewState::NotNew),
        ]
    );
    f.key_only(C, 2, DISPOSED);
    assert_eq!(
        f.take_all(),
        vec![(
            KEY,
            None,
            InstanceState::NotAliveDisposed,
            ViewState::NotNew
        )]
    );
}

/// A stronger writer whose only change to the instance is a dispose takes
/// it: a dispose modifies the instance (DDS v1.4 Sec.2.2.2.4.2.7: after an
/// unregister, a writer that "wants to modify (write or dispose) the
/// instance ... has to register it again, or else use the special handle
/// value HANDLE_NIL"), and the readers then "not see the values being
/// written by the weaker writer (even after the stronger one has disposed
/// the instance)" (Sec.2.2.3.23.3). Its departure hands the instance back.
#[test]
fn a_stronger_writer_that_only_disposes_takes_the_instance() {
    let f = Fixture::new("excl-dispose-only", OwnershipKind::Exclusive, [10, 1, 20]);
    f.write(A, 1, 10);
    assert_eq!(f.take_all(), vec![alive(10, ViewState::New)]);

    f.key_only(C, 1, DISPOSED);
    assert_eq!(
        f.take_all(),
        vec![(
            KEY,
            None,
            InstanceState::NotAliveDisposed,
            ViewState::NotNew
        )]
    );

    f.write(A, 2, 11);
    assert_eq!(f.take_all(), vec![], "C owns the disposed instance");

    f.depart(C);
    assert_eq!(f.take_all(), vec![], "A still writes the instance");
    f.write(A, 3, 12);
    assert_eq!(
        f.take_all(),
        vec![alive(12, ViewState::New)],
        "C left: A owns the instance, written again after the dispose"
    );
}

/// A non-owner's unregister is recorded: the instance stays with its owner,
/// and once the owner unregisters too no writer is left.
#[test]
fn a_non_owners_unregister_releases_only_its_registration() {
    let f = Fixture::new(
        "excl-foreign-unregister",
        OwnershipKind::Exclusive,
        [10, 1, 0],
    );
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    f.key_only(B, 2, UNREGISTERED);
    f.write(A, 2, 11);
    assert_eq!(
        f.take_all(),
        vec![alive(10, ViewState::New), alive(11, ViewState::NotNew)]
    );

    f.key_only(A, 3, UNREGISTERED);
    assert_eq!(
        f.take_all(),
        vec![(
            KEY,
            None,
            InstanceState::NotAliveNoWriters,
            ViewState::NotNew
        )],
        "B let it go first: no writer is left"
    );
}

/// A non-owner's dispose-and-unregister keeps only its unregister half.
#[test]
fn a_non_owners_dispose_and_unregister_keeps_only_its_unregister() {
    let f = Fixture::new(
        "excl-foreign-dispose-unreg",
        OwnershipKind::Exclusive,
        [10, 1, 0],
    );
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    f.key_only(B, 2, DISPOSED | UNREGISTERED);
    f.write(A, 2, 11);
    assert_eq!(
        f.take_all(),
        vec![alive(10, ViewState::New), alive(11, ViewState::NotNew)],
        "not disposed: B does not own the instance"
    );

    f.key_only(A, 3, UNREGISTERED);
    assert_eq!(
        f.take_all(),
        vec![(
            KEY,
            None,
            InstanceState::NotAliveNoWriters,
            ViewState::NotNew
        )],
        "B let it go first: no writer is left"
    );
}

/// An unregister older than the owner's last sample (by writerSN) does not
/// release the instance (Sec.8.3.8.2 orders a writer's changes): the weaker
/// writer stays hidden and nothing is announced.
#[test]
fn an_owners_unregister_older_than_its_last_sample_does_not_release() {
    let f = Fixture::new(
        "excl-stale-unregister",
        OwnershipKind::Exclusive,
        [10, 1, 0],
    );
    f.write(A, 5, 10);
    f.write(B, 1, 20);
    f.key_only(A, 3, UNREGISTERED);
    f.write(B, 2, 21);
    assert_eq!(
        f.take_all(),
        vec![alive(10, ViewState::New)],
        "A's change 5 came after its unregister 3: A still owns the instance"
    );
}

/// A SHARED reader applies a dispose from each writer (Sec.2.2.2.5.1.3).
#[test]
fn a_shared_reader_applies_each_writers_dispose() {
    let f = Fixture::new("shared-two-disposes", OwnershipKind::Shared, [0, 0, 0]);
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    assert_eq!(f.take_all().len(), 2);

    f.key_only(A, 2, DISPOSED);
    assert_eq!(
        f.take_all(),
        vec![(
            KEY,
            None,
            InstanceState::NotAliveDisposed,
            ViewState::NotNew
        )]
    );
    f.write(B, 2, 21);
    assert_eq!(f.take_all(), vec![alive(21, ViewState::New)]);
    f.key_only(B, 3, DISPOSED);
    assert_eq!(
        f.take_all(),
        vec![(
            KEY,
            None,
            InstanceState::NotAliveDisposed,
            ViewState::NotNew
        )],
        "B's dispose applies too"
    );
}

impl Fixture {
    /// A DataWriter of this process with `strength`, bound to the reader as
    /// the domain auto-bind does.
    ///
    /// Its deletion and its unregisters only unregister
    /// (autodispose_unregistered_instances FALSE, DDS v1.4 Sec.2.2.3.21):
    /// these tests are about who owns an instance once a writer lets it go,
    /// and with the default TRUE letting go disposes it too.
    fn local_writer(&self, topic: &str, strength: i32) -> crate::dds::DataWriter<Instance> {
        self.local_writer_of(
            topic,
            QoS::best_effort()
                .keep_last(16)
                .ownership_exclusive()
                .ownership_strength(strength)
                .writer_data_lifecycle_manual_dispose(),
        )
    }

    /// A DataWriter of this process with `qos`, bound to the reader.
    fn local_writer_of(&self, topic: &str, qos: QoS) -> crate::dds::DataWriter<Instance> {
        let writer = crate::dds::writer::WriterBuilder::<Instance>::new(topic.to_string())
            .qos(qos)
            .build()
            .expect("writer build should succeed");
        self.reader.bind_to_writer(writer.merger());
        writer
    }
}

/// A local DataWriter is arbitrated like a remote one: weaker than the
/// remote owner, its samples and its dispose are not seen (DDS v1.4
/// Sec.2.2.3.9.2, Sec.2.2.2.5.1.3).
#[test]
fn a_local_writer_weaker_than_the_remote_owner_is_hidden() {
    let topic = "excl-local-weaker";
    let f = Fixture::new(topic, OwnershipKind::Exclusive, [100, 1, 0]);
    let local = f.local_writer(topic, 0);
    f.write(A, 1, 10);
    local
        .write(&Instance {
            key: KEY,
            value: 50,
        })
        .expect("local write");
    local
        .dispose(&Instance { key: KEY, value: 0 })
        .expect("local dispose");
    assert_eq!(
        f.take_all(),
        vec![alive(10, ViewState::New)],
        "A, strength 100, owns the instance"
    );
    f.write(A, 2, 11);
    assert_eq!(f.take_all(), vec![alive(11, ViewState::NotNew)]);
}

/// A local owner hides a weaker remote writer, and its deletion hands the
/// instance over (Sec.2.2.3.23.3): the remote writer still writes it, so it
/// is not left without writers.
#[test]
fn a_local_owners_deletion_hands_the_instance_to_the_remote_writer() {
    let topic = "excl-local-owner-leaves";
    let f = Fixture::new(topic, OwnershipKind::Exclusive, [0, 1, 0]);
    let local = f.local_writer(topic, 50);
    local
        .write(&Instance {
            key: KEY,
            value: 50,
        })
        .expect("local write");
    f.write(B, 1, 20);
    assert_eq!(f.take_all(), vec![alive(50, ViewState::New)]);

    drop(local);
    assert_eq!(f.take_all(), vec![], "B still writes the instance");
    f.write(B, 2, 21);
    assert_eq!(f.take_all(), vec![alive(21, ViewState::NotNew)]);
}

/// A local owner that disposed the instance keeps it, and the weaker remote
/// writer stays hidden; deleted, it relinquishes it although its deletion
/// sends no unregister for an instance it disposed.
#[test]
fn a_local_owner_that_disposed_and_was_deleted_hands_the_instance_over() {
    let topic = "excl-local-disposed-leaves";
    let f = Fixture::new(topic, OwnershipKind::Exclusive, [0, 1, 0]);
    let local = f.local_writer(topic, 50);
    local
        .write(&Instance {
            key: KEY,
            value: 50,
        })
        .expect("local write");
    f.write(B, 1, 20);
    assert_eq!(f.take_all(), vec![alive(50, ViewState::New)]);
    local
        .dispose(&Instance { key: KEY, value: 0 })
        .expect("local dispose");
    f.write(B, 2, 21);
    assert_eq!(
        f.take_all(),
        vec![(
            KEY,
            None,
            InstanceState::NotAliveDisposed,
            ViewState::NotNew
        )],
        "the local owner disposed it; B stays hidden"
    );

    drop(local);
    f.write(B, 3, 22);
    assert_eq!(
        f.take_all(),
        vec![alive(22, ViewState::New)],
        "the owner is gone: B's sample brings the instance back"
    );
}

/// A local writer's dispose follows its own earlier sample, whatever other
/// writers' samples sit in front of that sample in the cache. The samples
/// read after the dispose was received carry the instance state at the time
/// they are read (DDS v1.4 Sec.2.2.2.5.1.3), NOT_ALIVE_DISPOSED; what the
/// order decides is that the transition is not returned before the value
/// the writer wrote before disposing.
#[test]
fn a_local_dispose_follows_its_writers_sample_behind_a_remote_one() {
    let topic = "shared-local-dispose-order";
    let f = Fixture::new(topic, OwnershipKind::Shared, [0, 0, 0]);
    let local = f.local_writer_of(topic, QoS::best_effort().keep_last(16));
    f.write(A, 1, 10);
    local
        .write(&Instance {
            key: KEY,
            value: 50,
        })
        .expect("local write");
    local
        .dispose(&Instance { key: KEY, value: 0 })
        .expect("local dispose");
    assert_eq!(
        f.take_all(),
        vec![
            (
                KEY,
                Some(10),
                InstanceState::NotAliveDisposed,
                ViewState::New
            ),
            (
                KEY,
                Some(50),
                InstanceState::NotAliveDisposed,
                ViewState::NotNew
            ),
            (
                KEY,
                None,
                InstanceState::NotAliveDisposed,
                ViewState::NotNew
            ),
        ],
        "the dispose comes after the local writer's sample, not before it"
    );
}

/// The same for a remote writer: its dispose follows its own sample even
/// when another writer's sample is in front of that sample. Only the order
/// is asserted: the instance state a sample is read with depends on when the
/// network samples are pumped relative to the transition being recorded,
/// which this test does not control.
#[test]
fn a_remote_dispose_follows_its_writers_sample_behind_another_writers() {
    let f = Fixture::new(
        "shared-remote-dispose-order",
        OwnershipKind::Shared,
        [0, 0, 0],
    );
    f.write(B, 1, 20);
    f.write(A, 1, 10);
    f.key_only(A, 2, DISPOSED);
    let taken = f.take_all();
    assert_eq!(
        taken.iter().map(|t| t.1).collect::<Vec<_>>(),
        vec![Some(20), Some(10), None],
        "A's dispose comes after A's sample: {taken:?}"
    );
    assert_eq!(taken[2].2, InstanceState::NotAliveDisposed);
}

/// A SHARED reader: a remote writer's unregister leaves the instance ALIVE
/// while a local writer still writes it (DDS v1.4 Sec.2.2.2.4.2.7:
/// NOT_ALIVE_NO_WRITERS "if no other DataWriter entities are writing the
/// instance").
#[test]
fn a_remote_unregister_leaves_a_shared_instance_a_local_writer_still_writes() {
    let topic = "shared-remote-unregister-local-holds";
    let f = Fixture::new(topic, OwnershipKind::Shared, [0, 0, 0]);
    let local = f.local_writer_of(topic, QoS::best_effort().keep_last(16));
    local
        .write(&Instance {
            key: KEY,
            value: 50,
        })
        .expect("local write");
    f.write(A, 1, 10);
    assert_eq!(f.take_all().len(), 2);

    f.key_only(A, 2, UNREGISTERED);
    assert_eq!(f.take_all(), vec![], "the local writer still writes it");
    local
        .write(&Instance {
            key: KEY,
            value: 51,
        })
        .expect("local write");
    assert_eq!(f.take_all(), vec![alive(51, ViewState::NotNew)]);
}

/// A SHARED reader: a remote writer's stale registration (it lost
/// LIVELINESS, which keeps its standing recorded, unlike a departure)
/// must not mask the LOCAL writer's own unregister - the local writer is
/// the only one left alive, so its unregister must move the instance
/// through the exact admission path a local writer's lifecycle entry
/// takes (`DataReader::admit_lifecycle_entry`), not only the remote one
/// covered above.
#[test]
fn a_not_alive_remote_writers_stale_registration_does_not_mask_a_local_unregister() {
    let topic = "shared-liveliness-local-unregister";
    let f = Fixture::new(topic, OwnershipKind::Shared, [0, 0, 0]);
    let local = f.local_writer_of(
        topic,
        QoS::best_effort()
            .keep_last(16)
            .writer_data_lifecycle_manual_dispose(),
    );
    local
        .write(&Instance {
            key: KEY,
            value: 50,
        })
        .expect("local write");
    f.write(A, 1, 10);
    assert_eq!(f.take_all().len(), 2);

    f.lose_liveliness(A);
    assert_eq!(
        f.take_all(),
        vec![],
        "A is not alive, but it did not unregister: no transition of its own"
    );

    local
        .unregister_instance(&Instance { key: KEY, value: 0 })
        .expect("unregister");
    assert_eq!(
        f.take_all(),
        vec![(
            KEY,
            None,
            InstanceState::NotAliveNoWriters,
            ViewState::NotNew
        )],
        "A is not alive: the local writer's unregister must move the \
         instance, not be masked by A's stale registration"
    );
}

/// A SHARED reader: one of two local writers unregistering leaves the
/// instance ALIVE, and the last one leaves it without writers.
#[test]
fn one_of_two_local_writers_unregistering_keeps_a_shared_instance_alive() {
    let topic = "shared-two-local-unregister";
    let f = Fixture::new(topic, OwnershipKind::Shared, [0, 0, 0]);
    // An unregister that only unregisters (autodispose_unregistered_instances
    // FALSE, Sec.2.2.3.21): with the default TRUE it disposes too.
    let qos = || {
        QoS::best_effort()
            .keep_last(16)
            .writer_data_lifecycle_manual_dispose()
    };
    let first = f.local_writer_of(topic, qos());
    let second = f.local_writer_of(topic, qos());
    first
        .write(&Instance { key: KEY, value: 1 })
        .expect("write");
    second
        .write(&Instance { key: KEY, value: 2 })
        .expect("write");
    assert_eq!(f.take_all().len(), 2);

    first
        .unregister_instance(&Instance { key: KEY, value: 0 })
        .expect("unregister");
    assert_eq!(f.take_all(), vec![], "the second writer still writes it");

    second
        .unregister_instance(&Instance { key: KEY, value: 0 })
        .expect("unregister");
    assert_eq!(
        f.take_all(),
        vec![(
            KEY,
            None,
            InstanceState::NotAliveNoWriters,
            ViewState::NotNew
        )]
    );
}

/// A SHARED reader: a remote writer's departure leaves the instance ALIVE
/// while a local writer still writes it, and a local writer's deletion
/// leaves it without writers once no one else holds it.
#[test]
fn a_remote_departure_leaves_a_shared_instance_a_local_writer_still_writes() {
    let topic = "shared-remote-departure-local-holds";
    let f = Fixture::new(topic, OwnershipKind::Shared, [0, 0, 0]);
    // A deletion that only unregisters (autodispose_unregistered_instances
    // FALSE, Sec.2.2.3.21): with the default TRUE it disposes too.
    let local = f.local_writer_of(
        topic,
        QoS::best_effort()
            .keep_last(16)
            .writer_data_lifecycle_manual_dispose(),
    );
    local
        .write(&Instance {
            key: KEY,
            value: 50,
        })
        .expect("local write");
    f.write(A, 1, 10);
    assert_eq!(f.take_all().len(), 2);

    f.depart(A);
    assert_eq!(f.take_all(), vec![], "the local writer still writes it");

    drop(local);
    assert_eq!(
        f.take_all(),
        vec![(
            KEY,
            None,
            InstanceState::NotAliveNoWriters,
            ViewState::NotNew
        )],
        "its last writer was deleted"
    );
}

/// An EXCLUSIVE reader: a local owner's own unregister, the only writer of
/// the instance, leaves it without writers. The unregister crosses the
/// ownership gate with its sequence number, after the writer forgot the
/// instance.
#[test]
fn a_local_owners_unregister_leaves_the_instance_without_writers() {
    let topic = "excl-local-unregister";
    let f = Fixture::new(topic, OwnershipKind::Exclusive, [0, 0, 0]);
    let local = f.local_writer_of(
        topic,
        QoS::best_effort()
            .keep_last(16)
            .ownership_exclusive()
            .ownership_strength(5)
            .writer_data_lifecycle_manual_dispose(),
    );
    local
        .write(&Instance {
            key: KEY,
            value: 50,
        })
        .expect("local write");
    assert_eq!(f.take_all(), vec![alive(50, ViewState::New)]);
    local
        .unregister_instance(&Instance { key: KEY, value: 0 })
        .expect("unregister");
    assert_eq!(
        f.take_all(),
        vec![(
            KEY,
            None,
            InstanceState::NotAliveNoWriters,
            ViewState::NotNew
        )]
    );
}

/// An EXCLUSIVE reader: a local owner's deletion unregisters what it wrote
/// (DDS v1.4 Sec.2.2.3.23.3), and the reader sees the instance without
/// writers at once, through the Drop-time unregister, not at its next
/// arbitration.
#[test]
fn a_local_owners_deletion_unregisters_at_once() {
    let topic = "excl-local-drop";
    let f = Fixture::new(topic, OwnershipKind::Exclusive, [0, 0, 0]);
    let local = f.local_writer(topic, 5);
    local
        .write(&Instance {
            key: KEY,
            value: 50,
        })
        .expect("local write");
    assert_eq!(f.take_all(), vec![alive(50, ViewState::New)]);
    drop(local);
    assert_eq!(
        f.take_all(),
        vec![(
            KEY,
            None,
            InstanceState::NotAliveNoWriters,
            ViewState::NotNew
        )]
    );
}

/// An EXCLUSIVE reader: a local writer that unregisters and then writes the
/// instance again registers it again and takes it back, by the order of its
/// own sequence numbers (its sample after the unregister); the weaker
/// remote writer is hidden again.
#[test]
fn a_local_writer_that_writes_again_after_its_unregister_owns_again() {
    let topic = "excl-local-rewrite";
    let f = Fixture::new(topic, OwnershipKind::Exclusive, [0, 1, 0]);
    let local = f.local_writer_of(
        topic,
        QoS::best_effort()
            .keep_last(16)
            .ownership_exclusive()
            .ownership_strength(50)
            .writer_data_lifecycle_manual_dispose(),
    );
    local
        .write(&Instance {
            key: KEY,
            value: 50,
        })
        .expect("local write");
    local
        .unregister_instance(&Instance { key: KEY, value: 0 })
        .expect("unregister");
    local
        .write(&Instance {
            key: KEY,
            value: 51,
        })
        .expect("local write");
    f.write(B, 1, 20);
    let taken = f.take_all();
    assert_eq!(
        taken.iter().filter_map(|t| t.1).collect::<Vec<_>>(),
        vec![50, 51],
        "B is hidden: the local writer owns the instance again ({taken:?})"
    );
}

/// An EXCLUSIVE reader: a local owner that disposed the instance and was
/// deleted sends no unregister for it (`DataWriter::drop` skips a disposed
/// instance). The first thing the reader hears after is a weaker remote
/// writer's dispose, and it applies: the deleted owner relinquished the
/// instance (Sec.2.2.3.23.3), which the reader notices on a lifecycle
/// change as on a sample.
#[test]
fn a_dispose_after_a_disposed_local_owners_deletion_applies() {
    let topic = "excl-local-disposed-then-remote-dispose";
    let f = Fixture::new(topic, OwnershipKind::Exclusive, [0, 1, 0]);
    let local = f.local_writer(topic, 50);
    local
        .write(&Instance {
            key: KEY,
            value: 50,
        })
        .expect("local write");
    f.write(B, 1, 20);
    local
        .dispose(&Instance { key: KEY, value: 0 })
        .expect("local dispose");
    f.write(B, 2, 21);
    assert_eq!(f.take_all().len(), 2, "the local sample and its dispose");

    drop(local);
    f.key_only(B, 3, DISPOSED);
    assert_eq!(
        f.take_all(),
        vec![(
            KEY,
            None,
            InstanceState::NotAliveDisposed,
            ViewState::NotNew
        )],
        "the owner is gone: B's dispose applies"
    );
}

/// An EXCLUSIVE reader whose local writer was deleted without its unregister
/// reaching the reader (a slab or journal failure in its `Drop`): when the
/// reader notices the deletion, an instance the writer left without writers
/// moves to NOT_ALIVE_NO_WRITERS, as a remote writer's departure does.
/// Driven on the reader's own registration table, with a merger standing in
/// for a writer whose unregister was lost.
#[test]
fn a_deleted_local_writer_whose_unregister_was_lost_leaves_its_instances_without_writers() {
    let topic = "excl-local-lost-unregister";
    let f = Fixture::new(topic, OwnershipKind::Exclusive, [0, 1, 0]);
    let registrations = f.reader.registrations_for_test();
    const LOST: [u8; 16] = [0x77; 16];
    let merger = Arc::new(crate::core::rt::TopicMerger::new());
    registrations.lock().add_local_writer(LOST, 5, &merger);
    assert!(registrations.admit_sample(LOST, key_hash(KEY), 1));
    drop(merger);

    // Any admission notices the deletion: another writer's sample of
    // another instance.
    f.write_key(B, 1, 8, 80);
    let taken = f.take_all();
    assert!(
        taken.contains(&(KEY, None, InstanceState::NotAliveNoWriters, ViewState::New)),
        "the instance the deleted writer held moved to NOT_ALIVE_NO_WRITERS: {taken:?}"
    );
}

/// The same, when the unregister was refused by a full reader ring rather
/// than lost before it: the ownership gate runs before the push, and must not
/// record the unregister if the push that follows fails, or the writer's
/// deletion would find the instance already let go and announce nothing -
/// the instance would stay ALIVE with no writer left. The gate records only
/// what the reader takes.
#[test]
fn an_unregister_a_full_ring_refused_is_not_recorded() {
    let topic = "excl-local-full-ring-unregister";
    let f = Fixture::new(topic, OwnershipKind::Exclusive, [0, 1, 0]);
    let local = f.local_writer(topic, 5);
    // Far more than the binding ring holds: the ring is full when the
    // writer's deletion pushes its unregister.
    for value in 0..4096 {
        local
            .write(&Instance { key: KEY, value })
            .expect("local write");
    }
    drop(local);

    // Any admission notices the deletion: another writer's sample of
    // another instance.
    f.write_key(B, 1, 8, 80);
    let taken = f.take_all();
    assert!(
        taken
            .iter()
            .any(|t| t.0 == KEY && t.2 == InstanceState::NotAliveNoWriters),
        "the instance the deleted writer held moved to NOT_ALIVE_NO_WRITERS: {:?}",
        taken
            .iter()
            .filter(|t| t.0 == KEY && t.1.is_none())
            .collect::<Vec<_>>()
    );
}

/// Two DataWriters of no participant, equal strength: two writers, so one
/// owns the instance and the other is hidden (which one depends on their
/// process-random identities, Sec.2.2.3.9.2 only asks that every reader
/// pick the same).
#[test]
fn two_participant_less_local_writers_are_two_writers() {
    let topic = "excl-two-local-identities";
    let f = Fixture::new(topic, OwnershipKind::Exclusive, [0, 0, 0]);
    let first = f.local_writer(topic, 5);
    let second = f.local_writer(topic, 5);
    for (writer, value) in [(&first, 1), (&second, 2), (&first, 3), (&second, 4)] {
        writer
            .write(&Instance { key: KEY, value })
            .expect("local write");
    }
    let values: Vec<i64> = f.take_all().iter().filter_map(|t| t.1).collect();
    assert!(
        values == vec![1, 3] || values == vec![1, 2, 4],
        "one writer owns the instance from the second write on: {values:?}"
    );
}

/// The ownership gate runs after the content filter: a local sample the
/// reader's filter rejects is not seen, so it does not make its writer the
/// owner either, and a weaker remote writer whose sample passes is seen.
#[test]
fn a_filtered_out_local_sample_does_not_take_the_instance() {
    let topic = "excl-filter-then-gate";
    let f = Fixture::filtered(topic, [0, 1, 0], "value < 100");
    let local = f.local_writer(topic, 50);
    local
        .write(&Instance {
            key: KEY,
            value: 500,
        })
        .expect("local write");
    f.write(B, 1, 20);
    assert_eq!(
        f.take_all(),
        vec![alive(20, ViewState::New)],
        "the local writer's only sample was filtered out: B owns the instance"
    );
}

/// A dropped EXCLUSIVE reader does not stay alive in the ownership gates it
/// left in a living local writer's merger: its registration table is freed
/// with it. (A reader of no participant, so nothing else holds the table.)
#[test]
fn a_dropped_reader_is_not_kept_alive_by_a_local_writers_gate() {
    let _ = rt::init_slab_pool();
    let topic = "excl-gate-weak";
    let reader = ReaderBuilder::<Instance>::new(topic.to_string())
        .qos(QoS::best_effort().keep_last(16).ownership_exclusive())
        .build()
        .expect("reader build should succeed");
    let local = crate::dds::writer::WriterBuilder::<Instance>::new(topic.to_string())
        .qos(
            QoS::best_effort()
                .keep_last(16)
                .ownership_exclusive()
                .ownership_strength(5),
        )
        .build()
        .expect("writer build should succeed");
    reader.bind_to_writer(local.merger());
    local
        .write(&Instance { key: KEY, value: 1 })
        .expect("local write");
    let registrations = Arc::downgrade(reader.registrations_for_test());
    drop(reader);
    assert!(
        registrations.upgrade().is_none(),
        "the reader's table outlived the reader"
    );
    local
        .write(&Instance { key: KEY, value: 2 })
        .expect("a write after the reader left");
}

/// A durable local writer's history replayed to an EXCLUSIVE reader that
/// binds later is arbitrated too (the replay carries no key hash: the gate
/// derives it from the bytes): the writer owns the instance, and the weaker
/// remote writer is hidden.
#[test]
fn a_replayed_local_history_is_arbitrated() {
    let topic = "excl-local-replay";
    let f = Fixture::new(topic, OwnershipKind::Exclusive, [0, 1, 0]);
    let local = crate::dds::writer::WriterBuilder::<Instance>::new(topic.to_string())
        .qos(
            QoS::best_effort()
                .keep_last(16)
                .transient_local()
                .ownership_exclusive()
                .ownership_strength(50),
        )
        .build()
        .expect("writer build should succeed");
    local
        .write(&Instance {
            key: KEY,
            value: 50,
        })
        .expect("local write");
    f.reader.bind_to_writer(local.merger());
    f.write(B, 1, 20);
    let values: Vec<i64> = f.take_all().iter().filter_map(|t| t.1).collect();
    assert_eq!(values, vec![50], "the replayed writer owns the instance");
}

/// The gate takes the writer's key hash instead of decoding the sample on
/// the writer's thread: a write to an EXCLUSIVE reader decodes nothing
/// before the reader takes it.
#[test]
fn the_gate_does_not_decode_a_local_sample() {
    static DECODES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    #[derive(Debug, Clone, Copy, PartialEq)]
    struct Counted {
        key: i64,
        value: i64,
    }
    impl DDS for Counted {
        fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
            InstanceWire::type_descriptor()
        }
        fn encode(
            &self,
            buf: &mut [u8],
            version: crate::dds::CdrVersion,
        ) -> crate::dds::Result<usize> {
            Instance {
                key: self.key,
                value: self.value,
            }
            .encode(buf, version)
        }
        fn decode(buf: &[u8], version: crate::dds::CdrVersion) -> crate::dds::Result<Self> {
            DECODES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let i = Instance::decode(buf, version)?;
            Ok(Self {
                key: i.key,
                value: i.value,
            })
        }
        fn compute_key(&self) -> [u8; 16] {
            key_hash(self.key)
        }
        fn has_key() -> bool {
            true
        }
    }

    let _ = rt::init_slab_pool();
    let topic = "excl-gate-no-decode";
    let reader = ReaderBuilder::<Counted>::new(topic.to_string())
        .qos(QoS::best_effort().keep_last(16).ownership_exclusive())
        .build()
        .expect("reader build should succeed");
    let writer = crate::dds::writer::WriterBuilder::<Counted>::new(topic.to_string())
        .qos(
            QoS::best_effort()
                .keep_last(16)
                .ownership_exclusive()
                .ownership_strength(5),
        )
        .build()
        .expect("writer build should succeed");
    reader.bind_to_writer(writer.merger());
    let before = DECODES.load(std::sync::atomic::Ordering::SeqCst);
    writer
        .write(&Counted { key: KEY, value: 1 })
        .expect("local write");
    assert_eq!(
        DECODES.load(std::sync::atomic::Ordering::SeqCst),
        before,
        "the write decoded the sample"
    );
    assert_eq!(reader.take().expect("take").map(|s| s.value), Some(1));
}

/// A reader the production builder makes against a topic registry (the
/// subscriber token path, `ReaderBuilder::build`), with every feature the
/// fixture above turns on (EXCLUSIVE ownership, a DEADLINE, a content
/// filter), holds nothing alive once it is dropped: its subscriber is dead
/// (no strong reference, no weak one left keeping its allocation) and the
/// registry no longer routes to it. The fixtures of this module register a
/// subscriber of their own on a registry that the subscriber also holds
/// (a cycle only the fixture forms); this is the same chain as production
/// builds it, which must not keep one.
#[test]
fn a_dropped_production_reader_leaves_no_subscriber_behind() {
    let _ = rt::init_slab_pool();
    for (topic, filter) in [
        ("excl-prod-release-plain", None),
        ("excl-prod-release-filtered", Some("value < 100")),
    ] {
        let registry = Arc::new(TopicRegistry::new());
        let mut builder = ReaderBuilder::<Instance>::new(topic.to_string());
        if let Some(filter) = filter {
            builder = builder.with_content_filter(
                crate::dds::filter::ContentFilter::new(filter)
                    .expect("filter")
                    .evaluator(),
            );
        }
        let reader = builder
            .qos(
                QoS::best_effort()
                    .keep_last(16)
                    .ownership_exclusive()
                    .deadline(crate::qos::deadline::Deadline::new(
                        std::time::Duration::from_secs(60),
                    )),
            )
            .network_ring_for_test()
            .with_registry(Arc::clone(&registry))
            .build()
            .expect("reader build should succeed");
        let subscriber = reader.subscriber_weak_for_test();
        let room = reader
            .network_room_for_test()
            .map(Arc::downgrade)
            .expect("fixture: the reader has a room");
        assert!(
            subscriber.upgrade().is_some(),
            "fixture: the subscriber is alive while the reader is"
        );
        assert_eq!(
            registry.get_topic(topic).map(|t| t.subscriber_count()),
            Some(1),
            "fixture: the registry routes to the reader's subscriber"
        );

        drop(reader);

        assert_eq!(
            subscriber.strong_count(),
            0,
            "{topic}: the dropped reader's subscriber is still alive"
        );
        assert_eq!(
            subscriber.weak_count(),
            0,
            "{topic}: something still holds a weak reference to the subscriber \
             (its allocation outlives it)"
        );
        assert_eq!(
            room.strong_count(),
            0,
            "{topic}: the dropped reader's history room is still alive"
        );
        assert_eq!(
            registry.get_topic(topic).map(|t| t.subscriber_count()),
            Some(0),
            "{topic}: the registry still routes to the dropped reader"
        );
        assert_eq!(
            Arc::strong_count(&registry),
            1,
            "{topic}: the dropped reader still holds the registry"
        );
    }
}
