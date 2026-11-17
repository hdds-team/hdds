// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Which instance a received dispose or unregister names, under EXCLUSIVE
//! ownership, where naming the wrong one is visible: the owner's unregister
//! must hand the instance to the next writer, a non-owner's dispose must not
//! touch it.
//!
//! A reader names an instance by `T::compute_key`, the KeyHash of DDSI-RTPS
//! 2.5 9.6.4.8 / DDS-XTypes 1.3 7.6.8. A key-only DATA (K=1) carries two
//! names for its instance: its serializedPayload, "the value of the key that
//! identifies the registered instance" (8.3.7.2), and maybe a PID_KEY_HASH,
//! "a hint for the key" (8.7.10). The reader names the change by the key
//! when its type reads it (`DDS::key_hash_of_key_payload`) and by the
//! PID_KEY_HASH otherwise.
//!
//! So a writer whose PID_KEY_HASH is not the reader's KeyHash (HDDS 1.4.x
//! hashed the key of every `hdds_gen` type with FNV-1a; [`fnv_key_hash`]
//! reproduces it), or that sends none, still reaches the instance when it
//! serialized the key. A 1.4.x writer of a generated type serialized no key
//! (its `encode_key` was the empty default), so its dispose and unregister
//! carry nothing but the FNV hash. A peer flagged legacy
//! (`TopicRegistry::writer_uses_legacy_key_hash`: vendor HDDS, not
//! announcing `CAP_CONFORMANT_KEY_HASH`) still names the instance it means
//! IF this reader has decoded one ordinary ALIVE sample bearing the same
//! hash first -- every 1.4.x sample carries it, not only a lifecycle one
//! (`TopicRegistry::resolve_legacy_key_hash_instance`,
//! [`a_1_4_dispose_with_an_empty_key_is_resolved_once_its_writer_has_been_seen_alive`]).
//! With nothing to resolve against, it still names an instance the 1.5.0
//! reader never wrote
//! ([`a_1_4_dispose_with_an_empty_key_names_another_instance`], the residual
//! case the changelog's upgrade notes describe).

use super::ReaderBuilder;
use crate::core::discovery::multicast::{classify_rtps, PacketKind};
use crate::core::rt;
use crate::dds::{DataReader, InstanceState, QoS, DDS};
use crate::engine::{route_data_packet, RouterMetrics, Subscriber, TopicRegistry};
use crate::qos::ownership::OwnershipKind;
use std::sync::Arc;

/// A type keyed on `key`, as `hdds_gen` 1.5.0 and `#[derive(DDS)]` key it:
/// `compute_key` is the KeyHash, and the type reads its key-only payload.
#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct Keyed {
    #[key]
    key: i64,
    value: i64,
}

const KEY: i64 = 7;

/// The KeyHash of `key` (DDSI-RTPS 2.5 9.6.4.8): one `int64` key member
/// serializes to 8 big-endian octets (at most 16, so Step 5.1: zero-padded,
/// no MD5).
fn rtps_key_hash(key: i64) -> [u8; 16] {
    let mut hash = [0u8; 16];
    hash[..8].copy_from_slice(&key.to_be_bytes());
    hash
}

/// The PID_KEY_HASH an HDDS 1.4.x writer of an `hdds_gen` type sends for an
/// `int64` key member: FNV-1a over its little-endian bytes, as the 1.4.x
/// Rust backend emitted `compute_key` (`rust_backend/dds_trait.rs`,
/// `emit_compute_key_method`).
fn fnv_key_hash(key: i64) -> [u8; 16] {
    let mut hash: u64 = 14_695_981_039_346_656_037;
    const PRIME: u64 = 1_099_511_628_211;
    for b in key.to_le_bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(PRIME);
    }
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&hash.to_le_bytes());
    hash = hash.wrapping_mul(PRIME);
    out[8..].copy_from_slice(&hash.to_le_bytes());
    out
}

/// A: strength 10, B: strength 1, each of its own participant.
const A: [u8; 16] = [
    0x01, 0x0f, 0xa1, 0xa1, 0x0e, 0x00, 0xad, 0xef, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x02,
];
const B: [u8; 16] = [
    0x01, 0x0f, 0xb2, 0xb2, 0x0e, 0x00, 0xad, 0xef, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x02,
];

const DISPOSED: u8 = 0x01;
const UNREGISTERED: u8 = 0x02;

/// The inline QoS of a lifecycle change: StatusInfo `status`, then
/// PID_KEY_HASH when given, then PID_COHERENT_SET when given.
struct Lifecycle {
    status: u8,
    key_hash: Option<[u8; 16]>,
    coherent_set: Option<u32>,
}

/// One little-endian DATA of `writer` as change `sn`, with the inline QoS
/// of `lifecycle` when given.
fn datagram(
    writer: [u8; 16],
    sn: u32,
    flags: u8,
    lifecycle: Option<&Lifecycle>,
    payload: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(&16u16.to_le_bytes());
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend_from_slice(&writer[12..]);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&sn.to_le_bytes());
    if let Some(l) = lifecycle {
        body.extend_from_slice(&[0x71, 0x00, 0x04, 0x00, 0, 0, 0, l.status]);
        if let Some(key_hash) = l.key_hash {
            body.extend_from_slice(&[0x70, 0x00, 0x10, 0x00]);
            body.extend_from_slice(&key_hash);
        }
        if let Some(set) = l.coherent_set {
            body.extend_from_slice(&[0x56, 0x00, 0x08, 0x00]);
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&set.to_le_bytes());
        }
        body.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    }
    body.extend_from_slice(payload);
    assert_eq!(body.len() % 4, 0);
    let mut packet = Vec::new();
    packet.extend_from_slice(b"RTPS");
    packet.extend_from_slice(&[2, 5, 0x01, 0x0f]);
    packet.extend_from_slice(&writer[..12]);
    packet.extend_from_slice(&[0x15, 0x01 | flags]);
    packet.extend_from_slice(&u16::try_from(body.len()).expect("fits").to_le_bytes());
    packet.extend_from_slice(&body);
    packet
}

/// One little-endian ORDINARY (D=1, no StatusInfo) DATA of `writer` as
/// change `sn`, carrying `key_hash` as its ONLY inline QoS parameter: what
/// a REAL HDDS 1.4.x writer's every sample carries beside the full
/// payload, lifecycle or not -- its generated `compute_key` is the FNV
/// hash ([`fnv_key_hash`]) for every PID_KEY_HASH it ever emits, not just a
/// dispose/unregister's. [`datagram`]'s `write`/`write_key` helper omits
/// this (the other tests do not need it), so a test
/// that wants the reader to have LEARNED the real instance behind a
/// writer's FNV hash goes through this one instead.
fn datagram_with_key_hash(
    writer: [u8; 16],
    sn: u32,
    key_hash: [u8; 16],
    payload: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(&16u16.to_le_bytes());
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend_from_slice(&writer[12..]);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&sn.to_le_bytes());
    body.extend_from_slice(&[0x70, 0x00, 0x10, 0x00]);
    body.extend_from_slice(&key_hash);
    body.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    body.extend_from_slice(payload);
    assert_eq!(body.len() % 4, 0);
    let mut packet = Vec::new();
    packet.extend_from_slice(b"RTPS");
    packet.extend_from_slice(&[2, 5, 0x01, 0x0f]);
    packet.extend_from_slice(&writer[..12]);
    // D (0x04, data present) + InlineQoS (0x02) + LE (0x01).
    packet.extend_from_slice(&[0x15, 0x07]);
    packet.extend_from_slice(&u16::try_from(body.len()).expect("fits").to_le_bytes());
    packet.extend_from_slice(&body);
    packet
}

/// The serializedPayload a conforming writer sends with a dispose or
/// unregister of `key`: D_CDR2_LE, then `Keyed`'s key-only payload.
fn serialized_key(key: i64) -> Vec<u8> {
    let mut payload = vec![0x00, 0x09, 0x00, 0x00];
    payload.extend_from_slice(&Keyed { key, value: 0 }.encode_key(crate::dds::CdrVersion::Xcdr2));
    payload
}

/// What an HDDS 1.4.x writer of an `hdds_gen` type sends as the
/// serializedPayload of a dispose or unregister: the encapsulation header
/// and no key (its `encode_key` returned nothing).
const EMPTY_KEY_1_4: [u8; 4] = [0x00, 0x09, 0x00, 0x00];

struct Fixture {
    /// Unregisters `subscriber` from `registry` when the fixture drops (the
    /// subscriber holds the registry and the registry the subscriber).
    _registration: crate::engine::SubscriberToken,
    reader: Arc<DataReader<Keyed>>,
    registry: Arc<TopicRegistry>,
    subscriber: Arc<super::subscriber::ReaderSubscriber<Keyed>>,
}

impl Fixture {
    fn new(topic: &str) -> Self {
        Self::with_qos(topic, QoS::best_effort().keep_last(16))
    }

    fn with_qos(topic: &str, qos: QoS) -> Self {
        let _ = rt::init_slab_pool();
        let reader = Arc::new(
            ReaderBuilder::<Keyed>::new(topic.to_string())
                .qos(qos)
                .network_ring_for_test()
                .build()
                .expect("reader build should succeed"),
        );
        let network_ring = Arc::clone(reader.network_ring_for_test().expect("network ring"));
        let registry = Arc::new(TopicRegistry::new());
        let sub = super::subscriber::ReaderSubscriber::<Keyed>::new_with_coherent(
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
            OwnershipKind::Exclusive,
            Some(Arc::clone(&registry)),
            None,
            None,
            #[cfg(feature = "security")]
            None,
        )
        .with_room(reader.network_room_for_test().cloned());
        let sub = Arc::new(sub);
        let registration = registry
            .register_subscriber_scoped(Arc::clone(&sub) as Arc<dyn Subscriber>)
            .expect("register subscriber");
        for (writer, strength) in [(A, 10), (B, 1)] {
            registry.register_writer_guid(writer, topic.to_string());
            registry.register_writer_ownership_kind(writer, OwnershipKind::Exclusive);
            registry.register_writer_ownership_strength(writer, strength);
        }
        // A is the fixture's stand-in for an HDDS 1.4.x writer (B is a
        // conforming one): real SEDP/SPDP discovery is bypassed here, as
        // for every other writer fact above, so the flag
        // `record_writer_vendor` would otherwise derive from A's
        // participant capabilities is set directly.
        registry.register_writer_legacy_key_hash(A, true);
        Self {
            _registration: registration,
            reader,
            registry,
            subscriber: sub,
        }
    }

    fn route(&self, packet: &[u8]) {
        let _ = self.route_counted(packet);
    }

    /// Route `packet`; the router's count of lifecycle changes that named
    /// no instance for a subscriber.
    fn route_counted(&self, packet: &[u8]) -> u64 {
        let (kind, offset, _, _) = classify_rtps(packet);
        assert_eq!(kind, PacketKind::Data);
        let metrics = RouterMetrics::new();
        let _ = route_data_packet(packet, packet.len(), offset, &self.registry, &metrics);
        metrics
            .lifecycle_unnamed
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn write(&self, writer: [u8; 16], sn: u32, value: i64) {
        self.write_key(writer, sn, KEY, value);
    }

    fn write_key(&self, writer: [u8; 16], sn: u32, key: i64, value: i64) {
        let mut payload = vec![0u8; 64];
        let len = Keyed { key, value }
            .encode(&mut payload[4..], crate::dds::CdrVersion::Xcdr2)
            .expect("encode");
        payload[..4].copy_from_slice(&[0x00, 0x09, 0x00, 0x00]);
        payload.truncate(4 + len);
        while !payload.len().is_multiple_of(4) {
            payload.push(0);
        }
        self.route(&datagram(writer, sn, 0x04, None, &payload));
    }

    /// [`write_key`](Self::write_key), but the DATA also carries
    /// `key_hash` in inline QoS ([`datagram_with_key_hash`]): what a REAL
    /// HDDS 1.4.x writer's ordinary samples do, so this reader gets the
    /// chance to learn the real instance behind that hash before a later
    /// dispose/unregister needs to resolve it.
    fn write_key_with_hash(
        &self,
        writer: [u8; 16],
        sn: u32,
        key: i64,
        value: i64,
        key_hash: [u8; 16],
    ) {
        let mut payload = vec![0u8; 64];
        let len = Keyed { key, value }
            .encode(&mut payload[4..], crate::dds::CdrVersion::Xcdr2)
            .expect("encode");
        payload[..4].copy_from_slice(&[0x00, 0x09, 0x00, 0x00]);
        payload.truncate(4 + len);
        while !payload.len().is_multiple_of(4) {
            payload.push(0);
        }
        self.route(&datagram_with_key_hash(writer, sn, key_hash, &payload));
    }

    /// `writer` sends a key-only lifecycle change (K=1) as `lifecycle`
    /// says, with `payload` as its serializedPayload.
    fn lifecycle(&self, writer: [u8; 16], sn: u32, lifecycle: &Lifecycle, payload: &[u8]) {
        let _ = self.lifecycle_counted(writer, sn, lifecycle, payload);
    }

    /// [`lifecycle`](Self::lifecycle), returning the router's count of
    /// changes that named no instance.
    fn lifecycle_counted(
        &self,
        writer: [u8; 16],
        sn: u32,
        lifecycle: &Lifecycle,
        payload: &[u8],
    ) -> u64 {
        let mut payload = payload.to_vec();
        while !payload.len().is_multiple_of(4) {
            payload.push(0);
        }
        self.route_counted(&datagram(writer, sn, 0x0a, Some(lifecycle), &payload))
    }

    /// A and B both write the instance; A, the stronger, owns it.
    fn both_write(&self) {
        self.write(A, 1, 10);
        self.write(B, 1, 20);
        assert_eq!(
            self.take_all(),
            vec![(instance(), Some(10), InstanceState::Alive)]
        );
    }

    /// After A's unregister: B, still writing, took the instance over.
    fn b_took_over(&self) {
        assert_eq!(self.take_all(), vec![], "B still writes the instance");
        self.write(B, 2, 21);
        assert_eq!(
            self.take_all(),
            vec![(instance(), Some(21), InstanceState::Alive)],
            "the owner let go: B's sample is visible"
        );
    }

    /// What the application takes: the instance handle, the value (None for
    /// a transition) and the instance state.
    fn take_all(&self) -> Vec<([u8; 16], Option<i64>, InstanceState)> {
        let mut taken = Vec::new();
        while let Some((data, info)) = self.reader.take_with_info().expect("take_with_info") {
            taken.push((
                info.instance_handle.0,
                data.map(|sample| sample.value),
                info.instance_state,
            ));
        }
        taken
    }
}

/// The instance the reader writes: `Keyed::compute_key` is the KeyHash.
fn instance() -> [u8; 16] {
    let instance = Keyed { key: KEY, value: 0 }.compute_key();
    assert_eq!(instance, rtps_key_hash(KEY));
    instance
}

const fn unregister(key_hash: Option<[u8; 16]>) -> Lifecycle {
    Lifecycle {
        status: UNREGISTERED,
        key_hash,
        coherent_set: None,
    }
}

/// A conforming writer's unregister: the KeyHash as PID_KEY_HASH, the key
/// serialized. The owner relinquishes the instance (DDS v1.4
/// Sec.2.2.3.23.3) and B, still writing it, takes over.
#[test]
fn a_foreign_owners_unregister_releases_the_instance() {
    let f = Fixture::new("foreign-key-hash-spec");
    f.both_write();
    f.lifecycle(
        A,
        2,
        &unregister(Some(rtps_key_hash(KEY))),
        &serialized_key(KEY),
    );
    f.b_took_over();
}

/// A non-owner's dispose reaches the written instance, which A owns, so it
/// is not applied (DDS v1.4 Sec.2.2.3.23.3).
#[test]
fn a_non_owners_dispose_is_not_applied() {
    let f = Fixture::new("foreign-key-hash-dispose");
    f.both_write();
    let dispose = Lifecycle {
        status: DISPOSED,
        key_hash: Some(rtps_key_hash(KEY)),
        coherent_set: None,
    };
    f.lifecycle(B, 2, &dispose, &serialized_key(KEY));
    assert_eq!(f.take_all(), vec![], "B does not own the instance");
    f.write(A, 2, 11);
    assert_eq!(
        f.take_all(),
        vec![(instance(), Some(11), InstanceState::Alive)],
        "the written instance was never disposed"
    );
}

/// An unregister with no PID_KEY_HASH ("when the key hash is not received
/// by a DataReader, it should be computed from the data itself", 8.7.10):
/// named by its serialized key. Before, an `int64` key was not the leading
/// short string the type-blind fallback reads, and the change named nothing.
#[test]
fn an_unregister_without_a_key_hash_is_named_by_its_serialized_key() {
    let f = Fixture::new("foreign-key-hash-none");
    f.both_write();
    f.lifecycle(A, 2, &unregister(None), &serialized_key(KEY));
    f.b_took_over();
}

/// An unregister whose PID_KEY_HASH is not the reader's KeyHash (an FNV
/// hash, as HDDS 1.4.x computed it) but that serialized the key: the key,
/// not the hint, names the instance.
#[test]
fn an_unregister_whose_key_hash_is_not_the_readers_is_named_by_its_serialized_key() {
    assert_ne!(fnv_key_hash(KEY), rtps_key_hash(KEY));
    let f = Fixture::new("foreign-key-hash-fnv");
    f.both_write();
    f.lifecycle(
        A,
        2,
        &unregister(Some(fnv_key_hash(KEY))),
        &serialized_key(KEY),
    );
    f.b_took_over();
}

/// The same, tagged as a member of a coherent set: the router's coherent
/// branch names it the same way.
#[test]
fn a_coherent_unregister_without_a_key_hash_is_named_by_its_serialized_key() {
    let f = Fixture::new("foreign-key-hash-coherent");
    f.both_write();
    let tagged = Lifecycle {
        status: UNREGISTERED,
        key_hash: None,
        coherent_set: Some(2),
    };
    f.lifecycle(A, 2, &tagged, &serialized_key(KEY));
    f.b_took_over();
}

/// A key the reader cannot read (an encapsulation that is not CDR, here
/// 0x0004, XML) leaves the change to its PID_KEY_HASH, never to a guess. The
/// key bytes are those of another key, so a reader that read them anyway
/// would name another instance and B would stay hidden.
#[test]
fn an_unreadable_serialized_key_falls_back_to_the_key_hash() {
    let f = Fixture::new("foreign-key-hash-unreadable");
    f.both_write();
    let mut not_cdr = serialized_key(KEY + 1);
    not_cdr[1] = 0x04;
    f.lifecycle(A, 2, &unregister(Some(rtps_key_hash(KEY))), &not_cdr);
    f.b_took_over();
}

/// A big-endian key (D_CDR2_BE) is read like a little-endian one: the
/// owner's unregister releases the instance, with no PID_KEY_HASH.
#[test]
fn a_big_endian_serialized_key_names_its_instance() {
    let f = Fixture::new("foreign-key-hash-big-endian");
    f.both_write();
    let mut big_endian = vec![0x00, 0x08, 0x00, 0x00];
    big_endian.extend_from_slice(&8u32.to_be_bytes());
    big_endian.extend_from_slice(&KEY.to_be_bytes());
    f.lifecycle(A, 2, &unregister(None), &big_endian);
    f.b_took_over();
}

/// THE 1.4.x INCOMPATIBILITY, RESIDUAL CASE. An HDDS 1.4.x
/// writer's unregister carries its FNV hash as PID_KEY_HASH and no
/// serialized key; this reader resolves such a hash against the real
/// instance it names ONLY once it has decoded an ordinary ALIVE sample of
/// A's that carried the SAME hash (`TopicRegistry::
/// resolve_legacy_key_hash_instance`, exercised by the resolving test right
/// below). `both_write` here uses `write`/`write_key`, which (like every
/// other test in this file) never puts a PID_KEY_HASH on an ordinary
/// sample -- so nothing is ever learned for A, and this one pins what
/// happens when there is genuinely nothing to resolve against: the
/// unregister lands on an instance nobody wrote (NOT_ALIVE_NO_WRITERS for
/// a handle that is the raw hash, not the real instance) and A keeps the
/// real one. Not a defect: without at least one prior ALIVE sample bearing
/// that hash, no reader, 1.4.x or
/// 1.5.0+, has anything to resolve the hash against.
#[test]
fn a_1_4_dispose_with_an_empty_key_names_another_instance() {
    let f = Fixture::new("foreign-key-hash-1-4");
    f.both_write();
    f.lifecycle(A, 2, &unregister(Some(fnv_key_hash(KEY))), &EMPTY_KEY_1_4);
    assert_eq!(
        f.take_all(),
        vec![(fnv_key_hash(KEY), None, InstanceState::NotAliveNoWriters)],
        "the unregister lands on the instance its FNV hash names"
    );
    f.write(B, 2, 21);
    assert_eq!(f.take_all(), vec![], "A still owns the written instance");
}

/// THE 1.4.x INCOMPATIBILITY, RESOLVED CASE. A's wire traffic (for a
/// real HDDS 1.4.x writer, every sample, not only a dispose/unregister)
/// carries the SAME FNV hash for an instance: [`write_key_with_hash`]
/// models that "every sample" fact (unlike `write_key`/`both_write`'s
/// hash-free ordinary writes above). Once this reader has decoded that one
/// ordinary ALIVE sample, A's unregister -- same hash, no key, exactly as
/// 1.4.x's empty `encode_key` sends it -- resolves to the REAL instance
/// through `TopicRegistry::resolve_legacy_key_hash_instance`, not the raw
/// hash bytes: it releases the instance B is still writing, which takes it
/// over, instead of the phantom notification the test above pins for the
/// case nothing was ever learned.
#[test]
fn a_1_4_dispose_with_an_empty_key_is_resolved_once_its_writer_has_been_seen_alive() {
    let f = Fixture::new("foreign-key-hash-1-4-learned");
    f.write_key_with_hash(A, 1, KEY, 10, fnv_key_hash(KEY));
    f.write(B, 1, 20);
    assert_eq!(
        f.take_all(),
        vec![(instance(), Some(10), InstanceState::Alive)],
        "A's ALIVE sample (carrying its FNV hash) is the stronger owner's"
    );
    f.lifecycle(A, 2, &unregister(Some(fnv_key_hash(KEY))), &EMPTY_KEY_1_4);
    f.b_took_over();
}

/// A key the type refuses and no PID_KEY_HASH: the change names no
/// instance. It is dropped and counted, not named by a type-blind reading
/// of the payload (whose zero-padded short-string form is not this type's
/// KeyHash, nor ShapeType's).
#[test]
fn a_refused_key_without_a_key_hash_names_no_instance() {
    let f = Fixture::new("foreign-key-hash-refused-none");
    f.both_write();
    // The string "BLUE" behind an encapsulation that is not CDR (0x0004,
    // XML): a type-blind reading took it for a short string.
    let string_key: [u8; 12] = [
        0x00, 0x04, 0x00, 0x03, 0x05, 0, 0, 0, b'B', b'L', b'U', b'E',
    ];
    assert_eq!(Keyed::key_hash_of_key_payload(&string_key), None);
    assert_eq!(
        f.lifecycle_counted(A, 2, &unregister(None), &string_key),
        1,
        "the change that named nothing is counted"
    );
    assert_eq!(f.take_all(), vec![], "nothing was named");
    f.write(B, 2, 21);
    assert_eq!(f.take_all(), vec![], "A still owns the instance");
}

/// Nor can a guess name another real instance: the writer means key
/// 0x0000_0002_4100_0055, big endian, whose bytes a type-blind reading
/// took for the short string "A" and named the instance of key
/// 0x0000_0002_4100_0000, which A owns. A's unregister of a key it never
/// wrote must not release the one it did. The type reads the key it is,
/// and the unregister names that instance, which nobody wrote.
#[test]
fn a_refused_key_never_releases_another_instance() {
    const WRITTEN: i64 = 0x0000_0002_4100_0000;
    const MEANT: i64 = 0x0000_0002_4100_0055;
    let f = Fixture::new("foreign-key-hash-refused-real");
    f.write_key(A, 1, WRITTEN, 10);
    f.write_key(B, 1, WRITTEN, 20);
    let written = Keyed {
        key: WRITTEN,
        value: 0,
    }
    .compute_key();
    assert_eq!(
        f.take_all(),
        vec![(written, Some(10), InstanceState::Alive)]
    );
    let mut big_endian = vec![0x00, 0x08, 0x00, 0x00, 0, 0, 0, 8];
    big_endian.extend_from_slice(&MEANT.to_be_bytes());
    f.lifecycle(A, 2, &unregister(None), &big_endian);
    let meant = Keyed {
        key: MEANT,
        value: 0,
    }
    .compute_key();
    assert_eq!(
        f.take_all(),
        vec![(meant, None, InstanceState::NotAliveNoWriters)],
        "the unregister names the key it carries"
    );
    f.write_key(B, 2, WRITTEN, 21);
    assert_eq!(f.take_all(), vec![], "A still owns the written instance");
}

/// A key the type reads, or a PID_KEY_HASH, is not counted as unnamed.
#[test]
fn a_named_change_is_not_counted_as_unnamed() {
    let f = Fixture::new("foreign-key-hash-named-count");
    f.both_write();
    assert_eq!(
        f.lifecycle_counted(A, 2, &unregister(None), &serialized_key(KEY)),
        0
    );
}

/// DDS 1.4 Sec.2.2.3.19: rejected instances must not consume compatibility
/// state outside RESOURCE_LIMITS. The same writer can keep sending new keys.
#[test]
fn legacy_hashes_of_resource_rejected_samples_are_not_learned() {
    let mut qos = QoS::best_effort().keep_last(1);
    qos.resource_limits.max_instances = 1;
    let f = Fixture::with_qos("legacy-admission", qos);
    f.write_key_with_hash(A, 1, KEY, 10, fnv_key_hash(KEY));
    for n in 1..=4 {
        f.write_key_with_hash(
            A,
            n + 1,
            KEY + i64::from(n),
            20,
            fnv_key_hash(KEY + i64::from(n)),
        );
        assert_eq!(
            f.registry
                .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY + i64::from(n))),
            None
        );
    }
    assert_eq!(
        f.registry
            .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY)),
        Some(instance())
    );
    assert_eq!(
        f.take_all(),
        vec![(instance(), Some(10), InstanceState::Alive)]
    );
}

/// RTPS 2.5 Sec.8.4.2.2: a retransmission's writerSN identifies the same
/// change. A rejected duplicate cannot teach a different hash or instance.
#[test]
fn legacy_hashes_of_duplicate_samples_are_not_learned() {
    let f = Fixture::new("legacy-duplicate");
    f.write_key_with_hash(A, 1, KEY, 10, fnv_key_hash(KEY));
    f.write_key_with_hash(A, 1, KEY + 1, 20, fnv_key_hash(KEY + 1));
    assert_eq!(
        f.registry
            .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY + 1)),
        None
    );
    assert_eq!(
        f.take_all(),
        vec![(instance(), Some(10), InstanceState::Alive)]
    );
}

/// DDS 1.4 Sec.2.2.2.4.2.7: unregister retires this writer's instance;
/// its compatibility record is released, while a dispose keeps it registered.
#[test]
fn legacy_instance_retirement_releases_its_mapping() {
    let f = Fixture::new("legacy-retirement");
    f.write_key_with_hash(A, 1, KEY, 10, fnv_key_hash(KEY));
    f.take_all();
    let dispose = Lifecycle {
        status: DISPOSED,
        key_hash: Some(fnv_key_hash(KEY)),
        coherent_set: None,
    };
    f.lifecycle(A, 2, &dispose, &EMPTY_KEY_1_4);
    assert_eq!(
        f.registry
            .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY)),
        Some(instance())
    );
    f.lifecycle(A, 3, &unregister(Some(fnv_key_hash(KEY))), &EMPTY_KEY_1_4);
    assert_eq!(
        f.registry
            .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY)),
        None
    );
}

/// DDS 1.4 Sec.2.2.2.4.2.7 retires only the unregistering writer's
/// registration. A conformant writer needs no legacy KeyHash bookkeeping
/// (RTPS 2.5 Sec.9.6.4.8), even while another writer uses compatibility.
#[test]
fn conformant_unregister_does_not_lock_or_change_legacy_instances() {
    let f = Fixture::new("conformant-retirement");
    let legacy_key = KEY + 1;
    let legacy_hash = fnv_key_hash(legacy_key);
    f.write_key_with_hash(A, 1, legacy_key, 10, legacy_hash);
    f.write(B, 1, 20);
    assert_eq!(f.take_all().len(), 2);
    assert!(!f.registry.writer_uses_legacy_key_hash(&B));
    assert_eq!(f.registry.legacy_key_hash_retirement_locks(), 0);

    f.lifecycle(B, 2, &unregister(Some(instance())), &serialized_key(KEY));
    assert_eq!(
        f.take_all(),
        vec![(instance(), None, InstanceState::NotAliveNoWriters)]
    );
    assert_eq!(f.registry.legacy_key_hash_retirement_locks(), 0);
    assert_eq!(
        f.registry
            .resolve_legacy_key_hash_instance(&A, &legacy_hash),
        Some(rtps_key_hash(legacy_key))
    );

    // A legacy unregister still takes the lock and retires its mapping.
    f.lifecycle(A, 2, &unregister(Some(legacy_hash)), &EMPTY_KEY_1_4);
    assert_eq!(f.registry.legacy_key_hash_retirement_locks(), 1);
    assert_eq!(
        f.registry
            .resolve_legacy_key_hash_instance(&A, &legacy_hash),
        None
    );
}

/// DDS 1.4 Sec.2.2.3.23.3: deleting a writer, directly or with its
/// participant, retires its instance state behind queued DATA.
#[test]
fn legacy_writer_and_participant_departures_clear_mappings() {
    use crate::engine::{subscriber::DisposeKind, WriterDeparture};
    for participant in [false, true] {
        let f = Fixture::new("legacy-departure");
        f.write_key_with_hash(A, 1, KEY, 10, fnv_key_hash(KEY));
        assert_eq!(
            f.registry
                .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY)),
            Some(instance())
        );
        if participant {
            f.registry.notify_participant_departure(
                &A[..12].try_into().unwrap(),
                WriterDeparture::Deleted,
            );
        } else {
            f.registry.notify_writer_departure(
                A,
                DisposeKind::Unregistered,
                WriterDeparture::Deleted,
            );
        }
        assert!(!f.registry.writer_uses_legacy_key_hash(&A));
        assert_eq!(
            f.registry
                .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY)),
            None
        );
        f.write_key_with_hash(A, 2, KEY + 1, 20, fnv_key_hash(KEY + 1));
        assert_eq!(
            f.registry
                .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY + 1)),
            None
        );
    }
}

/// A departure between preparation and admission must fence learning too
/// (DDS 1.4 Sec.2.2.3.23.3). No timing assumptions or sleeping threads.
#[test]
fn legacy_learning_cannot_recreate_state_after_a_fenced_departure() {
    use crate::engine::WriterDeparture;
    let f = Fixture::new("legacy-departure-in-flight");
    let registry = Arc::clone(&f.registry);
    *f.subscriber.admission_hook.lock().unwrap() = Some(Box::new(move || {
        registry
            .notify_participant_departure(&A[..12].try_into().unwrap(), WriterDeparture::Deleted);
    }));
    f.write_key_with_hash(A, 1, KEY, 10, fnv_key_hash(KEY));
    assert_eq!(
        f.registry
            .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY)),
        None
    );
    assert_eq!(f.take_all(), vec![]);
}

/// A queued departure keeps the compatibility mapping until its fence is
/// processed, so DATA ahead of it can still resolve lifecycle changes.
#[test]
fn legacy_mapping_cleanup_waits_for_the_departure_fence() {
    use crate::engine::{
        departures::{Departure, DepartureRoute},
        WriterDeparture,
    };
    let f = Fixture::new("legacy-departure-fence");
    let ring = Arc::new(crossbeam::queue::ArrayQueue::new(4));
    f.registry
        .set_departure_route(Arc::new(DepartureRoute::new(Arc::clone(&ring), None)));
    f.write_key_with_hash(A, 1, KEY, 10, fnv_key_hash(KEY));
    f.registry.post_departure(Departure::Participant {
        prefix: A[..12].try_into().unwrap(),
        cause: WriterDeparture::Deleted,
    });
    assert_eq!(
        f.registry
            .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY)),
        Some(instance())
    );
    assert!(ring.pop().is_some());
    let departure = f.registry.departure_route().unwrap().next().unwrap();
    f.registry.apply_departure(departure);
    assert_eq!(
        f.registry
            .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY)),
        None
    );
}

/// DDS 1.4 Sec.2.2.2.4.2.7: a sample written before unregister cannot
/// register the writer again when its reorder gate releases it later.
#[test]
fn legacy_instance_retirement_is_not_undone_by_an_older_sample() {
    let f = Fixture::new("legacy-retirement-order");
    f.write_key_with_hash(A, 1, KEY, 10, fnv_key_hash(KEY));
    f.lifecycle(A, 3, &unregister(Some(fnv_key_hash(KEY))), &EMPTY_KEY_1_4);
    f.subscriber.writer_instances.admit_sample(A, instance(), 2);
    f.subscriber
        .writer_instances
        .learn_legacy_key_hash(A, fnv_key_hash(KEY), instance());
    assert_eq!(
        f.registry
            .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY)),
        None
    );
}

/// DDS 1.4 Sec.2.2.3: a writer whose OWNERSHIP kind cannot satisfy this
/// reader's request supplies no admitted samples and no compatibility hints.
#[test]
fn legacy_hashes_of_incompatible_writers_are_not_learned() {
    let f = Fixture::new("legacy-incompatible");
    f.registry
        .register_writer_ownership_kind(A, OwnershipKind::Shared);
    f.write_key_with_hash(A, 1, KEY, 10, fnv_key_hash(KEY));
    assert_eq!(
        f.registry
            .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY)),
        None
    );
    assert_eq!(f.take_all(), vec![]);
}

/// RTPS 2.5 Sec.8.7.10: PID_KEY_HASH is a hint for the key. An observed
/// collision gives no basis to pick either instance. Both arrival orders
/// must keep both real owners intact for dispose and unregister alike.
fn check_legacy_hash_collision(keys: [i64; 2], status: u8) {
    let hash = fnv_key_hash(KEY);
    let f = Fixture::new("legacy-collision");
    for (sn, key) in (1..=2).zip(keys) {
        f.write_key_with_hash(A, sn, key, key * 10, hash);
    }
    assert_eq!(f.registry.resolve_legacy_key_hash_instance(&A, &hash), None);
    // Repeating either observation cannot undo known ambiguity.
    f.write_key_with_hash(A, 3, keys[0], 30, hash);
    f.write_key_with_hash(A, 4, keys[1], 40, hash);
    assert_eq!(f.registry.resolve_legacy_key_hash_instance(&A, &hash), None);
    f.take_all();
    let lifecycle = Lifecycle {
        status,
        key_hash: Some(hash),
        coherent_set: None,
    };
    f.lifecycle(A, 5, &lifecycle, &EMPTY_KEY_1_4);
    let expected_state = if status == DISPOSED {
        InstanceState::NotAliveDisposed
    } else {
        InstanceState::NotAliveNoWriters
    };
    assert_eq!(
        f.take_all(),
        vec![(hash, None, expected_state)],
        "ambiguous hints keep the previous raw-hash fallback"
    );
    f.write_key(B, 1, KEY, 70);
    f.write_key(B, 2, KEY + 1, 80);
    assert_eq!(f.take_all(), vec![], "neither real instance lost its owner");
    // An explicit unregister can retire one real instance, but
    // cannot turn an already ambiguous hint into a unique one.
    f.lifecycle(A, 6, &unregister(None), &serialized_key(keys[0]));
    assert_eq!(f.registry.resolve_legacy_key_hash_instance(&A, &hash), None);
    f.write_key_with_hash(A, 7, keys[1], 90, hash);
    assert_eq!(f.registry.resolve_legacy_key_hash_instance(&A, &hash), None);
}

#[test]
fn legacy_hash_collisions_dispose_forward() {
    check_legacy_hash_collision([KEY, KEY + 1], DISPOSED);
}

#[test]
fn legacy_hash_collisions_dispose_reverse() {
    check_legacy_hash_collision([KEY + 1, KEY], DISPOSED);
}

#[test]
fn legacy_hash_collisions_unregister_forward() {
    check_legacy_hash_collision([KEY, KEY + 1], UNREGISTERED);
}

#[test]
fn legacy_hash_collisions_unregister_reverse() {
    check_legacy_hash_collision([KEY + 1, KEY], UNREGISTERED);
}

fn enable_durable_ordering(f: &Fixture) {
    *f.subscriber.reorder.lock().unwrap() = super::reorder::ReorderGate::new(true, false);
    f.subscriber.on_writer_heartbeat(A, 1);
}

/// RTPS 2.5 Sec.8.4.12.2 T8: a DATA retained above a gap is received
/// before it is delivered. A later unregister must name that admitted key.
#[test]
fn legacy_pending_admission_resolves_an_unregister_before_delivery() {
    let f = Fixture::new("legacy-pending-lifecycle");
    enable_durable_ordering(&f);
    f.write_key_with_hash(A, 2, KEY, 10, fnv_key_hash(KEY));
    assert_eq!(f.take_all(), vec![], "DATA 2 waits for DATA 1");
    assert_eq!(
        f.registry
            .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY)),
        Some(instance())
    );
    f.lifecycle(A, 3, &unregister(Some(fnv_key_hash(KEY))), &EMPTY_KEY_1_4);
    assert!(
        f.take_all().is_empty(),
        "unregister 3 awaits the missing DATA 1"
    );
    f.write_key(A, 1, KEY, 9);
    let taken = f.take_all();
    assert_eq!(
        taken
            .iter()
            .filter_map(|(_, value, _)| *value)
            .collect::<Vec<_>>(),
        vec![9, 10],
        "the admitted DATA is delivered before its unregister"
    );
    assert!(taken.contains(&(instance(), None, InstanceState::NotAliveNoWriters)));
    assert_eq!(
        f.registry
            .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY)),
        None
    );
    assert!(!f.subscriber.writer_instances.is_held(&instance()));
}

/// DDS 1.4 Sec.2.2.2.4.2.7: an older admitted DATA held after an
/// unregister cannot recreate that writer's retired instance mapping.
#[test]
fn legacy_pending_admission_preserves_a_newer_retirement() {
    let f = Fixture::new("legacy-pending-retired");
    enable_durable_ordering(&f);
    f.lifecycle(A, 3, &unregister(None), &serialized_key(KEY));
    f.write_key_with_hash(A, 2, KEY, 10, fnv_key_hash(KEY));
    assert!(f.subscriber.reorder.lock().unwrap().holds_sample(&A, 2));
    assert_eq!(
        f.registry
            .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY)),
        None
    );
    assert!(!f.subscriber.writer_instances.is_held(&instance()));
}

/// RTPS 2.5 Sec.8.4.12.2 T4: a GAP makes its declared changes irrelevant.
/// Preparing a late copy is not admission and must not teach a hint.
#[test]
fn legacy_pending_admission_does_not_learn_a_change_crossed_by_gap() {
    let f = Fixture::new("legacy-pending-irrelevant");
    enable_durable_ordering(&f);
    f.subscriber.on_writer_gap(A, 1, 4, vec![]);
    f.write_key_with_hash(A, 2, KEY, 10, fnv_key_hash(KEY));
    assert!(!f.subscriber.reorder.lock().unwrap().holds_sample(&A, 2));
    assert_eq!(
        f.registry
            .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY)),
        None
    );
    assert_eq!(f.take_all(), vec![]);
}

/// DDS 1.4 Sec.2.2.2.4.2.7: writing after unregister registers again.
/// A delayed older unregister cannot release that newer admitted sample.
#[test]
fn legacy_pending_admission_survives_an_older_unregister() {
    let f = Fixture::new("legacy-pending-reregistered");
    enable_durable_ordering(&f);
    f.lifecycle(A, 3, &unregister(None), &serialized_key(KEY));
    f.write_key_with_hash(A, 4, KEY, 10, fnv_key_hash(KEY));
    assert!(f.subscriber.reorder.lock().unwrap().holds_sample(&A, 4));
    assert_eq!(
        f.registry
            .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY)),
        Some(instance())
    );
    f.lifecycle(A, 2, &unregister(None), &serialized_key(KEY));
    assert_eq!(
        f.registry
            .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY)),
        Some(instance())
    );
    assert!(
        !f.subscriber.writer_instances.is_held(&instance()),
        "a retained alias does not apply the pending DATA registration"
    );
    f.lifecycle(A, 5, &unregister(Some(fnv_key_hash(KEY))), &EMPTY_KEY_1_4);
    assert_eq!(
        f.registry
            .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY)),
        None
    );
    assert!(!f.subscriber.writer_instances.is_held(&instance()));
}

/// DDS 1.4 Sec.2.2.2.4.2.7 and Sec.2.2.2.5.5: an ordered unregister
/// leaves the instance without writers before a later retained DATA
/// registers it again. A compatibility hint cannot collapse that cycle.
#[test]
fn legacy_pending_alias_preserves_an_ordered_no_writers_generation() {
    let f = Fixture::new("legacy-pending-generation");
    enable_durable_ordering(&f);
    f.write_key_with_hash(A, 1, KEY, 9, fnv_key_hash(KEY));
    assert_eq!(
        f.take_all(),
        vec![(instance(), Some(9), InstanceState::Alive)]
    );
    f.write_key_with_hash(A, 4, KEY, 10, fnv_key_hash(KEY));
    assert!(f.subscriber.reorder.lock().unwrap().holds_sample(&A, 4));

    f.lifecycle(A, 2, &unregister(None), &serialized_key(KEY));
    assert_eq!(
        f.registry
            .resolve_legacy_key_hash_instance(&A, &fnv_key_hash(KEY)),
        Some(instance()),
        "the newer retained DATA still supplies its alias"
    );
    assert!(!f.subscriber.writer_instances.is_held(&instance()));
    let (data, info) = f
        .reader
        .take_with_info()
        .unwrap()
        .expect("ordered unregister");
    assert!(data.is_none());
    assert_eq!(info.instance_state, InstanceState::NotAliveNoWriters);
    assert_eq!(info.no_writers_generation_count, 0);

    // A sample-less change repairs the remaining ordering hole without
    // registering the instance before the retained DATA at SN 4.
    f.subscriber.on_writer_non_data(A, 3);
    let (data, info) = f.reader.take_with_info().unwrap().expect("retained DATA");
    assert_eq!(data.unwrap().value, 10);
    assert_eq!(info.instance_state, InstanceState::Alive);
    assert_eq!(info.no_writers_generation_count, 1);
    assert!(f.subscriber.writer_instances.is_held(&instance()));
    assert!(f.reader.take_with_info().unwrap().is_none());
}
