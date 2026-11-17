// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Foreign fixtures: real Eclipse Cyclone DDS 0.11.0 wire bytes, captured on
//! loopback (domain 0, `CYCLONEDDS_URI` pinned to the `lo` interface, no
//! multicast), never from our own encoder.
//!
//! Four IDL shapes probe one concern -- a `@final` type whose 8-byte
//! key sits behind a member not aligned to 8 (`T1`), the same shape
//! `@appendable` (`T2`), a two-member key (`T3`), and a key whose
//! serialization exceeds 16 bytes, which RTPS v2.5 9.6.4.8 Step 5 routes to
//! MD5 instead of the padded form (`T4`, three `int64` keys, 24 bytes):
//!
//! ```idl
//! @final      struct T1 { octet a; @key int64 k; long v; };
//! @appendable struct T2 { octet a; @key int64 k; long v; };
//! @final      struct T3 { @key octet a; long filler; @key int64 k; long v; };
//! @final      struct T4 { @key int64 k1; @key int64 k2; @key int64 k3; long v; };
//! ```
//!
//! Cyclone's default config (`GenerateKeyhash` false, the default) never
//! puts a `PID_KEY_HASH` on a dispose or unregister of any of the four: it
//! sends only the serialized key (K=1), the inline QoS carrying
//! `PID_STATUS_INFO` alone. [`a_cyclone_dispose_by_key_payload_alone`] and
//! [`a_cyclone_unregister_by_key_payload_alone`] replay those captures
//! verbatim and check the instance named and the resulting state, for the
//! four shapes.
//!
//! With `GenerateKeyhash` forced true (not the default), Cyclone DOES put a
//! `PID_KEY_HASH` beside the key payload, on both the write and the
//! dispose/unregister. `compute_key_hash_matches_cyclones_wire_value` checks
//! it against this crate's own [`DDS::compute_key`] for all four shapes.
//! T1, T2 and T4 match: a single-member key has nothing before it to
//! misalign (the key-only holder starts at its own offset 0), and T4's
//! >16-byte key goes through MD5 either way, byte for byte.
//!
//! T3 (two key members, `octet` then `int64`) does NOT match, and THIS is
//! a deviation of Cyclone's, reproduced from real wire bytes: RTPS v2.5
//! 9.6.4.8 Step 4 is explicit -- "initially aligned to the maximum
//! alignment in PLAIN_CDR2 (i.e., 4)" -- so the spec places `k` at byte
//! offset 4 (3 padding bytes after `a`). Cyclone 0.11.0's wire KeyHash
//! places `k` at byte offset 8, as if aligning it to 8 (an XCDR1 rule, not
//! XCDR2's). `CYCLONE_T3_KEY_HASH` is that wrong value, captured verbatim;
//! this crate's own `compute_key` is the spec value, and the two differ by
//! construction -- `compute_key_hash_matches_cyclones_wire_value` asserts
//! BOTH: that ours is the spec value, and that Cyclone's departs from it.
//!
//! That deviation does not reach a dispose or unregister in practice,
//! against this Cyclone version: a key-only DATA ALWAYS carries the
//! serialized key (K=1) regardless of `GenerateKeyhash`, so the
//! payload-key-first design (8.3.7.2: the key, not the hint) names the
//! instance from the (always correct) key payload and never consults the
//! (sometimes wrong, for a multi-member key) PID_KEY_HASH. The design is
//! not dead code against THIS peer only because nothing exercises its
//! fallback branch here; it is still the spec-mandated reading, and the
//! one thing standing between a future peer's wrong-but-present
//! PID_KEY_HASH and a misnamed instance.
//!
//! Capture method: a small publisher on the Cyclone C API with idlc-generated
//! bindings, `tcpdump -i lo udp`, decoded with `tshark -V` and cross-checked
//! against the raw bytes. The bytes below are the
//! full RTPS message (`b"RTPS"` through the trailing HEARTBEAT) exactly as
//! captured, Ethernet/IP/UDP headers stripped.

use super::ReaderBuilder;
use crate::core::discovery::multicast::{classify_rtps, PacketKind};
use crate::dds::{DataReader, InstanceState, QoS, DDS};
use crate::engine::{route_data_packet, RouterMetrics, Subscriber, TopicRegistry};
use crate::qos::ownership::OwnershipKind;
use std::sync::Arc;

/// `T1`: `@final struct { octet a; @key int64 k; long v; }`. The key (`k`)
/// sits behind `a`, 7 padding bytes short of the 8-byte alignment XCDR1
/// gives an `int64` -- the shape under test.
#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
#[dds(final)]
struct T1Rec {
    a: u8,
    #[key]
    k: i64,
    v: i32,
}

/// `T2`: `T1`'s shape, `@appendable` (a derived type's default: no
/// attribute needed).
#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct T2Rec {
    a: u8,
    #[key]
    k: i64,
    v: i32,
}

/// `T3`: `@final struct { @key octet a; long filler; @key int64 k; long v; }`,
/// a two-member key.
#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
#[dds(final)]
struct T3Rec {
    #[key]
    a: u8,
    filler: i32,
    #[key]
    k: i64,
    v: i32,
}

/// `T4`: `@final struct { @key int64 k1; @key int64 k2; @key int64 k3; long v; }`,
/// a 24-byte key (over the 16-byte pad bound, so RTPS 9.6.4.8 Step 5 hashes
/// it with MD5).
#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
#[dds(final)]
struct T4Rec {
    #[key]
    k1: i64,
    #[key]
    k2: i64,
    #[key]
    k3: i64,
    v: i32,
}

/// The writer GUID each capture below actually carries (guidPrefix, bytes
/// 8..20 of the RTPS header, concatenated with the DATA submessage's
/// writerEntityId): the router resolves a received writer GUID to a topic
/// through the registry, so the fixture must register exactly this value
/// or nothing is ever delivered.
const T1_WRITER_GUID: [u8; 16] = [
    0x01, 0x10, 0xdb, 0xd8, 0x23, 0x43, 0xbf, 0x51, 0x21, 0x52, 0xcf, 0xa9, 0x00, 0x00, 0x02, 0x02,
];
const T2_WRITER_GUID: [u8; 16] = [
    0x01, 0x10, 0xdb, 0xd8, 0x23, 0x43, 0xbf, 0x51, 0x21, 0x52, 0xcf, 0xa9, 0x00, 0x00, 0x04, 0x02,
];
const T3_WRITER_GUID: [u8; 16] = [
    0x01, 0x10, 0xdb, 0xd8, 0x23, 0x43, 0xbf, 0x51, 0x21, 0x52, 0xcf, 0xa9, 0x00, 0x00, 0x06, 0x02,
];
const T4_WRITER_GUID: [u8; 16] = [
    0x01, 0x10, 0x53, 0xbe, 0x64, 0xe2, 0x55, 0x3c, 0xdc, 0x1b, 0x4d, 0x49, 0x00, 0x00, 0x08, 0x02,
];

struct Fixture<T: DDS> {
    /// Unregisters the subscriber from `registry` when the fixture drops
    /// (the subscriber holds the registry and the registry the subscriber).
    _registration: crate::engine::SubscriberToken,
    reader: Arc<DataReader<T>>,
    registry: Arc<TopicRegistry>,
}

impl<T: DDS> Fixture<T> {
    /// `writer_guid` is the GUID the captured bytes carry: the RTPS
    /// header's guidPrefix (bytes 8..20) concatenated with the DATA
    /// submessage's writerEntityId (always 4 big-endian-looking octets,
    /// never byte-swapped by the E flag -- GUIDs are octet arrays, not
    /// integers). Without registering it the router cannot resolve the
    /// captured writer's GUID to this topic and delivers nothing.
    fn new(topic: &str, writer_guid: [u8; 16]) -> Self {
        let _ = crate::core::rt::init_slab_pool();
        let reader = Arc::new(
            ReaderBuilder::<T>::new(topic.to_string())
                .qos(QoS::best_effort().keep_last(16))
                .network_ring_for_test()
                .build()
                .expect("reader build should succeed"),
        );
        let network_ring = Arc::clone(reader.network_ring_for_test().expect("network ring"));
        let registry = Arc::new(TopicRegistry::new());
        let sub = super::subscriber::ReaderSubscriber::<T>::new_with_coherent(
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
            OwnershipKind::Shared,
            Some(Arc::clone(&registry)),
            None,
            None,
            #[cfg(feature = "security")]
            None,
        )
        .with_room(reader.network_room_for_test().cloned());
        let registration = registry
            .register_subscriber_scoped(Arc::new(sub) as Arc<dyn Subscriber>)
            .expect("register subscriber");
        registry.register_writer_guid(writer_guid, topic.to_string());
        // The OWNERSHIP RxO gate (`ReaderSubscriber::ownership_gate`) defers
        // a writer it cannot resolve via SEDP -- forever, in this fixture,
        // since nothing ever completes that resolution. With a real
        // `topic_registry` attached (needed for the lifecycle/dispose
        // delivery this module tests), the writer's ownership kind must be
        // registered explicitly or every plain DATA sample from it is
        // deferred and never reaches the reader.
        registry.register_writer_ownership_kind(writer_guid, OwnershipKind::Shared);
        Self {
            _registration: registration,
            reader,
            registry,
        }
    }

    /// Route a captured RTPS message (the full bytes, header through the
    /// trailing submessages) exactly as the live router would on receipt.
    fn route(&self, packet: &[u8]) {
        let (kind, offset, _, _) = classify_rtps(packet);
        assert_eq!(
            kind,
            PacketKind::Data,
            "fixture bytes must classify as DATA"
        );
        let metrics = RouterMetrics::new();
        let _ = route_data_packet(packet, packet.len(), offset, &self.registry, &metrics);
    }

    /// What the application takes: the instance handle, the value (`None`
    /// for a lifecycle transition) and the instance state.
    fn take_all(&self) -> Vec<([u8; 16], Option<T>, InstanceState)>
    where
        T: Clone,
    {
        let mut taken = Vec::new();
        while let Some((data, info)) = self.reader.take_with_info().expect("take_with_info") {
            taken.push((info.instance_handle.0, data, info.instance_state));
        }
        taken
    }
}

// ===========================================================================
// Case (a): dispose / unregister carrying a serialized key payload, no
// PID_KEY_HASH -- Cyclone's default (`GenerateKeyhash` false).
// ===========================================================================

/// `KHashT1` capture, default config: write(a=9,k=42,v=100), dispose(k=42),
/// unregister(k=42).
mod t1_default {
    #[rustfmt::skip]
    pub(super) const WRITE: [u8; 112] = [
        0x52, 0x54, 0x50, 0x53, 0x02, 0x05, 0x01, 0x10, 0x01, 0x10, 0xdb, 0xd8, 0x23, 0x43, 0xbf, 0x51, 0x21, 0x52, 0xcf, 0xa9, 0x09, 0x01, 0x08, 0x00, 0x3c, 0x62, 0xda, 0x6a, 0x80, 0x5b, 0x4b, 0x62, 0x15, 0x05, 0x2c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x09, 0x73, 0x2f, 0x59, 0xff, 0x7f, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x07, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    #[rustfmt::skip]
    pub(super) const DISPOSE: [u8; 112] = [
        0x52, 0x54, 0x50, 0x53, 0x02, 0x05, 0x01, 0x10, 0x01, 0x10, 0xdb, 0xd8, 0x23, 0x43, 0xbf, 0x51, 0x21, 0x52, 0xcf, 0xa9, 0x09, 0x01, 0x08, 0x00, 0x3c, 0x62, 0xda, 0x6a, 0xa8, 0x2a, 0x5c, 0xe2, 0x15, 0x0b, 0x2c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x71, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    ];
}

#[test]
fn a_cyclone_default_write_is_alive() {
    let f = Fixture::<T1Rec>::new("cyclone-t1-default", T1_WRITER_GUID);
    f.route(&t1_default::WRITE);
    assert_eq!(
        f.take_all(),
        vec![(
            T1Rec {
                a: 9,
                k: 42,
                v: 100
            }
            .compute_key(),
            Some(T1Rec {
                a: 9,
                k: 42,
                v: 100
            }),
            InstanceState::Alive
        )]
    );
}

/// Cyclone's default dispose of `T1` (K=1, no PID_KEY_HASH, inline QoS
/// carries only PID_STATUS_INFO): the reader names the instance by the
/// serialized key alone and marks it disposed.
#[test]
fn a_cyclone_dispose_by_key_payload_alone_t1() {
    let f = Fixture::<T1Rec>::new("cyclone-t1-dispose", T1_WRITER_GUID);
    f.route(&t1_default::WRITE);
    f.route(&t1_default::DISPOSE);
    let key = T1Rec {
        a: 9,
        k: 42,
        v: 100,
    }
    .compute_key();
    assert_eq!(
        f.take_all(),
        vec![
            (
                key,
                Some(T1Rec {
                    a: 9,
                    k: 42,
                    v: 100
                }),
                InstanceState::NotAliveDisposed
            ),
            (key, None, InstanceState::NotAliveDisposed),
        ]
    );
}

mod t2_default {
    #[rustfmt::skip]
    pub(super) const WRITE: [u8; 112] = [
        0x52, 0x54, 0x50, 0x53, 0x02, 0x05, 0x01, 0x10, 0x01, 0x10, 0xdb, 0xd8, 0x23, 0x43, 0xbf, 0x51, 0x21, 0x52, 0xcf, 0xa9, 0x09, 0x01, 0x08, 0x00, 0x3f, 0x62, 0xda, 0x6a, 0x46, 0x08, 0x9d, 0xe2, 0x15, 0x05, 0x2c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x07, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    #[rustfmt::skip]
    pub(super) const DISPOSE: [u8; 116] = [
        0x52, 0x54, 0x50, 0x53, 0x02, 0x05, 0x01, 0x10, 0x01, 0x10, 0xdb, 0xd8, 0x23, 0x43, 0xbf, 0x51, 0x21, 0x52, 0xcf, 0xa9, 0x09, 0x01, 0x08, 0x00, 0x40, 0x62, 0xda, 0x6a, 0x47, 0x80, 0xaa, 0x62, 0x15, 0x0b, 0x30, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x71, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    ];
    #[rustfmt::skip]
    pub(super) const UNREGISTER: [u8; 116] = [
        0x52, 0x54, 0x50, 0x53, 0x02, 0x05, 0x01, 0x10, 0x01, 0x10, 0xdb, 0xd8, 0x23, 0x43, 0xbf, 0x51, 0x21, 0x52, 0xcf, 0xa9, 0x09, 0x01, 0x08, 0x00, 0x40, 0x62, 0xda, 0x6a, 0xeb, 0xd6, 0xb4, 0xe2, 0x15, 0x0b, 0x30, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x71, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    ];
}

#[test]
fn a_cyclone_dispose_by_key_payload_alone_t2_appendable() {
    let f = Fixture::<T2Rec>::new("cyclone-t2-dispose", T2_WRITER_GUID);
    f.route(&t2_default::WRITE);
    f.route(&t2_default::DISPOSE);
    let key = T2Rec {
        a: 9,
        k: 43,
        v: 200,
    }
    .compute_key();
    assert_eq!(
        f.take_all(),
        vec![
            (
                key,
                Some(T2Rec {
                    a: 9,
                    k: 43,
                    v: 200
                }),
                InstanceState::NotAliveDisposed
            ),
            (key, None, InstanceState::NotAliveDisposed),
        ]
    );
}

/// Unregister after dispose carries BOTH status bits (Disposed|Unregistered,
/// 0x03): the instance stays `NotAliveDisposed` (DisposeKind collapses the
/// two into one instance state; `DataReader::get_dispose_events` keeps the
/// exact kind).
#[test]
fn a_cyclone_unregister_after_dispose_stays_disposed_t2() {
    let f = Fixture::<T2Rec>::new("cyclone-t2-unregister", T2_WRITER_GUID);
    f.route(&t2_default::WRITE);
    f.route(&t2_default::DISPOSE);
    f.route(&t2_default::UNREGISTER);
    let key = T2Rec {
        a: 9,
        k: 43,
        v: 200,
    }
    .compute_key();
    assert_eq!(
        f.take_all(),
        vec![
            (
                key,
                Some(T2Rec {
                    a: 9,
                    k: 43,
                    v: 200
                }),
                InstanceState::NotAliveDisposed
            ),
            (key, None, InstanceState::NotAliveDisposed),
        ],
        "the unregister after dispose adds no new entry: the instance state does not change"
    );
}

mod t3_default {
    #[rustfmt::skip]
    pub(super) const WRITE: [u8; 112] = [
        0x52, 0x54, 0x50, 0x53, 0x02, 0x05, 0x01, 0x10, 0x01, 0x10, 0xdb, 0xd8, 0x23, 0x43, 0xbf, 0x51, 0x21, 0x52, 0xcf, 0xa9, 0x09, 0x01, 0x08, 0x00, 0x43, 0x62, 0xda, 0x6a, 0x26, 0x63, 0xe6, 0x62, 0x15, 0x05, 0x2c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0x73, 0x2f, 0x59, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x01, 0x00, 0x00, 0x07, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    #[rustfmt::skip]
    pub(super) const DISPOSE: [u8; 120] = [
        0x52, 0x54, 0x50, 0x53, 0x02, 0x05, 0x01, 0x10, 0x01, 0x10, 0xdb, 0xd8, 0x23, 0x43, 0xbf, 0x51, 0x21, 0x52, 0xcf, 0xa9, 0x09, 0x01, 0x08, 0x00, 0x43, 0x62, 0xda, 0x6a, 0x90, 0xff, 0xf5, 0xe2, 0x15, 0x0b, 0x34, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x71, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    ];
    #[rustfmt::skip]
    pub(super) const UNREGISTER: [u8; 120] = [
        0x52, 0x54, 0x50, 0x53, 0x02, 0x05, 0x01, 0x10, 0x01, 0x10, 0xdb, 0xd8, 0x23, 0x43, 0xbf, 0x51, 0x21, 0x52, 0xcf, 0xa9, 0x09, 0x01, 0x08, 0x00, 0x44, 0x62, 0xda, 0x6a, 0x2c, 0x7e, 0x02, 0x63, 0x15, 0x0b, 0x34, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x71, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    ];
}

#[test]
fn a_cyclone_dispose_by_key_payload_alone_t3_two_member_key() {
    let f = Fixture::<T3Rec>::new("cyclone-t3-dispose", T3_WRITER_GUID);
    f.route(&t3_default::WRITE);
    f.route(&t3_default::DISPOSE);
    let key = T3Rec {
        a: 3,
        filler: 0,
        k: 44,
        v: 300,
    }
    .compute_key();
    assert_eq!(
        f.take_all(),
        vec![
            (
                key,
                Some(T3Rec {
                    a: 3,
                    filler: 0,
                    k: 44,
                    v: 300
                }),
                InstanceState::NotAliveDisposed
            ),
            (key, None, InstanceState::NotAliveDisposed),
        ]
    );
}

#[test]
fn a_cyclone_unregister_after_dispose_stays_disposed_t3() {
    let f = Fixture::<T3Rec>::new("cyclone-t3-unregister", T3_WRITER_GUID);
    f.route(&t3_default::WRITE);
    f.route(&t3_default::DISPOSE);
    f.route(&t3_default::UNREGISTER);
    let key = T3Rec {
        a: 3,
        filler: 0,
        k: 44,
        v: 300,
    }
    .compute_key();
    assert_eq!(
        f.take_all(),
        vec![
            (
                key,
                Some(T3Rec {
                    a: 3,
                    filler: 0,
                    k: 44,
                    v: 300
                }),
                InstanceState::NotAliveDisposed
            ),
            (key, None, InstanceState::NotAliveDisposed),
        ]
    );
}

mod t4_default {
    #[rustfmt::skip]
    pub(super) const WRITE: [u8; 120] = [
        0x52, 0x54, 0x50, 0x53, 0x02, 0x05, 0x01, 0x10, 0x01, 0x10, 0x53, 0xbe, 0x64, 0xe2, 0x55, 0x3c, 0xdc, 0x1b, 0x4d, 0x49, 0x09, 0x01, 0x08, 0x00, 0xdd, 0x62, 0xda, 0x6a, 0xa0, 0x79, 0x78, 0x2e, 0x15, 0x05, 0x34, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x07, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    #[rustfmt::skip]
    pub(super) const DISPOSE: [u8; 128] = [
        0x52, 0x54, 0x50, 0x53, 0x02, 0x05, 0x01, 0x10, 0x01, 0x10, 0x53, 0xbe, 0x64, 0xe2, 0x55, 0x3c, 0xdc, 0x1b, 0x4d, 0x49, 0x09, 0x01, 0x08, 0x00, 0xdd, 0x62, 0xda, 0x6a, 0x07, 0x9c, 0x89, 0xae, 0x15, 0x0b, 0x3c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x71, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    ];
}

#[test]
fn a_cyclone_dispose_by_key_payload_alone_t4_md5_sized_key() {
    let f = Fixture::<T4Rec>::new("cyclone-t4-dispose", T4_WRITER_GUID);
    f.route(&t4_default::WRITE);
    f.route(&t4_default::DISPOSE);
    let key = T4Rec {
        k1: 51,
        k2: 52,
        k3: 53,
        v: 400,
    }
    .compute_key();
    assert_eq!(
        f.take_all(),
        vec![
            (
                key,
                Some(T4Rec {
                    k1: 51,
                    k2: 52,
                    k3: 53,
                    v: 400
                }),
                InstanceState::NotAliveDisposed
            ),
            (key, None, InstanceState::NotAliveDisposed),
        ]
    );
}

// ===========================================================================
// Case (b)/compute_key cross-check: with Cyclone's `GenerateKeyhash` forced
// true, its PID_KEY_HASH for the same four shapes, bit for bit against
// this crate's own `DDS::compute_key` and against a hand check of RTPS
// v2.5 9.6.4.8.
// ===========================================================================

/// Cyclone's PID_KEY_HASH for `T1` (k=42), `GenerateKeyhash=true`: big
/// -endian `k` padded to 16 bytes (Step 4, serialization <=16 bytes). The
/// key sits behind the unaligned `a` in the FULL data stream, but the key
/// -only serialization Cyclone hashes starts at its own offset 0: no
/// misalignment survives into the hash.
const CYCLONE_T1_KEY_HASH: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Cyclone's PID_KEY_HASH for `T2` (k=43, `@appendable`): identical in
/// shape to T1's -- extensibility does not change the KeyHash (9.6.4.8
/// always hashes PLAIN_CDR2 of the key fields alone, no DHEADER).
const CYCLONE_T2_KEY_HASH: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Cyclone's ACTUAL wire PID_KEY_HASH for `T3` (a=3, k=44), captured
/// verbatim: `a` at byte 0, then 7 padding bytes before `k`, `k` big-endian
/// at bytes 8..16. This is NOT the spec value (see the module doc): RTPS
/// v2.5 9.6.4.8 Step 4 aligns to 4, which puts `k` at byte 4, not byte 8.
/// Cyclone 0.11.0's KeyHash for a multi-member key uses an 8-byte
/// alignment the spec does not ask for -- Cyclone's deviation, reproduced.
const CYCLONE_T3_KEY_HASH_WRONG_ON_WIRE: [u8; 16] = [
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c,
];

/// The RTPS v2.5 9.6.4.8 Step 4 value for `T3` (a=3, k=44): `a` at byte 0,
/// 3 padding bytes to align `k` to 4 (PLAIN_CDR2's max alignment), `k`
/// big-endian at bytes 4..12, zero-padded to 16.
const T3_KEY_HASH_PER_SPEC: [u8; 16] = [
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
];

/// Cyclone's PID_KEY_HASH for `T4` (k1=51, k2=52, k3=53): the 24-byte
/// key's serialization exceeds 16 bytes, so Step 5 hashes it with MD5.
/// `md5(be64(51) ++ be64(52) ++ be64(53))`, verified independently.
const CYCLONE_T4_KEY_HASH: [u8; 16] = [
    0x72, 0x12, 0xf3, 0x74, 0x4c, 0xcd, 0x30, 0x38, 0x42, 0xe5, 0x3f, 0xe4, 0x37, 0x19, 0xe6, 0x64,
];

#[test]
fn compute_key_hash_matches_cyclones_wire_value() {
    assert_eq!(
        T1Rec {
            a: 9,
            k: 42,
            v: 100
        }
        .compute_key(),
        CYCLONE_T1_KEY_HASH,
        "T1 (final, unaligned key): our compute_key must match Cyclone's own PID_KEY_HASH"
    );
    assert_eq!(
        T2Rec {
            a: 9,
            k: 43,
            v: 200
        }
        .compute_key(),
        CYCLONE_T2_KEY_HASH,
        "T2 (appendable, unaligned key): extensibility must not change the KeyHash"
    );
    assert_eq!(
        T3Rec {
            a: 3,
            filler: 0,
            k: 44,
            v: 300
        }
        .compute_key(),
        T3_KEY_HASH_PER_SPEC,
        "T3 (two-member key): we must compute the spec's Step 4 value (align 4), not Cyclone's"
    );
    assert_ne!(
        T3_KEY_HASH_PER_SPEC, CYCLONE_T3_KEY_HASH_WRONG_ON_WIRE,
        "Cyclone 0.11.0's own KeyHash for a multi-member key departs from the spec value \
         (it aligns `k` to 8, the spec's Step 4 says 4) -- pinning the gap, not closing it: \
         it is harmless here only because the key payload, not this hash, names the instance"
    );
    assert_eq!(
        T4Rec {
            k1: 51,
            k2: 52,
            k3: 53,
            v: 400
        }
        .compute_key(),
        CYCLONE_T4_KEY_HASH,
        "T4 (24-byte key): over 16 bytes, RTPS 9.6.4.8 Step 5 selects MD5"
    );
}

/// The serialized key payload Cyclone actually puts on the wire for `T4`'s
/// dispose (K=1, default config, no PID_KEY_HASH) decodes, through this
/// crate's own key-payload reader, to the SAME instance as `compute_key`:
/// the >16-byte key is read correctly even though the wire form (the raw
/// 24-byte concatenation) is not itself the KeyHash.
#[test]
fn a_cyclone_key_payload_for_an_md5_sized_key_names_the_right_instance() {
    let f = Fixture::<T4Rec>::new("cyclone-t4-key-payload-md5", T4_WRITER_GUID);
    f.route(&t4_default::WRITE);
    f.route(&t4_default::DISPOSE);
    let taken = f.take_all();
    assert_eq!(
        taken.len(),
        2,
        "the written sample, then the dispose transition"
    );
    for (handle, _, _) in &taken {
        assert_eq!(*handle, CYCLONE_T4_KEY_HASH);
        assert_eq!(
            *handle,
            T4Rec {
                k1: 51,
                k2: 52,
                k3: 53,
                v: 400
            }
            .compute_key()
        );
    }
    assert_eq!(
        taken[1].1, None,
        "the second entry is the dispose transition, no data"
    );
}
