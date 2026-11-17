// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::tests::{encoded_point, Point};
use crate::core::rt;

// ---------------------------------------------------------------------------
// OWNERSHIP data-plane gate: defer-then-resolve semantics for samples that
// arrive BEFORE their writer's SEDP is processed (the reverse discovery
// race). A TRANSIENT_LOCAL late-joiner history burst is one-shot: it must be
// HELD while the writer is unresolved, then delivered (compatible) or
// discarded (incompatible) once the verdict resolves -- never dropped while
// unresolved (that loses the burst above the RTPS reliability layer, where
// the writer never retransmits it).
// ---------------------------------------------------------------------------

/// Build a plain (non-coherent) ReaderSubscriber wired to a live
/// MatchNotificationRegistry backed by `fsm`, as ReaderBuilder does for a
/// network reader. Reorder gate disabled (Volatile passthrough) so admitted
/// samples land on the ring synchronously.
fn make_ownership_sub(
    topic: &str,
    ring: std::sync::Arc<rt::IndexRing>,
    fsm: &std::sync::Arc<crate::core::discovery::multicast::DiscoveryFsm>,
) -> std::sync::Arc<super::subscriber::ReaderSubscriber<Point>> {
    make_ownership_sub_with_gate(
        topic,
        ring,
        fsm,
        super::reorder::ReorderGate::new(false, false),
    )
}

/// `make_ownership_sub` behind `gate`.
pub(super) fn make_ownership_sub_with_gate(
    topic: &str,
    ring: std::sync::Arc<rt::IndexRing>,
    fsm: &std::sync::Arc<crate::core::discovery::multicast::DiscoveryFsm>,
    gate: super::reorder::ReorderGate,
) -> std::sync::Arc<super::subscriber::ReaderSubscriber<Point>> {
    use std::sync::{Arc, Mutex};
    let registry =
        Arc::new(crate::dds::match_notification::MatchNotificationRegistry::new(fsm, [0u8; 12]));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let reorder = Arc::new(Mutex::new(gate));
    let dispose = Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status)));
    let sub = Arc::new(
        super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
            topic.to_string(),
            ring,
            status,
            None,
            None,
            None,
            dispose,
            reorder,
            super::subscriber::CoherentConfig::default(),
            Some(registry),
            None,
            Arc::new(Mutex::new(
                crate::dds::listener::SampleRejectedStatus::default(),
            )),
            Vec::new(),
            crate::qos::partition::Partition::default(),
            crate::qos::ownership::OwnershipKind::default(),
            None,
            None,
            None,
            #[cfg(feature = "security")]
            None,
        ),
    );
    // Registered with its match registry, as the builder registers it: an
    // unregistered reader is matched with nothing and refuses every writer.
    sub.register_match_entry_for_test(crate::dds::QoS::best_effort());
    sub
}

/// A remote writer GUID under participant prefix `[p; 12]` with the user
/// DataWriter entity kind byte (0x02).
pub(super) fn ownership_writer_guid(p: u8) -> [u8; 16] {
    let mut g = [p; 16];
    g[12] = 0;
    g[13] = 0;
    g[14] = 1;
    g[15] = 0x02;
    g
}

/// Announce `writer_guid` to `fsm` on `topic`: SPDP first (handle_sedp
/// ignores endpoints of unknown participants), then the SEDP with the given
/// ownership PIDs. Mirrors discovery.rs::test_handle_sedp_inserts_endpoint.
pub(super) fn announce_writer(
    fsm: &crate::core::discovery::multicast::DiscoveryFsm,
    topic: &str,
    writer_guid: [u8; 16],
    qos: Option<crate::dds::QoS>,
    has_explicit_ownership: bool,
) {
    use crate::core::discovery::GUID;
    use crate::protocol::discovery::{SedpData, SpdpData};
    let mut participant = writer_guid;
    participant[12] = 0;
    participant[13] = 0;
    participant[14] = 0x01;
    participant[15] = 0xC1;
    fsm.handle_spdp(SpdpData {
        participant_guid: GUID::from_bytes(participant),
        lease_duration_ms: 100_000,
        domain_id: 0,
        metatraffic_unicast_locators: vec![],
        default_unicast_locators: vec![],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: None,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    });
    fsm.handle_sedp(SedpData {
        topic_name: topic.to_string(),
        type_name: "Point".to_string(),
        participant_guid: GUID::from_bytes(participant),
        endpoint_guid: GUID::from_bytes(writer_guid),
        qos_hash: 1,
        qos,
        type_object: None,
        dependents: Vec::new(),
        type_object_legacy_v1: false,
        unicast_locators: vec![],
        user_data: None,
        shm_capability: None,
        has_explicit_reliability: false,
        has_explicit_ownership,
        has_ownership_strength: false,
        type_information: None,
        type_consistency: None,
        group_entity_id: None,
        endpoint_security_info: None,
    });
}

/// THE DURABILITY SHAPE: a burst delivered to the reader path
/// BEFORE the registry knows the writer must be HELD, then surface once the
/// writer resolves as compatible via the proactive SEDP hook
/// (`on_writer_qos_resolved`) -- without any further live sample from the
/// writer, because a one-shot history burst never sends one.
#[test]
fn ownership_unresolved_burst_held_then_flushed_on_sedp_resolution() {
    let _ = rt::init_slab_pool();
    use crate::engine::Subscriber;
    use std::sync::Arc;

    let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
        crate::core::discovery::GUID::zero(),
        100_000,
    ));
    let ring = Arc::new(rt::IndexRing::with_capacity(256));
    let sub = make_ownership_sub("Square", Arc::clone(&ring), &fsm);
    let w = ownership_writer_guid(0xB7);
    let data = encoded_point(3, 4);

    // History burst races its own SEDP: writer unknown to the FSM.
    for seq in 1..=5u64 {
        sub.on_data_with_writer("Square", w, seq, &data, crate::dds::CdrVersion::Xcdr2);
    }
    assert_eq!(
        ring.len(),
        0,
        "unresolved writer's samples must be deferred, not delivered"
    );

    // SEDP lands (no ownership PIDs -> SHARED, matches the reader default).
    announce_writer(&fsm, "Square", w, None, false);
    // Proactive kick, as the SEDP handler does after fsm.handle_sedp.
    sub.on_writer_qos_resolved(w);

    assert_eq!(
        ring.len(),
        5,
        "resolved-compatible writer's deferred burst must surface without any further sample"
    );
}

/// Lazy-path variant: no proactive kick -- the writer's NEXT live sample
/// must flush the deferred backlog ahead of itself, in order.
#[test]
fn ownership_unresolved_burst_flushed_lazily_by_next_sample() {
    let _ = rt::init_slab_pool();
    use crate::engine::Subscriber;
    use std::sync::Arc;

    let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
        crate::core::discovery::GUID::zero(),
        100_000,
    ));
    let ring = Arc::new(rt::IndexRing::with_capacity(256));
    let sub = make_ownership_sub("Square", Arc::clone(&ring), &fsm);
    let w = ownership_writer_guid(0xB8);
    let data = encoded_point(1, 2);

    sub.on_data_with_writer("Square", w, 1, &data, crate::dds::CdrVersion::Xcdr2);
    sub.on_data_with_writer("Square", w, 2, &data, crate::dds::CdrVersion::Xcdr2);
    assert_eq!(ring.len(), 0);

    announce_writer(&fsm, "Square", w, None, false);
    // No proactive kick here: the next live sample resolves and flushes.
    sub.on_data_with_writer("Square", w, 3, &data, crate::dds::CdrVersion::Xcdr2);

    assert_eq!(
        ring.len(),
        3,
        "deferred samples must flush ahead of the live sample that resolved the writer"
    );
}

/// Incompatible variant: the deferred backlog must be DISCARDED when the
/// writer resolves as OWNERSHIP-incompatible, and stay gone.
#[test]
fn ownership_unresolved_burst_discarded_on_incompatible_resolution() {
    let _ = rt::init_slab_pool();
    use crate::engine::Subscriber;
    use std::sync::Arc;

    let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
        crate::core::discovery::GUID::zero(),
        100_000,
    ));
    let ring = Arc::new(rt::IndexRing::with_capacity(256));
    let sub = make_ownership_sub("Square", Arc::clone(&ring), &fsm);
    let w = ownership_writer_guid(0xB9);
    let data = encoded_point(5, 6);

    sub.on_data_with_writer("Square", w, 1, &data, crate::dds::CdrVersion::Xcdr2);
    sub.on_data_with_writer("Square", w, 2, &data, crate::dds::CdrVersion::Xcdr2);
    assert_eq!(ring.len(), 0);

    // Writer announces EXCLUSIVE ownership; the reader requested SHARED.
    let qos = crate::dds::QoS {
        ownership: crate::qos::ownership::Ownership::exclusive(),
        ..crate::dds::QoS::reliable()
    };
    announce_writer(&fsm, "Square", w, Some(qos), true);
    sub.on_writer_qos_resolved(w);
    assert_eq!(
        ring.len(),
        0,
        "ownership-incompatible writer's deferred backlog must be discarded"
    );

    // Later live samples from the same writer stay rejected (cached verdict).
    sub.on_data_with_writer("Square", w, 3, &data, crate::dds::CdrVersion::Xcdr2);
    assert_eq!(ring.len(), 0);
}

/// The pending buffer is bounded: pushing more than the per-writer cap while
/// unresolved keeps only the NEWEST `PER_WRITER_CAP` samples (oldest evicted),
/// which all surface on compatible resolution.
#[test]
fn ownership_pending_caps_evict_oldest() {
    let _ = rt::init_slab_pool();
    use crate::engine::Subscriber;
    use std::sync::Arc;

    let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
        crate::core::discovery::GUID::zero(),
        100_000,
    ));
    let ring = Arc::new(rt::IndexRing::with_capacity(256));
    let sub = make_ownership_sub("Square", Arc::clone(&ring), &fsm);
    let w = ownership_writer_guid(0xBA);
    let data = encoded_point(7, 8);

    // 70 samples > PER_WRITER_CAP (64): the 6 oldest are evicted.
    for seq in 1..=70u64 {
        sub.on_data_with_writer("Square", w, seq, &data, crate::dds::CdrVersion::Xcdr2);
    }
    assert_eq!(ring.len(), 0);

    announce_writer(&fsm, "Square", w, None, false);
    sub.on_writer_qos_resolved(w);

    assert_eq!(
        ring.len(),
        64,
        "bounded pending buffer must hold exactly the newest PER_WRITER_CAP samples"
    );
}

/// THE PURGED-ENDPOINT SHAPE: a writer whose SEDP-time OWNERSHIP kind
/// was recorded in the engine TopicRegistry but whose endpoint is ABSENT
/// from the discovery FSM registry (the unconfirmed-participant zombie
/// sweep removed it; a reliably-ACKed SEDP announcement is not re-sent).
/// The gate must resolve through the durable TopicRegistry record and
/// deliver -- resolving through the FSM alone blackholes the writer's data
/// forever when its first sample arrives after the sweep.
#[test]
fn ownership_gate_resolves_from_topic_registry_after_fsm_purge() {
    let _ = rt::init_slab_pool();
    use crate::engine::Subscriber;
    use std::sync::{Arc, Mutex};

    // Discovery judges the writer before its participant falls silent;
    // the router and the pair verdict survive that purge.
    let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
        crate::core::discovery::GUID::zero(),
        100_000,
    ));
    let match_registry =
        Arc::new(crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, [0u8; 12]));
    fsm.set_match_registry(match_registry.clone());
    fsm.register_listener(match_registry.clone());
    // Engine TopicRegistry holds the durable SEDP-time record.
    let topic_registry = Arc::new(crate::engine::TopicRegistry::new());
    let w = ownership_writer_guid(0xBB);
    topic_registry.register_writer_ownership_kind(w, crate::qos::ownership::OwnershipKind::Shared);
    announce_writer(
        &fsm,
        "Square",
        w,
        Some(crate::dds::QoS::best_effort()),
        false,
    );
    fsm.remove_participant(crate::core::discovery::GUID::new(
        [0xBB; 12],
        [0, 0, 1, 0xC1],
    ));

    let ring = Arc::new(rt::IndexRing::with_capacity(256));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let reorder = Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false)));
    let dispose = Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status)));
    let sub = Arc::new(
        super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
            "Square".to_string(),
            Arc::clone(&ring),
            status,
            None,
            None,
            None,
            dispose,
            reorder,
            super::subscriber::CoherentConfig::default(),
            Some(match_registry),
            None,
            Arc::new(Mutex::new(
                crate::dds::listener::SampleRejectedStatus::default(),
            )),
            Vec::new(),
            crate::qos::partition::Partition::default(),
            crate::qos::ownership::OwnershipKind::default(),
            Some(topic_registry),
            None,
            None,
            #[cfg(feature = "security")]
            None,
        ),
    );

    // Registered with its match registry, as the builder registers it.
    sub.register_match_entry_for_test(crate::dds::QoS::best_effort());
    let data = encoded_point(9, 9);
    sub.on_data_with_writer("Square", w, 1, &data, crate::dds::CdrVersion::Xcdr2);
    assert_eq!(
        ring.len(),
        1,
        "writer resolvable via the TopicRegistry record must deliver even with an empty FSM"
    );
}

/// A writer discovery holds, whose QoS verdict is not on record, keeps its
/// samples deferred and is reported once the discovery lease has passed. A
/// lease that has not passed reports nothing, and a lease that never expires
/// never does.
#[test]
fn a_writer_held_without_its_verdict_is_reported_once_past_the_lease() {
    let _ = rt::init_slab_pool();
    use crate::core::discovery::GUID;
    use crate::engine::Subscriber;
    use std::sync::{Arc, Mutex};

    for (lease_ms, expected_reports, announced) in
        [(0_u64, 1_u32, true), (u64::MAX, 0, true), (0_u64, 0, false)]
    {
        let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
            GUID::zero(),
            lease_ms,
        ));
        let match_registry = Arc::new(
            crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, [0u8; 12]),
        );
        fsm.set_match_registry(match_registry.clone());
        fsm.register_listener(match_registry.clone());
        let topic_registry = Arc::new(crate::engine::TopicRegistry::new());
        let w = ownership_writer_guid(0xBD);
        topic_registry
            .register_writer_ownership_kind(w, crate::qos::ownership::OwnershipKind::Shared);
        if announced {
            announce_writer(
                &fsm,
                "Square",
                w,
                Some(crate::dds::QoS::best_effort()),
                false,
            );
            // Discovery still holds the writer; its verdict is taken back, the
            // state the judgment of every announcement must not leave behind.
            match_registry.forget_remote_writer(&GUID::from_bytes(w));
        }
        // A writer that was never announced is not held by discovery: its
        // burst is deferred and reports nothing.

        let ring = Arc::new(rt::IndexRing::with_capacity(256));
        let status = Arc::new(crate::dds::StatusCondition::new());
        let reorder = Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false)));
        let dispose = Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status)));
        let sub = Arc::new(
            super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
                "Square".to_string(),
                Arc::clone(&ring),
                status,
                None,
                None,
                None,
                dispose,
                reorder,
                super::subscriber::CoherentConfig::default(),
                Some(match_registry),
                None,
                Arc::new(Mutex::new(
                    crate::dds::listener::SampleRejectedStatus::default(),
                )),
                Vec::new(),
                crate::qos::partition::Partition::default(),
                crate::qos::ownership::OwnershipKind::default(),
                Some(topic_registry),
                None,
                None,
                #[cfg(feature = "security")]
                None,
            ),
        );
        sub.register_match_entry_for_test(crate::dds::QoS::best_effort());

        let data = encoded_point(9, 9);
        sub.on_data_with_writer("Square", w, 1, &data, crate::dds::CdrVersion::Xcdr2);
        sub.on_data_with_writer("Square", w, 2, &data, crate::dds::CdrVersion::Xcdr2);
        assert_eq!(
            ring.len(),
            0,
            "lease {lease_ms} ms: deferred, not delivered, while the verdict is missing"
        );
        assert_eq!(
            sub.unjudged_reports_for_test(),
            expected_reports,
            "lease {lease_ms} ms, announced {announced}: reported once past the lease, never twice"
        );
    }
}

/// A writer's OWNERSHIP verdict is the verdict on that writer, not on its
/// GUID: a DataWriter re-created under the GUID of one that left, with
/// another OWNERSHIP kind, is judged again. The cached verdict of the retired
/// writer must not answer for the new one.
#[test]
fn ownership_verdict_of_a_retired_writer_does_not_answer_for_its_successor() {
    let _ = rt::init_slab_pool();
    use crate::engine::subscriber::DisposeKind;
    use crate::engine::Subscriber;
    use std::sync::{Arc, Mutex};

    let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
        crate::core::discovery::GUID::zero(),
        100_000,
    ));
    let match_registry =
        Arc::new(crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, [0u8; 12]));
    fsm.set_match_registry(match_registry.clone());
    let topic_registry = Arc::new(crate::engine::TopicRegistry::new());
    let w = ownership_writer_guid(0xBC);
    topic_registry.register_writer_ownership_kind(w, crate::qos::ownership::OwnershipKind::Shared);
    announce_writer(
        &fsm,
        "Square",
        w,
        Some(crate::dds::QoS::best_effort()),
        false,
    );

    let ring = Arc::new(rt::IndexRing::with_capacity(256));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let reorder = Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false)));
    let dispose = Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status)));
    let sub = super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
        "Square".to_string(),
        Arc::clone(&ring),
        status,
        None,
        None,
        None,
        dispose,
        reorder,
        super::subscriber::CoherentConfig::default(),
        Some(match_registry),
        None,
        Arc::new(Mutex::new(
            crate::dds::listener::SampleRejectedStatus::default(),
        )),
        Vec::new(),
        crate::qos::partition::Partition::default(),
        crate::qos::ownership::OwnershipKind::Shared,
        Some(Arc::clone(&topic_registry)),
        None,
        None,
        #[cfg(feature = "security")]
        None,
    );

    // Registered with its match registry, as the builder registers it.
    sub.register_match_entry_for_test(crate::dds::QoS::best_effort());
    let data = encoded_point(9, 9);
    sub.on_data_with_writer("Square", w, 1, &data, crate::dds::CdrVersion::Xcdr2);
    assert_eq!(ring.len(), 1, "a SHARED writer reaches a SHARED reader");

    // The writer leaves; a new one takes its GUID with EXCLUSIVE ownership,
    // which a SHARED reader does not match (DDS v1.4 Sec.2.2.3.11).
    sub.on_writer_dispose("Square", w, DisposeKind::Unregistered);
    topic_registry
        .register_writer_ownership_kind(w, crate::qos::ownership::OwnershipKind::Exclusive);
    sub.on_data_with_writer("Square", w, 1, &data, crate::dds::CdrVersion::Xcdr2);
    assert_eq!(
        ring.len(),
        1,
        "the EXCLUSIVE successor is judged on its own kind, and refused"
    );
}

/// The PARTITION verdict, likewise: a writer re-created under a retired
/// GUID in a partition this reader does not request is refused, whatever
/// the retired writer's partition was (DDS v1.4 Sec.2.2.3.13).
#[test]
fn partition_verdict_of_a_retired_writer_does_not_answer_for_its_successor() {
    let _ = rt::init_slab_pool();
    use crate::engine::subscriber::DisposeKind;
    use crate::engine::Subscriber;
    use std::sync::{Arc, Mutex};

    let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
        crate::core::discovery::GUID::zero(),
        100_000,
    ));
    let match_registry =
        Arc::new(crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, [0u8; 12]));
    let w = ownership_writer_guid(0xBD);
    announce_writer(
        &fsm,
        "Square",
        w,
        Some(crate::dds::QoS::default().partition_single("A")),
        false,
    );

    let ring = Arc::new(rt::IndexRing::with_capacity(256));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let reorder = Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false)));
    let dispose = Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status)));
    let sub = super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
        "Square".to_string(),
        Arc::clone(&ring),
        status,
        None,
        None,
        None,
        dispose,
        reorder,
        super::subscriber::CoherentConfig::default(),
        Some(match_registry),
        None,
        Arc::new(Mutex::new(
            crate::dds::listener::SampleRejectedStatus::default(),
        )),
        Vec::new(),
        crate::qos::partition::Partition::single("A"),
        crate::qos::ownership::OwnershipKind::default(),
        None,
        None,
        None,
        #[cfg(feature = "security")]
        None,
    );

    // Registered with its match registry, as the builder registers it.
    sub.register_match_entry_for_test(crate::dds::QoS::best_effort().partition_single("A"));
    let data = encoded_point(9, 9);
    sub.on_data_with_writer("Square", w, 1, &data, crate::dds::CdrVersion::Xcdr2);
    assert_eq!(
        ring.len(),
        1,
        "a writer in partition A reaches a reader of A"
    );

    sub.on_writer_dispose("Square", w, DisposeKind::Unregistered);
    assert!(fsm.remove_remote_endpoint(crate::core::discovery::GUID::from_bytes(w)));
    announce_writer(
        &fsm,
        "Square",
        w,
        Some(crate::dds::QoS::default().partition_single("B")),
        false,
    );
    sub.on_data_with_writer("Square", w, 1, &data, crate::dds::CdrVersion::Xcdr2);
    assert_eq!(
        ring.len(),
        1,
        "the successor, in partition B, is judged on its own partition, and refused"
    );
}

/// A reader of "Square" on `reg`, with `topics` for the ownership of the
/// writers it names, wired as the builder wires a network reader.
fn held_square_reader(
    reg: std::sync::Arc<crate::dds::match_notification::MatchNotificationRegistry>,
    topics: std::sync::Arc<crate::engine::TopicRegistry>,
) -> (
    std::sync::Arc<super::subscriber::ReaderSubscriber<Point>>,
    std::sync::Arc<rt::IndexRing>,
) {
    use std::sync::{Arc, Mutex};
    let ring = Arc::new(rt::IndexRing::with_capacity(256));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let reorder = Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false)));
    let dispose = Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status)));
    let sub = Arc::new(
        super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
            "Square".to_string(),
            Arc::clone(&ring),
            status,
            None,
            None,
            None,
            dispose,
            reorder,
            super::subscriber::CoherentConfig::default(),
            Some(reg),
            None,
            Arc::new(Mutex::new(
                crate::dds::listener::SampleRejectedStatus::default(),
            )),
            Vec::new(),
            crate::qos::partition::Partition::default(),
            crate::qos::ownership::OwnershipKind::default(),
            Some(topics),
            None,
            None,
            #[cfg(feature = "security")]
            None,
        ),
    );
    sub.register_match_entry_for_test(crate::dds::QoS::best_effort());
    (sub, ring)
}

/// A writer that leaves and comes back under its GUID is held afresh: the
/// stall of the writer that left is neither reported again for it nor carried
/// into its successor's hold, and a stall of the successor is reported.
#[test]
fn a_writer_that_left_is_held_afresh_when_it_comes_back() {
    let _ = rt::init_slab_pool();
    use crate::core::discovery::GUID;
    use crate::engine::{DisposeKind, Subscriber, WriterDeparture};
    use std::sync::Arc;
    use std::time::Duration;

    const LEASE_MS: u64 = 1_000;
    let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
        GUID::zero(),
        LEASE_MS,
    ));
    let reg =
        Arc::new(crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, [0u8; 12]));
    fsm.set_match_registry(reg.clone());
    fsm.register_listener(reg.clone());
    let topics = Arc::new(crate::engine::TopicRegistry::new());
    let w = ownership_writer_guid(0xBE);
    topics.register_writer_ownership_kind(w, crate::qos::ownership::OwnershipKind::Shared);
    let best_effort = || Some(crate::dds::QoS::best_effort());
    announce_writer(&fsm, "Square", w, best_effort(), false);
    reg.forget_remote_writer(&GUID::from_bytes(w));
    let (sub, ring) = held_square_reader(reg.clone(), topics.clone());
    let data = encoded_point(9, 9);
    let send = |seq: u64| {
        sub.on_data_with_writer("Square", w, seq, &data, crate::dds::CdrVersion::Xcdr2);
    };

    // Held, and stalled past the lease: reported.
    send(1);
    sub.age_unjudged_writer_for_test(&w, Duration::from_millis(2 * LEASE_MS));
    send(2);
    assert_eq!(sub.unjudged_reports_for_test(), 1, "the stall is reported");

    // It leaves: the report and the stall start go with it.
    Subscriber::on_writer_departure(
        sub.as_ref(),
        "Square",
        w,
        DisposeKind::Disposed,
        WriterDeparture::Deleted,
    );
    assert_eq!(
        sub.unjudged_reports_for_test(),
        0,
        "the departure takes the report of the writer that left"
    );

    // It comes back under its GUID, held again, and its SEDP reaches the reader.
    announce_writer(&fsm, "Square", w, best_effort(), false);
    reg.forget_remote_writer(&GUID::from_bytes(w));
    Subscriber::on_writer_qos_resolved(sub.as_ref(), w);
    send(3);
    assert_eq!(
        sub.unjudged_reports_for_test(),
        0,
        "the new hold starts its own lease: the old stall is not reported"
    );
    assert_eq!(ring.len(), 0, "still deferred while its verdict is missing");

    // Its own stall, past the lease, is reported.
    sub.age_unjudged_writer_for_test(&w, Duration::from_millis(2 * LEASE_MS));
    send(4);
    assert_eq!(
        sub.unjudged_reports_for_test(),
        1,
        "a stall of the writer that came back is reported"
    );
}

/// A writer whose verdict is on record for another topic is held on the topic
/// of the reader that has its samples: the detector and the pair verdict agree
/// on what is unjudged.
#[test]
fn a_writer_judged_on_another_topic_is_held_on_this_one() {
    let _ = rt::init_slab_pool();
    use crate::core::discovery::GUID;
    use crate::engine::Subscriber;
    use std::sync::Arc;

    let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
        GUID::zero(),
        0,
    ));
    let w = ownership_writer_guid(0xBF);
    // Discovery holds the writer on "Square"; no registry is installed yet.
    announce_writer(
        &fsm,
        "Square",
        w,
        Some(crate::dds::QoS::best_effort()),
        false,
    );
    let reg =
        Arc::new(crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, [0u8; 12]));
    // Its verdict on record is the verdict of another topic.
    reg.judge_remote_writer_qos(
        &crate::core::discovery::multicast::EndpointInfo::from_sedp(
            other_topic_announcement("Other", w),
            None,
        ),
        false,
        false,
    );
    let (sub, ring) = held_square_reader(reg, Arc::new(crate::engine::TopicRegistry::new()));

    let data = encoded_point(9, 9);
    sub.on_data_with_writer("Square", w, 1, &data, crate::dds::CdrVersion::Xcdr2);
    assert_eq!(ring.len(), 0, "deferred: no verdict for this topic");
    assert_eq!(
        sub.unjudged_reports_for_test(),
        1,
        "lease 0: the writer held without a verdict on this topic is reported"
    );
}

/// A SEDP announcement of `writer` on `topic`, for a fixture that judges it
/// directly.
fn other_topic_announcement(topic: &str, writer: [u8; 16]) -> crate::protocol::discovery::SedpData {
    use crate::core::discovery::GUID;
    let writer = GUID::from_bytes(writer);
    crate::protocol::discovery::SedpData {
        topic_name: topic.to_string(),
        type_name: "Point".to_string(),
        participant_guid: GUID::new(writer.prefix, [0x00, 0x00, 0x01, 0xC1]),
        endpoint_guid: writer,
        qos_hash: 1,
        qos: Some(crate::dds::QoS::best_effort()),
        type_object: None,
        dependents: Vec::new(),
        type_object_legacy_v1: false,
        unicast_locators: vec![],
        user_data: None,
        shm_capability: None,
        has_explicit_reliability: true,
        has_explicit_ownership: false,
        has_ownership_strength: false,
        type_information: None,
        type_consistency: None,
        group_entity_id: None,
        endpoint_security_info: None,
    }
}
