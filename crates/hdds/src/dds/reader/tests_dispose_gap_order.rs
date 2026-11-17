// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A dispose received before a GAP or HEARTBEAT that declares its sequence
//! number irrelevant must surface. Each zzdds dispose is followed by a
//! GAP(gapStart, gapList.base = k) and a HEARTBEAT(first = k): the GAP
//! declares every sequence below k irrelevant, the dispose of k-1 included.
//! Routed in arrival order the dispose is delivered first. Routed after the
//! GAP that follows it (the control path runs ahead of the DATA still queued
//! for the Router thread), the gate has crossed its sequence and drops it.

use super::{DataReader, ReaderBuilder};
use crate::core::discovery::multicast::classify_rtps;
use crate::core::discovery::multicast::control::{
    applies_gate_on_control, release_group_reorder_gate, seed_reorder_gate,
};
use crate::core::discovery::multicast::control_types::ControlMessage;
use crate::core::discovery::multicast::{PacketDispatch, RxPool};
use crate::dds::{CdrVersion, QoS, DDS};
use crate::engine::router::Router;
use crate::engine::{
    route_data_packet, route_raw_rtps_message, RouterMetrics, Subscriber, TopicRegistry,
};
use crate::protocol::builder::{self, RtpsEndpointContext, StatusInfoKind};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct Square {
    #[key]
    color: String,
    x: i32,
    y: i32,
    shapesize: i32,
}

const PREFIX: [u8; 12] = [
    0x01, 0x10, 0xdb, 0xd8, 0x23, 0x43, 0xbf, 0x51, 0x21, 0x52, 0xcf, 0xa9,
];
const WRITER_ID: [u8; 4] = [0x00, 0x00, 0x01, 0x02];
const READER_ID: [u8; 4] = [0x00, 0x00, 0x01, 0x07];

fn writer() -> [u8; 16] {
    let mut guid = [0u8; 16];
    guid[..12].copy_from_slice(&PREFIX);
    guid[12..].copy_from_slice(&WRITER_ID);
    guid
}

fn ctx() -> RtpsEndpointContext {
    RtpsEndpointContext {
        guid_prefix: PREFIX,
        reader_entity_id: READER_ID,
        writer_entity_id: WRITER_ID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0; 4],
    }
}

fn key(color: &str) -> Square {
    Square {
        color: color.to_string(),
        x: 0,
        y: 0,
        shapesize: 0,
    }
}

/// A key-only DATA (K flag) disposing `color` as writerSN `seq`.
fn dispose(seq: u64, color: &str) -> Vec<u8> {
    let sample = key(color);
    builder::build_dispose_packet_with_context(
        &ctx(),
        "Square",
        seq,
        &sample.compute_key(),
        &sample.encode_key(CdrVersion::Xcdr2),
        StatusInfoKind::Disposed,
    )
}

/// A GAP declaring [gap_start, gap_list_base) irrelevant, from the writer.
fn gap(gap_start: u64, gap_list_base: u64) -> Vec<u8> {
    builder::build_gap_packet_from_parts(
        &READER_ID,
        &WRITER_ID,
        gap_start,
        gap_list_base,
        &[],
        PREFIX,
    )
}

/// A HEARTBEAT whose firstSN is `first` (the writer keeps nothing below it).
fn heartbeat(first: u64) -> Vec<u8> {
    builder::build_heartbeat_packet_with_context(&ctx(), first, first, 1)
}

struct Fixture {
    /// Unregisters the subscriber from `registry` when the fixture drops
    /// (the subscriber holds the registry and the registry the subscriber).
    _registration: crate::engine::SubscriberToken,
    reader: DataReader<Square>,
    registry: Arc<TopicRegistry>,
}

impl Fixture {
    fn new() -> Self {
        let _ = crate::core::rt::init_slab_pool();
        let reader = ReaderBuilder::<Square>::new("Square".to_string())
            .qos(QoS::reliable().keep_all())
            .network_ring_for_test()
            .build()
            .expect("reader build should succeed");
        let ring = Arc::clone(reader.network_ring_for_test().expect("network ring"));
        let registry = Arc::new(TopicRegistry::new());
        let credit = crate::core::reader::ReaderAckCredit::new(
            crate::core::reader::ReaderProxyRegistry::new(),
            [0xA0; 16],
        );
        credit.match_writer(writer());
        let mut sub = super::subscriber::ReaderSubscriber::<Square>::new_with_coherent(
            "Square".to_string(),
            ring,
            reader.get_status_condition(),
            None,
            None,
            None,
            Arc::clone(reader.dispose_queue_for_test()),
            Arc::new(std::sync::Mutex::new(super::reorder::ReorderGate::new(
                true, true,
            ))),
            super::subscriber::CoherentConfig::default(),
            None,
            Some(credit),
            Arc::default(),
            Vec::new(),
            crate::qos::partition::Partition::default(),
            crate::qos::ownership::OwnershipKind::Shared,
            Some(Arc::clone(&registry)),
            None,
            None,
            #[cfg(feature = "security")]
            None,
        )
        .with_room(reader.network_room_for_test().cloned());
        sub.reader_entity_id = Some(READER_ID);
        sub.register_match_entry_for_test(QoS::reliable().keep_all());
        let sub = Arc::new(sub);
        let registration = registry
            .register_subscriber_scoped(Arc::clone(&sub) as Arc<dyn Subscriber>)
            .expect("register subscriber");
        registry.register_writer_guid(writer(), "Square".to_string());
        registry
            .register_writer_ownership_kind(writer(), crate::qos::ownership::OwnershipKind::Shared);
        Self {
            _registration: registration,
            reader,
            registry,
        }
    }

    /// A DATA datagram, routed as the Router thread routes it.
    fn route_data(&self, packet: &[u8]) {
        let (_, offset, _, _) = classify_rtps(packet);
        let _ = route_data_packet(
            packet,
            packet.len(),
            offset,
            &self.registry,
            &RouterMetrics::new(),
        );
    }

    /// A GAP or HEARTBEAT datagram, applied as the control path applies it.
    fn route_control(&self, packet: &[u8]) {
        let _ = route_raw_rtps_message(packet, &self.registry, &RouterMetrics::new(), None);
    }
}

/// The control datagram zzdds sends after DATA k: one RTPS message holding
/// GAP(1, k) then HEARTBEAT(k).
fn gap_and_heartbeat(k: u64) -> Vec<u8> {
    let mut datagram = dispose(k, "BLUE")[..20].to_vec();
    datagram.extend_from_slice(&gap(1, k)[20..]);
    datagram.extend_from_slice(&heartbeat(k)[20..]);
    datagram
}

/// Applies the reorder-gate effects of a control message as the UDP control
/// thread does (`control.rs`): only the ones it keeps, by the same decision
/// the thread makes.
fn apply_as_control_thread(registry: &TopicRegistry, msg: &ControlMessage) {
    if let Some(hb) = msg.heartbeat.as_ref() {
        if applies_gate_on_control(msg, &hb.writer_entity_id) {
            seed_reorder_gate(
                registry,
                &msg.peer_guid_prefix,
                hb,
                msg.reader_entity_id(),
                msg.heartbeat_group_info(),
            );
        }
    }
    if let Some(gap) = msg.gap.as_ref() {
        if applies_gate_on_control(msg, &gap.writer_entity_id) {
            release_group_reorder_gate(
                registry,
                &msg.peer_guid_prefix,
                gap,
                msg.reader_entity_id(),
                msg.gap_filtered_count(),
                msg.gap_names_gsns(),
                msg.gap_group_info(),
            );
        }
    }
}

/// zzdds pattern through the real UDP path: each DATA k is one datagram,
/// followed by one datagram of GAP(1, k) and HEARTBEAT(k), received on one
/// socket. Every datagram goes through the listener into the receive ring,
/// and the Router runs only after all of them arrived, so the control
/// thread (which applies only what the listener sent it) has applied every
/// GAP before any DATA is routed. Each GAP declares the dispose before it
/// irrelevant; a dispose that the ring still holds when its GAP is applied
/// must not be lost.
#[test]
#[allow(deprecated)] // the conformance app's accessor
fn a_dispose_still_queued_when_its_gap_is_applied_is_not_lost() {
    let f = Fixture::new();
    let colors = ["BLUE", "BLUE1", "BLUE2", "BLUE3"];
    let pool = Arc::new(RxPool::new(16, 1500).expect("pool"));
    let ring = Arc::new(crossbeam::queue::ArrayQueue::new(64));
    let (control_tx, control_rx) = crossbeam::channel::unbounded();
    let dispatch = PacketDispatch::for_test(Arc::clone(&pool), Arc::clone(&ring), control_tx);
    let source: SocketAddr = "240.0.0.5:7400".parse().expect("a literal address");
    for (i, color) in colors.iter().enumerate() {
        let k = i as u64 + 1;
        dispatch.dispatch(&dispose(k, color), source);
        dispatch.dispatch(&gap_and_heartbeat(k), source);
    }
    while let Ok(msg) = control_rx.try_recv() {
        apply_as_control_thread(&f.registry, &msg);
    }

    let router = Router::start(
        Arc::clone(&ring),
        Arc::clone(&pool),
        Arc::clone(&f.registry),
    )
    .expect("router");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut events = Vec::new();
    while events.len() < colors.len() && std::time::Instant::now() < deadline {
        events.extend(f.reader.get_dispose_events());
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    router.stop().expect("router stop");

    for color in colors {
        assert!(
            events
                .iter()
                .any(|event| event.key_hash == key(color).compute_key()),
            "a received dispose of {color} did not surface"
        );
    }
}

/// The same four disposes, each routed before the GAP and HEARTBEAT that
/// follow it on the wire: every dispose surfaces.
#[test]
#[allow(deprecated)] // the conformance app's accessor
fn disposes_routed_in_arrival_order_all_surface() {
    let f = Fixture::new();
    let colors = ["BLUE", "BLUE1", "BLUE2", "BLUE3"];
    for (i, color) in colors.iter().enumerate() {
        let seq = i as u64 + 1;
        f.route_data(&dispose(seq, color));
        f.route_control(&gap(1, seq));
        f.route_control(&heartbeat(seq));
    }
    let events = f.reader.get_dispose_events();
    for color in colors {
        assert!(
            events
                .iter()
                .any(|event| event.key_hash == key(color).compute_key()),
            "a dispose of {color} did not surface"
        );
    }
}

/// The pool refuses the datagram of a user GAP: the GAP is not ringed, so
/// the control thread applies it (the fallback). The gate still advances over
/// the sequence the GAP declares irrelevant, and the dispose behind it
/// surfaces. Without the fallback the control message would wait for a ring
/// that never takes it, and the gate would stay at 2.
#[test]
#[allow(deprecated)] // the conformance app's accessor
fn a_user_gap_the_pool_refuses_is_applied_by_the_control_thread() {
    let f = Fixture::new();
    let raw = RxPool::new(1, 1500).expect("pool");
    let _held = raw.acquire_for_listener().expect("the only buffer");
    let pool = Arc::new(raw);
    let ring = Arc::new(crossbeam::queue::ArrayQueue::new(64));
    let (control_tx, control_rx) = crossbeam::channel::unbounded();
    let dispatch = PacketDispatch::for_test(Arc::clone(&pool), Arc::clone(&ring), control_tx);
    let source: SocketAddr = "240.0.0.5:7400".parse().expect("a literal address");

    f.route_data(&dispose(1, "BLUE"));
    // GAP(1, 3): 2 is never sent. Its datagram is refused by the pool.
    let mut datagram = dispose(1, "BLUE")[..20].to_vec();
    datagram.extend_from_slice(&gap(1, 3)[20..]);
    dispatch.dispatch(&datagram, source);
    let mut controls = 0;
    while let Ok(msg) = control_rx.try_recv() {
        assert!(!msg.rides_ring, "a refused datagram rides no ring");
        apply_as_control_thread(&f.registry, &msg);
        controls += 1;
    }
    assert_eq!(controls, 1, "the GAP reached the control thread");
    assert_eq!(ring.len(), 0, "nothing was ringed");

    f.route_data(&dispose(3, "BLUE2"));
    let events = f.reader.get_dispose_events();
    for color in ["BLUE", "BLUE2"] {
        assert!(
            events
                .iter()
                .any(|event| event.key_hash == key(color).compute_key()),
            "a dispose of {color} did not surface"
        );
    }
}

/// Each datagram of the sequence: one DATA, then the GAP and HEARTBEAT that
/// trail it, in ONE RTPS message (the embedded path). Sequence 2 is never
/// sent, and the GAP(1, 3) of the third datagram is the only thing that
/// declares it irrelevant: a Router that does not apply the controls riding
/// behind a DATA never releases the DATA 3 behind the hole.
fn embedded_plan() -> [(u64, &'static str); 3] {
    [(1, "BLUE"), (3, "BLUE2"), (4, "BLUE3")]
}

/// Applies what reached the control thread and runs the Router until
/// `expected` dispose events surfaced (or the deadline passes).
#[allow(deprecated)] // the conformance app's accessor
fn route_and_collect_disposes(
    f: &Fixture,
    ring: &Arc<crossbeam::queue::ArrayQueue<(crate::core::discovery::multicast::RxMeta, u8)>>,
    pool: &Arc<RxPool>,
    control_rx: &crossbeam::channel::Receiver<ControlMessage>,
    expected: usize,
) -> Vec<crate::api::InstanceDisposeEvent> {
    while let Ok(msg) = control_rx.try_recv() {
        apply_as_control_thread(&f.registry, &msg);
    }
    let router =
        Router::start(Arc::clone(ring), Arc::clone(pool), Arc::clone(&f.registry)).expect("router");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut events = Vec::new();
    while events.len() < expected && std::time::Instant::now() < deadline {
        events.extend(f.reader.get_dispose_events());
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    router.stop().expect("router stop");
    events
}

/// The embedded path for DATA (dispose): the Data arm applies the GAP that
/// rides behind it. Mutant: delete the Data arm's `route_ring_controls` call.
#[test]
#[allow(deprecated)] // the conformance app's accessor
fn an_embedded_gap_behind_its_data_declares_the_hole_irrelevant() {
    let f = Fixture::new();
    let pool = Arc::new(RxPool::new(16, 1500).expect("pool"));
    let ring = Arc::new(crossbeam::queue::ArrayQueue::new(64));
    let (control_tx, control_rx) = crossbeam::channel::unbounded();
    let dispatch = PacketDispatch::for_test(Arc::clone(&pool), Arc::clone(&ring), control_tx);
    let source: SocketAddr = "240.0.0.5:7400".parse().expect("a literal address");
    let plan = embedded_plan();
    for (seq, color) in plan {
        let mut datagram = dispose(seq, color);
        datagram.extend_from_slice(&gap(1, seq)[20..]);
        datagram.extend_from_slice(&heartbeat(seq)[20..]);
        dispatch.dispatch(&datagram, source);
    }
    let events = route_and_collect_disposes(&f, &ring, &pool, &control_rx, plan.len());
    for (_, color) in plan {
        assert!(
            events
                .iter()
                .any(|event| event.key_hash == key(color).compute_key()),
            "a dispose of {color} did not surface"
        );
    }
}
