// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#[path = "tests_wire_control_receipt.rs"]
mod control_receipt;
#[path = "tests_wire_gap_proof_repair.rs"]
mod gap_proof_repair;
#[path = "tests_wire_group_order_loss.rs"]
mod loss;

use super::subscriber::{GroupRoster, ReaderSubscriber};
use super::{DataReader, ReaderBuilder};
use crate::dds::{CdrVersion, QoS, DDS};
use crate::engine::demux::TopicRegistry;
use crate::engine::router::{route_data_packet, RouterMetrics};
use crate::protocol::builder::{self, RtpsEndpointContext};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct Value {
    value: i32,
}

const PREFIX: [u8; 12] = [0x72; 12];
const PUBLISHER: [u8; 4] = [0, 0, 0x31, 8];
const WRITERS: [[u8; 4]; 2] = [[0, 0, 0x11, 2], [0, 0, 0x12, 2]];

type RosterHook = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;

struct Roster {
    hook: RosterHook,
    writer: usize,
    all: bool,
    /// Discovery knows the Publisher's vendor writes Dust DDS's digest.
    dust: bool,
    entities: Arc<Mutex<Vec<[u8; 4]>>>,
    ready: Arc<std::sync::atomic::AtomicBool>,
    registry: std::sync::Weak<TopicRegistry>,
}
impl GroupRoster for Roster {
    fn writer_set_digest(&self, _: &[u8; 12], writers: &[[u8; 4]]) -> [u8; 4] {
        if self.dust {
            crate::protocol::group::group_digest_dust(writers.iter().copied())
        } else {
            crate::protocol::group::group_digest(writers.iter().copied())
        }
    }

    fn writers_of(&self, _: &[u8; 12], _: [u8; 4], _: &str) -> Vec<([u8; 4], bool)> {
        let hook = self.hook.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        self.entities
            .lock()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(index, &entity)| (entity, self.all || index == self.writer))
            .collect()
    }
    fn ready(&self) -> bool {
        self.ready.load(std::sync::atomic::Ordering::Acquire)
    }

    fn terminal_writers(
        &self,
        publisher: [u8; 16],
    ) -> Option<Vec<([u8; 4], Arc<crate::engine::demux::GroupWriterTerminal>)>> {
        Some(self.registry.upgrade()?.snapshot_group_writers(publisher))
    }

    fn terminal_writer(
        &self,
        writer: &[u8; 16],
        publisher: [u8; 4],
    ) -> Option<Arc<crate::engine::demux::GroupWriterTerminal>> {
        self.registry
            .upgrade()?
            .group_writer_terminal(writer, publisher)
    }
}

struct Group {
    subscriber: Arc<crate::dds::Subscriber>,
    readers: Vec<DataReader<Value>>,
    _sinks: Vec<Arc<ReaderSubscriber<Value>>>,
    credits: Vec<crate::core::reader::ReaderAckCredit>,
    registry: Arc<TopicRegistry>,
    _join_registrations: Vec<crate::engine::demux::SubscriberToken>,
    roster: Arc<Mutex<Vec<[u8; 4]>>>,
    roster_hook: RosterHook,
    roster_ready: Arc<std::sync::atomic::AtomicBool>,
    topics: [String; 2],
}

fn group(coherent: bool) -> Group {
    configured_group(coherent, None, false)
}

fn configured_group(coherent: bool, limit: Option<u32>, shared_reader: bool) -> Group {
    configured_group_in_mode(coherent, limit, shared_reader, true)
}

fn configured_group_in_mode(
    coherent: bool,
    limit: Option<u32>,
    shared_reader: bool,
    reliable: bool,
) -> Group {
    configured_group_with_context(coherent, limit, shared_reader, reliable, true)
}

fn configured_group_with_context(
    coherent: bool,
    limit: Option<u32>,
    shared_reader: bool,
    reliable: bool,
    discovered: bool,
) -> Group {
    configured_group_with_ack(coherent, limit, shared_reader, reliable, discovered, false)
}

fn configured_group_with_ack(
    coherent: bool,
    limit: Option<u32>,
    shared_reader: bool,
    reliable: bool,
    discovered: bool,
    acknowledged: bool,
) -> Group {
    configured_group_for_writer(
        coherent,
        limit,
        shared_reader,
        reliable,
        discovered,
        acknowledged,
        None,
    )
}

fn configured_group_for_writer(
    coherent: bool,
    limit: Option<u32>,
    shared_reader: bool,
    reliable: bool,
    discovered: bool,
    acknowledged: bool,
    selected: Option<usize>,
) -> Group {
    configured_group_for_writer_with_durability(
        coherent,
        limit,
        shared_reader,
        reliable,
        discovered,
        acknowledged,
        selected,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn configured_group_for_writer_with_durability(
    coherent: bool,
    limit: Option<u32>,
    shared_reader: bool,
    reliable: bool,
    discovered: bool,
    acknowledged: bool,
    selected: Option<usize>,
    durable: bool,
) -> Group {
    configured_group_for_presentation(
        coherent,
        limit,
        shared_reader,
        reliable,
        discovered,
        acknowledged,
        selected,
        durable,
        (crate::dds::qos::PresentationAccessScope::Group, true),
    )
}

#[allow(clippy::too_many_arguments)]
fn configured_group_for_presentation(
    coherent: bool,
    limit: Option<u32>,
    shared_reader: bool,
    reliable: bool,
    discovered: bool,
    acknowledged: bool,
    selected: Option<usize>,
    durable: bool,
    presentation: (crate::dds::qos::PresentationAccessScope, bool),
) -> Group {
    configured_group_for_presentation_with_registry(
        coherent,
        limit,
        shared_reader,
        reliable,
        discovered,
        acknowledged,
        selected,
        durable,
        presentation,
        false,
        crate::protocol::group::GroupDialect::Spec,
    )
}

#[allow(clippy::too_many_arguments)]
fn configured_group_for_presentation_with_registry(
    coherent: bool,
    limit: Option<u32>,
    shared_reader: bool,
    reliable: bool,
    discovered: bool,
    acknowledged: bool,
    selected: Option<usize>,
    durable: bool,
    presentation: (crate::dds::qos::PresentationAccessScope, bool),
    connected_registry: bool,
    dialect: crate::protocol::group::GroupDialect,
) -> Group {
    configured_group_bound(
        coherent,
        limit,
        shared_reader,
        reliable,
        discovered,
        acknowledged,
        selected,
        durable,
        presentation,
        connected_registry,
        dialect,
        false,
    )
}

/// `configured_group_for_presentation_with_registry`, the readers built in
/// their participant when `bound`: each gets its entity id, so DATA can be
/// addressed to it by its readerId.
#[allow(clippy::too_many_arguments)]
fn configured_group_bound(
    coherent: bool,
    limit: Option<u32>,
    shared_reader: bool,
    reliable: bool,
    discovered: bool,
    acknowledged: bool,
    selected: Option<usize>,
    durable: bool,
    presentation: (crate::dds::qos::PresentationAccessScope, bool),
    connected_registry: bool,
    dialect: crate::protocol::group::GroupDialect,
    bound: bool,
) -> Group {
    let mut qos = if reliable {
        QoS::reliable().keep_all()
    } else {
        QoS::best_effort().keep_all()
    };
    if durable {
        qos = qos.transient_local();
    }
    if let Some(limit) = limit {
        qos.resource_limits.max_samples = limit as usize;
    }
    qos.presentation.access_scope = presentation.0;
    qos.presentation.coherent_access = coherent;
    qos.presentation.ordered_access = presentation.1;
    let participant = crate::Participant::builder("wire-group-order")
        .with_transport(crate::TransportMode::IntraProcess)
        .build()
        .unwrap();
    let subscriber = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
    let registry = Arc::new(TopicRegistry::new());
    let roster = Arc::new(Mutex::new(WRITERS.to_vec()));
    let roster_hook: RosterHook = Default::default();
    let roster_ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut readers = Vec::new();
    let mut sinks = Vec::new();
    let mut credits = Vec::new();
    let topics = if shared_reader {
        ["wire-order-0".to_string(), "wire-order-0".to_string()]
    } else {
        ["wire-order-0".to_string(), "wire-order-1".to_string()]
    };
    for (index, entity) in WRITERS
        .iter()
        .enumerate()
        .take(if shared_reader { 1 } else { 2 })
        .filter(|(index, _)| selected.is_none_or(|selected| selected == *index))
    {
        let topic = format!("wire-order-{index}");
        let mut builder = ReaderBuilder::<Value>::new(topic.clone())
            .qos(qos.clone())
            .subscriber(&subscriber)
            .network_ring_for_test();
        if connected_registry {
            builder = builder.with_registry(registry.clone());
        }
        if bound {
            builder = builder.with_participant(participant.clone());
        }
        if acknowledged {
            let credit = crate::core::reader::ReaderAckCredit::new(
                crate::core::reader::ReaderProxyRegistry::new(),
                [0xA0 + u8::try_from(index).unwrap(); 16],
            );
            for (writer_index, entity) in WRITERS.iter().enumerate() {
                if !shared_reader && writer_index != index {
                    continue;
                }
                let mut writer = [0; 16];
                writer[..12].copy_from_slice(&PREFIX);
                writer[12..].copy_from_slice(entity);
                credit.match_writer(writer);
            }
            credits.push(credit.clone());
            builder = builder.with_ack_credit_for_test(credit);
        }
        let reader = builder.build().unwrap();
        let sink = reader.subscriber_weak_for_test().upgrade().unwrap();
        assert!(sink
            .group_roster
            .set(Arc::new(Roster {
                hook: roster_hook.clone(),
                writer: index,
                all: shared_reader,
                dust: dialect == crate::protocol::group::GroupDialect::SpecReceive,
                entities: roster.clone(),
                ready: roster_ready.clone(),
                registry: Arc::downgrade(&registry),
            }))
            .is_ok());
        if !connected_registry {
            registry.register_subscriber(sink.clone()).unwrap();
        }
        let member = sink.barrier_member_for_test().unwrap();
        subscriber
            .coherent_barrier()
            .attach_resolver(member, Arc::new(|_| Some(PUBLISHER)));
        let mut writer = [0; 16];
        writer[..12].copy_from_slice(&PREFIX);
        writer[12..].copy_from_slice(entity);
        subscriber
            .coherent_barrier()
            .register_matched_writer(member, writer);
        if discovered || index != 0 {
            registry.register_writer_guid(writer, topic);
            registry.record_writer_group_dialect(writer, dialect, Some(PUBLISHER));
        }
        readers.push(reader);
        sinks.push(sink);
    }
    if shared_reader {
        let mut writer = [0; 16];
        writer[..12].copy_from_slice(&PREFIX);
        writer[12..].copy_from_slice(&WRITERS[1]);
        registry.register_writer_guid(writer, topics[1].clone());
        registry.record_writer_group_dialect(writer, dialect, Some(PUBLISHER));
        subscriber
            .coherent_barrier()
            .register_matched_writer(sinks[0].barrier_member_for_test().unwrap(), writer);
    }
    if selected.is_some() {
        for (index, entity) in WRITERS.iter().enumerate() {
            let mut writer = [0; 16];
            writer[..12].copy_from_slice(&PREFIX);
            writer[12..].copy_from_slice(entity);
            registry.register_writer_guid(writer, topics[index].clone());
            registry.record_writer_group_dialect(writer, dialect, Some(PUBLISHER));
        }
    }
    Group {
        subscriber,
        readers,
        _sinks: sinks,
        credits,
        registry,
        _join_registrations: Vec::new(),
        roster,
        roster_hook,
        roster_ready,
        topics,
    }
}

impl Group {
    fn heartbeat(&self, writer: usize, info: [u64; 3], digest: Option<[u8; 4]>) {
        let mut guid = [0; 16];
        guid[..12].copy_from_slice(&PREFIX);
        guid[12..].copy_from_slice(&WRITERS[writer]);
        let mut publisher = guid;
        publisher[12..].copy_from_slice(&PUBLISHER);
        self.subscriber
            .coherent_barrier()
            .wire_heartbeat(publisher, guid, info, digest);
    }

    fn gap(&self, writer: usize, start: u64, end: u64) {
        let mut guid = [0; 16];
        guid[..12].copy_from_slice(&PREFIX);
        guid[12..].copy_from_slice(&WRITERS[writer]);
        let mut publisher = guid;
        publisher[12..].copy_from_slice(&PUBLISHER);
        self.subscriber.coherent_barrier().wire_gap(
            publisher,
            guid,
            start,
            end,
            self._sinks[if self._sinks.len() == 1 { 0 } else { writer }]
                .barrier_member_for_test()
                .unwrap(),
        );
    }

    fn sampleless(&self, status: Option<builder::StatusInfoKind>) {
        let context = RtpsEndpointContext {
            guid_prefix: PREFIX,
            reader_entity_id: [0; 4],
            writer_entity_id: WRITERS[0],
            encapsulation_kind: 0x0007,
            publisher_entity_id: PUBLISHER,
        };
        let tag = crate::protocol::group::GroupTag {
            gsn: 1,
            writer_set: crate::protocol::group::group_digest(WRITERS),
            set_first_gsn: None,
            part_first_sn: None,
        };
        let packet = if let Some(status) = status {
            builder::build_dispose_packet_with_context_coherent_ts(
                &context,
                &self.topics[0],
                1,
                &[0; 16],
                &[],
                status,
                CdrVersion::Xcdr2,
                (0, 0),
                None,
                None,
                Some(&tag),
                false,
            )
        } else {
            let mut packet = builder::build_data_packet_grouped_ts(
                &context,
                &self.topics[0],
                1,
                &[],
                CdrVersion::Xcdr2,
                (0, 0),
                None,
                None,
                Some(&tag),
                None,
                false,
            );
            use crate::core::discovery::multicast::classifier::walk;
            let mut data = None;
            walk::for_each_submessage(&packet, |sub| {
                if sub.id == 0x15 {
                    data = Some(sub.offset);
                }
                walk::Step::Continue
            });
            let flags = &mut packet[data.unwrap() + 1];
            *flags = (*flags & !0x04) | 0x08;
            packet
        };
        route_data_packet(
            &packet,
            packet.len(),
            None,
            &self.registry,
            &RouterMetrics::new(),
        );
    }

    fn close_tagged(&self, writer: usize, seq: u64, gsn: u64, digest: [u8; 4]) {
        self.close_in_set(writer, seq, gsn, digest, 1, 1);
    }

    fn close_in_set(
        &self,
        writer: usize,
        seq: u64,
        gsn: u64,
        digest: [u8; 4],
        set_first: u64,
        part_first: u64,
    ) {
        let context = RtpsEndpointContext {
            guid_prefix: PREFIX,
            reader_entity_id: [0; 4],
            writer_entity_id: WRITERS[writer],
            encapsulation_kind: 0x0007,
            publisher_entity_id: PUBLISHER,
        };
        let tag = crate::protocol::group::GroupTag {
            gsn,
            writer_set: digest,
            set_first_gsn: Some(set_first),
            part_first_sn: Some(part_first),
        };
        let packet = builder::build_ecs_spec_ts(&context, &self.topics[writer], seq, &tag, (0, 0));
        route_data_packet(
            &packet,
            packet.len(),
            None,
            &self.registry,
            &RouterMetrics::new(),
        );
    }

    fn send(&self, writer: usize, seq: u64, gsn: u64, value: i32) {
        self.send_member(writer, seq, gsn, value, false);
    }

    fn send_member(&self, writer: usize, seq: u64, gsn: u64, value: i32, coherent: bool) {
        self.send_tagged(
            writer,
            seq,
            gsn,
            value,
            coherent,
            crate::protocol::group::group_digest(WRITERS),
        );
    }

    fn send_tagged(
        &self,
        writer: usize,
        seq: u64,
        gsn: u64,
        value: i32,
        coherent: bool,
        digest: [u8; 4],
    ) {
        self.send_set_tagged(writer, seq, gsn, value, coherent.then_some(1), digest);
    }

    fn send_set_tagged(
        &self,
        writer: usize,
        seq: u64,
        gsn: u64,
        value: i32,
        set_first: Option<u64>,
        digest: [u8; 4],
    ) {
        let context = RtpsEndpointContext {
            guid_prefix: PREFIX,
            reader_entity_id: [0; 4],
            writer_entity_id: WRITERS[writer],
            encapsulation_kind: 0x0007,
            publisher_entity_id: PUBLISHER,
        };
        let mut bytes = [0; 64];
        let len = Value { value }
            .encode(&mut bytes, CdrVersion::Xcdr2)
            .unwrap();
        let tag = crate::protocol::group::GroupTag {
            gsn,
            writer_set: digest,
            set_first_gsn: set_first,
            part_first_sn: None,
        };
        let packet = builder::build_data_packet_grouped_ts(
            &context,
            &self.topics[writer],
            seq,
            &bytes[..len],
            CdrVersion::Xcdr2,
            (0, 0),
            set_first.map(|_| 1),
            set_first,
            Some(&tag),
            None,
            false,
        );
        let metrics = RouterMetrics::new();
        route_data_packet(
            &packet,
            packet.len(),
            Some(packet.len() - len),
            &self.registry,
            &metrics,
        );
    }
}

fn reverse_arrivals(coherent: bool) {
    let group = group(coherent);
    group.subscriber.begin_access().unwrap();
    group.send(1, 1, 2, 20);
    group.send(0, 1, 1, 10);
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "an arrival changed the open bracket"
    );
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[1].take().unwrap(),
        None,
        "GSN 2 bypassed GSN 1 on another reader"
    );
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn ordinary_wire_group_order_does_not_require_coherent_access() {
    reverse_arrivals(false);
}

#[test]
fn ordinary_wire_group_order_also_applies_with_coherent_access() {
    reverse_arrivals(true);
}

#[test]
fn a_missing_lower_gsn_cannot_become_a_backward_delivery_in_the_next_bracket() {
    let group = group(false);
    group.subscriber.begin_access().unwrap();
    group.send(1, 1, 2, 20);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[1].take().unwrap(),
        None,
        "unknown predecessor was skipped"
    );
    group.send(0, 1, 1, 10);
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "late predecessor appeared mid bracket"
    );
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn all_writer_heartbeat_absence_can_advance_the_volatile_join_floor() {
    let group = group(false);
    group.subscriber.begin_access().unwrap();
    group.send(1, 1, 8, 80);
    for (index, entity) in WRITERS.iter().enumerate() {
        let mut writer = [0; 16];
        writer[..12].copy_from_slice(&PREFIX);
        writer[12..].copy_from_slice(entity);
        let mut publisher = writer;
        publisher[12..].copy_from_slice(&PUBLISHER);
        group.subscriber.coherent_barrier().wire_heartbeat(
            publisher,
            writer,
            [8, 8, if index == 0 { 7 } else { 8 }],
            None,
        );
    }
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 80 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn an_ordinary_wire_tail_cannot_bypass_a_retained_coherent_member() {
    let group = group(true);
    group.subscriber.begin_access().unwrap();
    group.send_member(0, 1, 1, 10, true);
    for (index, seq) in [(0, 2), (1, 1)] {
        let context = RtpsEndpointContext {
            guid_prefix: PREFIX,
            reader_entity_id: [0; 4],
            writer_entity_id: WRITERS[index],
            encapsulation_kind: 0x0007,
            publisher_entity_id: PUBLISHER,
        };
        let tag = crate::protocol::group::GroupTag {
            gsn: 2,
            writer_set: crate::protocol::group::group_digest(WRITERS),
            set_first_gsn: Some(1),
            part_first_sn: Some(1),
        };
        let packet =
            builder::build_ecs_spec_ts(&context, &format!("wire-order-{index}"), seq, &tag, (0, 0));
        route_data_packet(
            &packet,
            packet.len(),
            None,
            &group.registry,
            &RouterMetrics::new(),
        );
    }
    group.send(1, 2, 3, 30);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[1].take().unwrap(),
        None,
        "ordinary GSN bypassed a coherent predecessor"
    );
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 30 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn reordered_data_advances_a_writer_across_an_unowned_gsn() {
    let group = group(false);
    group.subscriber.begin_access().unwrap();
    group.send(0, 1, 1, 10);
    group.send(0, 2, 3, 30);
    group.heartbeat(0, [3, 1, 3], None);
    group.heartbeat(1, [3, 3, 2], None);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 30 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn one_writers_gap_cannot_skip_another_writers_unknown_predecessor() {
    let group = group(false);
    group.subscriber.begin_access().unwrap();
    group.send(1, 1, 3, 30);
    group.heartbeat(1, [3, 3, 3], None);
    group.gap(1, 1, 3);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[1].take().unwrap(), None);
    group.gap(0, 1, 3);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 30 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn an_accepted_writer_set_epoch_survives_discovery_churn() {
    let group = group(false);
    group.subscriber.begin_access().unwrap();
    group.send(0, 1, 2, 20);
    group.roster.lock().unwrap().push([0, 0, 0x13, 2]);
    group.heartbeat(0, [2, 2, 2], None);
    group.heartbeat(1, [2, 2, 1], None);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn an_unknown_historical_writer_set_is_retained_while_its_predecessor_is_unknown() {
    let group = group(false);
    group.roster.lock().unwrap().push([0, 0, 0x13, 2]);
    group.subscriber.begin_access().unwrap();
    group.send(0, 1, 2, 20);
    group.heartbeat(0, [2, 2, 2], None);
    group.heartbeat(1, [2, 2, 1], None);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), None);
    group.roster.lock().unwrap().pop();
    group.heartbeat(0, [2, 2, 2], None);
    group.heartbeat(1, [2, 2, 1], None);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_current_explicit_heartbeat_roster_can_resolve_an_old_unknown_epoch() {
    let group = group(false);
    group.roster.lock().unwrap().push([0, 0, 0x13, 2]);
    group.subscriber.begin_access().unwrap();
    group.send(0, 1, 2, 20);
    let digest = crate::protocol::group::group_digest(group.roster.lock().unwrap().iter().copied());
    group.heartbeat(0, [2, 2, 2], Some(digest));
    group.heartbeat(1, [2, 2, 1], Some(digest));
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_future_gsn_leaves_the_only_history_slot_for_its_predecessor() {
    let group = configured_group(false, Some(1), true);
    group.subscriber.begin_access().unwrap();
    group.send(1, 1, 2, 20);
    group.send(0, 1, 1, 10);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    group.subscriber.end_access().unwrap();
    // The refused future change is not acknowledged and can be repaired.
    group.subscriber.begin_access().unwrap();
    group.send(1, 1, 2, 20);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_contiguous_gsn_does_not_wait_for_an_unknown_old_roster() {
    let group = group(false);
    group.roster.lock().unwrap().push([0, 0, 0x13, 2]);
    group.subscriber.begin_access().unwrap();
    group.send(0, 1, 1, 10);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_mismatched_explicit_heartbeat_roster_cannot_prove_a_hole_absent() {
    let group = group(false);
    group.subscriber.begin_access().unwrap();
    group.send(0, 1, 2, 20);
    group.heartbeat(0, [2, 2, 2], Some([0x55; 4]));
    group.heartbeat(1, [2, 2, 1], Some([0x55; 4]));
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), None);
    group.heartbeat(0, [2, 2, 2], None);
    group.heartbeat(1, [2, 2, 1], None);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_reassembled_wire_member_keeps_its_gsn_across_readers() {
    let group = group(false);
    group.subscriber.begin_access().unwrap();
    group.send(1, 1, 2, 20);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    let mut qos = Vec::new();
    qos.extend_from_slice(&0x0064u16.to_le_bytes());
    qos.extend_from_slice(&8u16.to_le_bytes());
    qos.extend_from_slice(&0i32.to_le_bytes());
    qos.extend_from_slice(&1u32.to_le_bytes());
    qos.extend_from_slice(&0x0065u16.to_le_bytes());
    qos.extend_from_slice(&4u16.to_le_bytes());
    qos.extend_from_slice(&crate::protocol::group::group_digest(WRITERS));
    qos.extend_from_slice(&1u16.to_le_bytes());
    qos.extend_from_slice(&0u16.to_le_bytes());
    let mut value = [0; 64];
    let len = Value { value: 10 }
        .encode(&mut value, CdrVersion::Xcdr2)
        .unwrap();
    let mut payload = vec![0, 7, 0, 0];
    payload.extend_from_slice(&value[..len]);
    crate::engine::router::route_reassembled_data_for_test(
        writer,
        1,
        &payload,
        Some(&qos),
        Some(7_000_000_000),
        &group.registry,
        &RouterMetrics::new(),
    );
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[1].take().unwrap(),
        None,
        "DATA bypassed a lower reassembled GSN"
    );
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();
}

/// No set stays staged in any reader of `group`: each one delivered or
/// discarded what it held.
fn assert_staged_nothing(group: &Group) {
    for sink in &group._sinks {
        let buffer = sink.group_coherent_buffer.lock().unwrap();
        assert!(buffer.is_empty(), "a GROUP set stayed staged");
    }
}

/// Dust DDS 0.17.0 (vendor 0x0114) on the wire, as dust-h cap.pcap shows it.
/// A member carries PID_COHERENT_SET (the writer-scope first SN of the set),
/// PID_GROUP_COHERENT_SET (the set's first GSN) and PID_GROUP_SEQ_NUM. The
/// end of a set is one DATA per writer, with no payload, carrying
/// PID_GROUP_COHERENT_SET, PID_GROUP_SEQ_NUM and PID_WRITER_GROUP_INFO (16
/// octets, the first 4 read as the writer set) and no PID_COHERENT_SET.
fn dust_sn(sn: u64) -> Vec<u8> {
    let mut value = 0i32.to_le_bytes().to_vec();
    value.extend_from_slice(&(sn as u32).to_le_bytes());
    value
}

fn dust_qos(parameters: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut qos = Vec::new();
    for (pid, value) in parameters {
        qos.extend_from_slice(&pid.to_le_bytes());
        qos.extend_from_slice(&u16::try_from(value.len()).unwrap().to_le_bytes());
        qos.extend_from_slice(value);
    }
    qos.extend_from_slice(&0x0001u16.to_le_bytes());
    qos.extend_from_slice(&0u16.to_le_bytes());
    qos
}

fn dust_writer_info(writer: usize, sn: u64) -> Vec<u8> {
    let mut value = PREFIX.to_vec();
    value.extend_from_slice(&WRITERS[writer]);
    value.extend_from_slice(&dust_sn(sn));
    value
}

fn dust_member_qos(
    writer: usize,
    sn: u64,
    set_first_sn: u64,
    set_first_gsn: u64,
    gsn: u64,
) -> Vec<u8> {
    dust_qos(&[
        (0x0061, dust_writer_info(writer, sn)),
        (0x0056, dust_sn(set_first_sn)),
        (0x0063, dust_sn(set_first_gsn)),
        (0x0064, dust_sn(gsn)),
    ])
}

fn dust_end_qos(writer: usize, sn: u64, set_first_gsn: u64, end_gsn: u64) -> Vec<u8> {
    // Only the first 4 octets of the 16-octet value are read by HDDS.
    let mut writer_set = crate::protocol::group::group_digest_dust(WRITERS).to_vec();
    writer_set.resize(16, 0);
    dust_qos(&[
        (0x0061, dust_writer_info(writer, sn)),
        (0x0063, dust_sn(set_first_gsn)),
        (0x0064, dust_sn(end_gsn)),
        (0x0065, writer_set),
    ])
}

/// One RTPS message with one DATA submessage: flags E|Q, plus D when there is
/// a payload, octetsToInlineQos 16 (readerId, writerId, SN).
fn dust_rtps_packet(writer: usize, seq: u64, inline_qos: &[u8], payload: Option<&[u8]>) -> Vec<u8> {
    let mut body = vec![0, 0];
    body.extend_from_slice(&16u16.to_le_bytes());
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&WRITERS[writer]);
    body.extend_from_slice(&dust_sn(seq));
    body.extend_from_slice(inline_qos);
    let flags = 0x03 | if payload.is_some() { 0x04 } else { 0 };
    if let Some(payload) = payload {
        body.extend_from_slice(payload);
    }
    let mut packet = b"RTPS".to_vec();
    packet.extend_from_slice(&[2, 2, 0x01, 0x14]);
    packet.extend_from_slice(&PREFIX);
    packet.extend_from_slice(&[0x15, flags]);
    packet.extend_from_slice(&u16::try_from(body.len()).unwrap().to_le_bytes());
    packet.extend_from_slice(&body);
    packet
}

impl Group {
    fn dust_send(&self, writer: usize, seq: u64, inline_qos: &[u8], value: Option<i32>) {
        let payload = value.map(|value| {
            let mut bytes = [0; 64];
            let len = Value { value }
                .encode(&mut bytes, CdrVersion::Xcdr2)
                .unwrap();
            let mut payload = vec![0, 7, 0, 0];
            payload.extend_from_slice(&bytes[..len]);
            payload
        });
        let packet = dust_rtps_packet(writer, seq, inline_qos, payload.as_deref());
        route_data_packet(
            &packet,
            packet.len(),
            None,
            &self.registry,
            &RouterMetrics::new(),
        );
    }

    fn drain(&self, reader: usize) -> Vec<i32> {
        let mut values = Vec::new();
        while let Some(value) = self.readers[reader].take().unwrap() {
            values.push(value.value);
        }
        values
    }
}

fn configured_dust_group() -> Group {
    configured_group_for_presentation_with_registry(
        true,
        None,
        false,
        true,
        true,
        false,
        None,
        false,
        (crate::dds::qos::PresentationAccessScope::Group, true),
        false,
        crate::protocol::group::GroupDialect::SpecReceive,
    )
}

/// A TRANSIENT_LOCAL reader of a Dust Publisher: its history is replayed from SN 1.
fn configured_durable_dust_group() -> Group {
    configured_group_for_presentation_with_registry(
        true,
        None,
        false,
        true,
        true,
        false,
        None,
        true,
        (crate::dds::qos::PresentationAccessScope::Group, true),
        true,
        crate::protocol::group::GroupDialect::SpecReceive,
    )
}

/// Two writers of one Dust Publisher, one set of two samples each. Writer 0
/// holds GSNs 1 and 2, writer 1 GSNs 3 and 4; both end the set at GSN 5, one
/// bare end DATA each (dust-h cap.pcap, frames 117-119, with its GSNs).
#[test]
fn a_dust_group_set_is_delivered_once_every_writer_has_ended_it() {
    let group = configured_dust_group();
    group.subscriber.begin_access().unwrap();
    group.dust_send(0, 1, &dust_member_qos(0, 1, 1, 1, 1), Some(10));
    group.dust_send(0, 2, &dust_member_qos(0, 2, 1, 1, 2), Some(11));
    group.dust_send(1, 1, &dust_member_qos(1, 1, 1, 1, 3), Some(20));
    group.dust_send(1, 2, &dust_member_qos(1, 2, 1, 1, 4), Some(21));
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert!(
        group.drain(0).is_empty(),
        "a set is not delivered before it closes"
    );
    assert!(
        group.drain(1).is_empty(),
        "a set is not delivered before it closes"
    );
    group.subscriber.end_access().unwrap();

    group.subscriber.begin_access().unwrap();
    group.dust_send(0, 3, &dust_end_qos(0, 3, 1, 5), None);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert!(
        group.drain(0).is_empty() && group.drain(1).is_empty(),
        "the set waits for every writer of its Publisher to end it"
    );
    group.subscriber.end_access().unwrap();

    group.subscriber.begin_access().unwrap();
    group.dust_send(1, 3, &dust_end_qos(1, 3, 1, 5), None);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.drain(0), vec![10, 11], "writer 0 delivered in order");
    assert_eq!(group.drain(1), vec![20, 21], "writer 1 delivered in order");
    group.subscriber.end_access().unwrap();
    assert_staged_nothing(&group);
}

/// A volatile reader joins a Dust Publisher in the middle of its first set
/// (dust-h cap.pcap: the set's COHERENT_SET is 40 while the first DATA this
/// reader gets is SN 44). Set A starts at SN 1 (COHERENT_SET 1), and SN 1 and
/// 2 of each writer never reach the reader: that set is not whole for it and
/// is not delivered (it is reported lost). The next set, whose members all
/// arrive, is delivered in full.
#[test]
fn a_dust_set_begun_before_a_volatile_join_is_lost_and_the_next_one_is_delivered() {
    let group = configured_dust_group();
    group.subscriber.begin_access().unwrap();
    group.dust_send(0, 3, &dust_member_qos(0, 3, 1, 1, 1), Some(10));
    group.dust_send(0, 4, &dust_member_qos(0, 4, 1, 1, 2), Some(11));
    group.dust_send(1, 3, &dust_member_qos(1, 3, 1, 1, 3), Some(20));
    group.dust_send(1, 4, &dust_member_qos(1, 4, 1, 1, 4), Some(21));
    group.dust_send(0, 5, &dust_end_qos(0, 5, 1, 5), None);
    group.dust_send(1, 5, &dust_end_qos(1, 5, 1, 5), None);
    group.dust_send(0, 6, &dust_member_qos(0, 6, 6, 6, 6), Some(30));
    group.dust_send(0, 7, &dust_member_qos(0, 7, 6, 6, 7), Some(31));
    group.dust_send(1, 6, &dust_member_qos(1, 6, 6, 6, 8), Some(40));
    group.dust_send(1, 7, &dust_member_qos(1, 7, 6, 6, 9), Some(41));
    group.dust_send(0, 8, &dust_end_qos(0, 8, 6, 10), None);
    group.dust_send(1, 8, &dust_end_qos(1, 8, 6, 10), None);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.drain(0), vec![30, 31]);
    assert_eq!(group.drain(1), vec![40, 41]);
    group.subscriber.end_access().unwrap();
    // The set begun before the join is discarded, not kept waiting for SN 1-2.
    assert_staged_nothing(&group);
}

/// A Dust writer's reader matches while the writer is inside a set: the writer
/// sends the live members of that set at once (cap.pcap: HEARTBEAT 1..43, then
/// DATA 44..47 of the set whose COHERENT_SET is 40 and first GSN 112), before
/// the reader's first ACKNACK. Its history replay follows (SN 1.., whole sets
/// with their bare ends), and the live set's own SNs 40..43 and 48..51 come
/// last, its end after them. A member names no writer set, so the early
/// members open a set of no writer set; the replay's first end names one. That
/// end must not discard the live set as a set "of the other dialect": the
/// reader never delivered it and every later set of the Publisher stayed
/// behind its peers' presentation (108 samples, then nothing).
#[test]
fn a_dust_set_in_flight_at_the_join_survives_the_first_replayed_end() {
    use crate::engine::subscriber::Subscriber as _;
    let group = configured_durable_dust_group();
    // The writers' HEARTBEATs name SN 1 as their first (the replay is owed).
    for (writer, sink) in group._sinks.iter().enumerate() {
        let mut guid = [0; 16];
        guid[..12].copy_from_slice(&PREFIX);
        guid[12..].copy_from_slice(&WRITERS[writer]);
        sink.on_writer_heartbeat(guid, 1);
    }
    group.subscriber.begin_access().unwrap();
    // The live member of set B (first SN 4, first GSN 6) that overtook the replay.
    group.dust_send(0, 5, &dust_member_qos(0, 5, 4, 6, 7), Some(13));
    // Replay of set A (first SN 1, first GSN 1), both writers, then their ends.
    group.dust_send(0, 1, &dust_member_qos(0, 1, 1, 1, 1), Some(10));
    group.dust_send(0, 2, &dust_member_qos(0, 2, 1, 1, 2), Some(11));
    group.dust_send(1, 1, &dust_member_qos(1, 1, 1, 1, 3), Some(20));
    group.dust_send(1, 2, &dust_member_qos(1, 2, 1, 1, 4), Some(21));
    group.dust_send(0, 3, &dust_end_qos(0, 3, 1, 5), None);
    group.dust_send(1, 3, &dust_end_qos(1, 3, 1, 5), None);
    // The rest of set B, its ends last.
    group.dust_send(0, 4, &dust_member_qos(0, 4, 4, 6, 6), Some(12));
    group.dust_send(1, 4, &dust_member_qos(1, 4, 4, 6, 8), Some(22));
    group.dust_send(1, 5, &dust_member_qos(1, 5, 4, 6, 9), Some(23));
    group.dust_send(0, 6, &dust_end_qos(0, 6, 6, 10), None);
    group.dust_send(1, 6, &dust_end_qos(1, 6, 6, 10), None);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.drain(0), vec![10, 11, 12, 13]);
    assert_eq!(group.drain(1), vec![20, 21, 22, 23]);
    group.subscriber.end_access().unwrap();
    assert_staged_nothing(&group);
}

/// The same bare end of set from a writer that is not recorded as Dust
/// (`GroupDialect::Spec` here) closes nothing: the Dust form is read only
/// for the vendor that writes it.
#[test]
fn a_bare_group_end_from_a_writer_that_is_not_dust_closes_nothing() {
    let group = configured_group_for_presentation_with_registry(
        true,
        None,
        false,
        true,
        true,
        false,
        None,
        false,
        (crate::dds::qos::PresentationAccessScope::Group, true),
        false,
        crate::protocol::group::GroupDialect::Spec,
    );
    group.subscriber.begin_access().unwrap();
    group.dust_send(0, 1, &dust_member_qos(0, 1, 1, 1, 1), Some(10));
    group.dust_send(1, 1, &dust_member_qos(1, 1, 1, 1, 3), Some(20));
    group.dust_send(0, 2, &dust_end_qos(0, 2, 1, 5), None);
    group.dust_send(1, 2, &dust_end_qos(1, 2, 1, 5), None);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert!(group.drain(0).is_empty() && group.drain(1).is_empty());
    group.subscriber.end_access().unwrap();
}

#[test]
fn staged_members_and_an_unknown_predecessor_keep_all_their_history_places() {
    let group = configured_group(true, Some(3), true);
    let c = [0, 0, 0x13, 2];
    group.roster.lock().unwrap().push(c);
    let digest = crate::protocol::group::group_digest([WRITERS[0], WRITERS[1], c]);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&c);
    group
        .registry
        .register_writer_guid(writer, group.topics[0].clone());
    group.registry.record_writer_group_dialect(
        writer,
        crate::protocol::group::GroupDialect::Spec,
        Some(PUBLISHER),
    );
    group.subscriber.begin_access().unwrap();
    group.send_tagged(0, 1, 1, 10, true, digest);
    group.send_tagged(0, 2, 3, 30, true, digest);
    group.close_tagged(0, 3, 4, digest);
    group.close_tagged(1, 1, 4, digest);
    group.send_tagged(1, 2, 5, 50, false, digest);
    // C's first packet supplies the unknown member, before its own EOS.
    // No per-writer retransmission baseline is needed by this fixture.
    let context = RtpsEndpointContext {
        guid_prefix: PREFIX,
        reader_entity_id: [0; 4],
        writer_entity_id: c,
        encapsulation_kind: 0x0007,
        publisher_entity_id: PUBLISHER,
    };
    let tag = crate::protocol::group::GroupTag {
        gsn: 2,
        writer_set: digest,
        set_first_gsn: Some(1),
        part_first_sn: None,
    };
    let mut bytes = [0; 64];
    let len = Value { value: 20 }
        .encode(&mut bytes, CdrVersion::Xcdr2)
        .unwrap();
    let packet = builder::build_data_packet_grouped_ts(
        &context,
        &group.topics[0],
        1,
        &bytes[..len],
        CdrVersion::Xcdr2,
        (0, 0),
        Some(1),
        Some(1),
        Some(&tag),
        None,
        false,
    );
    route_data_packet(
        &packet,
        packet.len(),
        Some(packet.len() - len),
        &group.registry,
        &RouterMetrics::new(),
    );
    let end = crate::protocol::group::GroupTag {
        gsn: 4,
        part_first_sn: Some(1),
        ..tag
    };
    let packet = builder::build_ecs_spec_ts(&context, &group.topics[0], 2, &end, (0, 0));
    route_data_packet(
        &packet,
        packet.len(),
        None,
        &group.registry,
        &RouterMetrics::new(),
    );
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 30 }));
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    group.send_tagged(1, 2, 5, 50, false, digest);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 50 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_current_data_epoch_and_psm_heartbeat_can_resolve_an_old_unknown_epoch() {
    let group = group(false);
    group.roster.lock().unwrap().push([0, 0, 0x13, 2]);
    group.subscriber.begin_access().unwrap();
    group.send(0, 1, 2, 20);
    let digest = crate::protocol::group::group_digest(group.roster.lock().unwrap().iter().copied());
    group.send_tagged(0, 2, 3, 30, false, digest);
    group.heartbeat(0, [3, 2, 3], None);
    group.heartbeat(1, [3, 3, 2], None);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 30 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_gap_endpoint_does_not_overtake_the_next_available_writer_sample() {
    use crate::engine::Subscriber as _;
    let group = group(false);
    group.subscriber.begin_access().unwrap();
    group.send(1, 1, 3, 30);
    group.heartbeat(0, [3, 1, 2], None);
    group.heartbeat(1, [3, 3, 3], None);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    // SN 1 is unavailable; bitmapBase=2 still names an available sample.
    // Its GSN is also 2, the GroupInfo endpoint emitted by our GAP builder.
    group._sinks[0].on_writer_gap(writer, 1, 2, Vec::new());
    let packet = builder::build_gap_packet_group(&[0; 4], &WRITERS[0], 1, 1, 2, PREFIX);
    let gap =
        crate::core::discovery::multicast::control_parser::scan_all_embedded_control_submessages(
            &packet,
        )
        .0
        .pop()
        .unwrap();
    let safe_end = crate::core::discovery::multicast::control::group_gap_safe_end(&gap.info, 1, 2);
    group.gap(0, 1, safe_end);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[1].take().unwrap(),
        None,
        "GAP endpoint was treated as unavailable data"
    );
    group.send(0, 2, 2, 20);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 30 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_bare_group_change_passes_its_gsn_before_the_next_writers_data() {
    for coherent in [false, true] {
        for reliable in [false, true] {
            let group = configured_group_with_ack(coherent, None, false, reliable, true, true);
            let context = RtpsEndpointContext {
                guid_prefix: PREFIX,
                reader_entity_id: [0; 4],
                writer_entity_id: WRITERS[0],
                encapsulation_kind: 0x0007,
                publisher_entity_id: PUBLISHER,
            };
            let tag = crate::protocol::group::GroupTag {
                gsn: 1,
                writer_set: crate::protocol::group::group_digest(WRITERS),
                set_first_gsn: None,
                part_first_sn: None,
            };
            let mut packet = builder::build_data_packet_grouped_ts(
                &context,
                &group.topics[0],
                1,
                &[],
                CdrVersion::Xcdr2,
                (0, 0),
                None,
                None,
                Some(&tag),
                None,
                false,
            );
            use crate::core::discovery::multicast::classifier::walk;
            let mut data = None;
            walk::for_each_submessage(&packet, |sub| {
                if sub.id == 0x15 {
                    data = Some(sub.offset);
                }
                walk::Step::Continue
            });
            let data = data.expect("DATA submessage");
            packet[data + 1] &= !0x0c;
            // An empty serialized value has only its encapsulation. A bare
            // control has no serialized payload at all (RTPS 2.5 8.3.8.2).
            packet.truncate(packet.len() - 4);
            let size = u16::try_from(packet.len() - data - 4).expect("small DATA");
            packet[data + 2..data + 4].copy_from_slice(&size.to_le_bytes());
            assert!(builder::is_data_without_sample(&packet));

            group.subscriber.begin_access().unwrap();
            assert_eq!(
                route_data_packet(
                    &packet,
                    packet.len(),
                    None,
                    &group.registry,
                    &RouterMetrics::new(),
                ),
                crate::engine::RouteStatus::Delivered
            );
            group.send(1, 1, 2, 20);
            group.subscriber.end_access().unwrap();
            group.subscriber.begin_access().unwrap();
            assert_eq!(group.readers[0].take().unwrap(), None);
            assert_eq!(
                group.readers[1].take().unwrap(),
                Some(Value { value: 20 }),
                "a bare predecessor's GSN must not strand later DATA"
            );
            assert_eq!(group.readers[0].get_sample_lost_status().total_count, 0);
            group.subscriber.end_access().unwrap();
        }
    }
}

#[test]
fn sampleless_group_changes_do_not_strand_later_ordinary_data() {
    for status in [
        Some(builder::StatusInfoKind::Disposed),
        Some(builder::StatusInfoKind::Unregistered),
        Some(builder::StatusInfoKind::DisposedUnregistered),
        None,
    ] {
        let group = group(false);
        group.subscriber.begin_access().unwrap();
        group.sampleless(status);
        group.send(1, 1, 2, 20);
        group.subscriber.end_access().unwrap();
        group.subscriber.begin_access().unwrap();
        assert_eq!(
            group.readers[1].take().unwrap(),
            Some(Value { value: 20 }),
            "a sample-less predecessor's GSN was never consumed"
        );
        group.subscriber.end_access().unwrap();
    }
}

#[test]
fn best_effort_group_data_advances_without_heartbeats_and_never_reads_backwards() {
    let group = configured_group_in_mode(false, None, false, false);
    group.subscriber.begin_access().unwrap();
    group.send(1, 1, 2, 20);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 20 }));
    group.send(0, 1, 1, 10);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "late BEST_EFFORT data went backwards"
    );
    group.subscriber.end_access().unwrap();
}

#[test]
fn tagged_group_data_waits_for_discovered_dialect_and_publisher_before_receipt() {
    let group = configured_group_with_context(false, None, false, true, false);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    group.subscriber.begin_access().unwrap();
    group.send(0, 1, 1, 10);
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "pre-discovery GROUP metadata fell through unordered"
    );
    group
        .registry
        .register_writer_guid(writer, group.topics[0].clone());
    group.registry.record_writer_group_dialect(
        writer,
        crate::protocol::group::GroupDialect::Spec,
        None,
    );
    group.send(0, 1, 1, 10);
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "a missing Publisher became an unordered arrival"
    );
    group.send(1, 1, 2, 20);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[1].take().unwrap(), None);
    group.registry.record_writer_group_dialect(
        writer,
        crate::protocol::group::GroupDialect::Spec,
        Some(PUBLISHER),
    );
    group.send(0, 1, 1, 10);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[0].take().unwrap(),
        Some(Value { value: 10 }),
        "unaccepted context-free data was credited as a duplicate"
    );
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn known_legacy_dialect_does_not_acquire_spec_group_order_from_raw_parameters() {
    let group = group(false);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    group.registry.record_writer_group_dialect(
        writer,
        crate::protocol::group::GroupDialect::HddsLegacy,
        Some(PUBLISHER),
    );
    group.send(0, 1, 1, 10);
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_singleton_group_gap_from_our_writer_unblocks_the_next_ordinary_sample() {
    use crate::core::discovery::multicast::{control, control_parser, control_types::GroupInfo};
    let group = group(false);
    group.subscriber.begin_access().unwrap();
    group.send(1, 1, 2, 20);
    group.heartbeat(0, [2, 1, 1], None);
    group.heartbeat(1, [2, 2, 2], None);
    // The production repair helper emits inclusive singleton GSN endpoints.
    let packet = builder::build_gap_packet_group(&[0; 4], &WRITERS[0], 1, 1, 1, PREFIX);
    let gap = control_parser::scan_all_embedded_control_submessages(&packet)
        .0
        .pop()
        .unwrap();
    let Some(GroupInfo::Gap { start_gsn, end_gsn }) = gap.group_info else {
        panic!("GROUP GAP")
    };
    let safe_end = control::group_gap_safe_end(&gap.info, start_gsn, end_gsn);
    group.gap(0, start_gsn, safe_end);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();
}

// A fresh durable member is owed history even after another member consumed it.
fn late_durable_prefix(coherent: bool) {
    let mut group = configured_group(coherent, None, true);
    group.subscriber.begin_access().unwrap();
    group.send(0, 1, 1, 10);
    group.send(1, 1, 2, 20);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();

    group.join_durable(coherent, None);
    group.subscriber.begin_access().unwrap();
    group.send(1, 1, 2, 20);
    group.send(0, 1, 1, 10);
    assert_eq!(
        group.readers[1].take().unwrap(),
        None,
        "historical arrival changed an open bracket"
    );
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[1].take().unwrap(),
        Some(Value { value: 10 }),
        "new durable member lost its retained GSN 1"
    );
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 20 }));
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "settled member received duplicate history"
    );
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_late_durable_member_replays_the_consumed_prefix_without_coherent_access() {
    late_durable_prefix(false);
}

#[test]
fn a_late_durable_member_replays_the_consumed_prefix_with_coherent_access() {
    late_durable_prefix(true);
}

impl Group {
    fn join_durable(&mut self, coherent: bool, limit: Option<usize>) -> usize {
        self.join_reader(coherent, limit, true)
    }

    fn join_reader(&mut self, coherent: bool, limit: Option<usize>, durable: bool) -> usize {
        self.join_topic_reader(coherent, limit, durable, 0, true, false)
    }

    fn join_topic_reader(
        &mut self,
        coherent: bool,
        limit: Option<usize>,
        durable: bool,
        writer_index: usize,
        all: bool,
        acknowledged: bool,
    ) -> usize {
        use crate::engine::subscriber::Subscriber as _;
        let index = self.readers.len();
        let mut qos = QoS::reliable()
            .keep_all()
            .presentation_group_coherent_ordered();
        qos.presentation.coherent_access = coherent;
        if let Some(limit) = limit {
            qos.resource_limits.max_samples = limit;
        }
        qos.durability = if durable {
            crate::dds::qos::Durability::TransientLocal
        } else {
            crate::dds::qos::Durability::Volatile
        };
        let mut builder = ReaderBuilder::<Value>::new(self.topics[writer_index].clone())
            .qos(qos)
            .subscriber(&self.subscriber)
            .network_ring_for_test();
        if acknowledged {
            let credit = crate::core::reader::ReaderAckCredit::new(
                crate::core::reader::ReaderProxyRegistry::new(),
                [0xC0 + u8::try_from(index).unwrap(); 16],
            );
            for (index, entity) in WRITERS.iter().enumerate() {
                if !all && index != writer_index {
                    continue;
                }
                let mut writer = [0; 16];
                writer[..12].copy_from_slice(&PREFIX);
                writer[12..].copy_from_slice(entity);
                credit.match_writer(writer);
            }
            self.credits.push(credit.clone());
            builder = builder.with_ack_credit_for_test(credit);
        }
        let reader = builder.build().unwrap();
        let sink = reader.subscriber_weak_for_test().upgrade().unwrap();
        assert!(sink
            .group_roster
            .set(Arc::new(Roster {
                hook: self.roster_hook.clone(),
                writer: writer_index,
                all,
                dust: false,
                entities: self.roster.clone(),
                ready: self.roster_ready.clone(),
                registry: Arc::downgrade(&self.registry),
            }))
            .is_ok());
        let registration = self
            .registry
            .register_subscriber_scoped(sink.clone())
            .unwrap();
        self._join_registrations.push(registration);
        let member = sink.barrier_member_for_test().unwrap();
        self.subscriber
            .coherent_barrier()
            .attach_resolver(member, Arc::new(|_| Some(PUBLISHER)));
        for (index, entity) in WRITERS.iter().enumerate() {
            if !all && index != writer_index {
                continue;
            }
            let mut writer = [0; 16];
            writer[..12].copy_from_slice(&PREFIX);
            writer[12..].copy_from_slice(entity);
            self.subscriber
                .coherent_barrier()
                .register_matched_writer(member, writer);
            sink.on_writer_heartbeat(writer, 1);
        }
        self.readers.push(reader);
        self._sinks.push(sink);
        index
    }

    fn delete_joiner(&mut self) {
        assert!(self.readers.len() > 1);
        drop(self.readers.pop());
        drop(self._join_registrations.pop());
        drop(self._sinks.pop());
    }
}

fn consumed_prefix(group: &Group) {
    group.subscriber.begin_access().unwrap();
    group.send(0, 1, 1, 10);
    group.send(1, 1, 2, 20);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn late_durable_history_stays_owned_across_brackets_and_old_data_credits() {
    let mut group = configured_group(false, None, true);
    consumed_prefix(&group);
    group.subscriber.begin_access().unwrap();
    group.join_durable(false, None);
    group.send(1, 1, 2, 20);
    let mut publisher = [0; 16];
    publisher[..12].copy_from_slice(&PREFIX);
    publisher[12..].copy_from_slice(&PUBLISHER);
    group.subscriber.coherent_barrier().wire_settled(
        group._sinks[0].barrier_member_for_test().unwrap(),
        {
            let mut writer = publisher;
            writer[12..].copy_from_slice(&WRITERS[0]);
            writer
        },
        crate::engine::router::OrderedGroupChange {
            publisher,
            gsn: 1,
            writer_set: crate::protocol::group::group_digest(WRITERS),
        },
    );
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[1].take().unwrap(),
        None,
        "old-member credit skipped new history"
    );
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[1].take().unwrap(),
        None,
        "a bracket guessed the missing historical predecessor"
    );
    group.send(0, 1, 1, 10);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_late_durable_join_does_not_reopen_a_best_effort_members_skipped_prefix() {
    let mut group = configured_group_in_mode(false, None, true, false);
    group.subscriber.begin_access().unwrap();
    group.send(1, 1, 2, 20);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    group.join_durable(false, None);
    group.send(1, 1, 2, 20);
    group.send(0, 1, 1, 10);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "durable join rewound an existing BEST_EFFORT member"
    );
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_late_members_missing_prefix_fences_an_old_unread_newer_sample() {
    let mut group = configured_group(false, None, true);
    consumed_prefix(&group);
    group.subscriber.begin_access().unwrap();
    group.send(0, 2, 3, 30);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    group.join_durable(false, None);
    group.heartbeat(0, [3, 1, 3], None);
    group.heartbeat(1, [3, 2, 2], None);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "unknown history had no shared fence before any historical DATA arrived"
    );
    group.send(1, 1, 2, 20);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "old unread GSN 3 bypassed possible historical GSN 1"
    );
    assert_eq!(group.readers[1].take().unwrap(), None);
    group.send(0, 1, 1, 10);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 20 }));
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 30 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_late_members_one_slot_keeps_room_for_its_historical_predecessor() {
    let mut group = configured_group(false, None, true);
    consumed_prefix(&group);
    group.subscriber.begin_access().unwrap();
    group.join_durable(false, Some(1));
    group.send(1, 1, 2, 20);
    group.send(0, 1, 1, 10);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[1].take().unwrap(),
        Some(Value { value: 10 }),
        "future history took the predecessor's only place"
    );
    assert_eq!(group.readers[1].take().unwrap(), None);
    group.send(1, 1, 2, 20);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[1].take().unwrap(),
        Some(Value { value: 20 }),
        "refused history could not be repaired"
    );
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_late_member_joins_the_copies_owed_by_an_already_pending_live_change() {
    let mut group = configured_group(false, None, true);
    consumed_prefix(&group);
    group.subscriber.begin_access().unwrap();
    group.send(0, 2, 3, 30);
    group.join_durable(false, None);
    group.send(1, 1, 2, 20);
    group.send(0, 1, 1, 10);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 20 }));
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "pending live cohort omitted its new owed copy"
    );
    group.send(0, 2, 3, 30);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 30 }));
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 30 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn deleting_a_late_member_releases_an_owned_pending_survivor_without_an_arrival() {
    use crate::dds::Condition as _;
    let mut group = configured_group(false, None, true);
    consumed_prefix(&group);
    group.subscriber.begin_access().unwrap();
    group.send(0, 2, 3, 30);
    group.join_durable(false, None);
    group.send(1, 1, 2, 20);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "survivor was not pending behind replay"
    );
    group.subscriber.end_access().unwrap();
    let status = group.readers[0].get_status_condition();
    status.set_enabled_statuses(crate::dds::StatusMask::DATA_AVAILABLE);
    assert!(!status.get_trigger_value());
    let waitset = crate::WaitSet::new();
    waitset.attach_condition(status).unwrap();
    group.delete_joiner();
    group.subscriber.begin_access().unwrap();
    assert!(
        waitset
            .wait(Some(std::time::Duration::from_secs(2)))
            .is_ok(),
        "deleting replay debt did not wake its queued survivor"
    );
    assert_eq!(
        group.readers[0].take().unwrap(),
        Some(Value { value: 30 }),
        "dead replay cursor stranded an accepted payload"
    );
    group.subscriber.end_access().unwrap();
}

#[test]
fn an_empty_late_history_closes_at_the_last_real_publisher_gsn() {
    let mut group = configured_group(false, None, true);
    consumed_prefix(&group);
    group.subscriber.begin_access().unwrap();
    group.send(0, 2, 3, 30);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    group.join_durable(false, None);
    group.heartbeat(0, [3, 4, 3], None);
    group.heartbeat(1, [3, 4, 3], None);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[0].take().unwrap(),
        Some(Value { value: 30 }),
        "empty history required a nonexistent GSN 4 heartbeat"
    );
    assert_eq!(group.readers[1].take().unwrap(), None);
    group.subscriber.end_access().unwrap();
}

#[test]
fn temporarily_missing_order_membership_refuses_before_receive_credit() {
    let mut group = configured_group(false, None, true);
    consumed_prefix(&group);
    group.subscriber.begin_access().unwrap();
    group.join_durable(false, None);
    let member = group._sinks[1].barrier_member_for_test().unwrap();
    group
        .subscriber
        .coherent_barrier()
        .forget_wire_order_for_test(member);
    group.send(0, 1, 1, 10);
    group._sinks[1].attach_barrier_delivery();
    group.send(0, 1, 1, 10);
    group.send(1, 1, 2, 20);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[1].take().unwrap(),
        Some(Value { value: 10 }),
        "temporary order refusal credited and lost its repair"
    );
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn staged_data_without_order_membership_is_repaired_after_the_absent_release() {
    let group = configured_group_with_ack(true, None, true, true, true, true);
    group.subscriber.begin_access().unwrap();
    let member = group._sinks[0].barrier_member_for_test().unwrap();
    group
        .subscriber
        .coherent_barrier()
        .forget_wire_order_for_test(member);
    group.send_member(0, 1, 1, 10, true);
    group.send_member(1, 1, 2, 20, true);
    let digest = crate::protocol::group::group_digest(WRITERS);
    group.close_tagged(0, 2, 3, digest);
    group.close_tagged(1, 2, 3, digest);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    assert!(
        group.credits[0].awaits(&writer, 1),
        "refused DATA was credited"
    );
    assert!(
        group.credits[0].awaits(&writer, 2),
        "unretained ECS proof was credited"
    );
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), None);
    group.subscriber.end_access().unwrap();
    // Both payload and marker remain owed while ordering registration is
    // absent. Reattachment must admit these same writer SNs without loss.
    group._sinks[0].attach_barrier_delivery();
    group.subscriber.begin_access().unwrap();
    group.send_member(0, 1, 1, 10, true);
    group.send_member(1, 1, 2, 20, true);
    group.close_tagged(0, 2, 3, digest);
    group.close_tagged(1, 2, 3, digest);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[0].take().unwrap(),
        Some(Value { value: 10 }),
        "staged refusal credited and lost the first repair"
    );
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_stale_coherent_best_effort_member_consumes_its_sn_without_backlog() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let group = configured_group_in_mode(true, None, true, false);
    // Valid send order is A DATA1, A ECS2, then ordinary B DATA3.
    // Receive the later ordinary change first, as BEST_EFFORT permits.
    group.subscriber.begin_access().unwrap();
    group.send(1, 1, 3, 30);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 30 }));
    let refused = Arc::new(AtomicBool::new(false));
    let marked = refused.clone();
    *group._sinks[0].refusal_entry_hook.lock().unwrap() = Some(Box::new(move || {
        marked.store(true, Ordering::SeqCst);
    }));
    group.send_member(0, 1, 1, 10, true);
    group.close_tagged(0, 2, 2, crate::protocol::group::group_digest(WRITERS));
    assert!(
        !refused.load(Ordering::SeqCst),
        "terminal stale coherent DATA was treated as retryable Backlog"
    );
    group.send(0, 3, 4, 40);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[0].take().unwrap(),
        Some(Value { value: 40 }),
        "stale coherent traffic stranded the later writer SN"
    );
    assert_eq!(group.readers[0].take().unwrap(), None);
    group.subscriber.end_access().unwrap();
}

fn ordinary_packet(
    group: &Group,
    writer: usize,
    seq: u64,
    gsn: u64,
    value: i32,
) -> (Vec<u8>, usize) {
    let context = RtpsEndpointContext {
        guid_prefix: PREFIX,
        reader_entity_id: [0; 4],
        writer_entity_id: WRITERS[writer],
        encapsulation_kind: 0x0007,
        publisher_entity_id: PUBLISHER,
    };
    let mut bytes = [0; 64];
    let len = Value { value }
        .encode(&mut bytes, CdrVersion::Xcdr2)
        .unwrap();
    let tag = crate::protocol::group::GroupTag {
        gsn,
        writer_set: crate::protocol::group::group_digest(WRITERS),
        set_first_gsn: None,
        part_first_sn: None,
    };
    let packet = builder::build_data_packet_grouped_ts(
        &context,
        &group.topics[writer],
        seq,
        &bytes[..len],
        CdrVersion::Xcdr2,
        (0, 0),
        None,
        None,
        Some(&tag),
        None,
        false,
    );
    let offset = packet.len() - len;
    (packet, offset)
}

fn attach_during_deposit(durable: bool) {
    let mut group = configured_group(false, None, true);
    consumed_prefix(&group);
    group.subscriber.begin_access().unwrap();
    let (paused, ready) = std::sync::mpsc::channel();
    let (resume, resumed) = std::sync::mpsc::channel();
    *group.roster_hook.lock().unwrap() = Some(Box::new(move || {
        paused.send(()).unwrap();
        resumed
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
    }));
    let (packet, offset) = ordinary_packet(&group, 0, 2, 3, 30);
    let registry = group.registry.clone();
    let receiving = std::thread::spawn(move || {
        route_data_packet(
            &packet,
            packet.len(),
            Some(offset),
            &registry,
            &RouterMetrics::new(),
        )
    });
    ready
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("deposit roster snapshot");
    group.join_reader(false, None, durable);
    resume.send(()).unwrap();
    receiving.join().unwrap();
    if durable {
        group.send(1, 1, 2, 20);
        group.send(0, 1, 1, 10);
    }
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    if durable {
        assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 10 }));
        assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 20 }));
        assert_eq!(
            group.readers[0].take().unwrap(),
            None,
            "deposit omitted the newly owed durable copy of live3"
        );
        group.send(0, 2, 3, 30);
        group.subscriber.end_access().unwrap();
        group.subscriber.begin_access().unwrap();
        assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 30 }));
    } else {
        assert_eq!(group.readers[1].take().unwrap(), None);
    }
    assert_eq!(
        group.readers[0].take().unwrap(),
        Some(Value { value: 30 }),
        "a pre-join frame created phantom volatile copy debt"
    );
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_durable_join_during_deposit_preserves_its_live_copy_debt() {
    attach_during_deposit(true);
}
#[test]
fn a_volatile_join_during_deposit_does_not_owe_the_prejoin_copy() {
    attach_during_deposit(false);
}

#[test]
fn a_durable_join_during_release_restarts_its_roster_proof() {
    let mut group = configured_group(false, None, true);
    consumed_prefix(&group);
    group.subscriber.begin_access().unwrap();
    group.send(0, 2, 3, 30);
    // Existing valid heartbeats cannot substitute for the joining reader's
    // still-missing copy of A1. They make stale membership proof observable.
    group.heartbeat(0, [3, 1, 3], None);
    group.heartbeat(1, [3, 2, 2], None);
    let (paused, ready) = std::sync::mpsc::channel();
    let (resume, resumed) = std::sync::mpsc::channel();
    *group.roster_hook.lock().unwrap() = Some(Box::new(move || {
        paused.send(()).unwrap();
        resumed
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
    }));
    group.subscriber.end_access().unwrap();
    let subscriber = group.subscriber.clone();
    let beginning = std::thread::spawn(move || subscriber.begin_access().unwrap());
    ready
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("release roster snapshot");
    group.join_durable(false, None);
    resume.send(()).unwrap();
    beginning.join().unwrap();
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "release skipped a member absent from its roster snapshot"
    );
    group.send(1, 1, 2, 20);
    group.send(0, 1, 1, 10);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 20 }));
    assert_eq!(group.readers[0].take().unwrap(), None);
    group.send(0, 2, 3, 30);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 30 }));
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 30 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_stale_coherent_discard_cannot_credit_a_replacement_writer() {
    use crate::engine::subscriber::Subscriber as _;
    use std::sync::atomic::{AtomicBool, Ordering};
    let group = configured_group_in_mode(true, None, true, false);
    group.subscriber.begin_access().unwrap();
    group.send(1, 1, 3, 30);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 30 }));
    let called = Arc::new(AtomicBool::new(false));
    let marked = called.clone();
    let weak = Arc::downgrade(&group._sinks[0]);
    let topic = group.topics[0].clone();
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    *group._sinks[0].admission_hook.lock().unwrap() = Some(Box::new(move || {
        marked.store(true, Ordering::SeqCst);
        let sink = weak.upgrade().unwrap();
        sink.on_writer_departure(
            &topic,
            writer,
            crate::engine::subscriber::DisposeKind::Unregistered,
            crate::engine::WriterDeparture::Deleted,
        );
        sink.on_writer_qos_resolved(writer);
    }));
    group.send_member(0, 1, 1, 10, true);
    assert!(
        called.load(Ordering::SeqCst),
        "terminal discard did not reach admission"
    );
    group.send(0, 1, 4, 40);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[0].take().unwrap(),
        Some(Value { value: 40 }),
        "old discard polluted the replacement writer's SN1"
    );
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_sparse_ecs_proof_limit_refuses_before_credit_and_keeps_the_marker_repairable() {
    let group = configured_group_with_ack(false, None, true, true, true, true);
    group.subscriber.begin_access().unwrap();
    let context = RtpsEndpointContext {
        guid_prefix: PREFIX,
        reader_entity_id: [0; 4],
        writer_entity_id: WRITERS[0],
        encapsulation_kind: 0x0007,
        publisher_entity_id: PUBLISHER,
    };
    // B's withheld coherent DATA has each odd GSN; A's empty part closes
    // each set at the even GSN. Every A writer SN is otherwise contiguous.
    let marker = |seq| {
        let tag = crate::protocol::group::GroupTag {
            gsn: seq * 2,
            writer_set: crate::protocol::group::group_digest(WRITERS),
            set_first_gsn: Some(seq * 2 - 1),
            part_first_sn: Some(seq),
        };
        let packet = builder::build_ecs_spec_ts(&context, &group.topics[0], seq, &tag, (0, 0));
        route_data_packet(
            &packet,
            packet.len(),
            None,
            &group.registry,
            &RouterMetrics::new(),
        );
    };
    for seq in 1..=513 {
        marker(seq);
    }
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    assert!(!group.credits[0].awaits(&writer, 512));
    assert!(
        group.credits[0].awaits(&writer, 513),
        "refused proof marker was ACKed"
    );
    group.send_member(1, 1, 1, 10, true);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    marker(513);
    assert!(
        !group.credits[0].awaits(&writer, 513),
        "proof room did not admit the repair"
    );
    group.subscriber.end_access().unwrap();
}

fn cache_unread_third(group: &Group) {
    consumed_prefix(group);
    group.subscriber.begin_access().unwrap();
    group.send(0, 2, 3, 30);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    group.subscriber.end_access().unwrap();
}

#[test]
fn explicit_departure_of_every_known_writer_closes_an_empty_join_history() {
    let mut group = configured_group(false, None, true);
    cache_unread_third(&group);
    for entity in WRITERS {
        let mut writer = [0; 16];
        writer[..12].copy_from_slice(&PREFIX);
        writer[12..].copy_from_slice(&entity);
        group.registry.notify_writer_departure(
            writer,
            crate::engine::DisposeKind::Unregistered,
            crate::engine::WriterDeparture::Deleted,
        );
    }
    group.roster.lock().unwrap().clear();
    group.subscriber.begin_access().unwrap();
    group.join_durable(false, None);
    assert_eq!(group.readers[0].take().unwrap(), None);
    group.subscriber.end_access().unwrap();
    let status = group.readers[0].get_status_condition();
    status.set_enabled_statuses(crate::dds::StatusMask::DATA_AVAILABLE);
    let waitset = crate::WaitSet::new();
    waitset.attach_condition(status).unwrap();
    group.subscriber.begin_access().unwrap();
    assert!(
        waitset
            .wait(Some(std::time::Duration::from_secs(2)))
            .is_ok(),
        "terminal Publisher history left an unread survivor fenced"
    );
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 30 }));
    assert_eq!(group.readers[1].take().unwrap(), None);
    group.subscriber.end_access().unwrap();
}

#[test]
fn empty_partial_and_unresolved_discovery_do_not_prove_history_absent() {
    for mode in 0..3 {
        let mut group = configured_group(false, None, true);
        cache_unread_third(&group);
        group.subscriber.begin_access().unwrap();
        group.join_durable(false, None);
        if mode == 0 {
            group.roster.lock().unwrap().clear();
        } else if mode == 1 {
            group.roster.lock().unwrap().truncate(1);
        } else {
            group
                .roster_ready
                .store(false, std::sync::atomic::Ordering::Release);
        }
        group.subscriber.end_access().unwrap();
        group.subscriber.begin_access().unwrap();
        assert_eq!(
            group.readers[0].take().unwrap(),
            None,
            "uncertain discovery view {mode} erased historical debt"
        );
        assert_eq!(group.readers[1].take().unwrap(), None);
        group.subscriber.end_access().unwrap();
        *group.roster.lock().unwrap() = WRITERS.to_vec();
        group
            .roster_ready
            .store(true, std::sync::atomic::Ordering::Release);
        group.heartbeat(0, [3, 4, 3], None);
        group.heartbeat(1, [3, 4, 3], None);
        group.subscriber.begin_access().unwrap();
        assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 30 }));
        group.subscriber.end_access().unwrap();
    }
}

#[test]
fn dropping_an_unused_order_owner_keeps_the_joiners_unknown_prefix() {
    let mut group = configured_group(false, None, true);
    cache_unread_third(&group);
    group.subscriber.begin_access().unwrap();
    group.join_durable(false, None);
    let source = &group._sinks[1];
    let member = source.barrier_member_for_test().unwrap();
    let mut publisher = [0; 16];
    publisher[..12].copy_from_slice(&PREFIX);
    publisher[12..].copy_from_slice(&PUBLISHER);
    let token = super::wire_order::OrderToken::new(
        source.wire_bindings.as_ref().unwrap(),
        None,
        crate::engine::router::OrderedGroupChange {
            publisher,
            gsn: 1,
            writer_set: crate::protocol::group::group_digest(WRITERS),
        },
        group.subscriber.coherent_barrier(),
        member,
        None,
        super::wire_order::LossContext::default(),
    )
    .unwrap();
    // This owner never reached arrival. The unknown-prefix owner is separate.
    drop(token);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "unused owner cancellation erased another pending prefix owner"
    );
    group.send(1, 1, 2, 20);
    group.send(0, 1, 1, 10);
    group.send(0, 2, 3, 30);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 20 }));
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 30 }));
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 30 }));
    group.subscriber.end_access().unwrap();
}

fn finish_order_owner_without_a_visible_sample(arrived: bool) {
    let group = configured_group(false, None, true);
    group.subscriber.begin_access().unwrap();
    let source = &group._sinks[0];
    let member = source.barrier_member_for_test().unwrap();
    let mut publisher = [0; 16];
    publisher[..12].copy_from_slice(&PREFIX);
    publisher[12..].copy_from_slice(&PUBLISHER);
    let change = crate::engine::router::OrderedGroupChange {
        publisher,
        gsn: 1,
        writer_set: crate::protocol::group::group_digest(WRITERS),
    };
    {
        let _delivering = super::notices::Delivering::enter();
        // EMPTY is registered with the order ledger only, never dereferenced
        // or put into the ring: the arrived payload is rejected before push.
        let handle = arrived.then_some(crate::core::rt::SlabHandle::EMPTY);
        let mut token = super::wire_order::OrderToken::new(
            source.wire_bindings.as_ref().unwrap(),
            handle,
            change,
            group.subscriber.coherent_barrier(),
            member,
            None,
            super::wire_order::LossContext::default(),
        )
        .unwrap();
        assert!(token.attach());
        if !arrived {
            // A successful no-payload transition owns no arrived cache entry.
            token.commit();
        }
        drop(token);
        let mut writer = publisher;
        writer[12..].copy_from_slice(&WRITERS[0]);
        group
            .subscriber
            .coherent_barrier()
            .wire_settled(member, writer, change);
    }
    group.send(1, 1, 2, 20);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[0].take().unwrap(),
        Some(Value { value: 20 }),
        "a completed or rejected order owner stranded a later value"
    );
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_sampleless_commit_releases_its_unused_pending_order_owner() {
    finish_order_owner_without_a_visible_sample(false);
}

#[test]
fn a_rejected_arrival_releases_its_arrived_order_owner() {
    finish_order_owner_without_a_visible_sample(true);
}

#[test]
fn a_published_coherent_change_fences_a_later_members_older_ordinary_history() {
    use crate::dds::Condition as _;
    let mut group = configured_group_for_writer(true, None, false, true, true, true, Some(1));
    group.subscriber.begin_access().unwrap();
    let digest = crate::protocol::group::group_digest(WRITERS);
    // Valid Publisher order: A ordinary1, then set{B2}, common ECS3.
    // The existing B reader does not match A, so A1 is not sent to it.
    group.heartbeat(1, [2, 2, 2], Some(digest));
    group.send_set_tagged(1, 1, 2, 20, Some(2), digest);
    group.close_in_set(1, 2, 3, digest, 2, 1);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    let status = group.readers[0].get_status_condition();
    status.set_enabled_statuses(crate::dds::StatusMask::DATA_AVAILABLE);
    assert!(status.get_trigger_value(), "coherent B2 was not published");
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    group.join_topic_reader(true, None, true, 0, false, true);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "visible coherent B2 bypassed the new reader's ordinary A1 history"
    );
    group.send(0, 1, 1, 10);
    group.close_in_set(0, 2, 3, digest, 2, 2);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();
}

fn lost_ecs_departure_preserves_publisher_order(known_roster: bool) {
    use crate::dds::Condition as _;
    let mut group = configured_group_for_writer(true, None, false, true, true, true, Some(1));
    let digest = crate::protocol::group::group_digest(WRITERS);
    group.subscriber.begin_access().unwrap();
    // A1 is ordinary and unmatched here; the complete next set contains B2.
    group.heartbeat(1, [2, 2, 2], Some(digest));
    group.send_set_tagged(1, 1, 2, 20, Some(2), digest);
    group.close_in_set(1, 2, 3, digest, 2, 1);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    let status = group.readers[0].get_status_condition();
    status.set_enabled_statuses(crate::dds::StatusMask::DATA_AVAILABLE);
    assert!(
        status.get_trigger_value(),
        "the closed set was not published"
    );

    // The sender closes its next set, but its ECS5 is lost in transport.
    // B4 is received and ACKed before the authoritative writer departure.
    let context = RtpsEndpointContext {
        guid_prefix: PREFIX,
        reader_entity_id: [0; 4],
        writer_entity_id: WRITERS[1],
        encapsulation_kind: 0x0007,
        publisher_entity_id: PUBLISHER,
    };
    let mut bytes = [0; 64];
    let len = Value { value: 40 }
        .encode(&mut bytes, CdrVersion::Xcdr2)
        .unwrap();
    let tag = crate::protocol::group::GroupTag {
        gsn: 4,
        writer_set: if known_roster {
            digest
        } else {
            crate::protocol::group::group_digest([WRITERS[0], WRITERS[1], [0, 0, 0x13, 2]])
        },
        set_first_gsn: Some(4),
        part_first_sn: None,
    };
    let packet = builder::build_data_packet_grouped_ts(
        &context,
        &group.topics[1],
        3,
        &bytes[..len],
        CdrVersion::Xcdr2,
        (0, 0),
        Some(3),
        Some(4),
        Some(&tag),
        None,
        false,
    );
    route_data_packet(
        &packet,
        packet.len(),
        Some(packet.len() - len),
        &group.registry,
        &RouterMetrics::new(),
    );
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[1]);
    assert!(!group.credits[0].awaits(&writer, 3), "B4 was not received");
    for entity in WRITERS {
        writer[12..].copy_from_slice(&entity);
        group.registry.notify_writer_departure(
            writer,
            crate::engine::DisposeKind::Unregistered,
            crate::engine::WriterDeparture::Deleted,
        );
    }
    group.roster.lock().unwrap().clear();
    group.join_topic_reader(true, None, true, 0, false, true);
    group.subscriber.end_access().unwrap();
    let waitset = crate::WaitSet::new();
    waitset.attach_condition(status).unwrap();
    group.subscriber.begin_access().unwrap();
    if known_roster {
        assert!(
            waitset
                .wait(Some(std::time::Duration::from_secs(2)))
                .is_ok(),
            "a discarded incomplete set left an older complete set fenced"
        );
        assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    }
    assert_eq!(group.readers[0].take().unwrap(), None);
    assert_eq!(group.readers[1].take().unwrap(), None);
    group.subscriber.end_access().unwrap();
}

#[test]
fn deletion_after_a_lost_ecs_releases_an_older_published_coherent_change() {
    lost_ecs_departure_preserves_publisher_order(true);
}

#[test]
fn an_unknown_writer_set_cannot_extend_an_older_rosters_terminal_boundary() {
    lost_ecs_departure_preserves_publisher_order(false);
}

#[test]
fn attachment_and_reservation_order_a_change_before_it_can_be_published() {
    for attach_first in [false, true] {
        let mut group = configured_group_for_writer(true, None, false, true, true, true, Some(1));
        group.subscriber.begin_access().unwrap();
        let bindings = group._sinks[0]
            .wire_bindings
            .as_ref()
            .unwrap()
            .upgrade()
            .unwrap();
        let weak = Arc::downgrade(&bindings);
        let mut publisher = [0; 16];
        publisher[..12].copy_from_slice(&PREFIX);
        publisher[12..].copy_from_slice(&PUBLISHER);
        let change = crate::engine::router::OrderedGroupChange {
            publisher,
            gsn: 2,
            writer_set: crate::protocol::group::group_digest(WRITERS),
        };
        if attach_first {
            group.join_topic_reader(true, None, true, 0, false, true);
        }
        let mut token = super::wire_order::OrderToken::new(
            &weak,
            Some(crate::core::rt::SlabHandle::EMPTY),
            change,
            group.subscriber.coherent_barrier(),
            group._sinks[0].barrier_member_for_test().unwrap(),
            None,
            super::wire_order::LossContext::default(),
        )
        .unwrap();
        if !attach_first {
            group.join_topic_reader(true, None, true, 0, false, true);
        }
        let _delivering = super::notices::Delivering::enter();
        // The ledger handoff precedes ring publication. EMPTY is never
        // dereferenced or inserted into the ring in this protocol probe.
        assert!(token.attach());
        let order = bindings.local_read_order().unwrap();
        let reader = Arc::as_ptr(&bindings) as usize;
        let arrived = order
            .claim(reader, crate::core::rt::SlabHandle::EMPTY)
            .unwrap();
        let mut writer = publisher;
        writer[12..].copy_from_slice(&WRITERS[1]);
        let key = (Some(writer), 1);
        order.decoded_token(arrived, Some(key));
        assert!(
            !order.allows(reader, key),
            "publication could expose GSN2 before the joining reader's prefix"
        );
        drop(token);
        group.subscriber.end_access().unwrap();
    }
}

#[test]
fn a_contiguous_marker_prefix_reclaims_a_keep_all_heartbeat_span() {
    let group = configured_group_for_writer(false, None, false, true, true, true, Some(1));
    group.subscriber.begin_access().unwrap();
    let digest = crate::protocol::group::group_digest(WRITERS);
    // A writes the odd GSNs, B closes empty sets at the even GSNs. The
    // reader only matches B. KEEP_ALL retains a span across A's holes.
    for seq in 1..=514 {
        group.close_in_set(1, seq, seq * 2, digest, seq * 2, seq);
    }
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[1]);
    assert!(group.credits[0].awaits(&writer, 513));
    assert!(group.credits[0].awaits(&writer, 514));
    group.heartbeat(1, [1028, 2, 1028], Some(digest));
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    group.close_in_set(1, 513, 1026, digest, 1026, 513);
    group.close_in_set(1, 514, 1028, digest, 1028, 514);
    assert!(
        !group.credits[0].awaits(&writer, 514),
        "a complete own marker prefix did not reclaim the retained span"
    );
    group.send(1, 515, 1029, 77);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 77 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn retained_reliable_history_never_expires_from_an_order_wait() {
    let mut group = configured_group_with_ack(false, None, true, true, true, true);
    let clock = Arc::new(crate::dds::liveliness::ManualClock::new(0));
    let barrier = group.subscriber.coherent_barrier().clone();
    barrier.set_wire_clock_for_test(clock.clone());
    consumed_prefix(&group);
    group.subscriber.begin_access().unwrap();
    group.send(0, 2, 3, 30);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    group.join_topic_reader(false, None, true, 0, true, true);
    group.heartbeat(
        0,
        [3, 1, 3],
        Some(crate::protocol::group::group_digest(WRITERS)),
    );
    clock.advance(std::time::Duration::from_secs(365 * 86_400));
    barrier.pump_wire_history_for_test();
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "elapsed time skipped still-retained RELIABLE history"
    );
    group.send(0, 1, 1, 10);
    group.send(1, 1, 2, 20);
    group.send(0, 2, 3, 30);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 20 }));
    for reader in &group.readers {
        assert_eq!(reader.take().unwrap(), Some(Value { value: 30 }));
    }
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_long_order_wait_preserves_an_accepted_reservations_handoff() {
    let mut group = configured_group_with_ack(false, None, true, true, true, true);
    let clock = Arc::new(crate::dds::liveliness::ManualClock::new(0));
    let barrier = group.subscriber.coherent_barrier().clone();
    barrier.set_wire_clock_for_test(clock.clone());
    consumed_prefix(&group);
    group.subscriber.begin_access().unwrap();
    group.send(0, 2, 3, 30);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    group.join_topic_reader(false, None, true, 0, true, true);
    let bindings = group._sinks[1]
        .wire_bindings
        .as_ref()
        .unwrap()
        .upgrade()
        .unwrap();
    let mut publisher = [0; 16];
    publisher[..12].copy_from_slice(&PREFIX);
    publisher[12..].copy_from_slice(&PUBLISHER);
    let change = crate::engine::router::OrderedGroupChange {
        publisher,
        gsn: 1,
        writer_set: crate::protocol::group::group_digest(WRITERS),
    };
    let mut token = super::wire_order::OrderToken::new(
        &Arc::downgrade(&bindings),
        Some(crate::core::rt::SlabHandle::EMPTY),
        change,
        &barrier,
        group._sinks[1].barrier_member_for_test().unwrap(),
        None,
        super::wire_order::LossContext::default(),
    )
    .unwrap();
    clock.advance(std::time::Duration::from_secs(86_400));
    barrier.pump_wire_history_for_test();
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "expiry cancelled an accepted predecessor"
    );
    assert!(
        token.attach(),
        "an accepted pre-expiry owner lost its handoff"
    );
    let order = bindings.local_read_order().unwrap();
    let reader = Arc::as_ptr(&bindings) as usize;
    let claim = order
        .claim(reader, crate::core::rt::SlabHandle::EMPTY)
        .unwrap();
    let mut writer = publisher;
    writer[12..].copy_from_slice(&WRITERS[0]);
    let key = (Some(writer), 1);
    order.decoded_token(claim, Some(key));
    assert!(order.allows(reader, key));
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "arrived accepted predecessor was bypassed"
    );
    order.accessed(reader, key);
    token.commit();
    barrier.wire_settled(
        group._sinks[1].barrier_member_for_test().unwrap(),
        writer,
        change,
    );
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "a reservation handoff did not prove every other historical copy unavailable"
    );
    group.subscriber.end_access().unwrap();
}

impl Group {
    fn send_coherent_part(
        &self,
        writer: usize,
        seq: u64,
        gsn: u64,
        value: i32,
        first: u64,
        part: u64,
    ) {
        let context = RtpsEndpointContext {
            guid_prefix: PREFIX,
            reader_entity_id: [0; 4],
            writer_entity_id: WRITERS[writer],
            encapsulation_kind: 0x0007,
            publisher_entity_id: PUBLISHER,
        };
        let mut bytes = [0; 64];
        let len = Value { value }
            .encode(&mut bytes, CdrVersion::Xcdr2)
            .unwrap();
        let tag = crate::protocol::group::GroupTag {
            gsn,
            writer_set: crate::protocol::group::group_digest(WRITERS),
            set_first_gsn: Some(first),
            part_first_sn: None,
        };
        let packet = builder::build_data_packet_grouped_ts(
            &context,
            &self.topics[writer],
            seq,
            &bytes[..len],
            CdrVersion::Xcdr2,
            (0, 0),
            Some(part),
            Some(first),
            Some(&tag),
            None,
            false,
        );
        route_data_packet(
            &packet,
            packet.len(),
            Some(packet.len() - len),
            &self.registry,
            &RouterMetrics::new(),
        );
    }
}

#[test]
fn incomplete_historical_and_latest_units_need_an_actual_loss_proof() {
    let mut group = configured_group_for_writer(true, None, false, true, true, true, Some(1));
    let clock = Arc::new(crate::dds::liveliness::ManualClock::new(0));
    let barrier = group.subscriber.coherent_barrier().clone();
    barrier.set_wire_clock_for_test(clock.clone());
    let digest = crate::protocol::group::group_digest(WRITERS);
    group.subscriber.begin_access().unwrap();
    // The sender closed A1 with ECS2, lost here; then completed B3 with ECS4.
    group.send_coherent_part(1, 1, 3, 30, 3, 1);
    group.close_in_set(1, 2, 4, digest, 3, 1);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    // This genuinely live open set must survive the history wait.
    group.send_coherent_part(1, 3, 5, 50, 5, 3);
    group.join_topic_reader(true, None, true, 0, false, true);
    // Another late member owns the latest still-open B5 too. Its fixed
    // history cut includes5, so the completed-generation guard is required.
    group.join_topic_reader(true, None, true, 1, false, true);
    group.send_coherent_part(1, 1, 3, 30, 3, 1);
    group.close_in_set(1, 2, 4, digest, 3, 1);
    group.send_coherent_part(1, 3, 5, 50, 5, 3);
    group.send_coherent_part(0, 1, 1, 10, 1, 1);
    assert_eq!(group.readers[0].take().unwrap(), None);
    assert_eq!(group.readers[1].take().unwrap(), None);
    group.subscriber.end_access().unwrap();
    clock.advance(std::time::Duration::from_secs(365 * 86_400));
    barrier.pump_wire_history_for_test();
    group.subscriber.begin_access().unwrap();
    for reader in &group.readers {
        assert_eq!(
            reader.take().unwrap(),
            None,
            "elapsed time discarded an accepted coherent predecessor"
        );
    }
    group.subscriber.end_access().unwrap();
}

#[test]
fn resolved_history_keeps_a_later_unknown_live_prefix_ordered() {
    let mut group = configured_group(false, None, true);
    let clock = Arc::new(crate::dds::liveliness::ManualClock::new(0));
    let barrier = group.subscriber.coherent_barrier().clone();
    barrier.set_wire_clock_for_test(clock.clone());
    consumed_prefix(&group);
    group.subscriber.begin_access().unwrap();
    group.join_durable(false, None);
    group.send(1, 1, 2, 20);
    group.send(0, 1, 1, 10);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 20 }));
    group.send(0, 2, 3, 30);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 30 }));
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 30 }));
    clock.advance(std::time::Duration::from_secs(172_800));
    barrier.pump_wire_history_for_test();
    let old = group._sinks[0]
        .wire_bindings
        .as_ref()
        .unwrap()
        .upgrade()
        .unwrap();
    let late = group._sinks[1]
        .wire_bindings
        .as_ref()
        .unwrap()
        .upgrade()
        .unwrap();
    let mut publisher = [0; 16];
    publisher[..12].copy_from_slice(&PREFIX);
    publisher[12..].copy_from_slice(&PUBLISHER);
    let change = |gsn| crate::engine::router::OrderedGroupChange {
        publisher,
        gsn,
        writer_set: crate::protocol::group::group_digest(WRITERS),
    };
    let mut higher = super::wire_order::OrderToken::new(
        &Arc::downgrade(&old),
        Some(crate::core::rt::SlabHandle::EMPTY),
        change(5),
        &barrier,
        group._sinks[0].barrier_member_for_test().unwrap(),
        None,
        super::wire_order::LossContext::default(),
    )
    .unwrap();
    assert!(higher.attach());
    let order = old.local_read_order().unwrap();
    let old_id = Arc::as_ptr(&old) as usize;
    let high_token = order
        .claim(old_id, crate::core::rt::SlabHandle::EMPTY)
        .unwrap();
    let mut b = publisher;
    b[12..].copy_from_slice(&WRITERS[1]);
    let high_key = (Some(b), 2);
    order.decoded_token(high_token, Some(high_key));
    assert!(
        !order.allows(old_id, high_key),
        "resolved history erased a later live-prefix fence"
    );
    let mut lower = super::wire_order::OrderToken::new(
        &Arc::downgrade(&late),
        Some(crate::core::rt::SlabHandle::EMPTY),
        change(4),
        &barrier,
        group._sinks[1].barrier_member_for_test().unwrap(),
        None,
        super::wire_order::LossContext::default(),
    )
    .unwrap();
    assert!(lower.attach());
    let late_id = Arc::as_ptr(&late) as usize;
    let low_token = order
        .claim(late_id, crate::core::rt::SlabHandle::EMPTY)
        .unwrap();
    let mut a = publisher;
    a[12..].copy_from_slice(&WRITERS[0]);
    let low_key = (Some(a), 3);
    order.decoded_token(low_token, Some(low_key));
    assert!(order.allows(late_id, low_key));
    order.accessed(late_id, low_key);
    lower.commit();
    assert!(order.allows(old_id, high_key));
    order.accessed(old_id, high_key);
    higher.commit();
    group.subscriber.end_access().unwrap();
}

#[test]
fn an_owned_latest_coherent_set_repairs_after_a_long_order_wait() {
    let mut group = configured_group_with_ack(true, None, true, true, true, true);
    let clock = Arc::new(crate::dds::liveliness::ManualClock::new(0));
    let barrier = group.subscriber.coherent_barrier().clone();
    barrier.set_wire_clock_for_test(clock.clone());
    consumed_prefix(&group);
    let digest = crate::protocol::group::group_digest(WRITERS);
    group.subscriber.begin_access().unwrap();
    // The sender's current open set contains A3 and B4. A3 is delayed.
    // B uses its own next writer SN2, so no writer receive gate is bypassed.
    group.send_coherent_part(1, 2, 4, 40, 3, 2);
    group.join_topic_reader(true, None, true, 0, true, true);
    group.send(0, 1, 1, 10);
    group.send(1, 1, 2, 20);
    group.send_coherent_part(1, 2, 4, 40, 3, 2);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 20 }));
    assert_eq!(group.readers[0].take().unwrap(), None);
    group.subscriber.end_access().unwrap();
    clock.advance(std::time::Duration::from_secs(86_400));
    barrier.pump_wire_history_for_test();
    assert!(
        group._sinks[1]
            .group_coherent_buffer
            .lock()
            .unwrap()
            .keys()
            .any(|key| key.2 == 3),
        "a legitimate owned current set expired as unavailable history"
    );
    group.subscriber.begin_access().unwrap();
    // This is actual next SN2 of A, not a synthetic rewind or receipt.
    group.send_coherent_part(0, 2, 3, 30, 3, 2);
    group.close_in_set(0, 3, 5, digest, 3, 2);
    group.close_in_set(1, 3, 5, digest, 3, 2);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    for reader in &group.readers {
        assert_eq!(
            reader.take().unwrap(),
            Some(Value { value: 30 }),
            "history exhaustion refused a real repair of an already owned coherent set"
        );
    }
    for reader in &group.readers {
        assert_eq!(reader.take().unwrap(), Some(Value { value: 40 }));
    }
    for reader in &group.readers {
        assert_eq!(reader.take().unwrap(), None);
    }
    group.subscriber.end_access().unwrap();
}

#[test]
fn an_ordinary_successor_does_not_prove_retained_history_unavailable() {
    let mut group = configured_group_with_ack(true, None, true, true, true, true);
    let clock = Arc::new(crate::dds::liveliness::ManualClock::new(0));
    let barrier = group.subscriber.coherent_barrier().clone();
    barrier.set_wire_clock_for_test(clock.clone());
    let digest = crate::protocol::group::group_digest(WRITERS);
    group.subscriber.begin_access().unwrap();
    // A1 belongs to set1. B's empty ECS2 was received; A's ECS2 was lost.
    group.send_coherent_part(0, 1, 1, 10, 1, 1);
    group.close_in_set(1, 1, 2, digest, 1, 1);
    group.send(1, 2, 3, 30);
    group.join_topic_reader(true, None, true, 0, true, true);
    group.send_coherent_part(0, 1, 1, 10, 1, 1);
    group.close_in_set(1, 1, 2, digest, 1, 1);
    group.send(1, 2, 3, 30);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    for reader in &group.readers {
        assert_eq!(reader.take().unwrap(), None);
    }
    group.subscriber.end_access().unwrap();
    clock.advance(std::time::Duration::from_secs(365 * 86_400));
    barrier.pump_wire_history_for_test();
    group.subscriber.begin_access().unwrap();
    for reader in &group.readers {
        assert_eq!(
            reader.take().unwrap(),
            None,
            "elapsed time discarded an accepted coherent predecessor"
        );
    }
    group.subscriber.end_access().unwrap();
}

#[test]
fn unmatched_durable_ready_parts_are_not_discarded_by_elapsed_time() {
    let mut group = configured_group_for_writer(true, None, false, true, true, true, Some(1));
    let clock = Arc::new(crate::dds::liveliness::ManualClock::new(0));
    let barrier = group.subscriber.coherent_barrier().clone();
    barrier.set_wire_clock_for_test(clock.clone());
    let digest = crate::protocol::group::group_digest(WRITERS);
    group.subscriber.begin_access().unwrap();
    group.heartbeat(1, [3, 3, 3], Some(digest));
    group.send_coherent_part(1, 1, 3, 30, 3, 1);
    group.close_in_set(1, 2, 4, digest, 3, 1);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 30 }));
    group.send(1, 3, 5, 50);
    group.heartbeat(1, [5, 3, 5], Some(digest));
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    // B5 is complete and published, but its replay view will be fenced.
    group.send_coherent_part(1, 4, 6, 60, 6, 4);
    group.join_topic_reader(true, None, true, 0, false, true);
    group.join_topic_reader(true, None, true, 1, false, true);
    group.send_set_tagged(
        0,
        1,
        1,
        10,
        Some(1),
        crate::protocol::group::group_digest([WRITERS[0]]),
    );
    group.send_coherent_part(1, 1, 3, 30, 3, 1);
    group.close_in_set(1, 2, 4, digest, 3, 1);
    group.send(1, 3, 5, 50);
    group.send_coherent_part(1, 4, 6, 60, 6, 4);
    assert_eq!(group.readers[0].take().unwrap(), None);
    group.subscriber.end_access().unwrap();
    // DATA_AVAILABLE may stay raised for the complete cached B5 while its
    // order is fenced. Check actual readability after deterministic upkeep.
    clock.advance(std::time::Duration::from_secs(365 * 86_400));
    barrier.pump_wire_history_for_test();
    group.subscriber.begin_access().unwrap();
    for reader in &group.readers {
        assert_eq!(
            reader.take().unwrap(),
            None,
            "elapsed time discarded an accepted coherent predecessor"
        );
    }
    group.subscriber.end_access().unwrap();
}

#[test]
fn an_original_peer_repairs_its_real_missing_part_after_a_long_order_wait() {
    let mut group = configured_group_with_ack(true, None, false, true, true, true);
    let clock = Arc::new(crate::dds::liveliness::ManualClock::new(0));
    let barrier = group.subscriber.coherent_barrier().clone();
    barrier.set_wire_clock_for_test(clock.clone());
    let digest = crate::protocol::group::group_digest(WRITERS);
    group.subscriber.begin_access().unwrap();
    group.send_coherent_part(0, 1, 1, 10, 1, 1);
    group.close_in_set(0, 2, 3, digest, 1, 1);
    group.join_topic_reader(true, None, true, 0, false, true);
    group.subscriber.end_access().unwrap();
    clock.advance(std::time::Duration::from_secs(86_400));
    barrier.pump_wire_history_for_test();
    let mut b = [0; 16];
    b[..12].copy_from_slice(&PREFIX);
    b[12..].copy_from_slice(&WRITERS[1]);
    assert!(
        group.credits[1].awaits(&b, 1),
        "another member's owner fabricated B's receipt"
    );
    group.subscriber.begin_access().unwrap();
    group.send_coherent_part(1, 1, 2, 20, 1, 1);
    assert!(
        !group.credits[1].awaits(&b, 1),
        "the actual original peer repair was refused after history expiry"
    );
    // Complete the late A-reader's own copy; no proxy state is borrowed.
    group.send_coherent_part(0, 1, 1, 10, 1, 1);
    group.close_in_set(0, 2, 3, digest, 1, 1);
    group.close_in_set(1, 2, 3, digest, 1, 1);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    let publisher = super::coherent_barrier::publisher_key(PREFIX, PUBLISHER);
    assert_eq!(
        group.readers[0].take().unwrap(),
        Some(Value { value: 10 }),
        "wire={} alignment={}",
        barrier.diagnostic_wire_for_test(publisher),
        barrier.diagnostic_alignment_for_test(publisher)
    );
    assert_eq!(group.readers[2].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 20 }));
    for reader in &group.readers {
        assert_eq!(reader.take().unwrap(), None);
    }
    group.subscriber.end_access().unwrap();
}

#[test]
fn source_lifespan_deadline_includes_time_spent_waiting_for_admission() {
    let group = configured_group(false, None, true);
    let barrier = group.subscriber.coherent_barrier();
    let clock = Arc::new(crate::dds::liveliness::ManualClock::new(0));
    barrier.set_wire_clock_for_test(clock.clone());
    group.subscriber.begin_access().unwrap();
    let delayed = clock.clone();
    barrier.set_wire_reservation_hook_for_test(Box::new(move || {
        delayed.advance(std::time::Duration::from_secs(1))
    }));
    let member = group._sinks[0].barrier_member_for_test().unwrap();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = calls.clone();
    barrier.attach_wire_history(
        member,
        Arc::new(move |_| {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            true
        }),
    );
    let mut publisher = [0; 16];
    publisher[..12].copy_from_slice(&PREFIX);
    publisher[12..].copy_from_slice(&PUBLISHER);
    let token = super::wire_order::OrderToken::new(
        group._sinks[0].wire_bindings.as_ref().unwrap(),
        Some(crate::core::rt::SlabHandle::EMPTY),
        crate::engine::router::OrderedGroupChange {
            publisher,
            gsn: 1,
            writer_set: crate::protocol::group::group_digest(WRITERS),
        },
        barrier,
        member,
        Some(std::time::Duration::from_secs(1)),
        super::wire_order::LossContext::default(),
    )
    .unwrap();
    barrier.activate_wire_lifespan(token.owner_id());
    barrier.pump_wire_history_for_test();
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "admission lock wait extended the source timestamp's LIFESPAN"
    );
    drop(token);
    group.subscriber.end_access().unwrap();
}

#[test]
fn an_individual_unknown_roster_departure_cannot_certify_an_unknown_writer() {
    let group = configured_group_for_writer(false, None, false, true, false, true, Some(1));
    group
        .roster_ready
        .store(false, std::sync::atomic::Ordering::Release);
    group.subscriber.begin_access().unwrap();
    group.send(1, 1, 2, 20);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), None);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[1]);
    group.registry.notify_writer_departure(
        writer,
        crate::engine::DisposeKind::Unregistered,
        crate::engine::WriterDeparture::Unheard,
    );
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "B's departure certified the unannounced live writer A"
    );
    group
        .registry
        .notify_participant_departure(&PREFIX, crate::engine::WriterDeparture::Unheard);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[0].take().unwrap(),
        Some(Value { value: 20 }),
        "participant departure stranded an accepted payload behind an unknown roster"
    );
    assert_eq!(group.readers[0].take().unwrap(), None);
    group.subscriber.end_access().unwrap();
}

#[test]
fn staging_reclamation_preserves_profiles_outside_ordered_group() {
    use crate::dds::qos::PresentationAccessScope::{Group, Instance, Topic};
    for (scope, ordered) in [
        (Topic, true),
        (Instance, true),
        (Group, false),
        (Group, true),
    ] {
        let group = configured_group_for_presentation(
            true,
            Some(2),
            true,
            true,
            true,
            true,
            None,
            false,
            (scope, ordered),
        );
        group.subscriber.begin_access().unwrap();
        let protected = scope == Group && ordered;
        assert_eq!(group._sinks[0].wire_bindings.is_some(), protected);
        let mut writer = [0; 16];
        writer[..12].copy_from_slice(&PREFIX);
        writer[12..].copy_from_slice(&WRITERS[0]);
        for seq in 1..=2 {
            group.send_coherent_part(0, seq, seq, i32::try_from(seq).unwrap(), 1, 1);
        }
        let held = group._sinks[0].staging.used();
        assert!(held > 0, "the admitted prefix must own storage");
        assert!(!group.credits[0].awaits(&writer, 1));
        assert!(!group.credits[0].awaits(&writer, 2));
        for _ in 0..32 {
            group.send_coherent_part(0, 3, 3, 3, 1, 1);
            if protected {
                assert_eq!(
                    group._sinks[0].staging.used(),
                    held,
                    "ordered GROUP pressure reclaimed accepted bytes"
                );
                assert!(
                    group.credits[0].awaits(&writer, 3),
                    "a refused ordered GROUP member was credited"
                );
            } else {
                assert_eq!(
                    group._sinks[0].staging.used(),
                    0,
                    "ordered GROUP retention changed a legacy presentation profile"
                );
                assert!(
                    !group.credits[0].awaits(&writer, 3),
                    "the legacy whole-set rejection did not consume its actual member"
                );
            }
        }
        assert_eq!(
            group.readers[0].take().unwrap(),
            None,
            "a coherent prefix was exposed without its whole set"
        );
        group.subscriber.end_access().unwrap();
    }
}

/// Writer 0's GUID.
fn writer_zero() -> [u8; 16] {
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    writer
}

/// Writer 0's change `seq` (GSN `seq`, value `seq * 10`) addressed to
/// reader 0 by its readerId, as a writer that has discovered the reader
/// sends it.
fn send_directed(group: &Group, seq: u64) {
    let context = RtpsEndpointContext {
        guid_prefix: PREFIX,
        reader_entity_id: crate::engine::Subscriber::reader_entity_id(&*group._sinks[0])
            .expect("a reader built in its participant"),
        writer_entity_id: WRITERS[0],
        encapsulation_kind: 0x0007,
        publisher_entity_id: PUBLISHER,
    };
    let mut bytes = [0; 64];
    let value = i32::try_from(seq).unwrap() * 10;
    let len = Value { value }
        .encode(&mut bytes, CdrVersion::Xcdr2)
        .unwrap();
    let tag = crate::protocol::group::GroupTag {
        gsn: seq,
        writer_set: crate::protocol::group::group_digest(WRITERS),
        set_first_gsn: None,
        part_first_sn: None,
    };
    let packet = builder::build_data_packet_grouped_ts(
        &context,
        &group.topics[0],
        seq,
        &bytes[..len],
        CdrVersion::Xcdr2,
        (0, 0),
        None,
        None,
        Some(&tag),
        None,
        false,
    );
    route_data_packet(
        &packet,
        packet.len(),
        Some(packet.len() - len),
        &group.registry,
        &RouterMetrics::new(),
    );
}

/// A RELIABLE VOLATILE GROUP-ordered reader per writer, built in its
/// participant, acknowledging; writer 0 discovered when `discovered`.
fn bound_group(discovered: bool) -> Group {
    configured_group_bound(
        false,
        None,
        false,
        true,
        discovered,
        true,
        None,
        false,
        (crate::dds::qos::PresentationAccessScope::Group, true),
        false,
        crate::protocol::group::GroupDialect::Spec,
        true,
    )
}

/// What reader 0 delivers in one access bracket.
fn take_all_zero(group: &Group) -> Vec<i32> {
    group.subscriber.begin_access().unwrap();
    let mut values = Vec::new();
    while let Some(sample) = group.readers[0].take().unwrap() {
        values.push(sample.value);
    }
    group.subscriber.end_access().unwrap();
    values
}

/// Control for the case below: a RELIABLE VOLATILE GROUP-ordered reader
/// whose writer is discovered before its DATA delivers every change, in
/// order, and acknowledges each.
#[test]
fn a_group_ordered_reader_delivers_a_writer_discovered_before_its_data() {
    let group = bound_group(true);
    let writer = writer_zero();
    for seq in 1..=5 {
        send_directed(&group, seq);
    }
    assert_eq!(take_all_zero(&group), vec![10, 20, 30, 40, 50]);
    for seq in 1..=5 {
        assert!(
            !group.credits[0].awaits(&writer, seq),
            "{seq} unacknowledged"
        );
    }
}

/// Discovery is asymmetric: a writer that has discovered this reader sends
/// it DATA before this reader has discovered the writer, and the GROUP
/// context needed to order that DATA (the writer's class and Publisher) is
/// unknown. Dropped unacknowledged, it is sent again after discovery,
/// behind later changes; the reader joins at it, so the resends are not
/// judged history, and nothing is acknowledged undelivered.
#[test]
fn a_group_ordered_reader_joins_at_data_dropped_before_its_writer_was_discovered() {
    let group = bound_group(false);
    let writer = writer_zero();
    for seq in 1..=3 {
        send_directed(&group, seq);
    }
    assert_eq!(
        take_all_zero(&group),
        Vec::<i32>::new(),
        "writer undiscovered"
    );
    for seq in 1..=3 {
        assert!(group.credits[0].awaits(&writer, seq), "{seq} acknowledged");
    }
    group
        .registry
        .register_writer_guid(writer, group.topics[0].clone());
    group.registry.record_writer_group_dialect(
        writer,
        crate::protocol::group::GroupDialect::Spec,
        Some(PUBLISHER),
    );
    crate::engine::Subscriber::on_writer_qos_resolved(&*group._sinks[0], writer);
    for seq in 4..=5 {
        send_directed(&group, seq);
    }
    assert_eq!(
        take_all_zero(&group),
        Vec::<i32>::new(),
        "4 and 5 wait for 1..=3"
    );
    for seq in 1..=3 {
        assert!(
            group.credits[0].awaits(&writer, seq),
            "{seq} acknowledged undelivered"
        );
    }
    for seq in 1..=3 {
        send_directed(&group, seq);
    }
    assert_eq!(
        take_all_zero(&group),
        vec![10, 20, 30, 40, 50],
        "the changes dropped before discovery were dropped again as history"
    );
    for seq in 1..=5 {
        assert!(
            !group.credits[0].awaits(&writer, seq),
            "{seq} unacknowledged"
        );
    }
}
