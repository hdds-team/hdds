// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::engine::Subscriber as _;

fn coherent_packet(group: &Group, seq: u64, gsn: u64, value: i32) -> (Vec<u8>, usize) {
    let context = RtpsEndpointContext {
        guid_prefix: PREFIX,
        reader_entity_id: [0; 4],
        writer_entity_id: WRITERS[0],
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
        set_first_gsn: Some(1),
        part_first_sn: None,
    };
    let packet = builder::build_data_packet_grouped_ts(
        &context,
        &group.topics[0],
        seq,
        &bytes[..len],
        CdrVersion::Xcdr2,
        (0, 0),
        Some(1),
        Some(1),
        Some(&tag),
        None,
        false,
    );
    (packet, len)
}

#[test]
fn reliable_staging_pressure_retains_accepted_data_and_refuses_new_receipts() {
    let group = configured_group_with_ack(true, Some(1), true, true, true, true);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    group.subscriber.begin_access().unwrap();
    group.send_coherent_part(0, 1, 1, 10, 1, 1);
    assert!(!group.credits[0].awaits(&writer, 1));
    let accepted_bytes = group._sinks[0].staging.used();
    assert!(accepted_bytes > 0);
    for _ in 0..2 {
        group.send_coherent_part(0, 2, 2, 20, 1, 1);
        assert!(
            group.credits[0].awaits(&writer, 2),
            "a rejected reliable member was credited as received"
        );
        assert_eq!(
            group._sinks[0].staging.used(),
            accepted_bytes,
            "memory pressure purged previously acknowledged coherent DATA"
        );
    }
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 0);
    assert_eq!(group.readers[0].take().unwrap(), None);
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_duplicate_during_provisional_coherent_refusal_does_not_credit_receipt() {
    let group = configured_group_with_ack(true, Some(1), true, true, true, true);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    group.subscriber.begin_access().unwrap();
    group.send_coherent_part(0, 1, 1, 10, 1, 1);
    let (packet, len) = coherent_packet(&group, 2, 2, 20);
    let registry = group.registry.clone();
    let credit = group.credits[0].clone();
    *group._sinks[0]
        .refusal_entry_hook
        .lock()
        .expect("test state mutex") = Some(Box::new(move || {
        route_data_packet(
            &packet,
            packet.len(),
            Some(packet.len() - len),
            &registry,
            &RouterMetrics::new(),
        );
        assert!(
            credit.awaits(&writer, 2),
            "a duplicate acknowledged provisional storage that the first copy refused"
        );
    }));
    group.send_coherent_part(0, 2, 2, 20, 1, 1);
    assert!(group.credits[0].awaits(&writer, 2));
    group.subscriber.end_access().unwrap();
}

#[test]
fn an_unvalidated_roster_is_not_a_time_based_loss_proof() {
    let group = configured_group_with_ack(true, None, true, true, true, true);
    group
        .roster_ready
        .store(false, std::sync::atomic::Ordering::Release);
    group._sinks[0]
        .group_roster_wait_ms
        .store(0, std::sync::atomic::Ordering::Relaxed);
    let digest = crate::protocol::group::group_digest(WRITERS);
    group.subscriber.begin_access().unwrap();
    group.send_coherent_part(0, 1, 1, 10, 1, 1);
    group.send_coherent_part(1, 1, 2, 20, 1, 1);
    group.close_in_set(0, 2, 3, digest, 1, 1);
    group.close_in_set(1, 2, 3, digest, 1, 1);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), None);
    assert_eq!(
        group.readers[0].get_sample_lost_status().total_count,
        0,
        "missing discovery was treated as proof that received DATA was lost"
    );
    group
        .roster_ready
        .store(true, std::sync::atomic::Ordering::Release);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    group._sinks[0].on_writer_group_heartbeat(writer, 3, 1, 3);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn departure_retains_received_gate_data_without_counting_unknown_gsn_holes() {
    let group = configured_group_with_ack(false, None, true, true, true, true);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    group.subscriber.begin_access().unwrap();
    group._sinks[0].on_writer_heartbeat(writer, 1);
    group.send(0, 2, 2, 20);
    assert!(!group.credits[0].awaits(&writer, 2));
    assert_eq!(group.readers[0].take().unwrap(), None);
    depart_known_writers(&group);
    assert_eq!(
        group.readers[0].get_sample_lost_status().total_count,
        0,
        "received DATA survives departure; an unannounced GSN hole has no count"
    );
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    let (data, _) = group.readers[0]
        .take_with_info()
        .unwrap()
        .expect("retained DATA");
    assert_eq!(data, Some(Value { value: 20 }));
    let (data, info) = group.readers[0]
        .take_with_info()
        .unwrap()
        .expect("departure after retained value");
    assert!(data.is_none());
    assert_eq!(
        info.instance_state,
        crate::dds::InstanceState::NotAliveNoWriters
    );
    depart_known_writers(&group);
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 0);
    group.subscriber.end_access().unwrap();
}

fn depart_known_writers(group: &Group) {
    for entity in WRITERS {
        let mut writer = [0; 16];
        writer[..12].copy_from_slice(&PREFIX);
        writer[12..].copy_from_slice(&entity);
        group.registry.notify_writer_departure(
            writer,
            crate::engine::subscriber::DisposeKind::Unregistered,
            crate::engine::WriterDeparture::Deleted,
        );
    }
    group
        .subscriber
        .coherent_barrier()
        .pump_wire_history_for_test();
}

#[test]
fn departure_counts_announced_owed_writer_samples_and_received_payloads_once() {
    let group = configured_group_with_ack(false, None, true, true, true, true);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    group.credits[0].answer_heartbeat(
        &writer,
        &crate::core::reader::HeartbeatSeen {
            first_seq: 31,
            last_seq: 36,
            count: 1,
            final_flag: false,
        },
    );
    group._sinks[0].on_writer_heartbeat(writer, 31);
    group.subscriber.begin_access().unwrap();
    group.send(0, 31, 1, 10);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    group.send(0, 33, 3, 30);
    // This real change is irrelevant, not a lost sample. No prior range
    // 1..31 was owed by this reader, either.
    group.credits[0].note_gap(&writer, 35, 36, &[35]);
    depart_known_writers(&group);
    assert_eq!(
        group.readers[0].get_sample_lost_status().total_count,
        3,
        "only owed SN32,34,36 were lost; received SN33 stays owned"
    );
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 30 }));
    depart_known_writers(&group);
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 3);
    group.subscriber.end_access().unwrap();
}

fn lifespan_group(coherent: bool) -> Group {
    let mut qos = QoS::reliable().keep_all();
    qos.presentation.access_scope = crate::dds::qos::PresentationAccessScope::Group;
    qos.presentation.coherent_access = coherent;
    qos.presentation.ordered_access = true;
    let participant = crate::Participant::builder("wire-source-lifespan")
        .with_transport(crate::TransportMode::IntraProcess)
        .build()
        .unwrap();
    let subscriber = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
    let registry = Arc::new(TopicRegistry::new());
    let topic = "wire-source-lifespan".to_string();
    let credit = crate::core::reader::ReaderAckCredit::new(
        crate::core::reader::ReaderProxyRegistry::new(),
        [0xC1; 16],
    );
    for entity in WRITERS {
        let mut writer = [0; 16];
        writer[..12].copy_from_slice(&PREFIX);
        writer[12..].copy_from_slice(&entity);
        registry.register_writer_guid(writer, topic.clone());
        registry
            .register_writer_ownership_kind(writer, crate::qos::ownership::OwnershipKind::Shared);
        registry.register_writer_partition(writer, crate::qos::partition::Partition::default());
        registry.record_writer_group_dialect(
            writer,
            crate::protocol::group::GroupDialect::Spec,
            Some(PUBLISHER),
        );
        credit.match_writer(writer);
    }
    let reader = ReaderBuilder::<Value>::new(topic.clone())
        .qos(qos)
        .subscriber(&subscriber)
        .with_registry(registry.clone())
        .network_ring_for_test()
        .with_ack_credit_for_test(credit.clone())
        .build()
        .unwrap();
    let sink = reader.subscriber_weak_for_test().upgrade().unwrap();
    let roster = Arc::new(Mutex::new(WRITERS.to_vec()));
    let roster_hook: RosterHook = Default::default();
    let roster_ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
    assert!(sink
        .group_roster
        .set(Arc::new(Roster {
            hook: roster_hook.clone(),
            writer: 0,
            all: true,
            dust: false,
            entities: roster.clone(),
            ready: roster_ready.clone(),
            registry: Arc::downgrade(&registry),
        }))
        .is_ok());
    let member = sink.barrier_member_for_test().unwrap();
    subscriber
        .coherent_barrier()
        .attach_resolver(member, Arc::new(|_| Some(PUBLISHER)));
    for entity in WRITERS {
        let mut writer = [0; 16];
        writer[..12].copy_from_slice(&PREFIX);
        writer[12..].copy_from_slice(&entity);
        subscriber
            .coherent_barrier()
            .register_matched_writer(member, writer);
    }
    Group {
        subscriber,
        readers: vec![reader],
        _sinks: vec![sink],
        credits: vec![credit],
        registry,
        _join_registrations: Vec::new(),
        roster,
        roster_hook,
        roster_ready,
        topics: [topic.clone(), topic],
    }
}

fn source_packet(group: &Group, writer: usize, seq: u64, gsn: u64, value: i32, coherent: bool) {
    source_packet_in_epoch(
        group,
        writer,
        seq,
        gsn,
        value,
        coherent,
        crate::protocol::group::group_digest(WRITERS),
    );
}

#[allow(clippy::too_many_arguments)]
fn source_packet_in_epoch(
    group: &Group,
    writer: usize,
    seq: u64,
    gsn: u64,
    value: i32,
    coherent: bool,
    writer_set: [u8; 4],
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
        writer_set,
        set_first_gsn: coherent.then_some(1),
        part_first_sn: None,
    };
    // A real INFO_TS at one second after epoch. With a finite one-second
    // offer this is expired on receipt, without advancing any test timer.
    let packet = builder::build_data_packet_grouped_ts(
        &context,
        &group.topics[writer],
        seq,
        &bytes[..len],
        CdrVersion::Xcdr2,
        (1, 0),
        coherent.then_some(1),
        coherent.then_some(1),
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

/// A publication that runs between a deposit's lifespan activation and its
/// pending insertion (the publishing thread, woken by an earlier change,
/// delayed by CPU starvation) must not lose the expiry of an already
/// expired sample.
#[test]
fn a_publication_inside_a_deposit_does_not_lose_an_expired_sample() {
    let group = lifespan_group(false);
    let mut writer_b = [0; 16];
    writer_b[..12].copy_from_slice(&PREFIX);
    writer_b[12..].copy_from_slice(&WRITERS[1]);
    group
        .registry
        .register_writer_lifespan_of(&group.topics[1], writer_b, 1_000_000_000);
    group.subscriber.begin_access().unwrap();
    let barrier = group.subscriber.coherent_barrier().clone();
    super::super::wire_order::set_deposit_window_hook(Box::new(move || {
        barrier.pump_wire_history_for_test();
    }));
    source_packet(&group, 1, 1, 2, 20, false);
    group
        .subscriber
        .coherent_barrier()
        .pump_wire_history_for_test();
    assert_eq!(
        group.readers[0].get_sample_lost_status().total_count,
        1,
        "the sample expired on receipt was never reported lost"
    );
}

#[test]
fn source_lifespan_expires_only_its_real_sample_and_does_not_waive_an_unknown_predecessor() {
    let group = lifespan_group(false);
    let mut writer_b = [0; 16];
    writer_b[..12].copy_from_slice(&PREFIX);
    writer_b[12..].copy_from_slice(&WRITERS[1]);
    group
        .registry
        .register_writer_lifespan_of(&group.topics[1], writer_b, 1_000_000_000);
    group.subscriber.begin_access().unwrap();
    source_packet(&group, 1, 1, 2, 20, false);
    group
        .subscriber
        .coherent_barrier()
        .pump_wire_history_for_test();
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 1);
    source_packet(&group, 1, 1, 2, 20, false);
    assert_eq!(
        group.readers[0].get_sample_lost_status().total_count,
        1,
        "duplicate of an already expired entry reported another loss"
    );
    assert!(
        !group.credits[0].awaits(&writer_b, 1),
        "actual expired receipt was never owned"
    );
    group
        .registry
        .register_writer_lifespan_of(&group.topics[1], writer_b, u64::MAX);
    source_packet(&group, 1, 2, 3, 30, false);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "expiry of B2 invented proof that the unknown A1 never comes: {}",
        group
            .subscriber
            .coherent_barrier()
            .diagnostic_wire_for_test(crate::dds::reader::coherent_barrier::publisher_key(
                PREFIX, PUBLISHER
            ),)
    );
    source_packet(&group, 0, 1, 1, 10, false);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 30 }));
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 1);
    group.subscriber.end_access().unwrap();
}

#[test]
fn source_lifespan_omits_the_whole_owned_coherent_unit_and_counts_each_sample_once() {
    let group = lifespan_group(true);
    let mut writer_a = [0; 16];
    writer_a[..12].copy_from_slice(&PREFIX);
    writer_a[12..].copy_from_slice(&WRITERS[0]);
    group
        .registry
        .register_writer_lifespan_of(&group.topics[0], writer_a, 1_000_000_000);
    group.subscriber.begin_access().unwrap();
    source_packet(&group, 1, 1, 2, 20, true);
    source_packet(&group, 0, 1, 1, 10, true);
    group
        .subscriber
        .coherent_barrier()
        .pump_wire_history_for_test();
    assert_eq!(
        group.readers[0].get_sample_lost_status().total_count,
        2,
        "the expired coherent unit did not report exactly its two real DATA samples"
    );
    let digest = crate::protocol::group::group_digest(WRITERS);
    group.close_in_set(0, 2, 3, digest, 1, 1);
    group.close_in_set(1, 2, 3, digest, 1, 1);
    group
        .subscriber
        .coherent_barrier()
        .pump_wire_history_for_test();
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 2);
    assert_eq!(group.readers[0].take().unwrap(), None);
    group
        .registry
        .register_writer_lifespan_of(&group.topics[0], writer_a, u64::MAX);
    source_packet(&group, 0, 3, 4, 40, false);
    source_packet(&group, 1, 3, 5, 50, false);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 40 }));
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 50 }));
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 2);
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_future_ordinary_value_cannot_pin_the_head_coherent_units_history_room() {
    let group = configured_group_with_ack(true, Some(2), true, true, true, true);
    let mut writer_b = [0; 16];
    writer_b[..12].copy_from_slice(&PREFIX);
    writer_b[12..].copy_from_slice(&WRITERS[1]);
    let digest = crate::protocol::group::group_digest(WRITERS);
    group.subscriber.begin_access().unwrap();
    group._sinks[0].on_writer_heartbeat(writer_b, 1);
    group.send(1, 2, 4, 40);
    assert!(
        group.credits[0].awaits(&writer_b, 2),
        "a future ordinary value pinned room needed by an unknown head coherent unit"
    );
    group.send_coherent_part(0, 1, 1, 10, 1, 1);
    group.send_coherent_part(0, 2, 2, 20, 1, 1);
    group.close_in_set(0, 3, 3, digest, 1, 1);
    group.close_in_set(1, 1, 3, digest, 1, 1);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    group.send(1, 2, 4, 40);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 40 }));
    assert!(!group.credits[0].awaits(&writer_b, 2));
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 0);
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_future_coherent_unit_stays_repairable_until_the_head_unit_releases_its_budget() {
    let group = configured_group_with_ack(true, None, true, true, true, true);
    let mut writer_b = [0; 16];
    writer_b[..12].copy_from_slice(&PREFIX);
    writer_b[12..].copy_from_slice(&WRITERS[1]);
    let digest = crate::protocol::group::group_digest(WRITERS);
    group.subscriber.begin_access().unwrap();
    group._sinks[0].on_writer_heartbeat(writer_b, 1);
    group.send_coherent_part(1, 2, 3, 30, 3, 2);
    assert!(
        group.credits[0].awaits(&writer_b, 2),
        "a speculative later coherent unit took acknowledged staging bytes"
    );
    group.send_coherent_part(0, 1, 1, 10, 1, 1);
    group.close_in_set(0, 2, 2, digest, 1, 1);
    group.close_in_set(1, 1, 2, digest, 1, 1);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    group.send_coherent_part(1, 2, 3, 30, 3, 2);
    group.close_in_set(0, 3, 4, digest, 3, 3);
    group.close_in_set(1, 3, 4, digest, 3, 2);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 30 }));
    assert!(!group.credits[0].awaits(&writer_b, 2));
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 0);
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_later_topic_unit_cannot_use_its_local_prefix_to_bypass_a_siblings_head_unit() {
    let group = configured_group_with_ack(true, None, false, true, true, true);
    let mut writer_b = [0; 16];
    writer_b[..12].copy_from_slice(&PREFIX);
    writer_b[12..].copy_from_slice(&WRITERS[1]);
    let digest = crate::protocol::group::group_digest(WRITERS);
    group.subscriber.begin_access().unwrap();
    // B's own part of the old unit is empty and truly ended. A's DATA1
    // has not arrived. B's local receive/presentation prefix can advance,
    // but the Subscriber still owes the earlier coherent unit on topic A.
    group.close_in_set(1, 1, 2, digest, 1, 1);
    group.send_coherent_part(1, 2, 3, 30, 3, 2);
    assert!(
        group.credits[1].awaits(&writer_b, 2),
        "a sibling topic's future unit took staging bytes while the head unit was still owed"
    );
    group.send_coherent_part(0, 1, 1, 10, 1, 1);
    group.close_in_set(0, 2, 2, digest, 1, 1);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[1].take().unwrap(), None);
    group.send_coherent_part(1, 2, 3, 30, 3, 2);
    group.close_in_set(0, 3, 4, digest, 3, 3);
    group.close_in_set(1, 3, 4, digest, 3, 2);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[1].take().unwrap(), Some(Value { value: 30 }));
    assert!(!group.credits[1].awaits(&writer_b, 2));
    for reader in &group.readers {
        assert_eq!(reader.get_sample_lost_status().total_count, 0);
    }
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_control_callback_cannot_acknowledge_provisionally_refused_coherent_data() {
    let group = configured_group_with_ack(true, Some(1), true, true, true, true);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    group.subscriber.begin_access().unwrap();
    group.send_coherent_part(0, 1, 1, 10, 1, 1);
    let weak = Arc::downgrade(&group._sinks[0]);
    let credit = group.credits[0].clone();
    *group._sinks[0]
        .refusal_entry_hook
        .lock()
        .expect("test state mutex") = Some(Box::new(move || {
        weak.upgrade().unwrap().on_writer_non_data(writer, 2);
        assert!(
            credit.awaits(&writer, 2),
            "a control callback credited another callback's refused provisional DATA"
        );
    }));
    group.send_coherent_part(0, 2, 2, 20, 1, 1);
    assert!(group.credits[0].awaits(&writer, 2));
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_duplicate_of_completed_coherent_admission_still_credits_a_fresh_proxy() {
    let group = configured_group_with_ack(true, None, true, true, true, true);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    group.subscriber.begin_access().unwrap();
    group.send_coherent_part(0, 1, 1, 10, 1, 1);
    let bytes = group._sinks[0].staging.used();
    group.credits[0].unmatch_writer(&writer);
    group.credits[0].match_writer(writer);
    assert!(group.credits[0].awaits(&writer, 1));
    group.send_coherent_part(0, 1, 1, 10, 1, 1);
    assert!(
        !group.credits[0].awaits(&writer, 1),
        "an already owned coherent DATA was left uncredited after proxy replacement"
    );
    assert_eq!(group._sinks[0].staging.used(), bytes);
    group.subscriber.end_access().unwrap();
}

#[test]
fn reclaiming_best_effort_staging_reports_each_previously_owned_data_once() {
    let group = configured_group_in_mode(true, None, true, false);
    group.subscriber.begin_access().unwrap();
    group.send_coherent_part(0, 1, 1, 10, 1, 1);
    group._sinks[0].reject_group_set_for_test((PREFIX, PUBLISHER, 1));
    assert_eq!(
        group.readers[0].get_sample_lost_status().total_count,
        1,
        "reclaimed owned coherent DATA was abandoned without SAMPLE_LOST"
    );
    group._sinks[0].reject_group_set_for_test((PREFIX, PUBLISHER, 1));
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 1);
    assert_eq!(group.readers[0].take().unwrap(), None);
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_late_real_ordinary_copy_after_absence_proof_reports_one_loss_then_acks_duplicates() {
    let group = configured_group_with_ack(false, None, true, true, true, true);
    let mut writer_a = [0; 16];
    writer_a[..12].copy_from_slice(&PREFIX);
    writer_a[12..].copy_from_slice(&WRITERS[0]);
    group.subscriber.begin_access().unwrap();
    group.send(1, 1, 2, 20);
    group.heartbeat(0, [3, 3, 2], None);
    group.heartbeat(1, [3, 2, 2], None);
    group.gap(0, 1, 2);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    assert_eq!(
        group.readers[0].get_sample_lost_status().total_count,
        0,
        "an unknown GSN hole was counted before any real missing sample was identified"
    );
    // GAP proof has ended the legitimate order wait. A real late copy must
    // report its abandonment once and receive credit: further repair cannot
    // restore the order position already passed. Temporary refusals while
    // that wait is still legitimate remain uncredited in the pressure tests.
    assert!(
        group.credits[0].awaits(&writer_a, 1),
        "an order proof alone must not fabricate receipt of an unknown real sample"
    );
    for _ in 0..2 {
        group.send(0, 1, 1, 10);
        assert_eq!(
            group.readers[0].get_sample_lost_status().total_count,
            1,
            "a real abandoned late copy must be counted exactly once"
        );
        assert!(
            !group.credits[0].awaits(&writer_a, 1),
            "proven abandonment must credit a real late copy instead of requesting futile repair"
        );
        assert_eq!(group.readers[0].take().unwrap(), None);
    }
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_late_real_coherent_copy_after_absence_proof_reports_one_loss_then_acks_duplicates() {
    let group = configured_group_with_ack(true, None, true, true, true, true);
    let mut writer_a = [0; 16];
    writer_a[..12].copy_from_slice(&PREFIX);
    writer_a[12..].copy_from_slice(&WRITERS[0]);
    group.subscriber.begin_access().unwrap();
    group.heartbeat(0, [4, 4, 3], None);
    group.heartbeat(1, [4, 3, 3], None);
    group.gap(0, 1, 3);
    group.gap(1, 1, 3);
    group.send(1, 1, 3, 30);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 30 }));
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 0);
    // The proof has already made this unit unavailable. Its real late member
    // is lost once and credited, including repeats; it is not a repairable
    // resource refusal during a legitimate ordered wait.
    assert!(
        group.credits[0].awaits(&writer_a, 1),
        "an order proof alone must not fabricate receipt of an unknown real member"
    );
    for _ in 0..2 {
        group.send_coherent_part(0, 1, 1, 10, 1, 1);
        assert_eq!(
            group.readers[0].get_sample_lost_status().total_count,
            1,
            "stale coherent DATA was silently abandoned or counted twice"
        );
        assert!(
            !group.credits[0].awaits(&writer_a, 1),
            "proven abandonment must credit a real late member instead of requesting futile repair"
        );
        assert_eq!(group.readers[0].take().unwrap(), None);
    }
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_departure_before_coherent_credit_counts_the_identified_sample_once() {
    let group = configured_group_with_ack(true, None, true, true, true, true);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    group.credits[0].answer_heartbeat(
        &writer,
        &crate::core::reader::HeartbeatSeen {
            first_seq: 1,
            last_seq: 1,
            count: 1,
            final_flag: false,
        },
    );
    let registry = group.registry.clone();
    *group._sinks[0].hold_hook.lock().expect("test state mutex") = Some(Box::new(move || {
        registry.notify_writer_departure(
            writer,
            crate::engine::DisposeKind::Unregistered,
            crate::engine::WriterDeparture::Deleted,
        );
    }));
    group.subscriber.begin_access().unwrap();
    group.send_coherent_part(0, 1, 1, 10, 1, 1);
    group
        .subscriber
        .coherent_barrier()
        .pump_wire_history_for_test();
    assert_eq!(
        group.readers[0].get_sample_lost_status().total_count,
        1,
        "proxy-owed and prepared ownership reported the same identified SN twice"
    );
    assert_eq!(group.readers[0].take().unwrap(), None);
    group.subscriber.end_access().unwrap();
}

#[test]
fn an_old_owned_expiry_cannot_suppress_a_replacement_writers_same_sn_loss() {
    let group = lifespan_group(false);
    let clock = Arc::new(crate::dds::liveliness::ManualClock::new(0));
    let barrier = group.subscriber.coherent_barrier();
    barrier.set_wire_clock_for_test(clock.clone());
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    let now = crate::telemetry::metrics::current_time_ns();
    group
        .registry
        .register_writer_lifespan_of(&group.topics[0], writer, now);
    group.subscriber.begin_access().unwrap();
    source_packet(&group, 0, 1, 2, 20, false);
    group.registry.notify_writer_departure(
        writer,
        crate::engine::DisposeKind::Unregistered,
        crate::engine::WriterDeparture::Deleted,
    );
    assert_eq!(
        group.readers[0].get_sample_lost_status().total_count,
        0,
        "received ordinary DATA was purged merely because its writer departed"
    );
    group
        .registry
        .register_writer_guid(writer, group.topics[0].clone());
    group
        .registry
        .register_writer_ownership_kind(writer, crate::qos::ownership::OwnershipKind::Shared);
    group
        .registry
        .register_writer_partition(writer, crate::qos::partition::Partition::default());
    group.registry.record_writer_group_dialect(
        writer,
        crate::protocol::group::GroupDialect::Spec,
        Some(PUBLISHER),
    );
    group.registry.register_writer_lifespan_of(
        &group.topics[0],
        writer,
        crate::telemetry::metrics::current_time_ns() + 10_000_000_000,
    );
    group.credits[0].match_writer(writer);
    group._sinks[0].on_writer_qos_resolved(writer);
    source_packet(&group, 0, 1, 3, 30, false);
    assert!(!group.credits[0].awaits(&writer, 1));
    clock.advance(std::time::Duration::from_secs(2));
    barrier.pump_wire_history_for_test();
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 1);
    clock.advance(std::time::Duration::from_secs(10));
    barrier.pump_wire_history_for_test();
    assert_eq!(
        group.readers[0].get_sample_lost_status().total_count,
        2,
        "old owned SN1 polluted the replacement incarnation's SN1 loss record"
    );
    assert_eq!(group.readers[0].take().unwrap(), None);
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_confirmed_unheard_continuation_keeps_its_previous_sample_loss_deduplication() {
    let group = configured_group_with_ack(false, None, true, true, true, true);
    let mut writer_a = [0; 16];
    writer_a[..12].copy_from_slice(&PREFIX);
    writer_a[12..].copy_from_slice(&WRITERS[0]);
    group.subscriber.begin_access().unwrap();
    group.send(0, 1, 1, 10);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    group.credits[0].answer_heartbeat(
        &writer_a,
        &crate::core::reader::HeartbeatSeen {
            first_seq: 1,
            last_seq: 2,
            count: 1,
            final_flag: false,
        },
    );
    group.send(1, 1, 3, 30);
    group.heartbeat(0, [4, 1, 2], None);
    group.heartbeat(1, [4, 3, 3], None);
    group.registry.notify_writer_departure(
        writer_a,
        crate::engine::DisposeKind::Unregistered,
        crate::engine::WriterDeparture::Unheard,
    );
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 1);
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 30 }));
    group.credits[0].match_writer(writer_a);
    group._sinks[0].on_writer_qos_resolved(writer_a);
    group._sinks[0].on_writer_heartbeat_range(writer_a, 1, 2);
    group.send(0, 2, 2, 20);
    group.send(0, 2, 2, 20);
    assert_eq!(
        group.readers[0].get_sample_lost_status().total_count,
        1,
        "a confirmed same-writer continuation counted an already abandoned SN again"
    );
    assert!(!group.credits[0].awaits(&writer_a, 2));
    assert_eq!(group.readers[0].take().unwrap(), None);
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_valid_group_heartbeat_revokes_unheard_absence_before_presentation() {
    let group = lifespan_group(false);
    let mut writer_a = [0; 16];
    writer_a[..12].copy_from_slice(&PREFIX);
    writer_a[12..].copy_from_slice(&WRITERS[0]);
    let mut writer_b = writer_a;
    writer_b[12..].copy_from_slice(&WRITERS[1]);
    let entity_c = [0, 0, 0x13, 2];
    let mut writer_c = writer_a;
    writer_c[12..].copy_from_slice(&entity_c);
    group
        .registry
        .register_writer_guid(writer_c, group.topics[0].clone());
    group
        .registry
        .register_writer_ownership_kind(writer_c, crate::qos::ownership::OwnershipKind::Shared);
    group
        .registry
        .register_writer_partition(writer_c, crate::qos::partition::Partition::default());
    group.registry.record_writer_group_dialect(
        writer_c,
        crate::protocol::group::GroupDialect::Spec,
        Some(PUBLISHER),
    );
    group.credits[0].match_writer(writer_c);
    group
        .roster
        .lock()
        .expect("test state mutex")
        .push(entity_c);
    group
        .subscriber
        .coherent_barrier()
        .register_matched_writer(group._sinks[0].barrier_member_for_test().unwrap(), writer_c);
    let digest = crate::protocol::group::group_digest([WRITERS[0], WRITERS[1], entity_c]);
    let witness = group
        .registry
        .group_writer_terminal(&writer_a, PUBLISHER)
        .unwrap();
    group.subscriber.begin_access().unwrap();
    // C's unresolved prefix prevents committing A's temporary absence.
    source_packet_in_epoch(&group, 1, 1, 2, 20, false, digest);
    group.registry.notify_writer_departure(
        writer_a,
        crate::engine::DisposeKind::Unregistered,
        crate::engine::WriterDeparture::Unheard,
    );
    assert!(witness.is_departed());
    // The real control door sends the WriterSN heartbeat between the
    // GroupInfo announcement and its final roster notification.
    group.credits[0].match_writer(writer_a);
    group._sinks[0].on_writer_group_heartbeat(writer_a, 3, 1, 1);
    group._sinks[0].on_writer_heartbeat_range(writer_a, 1, 1);
    group._sinks[0].on_writer_group_heartbeat_roster(
        writer_a,
        [3, 1, 1],
        Some((PUBLISHER, digest)),
    );
    assert!(
        !witness.is_departed(),
        "accepted retained-range heartbeat left stale absence proof active"
    );
    group.registry.notify_writer_departure(
        writer_c,
        crate::engine::DisposeKind::Unregistered,
        crate::engine::WriterDeparture::Deleted,
    );
    group.registry.notify_writer_departure(
        writer_b,
        crate::engine::DisposeKind::Unregistered,
        crate::engine::WriterDeparture::Deleted,
    );
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(
        group.readers[0].take().unwrap(),
        None,
        "a stale lease proof skipped a writer that just advertised its retained predecessor"
    );
    group.credits[0].match_writer(writer_a);
    group._sinks[0].on_writer_qos_resolved(writer_a);
    group._sinks[0].on_writer_heartbeat_range(writer_a, 1, 1);
    source_packet_in_epoch(&group, 0, 1, 1, 10, false, digest);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    group.subscriber.end_access().unwrap();
}

#[test]
fn an_old_control_timestamp_does_not_expire_a_coherent_data_unit() {
    let group = lifespan_group(true);
    let mut writer_a = [0; 16];
    writer_a[..12].copy_from_slice(&PREFIX);
    writer_a[12..].copy_from_slice(&WRITERS[0]);
    group
        .registry
        .register_writer_lifespan_of(&group.topics[0], writer_a, 1_000_000_000);
    let context = RtpsEndpointContext {
        guid_prefix: PREFIX,
        reader_entity_id: [0; 4],
        writer_entity_id: WRITERS[0],
        encapsulation_kind: 0x0007,
        publisher_entity_id: PUBLISHER,
    };
    let digest = crate::protocol::group::group_digest(WRITERS);
    let tag = crate::protocol::group::GroupTag {
        gsn: 1,
        writer_set: digest,
        set_first_gsn: Some(1),
        part_first_sn: None,
    };
    let control = builder::build_dispose_packet_with_context_coherent_ts(
        &context,
        &group.topics[0],
        1,
        &[0; 16],
        &[],
        builder::StatusInfoKind::Unregistered,
        CdrVersion::Xcdr2,
        (1, 0),
        Some(1),
        Some(1),
        Some(&tag),
        false,
    );
    group.subscriber.begin_access().unwrap();
    source_packet(&group, 1, 1, 2, 20, true);
    route_data_packet(
        &control,
        control.len(),
        None,
        &group.registry,
        &RouterMetrics::new(),
    );
    group
        .subscriber
        .coherent_barrier()
        .pump_wire_history_for_test();
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 0);
    group.close_in_set(0, 2, 3, digest, 1, 1);
    group.close_in_set(1, 2, 3, digest, 1, 1);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 0);
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_prepared_sample_counts_after_departure_before_claim_without_a_prior_heartbeat() {
    let group = configured_group_with_ack(true, None, true, true, true, true);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    let registry = group.registry.clone();
    *group._sinks[0]
        .wire_claim_hook
        .lock()
        .expect("test state mutex") = Some(Box::new(move || {
        registry.notify_writer_departure(
            writer,
            crate::engine::DisposeKind::Unregistered,
            crate::engine::WriterDeparture::Deleted,
        );
    }));
    group.subscriber.begin_access().unwrap();
    group.send_coherent_part(0, 1, 1, 10, 1, 1);
    assert_eq!(
        group.readers[0].get_sample_lost_status().total_count,
        1,
        "actual prepared DATA vanished between empty proxy debt and claim publication"
    );
    assert_eq!(group.readers[0].take().unwrap(), None);
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_real_late_member_of_an_expired_unit_is_counted_and_credited_without_storage() {
    let group = lifespan_group(true);
    let mut writer_a = [0; 16];
    writer_a[..12].copy_from_slice(&PREFIX);
    writer_a[12..].copy_from_slice(&WRITERS[0]);
    let mut writer_b = writer_a;
    writer_b[12..].copy_from_slice(&WRITERS[1]);
    group
        .registry
        .register_writer_lifespan_of(&group.topics[0], writer_a, 1_000_000_000);
    group.subscriber.begin_access().unwrap();
    source_packet(&group, 0, 1, 1, 10, true);
    group
        .subscriber
        .coherent_barrier()
        .pump_wire_history_for_test();
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 1);
    let bytes = group._sinks[0].staging.used();
    // Source-time LIFESPAN has abandoned the unit. A later real member is
    // therefore lost once and credited, rather than kept in futile repair;
    // this is distinct from refusing a still-repairable member for capacity.
    assert!(
        group.credits[0].awaits(&writer_b, 1),
        "unit expiry alone must not fabricate receipt of an unknown member"
    );
    for _ in 0..2 {
        source_packet(&group, 1, 1, 2, 20, true);
        assert_eq!(
            group.readers[0].get_sample_lost_status().total_count,
            2,
            "late real DATA of an irreparable unit was not counted exactly once"
        );
        assert!(
            !group.credits[0].awaits(&writer_b, 1),
            "a real copy of a proven lost unit remained needlessly repairable"
        );
        assert!(
            group._sinks[0].staging.used() <= bytes,
            "a lost unit allocated new payload storage"
        );
        let member = group._sinks[0].barrier_member_for_test().unwrap();
        let key = crate::dds::reader::coherent_barrier::publisher_key(PREFIX, PUBLISHER);
        assert!(
            group
                .subscriber
                .coherent_barrier()
                .wire_loss_marker_counts_for_test(member, key)
                .0
                <= 1,
            "a duplicate created another uncharged loss marker"
        );
        assert_eq!(group.readers[0].take().unwrap(), None);
    }
    let digest = crate::protocol::group::group_digest(WRITERS);
    group.close_in_set(0, 2, 3, digest, 1, 1);
    group.close_in_set(1, 2, 3, digest, 1, 1);
    group
        .registry
        .register_writer_lifespan_of(&group.topics[0], writer_a, u64::MAX);
    source_packet(&group, 0, 3, 4, 40, false);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    let key = crate::dds::reader::coherent_barrier::publisher_key(PREFIX, PUBLISHER);
    assert_eq!(
        group.readers[0].take().unwrap(),
        Some(Value { value: 40 }),
        "{}; {}",
        group
            .subscriber
            .coherent_barrier()
            .diagnostic_wire_for_test(key),
        group
            .subscriber
            .coherent_barrier()
            .diagnostic_alignment_for_test(key)
    );
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 2);
    group.subscriber.end_access().unwrap();
}
#[test]
fn a_first_real_late_copy_is_counted_after_an_unannounced_writer_gap() {
    let group = configured_group_with_ack(false, None, true, true, true, true);
    let mut writer_a = [0; 16];
    writer_a[..12].copy_from_slice(&PREFIX);
    writer_a[12..].copy_from_slice(&WRITERS[0]);
    group.subscriber.begin_access().unwrap();
    group.registry.notify_writer_gap(writer_a, 1, 2, vec![1]);
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 0);
    group.send(1, 1, 2, 20);
    group.heartbeat(0, [3, 3, 2], None);
    group.heartbeat(1, [3, 2, 2], None);
    group.gap(0, 1, 2);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    for _ in 0..2 {
        group.send(0, 1, 1, 10);
        assert_eq!(
            group.readers[0].get_sample_lost_status().total_count,
            1,
            "irrelevant without an owed sample was confused with an already counted loss"
        );
        assert_eq!(group.readers[0].take().unwrap(), None);
    }
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_same_publisher_reannouncement_rejects_only_the_stale_admission_then_repairs() {
    let group = lifespan_group(false);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    let registry = group.registry.clone();
    *group._sinks[0]
        .wire_claim_hook
        .lock()
        .expect("test state mutex") = Some(Box::new(move || {
        registry.record_writer_group_dialect(
            writer,
            crate::protocol::group::GroupDialect::Spec,
            Some(PUBLISHER),
        );
    }));
    group.subscriber.begin_access().unwrap();
    source_packet(&group, 0, 1, 1, 10, false);
    assert!(
        group.credits[0].awaits(&writer, 1),
        "a stale availability stamp credited a rejected admission"
    );
    assert_eq!(
        group.readers[0].get_sample_lost_status().total_count,
        0,
        "a same-publisher announcement was mistaken for a loss proof"
    );
    source_packet(&group, 0, 1, 1, 10, false);
    assert!(!group.credits[0].awaits(&writer, 1));
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 10 }));
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 0);
    group.subscriber.end_access().unwrap();
}

#[test]
fn an_announced_writer_gap_and_its_late_copy_report_one_loss() {
    let group = configured_group_with_ack(false, None, true, true, true, true);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    let _ = group.credits[0].answer_heartbeat(
        &writer,
        &crate::core::reader::HeartbeatSeen {
            first_seq: 1,
            last_seq: 1,
            count: 1,
            final_flag: false,
        },
    );
    group._sinks[0].on_writer_heartbeat(writer, 1);
    group.subscriber.begin_access().unwrap();
    group.registry.notify_writer_gap(writer, 1, 2, vec![1]);
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 1);
    group.send(1, 1, 2, 20);
    group.heartbeat(0, [3, 3, 2], None);
    group.heartbeat(1, [3, 2, 2], None);
    group.gap(0, 1, 2);
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), Some(Value { value: 20 }));
    for _ in 0..2 {
        group.send(0, 1, 1, 10);
        assert_eq!(
            group.readers[0].get_sample_lost_status().total_count,
            1,
            "known owed loss was counted again after actual late receipt"
        );
        assert_eq!(group.readers[0].take().unwrap(), None);
    }
    group.subscriber.end_access().unwrap();
}

fn late_unknown_gap_after_a_full_duplicate_window(depart_before_claim: bool) {
    let group = configured_group_with_ack(false, None, true, true, true, true);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    group.registry.notify_writer_gap(writer, 1, 2, vec![1]);
    for seq in 2..=4200 {
        group.subscriber.begin_access().unwrap();
        group.send(0, seq, seq, i32::try_from(seq).unwrap());
        if seq == 2 {
            group.heartbeat(1, [3, 3, 2], None);
            group.gap(0, 1, 2);
        }
        group.subscriber.end_access().unwrap();
        group.subscriber.begin_access().unwrap();
        assert_eq!(
            group.readers[0].take().unwrap(),
            Some(Value {
                value: i32::try_from(seq).unwrap()
            })
        );
        group.subscriber.end_access().unwrap();
    }
    let _ = group.credits[0].answer_heartbeat(
        &writer,
        &crate::core::reader::HeartbeatSeen {
            first_seq: 2,
            last_seq: 4200,
            count: 1,
            final_flag: false,
        },
    );
    if depart_before_claim {
        let registry = group.registry.clone();
        *group._sinks[0]
            .admission_hook
            .lock()
            .expect("test state mutex") = Some(Box::new(move || {
            registry.notify_writer_departure(
                writer,
                crate::engine::DisposeKind::Unregistered,
                crate::engine::WriterDeparture::Deleted,
            );
        }));
    }
    group.subscriber.begin_access().unwrap();
    group.send(0, 1, 1, 10);
    assert_eq!(
        group.readers[0].get_sample_lost_status().total_count,
        1,
        "a native prefix erased the first real loss of an old uncounted hole"
    );
    assert_eq!(group.readers[0].take().unwrap(), None);
    group.subscriber.end_access().unwrap();
}

#[test]
fn a_first_late_loss_survives_a_full_duplicate_window_and_native_irrelevance() {
    late_unknown_gap_after_a_full_duplicate_window(false);
}

#[test]
fn a_prepared_old_hole_survives_departure_after_a_full_duplicate_window() {
    late_unknown_gap_after_a_full_duplicate_window(true);
}

#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct HistoryBoundSample {
    #[key]
    id: i32,
    value: i32,
}

#[test]
fn an_acknowledged_ordered_group_unit_keeps_its_bytes_when_history_cannot_hold_it() {
    let mut qos = QoS::reliable().keep_all();
    qos.presentation.access_scope = crate::dds::qos::PresentationAccessScope::Group;
    qos.presentation.coherent_access = true;
    qos.presentation.ordered_access = true;
    qos.resource_limits.max_instances = 1;
    let participant = crate::Participant::builder("wire-history-bound")
        .with_transport(crate::TransportMode::IntraProcess)
        .build()
        .unwrap();
    let subscriber = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
    let registry = Arc::new(TopicRegistry::new());
    let topic = "wire-history-bound";
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    registry.register_writer_guid(writer, topic.to_string());
    registry.register_writer_ownership_kind(writer, crate::qos::ownership::OwnershipKind::Shared);
    registry.register_writer_partition(writer, crate::qos::partition::Partition::default());
    registry.record_writer_group_dialect(
        writer,
        crate::protocol::group::GroupDialect::Spec,
        Some(PUBLISHER),
    );
    let credit = crate::core::reader::ReaderAckCredit::new(
        crate::core::reader::ReaderProxyRegistry::new(),
        [0xC2; 16],
    );
    credit.match_writer(writer);
    let reader = ReaderBuilder::<HistoryBoundSample>::new(topic.to_string())
        .qos(qos)
        .subscriber(&subscriber)
        .with_registry(registry.clone())
        .network_ring_for_test()
        .with_ack_credit_for_test(credit.clone())
        .build()
        .unwrap();
    let sink = reader.subscriber_weak_for_test().upgrade().unwrap();
    assert!(sink
        .group_roster
        .set(Arc::new(Roster {
            hook: Default::default(),
            writer: 0,
            all: true,
            dust: false,
            entities: Arc::new(Mutex::new(vec![WRITERS[0]])),
            ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            registry: Arc::downgrade(&registry),
        }))
        .is_ok());
    let member = sink.barrier_member_for_test().unwrap();
    subscriber
        .coherent_barrier()
        .attach_resolver(member, Arc::new(|_| Some(PUBLISHER)));
    subscriber
        .coherent_barrier()
        .register_matched_writer(member, writer);
    let context = RtpsEndpointContext {
        guid_prefix: PREFIX,
        reader_entity_id: [0; 4],
        writer_entity_id: WRITERS[0],
        encapsulation_kind: 0x0007,
        publisher_entity_id: PUBLISHER,
    };
    let digest = crate::protocol::group::group_digest([WRITERS[0]]);
    let send = |seq: u64, id: i32, coherent: bool| {
        let mut bytes = [0; 64];
        let len = HistoryBoundSample { id, value: id * 10 }
            .encode(&mut bytes, CdrVersion::Xcdr2)
            .unwrap();
        let tag = crate::protocol::group::GroupTag {
            gsn: seq,
            writer_set: digest,
            set_first_gsn: coherent.then_some(1),
            part_first_sn: None,
        };
        let packet = builder::build_data_packet_grouped_ts(
            &context,
            topic,
            seq,
            &bytes[..len],
            CdrVersion::Xcdr2,
            (0, 0),
            coherent.then_some(1),
            coherent.then_some(1),
            Some(&tag),
            None,
            false,
        );
        route_data_packet(
            &packet,
            packet.len(),
            None,
            &registry,
            &RouterMetrics::new(),
        );
    };
    subscriber.begin_access().unwrap();
    send(1, 1, true);
    send(2, 2, true);
    assert!(
        !credit.awaits(&writer, 1),
        "first real member was not admitted"
    );
    assert!(
        !credit.awaits(&writer, 2),
        "second real member was not admitted"
    );
    let held = sink.staging.used();
    assert!(held > 0 && held <= sink.staging.set_limit());
    let tag = crate::protocol::group::GroupTag {
        gsn: 3,
        writer_set: digest,
        set_first_gsn: Some(1),
        part_first_sn: Some(1),
    };
    let end = builder::build_ecs_spec_ts(&context, topic, 3, &tag, (0, 0));
    route_data_packet(&end, end.len(), None, &registry, &RouterMetrics::new());
    assert!(
        !credit.awaits(&writer, 3),
        "actual ECS receipt was not credited"
    );
    for _ in 0..8 {
        subscriber.end_access().unwrap();
        subscriber.begin_access().unwrap();
        assert_eq!(
            reader.take().unwrap(),
            None,
            "history exposed a partial unit"
        );
        assert_eq!(
            sink.staging.used(),
            held,
            "a history bound discarded already acknowledged bytes"
        );
        assert_eq!(reader.get_sample_lost_status().total_count, 0);
        assert_eq!(reader.get_sample_rejected_status().total_count, 0);
    }
    send(4, 1, false);
    assert!(
        credit.awaits(&writer, 4),
        "a successor passed an owned unit"
    );
    subscriber.end_access().unwrap();
    subscriber.begin_access().unwrap();
    assert_eq!(
        reader.take().unwrap(),
        None,
        "a successor bypassed the whole unit"
    );
    assert_eq!(sink.staging.used(), held);
    subscriber.end_access().unwrap();
}
