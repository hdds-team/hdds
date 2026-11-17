// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::engine::Subscriber as _;

#[test]
fn a_sampleless_change_cannot_credit_or_close_a_provisional_coherent_member() {
    use std::sync::atomic::{AtomicBool, Ordering};

    // KEEP_ALL has accepted the first member. Its second member remains
    // repairable while the intact unit legitimately waits for room.
    let group = configured_group_with_ack(true, Some(1), true, true, true, true);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    group.subscriber.begin_access().unwrap();
    group.send_coherent_part(0, 1, 1, 10, 1, 1);
    let retained = group._sinks[0].staging.used();
    let checked = Arc::new(AtomicBool::new(false));
    let observed = checked.clone();
    let weak = Arc::downgrade(&group._sinks[0]);
    let credit = group.credits[0].clone();
    *group._sinks[0]
        .refusal_entry_hook
        .lock()
        .expect("test state mutex") = Some(Box::new(move || {
        let sink = weak.upgrade().unwrap();
        observed.store(true, Ordering::Release);
        sink.on_change_without_sample(writer, 2);
        assert!(
            credit.awaits(&writer, 2),
            "a sampleless callback acknowledged DATA still awaiting admission"
        );
        assert!(
            !sink
                .pending_coherent_end
                .lock()
                .expect("set ends mutex")
                .contains_key(&writer),
            "a refused sampleless change was recorded as a coherent-set end"
        );
    }));
    group.send_coherent_part(0, 2, 2, 20, 1, 1);
    assert!(
        checked.load(Ordering::Acquire),
        "refusal schedule did not run"
    );
    assert!(
        group.credits[0].awaits(&writer, 2),
        "sampleless delivery credited a member still requiring repair"
    );
    assert_eq!(group._sinks[0].staging.used(), retained);
    for reader in &group.readers {
        assert_eq!(reader.take().unwrap(), None);
        assert_eq!(reader.get_sample_lost_status().total_count, 0);
    }
    group.subscriber.end_access().unwrap();
}

fn registration(group: &Group, seq: u64) {
    let context = RtpsEndpointContext {
        guid_prefix: PREFIX,
        reader_entity_id: [0; 4],
        writer_entity_id: WRITERS[0],
        encapsulation_kind: 0x0007,
        publisher_entity_id: PUBLISHER,
    };
    let tag = crate::protocol::group::GroupTag {
        gsn: seq,
        writer_set: crate::protocol::group::group_digest(WRITERS),
        set_first_gsn: None,
        part_first_sn: None,
    };
    let mut packet = builder::build_data_packet_grouped_ts(
        &context,
        &group.topics[0],
        seq,
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
    route_data_packet(
        &packet,
        packet.len(),
        None,
        &group.registry,
        &RouterMetrics::new(),
    );
}

#[test]
fn long_runs_of_received_controls_do_not_fill_sample_loss_history() {
    let group = configured_group_with_ack(false, None, true, true, true, true);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    const UNITS: u64 = 8192;
    // The final DATA is retained initially but never reaches this reader.
    group._sinks[0].on_writer_heartbeat_range(writer, 1, 2 * UNITS + 1);
    let _ = group.credits[0].answer_heartbeat(
        &writer,
        &crate::core::reader::HeartbeatSeen {
            first_seq: 1,
            last_seq: i64::try_from(2 * UNITS + 1).unwrap(),
            count: 1,
            final_flag: false,
        },
    );
    for unit in 0..UNITS {
        let seq = 2 * unit + 1;
        let value = i32::try_from(unit).unwrap();
        group.send(0, seq, seq, value);
        registration(&group, seq + 1);
        assert!(
            !group.credits[0].awaits(&writer, seq + 1),
            "received control at WriterSN {} remained unacknowledged",
            seq + 1
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            group.subscriber.begin_access().unwrap();
            let sample = group.readers[0].take().unwrap();
            group.subscriber.end_access().unwrap();
            if let Some(sample) = sample {
                assert_eq!(sample, Value { value });
                break;
            }
            assert!(std::time::Instant::now() < deadline, "DATA {seq} stalled");
            std::thread::yield_now();
        }
    }
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 0);
    // Only the one announced, unreceived DATA became unavailable.
    group._sinks[0].on_writer_heartbeat_range(writer, 2 * UNITS + 2, 2 * UNITS + 1);
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 1);
    registration(&group, 2);
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 1);
}

fn prepared_data_departure(announced: bool) {
    let group = configured_group_with_ack(false, None, true, true, true, true);
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    if announced {
        group._sinks[0].on_writer_heartbeat_range(writer, 1, 1);
        let _ = group.credits[0].answer_heartbeat(
            &writer,
            &crate::core::reader::HeartbeatSeen {
                first_seq: 1,
                last_seq: 1,
                count: 1,
                final_flag: false,
            },
        );
    }
    let registry = group.registry.clone();
    *group._sinks[0]
        .admission_hook
        .lock()
        .expect("test state mutex") = Some(Box::new(move || {
        registry.notify_writer_departure(
            writer,
            crate::engine::subscriber::DisposeKind::Unregistered,
            crate::engine::subscriber::WriterDeparture::Unheard,
        );
    }));
    group.send(0, 1, 1, 10);
    assert_eq!(
        group.readers[0].get_sample_lost_status().total_count,
        1,
        "a prepared real sample abandoned by departure was not counted"
    );
    group.subscriber.begin_access().unwrap();
    assert_eq!(group.readers[0].take().unwrap(), None);
    group.subscriber.end_access().unwrap();
}

#[test]
fn prepared_data_lost_at_the_admission_door_is_reported_without_a_heartbeat() {
    prepared_data_departure(false);
}

#[test]
fn prepared_data_with_announced_debt_is_not_counted_twice_at_departure() {
    prepared_data_departure(true);
}

#[test]
fn closed_coherent_controls_do_not_accumulate_unclassified_sample_holes() {
    let group = configured_group_with_ack(true, None, true, true, true, true);
    let guid = |entity: [u8; 4]| {
        let mut guid = [0; 16];
        guid[..12].copy_from_slice(&PREFIX);
        guid[12..].copy_from_slice(&entity);
        guid
    };
    // Only A remains a DataWriter of this Publisher before its first write.
    group.registry.notify_writer_departure(
        guid(WRITERS[1]),
        crate::engine::DisposeKind::Unregistered,
        crate::engine::WriterDeparture::Deleted,
    );
    *group.roster.lock().expect("test roster mutex") = vec![WRITERS[0]];
    let writer = guid(WRITERS[0]);
    let digest = crate::protocol::group::group_digest([WRITERS[0]]);
    let context = RtpsEndpointContext {
        guid_prefix: PREFIX,
        reader_entity_id: [0; 4],
        writer_entity_id: WRITERS[0],
        encapsulation_kind: 0x0007,
        publisher_entity_id: PUBLISHER,
    };
    const UNITS: u64 = 6400;
    group._sinks[0].on_writer_heartbeat_range(writer, 1, 2 * UNITS + 1);
    let _ = group.credits[0].answer_heartbeat(
        &writer,
        &crate::core::reader::HeartbeatSeen {
            first_seq: 1,
            last_seq: i64::try_from(2 * UNITS + 1).unwrap(),
            count: 1,
            final_flag: false,
        },
    );
    for unit in 0..UNITS {
        let seq = 2 * unit + 1;
        let value = i32::try_from(unit).unwrap();
        let mut bytes = [0; 64];
        let len = Value { value }
            .encode(&mut bytes, CdrVersion::Xcdr2)
            .unwrap();
        let tag = crate::protocol::group::GroupTag {
            gsn: seq,
            writer_set: digest,
            set_first_gsn: Some(seq),
            part_first_sn: None,
        };
        let packet = builder::build_data_packet_grouped_ts(
            &context,
            &group.topics[0],
            seq,
            &bytes[..len],
            CdrVersion::Xcdr2,
            (0, 0),
            Some(seq),
            Some(seq),
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
        group.close_in_set(0, seq + 1, seq + 1, digest, seq, seq);
        assert!(!group.credits[0].awaits(&writer, seq + 1));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            group.subscriber.begin_access().unwrap();
            let sample = group.readers[0].take().unwrap();
            group.subscriber.end_access().unwrap();
            if let Some(sample) = sample {
                assert_eq!(sample, Value { value });
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "coherent DATA {seq} stalled"
            );
            std::thread::yield_now();
        }
    }
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 0);
    group._sinks[0].on_writer_heartbeat_range(writer, 2 * UNITS + 2, 2 * UNITS + 1);
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 1);
}

#[test]
fn a_durable_writer_gate_keeps_received_data_when_its_writer_departs() {
    let group = configured_group_for_writer_with_durability(
        false, None, true, true, true, true, None, true,
    );
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[0]);
    group._sinks[0].on_writer_heartbeat_range(writer, 1, 2);
    let _ = group.credits[0].answer_heartbeat(
        &writer,
        &crate::core::reader::HeartbeatSeen {
            first_seq: 1,
            last_seq: 2,
            count: 1,
            final_flag: false,
        },
    );
    group.subscriber.begin_access().unwrap();
    group.send(0, 2, 2, 20);
    assert!(!group.credits[0].awaits(&writer, 2));
    assert_eq!(group.readers[0].take().unwrap(), None);
    // B proves it has no earlier Publisher change while A still lives.
    group.heartbeat(
        1,
        [3, 3, 2],
        Some(crate::protocol::group::group_digest(WRITERS)),
    );
    group.registry.notify_writer_departure(
        writer,
        crate::engine::DisposeKind::Unregistered,
        crate::engine::WriterDeparture::Unheard,
    );
    group.subscriber.end_access().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        group.subscriber.begin_access().unwrap();
        let sample = group.readers[0].take().unwrap();
        group.subscriber.end_access().unwrap();
        if let Some(sample) = sample {
            assert_eq!(sample, Value { value: 20 });
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "received DATA vanished with its writer"
        );
        std::thread::yield_now();
    }
    assert_eq!(group.readers[0].get_sample_lost_status().total_count, 1);
}
