// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A dispose or an unregister is a change with its own sequence number in
//! the writer's history (RTPS 2.5 8.2.3), and a reliable reader only learns
//! that a number exists from the writer's HEARTBEATs, which communicate
//! "the sequence numbers of changes that the Writer has available"
//! (8.3.8.6) and which a reliable writer must keep sending (8.4.2.2). A lost
//! lifecycle change with no later write must therefore still be announced,
//! then NACKed, then repaired.
//!
//! The writer is the real `DataWriter`; the reader is the real reader-side
//! state machine (`ReliableReaderProxy`), fed by hand from the captured
//! datagrams, the dropped one excepted. Every HEARTBEAT is decoded from its
//! bytes here, not with our own parser.

use super::coherent_dispose_tests::{
    build_pair, decode_data_submsg, writer_ctx, CoherentDisposeSample, DATA_SUBMSG_OFFSET,
    OUR_PREFIX, PID_STATUS_INFO, WRITER_EID,
};
use super::heartbeat_scheduler::{spawn_heartbeat_scheduler, HeartbeatPeriodic};
use super::nack::{RetransmitCfg, WriterNackHandler};
use crate::core::reader::{AcknackDecision, ReliableReaderProxy};
use crate::dds::qos::PresentationAccessScope;
use crate::engine::NackHandler;
use crate::reliability::ReliableMetrics;
use std::sync::Arc;
use std::time::Duration;

/// The reader `build_pair` registers: participant prefix 0x46, entity
/// 0x00002004.
const READER_PREFIX: [u8; 12] = [0x46; 12];
const READER_EID: [u8; 4] = [0x00, 0x00, 0x20, 0x04];

/// One HEARTBEAT as read from the wire: (firstSN, lastSN, count).
type Heartbeat = (u64, u64, u32);

/// Every HEARTBEAT submessage of `pkt`, walked by hand (RTPS 2.5 9.4.1,
/// 9.4.5.7): after the 20-octet header, each submessage is id (1), flags
/// (1), octetsToNextHeader (2, in the E flag's order); a HEARTBEAT (0x07)
/// body is readerId (4), writerId (4), firstSN (8), lastSN (8), count (4),
/// each SequenceNumber_t being high:i32 then low:u32.
fn heartbeats_in(pkt: &[u8]) -> Vec<Heartbeat> {
    let mut found = Vec::new();
    let mut at = 20;
    while at + 4 <= pkt.len() {
        let id = pkt[at];
        let le = pkt[at + 1] & 0x01 != 0;
        let u16_at = |b: [u8; 2]| {
            if le {
                u16::from_le_bytes(b)
            } else {
                u16::from_be_bytes(b)
            }
        };
        let u32_at = |i: usize| {
            let b = [pkt[i], pkt[i + 1], pkt[i + 2], pkt[i + 3]];
            if le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };
        let len = usize::from(u16_at([pkt[at + 2], pkt[at + 3]]));
        let body = at + 4;
        if id == 0x07 {
            assert!(body + 28 <= pkt.len(), "HEARTBEAT body truncated");
            let sn = |i: usize| (u64::from(u32_at(i)) << 32) | u64::from(u32_at(i + 4));
            assert_eq!(&pkt[body + 4..body + 8], &WRITER_EID, "writerId");
            found.push((sn(body + 8), sn(body + 16), u32_at(body + 24)));
        }
        if len == 0 {
            break;
        }
        at = body + len;
    }
    found
}

/// Every datagram `sock` receives for `window`. Not `drain`: with the
/// periodic HEARTBEAT thread running, the socket is never quiet.
fn collect(sock: &std::net::UdpSocket, window: Duration) -> Vec<Vec<u8>> {
    sock.set_read_timeout(Some(Duration::from_millis(5)))
        .expect("set timeout");
    let deadline = std::time::Instant::now() + window;
    let mut packets = Vec::new();
    let mut buf = [0u8; 4096];
    while std::time::Instant::now() < deadline {
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            packets.push(buf[..n].to_vec());
        }
    }
    packets
}

fn heartbeats(packets: &[Vec<u8>]) -> Vec<Heartbeat> {
    packets.iter().flat_map(|p| heartbeats_in(p)).collect()
}

/// The writerSN of a DATA submessage, read by hand (RTPS 2.5 9.4.5.3:
/// extraFlags 2, octetsToInlineQos 2, readerId 4, writerId 4, writerSN 8).
fn data_sn(pkt: &[u8]) -> Option<u64> {
    let off = DATA_SUBMSG_OFFSET;
    if pkt.len() < off + 24 || pkt[off] != 0x15 {
        return None;
    }
    let w = |i: usize| u32::from_le_bytes([pkt[i], pkt[i + 1], pkt[i + 2], pkt[i + 3]]);
    Some((u64::from(w(off + 16)) << 32) | u64::from(w(off + 20)))
}

fn writer_guid() -> [u8; 16] {
    let mut guid = [0u8; 16];
    guid[..12].copy_from_slice(&OUR_PREFIX);
    guid[12..].copy_from_slice(&WRITER_EID);
    guid
}

fn reader_guid() -> [u8; 16] {
    let mut guid = [0u8; 16];
    guid[..12].copy_from_slice(&READER_PREFIX);
    guid[12..].copy_from_slice(&READER_EID);
    guid
}

#[derive(Clone, Copy, Debug)]
enum Lifecycle {
    Dispose,
    Unregister,
}

/// Write SN 1, deliver it; make `change` (SN 2) and drop its datagram;
/// write nothing more. The HEARTBEATs that follow must announce SN 2, the
/// reader must NACK it, and the writer's repair must be the lifecycle
/// change. `scheduled`: the writer has its periodic HEARTBEAT thread and
/// the change follows the write at once (inside the on-write HEARTBEAT's
/// period, so only the thread can announce it); otherwise there is no
/// thread and the change comes a period later, so the writer announces it
/// itself, as after a write.
fn a_lost_lifecycle_change_is_announced_and_repaired(change: Lifecycle, scheduled: bool) {
    let topic = format!("test/lifecycle_hb_{change:?}_{scheduled}");
    let participant_id = match (change, scheduled) {
        (Lifecycle::Dispose, true) => 60,
        (Lifecycle::Dispose, false) => 61,
        (Lifecycle::Unregister, true) => 62,
        (Lifecycle::Unregister, false) => 63,
    };
    let (_publisher, mut writer, capture, registry, fsm, _domain) = build_pair(
        &topic,
        participant_id,
        PresentationAccessScope::Topic,
        |qos| qos.transient_local(),
    );
    let transport = writer.transport.clone().expect("a wire writer");
    let cache = writer.history_cache.clone().expect("a reliable history");
    if scheduled {
        writer._heartbeat_scheduler =
            Some(HeartbeatPeriodic::Standalone(spawn_heartbeat_scheduler(
                Arc::clone(&transport),
                Arc::clone(&cache),
                writer_ctx(),
                50,
                topic.clone(),
                Some(Arc::clone(&fsm)),
                Some(registry.clone()),
                None,
            )));
    }

    let mut reader = ReliableReaderProxy::new(writer_guid());
    let sample = CoherentDisposeSample { id: 7, v: 1 };
    writer.write(&sample).expect("write");
    let first = collect(&capture, Duration::from_millis(30));
    assert!(
        first.iter().any(|p| data_sn(p) == Some(1)),
        "SN 1 reaches the reader"
    );
    reader.on_data(1);

    if !scheduled {
        // Past the on-write HEARTBEAT's period (100 ms +/- 10%).
        std::thread::sleep(Duration::from_millis(150));
    }
    match change {
        Lifecycle::Dispose => writer.dispose(&sample).expect("dispose"),
        Lifecycle::Unregister => writer.unregister_instance(&sample).expect("unregister"),
    }
    // The change's datagram is lost: everything but the HEARTBEATs. With
    // the thread, a few of its periods; without, the writer's own.
    let after = collect(
        &capture,
        Duration::from_millis(if scheduled { 250 } else { 50 }),
    );
    assert!(
        after.iter().any(|p| data_sn(p) == Some(2)),
        "the change was sent as SN 2 (then dropped here)"
    );
    let hbs = heartbeats(&after);
    assert!(!hbs.is_empty(), "a HEARTBEAT follows the change");
    let (first_sn, last_sn, count) = *hbs.last().expect("one HEARTBEAT");
    assert_eq!(
        last_sn, 2,
        "lastSN announces the lifecycle change (HEARTBEATs seen: {hbs:?})"
    );
    assert_eq!(first_sn, 1, "firstSN: the whole history is available");

    // The reader's own state machine decides to NACK SN 2.
    let first_i = i64::try_from(first_sn).expect("small");
    let last_i = i64::try_from(last_sn).expect("small");
    let decision = reader.on_heartbeat(first_i, last_i, count, false);
    let AcknackDecision::NeedData { bitmap_base } = decision else {
        panic!("the reader must ask for the change, decided {decision:?}");
    };
    let holes = reader.missing_holes(last_i);
    assert_eq!((bitmap_base, holes.clone()), (2, vec![2]), "NACK SN 2");

    // That NACK, to the writer's repair path.
    let nack_lease = crate::test_support::domains::unique_domain();
    let mapping =
        crate::transport::PortMapping::calculate(nack_lease.id(), 0).expect("port mapping");
    let repair_transport = Arc::new(
        crate::transport::UdpTransport::new(nack_lease.id(), 0, mapping).expect("transport"),
    );
    let handler = WriterNackHandler::new(
        topic.clone(),
        Arc::clone(&cache),
        repair_transport,
        Arc::new(ReliableMetrics::new()),
        RetransmitCfg {
            rtps_endpoint: Some(writer_ctx()),
            endpoint_registry: Some(registry.clone()),
            canonical_encapsulation_kind: 0x0007,
            ack_track: None,
            frag_route: Arc::new(super::frag_route::FragRouteProfile::new(
                u16::try_from(crate::protocol::builder::DEFAULT_FRAGMENT_SIZE)
                    .expect("DEFAULT_FRAGMENT_SIZE fits u16"),
            )),
            discovery_fsm: None,
        },
    );
    let missing: Vec<u64> = holes
        .iter()
        .map(|&s| u64::try_from(s).expect("positive"))
        .collect();
    let acknack = crate::protocol::builder::build_acknack_packet(
        READER_PREFIX,
        OUR_PREFIX,
        READER_EID,
        WRITER_EID,
        u64::try_from(bitmap_base).expect("positive"),
        &missing,
        1,
    );
    handler.on_nack(&acknack, Some(reader_guid()));

    let repaired = collect(&capture, Duration::from_millis(200));
    let repair = repaired
        .iter()
        .find(|p| data_sn(p) == Some(2))
        .unwrap_or_else(|| {
            panic!(
                "the NACK is repaired with SN 2 ({} packets)",
                repaired.len()
            )
        });
    let (flags, pids) = decode_data_submsg(repair);
    assert_eq!(flags & 0x0C, 0x08, "a key-only DATA: K set, D clear");
    let status = pids.get(&PID_STATUS_INFO).expect("PID_STATUS_INFO");
    let expected = match change {
        Lifecycle::Dispose => 0x01,
        // autodispose_unregistered_instances defaults to TRUE.
        Lifecycle::Unregister => 0x03,
    };
    assert_eq!(
        status[3], expected,
        "the repaired change is the lifecycle change"
    );
    reader.on_data(2);
    assert!(reader.low_mark() == 2, "the reader holds the change");
}

#[test]
fn a_lost_dispose_is_announced_by_the_periodic_heartbeat_and_repaired() {
    a_lost_lifecycle_change_is_announced_and_repaired(Lifecycle::Dispose, true);
}

#[test]
fn a_lost_dispose_is_announced_by_the_writer_and_repaired() {
    a_lost_lifecycle_change_is_announced_and_repaired(Lifecycle::Dispose, false);
}

#[test]
fn a_lost_unregister_is_announced_by_the_periodic_heartbeat_and_repaired() {
    a_lost_lifecycle_change_is_announced_and_repaired(Lifecycle::Unregister, true);
}

#[test]
fn a_lost_unregister_is_announced_by_the_writer_and_repaired() {
    a_lost_lifecycle_change_is_announced_and_repaired(Lifecycle::Unregister, false);
}

/// The announced lastSN never falls back: an end-of-set marker numbered
/// by the thread closing a set (above the writer's last change) must not be
/// hidden by a change the writer thread records later with a lower number,
/// the race of a write against `end_coherent_changes`.
#[test]
fn the_announced_last_sequence_number_only_rises() {
    let state = super::heartbeat_scheduler::HeartbeatSchedulerState::new();
    state.record_end_of_set(6);
    state.update_seq(5);
    assert_eq!(state.announced_last_seq(), 6);
    state.update_seq(7);
    assert_eq!(state.announced_last_seq(), 7);
    state.record_end_of_set(4);
    assert_eq!(
        state.announced_last_seq(),
        7,
        "an older marker hides nothing"
    );
}
