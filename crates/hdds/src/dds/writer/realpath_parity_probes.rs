// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Real-path repair parity probes.
//!
//! `emission_parity_tests.rs` compares the *builder* outputs directly: it
//! calls the live builder and the repair builder with the same arguments
//! and diffs the returned `Vec<u8>`. That proves the builders agree given
//! the same inputs, but it does not prove the real repair entry points --
//! `WriterReplayState::replay_to` and `WriterNackHandler::on_nack` -- feed
//! them the SAME inputs the live write did, since those entry points sit
//! between the cache and the builder and could in principle normalize away
//! a difference (or introduce a new one).
//!
//! Every probe here drives the REAL entry point end to end: insert a change
//! into a real `HistoryCache` with the real full-metadata insert API (a
//! FIXED `source_ts` and the write-time `cdr_version`, exactly as
//! `DataWriter::write()` journals them), build the "live" reference
//! packet with the SAME `_ts` builder variant the write path uses and the
//! SAME fixed timestamp, then trigger the real repair entry point with a
//! genuine UDP socket standing in for the peer and capture what actually
//! left the wire.
//!
//! Since `source_ts` is a caller-supplied input (not a fresh
//! `now_rtps_timestamp()` read -- see `ChangeMetadata::source_ts`), every
//! probe below asserts FULL byte-for-byte parity, INFO_TS included, no
//! masking. `report_and_assert_parity` keeps an INFO_TS mask as an OPTIONAL
//! diagnostic: if two buffers ever disagree, it prints whether masking
//! INFO_TS alone would make them agree, so a regression that is "only the
//! timestamp" is distinguishable at a glance from a deeper wire-shape
//! disagreement.
//!
//! P1-P7 pass (history replay and NACK repair both consume the journaled
//! coherent markers, key hash, source timestamp and CDR version). P8
//! (replay's encapsulation header vs the write-time CDR version) passes
//! because the journaled `cdr_version` carries the write-time version. P9
//! drives the REAL `DataWriter::write()` path
//! in-process (not a hand-built cache entry) and compares its live wire
//! bytes against a `WriterReplayState::replay_to` sharing the same cache.

use super::nack::{RetransmitCfg, WriterNackHandler};
use super::runtime::WriterReplayState;
use crate::core::discovery::multicast::DiscoveryFsm;
use crate::core::discovery::{EndpointRegistry, GUID};
use crate::core::rt::slabpool::SlabPool;
use crate::core::rtps_constants::{HDDS_VENDOR_ID_U16, INTERCOM_VENDOR_ID_U16};
use crate::dds::CdrVersion;
use crate::engine::NackHandler;
use crate::protocol::builder::{self, RtpsEndpointContext};
use crate::qos::History;
use crate::reliability::{ChangeKind, ChangeMetadata, HistoryCache, NackMsg, ReliableMetrics};
use crate::test_support::domains::unique_domain;
use crate::transport::UdpTransport;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Dedicated to giving each probe's test topic a unique name (SEDP
/// matching is process-wide, so two probes sharing a topic name could
/// route each other's DATA). NOT a port and never fed to a bind call --
/// port collisions are handled by the shared
/// `crate::test_support::ports::with_reserved_ports` retry instead, see
/// `writer_transport`.
static NEXT_TOPIC_SEQ: AtomicU16 = AtomicU16::new(1);

fn claim_topic_seq() -> u16 {
    NEXT_TOPIC_SEQ.fetch_add(1, Ordering::Relaxed)
}

fn isolated_wire_domain() -> crate::test_support::domains::DomainLease {
    for _ in 0..512 {
        let lease = unique_domain();
        if (200..=230).contains(&lease.id()) {
            return lease;
        }
    }
    panic!("no isolated interoperability domain available");
}

fn remote_only_coherent_write(seq: u64, forbid_local: bool) {
    use crate::dds::qos::PresentationAccessScope;
    use crate::dds::{Participant, QoS};
    use crate::generated::temperature::Temperature;
    let domain = isolated_wire_domain();
    let participant = Participant::builder("coherent_remote_only")
        .domain_id(domain.id())
        .build()
        .unwrap();
    for scope in [
        PresentationAccessScope::Group,
        PresentationAccessScope::Topic,
        PresentationAccessScope::Instance,
    ] {
        let mut qos = QoS::reliable().keep_all();
        qos.presentation.access_scope = scope;
        qos.presentation.coherent_access = true;
        let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
        let topic = format!("remote_only_coherent_{}", claim_topic_seq());
        let writer = participant
            .topic::<Temperature>(&topic)
            .unwrap()
            .writer()
            .qos(qos)
            .publisher(&publisher)
            .build()
            .unwrap();
        let (capture, addr) = bind_capture();
        register_matched_reader(
            writer.discovery_fsm.as_ref().unwrap(),
            &topic,
            "Temperature",
            nack_reader_guid(),
            addr,
            Some(HDDS_VENDOR_ID_U16),
        );
        assert_eq!(writer.merger.reader_count(), 0);
        writer.next_seq.store(seq, Ordering::Release);
        if forbid_local {
            super::before_next_local_prepare(Box::new(|| {
                panic!("remote-only change requested local ring storage")
            }));
        }
        publisher.begin_coherent_changes().unwrap();
        writer
            .write(&Temperature {
                value: 21.5,
                timestamp: 1_700_000_000,
            })
            .expect("remote-only write uses RTPS resources and a 64-bit sequence");
        publisher.end_coherent_changes().unwrap();
        assert!(
            recv_one(&capture, seq).is_some(),
            "remote-only DATA was not emitted"
        );
        super::clear_local_prepare_hook();
    }
}

#[test]
fn remote_only_coherent_writes_do_not_prepare_local_slabs() {
    remote_only_coherent_write(1, true);
}

#[test]
fn remote_only_coherent_writes_keep_the_rtps_64_bit_sequence_range() {
    remote_only_coherent_write(u64::from(u32::MAX) + 17, false);
}

#[test]
fn topic_and_instance_publishers_do_not_arm_the_group_producer() {
    use crate::dds::qos::PresentationAccessScope;
    use crate::dds::{Participant, QoS};
    use crate::generated::temperature::Temperature;
    use crate::TransportMode;
    let participant = Participant::builder("single_coherent_producer")
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    for scope in [
        PresentationAccessScope::Topic,
        PresentationAccessScope::Instance,
    ] {
        let mut qos = QoS::reliable().keep_all();
        qos.presentation.access_scope = scope;
        qos.presentation.coherent_access = true;
        let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
        let topic = participant
            .topic::<Temperature>(&format!("single_coherent_producer_{}", claim_topic_seq()))
            .unwrap();
        let writer = topic
            .writer()
            .qos(qos.clone())
            .publisher(&publisher)
            .build()
            .unwrap();
        let reader = topic.reader().qos(qos).build().unwrap();
        for value in [1u8, 2, 3] {
            if value == 2 {
                publisher.begin_coherent_changes().unwrap();
            }
            writer
                .write(&Temperature {
                    value: f32::from(value),
                    timestamp: 1,
                })
                .unwrap();
            if value == 2 {
                publisher.end_coherent_changes().unwrap();
            }
            assert!(
                !writer.merger.coherent_producer_enabled(),
                "single-writer scope armed GROUP production"
            );
            assert_eq!(reader.take().unwrap().unwrap().value, f32::from(value));
        }
    }
}

#[test]
fn an_ordinary_write_waits_for_an_earlier_close_without_a_group_mutex() {
    use crate::dds::qos::PresentationAccessScope;
    use crate::dds::{Participant, QoS};
    use crate::generated::temperature::Temperature;
    let participant = Participant::builder("ordinary_coherent_close_order")
        .with_transport(crate::TransportMode::IntraProcess)
        .build()
        .unwrap();
    for scope in [
        PresentationAccessScope::Topic,
        PresentationAccessScope::Instance,
    ] {
        let mut qos = QoS::reliable().keep_all();
        qos.presentation.access_scope = scope;
        qos.presentation.coherent_access = true;
        let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
        let topic = participant
            .topic::<Temperature>(&format!(
                "ordinary_coherent_close_order_{}",
                claim_topic_seq()
            ))
            .unwrap();
        let writer = topic
            .writer()
            .qos(qos.clone())
            .publisher(&publisher)
            .build()
            .unwrap();
        let reader = topic.reader().qos(qos).build().unwrap();
        let (paused, ready) = std::sync::mpsc::channel();
        let resume = Arc::new(std::sync::Barrier::new(2));
        let turn = resume.clone();
        writer.merger.pause_local_delivery(Arc::new(move |seq| {
            if seq == 1 {
                paused.send(()).unwrap();
                turn.wait();
            }
        }));
        publisher.begin_coherent_changes().unwrap();
        writer
            .write(&Temperature {
                value: 1.0,
                timestamp: 1,
            })
            .unwrap();
        let close = {
            let publisher = publisher.clone();
            std::thread::spawn(move || publisher.end_coherent_changes())
        };
        ready
            .recv_timeout(Duration::from_secs(5))
            .expect("coherent close paused before publication");
        writer
            .write(&Temperature {
                value: 2.0,
                timestamp: 2,
            })
            .unwrap();
        let inside = reader.take().unwrap();
        resume.wait();
        close.join().unwrap().unwrap();
        assert!(
            inside.is_none(),
            "ordinary write overtook a retained coherent close"
        );
        assert_eq!(reader.take().unwrap().unwrap().value, 1.0);
        assert_eq!(reader.take().unwrap().unwrap().value, 2.0);
    }
}

/// Bind a UDP capture socket standing in for the NACKing/late-joining
/// peer: ephemeral port on the address the writer can reach (loopback,
/// or the primary interface on Windows, see `bind_capture_socket`), 2s
/// read timeout per the task spec.
fn bind_capture() -> (UdpSocket, SocketAddr) {
    let sock = crate::test_support::ports::bind_capture_socket();
    sock.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set 2s read timeout on capture socket");
    let addr = sock.local_addr().expect("capture socket local_addr");
    (sock, addr)
}

/// Build the writer-side transport bound to a freshly reserved ephemeral
/// port, retrying with a NEW reservation (not `port + 1`) on `AddrInUse`
/// via the shared `crate::test_support::ports::with_reserved_ports`:
/// another process, or another test's leftover socket, could grab the
/// exact port between the reservation and this bind.
#[allow(deprecated)] // UdpTransport::with_port is deprecated, unrelated to this probe
fn writer_transport() -> Arc<UdpTransport> {
    let transport = crate::test_support::ports::with_reserved_ports(8, |[port]: [u16; 1]| {
        UdpTransport::with_port(port)
    })
    .expect("bind writer transport after 8 ephemeral-port attempts");
    Arc::new(transport)
}

/// RTPS submessage ids for DATA and DATA_FRAG (RTPS v2.5 Table 8.13).
const RTPS_SUBMSG_DATA: u8 = 0x15;
const RTPS_SUBMSG_DATA_FRAG: u8 = 0x16;

/// Extract the writerSN from a DATA or DATA_FRAG submessage body. Both
/// submessages share the same layout up to the SN: extraFlags(2) +
/// octetsToInlineQos(2) + readerId(4) + writerId(4) + writerSN(8) -- see
/// `emit_canonical_native_frags`'s ASCII diagram in `emit_canonical.rs`.
/// `body_start` is the offset right after the 4-byte submessage header.
fn submsg_writer_sn(pkt: &[u8], body_start: usize) -> Option<u64> {
    if body_start + 20 > pkt.len() {
        return None;
    }
    let sn_high = i32::from_le_bytes([
        pkt[body_start + 12],
        pkt[body_start + 13],
        pkt[body_start + 14],
        pkt[body_start + 15],
    ]);
    let sn_low = u32::from_le_bytes([
        pkt[body_start + 16],
        pkt[body_start + 17],
        pkt[body_start + 18],
        pkt[body_start + 19],
    ]);
    Some(((sn_high as i64) << 32 | sn_low as i64) as u64)
}

/// True when `pkt` contains a DATA (0x15) or DATA_FRAG (0x16) submessage
/// whose writerSN is `expected_seq`. Scans from offset 20 (end of the
/// fixed RTPS header), the same submessage walk `mask_info_ts` uses.
fn packet_carries_seq(pkt: &[u8], expected_seq: u64) -> bool {
    let mut offset = 20usize;
    while offset + 4 <= pkt.len() {
        let id = pkt[offset];
        let len = u16::from_le_bytes([pkt[offset + 2], pkt[offset + 3]]) as usize;
        let body_start = offset + 4;
        if (id == RTPS_SUBMSG_DATA || id == RTPS_SUBMSG_DATA_FRAG)
            && submsg_writer_sn(pkt, body_start) == Some(expected_seq)
        {
            return true;
        }
        if len == 0 {
            break;
        }
        offset = body_start + len;
    }
    false
}

/// Try to receive exactly one datagram carrying a DATA/DATA_FRAG
/// submessage for `expected_seq`, within the socket's read timeout.
///
/// Any OTHER datagram -- e.g. a HEARTBEAT that raced ahead of the DATA on
/// a real writer (probe P9 drives the real heartbeat scheduler) -- is
/// SKIPPED, not returned, up to `MAX_SKIPPED_DATAGRAMS` of them, so a
/// probe never mistakes "the wrong datagram arrived first" for either
/// "nothing arrived" or "the repair/replay bytes are wrong". `None` means
/// the read timeout elapsed with no matching datagram ever seen (a
/// genuine silence, not an error being swallowed -- any other I/O error
/// panics so a probe never misreports "dropped" for "socket broke").
fn recv_one(sock: &UdpSocket, expected_seq: u64) -> Option<Vec<u8>> {
    // A real writer with a real matched reader (P9-P11) runs its actual
    // HeartbeatScheduler, which can deliver several periodic HEARTBEATs
    // to the capture socket before or interleaved with the DATA this
    // probe is waiting for -- especially under parallel test-thread
    // contention. Skipping is cheap (each iteration only costs a real
    // recv, never an extra timeout wait -- see the doc above), so a
    // generous budget costs nothing when the match arrives quickly and
    // only helps when it does not.
    const MAX_SKIPPED_DATAGRAMS: u32 = 64;
    for _ in 0..MAX_SKIPPED_DATAGRAMS {
        let mut buf = [0u8; 65536];
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                let pkt = buf[..n].to_vec();
                if packet_carries_seq(&pkt, expected_seq) {
                    return Some(pkt);
                }
                eprintln!(
                    "[probe] recv_one: skipped a {n}-byte datagram with no DATA/DATA_FRAG \
                     for seq {expected_seq}"
                );
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return None;
            }
            Err(e) => panic!("capture socket I/O error (not a timeout): {}", e),
        }
    }
    None
}

/// Locate the INFO_TS submessage (id 0x09) in an RTPS packet and zero its
/// 8-byte timestamp payload in place. Scans the submessage stream from
/// offset 20 (end of the fixed RTPS header) instead of hardcoding offset
/// 20 for the submessage itself, so a probe that captures something with
/// unexpected leading submessages fails loudly (returns `false`) instead
/// of silently masking the wrong bytes.
fn mask_info_ts(pkt: &mut [u8]) -> bool {
    let mut offset = 20usize;
    while offset + 4 <= pkt.len() {
        let id = pkt[offset];
        let len = u16::from_le_bytes([pkt[offset + 2], pkt[offset + 3]]) as usize;
        if id == 0x09 {
            let ts_start = offset + 4;
            let ts_end = ts_start + 8;
            if ts_end > pkt.len() {
                return false;
            }
            for b in &mut pkt[ts_start..ts_end] {
                *b = 0;
            }
            return true;
        }
        if len == 0 {
            return false;
        }
        offset += 4 + len;
    }
    false
}

/// Render bytes as a compact hex string for failure output.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// First index at which two byte slices differ, considering a length
/// mismatch itself a "difference" at the shorter length.
fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    let n = a.len().min(b.len());
    for i in 0..n {
        if a[i] != b[i] {
            return Some(i);
        }
    }
    if a.len() != b.len() {
        Some(n)
    } else {
        None
    }
}

/// Shared compare-and-report for the whole-packet probes (P1-P9): asserts
/// the RAW, unmasked bytes are identical -- source_ts is a caller-supplied
/// input (see `ChangeMetadata::source_ts`), not a fresh clock read, so a
/// probe has no reason to mask INFO_TS out of the assertion. Masking is
/// kept purely as an OPTIONAL diagnostic: on a
/// mismatch, prints whether the two sides would agree if INFO_TS alone
/// were zeroed, so "only the timestamp differs" is distinguishable at a
/// glance from a deeper wire-shape regression.
fn report_and_assert_parity(probe: &str, live: Vec<u8>, captured: Vec<u8>) {
    let unmasked_equal = live == captured;
    let diff_at = first_diff(&live, &captured);

    if unmasked_equal {
        println!(
            "[probe {}] unmasked_equal=true (byte-for-byte parity, INFO_TS included)",
            probe
        );
    } else {
        let mut live_masked = live.clone();
        let mut captured_masked = captured.clone();
        let live_had_ts = mask_info_ts(&mut live_masked);
        let captured_had_ts = mask_info_ts(&mut captured_masked);
        let masked_equal = live_masked == captured_masked;
        println!(
            "[probe {}] unmasked_equal=false masked_equal(diagnostic only)={} \
             live_had_info_ts={} captured_had_info_ts={} diff_at={:?}",
            probe, masked_equal, live_had_ts, captured_had_ts, diff_at
        );
        println!(
            "[probe {}] live     ({} bytes): {}",
            probe,
            live.len(),
            hex(&live)
        );
        println!(
            "[probe {}] captured ({} bytes): {}",
            probe,
            captured.len(),
            hex(&captured)
        );
    }

    assert_eq!(
        live, captured,
        "[probe {}] live vs real-path-repaired bytes disagree byte-for-byte \
         (unmasked, INFO_TS included); first differing offset={:?}",
        probe, diff_at
    );
}

// ---------------------------------------------------------------------
// P1: history replay of a keyed user-data change
// ---------------------------------------------------------------------

/// Coherent markers, key hash and source timestamp, driven through the REAL
/// `WriterReplayState::replay_to` entry point instead of a bare builder
/// call: `replay_to` reads `HistoryCache::snapshot_changes` (full
/// `CachedChange`, metadata included), not the metadata-dropping
/// `snapshot_payloads`, and terminates in
/// `build_data_packet_with_context_full_keyed_ts` with the journaled
/// `key_hash` / coherent markers / `cdr_version` / `source_ts` -- so a
/// keyed change replays with its `PID_KEY_HASH` intact. This probe drives
/// that through the real replay call, not by inspecting `replay_to`'s
/// source.
#[test]
fn replay_to_user_data_keyed() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x30; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let topic = "probe/replay_keyed";
    let seq = 41u64;
    let payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
    let version = CdrVersion::Xcdr2;
    let key_hash = [0x77u8; 16];
    // Fixed, not now(): source_ts is a caller-supplied input to both the
    // live builder and the cache journal, so the two sides can be
    // compared byte-for-byte with no masking.
    let source_ts = (0x1000_0001u32, 0x2000_0002u32);

    let live = builder::build_data_packet_with_context_full_keyed_ts(
        &ctx,
        topic,
        seq,
        &payload,
        version,
        source_ts,
        None,
        None,
        Some(&key_hash),
        false,
    );

    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        16,
        256 * 1024,
        History::KeepLast(16),
    ));
    cache
        .insert_with_metadata(
            seq,
            &payload,
            0,
            ChangeMetadata {
                kind: ChangeKind::UserData,
                key_hash: Some(key_hash),
                source_ts,
                source_ts_known: true,
                cdr_version: version,
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert keyed change");

    let transport = writer_transport();
    let state = WriterReplayState::new(topic.to_string(), Some(ctx), transport, cache, None);

    let (capture, capture_addr) = bind_capture();
    state.replay_to(capture_addr, None);
    let captured = recv_one(&capture, seq).expect("replay must send exactly one repair datagram");

    report_and_assert_parity("P1 replay_to_user_data_keyed", live, captured);
}

/// A dispose kept in the history reaches a late joiner as the key-only
/// DATA it was live (decoded, not byte-compared: the dispose builder stamps
/// its own INFO_TS). Were it absent from the history, a TRANSIENT_LOCAL late
/// joiner would be handed the instance ALIVE.
#[test]
fn replay_to_sends_a_dispose_kept_in_the_history() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x3A; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let seq = 9u64;
    let cache = Arc::new(HistoryCache::new_with_limits(
        Arc::new(SlabPool::new()),
        16,
        256 * 1024,
        History::KeepLast(16),
    ));
    cache
        .insert_with_metadata(
            seq,
            &[0x00, 0x09, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00],
            0,
            ChangeMetadata {
                key_hash: Some([0x5C; 16]),
                source_ts: (0x1111_2222, 0x3333_4444),
                source_ts_known: true,
                status_info: Some(crate::protocol::builder::StatusInfoKind::Disposed),
                ..ChangeMetadata::user_data()
            },
        )
        .expect("journal the dispose");

    let state = WriterReplayState::new(
        "probe/replay_dispose".to_string(),
        Some(ctx),
        writer_transport(),
        cache,
        None,
    );
    let (capture, capture_addr) = bind_capture();
    state.replay_to(capture_addr, None);
    let pkt = recv_one(&capture, seq).expect("the replay must send the dispose");

    let off = builder::helpers::find_data_submsg_offset(&pkt).expect("a DATA");
    assert_ne!(pkt[off + 1] & 0x08, 0, "K flag: a key-only DATA");
    assert_eq!(pkt[off + 1] & 0x04, 0, "no D flag");
    let (inline_qos, le) = builder::extract_inline_qos(&pkt).expect("inline QoS");
    assert_eq!(
        builder::extract_status_info(inline_qos, le),
        Some(1),
        "PID_STATUS_INFO: disposed"
    );
    // INFO_TS right after the 20-byte header: the journaled timestamp.
    assert_eq!(pkt[20], 0x09, "INFO_TS precedes the DATA");
    assert_eq!(
        (
            u32::from_le_bytes([pkt[24], pkt[25], pkt[26], pkt[27]]),
            u32::from_le_bytes([pkt[28], pkt[29], pkt[30], pkt[31]])
        ),
        (0x1111_2222, 0x3333_4444),
        "the replay carries the journaled source timestamp, not a fresh one"
    );
}

// ---------------------------------------------------------------------
// P2: history replay of a TOPIC-scope coherent member
// ---------------------------------------------------------------------

#[test]
fn replay_to_coherent_member_topic_scope() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x31; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let topic = "probe/replay_topic_scope";
    let seq = 42u64;
    let payload = vec![0x11, 0x22, 0x33];
    let version = CdrVersion::Xcdr2;
    let source_ts = (0x1000_0003u32, 0x2000_0004u32);

    // TOPIC scope: coherent_sn set, group_sn None (no PID_GROUP_ENTITY_ID).
    let live = builder::build_data_packet_with_context_full_keyed_ts(
        &ctx,
        topic,
        seq,
        &payload,
        version,
        source_ts,
        Some(seq),
        None,
        None,
        false,
    );

    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        16,
        256 * 1024,
        History::KeepLast(16),
    ));
    cache
        .insert_with_metadata(
            seq,
            &payload,
            0,
            ChangeMetadata {
                kind: ChangeKind::UserData,
                coherent_sn: Some(seq),
                source_ts,
                source_ts_known: true,
                cdr_version: version,
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert TOPIC-scope coherent change");

    let transport = writer_transport();
    let state = WriterReplayState::new(topic.to_string(), Some(ctx), transport, cache, None);

    let (capture, capture_addr) = bind_capture();
    state.replay_to(capture_addr, None);
    let captured = recv_one(&capture, seq).expect("replay must send exactly one repair datagram");

    report_and_assert_parity("P2 replay_to_coherent_member_topic_scope", live, captured);
}

// ---------------------------------------------------------------------
// P3: history replay of a GROUP-scope coherent member
// ---------------------------------------------------------------------

#[test]
fn replay_to_coherent_member_group_scope() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x32; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let topic = "probe/replay_group_scope";
    let seq = 43u64;
    let payload = vec![0x44, 0x55, 0x66, 0x77, 0x88];
    let version = CdrVersion::Xcdr2;
    let source_ts = (0x1000_0005u32, 0x2000_0006u32);

    // GROUP scope: both coherent_sn and group_sn set, which is what makes
    // the live builder also emit PID_GROUP_ENTITY_ID (0x0053).
    let live = builder::build_data_packet_with_context_full_keyed_ts(
        &ctx,
        topic,
        seq,
        &payload,
        version,
        source_ts,
        Some(seq),
        Some(9),
        None,
        false,
    );

    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        16,
        256 * 1024,
        History::KeepLast(16),
    ));
    cache
        .insert_with_metadata(
            seq,
            &payload,
            0,
            ChangeMetadata {
                kind: ChangeKind::UserData,
                coherent_sn: Some(seq),
                group_sn: Some(9),
                source_ts,
                source_ts_known: true,
                cdr_version: version,
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert GROUP-scope coherent change");

    let transport = writer_transport();
    let state = WriterReplayState::new(topic.to_string(), Some(ctx), transport, cache, None);

    let (capture, capture_addr) = bind_capture();
    state.replay_to(capture_addr, None);
    let captured = recv_one(&capture, seq).expect("replay must send exactly one repair datagram");

    report_and_assert_parity("P3 replay_to_coherent_member_group_scope", live, captured);
}

// ---------------------------------------------------------------------
// Shared NACK-handler scaffolding for P4-P7
// ---------------------------------------------------------------------

fn nack_reader_guid() -> [u8; 16] {
    let mut g = [0xBBu8; 16];
    g[12..16].copy_from_slice(&[0x00, 0x00, 0x20, 0x07]);
    g
}

/// `participant_guid_of` from `nack.rs` is private to that module and not
/// reachable from here; this is the same one-line derivation copied
/// verbatim (endpoint GUID with its entity-id trailer replaced by
/// RTPS_ENTITYID_PARTICIPANT) so `fsm_with_vendor` below can drive
/// `DiscoveryFsm::handle_spdp` with the right participant GUID.
fn participant_guid_of(endpoint_guid: [u8; 16]) -> GUID {
    let mut bytes = endpoint_guid;
    bytes[12..16].copy_from_slice(&crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT);
    GUID::from_bytes(bytes)
}

/// A `DiscoveryFsm` that has "discovered" the reader's participant with the
/// given vendor id via the real SPDP ingestion path -- same construction
/// `nack.rs`'s own `mod tests::fsm_with_vendor` uses (that helper is
/// private to `nack`, so this is a same-crate copy, not a reference to it).
fn fsm_with_vendor(reader_guid: [u8; 16], vendor_id: Option<u16>) -> Arc<DiscoveryFsm> {
    fsm_with(reader_guid, vendor_id, None)
}

fn fsm_with(
    reader_guid: [u8; 16],
    vendor_id: Option<u16>,
    hdds_capabilities: Option<u32>,
) -> Arc<DiscoveryFsm> {
    let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
    // This participant speaks the spec GROUP dialect.
    fsm.set_local_capabilities(crate::protocol::group::CAP_SPEC_GROUP_COHERENT);
    fsm.handle_spdp(crate::protocol::discovery::SpdpData {
        participant_guid: participant_guid_of(reader_guid),
        lease_duration_ms: 100_000,
        domain_id: 0,
        metatraffic_unicast_locators: vec![],
        default_unicast_locators: vec![],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id,
        hdds_capabilities,
        builtin_endpoint_set: None,
    });
    Arc::new(fsm)
}

/// Build a `WriterNackHandler` wired to a real transport and, optionally,
/// a real (resolved) `EndpointRegistry` + `DiscoveryFsm`.
fn nack_handler(
    topic: &str,
    ctx: RtpsEndpointContext,
    cache: Arc<HistoryCache>,
    endpoint_registry: Option<EndpointRegistry>,
    discovery_fsm: Option<Arc<DiscoveryFsm>>,
) -> (WriterNackHandler, Arc<UdpTransport>) {
    let transport = writer_transport();
    let handler = WriterNackHandler::new(
        topic.to_string(),
        cache,
        transport.clone(),
        Arc::new(ReliableMetrics::new()),
        RetransmitCfg {
            rtps_endpoint: Some(ctx),
            endpoint_registry,
            canonical_encapsulation_kind: ctx.encapsulation_kind,
            ack_track: None,
            frag_route: Arc::new(super::frag_route::FragRouteProfile::new(
                u16::try_from(builder::DEFAULT_FRAGMENT_SIZE)
                    .expect("DEFAULT_FRAGMENT_SIZE fits the u16 fragmentSize field"),
            )),
            discovery_fsm,
        },
    );
    (handler, transport)
}

/// Minimal CDR2 NackMsg construction, driven straight into `on_nack` --
/// this is the `control.rs` format, the simpler of the two `on_nack`
/// accepts (see `nack.rs`'s module doc comment on "dual-format ACKNACK
/// parsing"); it carries no writer entity id, so the ACKNACK entity-id
/// filter never applies and the resolved reader GUID is exactly what is
/// passed in.
// NackMsg::new() takes a Vec<Range<u64>> because a real ACKNACK can carry
// several missing ranges; every probe here NACKs exactly one seq, so this
// is genuinely a one-element Vec, not a Range that should be flattened.
#[allow(clippy::single_range_in_vec_init)]
fn drive_single_seq_nack(handler: &WriterNackHandler, seq: u64, reader_guid: [u8; 16]) {
    let nack = NackMsg::new(vec![seq..seq + 1]);
    handler.on_nack(&nack.encode_cdr2_le(), Some(reader_guid));
}

// ---------------------------------------------------------------------
// P4: NACK repair of a keyed user-data change
// ---------------------------------------------------------------------

/// Same property as P1, driven through the REAL `on_nack` entry point.
/// The NACK small-payload branch forwards `change.metadata.coherent_sn` /
/// `group_sn` / `key_hash` (see the
/// `build_data_packet_with_context_full_keyed` call in `nack.rs`), so this
/// probe measures parity.
#[test]
fn on_nack_user_data_keyed() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x33; 12],
        reader_entity_id: [0x00, 0x00, 0x20, 0x07],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let topic = "probe/nack_keyed";
    let seq = 44u64;
    let payload = vec![0x91, 0x92, 0x93];
    let version = CdrVersion::Xcdr2;
    let key_hash = [0x55u8; 16];
    let source_ts = (0x1000_0007u32, 0x2000_0008u32);

    let live = builder::build_data_packet_with_context_full_keyed_ts(
        &ctx,
        topic,
        seq,
        &payload,
        version,
        source_ts,
        None,
        None,
        Some(&key_hash),
        false,
    );

    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        16,
        256 * 1024,
        History::KeepLast(16),
    ));
    cache
        .insert_with_metadata(
            seq,
            &payload,
            0,
            ChangeMetadata {
                kind: ChangeKind::UserData,
                key_hash: Some(key_hash),
                source_ts,
                source_ts_known: true,
                cdr_version: version,
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert keyed change");

    let (capture, capture_addr) = bind_capture();
    let reader_guid = nack_reader_guid();
    let registry = EndpointRegistry::new();
    registry.register_reader_locator(GUID::from_bytes(reader_guid), capture_addr);

    let (handler, _transport) = nack_handler(topic, ctx, cache, Some(registry), None);
    drive_single_seq_nack(&handler, seq, reader_guid);

    let captured = recv_one(&capture, seq).expect("on_nack must send exactly one repair datagram");

    report_and_assert_parity("P4 on_nack_user_data_keyed", live, captured);
}

// ---------------------------------------------------------------------
// P5: NACK repair of a GROUP-scope coherent + keyed change
// ---------------------------------------------------------------------

#[test]
fn on_nack_coherent_member_group_scope() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x34; 12],
        reader_entity_id: [0x00, 0x00, 0x20, 0x07],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let topic = "probe/nack_group_scope";
    let seq = 45u64;
    let payload = vec![0xA1, 0xA2, 0xA3, 0xA4];
    let version = CdrVersion::Xcdr2;
    let key_hash = [0x66u8; 16];
    let source_ts = (0x1000_0009u32, 0x2000_000au32);

    let live = builder::build_data_packet_with_context_full_keyed_ts(
        &ctx,
        topic,
        seq,
        &payload,
        version,
        source_ts,
        Some(seq),
        Some(9),
        Some(&key_hash),
        false,
    );

    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        16,
        256 * 1024,
        History::KeepLast(16),
    ));
    cache
        .insert_with_metadata(
            seq,
            &payload,
            0,
            ChangeMetadata {
                kind: ChangeKind::UserData,
                coherent_sn: Some(seq),
                group_sn: Some(9),
                key_hash: Some(key_hash),
                source_ts,
                source_ts_known: true,
                cdr_version: version,
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert GROUP-scope coherent keyed change");

    let (capture, capture_addr) = bind_capture();
    let reader_guid = nack_reader_guid();
    let registry = EndpointRegistry::new();
    registry.register_reader_locator(GUID::from_bytes(reader_guid), capture_addr);

    let (handler, _transport) = nack_handler(topic, ctx, cache, Some(registry), None);
    drive_single_seq_nack(&handler, seq, reader_guid);

    let captured = recv_one(&capture, seq).expect("on_nack must send exactly one repair datagram");

    report_and_assert_parity("P5 on_nack_coherent_member_group_scope", live, captured);
}

// ---------------------------------------------------------------------
// P6: NACK repair of an ECS close slot, vendor unresolved -> must DROP
// ---------------------------------------------------------------------

/// Not a live-vs-repair byte comparison: the documented behavior for an
/// ECS close slot whose reader vendor cannot be resolved is DROP (see
/// `WriterNackHandler::repair_ecs_close`'s doc comment: "never guess a
/// close dialect"). This probe measures whether that is what actually
/// happens through the real `on_nack` entry point with `discovery_fsm:
/// None`, and reports the observed datagram (if any arrived at all,
/// which would itself be the finding).
#[test]
fn on_nack_ecs_close_vendor_unresolved() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x35; 12],
        reader_entity_id: [0x00, 0x00, 0x20, 0x07],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let seq = 46u64;

    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        16,
        256 * 1024,
        History::KeepLast(16),
    ));
    cache
        .insert_ecs_close(seq, Some(seq - 1), Some(4))
        .expect("insert ECS close entry");

    let (capture, capture_addr) = bind_capture();
    // `bind_capture`'s shared 2s read timeout is sized for
    // the POSITIVE probes (P1-P11), which wait for a real repair datagram
    // to travel through a live send path -- that IS a race against a
    // sender, and 2s is its generous ceiling. This probe expects the
    // opposite: `WriterNackHandler::repair_ecs_close` (nack.rs:378-438)
    // resolves the vendor, gets `None` (this test wires `discovery_fsm:
    // None`), and returns WITHOUT ever calling `send_user_data_unicast` --
    // entirely synchronously, on this thread, inside the
    // `drive_single_seq_nack` call below. That function has no thread,
    // timer, or retry queue in its call graph, so the DROP decision is
    // already final by the time it returns: no clock speed can make a
    // datagram appear afterward. The wait below is therefore not a race to
    // win, only defense-in-depth against a FUTURE implementation that
    // moves ECS repair onto an async path (exactly what this probe exists
    // to catch) -- 200ms is ample margin for that without inheriting the
    // positive probes' multi-second budget.
    capture
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("shorten the capture read timeout for this synchronous-drop probe");
    let reader_guid = nack_reader_guid();
    let registry = EndpointRegistry::new();
    registry.register_reader_locator(GUID::from_bytes(reader_guid), capture_addr);

    // discovery_fsm: None -> the reader's vendor can never resolve.
    let (handler, _transport) = nack_handler(
        "probe/nack_ecs_unresolved",
        ctx,
        cache,
        Some(registry),
        None,
    );
    drive_single_seq_nack(&handler, seq, reader_guid);

    match recv_one(&capture, seq) {
        None => {
            println!(
                "[probe P6 on_nack_ecs_close_vendor_unresolved] OBSERVED: DROP (no datagram \
                 arrived within 200ms of a synchronous, already-completed on_nack call) -- \
                 matches the documented drop-on-unresolved-vendor behavior"
            );
        }
        Some(pkt) => {
            println!(
                "[probe P6 on_nack_ecs_close_vendor_unresolved] OBSERVED: a datagram DID arrive \
                 ({} bytes): {}",
                pkt.len(),
                hex(&pkt)
            );
            panic!(
                "[probe P6] expected DROP (no repair) for an ECS close slot with an unresolved \
                 reader vendor, but a {}-byte datagram arrived instead",
                pkt.len()
            );
        }
    }
}

// ---------------------------------------------------------------------
// P7: NACK repair of an ECS close slot, HDDS vendor resolved
// ---------------------------------------------------------------------

/// Same cached entry as P6, but with the reader's participant vendor
/// resolved as HDDS via a real `DiscoveryFsm::handle_spdp` call (the same
/// technique `nack.rs`'s own `fsm_with_vendor` test helper uses -- so this
/// probe IS drivable in-process; see the module doc on why that helper
/// itself is not reachable across module boundaries). Compared against
/// the live native-ECS shape `build_ecs_data_submessage` produces, patched
/// to the reader entity id the same way `repair_ecs_close` patches it.
#[test]
fn on_nack_ecs_close_hdds_vendor() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x36; 12],
        reader_entity_id: [0x00, 0x00, 0x20, 0x07],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let topic = "probe/nack_ecs_hdds";
    let seq = 47u64;
    let coherent_sn = seq - 1;
    let group_sn = 4u64;
    let reader_guid = nack_reader_guid();
    let reader_entity_id: [u8; 4] = [
        reader_guid[12],
        reader_guid[13],
        reader_guid[14],
        reader_guid[15],
    ];
    let source_ts = (0x1000_000bu32, 0x2000_000cu32);

    // Live native ECS DATA, ENTITYID_UNKNOWN reader then patched to the
    // requesting reader -- exactly what `build_ecs_repair_packet`'s
    // HDDS-vendor branch does (nack.rs), and what
    // `WriterCoherentBridge::emit_ecs_data` does live.
    let live_ctx = RtpsEndpointContext {
        reader_entity_id: [0u8; 4],
        ..ctx
    };
    let mut live = builder::build_ecs_data_submessage_ts(
        &live_ctx,
        topic,
        seq,
        coherent_sn,
        Some(group_sn),
        Some([0x00, 0x00, 0x01, 0x08]),
        source_ts,
    );
    live[builder::READER_ENTITY_ID_OFFSET..builder::READER_ENTITY_ID_OFFSET + 4]
        .copy_from_slice(&reader_entity_id);

    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        16,
        256 * 1024,
        History::KeepLast(16),
    ));
    cache
        .insert_with_metadata(
            seq,
            &[],
            0,
            ChangeMetadata {
                kind: ChangeKind::EcsClose,
                coherent_sn: Some(coherent_sn),
                group_sn: Some(group_sn),
                source_ts,
                source_ts_known: true,
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert ECS close entry");

    let (capture, capture_addr) = bind_capture();
    let registry = EndpointRegistry::new();
    registry.register_reader_locator(GUID::from_bytes(reader_guid), capture_addr);
    let fsm = fsm_with_vendor(reader_guid, Some(HDDS_VENDOR_ID_U16));

    let (handler, _transport) = nack_handler(topic, ctx, cache, Some(registry), Some(fsm));
    drive_single_seq_nack(&handler, seq, reader_guid);

    let captured = recv_one(&capture, seq).expect("on_nack must send exactly one repair datagram");

    report_and_assert_parity("P7 on_nack_ecs_close_hdds_vendor", live, captured);
}

/// Driven through the REAL `WriterReplayState::
/// replay_to` entry point: an InterCOM (0x0105) late joiner's ECS close
/// replay must get the bare close MARKER `dispatch_ecs`'s live path
/// sends, NOT `nack::build_ecs_repair_packet`'s on_nack-only single-SN
/// GAP -- a late joiner is seeing the close for the first time, it has
/// no prior delivery of this SN for a GAP to retire.
///
/// `recv_one` only recognizes DATA/DATA_FRAG submessages as "carrying"
/// `seq` (see its doc); a GAP submessage never matches, so replay routing
/// InterCOM through the GAP form would make this probe time out with `None`,
/// not merely mismatch bytes. Getting `Some` proves a DATA submessage arrived; the byte
/// comparison against `build_ecs_close_marker_ts` proves it is exactly
/// the marker shape, not some other DATA.
#[test]
fn replay_ecs_close_intercom_is_marker_not_gap() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x42; 12],
        reader_entity_id: [0u8; 4],
        writer_entity_id: [0x00, 0x00, 0x20, 0x02],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let topic = "probe/replay_ecs_intercom";
    let seq = 91u64;
    let coherent_sn = seq - 1;
    let reader_guid = nack_reader_guid();
    let reader_entity_id: [u8; 4] = [
        reader_guid[12],
        reader_guid[13],
        reader_guid[14],
        reader_guid[15],
    ];
    let source_ts = (0x1000_000du32, 0x2000_000eu32);

    // The live marker `dispatch_ecs` would build for this reader --
    // shared with replay via `coherent::ecs_close_form_for` (see that
    // function's doc).
    let expected = builder::build_ecs_close_marker_ts(&ctx, &reader_entity_id, seq, source_ts);

    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        16,
        256 * 1024,
        History::KeepLast(16),
    ));
    // A live member of this coherent set, still present in the same
    // snapshot -- required since the item-5 orphan gate (replay_to)
    // skips an EcsClose entry with no surviving member of its own
    // coherent_sn.
    cache
        .insert_with_metadata(
            coherent_sn,
            &[0xAA],
            0,
            ChangeMetadata {
                kind: ChangeKind::UserData,
                coherent_sn: Some(coherent_sn),
                source_ts,
                source_ts_known: true,
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert coherent member");
    cache
        .insert_with_metadata(
            seq,
            &[],
            0,
            ChangeMetadata {
                kind: ChangeKind::EcsClose,
                coherent_sn: Some(coherent_sn),
                group_sn: None,
                source_ts,
                source_ts_known: true,
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert ECS close entry");

    let transport = writer_transport();
    let fsm = fsm_with_vendor(reader_guid, Some(INTERCOM_VENDOR_ID_U16));
    let state = WriterReplayState::new(topic.to_string(), Some(ctx), transport, cache, Some(fsm));

    let (capture, capture_addr) = bind_capture();
    state.replay_to(capture_addr, Some(reader_guid));
    let captured = recv_one(&capture, seq)
        .expect("replay_to must send the InterCOM close as a DATA marker, not a GAP");

    report_and_assert_parity(
        "replay_ecs_close_intercom_is_marker_not_gap",
        expected,
        captured,
    );
}

/// `History::KeepLast` evicts cache entries
/// INDIVIDUALLY (oldest sequence number first, see `HistoryCache::
/// enforce_limits`), so an `EcsClose` entry can outlive every `UserData`
/// member of its own coherent set once the ring wraps past capacity.
/// `replay_to` must skip such an ORPHANED close instead of telling a late
/// joiner a set closed that it never received any part of.
///
/// `KeepLast(2)`: insert a UserData member (seq 1, coherent_sn=500), then
/// its EcsClose (seq 2, same coherent_sn), then two unrelated UserData
/// (seq 3 and 4, no coherent_sn) -- the fourth insert evicts seq 1 (oldest;
/// a close counts towards no limit), leaving the close alone with no member
/// of coherent_sn=500 in the snapshot. `replay_to` must send seq 3
/// (proving it did not just error out on the whole batch) and must NEVER
/// send anything for seq 2.
#[test]
fn replay_skips_orphaned_ecs_close_after_keep_last_eviction() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x51; 12],
        reader_entity_id: [0u8; 4],
        writer_entity_id: [0x00, 0x00, 0x30, 0x02],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let topic = "probe/replay_orphan_ecs_close";
    let coherent_sn = 500u64;
    let source_ts = (0x1000_000fu32, 0x2000_0010u32);

    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        2, // KeepLast(2): the ring holds at most 2 data entries
        256 * 1024,
        History::KeepLast(2),
    ));

    // seq 1: the coherent set's only member.
    cache
        .insert_with_metadata(
            1,
            &[0xAA],
            0,
            ChangeMetadata {
                kind: ChangeKind::UserData,
                coherent_sn: Some(coherent_sn),
                source_ts,
                source_ts_known: true,
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert coherent member (seq 1)");
    // seq 2: closes coherent_sn=500.
    cache
        .insert_ecs_close(2, Some(coherent_sn), None)
        .expect("insert ECS close (seq 2)");
    // seq 3 and 4: unrelated samples -> the second fills max_samples (2,
    // a close counts towards no limit) and evicts seq 1 (oldest), leaving
    // seq 2's close ORPHANED (its only member is gone).
    for seq in [3, 4] {
        cache
            .insert_with_metadata(
                seq,
                &[0xBB],
                0,
                ChangeMetadata {
                    kind: ChangeKind::UserData,
                    source_ts,
                    source_ts_known: true,
                    ..ChangeMetadata::user_data()
                },
            )
            .expect("insert unrelated sample, the second evicting seq 1");
    }
    assert!(cache.get_change(1).is_none(), "seq 1 evicted");
    assert!(
        cache.get_change(2).is_some(),
        "an orphan close within depth stays"
    );

    // Resolved HDDS vendor -- so the ONLY thing that can gate seq 2's
    // replay is the item-5 orphan check, not the pre-existing "vendor
    // unresolved" skip (`build_ecs_close_replay_packet`'s `reader_vendor?`
    // early return): without this, `nack_reader_guid`'s vendor never
    // resolves (no discovery_fsm here) and this test would pass even
    // with the orphan check deleted entirely -- verified by hand.
    let reader_guid = nack_reader_guid();
    let fsm = fsm_with_vendor(reader_guid, Some(HDDS_VENDOR_ID_U16));
    let transport = writer_transport();
    let state = WriterReplayState::new(topic.to_string(), Some(ctx), transport, cache, Some(fsm));

    let (capture, capture_addr) = bind_capture();
    state.replay_to(capture_addr, Some(reader_guid));

    // Drain every datagram `replay_to` sent, rather than using `recv_one`
    // per expected seq: `recv_one` CONSUMES (and discards) any datagram
    // that fails to match while scanning for the one it wants, so calling
    // it once per seq here would let whichever call runs first silently
    // eat the other seq's datagram and make the second call's result
    // meaningless whether or not the orphan check is present (the test
    // would pass even with the orphan check deleted).
    capture
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("shorten capture timeout for the drain loop");
    let mut sent = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        match capture.recv_from(&mut buf) {
            Ok((n, _)) => sent.push(buf[..n].to_vec()),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => panic!("capture socket I/O error (not a timeout): {}", e),
        }
    }

    assert!(
        sent.iter().any(|pkt| packet_carries_seq(pkt, 3)),
        "replay_to must still replay the unrelated live sample (seq 3); \
         an orphaned close must not abort the whole replay"
    );
    assert!(
        !sent.iter().any(|pkt| packet_carries_seq(pkt, 2)),
        "replay_to must NEVER send a close for coherent_sn=500: its only \
         member (seq 1) was evicted by KeepLast, so this close is orphaned"
    );
}

/// A set of more than one change, whole in the history: its close is
/// replayed to a late joiner. A close carries the set's LAST SN, a member
/// the set's FIRST: matched by value, they never meet for such a set, and
/// its close must not be skipped as an orphan. A second set whose members were all
/// evicted keeps its close skipped.
#[test]
fn replay_sends_the_close_of_a_set_of_several_changes() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x52; 12],
        reader_entity_id: [0u8; 4],
        writer_entity_id: [0x00, 0x00, 0x31, 0x02],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let topic = "probe/replay_close_of_several";
    let source_ts = (0x1000_0011u32, 0x2000_0012u32);
    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        16,
        256 * 1024,
        History::KeepLast(16),
    ));
    let member = |first: u64| ChangeMetadata {
        kind: ChangeKind::UserData,
        coherent_sn: Some(first),
        source_ts,
        source_ts_known: true,
        ..ChangeMetadata::user_data()
    };
    // Set 1..=2, closed at 3 (last SN 2); set 4..=5 never in the
    // snapshot (as if evicted), closed at 6 (last SN 5).
    cache
        .insert_with_metadata(1, &[0xA1], 0, member(1))
        .expect("member 1");
    cache
        .insert_with_metadata(2, &[0xA2], 0, member(1))
        .expect("member 2");
    cache.insert_ecs_close(3, Some(2), None).expect("close 3");
    cache.insert_ecs_close(6, Some(5), None).expect("close 6");
    let reader_guid = nack_reader_guid();
    let fsm = fsm_with_vendor(reader_guid, Some(HDDS_VENDOR_ID_U16));
    let state = WriterReplayState::new(
        topic.to_string(),
        Some(ctx),
        writer_transport(),
        cache,
        Some(fsm),
    );
    let (capture, capture_addr) = bind_capture();
    state.replay_to(capture_addr, Some(reader_guid));
    capture
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("shorten capture timeout for the drain loop");
    let mut sent = Vec::new();
    let mut buf = [0u8; 65536];
    while let Ok((n, _)) = capture.recv_from(&mut buf) {
        sent.push(buf[..n].to_vec());
    }
    for seq in 1..=3 {
        assert!(
            sent.iter().any(|pkt| packet_carries_seq(pkt, seq)),
            "seq {seq} replayed"
        );
    }
    assert!(
        !sent.iter().any(|pkt| packet_carries_seq(pkt, 6)),
        "the close of a set with no member left is not replayed"
    );
}

/// `WriterReplayState`'s ECS-replay outcome counters
/// are PER-INSTANCE (one `[AtomicU64; 5]` per writer), not a process-wide
/// static shared by every writer. Drives two INDEPENDENT
/// `WriterReplayState`s, each through a DIFFERENT `EcsReplayOutcome`, and
/// asserts each instance's `ecs_replay_counters()` shows ONLY its own
/// outcome -- with a shared static, both instances would observe BOTH
/// outcomes' counts combined.
#[test]
fn ecs_replay_counters_are_per_writer_not_shared() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x61; 12],
        reader_entity_id: [0u8; 4],
        writer_entity_id: [0x00, 0x00, 0x40, 0x02],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };

    // Writer A: one EcsClose entry, NO reader_guid at all -> UnresolvedVendor.
    let pool_a = Arc::new(SlabPool::new());
    let cache_a = Arc::new(HistoryCache::new_with_limits(
        pool_a,
        8,
        256 * 1024,
        History::KeepLast(8),
    ));
    cache_a
        .insert_with_metadata(
            1,
            &[0xBB],
            0,
            ChangeMetadata {
                kind: ChangeKind::UserData,
                coherent_sn: Some(100),
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert member (writer A), so this close is NOT orphaned");
    cache_a
        .insert_ecs_close(2, Some(100), None)
        .expect("insert ECS close (writer A)");
    let state_a = WriterReplayState::new(
        "probe/stats_a".to_string(),
        Some(ctx),
        writer_transport(),
        cache_a,
        None,
    );
    let (capture_a, capture_addr_a) = bind_capture();
    state_a.replay_to(capture_addr_a, None); // no reader_guid -> UnresolvedVendor

    // Writer B: a member + its close, then two unrelated samples evict the
    // member (KeepLast(2), a close counting towards no limit) -> OrphanClose.
    let pool_b = Arc::new(SlabPool::new());
    let cache_b = Arc::new(HistoryCache::new_with_limits(
        pool_b,
        2,
        256 * 1024,
        History::KeepLast(2),
    ));
    cache_b
        .insert_with_metadata(
            1,
            &[0xCC],
            0,
            ChangeMetadata {
                kind: ChangeKind::UserData,
                coherent_sn: Some(200),
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert member (writer B)");
    cache_b
        .insert_ecs_close(2, Some(200), None)
        .expect("insert ECS close (writer B)");
    for seq in [3, 4] {
        cache_b
            .insert_with_metadata(seq, &[0xDD], 0, ChangeMetadata::user_data())
            .expect("insert unrelated samples, the second evicting seq 1 (writer B)");
    }
    let state_b = WriterReplayState::new(
        "probe/stats_b".to_string(),
        Some(ctx),
        writer_transport(),
        cache_b,
        None,
    );
    let (capture_b, capture_addr_b) = bind_capture();
    state_b.replay_to(capture_addr_b, Some(nack_reader_guid()));

    drop(capture_a);
    drop(capture_b);

    // [BuiltAndSent, UnresolvedVendor, IncompleteMetadata, OrphanClose, SendError]
    let counters_a = state_a.ecs_replay_counters();
    let counters_b = state_b.ecs_replay_counters();

    assert_eq!(
        counters_a,
        [0, 1, 0, 0, 0],
        "writer A must show exactly one UnresolvedVendor and nothing else"
    );
    assert_eq!(
        counters_b,
        [0, 0, 0, 1, 0],
        "writer B must show exactly one OrphanClose and nothing else -- if \
         these counters were still the old process-wide statics, writer B \
         would also show writer A's UnresolvedVendor count"
    );
}

// ---------------------------------------------------------------------
// P8: replay's encapsulation header vs the version the body was encoded
// with
// ---------------------------------------------------------------------

/// Driven through the REAL `WriterReplayState::replay_to` entry point:
/// `replay_to` derives the wire encapsulation header from the journaled
/// `change.metadata.cdr_version` (the version the cached body was ACTUALLY
/// encoded with), not from a `WriterReplayState`-level default -- there is
/// no such field on `WriterReplayState`. `write_time_version` is
/// deliberately Xcdr1, the OPPOSITE of `ChangeMetadata::user_data()`'s own
/// best-effort default (Xcdr2, see its doc comment): if replay fell back to
/// a hardcoded/defaulted version instead of the journaled one, this probe
/// would catch it (the header would come back as the Xcdr2 wire code
/// instead of Xcdr1's).
#[test]
fn replay_encapsulation_version() {
    // @appendable: encap_kind_for_version maps this canonical kind to a
    // different wire code per CdrVersion (0x0009 for Xcdr2, 0x0001 for
    // Xcdr1), unlike @final (0x0007) which happens to collapse both
    // versions onto related legacy codes -- this is the version-sensitive
    // branch the row actually describes.
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x37; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0009,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let topic = "probe/replay_encap_version";
    let seq = 48u64;
    let payload = vec![0xEE; 6];
    let write_time_version = CdrVersion::Xcdr1;
    let source_ts = (0x1000_000du32, 0x2000_000eu32);

    let live = builder::build_data_packet_with_context_full_keyed_ts(
        &ctx,
        topic,
        seq,
        &payload,
        write_time_version,
        source_ts,
        None,
        None,
        None,
        false,
    );

    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        16,
        256 * 1024,
        History::KeepLast(16),
    ));
    cache
        .insert_with_metadata(
            seq,
            &payload,
            0,
            ChangeMetadata {
                kind: ChangeKind::UserData,
                source_ts,
                source_ts_known: true,
                cdr_version: write_time_version,
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert body with the honest write-time (Xcdr1) CDR version");

    let transport = writer_transport();
    let state = WriterReplayState::new(topic.to_string(), Some(ctx), transport, cache, None);

    let (capture, capture_addr) = bind_capture();
    state.replay_to(capture_addr, None);
    let captured = recv_one(&capture, seq).expect("replay must send exactly one repair datagram");

    report_and_assert_parity("P8 replay_encapsulation_version", live, captured);
}

// ---------------------------------------------------------------------
// P9-P11: the REAL DataWriter::write() path, not a hand-built cache entry
// ---------------------------------------------------------------------

/// Feed a matched reader's SPDP + SEDP announcements into an EXISTING,
/// already-running `DiscoveryFsm` -- unlike `fsm_with_vendor` (which
/// builds a FRESH standalone `DiscoveryFsm` for the P1-P8 on_nack/replay
/// probes), P9-P11 drive a REAL writer whose `discovery_fsm` was already
/// constructed by `WriterBuilder::build()` and must not be replaced.
///
/// This is what makes `send_packet_to_endpoints`'s PER-READER branch run
/// instead of the participant-level fallback: `find_readers_for_topic`
/// requires a real SEDP reader registration on this exact topic
/// (`registry.insert(endpoint)` runs unconditionally in `handle_sedp`,
/// before any QoS/type compatibility check -- see `DiscoveryFsm::
/// handle_sedp`), and the reader's `unicast_locators` here also drives
/// `handle_sedp`'s own `endpoint_registry.register_reader_locator` call,
/// so no separate manual registry call is needed.
fn register_matched_reader(
    fsm: &DiscoveryFsm,
    topic: &str,
    type_name: &str,
    reader_guid: [u8; 16],
    reader_locator: SocketAddr,
    vendor_id: Option<u16>,
) {
    // default_unicast_locators (NOT empty, unlike fsm_with_vendor's
    // participant-only registration): handle_spdp registers this into
    // the PARTICIPANT-level endpoint table (`EndpointRegistry::register`),
    // which `EndpointRegistry::is_empty()` actually checks (it only looks
    // at that table, not `reader_locators`). Every real peer announces a
    // default_unicast_locator in its SPDP, so this matches reality; a
    // synthetic reader-only registration (empty default_unicast_locators)
    // left `is_empty()` true and made `send_packet_to_endpoints` take its
    // "no endpoints in registry" multicast fallback BEFORE ever reaching
    // the per-reader loop -- silently defeating this probe's whole point.
    fsm.handle_spdp(crate::protocol::discovery::SpdpData {
        participant_guid: participant_guid_of(reader_guid),
        lease_duration_ms: 100_000,
        domain_id: 39,
        metatraffic_unicast_locators: vec![],
        default_unicast_locators: vec![reader_locator],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    });
    fsm.handle_sedp(crate::protocol::discovery::SedpData {
        topic_name: topic.to_string(),
        type_name: type_name.to_string(),
        participant_guid: participant_guid_of(reader_guid),
        endpoint_guid: GUID::from_bytes(reader_guid),
        qos_hash: 0,
        qos: None,
        type_object: None,
        dependents: Vec::new(),
        type_object_legacy_v1: false,
        type_information: None,
        unicast_locators: vec![reader_locator],
        user_data: None,
        shm_capability: None,
        has_explicit_reliability: false,
        has_explicit_ownership: false,
        has_ownership_strength: false,
        type_consistency: None,
        group_entity_id: None,
        endpoint_security_info: None,
    });
}

/// P1-P8 all insert a hand-built `ChangeMetadata` to isolate the repair
/// core from `write()`'s own bookkeeping. This probe closes that last gap:
/// it drives a REAL `DataWriter::write()` call (through the public
/// `Participant` / `create_writer` API, in-process) and compares the
/// datagram that call actually put on the wire against a
/// `WriterReplayState::replay_to` sharing the SAME `history_cache` +
/// `transport` + `rtps_endpoint` the writer used -- so the journaled
/// `source_ts` / `cdr_version` under test are whatever `write()` itself
/// captured, not values this probe chose.
///
/// A real matched reader is registered via `register_matched_reader` with
/// the given `vendor_id`, so `send_packet_to_endpoints` runs its PER-READER
/// branch -- the one `finalize_for_reader`'s three wire transforms (item 1)
/// apply to -- instead of falling through to the participant-level
/// fallback (which applies none of them). `replay_to` is given the SAME
/// `discovery_fsm` and the reader's GUID, so it resolves the identical
/// `ReaderWireProfile` and applies the identical transforms: this asserts
/// repair == live AFTER the vendor-specific transforms, not just before
/// them.
///
/// * P9 (`vendor_id = Some(HDDS_VENDOR_ID_U16)`): baseline, self/native
///   peer -- entity id patch only, no encap downgrade, no HEADER_EXTENSION.
/// * P10 (`vendor_id = Some(0x0123)`, zzdds): also exercises the
///   PLAIN_CDR2_LE encapsulation downgrade.
/// * P11 (`vendor_id = Some(INTERCOM_VENDOR_ID_U16)`): also exercises the
///   prepended RTPS HEADER_EXTENSION.
fn write_then_replay_real_path_with_vendor(probe_name: &str, vendor_id: Option<u16>) {
    use crate::dds::{Participant, QoS};
    use crate::generated::temperature::Temperature;

    // Unique per test run so no other test's SEDP-discovered reader can
    // ever match this topic.
    let topic = format!("probe/p9_write_replay_{}", claim_topic_seq());

    // A real Participant is required: only `WriterBuilder::build()`'s
    // participant branch calls `announce_writer_endpoint`, which is what
    // populates `rtps_endpoint` (GUID prefix + writer entity id) -- see
    // the module doc above.
    //
    // A LEASED domain, not a fixed one.
    //
    // Hardcoding a fixed domain would be wrong, even though the
    // auto-assigned participant_id already makes two probes' ports disjoint:
    // `late_joiner_automatic_replay_via_real_discovery_fsm` could panic with
    // "Address already in use (os error 98)" when a fixed domain is shared
    // with other test binaries (`tests/concurrency_stress.rs`,
    // `tests/intra_qos_gate_parity.rs`), which are SEPARATE processes: the
    // participant_id auto-assignment cannot see another binary's sockets,
    // so on a shared domain the ports are only disjoint by luck. A fixed
    // domain is also one a live service may use, which no test should join.
    //
    // The lease is declared before the participant so it is released after
    // the participant's sockets are closed.
    let domain = unique_domain();
    let participant = Participant::builder("probe_p9")
        .domain_id(domain.id())
        .build()
        .expect("build a real Participant for P9 (rtps_endpoint requires one)");

    let writer = participant
        .topic::<Temperature>(&topic)
        .expect("register topic for P9")
        .writer()
        .qos(QoS::reliable())
        .build()
        .expect("create a Reliable writer for P9 (Reliable is required for a history_cache)");

    let (capture, capture_addr) = bind_capture();
    let reader_guid = nack_reader_guid();
    let fsm = writer
        .discovery_fsm
        .clone()
        .expect("[probe P9] a real Participant must give the writer a discovery_fsm");
    register_matched_reader(
        &fsm,
        &topic,
        "Temperature",
        reader_guid,
        capture_addr,
        vendor_id,
    );

    let ctx = writer
        .rtps_endpoint
        .expect("[probe P9] writer must have an rtps_endpoint (see module doc)");
    let transport = writer
        .transport
        .clone()
        .expect("[probe P9] writer must have a transport (Participant provides one)");
    let cache = writer
        .history_cache
        .clone()
        .expect("[probe P9] Reliable QoS must give the writer a history_cache");

    let sample = Temperature {
        value: 21.5,
        timestamp: 1_700_000_000,
    };
    // A freshly built writer's first write() always takes seq 1
    // (WriterBuilder::build's `let next_seq = 1u64;`).
    let seq = 1u64;
    writer.write(&sample).expect("[probe P9] real write() call");

    let live =
        recv_one(&capture, seq).expect("[probe P9] write() must send exactly one live datagram");

    // Force replay_to the SAME capture address, sharing the SAME
    // history_cache / transport / rtps_endpoint write() just used AND the
    // SAME discovery_fsm + reader GUID, so the replayed bytes are rebuilt
    // from the EXACT change write() journaled (its real source_ts,
    // cdr_version, key_hash) AND go through the identical per-reader wire
    // transforms (entity id patch / encap downgrade / HEADER_EXTENSION).
    let state = WriterReplayState::new(topic.clone(), Some(ctx), transport, cache, Some(fsm));
    state.replay_to(capture_addr, Some(reader_guid));
    let replayed = recv_one(&capture, seq)
        .expect("[probe P9] replay_to must send exactly one repair datagram");

    report_and_assert_parity(probe_name, live, replayed);
}

#[test]
fn write_then_replay_real_path() {
    write_then_replay_real_path_with_vendor(
        "P9 write_then_replay_real_path",
        Some(HDDS_VENDOR_ID_U16),
    );
}

#[test]
fn write_then_replay_real_path_zzdds_vendor() {
    write_then_replay_real_path_with_vendor(
        "P10 write_then_replay_real_path_zzdds_vendor",
        Some(crate::protocol::constants::ZZDDS_LEGACY_VENDOR_ID_U16),
    );
}

/// Same probe under the vendor ID zzdds announces from 0.3.1 on: the
/// encapsulation downgrade must follow the stack, not one of its IDs.
#[test]
fn write_then_replay_real_path_zzdds_registered_vendor() {
    write_then_replay_real_path_with_vendor(
        "P10 write_then_replay_real_path_zzdds_registered_vendor",
        Some(crate::protocol::constants::ZZDDS_VENDOR_ID_U16),
    );
}

#[test]
fn write_then_replay_real_path_intercom_vendor() {
    write_then_replay_real_path_with_vendor(
        "P11 write_then_replay_real_path_intercom_vendor",
        Some(INTERCOM_VENDOR_ID_U16),
    );
}

// ---------------------------------------------------------------------
// P12: real write() of a fragmented (DATA_FRAG) sample vs replay_to
// ---------------------------------------------------------------------

/// A type with a variable-size field so a real, in-process `write()` can
/// be forced over `builder::DEFAULT_MAX_UNFRAGMENTED_SIZE` and produce a
/// genuine multi-fragment DATA_FRAG burst. `#[derive(hdds::DDS)]` from
/// INSIDE the `hdds` crate itself works because `lib.rs` declares
/// `extern crate self as hdds;` -- the derive macro's generated code
/// references `::hdds::...` paths exactly as an external consumer's
/// would, and that self-referential extern crate makes `hdds` resolve
/// from here too. Mirrors `tests/frag_user_data_e2e.rs`'s `BigBlob`
/// (an external integration test, so it never needed this trick).
#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct P12BigBlob {
    id: u32,
    data: Vec<u8>,
}

/// Collect every datagram on `sock` that carries a DATA_FRAG (0x16)
/// submessage for `expected_seq`. Unlike `recv_one` (which returns the
/// FIRST match and stops), this drains the WHOLE fragmented burst: every
/// fragment of one sample shares the same writer SN, so `recv_one` would
/// silently return after fragment 1 and never see the rest.
///
/// Stops on IDLE TIME SINCE THE LAST MATCHING FRAGMENT (`IDLE_GRACE`), not
/// idle time since the last READ of any kind: a real writer with a real
/// matched reader (P12 registers one, exactly like P9-P11) runs its
/// actual `HeartbeatScheduler` in the background, which keeps sending
/// periodic HEARTBEATs to this same capture socket for as long as the
/// writer lives -- an "idle since last read" rule would never see a gap
/// and would drain for as long as the scheduler keeps ticking (far
/// over 100s, vs. the whole fragmented burst
/// actually landing in well under `IDLE_GRACE` after `write()` returns).
/// `OVERALL_DEADLINE` is a hard backstop so a genuine delivery failure
/// times out in bounded time instead of hanging.
fn drain_data_frag_fragments(sock: &UdpSocket, expected_seq: u64) -> Vec<Vec<u8>> {
    const PER_READ_TIMEOUT: Duration = Duration::from_millis(50);
    const IDLE_GRACE: Duration = Duration::from_millis(250);
    const OVERALL_DEADLINE: Duration = Duration::from_secs(2);

    sock.set_read_timeout(Some(PER_READ_TIMEOUT))
        .expect("set short per-read timeout for the fragment drain loop");

    let mut fragments = Vec::new();
    let mut buf = [0u8; 65536];
    let start = std::time::Instant::now();
    let mut last_match = start;
    loop {
        if start.elapsed() >= OVERALL_DEADLINE {
            break;
        }
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                let pkt = buf[..n].to_vec();
                // `packet_carries_seq` walks the submessage chain generically
                // (it does not assume a fixed INFO_TS-or-not offset) and
                // matches DATA (0x15) or DATA_FRAG (0x16) carrying
                // `expected_seq` -- a HEARTBEAT (submessage id 0x07) never
                // matches, and is simply ignored here rather than resetting
                // any idle clock.
                if packet_carries_seq(&pkt, expected_seq) {
                    fragments.push(pkt);
                    last_match = std::time::Instant::now();
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if !fragments.is_empty() && last_match.elapsed() >= IDLE_GRACE {
                    break;
                }
            }
            Err(e) => panic!("capture socket I/O error (not a timeout): {}", e),
        }
    }
    fragments
}

/// A real `write()` of a payload over the fragmentation
/// threshold (`builder::should_fragment`) vs `replay_to` replaying the
/// SAME cached change, byte-identical INFO_TS and reader entity id
/// included. Same real-`Participant` shape as P9-P11 (see that
/// function's doc, including the leased-domain rationale), but with
/// `P12BigBlob` instead of `Temperature` so the live write() call itself
/// produces DATA_FRAG, not a single DATA.
#[test]
fn write_then_replay_real_path_fragmented() {
    use crate::dds::{Participant, QoS};

    let topic = format!("probe/p12_frag_write_replay_{}", claim_topic_seq());

    // Leased domain: see write_then_replay_real_path_with_vendor.
    let domain = unique_domain();
    let participant = Participant::builder("probe_p12")
        .domain_id(domain.id())
        .build()
        .expect("build a real Participant for P12 (rtps_endpoint requires one)");

    let writer = participant
        .topic::<P12BigBlob>(&topic)
        .expect("register topic for P12")
        .writer()
        .qos(QoS::reliable())
        .build()
        .expect("create a Reliable writer for P12 (Reliable is required for a history_cache)");

    // `drain_data_frag_fragments` sets its own short per-read timeout and
    // stops on idle-since-last-MATCH (see its doc), overriding
    // bind_capture's 2s default -- no manual timeout override needed here.
    let (capture, capture_addr) = bind_capture();
    let reader_guid = nack_reader_guid();
    let fsm = writer
        .discovery_fsm
        .clone()
        .expect("[probe P12] a real Participant must give the writer a discovery_fsm");
    register_matched_reader(
        &fsm,
        &topic,
        "P12BigBlob",
        reader_guid,
        capture_addr,
        Some(HDDS_VENDOR_ID_U16),
    );

    let ctx = writer
        .rtps_endpoint
        .expect("[probe P12] writer must have an rtps_endpoint (see module doc)");
    let transport = writer
        .transport
        .clone()
        .expect("[probe P12] writer must have a transport (Participant provides one)");
    let cache = writer
        .history_cache
        .clone()
        .expect("[probe P12] Reliable QoS must give the writer a history_cache");

    // Comfortably over DEFAULT_MAX_UNFRAGMENTED_SIZE (8192) once CDR-
    // encoded, forcing a genuine multi-fragment burst at the default
    // 1024-byte fragment size (roughly 20 fragments).
    let sample = P12BigBlob {
        id: 7,
        data: vec![0x5Au8; 20_000],
    };
    let seq = 1u64; // a freshly built writer's first write() always takes seq 1
    writer
        .write(&sample)
        .expect("[probe P12] real write() call");

    let live_fragments = drain_data_frag_fragments(&capture, seq);
    assert!(
        live_fragments.len() > 1,
        "P12 needs write() to actually fragment (got {} datagram(s)); the \
         payload is not over the fragmentation threshold",
        live_fragments.len()
    );

    // Force replay_to the SAME capture address, sharing the SAME
    // history_cache / transport / rtps_endpoint write() just used AND the
    // SAME discovery_fsm + reader GUID (see write_then_replay_real_path's
    // doc for the full rationale).
    let state = WriterReplayState::new(topic.clone(), Some(ctx), transport, cache, Some(fsm));
    state.replay_to(capture_addr, Some(reader_guid));
    let replayed_fragments = drain_data_frag_fragments(&capture, seq);

    assert_eq!(
        replayed_fragments.len(),
        live_fragments.len(),
        "replay_to must reproduce the exact SAME NUMBER of fragments write() sent"
    );

    // Compare as sorted multisets, not positionally: UDP delivery order
    // is not guaranteed (loopback usually preserves it, but nothing here
    // depends on that assumption holding).
    let mut live_sorted = live_fragments;
    let mut replayed_sorted = replayed_fragments;
    live_sorted.sort();
    replayed_sorted.sort();
    assert_eq!(
        live_sorted, replayed_sorted,
        "P12 write_then_replay_real_path_fragmented: every fragment (INFO_TS \
         and readerEntityId included) must be byte-identical between the \
         live write() burst and the replay_to burst"
    );
}

// ---------------------------------------------------------------------
// P13: the real late-joiner path, driven through DiscoveryFsm entry points
// ---------------------------------------------------------------------

/// The REAL late-joiner path, end to end, with NO hand-built
/// `WriterReplayState` and NO direct `replay_to` call anywhere in this
/// test -- unlike every probe above (P1-P12), which all drive `replay_to`
/// directly. Sequence:
///
/// 1. A real `Participant` builds a TRANSIENT_LOCAL Reliable writer and
///    calls the real `write()` BEFORE any reader exists at all (no SEDP
///    for a reader has been injected yet -- `send_packet_to_endpoints`
///    has no matched reader to unicast to, so nothing reaches the
///    capture socket at this point; the sample only lives in the
///    writer's `history_cache`).
/// 2. SPDP and SEDP for a capturing reader are injected through the
///    SAME real `DiscoveryFsm` entry points P9-P11 already use via
///    `register_matched_reader` (`handle_spdp` then `handle_sedp` --
///    see that helper's doc for why `default_unicast_locators` must be
///    non-empty).
/// 3. That `handle_sedp` call is the ENTIRE trigger: durability is
///    TRANSIENT_LOCAL and this is a newly-discovered reader, so
///    `handle_sedp`'s own internal logic (item 4's destination
///    resolution, item 6's deferred-past-the-lock `replay_for` firing)
///    resolves the destination and invokes the writer's replay callback
///    AUTOMATICALLY -- nothing in this test calls `replay_to` or even
///    names `WriterReplayState`.
///
/// The "live emission" reference is NOT a captured datagram (nothing was
/// ever sent live -- there was no reader to send it to): it is rebuilt
/// from the SAME journaled `CachedChange` `write()` produced, with the
/// SAME builder call `replay_to`'s small-payload branch uses, exactly
/// like P1-P8's hand-built-cache-entry references. This is a stronger
/// proof than P1-P8 for the SAME wire shape: here the metadata comes from
/// a REAL write() call, not test-authored `ChangeMetadata`.
#[test]
fn late_joiner_automatic_replay_via_real_discovery_fsm() {
    use crate::dds::{Participant, QoS};
    use crate::generated::temperature::Temperature;

    let topic = format!("probe/p13_late_joiner_{}", claim_topic_seq());

    // Leased domain: see write_then_replay_real_path_with_vendor.
    let domain = unique_domain();
    let participant = Participant::builder("probe_p13")
        .domain_id(domain.id())
        .build()
        .expect("build a real Participant for P13 (rtps_endpoint requires one)");

    let writer = participant
        .topic::<Temperature>(&topic)
        .expect("register topic for P13")
        .writer()
        .qos(QoS::reliable().transient_local())
        .build()
        .expect("create a TRANSIENT_LOCAL Reliable writer for P13");

    let cache = writer
        .history_cache
        .clone()
        .expect("[probe P13] TRANSIENT_LOCAL Reliable QoS must give the writer a history_cache");
    let ctx = writer
        .rtps_endpoint
        .expect("[probe P13] writer must have an rtps_endpoint (see module doc)");

    // Step 1: write BEFORE any reader exists. No SEDP for a reader has
    // been injected yet, so this cannot reach any capture socket live.
    let sample = Temperature {
        value: -12.5,
        timestamp: 1_700_000_100,
    };
    let seq = 1u64; // a freshly built writer's first write() always takes seq 1
    writer
        .write(&sample)
        .expect("[probe P13] real write() call");

    // Reference bytes: rebuilt from the SAME journaled CachedChange
    // write() produced, with the SAME builder replay_to's small-payload
    // branch uses (see this test's doc for why this -- not a captured
    // live datagram -- is the correct reference here).
    let journaled = cache
        .get_change(seq)
        .expect("[probe P13] write() must have journaled seq 1 in the history_cache");
    let expected = builder::build_data_packet_with_context_full_keyed_ts(
        &ctx,
        &topic,
        seq,
        &journaled.payload,
        journaled.metadata.cdr_version,
        journaled.metadata.source_ts,
        journaled.metadata.coherent_sn,
        journaled.metadata.group_sn,
        journaled.metadata.key_hash.as_ref(),
        journaled.metadata.key_epoch != 0,
    );
    assert!(!expected.is_empty(), "reference packet build must not fail");
    // Same per-reader wire transform replay_to's small-payload branch
    // applies via `finalize_for_reader` (item 1): the readerEntityId
    // patch. Vendor is HDDS here, so this is a no-op beyond that patch
    // (no encap downgrade, no HEADER_EXTENSION).
    let reader_guid_bytes = nack_reader_guid();
    let expected = super::runtime::finalize_for_reader(
        expected,
        super::runtime::ReaderWireProfile {
            entity_id: [
                reader_guid_bytes[12],
                reader_guid_bytes[13],
                reader_guid_bytes[14],
                reader_guid_bytes[15],
            ],
            vendor: Some(HDDS_VENDOR_ID_U16),
        },
        false,
    );

    // Step 2 + 3: inject SPDP then SEDP for a capturing reader through
    // the REAL DiscoveryFsm entry points -- this `handle_sedp` call is
    // the entire trigger for the automatic replay (see this test's doc).
    let (capture, capture_addr) = bind_capture();
    let reader_guid = nack_reader_guid();
    let fsm = writer
        .discovery_fsm
        .clone()
        .expect("[probe P13] a real Participant must give the writer a discovery_fsm");

    // NOT `register_matched_reader` (used by P9-P12): that helper leaves
    // the reader's SEDP `qos: None`, which materializes to the spec
    // default (VOLATILE) durability -- and `handle_sedp`'s replay trigger
    // gates on the DISCOVERED ENDPOINT's (here, the reader's) OWN
    // `qos.durability` being TRANSIENT_LOCAL/TRANSIENT/PERSISTENT, not the
    // writer's. A volatile reader would never trigger the replay this
    // probe exists to prove, so P13 announces the reader's durability
    // explicitly instead of reusing that helper.
    fsm.handle_spdp(crate::protocol::discovery::SpdpData {
        participant_guid: participant_guid_of(reader_guid),
        lease_duration_ms: 100_000,
        domain_id: 39,
        metatraffic_unicast_locators: vec![],
        default_unicast_locators: vec![capture_addr],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: Some(HDDS_VENDOR_ID_U16),
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    });
    fsm.handle_sedp(crate::protocol::discovery::SedpData {
        topic_name: topic.clone(),
        type_name: "Temperature".to_string(),
        participant_guid: participant_guid_of(reader_guid),
        endpoint_guid: GUID::from_bytes(reader_guid),
        qos_hash: 0,
        qos: Some(crate::dds::QoS {
            durability: crate::dds::qos::Durability::TransientLocal,
            ..crate::dds::QoS::default()
        }),
        type_object: None,
        dependents: Vec::new(),
        type_object_legacy_v1: false,
        type_information: None,
        unicast_locators: vec![capture_addr],
        user_data: None,
        shm_capability: None,
        has_explicit_reliability: false,
        has_explicit_ownership: false,
        has_ownership_strength: false,
        type_consistency: None,
        group_entity_id: None,
        endpoint_security_info: None,
    });

    let replayed = recv_one(&capture, seq).expect(
        "[probe P13] handle_sedp's automatic TRANSIENT_LOCAL replay must reach \
         the capture socket -- nothing in this test called replay_to directly",
    );

    report_and_assert_parity(
        "P13 late_joiner_automatic_replay_via_real_discovery_fsm",
        expected,
        replayed,
    );
}

/// RTPS 2.5 8.7.6 says an ECS "is not filtered by time,
/// content, history ... It can only be removed from the RTPS Writer cache
/// when all data samples belonging to the coherent set are removed". A
/// KEEP_LAST(1) durable keyed writer, two sets on distinct instances: every
/// member of set 1 is still in the history, so its close must be too, and a
/// late joiner must be replayed that close.
#[test]
fn keep_last_keeps_the_close_of_a_set_whose_members_remain() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x53; 12],
        reader_entity_id: [0u8; 4],
        writer_entity_id: [0x00, 0x00, 0x32, 0x02],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let topic = "probe/close_eviction";
    let source_ts = (0x1000_0021u32, 0x2000_0022u32);
    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        16,
        256 * 1024,
        History::KeepLast(1),
    ));
    let member = |first: u64, key: u8| ChangeMetadata {
        kind: ChangeKind::UserData,
        coherent_sn: Some(first),
        key_hash: Some([key; 16]),
        source_ts,
        source_ts_known: true,
        ..ChangeMetadata::user_data()
    };
    // Set 1 = {1 (key A), 2 (key B)}, closed at 3; set 4 = {4 (key C)},
    // closed at 5. No instance is written twice: no member is evicted.
    cache
        .insert_with_metadata(1, &[0xA1], 0, member(1, 0xA))
        .expect("1");
    cache
        .insert_with_metadata(2, &[0xA2], 0, member(1, 0xB))
        .expect("2");
    cache.insert_ecs_close(3, Some(2), None).expect("close 3");
    cache
        .insert_with_metadata(4, &[0xA4], 0, member(4, 0xC))
        .expect("4");
    cache.insert_ecs_close(5, Some(4), None).expect("close 5");
    assert!(cache.get_change(1).is_some() && cache.get_change(2).is_some());
    assert!(
        cache.get_change(3).is_some(),
        "the close of set 1 was evicted by the close of set 4 while every member of set 1 \
         is still in the history (RTPS 2.5 8.7.6: an ECS is not filtered by history)"
    );
    let reader_guid = nack_reader_guid();
    let fsm = fsm_with_vendor(reader_guid, Some(HDDS_VENDOR_ID_U16));
    let state = WriterReplayState::new(
        topic.to_string(),
        Some(ctx),
        writer_transport(),
        cache,
        Some(fsm),
    );
    let (capture, capture_addr) = bind_capture();
    state.replay_to(capture_addr, Some(reader_guid));
    capture
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let mut sent = Vec::new();
    let mut buf = [0u8; 65536];
    while let Ok((n, _)) = capture.recv_from(&mut buf) {
        sent.push(buf[..n].to_vec());
    }
    assert!(
        sent.iter().any(|pkt| packet_carries_seq(pkt, 3)),
        "close 3 replayed"
    );
}

/// The end of a GROUP set its writer had no part in is replayed to a
/// late joiner of the spec class, in the spec form, though no member of the
/// set is in the history; no other late joiner is replayed it.
#[test]
fn an_idle_end_of_set_is_replayed_to_spec_late_joiners_only() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x54; 12],
        reader_entity_id: [0u8; 4],
        writer_entity_id: [0x00, 0x00, 0x33, 0x02],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    for (vendor, capabilities, replayed) in [
        (
            HDDS_VENDOR_ID_U16,
            Some(crate::protocol::group::CAP_SPEC_GROUP_COHERENT),
            true,
        ),
        (HDDS_VENDOR_ID_U16, None, false),
        // A classic vendor would be sent a bare close marker: a close of a
        // set at a reader that never had a part of it.
        (0x0101, None, false),
    ] {
        let cache = Arc::new(HistoryCache::new_with_limits(
            Arc::new(SlabPool::new()),
            16,
            256 * 1024,
            History::KeepLast(16),
        ));
        // A change of an earlier set of the writer, still in the history:
        // the end of set is no orphan by the replay's member rule.
        cache
            .insert_with_metadata(
                2,
                &[0xA2],
                0,
                ChangeMetadata {
                    coherent_sn: Some(2),
                    source_ts_known: true,
                    ..ChangeMetadata::user_data()
                },
            )
            .expect("an earlier change");
        cache
            .insert_grouped_until(
                4,
                &[],
                0,
                ChangeMetadata {
                    kind: ChangeKind::EcsClose,
                    source_ts_known: true,
                    ..ChangeMetadata::user_data()
                },
                Some(crate::protocol::group::GroupTag {
                    gsn: 3,
                    writer_set: [1, 2, 3, 4],
                    set_first_gsn: Some(1),
                    part_first_sn: Some(4),
                }),
                None,
            )
            .expect("idle end of set");
        let reader_guid = nack_reader_guid();
        let fsm = fsm_with(reader_guid, Some(vendor), capabilities);
        let state = WriterReplayState::new(
            "probe/idle_replay".to_string(),
            Some(ctx),
            writer_transport(),
            cache,
            Some(fsm),
        );
        let (capture, capture_addr) = bind_capture();
        state.replay_to(capture_addr, Some(reader_guid));
        capture
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("timeout");
        let mut sent = Vec::new();
        let mut buf = [0u8; 65536];
        while let Ok((n, _)) = capture.recv_from(&mut buf) {
            sent.push(buf[..n].to_vec());
        }
        assert_eq!(
            sent.iter().any(|pkt| packet_carries_seq(pkt, 4)),
            replayed,
            "vendor {vendor:#06x} capabilities {capabilities:?}"
        );
    }
}

/// The history replay takes the door of the data plane (`replay_admits`,
/// DDS Security v1.1 Sec.8.8.7.1): `replay_to` sends nothing to a reader
/// the security plugins refuse - here an unauthenticated participant's
/// reader of a read-protected topic - nor to an unnamed one while a
/// security plugin judges remote readers; an unprotected topic's history
/// goes to the same reader. Whoever triggers the replay, the writer
/// applies the door itself.
#[cfg(feature = "security")]
#[test]
fn replay_to_a_reader_the_security_plugins_refuse_sends_nothing() {
    use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
    use crate::security::access::{
        BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
    };
    let rule = |expression: &str, protected: bool| TopicRule {
        topic_expression: expression.to_string(),
        enable_discovery_protection: false,
        enable_liveliness_protection: false,
        enable_read_access_control: protected,
        enable_write_access_control: protected,
        metadata_protection_kind: ProtectionKind::None,
        data_protection_kind: BasicProtectionKind::None,
    };
    let mut fsm = DiscoveryFsm::new(GUID::new([0x3C; 12], RTPS_ENTITYID_PARTICIPANT), 30_000);
    fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
        domains: vec![0],
        domain_ranges: vec![],
        allow_unauthenticated: true,
        enable_join_access_control: false,
        discovery_protection_kind: ProtectionKind::None,
        liveliness_protection_kind: ProtectionKind::None,
        rtps_protection_kind: ProtectionKind::None,
        topic_rules: vec![rule("probe/protected*", true), rule("*", false)],
    })));
    let fsm = Arc::new(fsm);
    let stranger_reader = GUID::new([0x33; 12], [0, 0, 1, 0x07]).as_bytes();
    let replay = |topic: &str, reader: Option<[u8; 16]>| -> bool {
        let ctx = RtpsEndpointContext {
            guid_prefix: [0x3C; 12],
            reader_entity_id: [0x00, 0x00, 0x01, 0x07],
            writer_entity_id: [0x00, 0x00, 0x01, 0x03],
            encapsulation_kind: 0x0007,
            publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
        };
        let cache = Arc::new(HistoryCache::new_with_limits(
            Arc::new(SlabPool::new()),
            16,
            256 * 1024,
            History::KeepLast(16),
        ));
        cache
            .insert_with_metadata(7, &[0xAB; 8], 0, ChangeMetadata::user_data())
            .expect("insert");
        let state = WriterReplayState::new(
            topic.to_string(),
            Some(ctx),
            writer_transport(),
            cache,
            Some(Arc::clone(&fsm)),
        );
        let (capture, capture_addr) = bind_capture();
        state.replay_to(capture_addr, reader);
        recv_one(&capture, 7).is_some()
    };
    assert!(
        replay("probe/free", Some(stranger_reader)),
        "fixture: an unprotected topic's history is replayed"
    );
    assert!(
        !replay("probe/protected", Some(stranger_reader)),
        "the history of a read-protected topic reached an unauthenticated reader"
    );
    assert!(
        !replay("probe/free", None),
        "a replay naming no reader went out while the plugins judge readers"
    );
}
