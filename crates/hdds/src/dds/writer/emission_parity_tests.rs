// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Differential live-vs-repair emission suite.
//!
//! The invariant under test: for a fixed (change, dialect), the bytes a
//! repair (history replay or NACK retransmit) emits for a cached change
//! must equal the bytes originally emitted live. Where this does not hold
//! yet, every RED test below names the divergence it exercises.
//!
//! RED tests (`#[ignore]`) are executable debt: they fail today and are
//! expected to turn green once a single pure emission function replaces
//! the divergent live/replay/NACK/ECS/dispose builder call sites. GREEN
//! tests lock today's *accidental* invariants (things that happen to
//! already agree).
//!
//! There is deliberately no "the ECS close form is stable across two calls"
//! check. Every byte `build_ecs_data_submessage` produces other than
//! INFO_TS is already a pure function of its arguments, so the only way to make two calls
//! compare equal is to mask out the INFO_TS region -- which would prove
//! nothing beyond "the timestamp is where we already know it is". That
//! kind of mask is an architecture leak, not a real invariant, so it is
//! left out.

use super::*;
use crate::core::rt;
use crate::dds::CdrVersion;
use crate::dds::QoS;
use crate::protocol::builder::{
    build_data_packet_with_context, build_data_packet_with_context_full_keyed,
    build_ecs_data_submessage, RtpsEndpointContext,
};
use crate::transport::UdpTransport;
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct LifecycleProbe {
    x: i32,
    y: i32,
}

/// The live path
/// (`build_data_packet_with_context_full_keyed`, `runtime.rs:776`) carries
/// the publisher's coherent-set state (PID_COHERENT_SET,
/// PID_GROUP_COHERENT_SET, PID_GROUP_ENTITY_ID) and the instance's
/// PID_KEY_HASH in inline QoS. Both the history-replay path
/// (`runtime.rs:289`) and the NACK repair path (`nack.rs:282`) terminate in
/// the plain `build_data_packet_with_context`, which forwards to the same
/// builder but hardcodes all three to `None`. A repair of a coherent-set
/// member or a keyed instance therefore drops information the original
/// wire bytes carried.
#[test]
#[ignore = "RED by design: repair strips coherent-set + key-hash inline QoS present on live bytes; goes green with the emit_canonical refactor"]
fn repair_strips_coherent_and_key_tags_present_on_live_bytes() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x20; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let topic = "coherent/topic";
    let seq = 5u64;
    let payload = vec![0x01, 0x02, 0x03, 0x04];
    let version = CdrVersion::Xcdr2;
    let key_hash = [0x42u8; 16];

    let live = build_data_packet_with_context_full_keyed(
        &ctx,
        topic,
        seq,
        &payload,
        version,
        Some(3), // coherent_sn: sample #3 of an open coherent set
        Some(9), // group_sn: GROUP-scope publisher GSN
        Some(&key_hash),
    );

    // Same (ctx, topic, seq, payload, version) as the live call above --
    // exactly what replay_to (runtime.rs:289) and the NACK handler
    // (nack.rs:282) build for this same cached change.
    let repair = build_data_packet_with_context(&ctx, topic, seq, &payload, version);

    assert_eq!(
        live, repair,
        "repair must reproduce the live wire bytes for a fixed (change, dialect); \
         today it silently drops PID_COHERENT_SET / PID_GROUP_COHERENT_SET / \
         PID_GROUP_ENTITY_ID / PID_KEY_HASH because the terminal builder call is \
         given None for all three instead of the write-time values"
    );
}

/// The cached body bytes are frozen with whatever CDR version was
/// negotiated at write time
/// (`effective_cdr_version()`, `runtime.rs:581`), but `CacheEntry`
/// (`history_cache.rs:24-32`) stores no version tag alongside them. Replay
/// and NACK repair re-derive the wire encapsulation header from
/// `default_version` (the writer's *stable* version) instead of the
/// per-write negotiated one -- so whenever those two differ, the repaired
/// header advertises a CDR version that does not match how the cached
/// bytes were actually encoded.
///
/// Closed: `ChangeMetadata::cdr_version` journals the version the cached
/// body was ACTUALLY encoded with, and `WriterReplayState::replay_to`
/// derives the wire encapsulation header from that journaled value
/// (`change.metadata.cdr_version`), not from any writer-level default;
/// `WriterReplayState` has no `default_version` field. The test drives the
/// real wired `replay_to` entry point rather than two raw builder calls
/// given two different explicit versions: a raw builder call has no way to
/// "know" a different write-time version on its own, so the property lives
/// in the WIRING (the repair entry point picking the journaled version),
/// not in the builder. See also the real-path probe
/// `realpath_parity_probes::replay_encapsulation_version` for the same
/// proof exercised end to end.
#[test]
fn repair_encapsulation_header_disagrees_with_the_version_the_body_was_encoded_with() {
    use super::runtime::WriterReplayState;
    use crate::core::rt::slabpool::SlabPool;
    use crate::qos::History;
    use crate::reliability::{ChangeKind, ChangeMetadata, HistoryCache};

    let ctx = RtpsEndpointContext {
        guid_prefix: [0x21; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        // @appendable: encap_kind_for_version maps this to a different
        // wire code per CdrVersion (0x0009 for Xcdr2, 0x0001 for Xcdr1),
        // so this canonical kind actually exercises the version-dependent
        // branch instead of a code path where both versions agree.
        encapsulation_kind: 0x0009,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let topic = "versioned/topic";
    let seq = 11u64;
    let payload = vec![0xAAu8; 4];
    // Deliberately Xcdr1: the OPPOSITE of ChangeMetadata::user_data()'s
    // own best-effort default (Xcdr2). If replay ever regressed to a
    // hardcoded/defaulted version instead of the journaled one, this
    // test would catch it (the header would come back as Xcdr2's wire
    // code instead of Xcdr1's).
    let write_time_version = CdrVersion::Xcdr1;
    let source_ts = (0x2121_2121u32, 0x3131_3131u32);

    let live = crate::protocol::builder::build_data_packet_with_context_ts(
        &ctx,
        topic,
        seq,
        &payload,
        write_time_version,
        source_ts,
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

    #[allow(deprecated)] // UdpTransport::with_port is deprecated, unrelated to this test
    let transport = Arc::new(
        crate::test_support::ports::with_reserved_ports(8, |[port]: [u16; 1]| {
            UdpTransport::with_port(port)
        })
        .expect("bind local UDP socket for writer transport (unit-test only) after 8 ephemeral-port attempts"),
    );
    let state = WriterReplayState::new(topic.to_string(), Some(ctx), transport, cache, None);

    let capture = crate::test_support::ports::bind_capture_socket();
    capture
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("set 2s read timeout on capture socket");
    let capture_addr = capture.local_addr().expect("capture socket local_addr");

    state.replay_to(capture_addr, None);

    let mut buf = [0u8; 65536];
    let (n, _) = capture
        .recv_from(&mut buf)
        .expect("replay_to must send exactly one repair datagram");
    let repaired = buf[..n].to_vec();

    assert_eq!(
        live, repaired,
        "replay_to must reproduce the live wire bytes byte-for-byte (encapsulation \
         header included) once the journaled write-time CDR version and source_ts \
         are replayed, instead of deriving the header from a writer-level default \
         the cached body was never actually encoded with"
    );
}

/// ECS close marker: `emit_ecs_data`
/// (`coherent.rs:179-251`) builds the live ECS close marker via
/// `build_ecs_data_submessage` (`packet.rs:497`, flags `0x03`,
/// PID_COHERENT_SET in inline QoS, no payload) and then caches an EMPTY
/// payload for that SN (`coherent.rs:225-234`, `cache.insert(seq, &[])`).
/// A NACK for that SN is answered by the generic small-payload branch
/// (`nack.rs:282`), which rebuilds via `build_data_packet_with_context` --
/// a plain DATA (flags `0x07`, TOPIC-only inline QoS) over the empty
/// cached stub. That is a different submessage form than what was
/// actually sent on the wire.
#[test]
#[ignore = "RED by design: NACK repair of an ECS marker's SN rebuilds a generic empty DATA, not the ECS wire form; goes green with the emit_canonical refactor"]
fn nack_repair_of_an_ecs_marker_slot_is_not_the_ecs_wire_form() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x22; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let topic = "coherent/ecs_topic";
    let seq = 7u64;
    let coherent_sn = 7u64;

    // Live close form (coherent.rs:202): D=0 K=0 Q=1, PID_COHERENT_SET only
    // (writer-scope, no GROUP tag).
    let live_close = build_ecs_data_submessage(&ctx, topic, seq, coherent_sn, None, None);

    // What a NACK for `seq` produces today: emit_ecs_data cached an empty
    // payload for this SN (coherent.rs:226), so the generic small-payload
    // NACK branch (nack.rs:282) rebuilds it as a plain DATA over that
    // empty stub.
    let nack_repair = build_data_packet_with_context(&ctx, topic, seq, &[], CdrVersion::Xcdr2);

    assert_eq!(
        live_close, nack_repair,
        "a NACK repair of an ECS marker's SN must reproduce the ECS wire form \
         (flags 0x03, PID_COHERENT_SET); today it rebuilds a generic empty DATA \
         (flags 0x07, TOPIC-only inline QoS) instead"
    );
}

/// Dispose/unregister:
/// `send_lifecycle_change` (`runtime.rs:1187-1226`) fetches a fresh writer
/// SN (`self.next_seq.fetch_add`, `runtime.rs:1210`) and sends a DATA with
/// PID_STATUS_INFO on the wire, but never calls `history_cache.insert` for
/// that SN anywhere in the function. A NACK later addressed to that SN
/// therefore hits a cache miss: `WriterRetransmitHandler` either GAPs it
/// or silently skips it (`writer.rs:429-447`), and the StatusInfo intent
/// is never re-emitted.
///
/// This drives `DataWriter::dispose()` -- the public API that reaches
/// `send_lifecycle_change` -- directly, which is the honest way to prove
/// "SN consumed, cache skipped" from outside the module. The only
/// complication: `send_lifecycle_change` early-returns unless both
/// `transport` and `rtps_endpoint` are `Some`, and the only production
/// path that populates `rtps_endpoint` announces the writer through a live
/// `DomainParticipant` (SEDP), which is far more scaffolding than this
/// unit test needs. Since `rtps_endpoint` is just a plain `Copy` struct
/// with no participant-owned state, this test assigns it directly instead
/// of standing up a participant -- the smallest seam that still exercises
/// the real `dispose()` -> `send_lifecycle_change` code path end to end.
#[test]
#[ignore = "RED by design: dispose()/unregister_instance() consume a writer SN but never insert a HistoryCache entry for it; goes green with the emit_canonical refactor"]
#[allow(deprecated)] // UdpTransport::with_port is deprecated, unrelated to this test
fn dispose_consumes_a_writer_sn_but_never_journals_it_in_the_history_cache() {
    let _ = rt::init_slab_pool();

    let transport = crate::test_support::ports::with_reserved_ports(8, |[port]: [u16; 1]| {
        UdpTransport::with_port(port)
    })
    .expect("bind local UDP socket for writer transport (unit-test only, no remote peer) after 8 ephemeral-port attempts");

    let mut writer = WriterBuilder::<LifecycleProbe>::new("test/lifecycle_journal".to_string())
        .qos(QoS::reliable())
        .with_transport(Arc::new(transport))
        .build()
        .expect("writer build should succeed");

    // No live DomainParticipant in this test; hand-assign the same Copy
    // struct a SEDP announcement would have produced (see doc comment
    // above for why this is the smallest honest seam).
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x25; 12],
        reader_entity_id: [0x00, 0x00, 0x00, 0x00],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });

    let cache = writer
        .history_cache
        .clone()
        .expect("QoS::reliable() must allocate a HistoryCache");

    let seq_before = writer.next_seq.load(Ordering::Relaxed);
    let _ = writer.dispose(&LifecycleProbe { x: 1, y: 2 });
    let seq_after = writer.next_seq.load(Ordering::Relaxed);

    assert_eq!(
        seq_after,
        seq_before + 1,
        "dispose() must consume exactly one writer SequenceNumber_t (RTPS v2.5 section 8.3.5.4)"
    );

    let disposed_seq = seq_before;
    assert!(
        cache.get(disposed_seq).is_some(),
        "dispose() consumed writer SN {} but the HistoryCache has no entry for \
         it; a NACK addressed to this SN today gets a GAP or a silent skip \
         instead of a StatusInfo repair",
        disposed_seq
    );
}

/// `source_ts` is an explicit INPUT to every DATA-emitting builder
/// (`build_data_packet_with_context_ts` and friends, `packet.rs`),
/// captured ONCE at the write() site (`runtime.rs`'s small-DATA branch)
/// and journaled in `ChangeMetadata::source_ts` (`history_cache.rs`) so a
/// later repair replays the SAME timestamp instead of stamping a fresh
/// one.
///
/// REPLACES a tautology of the same name that called the same PURE
/// builder function twice with the SAME hand-supplied `source_ts` and
/// checked the outputs matched -- true for any pure function regardless
/// of whether `write()` ever captures a real clock read, so it proved
/// nothing about the actual journaling behavior. This drives TWO REAL
/// `DataWriter::write()` calls of the SAME writer, separated by a real
/// sleep, and asserts the JOURNALED `source_ts` values actually DIFFER
/// (write() really reads the clock fresh each call), while a repair of
/// each cached change reproduces exactly ITS OWN timestamp -- not the
/// other call's, and not a third, unrelated one.
#[test]
#[allow(deprecated)] // UdpTransport::with_port is deprecated, unrelated to this test
fn live_writes_journal_distinct_source_ts_and_each_repair_reproduces_its_own() {
    let _ = rt::init_slab_pool();

    let transport = crate::test_support::ports::with_reserved_ports(8, |[port]: [u16; 1]| {
        UdpTransport::with_port(port)
    })
    .expect("bind local UDP socket for writer transport (unit-test only, no remote peer) after 8 ephemeral-port attempts");

    let mut writer = WriterBuilder::<LifecycleProbe>::new("test/source_ts_journal".to_string())
        .qos(QoS::reliable())
        .with_transport(Arc::new(transport))
        .build()
        .expect("writer build should succeed");

    // No live DomainParticipant needed for this test either -- see
    // `dispose_consumes_a_writer_sn_but_never_journals_it_in_the_history_cache`'s
    // doc comment for why hand-assigning `rtps_endpoint` is the smallest
    // honest seam that still exercises the real write() code path.
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x26; 12],
        reader_entity_id: [0x00, 0x00, 0x00, 0x00],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    writer.rtps_endpoint = Some(ctx);

    let cache = writer
        .history_cache
        .clone()
        .expect("QoS::reliable() must allocate a HistoryCache");
    // A VOLATILE writer keeps a change only while a matched reliable reader
    // still owes an acknowledgement for it (nothing is owed with no reader
    // at all). Match one, as discovery would, so both writes are owed.
    super::nack::track_reader_proxy(
        &writer.ack_track,
        &cache,
        true,
        crate::dds::match_notification::PeerChange::Matched {
            guid: crate::core::discovery::GUID::new([0x27; 12], [0x00, 0x00, 0x01, 0x04]),
            reliable: true,
            volatile: false,
        },
    );

    let seq1 = writer.next_seq.load(Ordering::Relaxed);
    writer
        .write(&LifecycleProbe { x: 1, y: 2 })
        .expect("first real write() call");
    // The RTPS Time_t fraction field has ~2^-32s resolution; a few
    // milliseconds of real sleep is many orders of magnitude more than
    // enough to roll it (and very likely the whole-second field too).
    std::thread::sleep(std::time::Duration::from_millis(5));
    let seq2 = writer.next_seq.load(Ordering::Relaxed);
    writer
        .write(&LifecycleProbe { x: 3, y: 4 })
        .expect("second real write() call");

    let change1 = cache
        .get_change(seq1)
        .expect("first write() must journal a change");
    let change2 = cache
        .get_change(seq2)
        .expect("second write() must journal a change");

    assert!(
        change1.metadata.source_ts_known && change2.metadata.source_ts_known,
        "both real write() calls must journal a captured source_ts, not the \
         unknown/legacy sentinel"
    );
    assert_ne!(
        change1.metadata.source_ts, change2.metadata.source_ts,
        "two real write() calls separated by a real sleep must journal DIFFERENT \
         source_ts values -- write() reads the clock fresh each call, this is not \
         a fixed/frozen value"
    );

    // Each repair reproduces exactly its OWN call's timestamp: rebuild the
    // small-DATA packet from each journaled change and confirm swapping in
    // the OTHER change's timestamp actually changes the wire bytes -- i.e.
    // the INFO_TS field genuinely carries the value under test, and a
    // repair is not silently ignoring it or reproducing a third value.
    let repaired1 = crate::protocol::builder::build_data_packet_with_context_ts(
        &ctx,
        "test/source_ts_journal",
        seq1,
        &change1.payload,
        change1.metadata.cdr_version,
        change1.metadata.source_ts,
    );
    let repaired1_with_seq2_ts = crate::protocol::builder::build_data_packet_with_context_ts(
        &ctx,
        "test/source_ts_journal",
        seq1,
        &change1.payload,
        change1.metadata.cdr_version,
        change2.metadata.source_ts,
    );
    assert_ne!(
        repaired1, repaired1_with_seq2_ts,
        "repairing seq1's change with seq2's journaled timestamp must NOT \
         reproduce the same bytes as repairing it with its own -- otherwise \
         the timestamp asserted above would not be the one actually on the wire"
    );
}

/// Locks today's accidental invariant: the history-replay path (`replay_to`,
/// `runtime.rs:289`) and the NACK repair path (`nack.rs:282`) both
/// terminate in `build_data_packet_with_context` with the exact same
/// argument set (ctx, topic, seq, payload, default_version) for a small
/// (non-fragmented) cached sample -- so today they are byte-identical to
/// EACH OTHER, even though both diverge from what LIVE originally sent
/// (see the RED tests above). If the pure-emission refactor ever gives
/// replay and NACK different inputs for the same cached change, this
/// regression test should catch it.
///
/// INFO_TS (bytes 24..32: RTPS header 20 bytes + INFO_TS submessage header
/// 4 bytes) is masked because the two builder calls below happen at
/// different wall-clock instants; that non-determinism is the subject of
/// its own RED test above and is orthogonal to whether replay and NACK
/// agree on everything else.
#[test]
fn replay_and_nack_repair_paths_agree_on_repair_bytes() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x23; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let topic = "replay/nack_parity";
    let seq = 13u64;
    let payload = vec![0x10, 0x20, 0x30];
    let default_version = CdrVersion::Xcdr2;

    let mut replay_side =
        build_data_packet_with_context(&ctx, topic, seq, &payload, default_version);
    let mut nack_side = build_data_packet_with_context(&ctx, topic, seq, &payload, default_version);

    for pkt in [&mut replay_side, &mut nack_side] {
        assert!(pkt.len() >= 32, "packet too short to carry INFO_TS");
        for b in &mut pkt[24..32] {
            *b = 0;
        }
    }

    assert_eq!(
        replay_side, nack_side,
        "replay and NACK repair must at least agree with each other on a fixed \
         (change, dialect), modulo the INFO_TS timestamp"
    );
}
