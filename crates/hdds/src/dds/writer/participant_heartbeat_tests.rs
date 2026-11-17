// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The periodic HEARTBEAT path end to end, through a real `Participant`
//! (RTPS v2.5 Sec.8.4.7.2): a reliable writer built with a participant
//! schedules its periodic HEARTBEAT on that participant's liveliness
//! scheduler (`crate::dds::liveliness`, `HeartbeatPeriodic::Participant`)
//! instead of a dedicated thread, driven here by an injected
//! `ManualClock` instead of real time, and decoded from the actual wire
//! bytes rather than the in-process `HeartbeatSchedulerState` counters.

use crate::dds::liveliness::ManualClock;
use crate::{Participant, QoS, TransportMode};
use std::sync::{Arc, Weak};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct Ping {
    id: u32,
}

/// RAII: sets the barrier's flag and notifies its condvar when dropped,
/// whatever the reason -- normal return, or an assertion panicking
/// partway through. A plain `*release.0.lock()... = true` right before
/// each `return`/assertion, repeated at every exit point, is easy to
/// miss on at least one path (a panic between arming and the manual
/// release would leave a worker thread stuck on the barrier forever). Binding this as `let
/// _guard = ReleaseOnDrop(...)` right after arming covers every exit.
struct ReleaseOnDrop(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        *self.0 .0.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.0 .1.notify_all();
    }
}

/// RAII: joins a spawned thread when dropped, whatever the reason. Pairs
/// with a release/stop guard declared AFTER it in source (Rust drops
/// locals in reverse declaration order, so the later-declared release
/// guard runs first, unblocking the thread, before this one joins it).
/// A test holding `peers` and running a keepalive thread with no RAII
/// at all would, on an assertion panicking between arming and manual
/// cleanup, leave both stuck forever, hanging the process on this
/// test's own participant teardown.
struct JoinOnDrop(Option<std::thread::JoinHandle<()>>);

impl Drop for JoinOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            let _ = handle.join();
        }
    }
}

/// RAII: flips an `AtomicBool` stop flag when dropped. See `JoinOnDrop`'s
/// doc for the declaration-order pairing this relies on.
struct StopOnDrop(Arc<std::sync::atomic::AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The full 16-byte writer GUID (12-byte participant GUID prefix +
/// 4-byte entity id) `send_seam` keys on, read off a writer's own RTPS
/// context the same way `transport::udp::send_seam::intercept` reads it
/// off the wire.
fn writer_guid_of<T: crate::dds::DDS>(writer: &super::DataWriter<T>) -> [u8; 16] {
    let ctx = writer.rtps_endpoint.expect("writer has an rtps context");
    let mut guid = [0u8; 16];
    guid[..12].copy_from_slice(&ctx.guid_prefix);
    guid[12..].copy_from_slice(&ctx.writer_entity_id);
    guid
}

/// A socket joined to the user-data multicast group of `p`'s domain, on
/// the loopback interface -- the multicast fallback
/// `heartbeat_scheduler::send_heartbeat_to_readers` uses for a writer
/// with no matched reader.
fn user_multicast_capture(p: &Participant) -> std::net::UdpSocket {
    let port = p.transport().expect("transport").data_multicast_port();
    let group: std::net::Ipv4Addr = crate::config::MULTICAST_GROUP.parse().expect("group");
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .expect("socket");
    socket.set_reuse_address(true).expect("reuse");
    socket
        .bind(&std::net::SocketAddr::from(([0, 0, 0, 0], port)).into())
        .expect("bind");
    socket
        .join_multicast_v4(&group, &std::net::Ipv4Addr::LOCALHOST)
        .expect("join");
    let socket: std::net::UdpSocket = socket.into();
    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    socket
}

/// Every HEARTBEAT submessage's (firstSN, lastSN, count) in `pkt`, walked
/// by hand (RTPS v2.5 9.4.1, 9.4.5.7): after the 20-octet header, each
/// submessage is id (1), flags (1), octetsToNextHeader (2, in the E
/// flag's endianness); a HEARTBEAT (0x07) body is readerId (4), writerId
/// (4), firstSN (8), lastSN (8), count (4), each SequenceNumber_t being
/// high:i32 then low:u32.
fn heartbeats_in(pkt: &[u8]) -> Vec<(u64, u64, u32)> {
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
        let len = u16_at([pkt[at + 2], pkt[at + 3]]) as usize;
        if id == 0x07 && at + 4 + 28 <= pkt.len() {
            let body = at + 4;
            let first = (u64::from(u32_at(body + 8)) << 32) | u64::from(u32_at(body + 12));
            let last = (u64::from(u32_at(body + 16)) << 32) | u64::from(u32_at(body + 20));
            let count = u32_at(body + 24);
            found.push((first, last, count));
        }
        if len == 0 {
            break;
        }
        at += 4 + len;
    }
    found
}

/// Every HEARTBEAT submessage's writerEntityId in `pkt` (RTPS v2.5
/// 9.4.5.7: readerId at body+0, writerId at body+4), walked the same way
/// `heartbeats_in` walks (first,last,count) -- kept separate rather than
/// widening that helper's tuple, since only the progress test below
/// needs writer identity (to tell writer A's HEARTBEAT apart from
/// writer B's when both share the same multicast fallback destination).
/// Every HEARTBEAT submessage's full writer GUID in `pkt`: the 12-byte
/// participant GUID prefix from the RTPS header (bytes 8..20) plus the
/// 4-byte writerEntityId from the HEARTBEAT body (readerId at body+0,
/// writerId at body+4 -- RTPS v2.5 9.4.5.7). Matches
/// `transport::udp::send_seam`'s keying exactly (entity ids alone
/// restart on every participant and can collide across parallel tests).
fn heartbeat_writer_guids_in(pkt: &[u8]) -> Vec<[u8; 16]> {
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
        let len = u16_at([pkt[at + 2], pkt[at + 3]]) as usize;
        if id == 0x07 && at + 4 + 8 <= pkt.len() && pkt.len() >= 20 {
            let body = at + 4;
            let mut writer_guid = [0u8; 16];
            writer_guid[..12].copy_from_slice(&pkt[8..20]);
            writer_guid[12..].copy_from_slice(&pkt[body + 4..body + 8]);
            found.push(writer_guid);
        }
        if len == 0 {
            break;
        }
        at += 4 + len;
    }
    found
}

fn drain_heartbeats(sock: &std::net::UdpSocket) -> Vec<(u64, u64, u32)> {
    let mut found = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok((n, _)) = sock.recv_from(&mut buf) {
        found.extend(heartbeats_in(&buf[..n]));
    }
    found
}

/// Polls (bounded, 30 s) until `watch`'s HEARTBEAT admission slot
/// (`HeartbeatPending`) is free. Advancing a `ManualClock` to the next
/// period right after a signal that only confirms `fire()` RETURNED -- `HeartbeatPending::
/// end()`, which actually frees the slot, runs later still, from
/// `HeartbeatJob::Drop` in the worker's own loop (after any panic is
/// logged there too). Advancing before that release coalesces the next
/// period's tick away instead of dispatching it. Checks the real
/// admission state directly rather than inferring it from a signal's
/// timing.
fn wait_for_admission_released(watch: &crate::dds::liveliness::HeartbeatWatchHandle) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while watch.pending().is_busy_for_test() {
        assert!(
            std::time::Instant::now() < deadline,
            "HEARTBEAT admission slot never released within 30s"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// RTPS v2.5 Sec.8.4.7.2: a reliable writer with unacked data sends a
/// HEARTBEAT every period, unprompted by any write(). Scheduled on the
/// participant, the periodic HEARTBEAT must still reach
/// the wire on every tick of the participant's liveliness clock, with a
/// monotonically increasing count.
#[test]
fn a_reliable_writer_sends_a_heartbeat_every_period_from_the_participant_scheduler() {
    let clock = Arc::new(ManualClock::new(0));
    let domain = crate::test_support::domains::unique_domain();
    let mut builder = Participant::builder("periodic-hb-participant")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast);
    builder.liveliness_clock = Some(clock.clone());
    let participant = builder.build().expect("participant");
    let capture = user_multicast_capture(&participant);
    let topic = participant
        .topic::<Ping>("PeriodicHeartbeatFromScheduler")
        .expect("topic");
    let writer = topic
        .writer()
        .qos(QoS::reliable())
        .build()
        .expect("reliable writer");
    writer.write(&Ping { id: 1 }).expect("write");
    drain_heartbeats(&capture); // discard the on-write ("piggyback") one, if any

    let shared = participant
        .liveliness
        .as_ref()
        .expect("liveliness")
        .shared();
    let mut counts = Vec::new();
    for _ in 0..3 {
        clock.advance(Duration::from_millis(100));
        shared.settle();
        let heartbeats = drain_heartbeats(&capture);
        assert!(
            !heartbeats.is_empty(),
            "the participant's scheduler must have fired a periodic HEARTBEAT"
        );
        for (first, last, count) in heartbeats {
            assert_eq!((first, last), (1, 1), "the single write is SN 1");
            counts.push(count);
        }
    }
    for pair in counts.windows(2) {
        assert!(
            pair[1] > pair[0],
            "the HEARTBEAT count must be strictly monotonic: {counts:?}"
        );
    }

    drop(writer);
    clock.advance(Duration::from_secs(10));
    shared.settle();
    assert!(
        drain_heartbeats(&capture).is_empty(),
        "no HEARTBEAT reaches the wire after the writer is dropped"
    );
}

/// Threads named `comm` in the whole process (`/proc/self/task`): the
/// same counting technique as `dds::reader::tests_verify_barrier2`'s
/// `presentation_threads`. Counts process-wide, so this test (like that
/// one) must run alone.
fn threads_named(comm: &str) -> usize {
    std::fs::read_dir("/proc/self/task")
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter(|e| {
                    std::fs::read_to_string(e.path().join("comm")).is_ok_and(|c| c.trim() == comm)
                })
                .count()
        })
        .unwrap_or(0)
}

/// One participant with 50 reliable writers runs no per-writer
/// "hdds-heartbeat" threads (`spawn_heartbeat_scheduler` would start one
/// per writer): every one of them is an entry on the participant's
/// single "hdds-liveliness" scheduler thread, which already serves
/// LIVELINESS and DEADLINE.
#[test]
#[ignore = "counts process threads: run alone"]
fn fifty_reliable_writers_add_no_heartbeat_threads() {
    let domain = crate::test_support::domains::unique_domain();
    let participant = Participant::builder("fifty-writers-participant")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let liveliness_threads_before = threads_named("hdds-liveliness");
    assert_eq!(
        liveliness_threads_before, 1,
        "one scheduler thread per participant, already running"
    );

    let mut writers = Vec::new();
    for i in 0..50u32 {
        let topic = participant
            .topic::<Ping>(&format!("FiftyWriters{i}"))
            .expect("topic");
        let writer = topic
            .writer()
            .qos(QoS::reliable())
            .build()
            .expect("reliable writer");
        writer.write(&Ping { id: i }).expect("write");
        writers.push(writer);
    }

    assert_eq!(
        threads_named("hdds-heartbeat"),
        0,
        "50 reliable writers on one participant add zero per-writer HEARTBEAT threads"
    );
    assert_eq!(
        threads_named("hdds-liveliness"),
        1,
        "still the same one scheduler thread, now also carrying 50 HEARTBEAT entries"
    );
    // Spawning a brand new `hdds-notices` thread for every nonempty
    // delivery batch would create hundreds of threads per second with 50
    // writers at ~100ms. Dispatch uses one single, long-lived
    // `hdds-hb-sender` worker, never more:
    // see `fifty_writers_idle_creates_no_new_heartbeat_send_threads` for
    // the creation-rate measurement across several periods.
    assert_eq!(
        threads_named("hdds-hb-sender"),
        1,
        "one long-lived bounded sender per participant, not one thread per batch"
    );

    drop(writers);
    drop(participant);
    assert_eq!(
        crate::test_support::threads::settled(&0usize, || threads_named("hdds-liveliness")),
        0,
        "the participant's scheduler thread is joined, bounded, on drop"
    );
    assert_eq!(
        threads_named("hdds-hb-sender"),
        0,
        "the sender worker is joined, bounded, right along with it"
    );
}

/// Only the periodic HEARTBEAT path may use the best-effort, non-blocking
/// send (`UdpTransport::send_user_data_unicast_best_effort` /
/// `send_user_data_multicast_best_effort`): a slow or unresponsive
/// destination must never be able to block the single `hdds-hb-sender`
/// worker thread that serves every OTHER writer's periodic HEARTBEAT too
/// (see `dds::liveliness::scheduler`'s module doc). `write()`'s DATA
/// sample and its on-write ("piggyback") HEARTBEAT must keep the exact
/// blocking send -- only the periodic scheduler tick's semantics differ.
///
/// Mutant: routing `send_heartbeat_to_readers`'s transmit calls through
/// `WriterWindows::send_classed` / `UdpTransport::
/// send_user_data_multicast` (the blocking originals) instead of their
/// `_best_effort` twins makes the periodic-tick assertion below fail (the
/// best-effort counter never moves); routing `write()`'s DATA or its
/// piggyback HEARTBEAT through a `_best_effort` call instead would make
/// the "write() path is unchanged" assertion fail instead (the blocking
/// counter would stop moving on `write()`).
#[test]
fn only_the_periodic_heartbeat_uses_the_best_effort_send() {
    let clock = Arc::new(ManualClock::new(0));
    let domain = crate::test_support::domains::unique_domain();
    let mut builder = Participant::builder("best-effort-wiring")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast);
    builder.liveliness_clock = Some(clock.clone());
    let participant = builder.build().expect("participant");
    let transport = participant.transport().expect("transport");
    let capture = user_multicast_capture(&participant);
    let topic = participant
        .topic::<Ping>("BestEffortWiring")
        .expect("topic");
    let writer = topic.writer().qos(QoS::reliable()).build().expect("writer");

    assert_eq!(transport.blocking_sends_for_test(), 0, "nothing sent yet");
    assert_eq!(
        transport.best_effort_sends_for_test(),
        0,
        "nothing sent yet"
    );

    writer.write(&Ping { id: 1 }).expect("write");
    drain_heartbeats(&capture);
    let blocking_after_write = transport.blocking_sends_for_test();
    assert!(
        blocking_after_write > 0,
        "the DATA sample and its piggyback HEARTBEAT must use the ordinary blocking send"
    );
    assert_eq!(
        transport.best_effort_sends_for_test(),
        0,
        "write() must never touch the best-effort send path"
    );

    let shared = participant
        .liveliness
        .as_ref()
        .expect("liveliness")
        .shared();
    clock.advance(Duration::from_millis(100));
    shared.settle();
    drain_heartbeats(&capture);
    assert!(
        transport.best_effort_sends_for_test() > 0,
        "the periodic scheduler tick must use the best-effort send"
    );
    assert_eq!(
        transport.blocking_sends_for_test(),
        blocking_after_write,
        "the periodic tick must not also count as a blocking send"
    );
}

/// `send_heartbeat_to_readers` is a shared
/// helper -- the periodic scheduler is not its only caller. The on-write
/// ("piggyback") HEARTBEAT (`maybe_send_heartbeat`) and the
/// MANUAL_BY_TOPIC `assert_liveliness()` HEARTBEAT
/// (`assert_liveliness_heartbeat`) must keep passing `best_effort =
/// false`: only the periodic origin may ask for the non-blocking send.
/// `only_the_periodic_heartbeat_uses_the_best_effort_send` above checks
/// this too, but piggyback's `Instant`-based deadline normally has not
/// elapsed right after `build()`, so that test exercises DATA only and
/// would not catch a regression where piggyback and manual-assert quietly
/// route through `best_effort = true` as well.
/// This test forces piggyback due WITHOUT relying on wall-clock luck (no
/// sleep racing `Instant::now()`): it replaces the writer's `HeartbeatTx`
/// with a zero-period, zero-jitter one, whose deadline is `Instant::
/// now()` at construction and therefore already in the past by the time
/// the next `write()` checks it.
///
/// Mutant: passing `true` instead of `false` for `best_effort` from
/// either `maybe_send_heartbeat` or `assert_liveliness_heartbeat` makes
/// this fail -- the blocking-send counter stops moving for that call and
/// the best-effort one moves instead.
#[test]
fn piggyback_and_manual_assert_heartbeats_keep_the_blocking_send() {
    let domain = crate::test_support::domains::unique_domain();
    let mut qos = QoS::reliable();
    qos.liveliness.kind = crate::dds::qos::LivelinessKind::ManualByTopic;
    let participant = Participant::builder("piggyback-stays-blocking")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let transport = participant.transport().expect("transport");
    let topic = participant
        .topic::<Ping>("PiggybackStaysBlocking")
        .expect("topic");
    let writer = topic.writer().qos(qos).build().expect("writer");

    // Force piggyback due on the very next write(), deterministically:
    // a zero-period, zero-jitter HeartbeatTx's deadline is Instant::now()
    // at construction, already past by the time write() checks it.
    *writer
        .heartbeat_tx
        .as_ref()
        .expect("a reliable writer has a heartbeat_tx")
        .borrow_mut() = crate::reliability::HeartbeatTx::with_period_ms(0, 0);

    assert_eq!(transport.blocking_sends_for_test(), 0, "nothing sent yet");
    assert_eq!(
        transport.best_effort_sends_for_test(),
        0,
        "nothing sent yet"
    );

    writer.write(&Ping { id: 1 }).expect("write");
    let blocking_after_write = transport.blocking_sends_for_test();
    assert!(
        blocking_after_write > 0,
        "the DATA sample and its now-due piggyback HEARTBEAT must use the ordinary blocking send"
    );
    assert_eq!(
        transport.best_effort_sends_for_test(),
        0,
        "the piggyback HEARTBEAT must never use the best-effort send"
    );

    writer.assert_liveliness().expect("assert_liveliness");
    assert!(
        transport.blocking_sends_for_test() > blocking_after_write,
        "MANUAL_BY_TOPIC assert_liveliness's HEARTBEAT must use the ordinary blocking send"
    );
    assert_eq!(
        transport.best_effort_sends_for_test(),
        0,
        "assert_liveliness's HEARTBEAT must never use the best-effort send"
    );
}

/// The actual progress claim: a stuck destination for ONE
/// writer must not starve every OTHER writer's periodic HEARTBEAT
/// queued behind it on the single `hdds-hb-sender` worker, which is
/// still strictly serial, unchanged (`dds::liveliness::scheduler`'s
/// module doc). `send_seam` (test-only, `transport::udp::send_seam`)
/// makes writer A's HEARTBEAT behave exactly as if its kernel send
/// buffer were genuinely full: `Err(WouldBlock)` at once for the
/// best-effort call the periodic path makes, or an indefinite, externally
/// releasable block for the ordinary blocking one -- what a blocking
/// periodic send would cause. Writer B, created after A
/// so it dispatches behind it on the worker (`leases::Core`'s heap
/// breaks same-deadline ties by ascending `WatchKey`, itself ascending
/// by creation order), must still get its own HEARTBEAT within a
/// bounded wait, every period.
///
/// Neither writer has a matched reader, so both reach the wire through
/// the SAME multicast fallback address -- this covers that path
/// specifically (hence keying the seam on the HEARTBEAT's own full
/// writer GUID, not on the destination, which is identical for both
/// writers here). The per-reader unicast call shares the exact same
/// syscall-level interception with no branch on destination, and its
/// own happy-path wiring is separately pinned by
/// `transport::udp::tests::best_effort_unicast_send_delivers_like_the_
/// blocking_one`; a live cross-participant matched-reader variant of
/// THIS two-writer scenario is not built (real SPDP/SEDP discovery
/// timing would need further clock-injection plumbing, and risks
/// flakiness disproportionate to what it would add here).
///
/// The seam is keyed by the FULL 16-byte writer GUID (participant
/// prefix + entity id), not the 4-byte entity id alone: entity ids restart
/// from the same small range on every participant, so a parallel test's
/// unrelated participant could collide on just the id.
///
/// The seam's interception sits at the actual send syscall
/// (`best_effort_send_to`), reading the REAL flags that call is about
/// to make, so it can tell a correct `MSG_DONTWAIT` request apart from
/// a mutant that silently drops it (a higher-level interception
/// point would return before that flag was ever read, so removing it
/// would leave this test green).
///
/// Mutant: route `fire_heartbeat_tick`'s call to `send_heartbeat_to_
/// readers` with `best_effort = false` instead of `true`, OR zero out
/// `best_effort_send_to`'s `flags`, and this test fails -- B's
/// HEARTBEAT never arrives within the bound, because the worker is
/// stuck inside A's armed, releasable block. It fails, it does not
/// hang: the capture socket's read is bounded (2 s), and A's barrier is
/// released on cleanup regardless of the outcome (RAII, runs even if an
/// assertion below panics), before any assertion can panic past it.
// On Windows, `best_effort_send_to`
// has no non-blocking flag to request at all (`send_seam::intercept`
// always sees `requested_nonblocking = false` there), and the periodic
// path holds no gate around its transmits on that platform either (see
// `send_heartbeat_best_effort`'s Windows branch) -- so a genuinely stuck
// destination for writer A WOULD starve writer B on that platform, by
// design, an accepted, already-documented gap (no per-call non-blocking
// primitive in Winsock), not something the gate claims to close there.
// This test's guarantee is real only where the non-blocking flag is: on
// Windows it would fail for a reason that is already documented,
// not a regression this test should flag.
#[cfg_attr(
    windows,
    ignore = "accepted Windows gap: best_effort_send_to has no non-blocking flag there, so a \
              stuck destination DOES starve the shared worker on this platform (documented, not \
              fixed)"
)]
#[test]
fn a_stuck_writer_does_not_starve_the_worker_queued_behind_it() {
    let clock = Arc::new(ManualClock::new(0));
    let domain = crate::test_support::domains::unique_domain();
    let mut builder = Participant::builder("stuck-writer-does-not-starve")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast);
    builder.liveliness_clock = Some(clock.clone());
    let participant = builder.build().expect("participant");
    let capture = user_multicast_capture(&participant);
    // A positive-receipt wait (`recv_from` returns the instant B's
    // HEARTBEAT arrives, same as a channel `recv_timeout`): the bound
    // only matters for the FAILED case, so it costs nothing to make it
    // generous. A 2 s bound flakes under heavy concurrent CPU load -- bounded
    // wrong, not unbounded: the code still returns almost instantly in the
    // overwhelmingly common case, and a genuine regression (the worker
    // actually starved behind writer A) still fails in bounded time, just
    // a more generous one.
    capture
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("read timeout");

    // Writer A created before writer B: see the tie-break reasoning above.
    let topic_a = participant.topic::<Ping>("StuckWriterA").expect("topic a");
    let writer_a = topic_a
        .writer()
        .qos(QoS::reliable())
        .build()
        .expect("writer a");
    let topic_b = participant.topic::<Ping>("StuckWriterB").expect("topic b");
    let writer_b = topic_b
        .writer()
        .qos(QoS::reliable())
        .build()
        .expect("writer b");

    writer_a.write(&Ping { id: 1 }).expect("write a");
    writer_b.write(&Ping { id: 2 }).expect("write b");
    drain_heartbeats(&capture); // discard both writers' piggyback, if any

    let writer_a_guid = writer_guid_of(&writer_a);
    let writer_b_guid = writer_guid_of(&writer_b);

    let barrier = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    crate::transport::udp::send_seam::arm(writer_a_guid, Arc::clone(&barrier));
    let _release_guard = ReleaseOnDrop(Arc::clone(&barrier));

    let shared = participant
        .liveliness
        .as_ref()
        .expect("liveliness")
        .shared();

    let watch_a = match writer_a._heartbeat_scheduler.as_ref().expect("scheduled") {
        super::heartbeat_scheduler::HeartbeatPeriodic::Participant { watch, .. } => watch,
        super::heartbeat_scheduler::HeartbeatPeriodic::Standalone(_) => {
            panic!("expected a participant-scheduled writer")
        }
    };
    let watch_b = match writer_b._heartbeat_scheduler.as_ref().expect("scheduled") {
        super::heartbeat_scheduler::HeartbeatPeriodic::Participant { watch, .. } => watch,
        super::heartbeat_scheduler::HeartbeatPeriodic::Standalone(_) => {
            panic!("expected a participant-scheduled writer")
        }
    };

    // Two periods, armed throughout: collect outcomes first, assert
    // nothing yet (the RAII guard above releases the barrier when this
    // function returns either way, including via an early panic).
    let mut period_results: Vec<std::io::Result<([u8; 4096], usize)>> = Vec::new();
    for _ in 0..2 {
        clock.advance(Duration::from_millis(100));
        shared.settle();
        let mut buf = [0u8; 4096];
        let outcome = capture.recv_from(&mut buf).map(|(n, _)| (buf, n));
        period_results.push(outcome);
        // Advancing to the next period right after the packet's OWN
        // arrival does not mean the
        // admission slot (`HeartbeatPending`) for either writer's job
        // has actually been released yet -- that happens later, from
        // `HeartbeatJob::Drop` in the worker's loop, after `fire()`
        // returns. Advancing before release coalesces the next period's
        // tick away rather than dispatching it.
        wait_for_admission_released(watch_a);
        wait_for_admission_released(watch_b);
    }

    crate::transport::udp::send_seam::disarm(writer_a_guid);

    for (period, outcome) in period_results.into_iter().enumerate() {
        let (buf, n) = outcome.unwrap_or_else(|e| {
            panic!(
                "period {period}: writer B's HEARTBEAT must arrive within the bound (the \
                 worker must not be stuck behind writer A's armed destination): {e}"
            )
        });
        let guids = heartbeat_writer_guids_in(&buf[..n]);
        assert!(
            guids.contains(&writer_b_guid),
            "period {period}: expected writer B's HEARTBEAT, decoded writer guids: {guids:?}"
        );
        assert!(
            !guids.contains(&writer_a_guid),
            "period {period}: writer A's HEARTBEAT must have been dropped (WouldBlock), not \
             delivered: {guids:?}"
        );
    }
}

/// Thread-CREATION-RATE check, as opposed to
/// `fifty_reliable_writers_add_no_heartbeat_threads`'s steady-state
/// count: a per-batch-thread dispatch would create hundreds of NEW
/// `hdds-notices` threads per second with 50 writers. Idle for
/// several periods after setup and the "hdds-hb-sender" thread
/// count must stay at exactly 1 throughout -- never a second one
/// spawned for a batch, never zero while writers are still watched.
/// (`strace -f -c -e trace=clone,clone3` gives the actual creation-rate
/// figure; this assertion is the one a unit test can make deterministically.)
#[test]
#[ignore = "counts process threads over a real-time window: run alone"]
fn fifty_writers_idle_creates_no_new_heartbeat_send_threads() {
    let domain = crate::test_support::domains::unique_domain();
    let participant = Participant::builder("rate-fifty-writers")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let mut writers = Vec::new();
    for i in 0..50u32 {
        let topic = participant
            .topic::<Ping>(&format!("RateFifty{i}"))
            .expect("topic");
        let writer = topic.writer().qos(QoS::reliable()).build().expect("writer");
        writer.write(&Ping { id: i }).expect("write");
        writers.push(writer);
    }
    // Markers for a strace -tt window: everything from BEGIN to END is
    // steady-state idle, 50 writers each ticking their periodic
    // HEARTBEAT every ~100ms with no application callback due -- the
    // regime in which a per-batch dispatch would create hundreds of new
    // threads per second.
    eprintln!("RATE_WINDOW_BEGIN {:?}", std::time::SystemTime::now());
    for _ in 0..10 {
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(
            threads_named("hdds-hb-sender"),
            1,
            "still the one worker, several periods in"
        );
        assert_eq!(
            threads_named("hdds-notices"),
            0,
            "no application callback is due; nothing should be queued for it"
        );
    }
    eprintln!("RATE_WINDOW_END {:?}", std::time::SystemTime::now());
    drop(writers);
    drop(participant);
}

/// Removing `WriterHeartbeatSink::fire`'s `should_stop()` guard would
/// survive the scheduler-driven HEARTBEAT tests: nothing else calls
/// `fire()` directly on a sink whose writer had already been dropped,
/// only through the scheduler (which has no live watch to dispatch from
/// once unwatched). This pins the
/// guard itself, bypassing the scheduler entirely, so a future change
/// that removes it fails here even if the dispatch path happens to hide
/// the symptom.
///
/// Mutant: deleting `if self.state.should_stop() { return; }` in
/// `WriterHeartbeatSink::fire` makes this fail: the retained `sink`
/// would still build and send a HEARTBEAT for a writer that no longer
/// exists.
#[test]
fn the_stop_guard_silences_an_already_upgraded_sink() {
    let clock = Arc::new(ManualClock::new(0));
    let domain = crate::test_support::domains::unique_domain();
    let mut builder = Participant::builder("stop-guard-upgraded-sink")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast);
    builder.liveliness_clock = Some(clock);
    let participant = builder.build().expect("participant");
    let capture = user_multicast_capture(&participant);
    let topic = participant
        .topic::<Ping>("StopGuardUpgradedSink")
        .expect("topic");
    let writer = topic.writer().qos(QoS::reliable()).build().expect("writer");
    writer.write(&Ping { id: 1 }).expect("write");
    drain_heartbeats(&capture);
    let sink = match writer._heartbeat_scheduler.as_ref().expect("scheduled") {
        super::heartbeat_scheduler::HeartbeatPeriodic::Participant { sink, .. } => Arc::clone(sink),
        super::heartbeat_scheduler::HeartbeatPeriodic::Standalone(_) => {
            panic!("expected a participant-scheduled writer")
        }
    };
    drop(writer);
    // Direct call, bypassing the scheduler/worker entirely: proves the
    // guard INSIDE `fire()` itself, not only that nothing dispatches to
    // a dead watch.
    crate::dds::liveliness::HeartbeatSink::fire(&*sink);
    let after = drain_heartbeats(&capture);
    assert!(after.is_empty(), "a stopped sink must not send: {after:?}");
}

/// RTPS v2.5 Sec.8.3.8.6: one writer, one monotonic HEARTBEAT count,
/// whichever of the three origins asserts it -- the on-write
/// ("piggyback") path, a MANUAL_BY_TOPIC `assert_liveliness()` (the L
/// flag), and the periodic scheduler entry all draw from
/// the SAME counter (`HeartbeatSchedulerState::next_count`).
///
/// Mutant: giving the periodic origin its own independent counter (`state.next_count()` replaced by a private static
/// inside `fire_heartbeat_tick`) makes the merged wire sequence
/// non-monotonic -- no test that does not interleave origins catches it;
/// this one does.
#[test]
fn three_heartbeat_origins_share_one_monotonic_count() {
    let clock = Arc::new(ManualClock::new(0));
    let domain = crate::test_support::domains::unique_domain();
    let mut builder = Participant::builder("three-origins-share-count")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast);
    builder.liveliness_clock = Some(clock.clone());
    let participant = builder.build().expect("participant");
    let capture = user_multicast_capture(&participant);
    let topic = participant
        .topic::<Ping>("ThreeOriginsShareCount")
        .expect("topic");
    let mut qos = QoS::reliable();
    qos.liveliness.kind = crate::dds::qos::LivelinessKind::ManualByTopic;
    let writer = topic.writer().qos(qos).build().expect("writer");
    let shared = Arc::clone(
        participant
            .liveliness
            .as_ref()
            .expect("liveliness")
            .shared(),
    );

    // The on-write ("piggyback") path rate-limits itself against a real
    // `Instant` deadline set at construction (`HeartbeatTx::new`, not
    // the injected `ManualClock`), so a write right after `build()`
    // sends nothing on it yet; real sleep past its period is the only
    // way to make it fire deterministically.
    std::thread::sleep(Duration::from_millis(150));
    writer.write(&Ping { id: 1 }).expect("write");
    let piggyback = drain_heartbeats(&capture);
    writer.assert_liveliness().expect("assert_liveliness");
    let manual = drain_heartbeats(&capture);
    clock.advance(Duration::from_millis(100));
    shared.settle();
    let periodic = drain_heartbeats(&capture);
    std::thread::sleep(Duration::from_millis(150));
    writer.write(&Ping { id: 2 }).expect("write");
    let piggyback2 = drain_heartbeats(&capture);

    assert!(!piggyback.is_empty(), "the write asserts on write");
    assert!(!manual.is_empty(), "assert_liveliness asserts the L flag");
    assert!(!periodic.is_empty(), "the scheduler asserts periodically");
    assert!(!piggyback2.is_empty(), "the second write asserts again");

    let counts: Vec<u32> = piggyback
        .iter()
        .chain(&manual)
        .chain(&periodic)
        .chain(&piggyback2)
        .map(|hb| hb.2)
        .collect();
    for pair in counts.windows(2) {
        assert!(
            pair[1] > pair[0],
            "one writer, one monotonic count across every origin: {counts:?}"
        );
    }
}

/// The writer-side stop check alone does not stop a send already handed
/// to the dispatcher: drop would signal stop and return before that job
/// had run, so its HEARTBEAT would reach the wire AFTER both the
/// writer's and the participant's drop had already returned.
///
/// The deletion barrier (`HeartbeatPending::wait_idle`) alone only
/// BOUNDS that gap, rather than closing it: once the bound (2 s)
/// expires, drop logs a warning and returns anyway, and a job that had
/// not yet reached its actual transmit call could still send
/// afterward. The real guarantee is a second, unconditional gate (`HeartbeatSchedulerState::revoke_sends`,
/// checked by `send_heartbeat_to_readers` immediately before every real
/// socket transmission): drop sets it FIRST, synchronously, before the
/// (still bounded, best-effort) wait -- so even a job that resumes long
/// after the bound expired finds its own transmit check already
/// revoked and sends nothing. This test pauses a tick right after it
/// allocates its count drops the writer
/// while it is paused, and confirms the drop still waits (bounded) for
/// a quick send, but that NOTHING reaches the wire for it either way --
/// a strictly stronger guarantee than "the send completes before drop
/// returns".
///
/// Mutant: removing `HeartbeatSchedulerState::revoke_sends`'s call (or
/// the `sends_revoked()` check in `send_heartbeat_to_readers`) makes
/// this fail: the paused send, once released, would reach the wire
/// after all.
#[test]
fn writer_drop_waits_for_a_paused_send_but_nothing_reaches_the_wire() {
    let clock = Arc::new(ManualClock::new(0));
    let domain = crate::test_support::domains::unique_domain();
    let mut builder = Participant::builder("delete-barrier-paused")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast);
    builder.liveliness_clock = Some(clock.clone());
    let participant = builder.build().expect("participant");
    let capture = user_multicast_capture(&participant);
    let topic_name = "DeleteBarrierPaused";
    let topic = participant.topic::<Ping>(topic_name).expect("topic");
    let writer = topic.writer().qos(QoS::reliable()).build().expect("writer");
    writer.write(&Ping { id: 1 }).expect("write");
    drain_heartbeats(&capture);

    let shared = Arc::clone(
        participant
            .liveliness
            .as_ref()
            .expect("liveliness")
            .shared(),
    );
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    super::heartbeat_scheduler::test_pause::arm(topic_name, entered_tx, Arc::clone(&release));
    let _release_guard = ReleaseOnDrop(Arc::clone(&release));

    clock.advance(Duration::from_millis(100));
    shared.settle();
    // The periodic tick is paused inside `fire_heartbeat_tick`, past
    // count allocation but before the actual send.
    entered_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the paused tick entered");

    let release_for_unblock = Arc::clone(&release);
    let unblock = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        *release_for_unblock
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = true;
        release_for_unblock.1.notify_all();
    });
    let drop_started = std::time::Instant::now();
    drop(writer);
    let drop_elapsed = drop_started.elapsed();
    unblock.join().expect("release thread");

    assert!(
        drop_elapsed >= Duration::from_millis(150),
        "the drop must wait for the paused send, not return immediately: {drop_elapsed:?}"
    );
    assert!(
        drop_elapsed < DELETE_BARRIER_BOUND_FOR_TEST,
        "a send that finishes quickly must not hit the barrier's own bound: {drop_elapsed:?}"
    );
    let after_drop = drain_heartbeats(&capture);
    assert!(
        after_drop.is_empty(),
        "revoked before drop returned: nothing reaches the wire for this writer again, \
         not even a send that was already in flight: {after_drop:?}"
    );
    drop(topic);
    drop(participant);
    assert!(
        drain_heartbeats(&capture).is_empty(),
        "nothing more reaches the wire after both drops return"
    );
}

/// `DELETE_BARRIER_BOUND` itself is private to `heartbeat_scheduler`;
/// this is only used as a loose upper bound in the test above (a send
/// that takes 200 ms must not come anywhere near a 2 s barrier), not a
/// precise mirror of it.
const DELETE_BARRIER_BOUND_FOR_TEST: Duration = Duration::from_secs(1);

/// The paused send
/// outlives `HeartbeatPeriodic::drop`'s own bounded wait (2 s) entirely
/// -- drop logs its warning and returns -- and is released only
/// afterward. `revoke_sends()` is unconditional and set before that
/// wait even starts, so this must behave exactly like the quick-send
/// case above: nothing reaches the wire, regardless of how much later
/// the paused send actually resumes.
///
/// Mutant: same as the test above (removing `revoke_sends`/
/// `sends_revoked`), but exercised past the bound instead of within it
/// -- the two tests together cover both branches of `wait_idle`'s
/// result.
#[test]
fn nothing_reaches_the_wire_even_released_after_the_barrier_bound_expires() {
    let clock = Arc::new(ManualClock::new(0));
    let domain = crate::test_support::domains::unique_domain();
    let mut builder = Participant::builder("delete-barrier-exceeded")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast);
    builder.liveliness_clock = Some(clock.clone());
    let participant = builder.build().expect("participant");
    let capture = user_multicast_capture(&participant);
    let topic_name = "DeleteBarrierExceeded";
    let topic = participant.topic::<Ping>(topic_name).expect("topic");
    let writer = topic.writer().qos(QoS::reliable()).build().expect("writer");
    writer.write(&Ping { id: 1 }).expect("write");
    drain_heartbeats(&capture);

    let shared = Arc::clone(
        participant
            .liveliness
            .as_ref()
            .expect("liveliness")
            .shared(),
    );
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    super::heartbeat_scheduler::test_pause::arm(topic_name, entered_tx, Arc::clone(&release));
    let _release_guard = ReleaseOnDrop(Arc::clone(&release));

    clock.advance(Duration::from_millis(100));
    shared.settle();
    entered_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the paused tick entered");

    // Never released during this drop: it must hit its own bound
    // (2 s), log a warning, and return anyway.
    let drop_started = std::time::Instant::now();
    drop(writer);
    let drop_elapsed = drop_started.elapsed();
    assert!(
        drop_elapsed >= Duration::from_secs(2),
        "drop must have hit its own bound, not returned early: {drop_elapsed:?}"
    );
    assert!(
        drain_heartbeats(&capture).is_empty(),
        "nothing reaches the wire while drop is still blocked or right after it returns"
    );

    // Only now, well after both the bound and drop's return, release
    // the paused send: it must still find itself revoked.
    *release.0.lock().unwrap_or_else(|e| e.into_inner()) = true;
    release.1.notify_all();
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        drain_heartbeats(&capture).is_empty(),
        "released long after drop returned: still nothing on the wire"
    );
    drop(topic);
    drop(participant);
}

/// The send gate must cover ONLY the already-resolved, non-blocking
/// transmit -- never discovery, registry lookups or window-table
/// translation. Holding it across that work too would let
/// `revoke_sends()` -- and so `HeartbeatPeriodic::drop` -- wait
/// UNBOUNDED on whatever unrelated thread happened to be holding one of
/// those locks.
///
/// This test holds `WriterWindows::peers`'s mutex from a separate
/// thread (`hold_peers_for_test`, simulating ANY other holder: another
/// HEARTBEAT/ACKNACK/DATA `resolve_inner` call) for the rest of the
/// test -- never released while `drop(writer)` runs -- while a periodic
/// tick is due. `drop(writer)` must still return within a generous
/// ceiling, bounded by the EXISTING, unrelated `wait_idle`
/// (`DELETE_BARRIER_BOUND`, ~2 s, the scheduler's own admission-
/// tracking wait), not by how long the window mutex happens to stay
/// held. Deterministic: the holder signals `entered` only AFTER it
/// actually holds the lock (not merely "this thread has started"), so
/// there is no race between arming and checking.
///
/// The writer needs a matched classic reader: with
/// `WriterWindows::present` false, `resolve_inner` takes its early
/// return straight into `resolve_native`, never touching `peers`, so
/// holding that mutex elsewhere would prove nothing about gate
/// placement regardless of how long `drop` took. The test therefore
/// registers one classic peer through real SPDP/SEDP -- vendor id
/// 0x0101, which `GroupDialect::needs_sequence_window` keys on -- then
/// pairing it directly (`WriterWindows::pair`, the same call the
/// production ACKNACK-driven match path makes). A second signal
/// (`arm_peers_contention_signal`, fired from inside `resolve_inner`
/// right before it attempts `peers.lock()`) confirms the periodic
/// tick's own resolve call actually REACHED that contested acquisition
/// before this test ever looks at `drop_elapsed`.
///
/// Mutant: moving
/// window-table resolution back inside `with_send_gate_held` makes
/// `revoke_sends()` itself wait on the still-held `peers` mutex, which
/// this test never releases -- `drop(writer)` does not return within
/// the ceiling at all.
#[test]
fn drop_is_bounded_when_the_window_table_is_held_elsewhere() {
    let clock = Arc::new(ManualClock::new(0));
    let domain = crate::test_support::domains::unique_domain();
    let mut builder = Participant::builder("gate-excludes-window-table")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast);
    builder.liveliness_clock = Some(clock.clone());
    let participant = builder.build().expect("participant");
    let topic_name = "GateExcludesWindowTable";
    let topic = participant.topic::<Ping>(topic_name).expect("topic");
    let writer = topic.writer().qos(QoS::reliable()).build().expect("writer");
    writer.write(&Ping { id: 1 }).expect("write");
    // Unregister the instance now, while nothing contends `send_serial`
    // yet: `DataWriter::drop`'s auto-unregister loop (any instance still
    // in `written_instances`) sends its own BLOCKING lifecycle change
    // before this writer's `HeartbeatPeriodic::drop` ever runs, and that
    // would deadlock later in this test on the SAME writer's own
    // `send_serial` -- held by the periodic tick this test deliberately
    // leaves stuck resolving against the held `peers` mutex below. Not
    // what this test is about; emptying `written_instances` up front
    // sidesteps it.
    writer
        .unregister_instance(&Ping { id: 1 })
        .expect("unregister");

    let windows = Arc::clone(
        &writer
            .history_cache
            .as_ref()
            .expect("a reliable writer has a history cache")
            .wire_windows,
    );

    // A matched CLASSIC reader (vendor 0x0101) so the periodic tick's
    // own resolve call actually reaches `peers` instead of taking
    // `resolve_native`'s early return.
    windows.configure(true);
    let fsm = participant
        .discovery_fsm
        .as_ref()
        .expect("participant has a discovery fsm");
    let reg = fsm.endpoint_registry();
    let capture = crate::test_support::ports::bind_capture_socket();
    let dest = capture.local_addr().expect("capture addr");
    let mut pguid = [0x51u8; 16];
    pguid[12..16].copy_from_slice(&[0x00, 0x00, 0x01, 0xC1]);
    let participant_guid = crate::core::discovery::GUID::from_bytes(pguid);
    let domain_id = domain.id();
    let spdp = move || crate::protocol::discovery::SpdpData {
        participant_guid,
        lease_duration_ms: 100_000,
        domain_id,
        metatraffic_unicast_locators: vec![],
        default_unicast_locators: vec![],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: Some(0x0101),
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    };
    // A second SPDP at least PROBATION_WINDOW_MS after the first
    // confirms the fake participant alive (same technique as
    // `coherent_dispose_tests::register_reader`).
    fsm.handle_spdp(spdp());
    std::thread::sleep(Duration::from_millis(120));
    fsm.handle_spdp(spdp());
    let mut rguid = [0x51u8; 16];
    rguid[12..16].copy_from_slice(&[0x00, 0x00, 0x20, 0x04]);
    let reader_guid = crate::core::discovery::GUID::from_bytes(rguid);
    fsm.handle_sedp(crate::protocol::discovery::SedpData {
        topic_name: topic_name.to_string(),
        type_name: "Ping".to_string(),
        participant_guid,
        endpoint_guid: reader_guid,
        qos_hash: 0,
        qos: None,
        type_object: None,
        dependents: Vec::new(),
        type_object_legacy_v1: false,
        type_information: None,
        unicast_locators: vec![dest],
        user_data: None,
        shm_capability: None,
        endpoint_security_info: None,
        has_explicit_reliability: false,
        has_explicit_ownership: false,
        has_ownership_strength: false,
        type_consistency: None,
        group_entity_id: None,
    });
    reg.register_reader_locator(reader_guid, dest);
    reg.register(participant_guid, dest);
    windows.pair(reader_guid, Some(dest), 0, false);

    // Keep the fake participant alive for the rest of this test: left
    // silent, `DiscoveryFsm::purge_unconfirmed_participants` (a REAL
    // background sweep, on its own thread, independent of the manual
    // clock below) judges it a stale entry within a couple of SPDP
    // periods and removes it -- whose unmatch dispatch calls
    // `WriterWindows::unpair`, needing the SAME `peers` mutex this test
    // holds elsewhere. That removal's
    // `MatchNotificationRegistry::unregister` (run from `DataWriter`'s
    // own drop, waiting for every in-flight dispatch to drain) then
    // waits UNBOUNDED for that stuck unpair -- a real liveness gap in
    // `DispatchGate::close`, but a DIFFERENT mechanism than the
    // send-gate/wait_idle, and out of scope here. Re-announcing
    // keeps the sweep from ever judging this participant stale during
    // this test's lifetime, sidestepping it entirely.
    let keepalive_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let keepalive_stop_for_thread = Arc::clone(&keepalive_stop);
    let fsm_for_keepalive = Arc::clone(fsm);
    let keepalive = std::thread::spawn(move || {
        while !keepalive_stop_for_thread.load(std::sync::atomic::Ordering::Relaxed) {
            fsm_for_keepalive.handle_spdp(spdp());
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    // RAII from the moment the thread exists, covering every exit path
    // below (including a panic in an assertion before the manual
    // manual cleanup alone). Declaration order matters: the join guard first (so it
    // drops LAST), the stop guard second (so it drops FIRST, waking the
    // thread before this joins it).
    let _join_keepalive = JoinOnDrop(Some(keepalive));
    let _stop_keepalive = StopOnDrop(Arc::clone(&keepalive_stop));

    let hold_release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let (holder_entered_tx, holder_entered_rx) = std::sync::mpsc::channel();
    let hold_release_for_holder = Arc::clone(&hold_release);
    let windows_for_holder = Arc::clone(&windows);
    let holder = std::thread::spawn(move || {
        windows_for_holder.hold_peers_for_test(holder_entered_tx, hold_release_for_holder);
    });
    // Same RAII pairing as above, armed before the `recv_timeout` below
    // (which itself can panic on timeout) rather than after it.
    let _join_holder = JoinOnDrop(Some(holder));
    let _release_holder = ReleaseOnDrop(Arc::clone(&hold_release));
    holder_entered_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the holder thread actually holds the window mutex now");

    let (contended_tx, contended_rx) = std::sync::mpsc::channel();
    windows.arm_peers_contention_signal(contended_tx);

    let shared = Arc::clone(
        participant
            .liveliness
            .as_ref()
            .expect("liveliness")
            .shared(),
    );
    clock.advance(Duration::from_millis(100));
    shared.settle();

    contended_rx.recv_timeout(Duration::from_secs(30)).expect(
        "the periodic tick's own resolve call must actually reach the contested peers \
         acquisition -- otherwise this test proves nothing about gate placement",
    );

    // `drop(writer)` runs on its OWN thread, bounded by a channel receive,
    // not called inline: this test deliberately leaves a periodic tick
    // stuck resolving against the held `peers` mutex for as long as the
    // holder thread is not released, and a hang anywhere in teardown
    // (`revoke_sends`/`wait_idle`, or anything else) must
    // surface as a clean, bounded test failure -- never as a hung test
    // binary that an external `timeout` has to kill.
    let (dropped_tx, dropped_rx) = std::sync::mpsc::channel();
    let drop_thread = std::thread::spawn(move || {
        let drop_started = std::time::Instant::now();
        drop(writer);
        let _ = dropped_tx.send(drop_started.elapsed());
    });
    let dropped = dropped_rx.recv_timeout(Duration::from_secs(30));

    // Release and join explicitly here, however the drop thread came
    // out, so neither thread outlives this test any longer than it has
    // to -- the RAII guards above (`_release_holder`/`_join_holder`,
    // `_stop_keepalive`/`_join_keepalive`) still cover every path that
    // panics before reaching this point; dropping them early here is
    // just promptness, not a correctness requirement.
    drop(_release_holder);
    drop(_join_holder);
    drop(_stop_keepalive);
    drop(_join_keepalive);

    let drop_elapsed = dropped.expect(
        "drop(writer) must return within 30s even with the window table held elsewhere; a \
         hang past this generous bound points at a teardown step the send gate does not \
         cover (not merely the send_gate/wait_idle interaction)",
    );
    drop_thread.join().expect("drop thread");

    assert!(
        drop_elapsed < Duration::from_secs(15),
        "drop must stay bounded by the UNRELATED wait_idle bound (~2s, generous margin for \
         machine load) even with the window table held elsewhere for the writer's whole \
         lifetime -- the send gate must never cover that lookup: {drop_elapsed:?}"
    );
    drop(topic);
    drop(participant);
}

/// `try_with_next_count` must not use `self.send_serial.try_lock().ok()?`,
/// which treats `TryLockError::Poisoned` exactly like `WouldBlock`. A single caught
/// panic while holding `send_serial` (the worker's own `catch_unwind`
/// around `sink.fire()` keeps the WORKER alive, but does nothing about
/// a lock it was holding) would poison it forever, and every LATER tick
/// for THIS writer would silently skip -- an idle reliable writer stops
/// announcing unacknowledged data, permanently, with nothing to say why.
///
/// `test_pause::arm_panic_once` panics the next tick from INSIDE
/// `try_with_next_count`'s closure, so `send_serial` is genuinely
/// poisoned by a real unwind, not simulated. The SAME writer's next
/// periodic tick (a second, later period) must still fire.
///
/// The test learns "the first (panicking) tick is done" from the
/// same completion signal as the emission-order test above
/// (`test_pause::arm_completion`/`CompletionGuard`, fired from `fire()`
/// via `Drop` so it still fires when the tick panics): each tick is
/// confirmed to have fully returned, from inside the worker, before
/// this test looks at what it sent or advances the clock again.
///
/// Mutant: reverting `try_with_next_count` to `self.send_serial.
/// try_lock().ok()?` makes this fail -- the second period's HEARTBEAT
/// never arrives, because `send_serial` stays poisoned/"busy" forever.
#[test]
fn a_panicked_tick_does_not_starve_this_writers_next_one() {
    let clock = Arc::new(ManualClock::new(0));
    let domain = crate::test_support::domains::unique_domain();
    let mut builder = Participant::builder("panic-does-not-starve")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast);
    builder.liveliness_clock = Some(clock.clone());
    let participant = builder.build().expect("participant");
    let capture = user_multicast_capture(&participant);
    let topic_name = "PanicDoesNotStarve";
    let topic = participant.topic::<Ping>(topic_name).expect("topic");
    let writer = topic.writer().qos(QoS::reliable()).build().expect("writer");
    writer.write(&Ping { id: 1 }).expect("write");
    drain_heartbeats(&capture);

    let shared = Arc::clone(
        participant
            .liveliness
            .as_ref()
            .expect("liveliness")
            .shared(),
    );

    let watch = match writer._heartbeat_scheduler.as_ref().expect("scheduled") {
        super::heartbeat_scheduler::HeartbeatPeriodic::Participant { watch, .. } => watch,
        super::heartbeat_scheduler::HeartbeatPeriodic::Standalone(_) => {
            panic!("expected a participant-scheduled writer")
        }
    };

    super::heartbeat_scheduler::test_pause::arm_panic_once(topic_name);
    let (first_done_tx, first_done_rx) = std::sync::mpsc::channel();
    super::heartbeat_scheduler::test_pause::arm_completion(topic_name, first_done_tx);
    clock.advance(Duration::from_millis(100));
    shared.settle();
    first_done_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the first (panicking) tick must have fully returned by now");
    // `fire()` returning is NOT the same event as
    // its admission slot (`HeartbeatPending`) actually freeing: that
    // happens later, from `HeartbeatJob::Drop` in the worker's loop
    // (after any panic is logged). Advancing to the next period before
    // this slot clears would coalesce it away rather than dispatch it.
    // Poll the real admission state directly, bounded.
    wait_for_admission_released(watch);
    drain_heartbeats(&capture); // the panicking tick sent nothing; discard

    let (second_done_tx, second_done_rx) = std::sync::mpsc::channel();
    super::heartbeat_scheduler::test_pause::arm_completion(topic_name, second_done_tx);
    clock.advance(Duration::from_millis(100));
    shared.settle();
    second_done_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the second tick must have fully returned by now");
    wait_for_admission_released(watch);
    let after = drain_heartbeats(&capture);
    assert!(
        !after.is_empty(),
        "this writer's SECOND periodic tick must still fire after the first one panicked -- \
         Poisoned must be recovered, never treated as permanently busy like WouldBlock"
    );
    drop(topic);
    drop(participant);
}

/// Re-verifies the count-ordering claim through the PRODUCTION origin paths themselves
/// (`fire_heartbeat_tick` via the real scheduler/worker,
/// `maybe_send_heartbeat` via a real `write()`), asserting the
/// EMISSION order actually observed on the wire -- not the allocation
/// order, which calling `HeartbeatSchedulerState` directly and
/// comparing the closures' return values would check (a lock-removal
/// mutant can still satisfy that: the
/// shared atomic `count` alone already orders allocation, with or
/// without `send_serial`).
///
/// No wall-clock race, and no sleep at all: the periodic tick's pause
/// is confirmed held via a channel (deterministic), `write()` is the
/// real, unmodified piggyback path on this test's own thread (never
/// spawned: `DataWriter` is deliberately not `Sync`), and a THIRD,
/// independent thread releases the periodic tick's pause only once
/// write()'s own attempt to allocate its count has actually reached the
/// contested `send_serial.lock()` call site
/// (`arm_send_serial_contention_signal` -- not a fixed 200 ms sleep). The
/// ordering assertion below is what catches a lock-removal mutant, a pure
/// comparison on decoded wire bytes, not a numeric threshold.
///
/// Mutant: removing `send_serial`'s lock from either origin lets
/// `write()`'s piggyback HEARTBEAT -- which allocates its count AFTER
/// the periodic tick already did -- reach the wire WHILE the periodic
/// tick is still paused: the decoded arrival order is piggyback's count
/// before periodic's, violating RTPS v2.5 Sec.8.3.8.6.
#[test]
fn periodic_and_piggyback_emit_in_allocation_order_on_the_wire() {
    let clock = Arc::new(ManualClock::new(0));
    let domain = crate::test_support::domains::unique_domain();
    let mut builder = Participant::builder("emission-order-not-allocation")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast);
    builder.liveliness_clock = Some(clock.clone());
    let participant = builder.build().expect("participant");
    let capture = user_multicast_capture(&participant);
    let topic_name = "EmissionOrderNotAllocation";
    let topic = participant.topic::<Ping>(topic_name).expect("topic");
    let writer = topic.writer().qos(QoS::reliable()).build().expect("writer");
    writer.write(&Ping { id: 1 }).expect("seed write");
    drain_heartbeats(&capture);

    // Force piggyback due on the NEXT write(), deterministically -- no
    // sleep racing Instant::now() (same technique as
    // `piggyback_and_manual_assert_heartbeats_keep_the_blocking_send`).
    *writer
        .heartbeat_tx
        .as_ref()
        .expect("a reliable writer has a heartbeat_tx")
        .borrow_mut() = crate::reliability::HeartbeatTx::with_period_ms(0, 0);

    let shared = Arc::clone(
        participant
            .liveliness
            .as_ref()
            .expect("liveliness")
            .shared(),
    );
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    super::heartbeat_scheduler::test_pause::arm(topic_name, entered_tx, Arc::clone(&release));
    let _release_guard = ReleaseOnDrop(Arc::clone(&release));

    clock.advance(Duration::from_millis(100));
    shared.settle();
    let periodic_count = entered_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the periodic tick entered, holding send_serial");

    // Release periodic's pause from a THIRD thread, but only once
    // write()'s own piggyback attempt has actually reached its
    // `send_serial.lock()` call site -- a deterministic signal
    // (`arm_send_serial_contention_signal`, fired from inside
    // `with_next_count` right before it attempts the lock), replacing a
    // fixed sleep. With the lock in place write() blocks
    // there until this release; in a mutant without the lock, write()
    // never attempts this acquisition point at all (it just sends), so
    // the signal race is moot for that case -- the ordering assertion
    // below is still what actually catches it.
    let shared_state = match writer._heartbeat_scheduler.as_ref().expect("scheduled") {
        super::heartbeat_scheduler::HeartbeatPeriodic::Participant { sink, .. } => {
            Arc::clone(sink.state())
        }
        super::heartbeat_scheduler::HeartbeatPeriodic::Standalone(_) => {
            panic!("expected a participant-scheduled writer")
        }
    };
    let (write_contended_tx, write_contended_rx) = std::sync::mpsc::channel();
    shared_state.arm_send_serial_contention_signal(write_contended_tx);
    // The contention signal above, ALONE, is an
    // insufficient mutant proof: it fires before write() even attempts
    // the lock, so a mutant that deletes just the `lock()` call still
    // lets the releaser wake the paused periodic tick, and the two
    // sends can then race on the wire -- sometimes landing in the
    // "expected" order by luck, passing a mutant that should fail. This
    // second signal fires from `with_next_count` only AFTER
    // `send_serial.lock()` actually returns a guard (tied to it by
    // parameter, so a mutant deleting the lock call cannot keep this
    // one compiling by accident): asserted below, independent of wire
    // timing.
    let (write_acquired_tx, write_acquired_rx) = std::sync::mpsc::channel();
    shared_state.arm_send_serial_acquired_signal(write_acquired_tx);
    let release_for_releaser = Arc::clone(&release);
    let releaser = std::thread::spawn(move || {
        let _ = write_contended_rx.recv_timeout(Duration::from_secs(30));
        *release_for_releaser
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = true;
        release_for_releaser.1.notify_all();
    });

    // The REAL production path: write()'s own piggyback HEARTBEAT, on
    // this test's own thread. Blocks on send_serial until the releaser
    // above lets the periodic tick's paused closure finish, in the
    // fixed code; races ahead of it, if the lock is missing, in a mutant.
    writer.write(&Ping { id: 2 }).expect("write");
    releaser.join().expect("releaser thread");

    write_acquired_rx
        .recv_timeout(Duration::from_secs(30))
        .expect(
            "write()'s piggyback must have genuinely acquired send_serial -- a mutant that \
         deletes the lock call never produces this signal, whatever the wire arrival order",
        );

    let heartbeats = drain_heartbeats(&capture);
    let counts: Vec<u32> = heartbeats.iter().map(|hb| hb.2).collect();
    assert!(
        counts.len() >= 2,
        "expected both the periodic tick's and write()'s piggyback HEARTBEAT: {counts:?}"
    );
    assert_eq!(
        counts.first().copied(),
        Some(periodic_count),
        "the periodic tick's count ({periodic_count}) must be the FIRST to reach the wire -- \
         it allocated first and send_serial must keep allocate-then-send atomic per writer \
         across origins: decoded arrival order was {counts:?}"
    );
    for pair in counts.windows(2) {
        assert!(
            pair[1] > pair[0],
            "counts must be strictly increasing in arrival order too: {counts:?}"
        );
    }
    drop(topic);
    drop(participant);
}

/// A reachable scenario: a writer destroyed by
/// code running ON the participant's own scheduler thread (a sink
/// callback `deliver` invokes inline, which can end up owning and
/// dropping the last reference to a writer) would otherwise make
/// `HeartbeatPeriodic::drop`'s deletion barrier wait, bounded, on work
/// that very thread has to do -- stalling every timer on it for up to
/// the bound. This reproduces exactly that: a plain LIVELINESS watch
/// whose sink drops a writer (one with its own paused, still in-flight
/// periodic HEARTBEAT, so the barrier would otherwise have something
/// real to wait for) from inside `transition()`, which `deliver` calls
/// inline on the scheduler thread.
///
/// Mutant: removing the `is_on_its_own_scheduler_or_sender_thread`
/// check in `HeartbeatPeriodic::drop` makes this fail: `elapsed` would
/// be at least the barrier's own bound (2s) instead of near-instant,
/// because the scheduler thread would be waiting on itself.
#[test]
fn dropping_a_writer_from_the_scheduler_thread_does_not_stall_it() {
    let clock = Arc::new(ManualClock::new(0));
    let domain = crate::test_support::domains::unique_domain();
    let mut builder = Participant::builder("drop-on-scheduler-thread")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast);
    builder.liveliness_clock = Some(clock.clone());
    let participant = builder.build().expect("participant");
    let topic_name = "DropOnSchedulerThread";
    let topic = participant.topic::<Ping>(topic_name).expect("topic");
    let writer = topic.writer().qos(QoS::reliable()).build().expect("writer");
    writer.write(&Ping { id: 1 }).expect("write");

    let shared = Arc::clone(
        participant
            .liveliness
            .as_ref()
            .expect("liveliness")
            .shared(),
    );

    // Pause the writer's own periodic tick so its HeartbeatPending
    // stays claimed ("busy") when the writer is dropped below --
    // otherwise `wait_idle` would return at once regardless of the fix
    // under test, and the mutant could not be told apart from the fix.
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    super::heartbeat_scheduler::test_pause::arm(topic_name, entered_tx, Arc::clone(&release));
    let _release_guard = ReleaseOnDrop(Arc::clone(&release));
    clock.advance(Duration::from_millis(100));
    shared.settle();
    entered_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the paused tick entered");

    // A plain LIVELINESS watch whose sink drops the writer the moment
    // it is told a transition -- which `deliver` calls inline, on the
    // scheduler thread.
    struct DropOnTransition {
        writer: std::sync::Mutex<Option<super::DataWriter<Ping>>>,
        dropped: std::sync::Mutex<bool>,
    }
    impl crate::dds::liveliness::LivelinessSink for DropOnTransition {
        fn transition(
            &self,
            _key: crate::dds::liveliness::WatchKey,
            _alive: bool,
        ) -> Option<Arc<crate::dds::reader::notices::Ordered>> {
            drop(self.writer.lock().unwrap_or_else(|e| e.into_inner()).take());
            *self.dropped.lock().unwrap_or_else(|e| e.into_inner()) = true;
            None
        }
    }
    let sink = Arc::new(DropOnTransition {
        writer: std::sync::Mutex::new(Some(writer)),
        dropped: std::sync::Mutex::new(false),
    });
    let renewal = shared.renewal();
    let sink_weak: Weak<dyn crate::dds::liveliness::LivelinessSink> = {
        let s: Arc<dyn crate::dds::liveliness::LivelinessSink> =
            Arc::clone(&sink) as Arc<dyn crate::dds::liveliness::LivelinessSink>;
        Arc::downgrade(&s)
    };
    let _watch_key = shared.watch(renewal, Duration::from_millis(10), sink_weak);

    let before = std::time::Instant::now();
    clock.advance(Duration::from_millis(10));
    shared.settle();
    let elapsed = before.elapsed();

    assert!(
        *sink.dropped.lock().unwrap_or_else(|e| e.into_inner()),
        "the sink's transition() must have run and dropped the writer"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "dropping a writer from the scheduler thread must not stall it on its own \
         deletion barrier: {elapsed:?}"
    );

    // Clean up: release the paused tick so nothing is left stuck before
    // the participant (and its sender thread) tear down.
    *release.0.lock().unwrap_or_else(|e| e.into_inner()) = true;
    release.1.notify_all();
    std::thread::sleep(Duration::from_millis(200));
    drop(topic);
    drop(participant);
}

/// The periodic HEARTBEAT path's non-blocking multicast fallback
/// (`UdpTransport::transmit_best_effort_multicast_resolved`) must honour
/// `MulticastMode` like every ordinary multicast send (`send`,
/// `send_user_data_multicast`, ...): calling the bare syscall directly,
/// with no `multicast_send_refused` check, would silently ignore
/// `ReceiveOnly` and `Disabled` for this one path: a reliable,
/// non-GROUP writer with no matched reader (so no unicast
/// destination) would still put its periodic HEARTBEAT on the multicast
/// wire, and `suppressed_multicast_sends` would never see it.
///
/// Mutant: dropping the `transport.multicast_send_refused(...)` check
/// from `multicast_allowed`'s computation (`send_heartbeat_best_effort`)
/// makes this fail both ways -- the (wrongly sent) HEARTBEAT reaches the
/// capture socket, and the suppression counter does not move.
#[test]
fn periodic_heartbeat_respects_multicast_mode() {
    for mode in [
        crate::transport::MulticastMode::ReceiveOnly,
        crate::transport::MulticastMode::Disabled,
    ] {
        let clock = Arc::new(ManualClock::new(0));
        let domain = crate::test_support::domains::unique_domain();
        let options = crate::transport::TransportOptions {
            multicast: mode,
            ..Default::default()
        };
        let mut builder = Participant::builder("multicast-mode-respected")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .with_transport_options(options);
        builder.liveliness_clock = Some(clock.clone());
        let participant = builder.build().expect("participant");
        let capture = user_multicast_capture(&participant);
        let topic_name = "MulticastModeRespected";
        let topic = participant.topic::<Ping>(topic_name).expect("topic");
        let writer = topic.writer().qos(QoS::reliable()).build().expect("writer");
        writer.write(&Ping { id: 1 }).expect("write");
        drain_heartbeats(&capture);

        let transport = participant.transport().expect("transport");
        let suppressed_before = transport.suppressed_multicast_sends();

        let shared = participant
            .liveliness
            .as_ref()
            .expect("liveliness")
            .shared();
        clock.advance(Duration::from_millis(100));
        shared.settle();

        // A generous, positive-receipt-shaped bound even for a NEGATIVE
        // outcome: give a wrongly sent packet every real chance to arrive
        // on the capture socket's own (short) read timeout before
        // declaring none did -- `drain_heartbeats` already drains until
        // its 300 ms read times out with nothing queued.
        let leaked = drain_heartbeats(&capture);
        assert!(
            leaked.is_empty(),
            "{mode:?}: no periodic HEARTBEAT may reach the wire while multicast emission is \
             refused by MulticastMode: {leaked:?}"
        );

        let suppressed_after = transport.suppressed_multicast_sends();
        assert!(
            suppressed_after > suppressed_before,
            "{mode:?}: the periodic tick's multicast attempt must be counted as suppressed, \
             the same as an ordinary multicast send -- before={suppressed_before} \
             after={suppressed_after}"
        );

        drop(topic);
        drop(participant);
    }
}

/// `send_heartbeat_best_effort`'s `delivered` is `true` only on a
/// successful UNICAST send -- its documented meaning. The durable-writer
/// first-match announcement's retry must not treat `delivered == false`
/// as "nothing was accepted this tick": that is also true whenever the
/// announcement reached the wire through the MULTICAST fallback
/// instead (no matched reader at all, here), and the retry would re-arm
/// `announce_pending` forever, resending the empty announcement every
/// period even though it had already, genuinely, succeeded.
///
/// `mark_announce_pending` is called directly (the same `pub(crate)`
/// hook `fire_heartbeat_tick`'s own contention path uses) rather than
/// orchestrating a real `send_serial` race from a discovery thread --
/// this test is about what happens to the flag AFTER a tick runs with
/// it set, not about how it got set.
///
/// Mutant: reverting the retry's check from `outcome.transmitted()`
/// (`delivered || multicast_delivered`) to `delivered` alone makes this
/// fail -- the second tick resends the announcement, because
/// `announce_pending` is wrongly re-armed after the first tick's
/// successful multicast delivery.
#[test]
fn durable_announce_retry_stops_after_a_successful_multicast_fallback() {
    let clock = Arc::new(ManualClock::new(0));
    let domain = crate::test_support::domains::unique_domain();
    let mut builder = Participant::builder("announce-retry-stops-on-multicast")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast);
    builder.liveliness_clock = Some(clock.clone());
    let participant = builder.build().expect("participant");
    let capture = user_multicast_capture(&participant);
    let topic_name = "AnnounceRetryStopsOnMulticast";
    let topic = participant.topic::<Ping>(topic_name).expect("topic");
    // Never written: `last_seq` stays 0, so `fire_heartbeat_tick` keeps
    // taking the announce-retry branch instead of the regular one.
    let writer = topic.writer().qos(QoS::reliable()).build().expect("writer");

    let shared_state = match writer._heartbeat_scheduler.as_ref().expect("scheduled") {
        super::heartbeat_scheduler::HeartbeatPeriodic::Participant { sink, .. } => {
            Arc::clone(sink.state())
        }
        super::heartbeat_scheduler::HeartbeatPeriodic::Standalone(_) => {
            panic!("expected a participant-scheduled writer")
        }
    };
    shared_state.mark_announce_pending();

    let shared = Arc::clone(
        participant
            .liveliness
            .as_ref()
            .expect("liveliness")
            .shared(),
    );
    clock.advance(Duration::from_millis(100));
    shared.settle();
    let first = drain_heartbeats(&capture);
    assert!(
        !first.is_empty(),
        "the pending announcement must reach the wire via the multicast fallback (no matched \
         reader exists here): {first:?}"
    );

    // The real assertion: a second period must send NOTHING -- the
    // first tick's successful multicast delivery must have cleared
    // `announce_pending`, not left it set for every period thereafter.
    clock.advance(Duration::from_millis(100));
    shared.settle();
    let second = drain_heartbeats(&capture);
    assert!(
        second.is_empty(),
        "a successful multicast fallback must stop the retry, not re-arm it forever: {second:?}"
    );

    drop(topic);
    drop(participant);
}

/// `multicast_send_refused` must not be called unconditionally during
/// `send_heartbeat_best_effort`'s prepare phase to decide
/// `multicast_allowed` -- it is a side-effecting call
/// (increments `suppressed_multicast_sends`, logs) that would be made on EVERY tick
/// whose `MulticastMode` disables multicast, even when unicast delivery
/// succeeded and the fallback was never needed at all. Every ordinary
/// multicast send only ever makes that call at the moment it actually
/// tries to use multicast; this periodic path must match that.
///
/// Mutant: reverting `multicast_allowed`'s computation to call
/// `multicast_send_refused` directly in prepare (instead of the
/// side-effect-free `multicast_send_allowed` there, with the real
/// refusal counted only after the gate, gated on `!delivered`) makes
/// this fail -- `suppressed_multicast_sends` moves even though the
/// matched reader's unicast locator took the HEARTBEAT.
#[test]
fn multicast_refusal_is_not_counted_when_unicast_succeeds() {
    let clock = Arc::new(ManualClock::new(0));
    let domain = crate::test_support::domains::unique_domain();
    let options = crate::transport::TransportOptions {
        multicast: crate::transport::MulticastMode::ReceiveOnly,
        ..Default::default()
    };
    let mut builder = Participant::builder("multicast-refusal-not-counted")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .with_transport_options(options);
    builder.liveliness_clock = Some(clock.clone());
    let participant = builder.build().expect("participant");
    let topic_name = "MulticastRefusalNotCountedOnUnicastSuccess";
    let topic = participant.topic::<Ping>(topic_name).expect("topic");
    let writer = topic.writer().qos(QoS::reliable()).build().expect("writer");
    writer.write(&Ping { id: 1 }).expect("write");

    // A matched, confirmed NATIVE reader with a resolvable unicast
    // locator, so the periodic tick's unicast send succeeds and the
    // multicast fallback is never even considered.
    let fsm = participant
        .discovery_fsm
        .as_ref()
        .expect("participant has a discovery fsm");
    let reg = fsm.endpoint_registry();
    let capture = crate::test_support::ports::bind_capture_socket();
    capture
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("read timeout");
    let dest = capture.local_addr().expect("capture addr");
    let mut pguid = [0x53u8; 16];
    pguid[12..16].copy_from_slice(&[0x00, 0x00, 0x01, 0xC1]);
    let participant_guid = crate::core::discovery::GUID::from_bytes(pguid);
    let domain_id = domain.id();
    let spdp = move || crate::protocol::discovery::SpdpData {
        participant_guid,
        lease_duration_ms: 100_000,
        domain_id,
        metatraffic_unicast_locators: vec![],
        default_unicast_locators: vec![],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    };
    fsm.handle_spdp(spdp());
    std::thread::sleep(Duration::from_millis(120));
    fsm.handle_spdp(spdp());
    let mut rguid = [0x53u8; 16];
    rguid[12..16].copy_from_slice(&[0x00, 0x00, 0x20, 0x04]);
    let reader_guid = crate::core::discovery::GUID::from_bytes(rguid);
    fsm.handle_sedp(crate::protocol::discovery::SedpData {
        topic_name: topic_name.to_string(),
        type_name: "Ping".to_string(),
        participant_guid,
        endpoint_guid: reader_guid,
        qos_hash: 0,
        qos: None,
        type_object: None,
        dependents: Vec::new(),
        type_object_legacy_v1: false,
        type_information: None,
        unicast_locators: vec![dest],
        user_data: None,
        shm_capability: None,
        endpoint_security_info: None,
        has_explicit_reliability: false,
        has_explicit_ownership: false,
        has_ownership_strength: false,
        type_consistency: None,
        group_entity_id: None,
    });
    reg.register_reader_locator(reader_guid, dest);
    reg.register(participant_guid, dest);

    let transport = participant.transport().expect("transport");
    let suppressed_before = transport.suppressed_multicast_sends();

    let shared = Arc::clone(
        participant
            .liveliness
            .as_ref()
            .expect("liveliness")
            .shared(),
    );
    clock.advance(Duration::from_millis(100));
    shared.settle();

    let mut buf = [0u8; 4096];
    let (n, _) = capture
        .recv_from(&mut buf)
        .expect("the periodic HEARTBEAT must reach the matched reader's unicast locator");
    assert!(n > 0);

    let suppressed_after = transport.suppressed_multicast_sends();
    assert_eq!(
        suppressed_after, suppressed_before,
        "no multicast refusal may be counted when unicast delivery succeeded and the \
         fallback was never needed -- before={suppressed_before} after={suppressed_after}"
    );

    drop(topic);
    drop(participant);
}
