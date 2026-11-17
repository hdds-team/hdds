// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! What a writer does with what its readers acknowledged.
//!
//! RTPS 2.5 8.4.1 steps 20-22: the DataWriter uses `is_acked_by_all` over
//! its matched readers to decide which changes it may remove, "taking into
//! account other DDS QoS such as DURABILITY". DDS 1.4 2.2.3.18: a full
//! RELIABLE KEEP_ALL history blocks the writer "until it can deliver the
//! necessary old values to all subscribers", and 2.2.2.4.2.11 bounds that
//! wait by `max_blocking_time`, after which `write` returns TIMEOUT.

use super::nack::{acked_floor, track_reader_proxy, RetransmitCfg, WriterNackHandler};
use super::runtime::{rtps_timestamp_from_unix_nanos, DROP_LIFECYCLE_ACK_GRACE};
use super::WriterBuilder;
use crate::core::discovery::multicast::control_types::AckNackInfo;
use crate::core::discovery::GUID;
use crate::dds::match_notification::PeerChange;
use crate::dds::{Error, QoS};
use crate::engine::NackHandler;
use crate::protocol::builder::RtpsEndpointContext;
use crate::qos::History;
use crate::reliability::{HistoryCache, ReliableMetrics, LENGTH_UNLIMITED};
use crate::transport::{PortMapping, UdpTransport};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const WRITER_EID: [u8; 4] = [0x00, 0x00, 0x01, 0x03];
const READER_EID: [u8; 4] = [0x00, 0x00, 0x01, 0x04];

#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct Probe {
    x: i32,
}

/// A keyed sample: only a keyed write registers an instance, and only a
/// registered instance is auto-unregistered when the writer is deleted.
#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct KeyedProbe {
    #[key]
    k: i32,
    x: i32,
}

fn reader(n: u8) -> GUID {
    GUID::new([0x31, n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], READER_EID)
}

fn volatile_cache() -> Arc<HistoryCache> {
    let cache = Arc::new(HistoryCache::new_with_limits(
        Arc::new(crate::core::rt::slabpool::SlabPool::new()),
        LENGTH_UNLIMITED,
        10_000_000,
        History::KeepAll,
    ));
    cache.set_release_policy(true, false);
    cache.set_acked_floor(u64::MAX);
    cache
}

/// Write changes 1..=`n` into `cache`, as a writer would before a match.
fn written(cache: &HistoryCache, n: u64) {
    for seq in 1..=n {
        cache.insert(seq, b"w").expect("insert");
    }
}

fn seqs(cache: &HistoryCache) -> Vec<u64> {
    cache.get_all_samples().iter().map(|s| s.0).collect()
}

#[test]
fn a_reliable_reader_is_owed_what_comes_after_it_matched_a_volatile_writer() {
    let cache = volatile_cache();
    let track = Arc::new(Mutex::new(HashMap::new()));
    written(&cache, 10);
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: false,
    };
    track_reader_proxy(&track, &cache, true, matched);
    assert_eq!(cache.acked_floor(), 10, "owed from 11 on, not the history");
}

#[test]
fn a_volatile_reader_is_owed_only_what_a_durable_writer_writes_after_it_matched() {
    let cache = volatile_cache();
    let track = Arc::new(Mutex::new(HashMap::new()));
    written(&cache, 10);
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: true,
    };
    track_reader_proxy(&track, &cache, false, matched);
    assert_eq!(cache.acked_floor(), 10, "owed from 11 on, not the history");
}

#[test]
fn a_request_below_the_watermark_is_not_owed() {
    use super::nack::split_at_watermark;
    // No watermark (no proxy): everything requested is owed.
    let one = || vec![std::ops::Range { start: 1, end: 4 }];
    assert_eq!(split_at_watermark(one(), None), (one(), vec![]));
    // Watermark 5: 1..=5 are not owed, 6 on is.
    assert_eq!(
        split_at_watermark(vec![1..4, 5..8, 9..10], Some(5)),
        (vec![6..8, 9..10], vec![1, 2, 3, 5])
    );
    // A range ending exactly past the watermark leaves nothing owed.
    let tail = vec![std::ops::Range { start: 3, end: 6 }];
    assert_eq!(split_at_watermark(tail, Some(5)), (vec![], vec![3, 4, 5]));
}

#[test]
fn a_reliable_reader_is_owed_the_whole_history_of_a_durable_writer() {
    let cache = volatile_cache();
    let track = Arc::new(Mutex::new(HashMap::new()));
    written(&cache, 10);
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: false,
    };
    track_reader_proxy(&track, &cache, false, matched);
    assert_eq!(cache.acked_floor(), 0);
}

#[test]
fn a_best_effort_reader_never_holds_the_history_back() {
    let cache = volatile_cache();
    let track = Arc::new(Mutex::new(HashMap::new()));
    written(&cache, 10);
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: false,
        volatile: false,
    };
    track_reader_proxy(&track, &cache, false, matched);
    assert!(track.lock().unwrap().is_empty());
    assert_eq!(cache.acked_floor(), u64::MAX);
}

#[test]
fn a_departed_reader_stops_holding_the_history_back() {
    let cache = volatile_cache();
    let track = Arc::new(Mutex::new(HashMap::new()));
    for n in [1, 2] {
        let matched = PeerChange::Matched {
            guid: reader(n),
            reliable: true,
            volatile: false,
        };
        track_reader_proxy(&track, &cache, false, matched);
    }
    track.lock().unwrap().insert(reader(2).as_bytes(), 7);
    assert_eq!(acked_floor(&track.lock().unwrap()), 0, "reader 1 holds 0");
    let left = PeerChange::Unmatched { guid: reader(1) };
    track_reader_proxy(&track, &cache, false, left);
    assert_eq!(cache.acked_floor(), 7, "only reader 2 is left");
    // The last reliable reader leaves: nobody is owed anything any more, so
    // everything counts as acknowledged by all (an empty `matched_readers`).
    // A floor of 0 here would freeze a VOLATILE history and block a full
    // RELIABLE KEEP_ALL writer that has no reader at all.
    let left = PeerChange::Unmatched { guid: reader(2) };
    track_reader_proxy(&track, &cache, false, left);
    assert_eq!(cache.acked_floor(), u64::MAX);
}

/// The domain lease comes back with the handler and must outlive its
/// transport: dropped inside, the domain went back to the pool while the
/// transport still held its unicast ports.
fn handler_on(
    cache: Arc<HistoryCache>,
    track: super::nack::AckTrack,
) -> (crate::test_support::domains::DomainLease, WriterNackHandler) {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 0).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 0, mapping).expect("test transport"));
    let handler = WriterNackHandler::new(
        "AckTestTopic".to_string(),
        cache,
        transport,
        Arc::new(ReliableMetrics::new()),
        RetransmitCfg {
            rtps_endpoint: Some(RtpsEndpointContext {
                guid_prefix: [0x30; 12],
                reader_entity_id: [0; 4],
                writer_entity_id: WRITER_EID,
                encapsulation_kind: 0x0007,
                publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
            }),
            endpoint_registry: None,
            canonical_encapsulation_kind: 0x0007,
            ack_track: Some(track),
            frag_route: Arc::new(super::frag_route::FragRouteProfile::new(
                u16::try_from(crate::protocol::builder::DEFAULT_FRAGMENT_SIZE)
                    .expect("DEFAULT_FRAGMENT_SIZE fits u16"),
            )),
            discovery_fsm: None,
        },
    );
    (lease, handler)
}

fn pure_ack(writer_entity_id: [u8; 4], bitmap_base: u64) -> AckNackInfo {
    AckNackInfo {
        reader_entity_id: READER_EID,
        writer_entity_id,
        missing_ranges: Vec::new(),
        bitmap_base,
        count: None,
    }
}

#[test]
fn a_pure_acknowledgement_on_the_control_path_frees_a_volatile_history() {
    let cache = volatile_cache();
    let track: super::nack::AckTrack = Arc::new(Mutex::new(HashMap::new()));
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: false,
    };
    track_reader_proxy(&track, &cache, true, matched);
    for seq in 1..=3 {
        cache.insert(seq, b"v").unwrap();
    }
    let (_domain, handler) = handler_on(Arc::clone(&cache), Arc::clone(&track));

    // An ACKNACK naming ANOTHER writer moves nothing here.
    handler.on_acknack(reader(1).as_bytes(), &pure_ack([0, 0, 0x02, 0x03], 4));
    assert_eq!(seqs(&cache), vec![1, 2, 3]);

    // A pure ACK (no hole) naming this writer: 1 and 2 are held by all.
    handler.on_acknack(reader(1).as_bytes(), &pure_ack(WRITER_EID, 3));
    assert_eq!(track.lock().unwrap()[&reader(1).as_bytes()], 2);
    assert_eq!(seqs(&cache), vec![3]);

    // A reader that was never matched as reliable has no proxy to move.
    handler.on_acknack(reader(9).as_bytes(), &pure_ack(WRITER_EID, 4));
    assert!(!track.lock().unwrap().contains_key(&reader(9).as_bytes()));
    assert_eq!(seqs(&cache), vec![3]);
}

#[test]
fn a_full_reliable_history_makes_write_wait_then_time_out_without_emitting() {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 2;
    qos.resource_limits.max_samples_per_instance = 2;
    let mut writer = WriterBuilder::<Probe>::new("test/blocking_write".to_string())
        .qos(qos)
        .with_transport(transport)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x32; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: WRITER_EID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: false,
    };
    track_reader_proxy(&writer.ack_track, &cache, true, matched);

    writer.write(&Probe { x: 1 }).expect("room for 1");
    writer.write(&Probe { x: 2 }).expect("room for 2");
    let next_before = writer.next_seq.load(Ordering::Relaxed);

    let start = Instant::now();
    let refused = writer.write(&Probe { x: 3 });
    let waited = start.elapsed();
    assert!(
        matches!(refused, Err(Error::WriteTimeout)),
        "got {refused:?}"
    );
    assert!(
        waited >= Duration::from_millis(90),
        "did not wait: {waited:?}"
    );
    assert_eq!(
        writer.next_seq.load(Ordering::Relaxed),
        next_before,
        "a refused write consumes no sequence number"
    );
    assert_eq!(seqs(&cache), vec![1, 2], "and journals nothing");

    // The reader acknowledges 1: its room is free and the write goes through.
    {
        let mut map = writer.ack_track.lock().unwrap();
        map.insert(reader(1).as_bytes(), 1);
        cache.set_acked_floor(acked_floor(&map));
    }
    writer
        .write(&Probe { x: 3 })
        .expect("room after the acknowledgement");
    assert_eq!(seqs(&cache), vec![2, 3]);
}

/// A write the writer's own history refuses is counted once as a
/// `cache_insert_errors` and is not a message sent; the writes before it
/// are, with their serialized bytes.
#[test]
fn a_write_refused_by_the_history_is_a_cache_insert_error_and_no_message() {
    let (metrics, _private) = crate::telemetry::private_metrics_for_test();
    let mut skipped = Vec::new();
    let lease = loop {
        let lease = crate::test_support::domains::unique_domain();
        if (200..=230).contains(&lease.id()) {
            break lease;
        }
        skipped.push(lease);
    };
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let mut qos = QoS::reliable()
        .keep_all()
        .max_blocking_time(Duration::from_millis(50));
    qos.resource_limits.max_samples = 2;
    qos.resource_limits.max_samples_per_instance = 2;
    let mut writer = WriterBuilder::<Probe>::new("test/telemetry_history_refusal".to_string())
        .qos(qos)
        .with_transport(transport)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x34; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: WRITER_EID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: false,
    };
    track_reader_proxy(&writer.ack_track, &cache, true, matched);

    writer.write(&Probe { x: 1 }).expect("room for 1");
    writer.write(&Probe { x: 2 }).expect("room for 2");
    assert_eq!(metrics.messages_sent(), 2);
    assert_eq!(metrics.cache_insert_errors(), 0);
    let bytes_of_two = metrics.bytes_sent();
    assert!(bytes_of_two > 0 && bytes_of_two % 2 == 0, "{bytes_of_two}");

    let refused = writer.write(&Probe { x: 3 });
    assert!(
        matches!(refused, Err(Error::WriteTimeout)),
        "got {refused:?}"
    );
    assert_eq!(metrics.cache_insert_errors(), 1, "one refused insert");
    assert_eq!(metrics.messages_sent(), 2, "a refused write is no message");
    assert_eq!(metrics.bytes_sent(), bytes_of_two, "and carries no bytes");
    assert_eq!(metrics.would_block(), 0, "a timeout is not a would-block");
}

/// The wait on a full writer history lasts the writer's RELIABILITY
/// `max_blocking_time` (DDS v1.4 Sec.2.2.3.14), not a fixed 100 ms.
#[test]
fn a_full_history_waits_the_qos_max_blocking_time() {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let mut qos = QoS::reliable()
        .keep_all()
        .max_blocking_time(Duration::from_millis(300));
    qos.resource_limits.max_samples = 1;
    qos.resource_limits.max_samples_per_instance = 1;
    let mut writer = WriterBuilder::<Probe>::new("test/blocking_write_qos".to_string())
        .qos(qos)
        .with_transport(transport)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x33; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: WRITER_EID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: false,
    };
    track_reader_proxy(&writer.ack_track, &cache, true, matched);
    writer.write(&Probe { x: 1 }).expect("room for 1");
    let start = Instant::now();
    let refused = writer.write(&Probe { x: 2 });
    let waited = start.elapsed();
    assert!(
        matches!(refused, Err(Error::WriteTimeout)),
        "got {refused:?}"
    );
    assert!(waited >= Duration::from_millis(300), "waited {waited:?}");
    assert!(waited < Duration::from_millis(450), "waited {waited:?}");
}

/// A TRANSIENT_LOCAL writer's history is bounded by HISTORY /
/// RESOURCE_LIMITS alone (DDS v1.4 Sec.2.2.3.4): `service_cleanup_delay`
/// (Sec.2.2.3.5) governs the TRANSIENT/PERSISTENT persistence service and
/// its own fictitious entities, never a TRANSIENT_LOCAL writer's own
/// history. Setting it on a TRANSIENT_LOCAL writer anyway must not spawn
/// the DurabilityService cleanup timer, which purges every change every
/// matched reader has acknowledged on a plain delay -- none of
/// Sec.2.2.3.5's three conditions (disposed, no live writer, delay since
/// both) checked. A late joiner that matched after every current reader
/// had acknowledged everything would get an empty history instead of the
/// KEEP_LAST depth it is owed.
#[test]
fn transient_local_keeps_its_acked_history_past_the_cleanup_delay() {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(3)
        .durability_service(crate::dds::qos::DurabilityService {
            service_cleanup_delay_us: 20_000,
            ..crate::dds::qos::DurabilityService::default()
        });
    let mut writer = WriterBuilder::<Probe>::new("test/transient_local_cleanup".to_string())
        .qos(qos)
        .with_transport(transport)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x37; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: WRITER_EID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    assert!(
        writer._cleanup_timer.is_none(),
        "TRANSIENT_LOCAL is not DurabilityService's persistence service: \
         a non-zero service_cleanup_delay must spawn no cleanup timer for it"
    );
    let cache = writer.history_cache.clone().expect("durable writer cache");
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: false,
    };
    track_reader_proxy(&writer.ack_track, &cache, false, matched);

    writer.write(&Probe { x: 1 }).expect("write 1");
    writer.write(&Probe { x: 2 }).expect("write 2");
    writer.write(&Probe { x: 3 }).expect("write 3");

    // Every matched reader acknowledges everything written.
    {
        let mut map = writer.ack_track.lock().unwrap();
        map.insert(reader(1).as_bytes(), 3);
        cache.set_acked_floor(acked_floor(&map));
    }

    // Long enough for a wrongly-wired cleanup timer (interval capped at 1 ms
    // here) to have run several times over.
    std::thread::sleep(Duration::from_millis(100));

    assert_eq!(
        seqs(&cache),
        vec![1, 2, 3],
        "a late joiner must still get the full KEEP_LAST(3) history: \
         TRANSIENT_LOCAL's own acknowledged samples are not \
         DurabilityService's to clean up"
    );
}

/// A coherent write that fails after its stamp into the open set -- here
/// `journal_before_emission` timing out because the writer's own
/// RESOURCE_LIMITS are full and unacknowledged, an ordinary DDS v1.4
/// Sec.2.2.3.14 outcome -- gives its sequence number back under the
/// Publisher's lock (`abandon_unpublished_sequence`). An
/// `end_coherent_changes` racing it must not wait, under that same lock,
/// for the write to finish: each would wait for the other forever, and the
/// whole Publisher with them. Both calls return; the write reports its
/// timeout.
#[test]
fn coherent_write_timeout_races_a_concurrent_close() {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let wait = Duration::from_millis(200);
    let mut qos = QoS::reliable()
        .keep_all()
        .transient_local()
        .presentation_topic_coherent()
        .max_blocking_time(wait);
    qos.resource_limits.max_samples = 1;
    qos.resource_limits.max_samples_per_instance = 1;
    let publisher = Arc::new(crate::dds::Publisher::new(qos.clone(), None, None, None));
    let mut writer = WriterBuilder::<Probe>::new("test/coherent_deadlock".to_string())
        .qos(qos)
        .with_transport(transport)
        .publisher(&publisher)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x36; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: WRITER_EID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: false,
    };
    track_reader_proxy(&writer.ack_track, &cache, true, matched);

    publisher.begin_coherent_changes().unwrap();
    writer
        .write(&Probe { x: 1 })
        .expect("room for the first sample");

    let (write_tx, write_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = writer.write(&Probe { x: 2 });
        let _ = write_tx.send(result);
    });

    // Let write(2) stamp the coherent set and start blocking on the full,
    // unacknowledged history before the close races it.
    std::thread::sleep(Duration::from_millis(50));

    let (close_tx, close_rx) = std::sync::mpsc::channel();
    let publisher_for_close = Arc::clone(&publisher);
    std::thread::spawn(move || {
        let result = publisher_for_close.end_coherent_changes();
        let _ = close_tx.send(result);
    });

    let close_result = close_rx.recv_timeout(Duration::from_secs(3));
    let write_result = write_rx.recv_timeout(Duration::from_secs(3));
    assert!(
        close_result.is_ok(),
        "end_coherent_changes never returned: deadlocked against the \
         timed-out write's abandon path reacquiring set_lock"
    );
    assert!(
        write_result.is_ok(),
        "the timed-out write() never returned: deadlocked waiting for \
         set_lock held by end_coherent_changes"
    );
    assert!(close_result.unwrap().is_ok(), "the set closes");
    assert!(
        matches!(write_result.unwrap(), Err(crate::dds::Error::WriteTimeout)),
        "the blocked write reports its timeout"
    );
}

/// A coherent writer of TOPIC scope with one co-located reader (so its
/// writes take the intra-process path) whose history holds `max_samples`
/// changes a remote reliable reader never acknowledges: the next write
/// blocks `wait`, then fails.
fn coherent_writer_with_a_full_history(
    topic: &str,
    max_samples: usize,
    wait: Duration,
) -> (
    super::DataWriter<Probe>,
    Arc<crate::dds::Publisher>,
    Arc<crate::dds::DataReader<Probe>>,
    crate::test_support::domains::DomainLease,
) {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let mut qos = QoS::reliable()
        .keep_all()
        .transient_local()
        .presentation_topic_coherent()
        .max_blocking_time(wait);
    qos.resource_limits.max_samples = max_samples;
    qos.resource_limits.max_samples_per_instance = max_samples;
    let publisher = Arc::new(crate::dds::Publisher::new(qos.clone(), None, None, None));
    let mut writer = WriterBuilder::<Probe>::new(topic.to_string())
        .qos(qos)
        .with_transport(transport)
        .publisher(&publisher)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x37; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: WRITER_EID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: false,
    };
    track_reader_proxy(&writer.ack_track, &cache, true, matched);
    let local = Arc::new(
        crate::dds::reader::ReaderBuilder::<Probe>::new(topic.to_string())
            .qos(QoS::reliable().keep_all())
            .build()
            .expect("reader build"),
    );
    local.bind_to_writer(writer.merger());
    (writer, publisher, local, lease)
}

fn taken(reader: &crate::dds::DataReader<Probe>) -> Vec<i32> {
    let mut got = Vec::new();
    while let Some(sample) = reader.take().expect("take") {
        got.push(sample.x);
    }
    got
}

/// A member of a coherent set whose write fails was never part of the set
/// (the application got the error): the set reaches the co-located reader
/// without it, at its close, and nothing of it before.
#[test]
fn a_coherent_set_is_delivered_locally_without_its_failed_member() {
    let (writer, publisher, local, _lease) = coherent_writer_with_a_full_history(
        "test/coherent_failed_member",
        2,
        Duration::from_millis(100),
    );
    publisher.begin_coherent_changes().unwrap();
    writer.write(&Probe { x: 1 }).expect("room for 1");
    writer.write(&Probe { x: 2 }).expect("room for 2");
    assert!(
        matches!(writer.write(&Probe { x: 3 }), Err(Error::WriteTimeout)),
        "fixture: the third write finds the history full"
    );
    assert_eq!(taken(&local), Vec::<i32>::new(), "nothing before the close");
    publisher.end_coherent_changes().unwrap();
    assert_eq!(
        taken(&local),
        vec![1, 2],
        "the set, without its failed member"
    );
}

/// The close comes while a member is still blocked in its write: it
/// returns at once, delivering nothing (the set is incomplete); the
/// member's failure then completes the set, which reaches the co-located
/// reader without it.
#[test]
fn a_member_failing_after_the_close_delivers_the_rest_of_its_set() {
    let wait = Duration::from_millis(800);
    let (writer, publisher, local, _lease) =
        coherent_writer_with_a_full_history("test/coherent_failing_straggler", 1, wait);
    publisher.begin_coherent_changes().unwrap();
    writer.write(&Probe { x: 1 }).expect("room for 1");

    let (write_tx, write_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = write_tx.send(writer.write(&Probe { x: 2 }));
    });
    std::thread::sleep(Duration::from_millis(50));

    let (close_tx, close_rx) = std::sync::mpsc::channel();
    let publisher_for_close = Arc::clone(&publisher);
    std::thread::spawn(move || {
        let _ = close_tx.send(publisher_for_close.end_coherent_changes());
    });
    close_rx
        .recv_timeout(Duration::from_millis(400))
        .expect("the close must not wait for the blocked member")
        .expect("the set closes");
    assert!(
        write_rx.try_recv().is_err(),
        "fixture: the member is still blocked at the close"
    );
    assert_eq!(taken(&local), Vec::<i32>::new(), "incomplete: nothing yet");

    let refused = write_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("the blocked write returns");
    assert!(
        matches!(refused, Err(Error::WriteTimeout)),
        "got {refused:?}"
    );
    assert_eq!(
        taken(&local),
        vec![1],
        "completed by the failure, without it"
    );
}

/// One `write()` blocks at most `max_blocking_time` in all (DDS v1.4
/// Sec.2.2.3.14: "the maximum duration the write operation may block"),
/// however many things it waits for. A durable RELIABLE writer waits for
/// room in a co-located reliable reader's history first, then in its own
/// (held by a remote reliable reader that does not acknowledge): the local
/// reader taking part-way through leaves the second wait only what remains
/// of the first: the waits share one deadline.
#[test]
fn a_write_blocks_at_most_its_max_blocking_time_in_all() {
    let wait = Duration::from_millis(300);
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let mut qos = QoS::reliable()
        .keep_all()
        .transient_local()
        .max_blocking_time(wait);
    qos.resource_limits.max_samples = 1;
    qos.resource_limits.max_samples_per_instance = 1;
    let mut writer = WriterBuilder::<Probe>::new("test/one_deadline".to_string())
        .qos(qos)
        .with_transport(transport)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x34; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: WRITER_EID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: false,
    };
    track_reader_proxy(&writer.ack_track, &cache, true, matched);
    let mut reader_qos = QoS::reliable().keep_all();
    reader_qos.resource_limits.max_samples = 1;
    let local = Arc::new(
        crate::dds::reader::ReaderBuilder::<Probe>::new("test/one_deadline".to_string())
            .qos(reader_qos)
            .build()
            .expect("reader build"),
    );
    local.bind_to_writer(writer.merger());
    writer.write(&Probe { x: 1 }).expect("room for 1");

    let taker = {
        let local = Arc::clone(&local);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            local.take().expect("take")
        })
    };
    let start = Instant::now();
    let refused = writer.write(&Probe { x: 2 });
    let waited = start.elapsed();
    assert_eq!(taker.join().expect("taker"), Some(Probe { x: 1 }));
    assert!(
        matches!(refused, Err(Error::WriteTimeout)),
        "got {refused:?}"
    );
    assert!(waited >= wait, "waited {waited:?}");
    assert!(
        waited < wait + Duration::from_millis(100),
        "one deadline for the whole write, not one per wait: waited {waited:?}"
    );
}

#[test]
fn an_empty_history_advertises_the_next_sequence_number() {
    use super::heartbeat_scheduler::advertised_first_seq;
    assert_eq!(advertised_first_seq(None, 0), 1, "nothing written yet");
    assert_eq!(
        advertised_first_seq(None, 10),
        11,
        "all ten acknowledged and removed"
    );
    assert_eq!(advertised_first_seq(Some(4), 10), 4);
}

/// The domain lease comes back last and must outlive the writer's transport.
fn built_writer(
    qos: QoS,
    participant_id: u8,
) -> (
    super::DataWriter<Probe>,
    Arc<HistoryCache>,
    crate::test_support::domains::DomainLease,
) {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), participant_id).expect("port mapping");
    let transport =
        Arc::new(UdpTransport::new(lease.id(), participant_id, mapping).expect("transport"));
    let mut writer = WriterBuilder::<Probe>::new("test/acknowledged".to_string())
        .qos(qos)
        .with_transport(transport)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x33; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: WRITER_EID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    (writer, cache, lease)
}

#[test]
fn a_volatile_writer_with_no_reliable_reader_keeps_only_its_newest_change() {
    // No reliable reader is matched: nobody is owed a repair, so the history
    // does not grow towards max_samples.
    let (writer, cache, _domain) = built_writer(QoS::reliable().keep_all(), 3);
    for x in 1..=3 {
        writer.write(&Probe { x }).expect("write");
    }
    assert_eq!(seqs(&cache), vec![3]);
}

#[test]
fn a_volatile_writer_removes_what_its_reader_acknowledged_and_a_durable_one_keeps_it() {
    for (durable, participant_id) in [(false, 4u8), (true, 5u8)] {
        let qos = if durable {
            QoS::reliable().transient_local().keep_all()
        } else {
            QoS::reliable().keep_all()
        };
        let (writer, cache, _domain) = built_writer(qos, participant_id);
        let matched = PeerChange::Matched {
            guid: reader(1),
            reliable: true,
            volatile: false,
        };
        track_reader_proxy(&writer.ack_track, &cache, !durable, matched);
        for x in 1..=3 {
            writer.write(&Probe { x }).expect("write");
        }
        {
            let mut map = writer.ack_track.lock().unwrap();
            map.insert(reader(1).as_bytes(), 3);
            cache.set_acked_floor(acked_floor(&map));
        }
        let expected: Vec<u64> = if durable { vec![1, 2, 3] } else { Vec::new() };
        assert_eq!(seqs(&cache), expected, "durable={durable}");
    }
}

#[test]
fn a_live_dispose_journals_the_timestamp_it_was_sent_with() {
    let (writer, cache, _domain) = built_writer(QoS::reliable().transient_local().keep_all(), 6);
    let seq = writer.next_seq.load(Ordering::Relaxed);
    writer.dispose(&Probe { x: 1 }).expect("dispose");
    let change = cache
        .get_change(seq)
        .expect("the dispose is in the history");
    assert!(change.metadata.status_info.is_some());
    assert!(
        change.metadata.source_ts_known,
        "a repair must be able to reproduce the live INFO_TS"
    );
}

#[test]
fn the_live_dispose_and_its_journal_carry_the_same_timestamp() {
    // Capture the dispose the writer actually sends (a writer without
    // discovery routes to every registered participant), then compare its
    // INFO_TS with the history's: a repair reproduces the journaled one, so
    // they must be the same value.
    let (mut writer, cache, _domain) =
        built_writer(QoS::reliable().transient_local().keep_all(), 7);
    let capture = crate::test_support::ports::bind_capture_socket();
    capture
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("timeout");
    let registry = crate::core::discovery::EndpointRegistry::new();
    registry.register(
        GUID::new([0x44; 12], [0x00, 0x00, 0x01, 0xC1]),
        capture.local_addr().expect("capture addr"),
    );
    writer.endpoint_registry = Some(registry);

    let seq = writer.next_seq.load(Ordering::Relaxed);
    writer.dispose(&Probe { x: 1 }).expect("dispose");

    let mut buf = [0u8; 2048];
    let (n, _) = capture
        .recv_from(&mut buf)
        .expect("the live dispose must arrive");
    let pkt = &buf[..n];
    assert_eq!(pkt[20], 0x09, "INFO_TS precedes the DATA");
    let live_ts = (
        u32::from_le_bytes([pkt[24], pkt[25], pkt[26], pkt[27]]),
        u32::from_le_bytes([pkt[28], pkt[29], pkt[30], pkt[31]]),
    );
    let journaled = cache.get_change(seq).expect("journaled").metadata.source_ts;
    assert_eq!(live_ts, journaled);
}

#[test]
fn a_fragment_request_for_a_change_a_reader_is_not_owed_is_refused() {
    let cache = volatile_cache();
    let track: super::nack::AckTrack = Arc::new(Mutex::new(HashMap::new()));
    written(&cache, 5); // five changes written before the match
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: true,
    };
    track_reader_proxy(&track, &cache, false, matched);
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 6).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 6, mapping).expect("transport"));
    let handler = super::nack::WriterNackFragHandler::new(
        "AckTestTopic".to_string(),
        Arc::clone(&cache),
        transport,
        Arc::new(ReliableMetrics::new()),
        WRITER_EID,
        RetransmitCfg {
            rtps_endpoint: None,
            endpoint_registry: None,
            canonical_encapsulation_kind: 0x0007,
            ack_track: Some(Arc::clone(&track)),
            frag_route: Arc::new(super::frag_route::FragRouteProfile::new(
                u16::try_from(crate::protocol::builder::DEFAULT_FRAGMENT_SIZE)
                    .expect("DEFAULT_FRAGMENT_SIZE fits u16"),
            )),
            discovery_fsm: None,
        },
    );
    assert!(
        !handler.owes(reader(1).as_bytes(), 5),
        "written before it matched"
    );
    assert!(handler.owes(reader(1).as_bytes(), 6), "written after");
    assert!(
        handler.owes(reader(2).as_bytes(), 1),
        "a reader with no proxy here is not judged by another's"
    );
}

#[test]
fn a_reader_discovered_but_not_paired_yet_is_not_answered() {
    use super::nack::discovered_but_unpaired;
    use crate::core::discovery::multicast::DiscoveryFsm;
    use crate::protocol::discovery::SedpData;
    let topic = "UnpairedTopic";
    let fsm = DiscoveryFsm::new(GUID::zero(), 30_000);
    let remote = GUID::new([0x5B; 12], [0x00, 0x00, 0x01, 0x04]);
    // A participant announced once, past the startup probation: known, not
    // yet confirmed, so the match its endpoints make is held back.
    std::thread::sleep(Duration::from_millis(300));
    fsm.handle_spdp(crate::protocol::discovery::SpdpData {
        participant_guid: GUID::new([0x5B; 12], [0x00, 0x00, 0x01, 0xC1]),
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
        type_name: "Probe".to_string(),
        participant_guid: GUID::new([0x5B; 12], [0x00, 0x00, 0x01, 0xC1]),
        endpoint_guid: remote,
        qos_hash: 1,
        qos: Some(QoS::reliable()),
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
    });
    assert!(
        fsm.find_readers_for_topic(topic)
            .iter()
            .any(|r| r.endpoint_guid == remote),
        "the fixture must announce a reader"
    );
    let track: super::nack::AckTrack = Arc::new(Mutex::new(HashMap::new()));
    let guid = remote.as_bytes();

    assert!(discovered_but_unpaired(
        Some(&track),
        Some(&fsm),
        topic,
        guid
    ));
    // Paired: served (by its watermark).
    track.lock().unwrap().insert(guid, 0);
    assert!(!discovered_but_unpaired(
        Some(&track),
        Some(&fsm),
        topic,
        guid
    ));
    // Never announced (an older peer acknowledging under another id): served.
    assert!(!discovered_but_unpaired(
        Some(&track),
        Some(&fsm),
        topic,
        reader(7).as_bytes()
    ));
    // Nothing to judge by: served, as before.
    track.lock().unwrap().clear();
    assert!(!discovered_but_unpaired(None, Some(&fsm), topic, guid));
    assert!(!discovered_but_unpaired(Some(&track), None, topic, guid));
}

#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct Blob {
    data: Vec<u8>,
}

/// A writer built by a participant hands its fragment handler the SAME
/// acknowledgement table its ACKNACK handler fills: a fragment request for a
/// change the reader is not owed is answered with a GAP, not the fragments.
#[test]
fn a_built_writer_refuses_fragments_of_what_a_reader_is_not_owed() {
    let domain = crate::test_support::domains::unique_domain();
    let participant = crate::Participant::builder("owed_frag_writer")
        .domain_id(domain.id())
        .with_transport(crate::TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let writer = participant
        .topic::<Blob>("OwedFragTopic")
        .expect("topic")
        .writer()
        .qos(QoS::reliable().transient_local().keep_last(4))
        .build()
        .expect("writer");
    writer
        .write(&Blob {
            data: vec![0x5A; 10_000],
        })
        .expect("a fragmented sample");
    let cache = writer.history_cache.clone().expect("history");
    // A VOLATILE reader paired after that write.
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: true,
    };
    track_reader_proxy(&writer.ack_track, &cache, false, matched);

    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("reader socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("timeout");
    participant
        .discovery()
        .expect("discovery")
        .endpoint_registry()
        .register_reader_locator(reader(1), socket.local_addr().expect("addr"));
    let writer_entity_id = writer.rtps_endpoint.expect("endpoint").writer_entity_id;
    let panics = participant
        .registry
        .as_ref()
        .expect("registry")
        .deliver_nack_frag(&writer_entity_id, 1, &[1], Some(reader(1).as_bytes()));
    assert_eq!(panics, 0);

    let mut buf = [0u8; 4096];
    let len = socket.recv(&mut buf).expect("an answer");
    let mut ids = Vec::new();
    crate::core::discovery::multicast::classifier::walk::for_each_submessage(&buf[..len], |sub| {
        ids.push(sub.id);
        crate::core::discovery::multicast::classifier::walk::Step::Continue
    });
    assert!(ids.contains(&0x08), "a GAP: {ids:02x?}");
    assert!(!ids.contains(&0x16), "no fragment: {ids:02x?}");
}

/// A reliable reader whose match the FSM still holds back (a quiet peer:
/// its participant announced once, its SEDP came ~150 ms
/// later, and nothing confirms it past the probation boundary) is a reader
/// the writer owes. RTPS 2.5 8.4.7.4: the writer's ReaderProxy is a
/// discovery event, `is_acked_by_all` runs over it. So a KEEP_ALL writer
/// keeps what it wrote for that reader, and the reader's ACKNACK is honoured
/// and frees what it acknowledged. Before: no proxy until the match
/// surfaced, the history counted as acknowledged by all (only the newest
/// change kept), and the ACKNACK ignored as "not paired yet".
#[test]
fn a_reader_whose_match_is_deferred_is_owed_the_history_and_heard() {
    use crate::core::discovery::multicast::control_types::AckNackInfo;
    use crate::dds::DDS;
    use crate::protocol::discovery::{SedpData, SpdpData};
    let _ = crate::core::rt::init_slab_pool();
    let domain = crate::test_support::domains::unique_domain();
    let participant = crate::Participant::builder("deferred_reader_owed")
        .domain_id(domain.id())
        .with_transport(crate::TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let topic = "DeferredReaderOwed";
    let writer = participant
        .topic::<Probe>(topic)
        .expect("topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reliable KEEP_ALL VOLATILE writer");
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    let fsm = participant.discovery().expect("discovery FSM");
    assert!(
        fsm.uptime() < Duration::from_millis(90),
        "fixture: the peer must announce early in the probation window"
    );

    // Written before the reader is discovered: not owed to it. With no
    // reliable reader tracked, the VOLATILE history keeps only its newest.
    for x in 1..=2 {
        writer.write(&Probe { x }).expect("write before discovery");
    }
    assert_eq!(seqs(&cache), vec![2]);

    let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer socket");
    let peer_addr = peer.local_addr().expect("peer addr");
    let prefix = [0x5A; 12];
    let remote = GUID::new(prefix, [0x00, 0x00, 0x01, 0xC1]);
    let reader_guid = GUID::new(prefix, READER_EID);
    fsm.handle_spdp(SpdpData {
        participant_guid: remote,
        lease_duration_ms: 100_000,
        domain_id: domain.id(),
        metatraffic_unicast_locators: vec![peer_addr],
        default_unicast_locators: vec![peer_addr],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: None,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    });
    // Its SEDP is its one liveness mark (at least 100 ms after we first heard
    // it), and it must land before the probation boundary: a first mark
    // after the boundary would let its match surface at once.
    std::thread::sleep(Duration::from_millis(120));
    assert!(
        fsm.uptime() < Duration::from_millis(250),
        "fixture: the reader's SEDP lands before the probation boundary"
    );
    fsm.handle_sedp(SedpData {
        topic_name: topic.to_string(),
        type_name: Probe::type_descriptor().type_name.to_string(),
        participant_guid: remote,
        endpoint_guid: reader_guid,
        qos_hash: 1,
        qos: Some(QoS::reliable()),
        type_object: None,
        dependents: Vec::new(),
        type_object_legacy_v1: false,
        unicast_locators: vec![peer_addr],
        user_data: None,
        shm_capability: None,
        has_explicit_reliability: true,
        has_explicit_ownership: false,
        has_ownership_strength: false,
        type_information: None,
        type_consistency: None,
        group_entity_id: None,
        endpoint_security_info: None,
    });
    let uptime = fsm.uptime();
    if uptime < Duration::from_millis(320) {
        std::thread::sleep(Duration::from_millis(320) - uptime);
    }
    assert!(fsm.is_probation_done(), "past the probation boundary");
    assert!(fsm.has_participant(&remote), "kept: it spoke after 100 ms");
    assert!(
        !fsm.is_participant_confirmed(&prefix),
        "fixture: the match is still deferred"
    );

    assert_eq!(
        writer
            .ack_track
            .lock()
            .unwrap()
            .get(&reader_guid.as_bytes()),
        Some(&2),
        "a ReaderProxy from discovery, owed everything written from then on \
         (what was written before its discovery is not owed)"
    );
    assert!(seqs(&cache).is_empty(), "nothing it is not owed is kept");
    for x in 3..=5 {
        writer.write(&Probe { x }).expect("write");
    }
    assert_eq!(seqs(&cache), vec![3, 4, 5], "kept for the reader it owes");

    let writer_entity_id = writer.rtps_endpoint.expect("endpoint").writer_entity_id;
    let ack = AckNackInfo {
        reader_entity_id: READER_EID,
        writer_entity_id,
        missing_ranges: Vec::new(),
        bitmap_base: 5,
        count: None,
    };
    let panics = participant
        .registry
        .as_ref()
        .expect("registry")
        .deliver_acknack(reader_guid.as_bytes(), &ack);
    assert_eq!(panics, 0);
    assert_eq!(
        writer
            .ack_track
            .lock()
            .unwrap()
            .get(&reader_guid.as_bytes()),
        Some(&4),
        "its ACKNACK moved its watermark"
    );
    assert_eq!(seqs(&cache), vec![5], "and freed what it acknowledged");
}

/// The other side of taking a ReaderProxy at discovery: a reader whose
/// participant spoke once after its first 100 ms (its SEDP) and then fell
/// silent, never confirmed, holds a reliable KEEP_ALL writer's history back
/// only until its participant has been silent for a second, not for its
/// whole lease (100 s here): the participant is purged and the proxy goes
/// with it, and the writer stops blocking. Before: the proxy stayed for the
/// lease and every write past the history's depth timed out.
#[test]
fn a_reader_whose_participant_falls_silent_unconfirmed_stops_holding_the_history_back() {
    use crate::dds::DDS;
    use crate::protocol::discovery::{SedpData, SpdpData};
    let _ = crate::core::rt::init_slab_pool();
    let domain = crate::test_support::domains::unique_domain();
    let participant = crate::Participant::builder("silent_unconfirmed_reader")
        .domain_id(domain.id())
        .with_transport(crate::TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let topic = "SilentUnconfirmedReader";
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 2;
    qos.resource_limits.max_samples_per_instance = 2;
    let writer = participant
        .topic::<Probe>(topic)
        .expect("topic")
        .writer()
        .qos(qos)
        .build()
        .expect("reliable KEEP_ALL VOLATILE writer");
    let fsm = participant.discovery().expect("discovery FSM");
    assert!(
        fsm.uptime() < Duration::from_millis(90),
        "fixture: the peer must announce early in the probation window"
    );

    let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer socket");
    let peer_addr = peer.local_addr().expect("peer addr");
    let prefix = [0x5B; 12];
    let remote = GUID::new(prefix, [0x00, 0x00, 0x01, 0xC1]);
    let reader_guid = GUID::new(prefix, READER_EID);
    fsm.handle_spdp(SpdpData {
        participant_guid: remote,
        lease_duration_ms: 100_000,
        domain_id: domain.id(),
        metatraffic_unicast_locators: vec![peer_addr],
        default_unicast_locators: vec![peer_addr],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: None,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    });
    // Its SEDP is its one liveness mark (at least 100 ms after we first heard
    // it), and it must land before the probation boundary: a first mark
    // after the boundary would let its match surface at once.
    std::thread::sleep(Duration::from_millis(120));
    assert!(
        fsm.uptime() < Duration::from_millis(250),
        "fixture: the reader's SEDP lands before the probation boundary"
    );
    fsm.handle_sedp(SedpData {
        topic_name: topic.to_string(),
        type_name: Probe::type_descriptor().type_name.to_string(),
        participant_guid: remote,
        endpoint_guid: reader_guid,
        qos_hash: 1,
        qos: Some(QoS::reliable()),
        type_object: None,
        dependents: Vec::new(),
        type_object_legacy_v1: false,
        unicast_locators: vec![peer_addr],
        user_data: None,
        shm_capability: None,
        has_explicit_reliability: true,
        has_explicit_ownership: false,
        has_ownership_strength: false,
        type_information: None,
        type_consistency: None,
        group_entity_id: None,
        endpoint_security_info: None,
    });
    let last_heard = Instant::now();
    assert!(
        writer
            .ack_track
            .lock()
            .unwrap()
            .contains_key(&reader_guid.as_bytes()),
        "fixture: a ReaderProxy from discovery"
    );
    writer.write(&Probe { x: 1 }).expect("room for 1");
    writer.write(&Probe { x: 2 }).expect("room for 2");
    assert!(
        matches!(writer.write(&Probe { x: 3 }), Err(Error::WriteTimeout)),
        "fixture: the reader holds the history back"
    );

    // A second of silence, plus the control thread's tick and a margin.
    let purge_due = last_heard + Duration::from_millis(1_400);
    if let Some(left) = purge_due.checked_duration_since(Instant::now()) {
        std::thread::sleep(left);
    }
    assert!(
        !fsm.has_participant(&remote),
        "silent for a second without becoming eligible: purged"
    );
    assert!(
        !writer
            .ack_track
            .lock()
            .unwrap()
            .contains_key(&reader_guid.as_bytes()),
        "its ReaderProxy went with it"
    );
    let start = Instant::now();
    writer
        .write(&Probe { x: 3 })
        .expect("the writer no longer blocks");
    assert!(start.elapsed() < Duration::from_millis(90), "no wait");
}

/// The VOLATILE HEARTBEAT floor and the reader's watermark are taken at the
/// same instant, the discovery pairing. A reliable reader whose match is
/// deferred (its participant spoke once after its first 100 ms) is owed what
/// the writer writes from its discovery on; when its match surfaces later,
/// the floor must not hide those samples behind the HEARTBEAT's firstSN,
/// or one of them lost on the way is owed and never asked for. The floor is
/// not taken at the surfaced match from the writer's last sequence number:
/// that would sit above everything written meanwhile.
#[test]
fn what_a_reader_is_owed_before_its_match_surfaces_stays_above_the_heartbeat_floor() {
    use crate::dds::DDS;
    use crate::protocol::discovery::{SedpData, SpdpData};
    let _ = crate::core::rt::init_slab_pool();
    let domain = crate::test_support::domains::unique_domain();
    let participant = crate::Participant::builder("floor_at_discovery")
        .domain_id(domain.id())
        .with_transport(crate::TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let topic = "FloorAtDiscovery";
    let writer = participant
        .topic::<Probe>(topic)
        .expect("topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reliable KEEP_ALL VOLATILE writer");
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    let fsm = participant.discovery().expect("discovery FSM");
    assert!(
        fsm.uptime() < Duration::from_millis(90),
        "fixture: the peer must announce early in the probation window"
    );

    let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer socket");
    let peer_addr = peer.local_addr().expect("peer addr");
    let prefix = [0x5C; 12];
    let remote = GUID::new(prefix, [0x00, 0x00, 0x01, 0xC1]);
    let reader_guid = GUID::new(prefix, READER_EID);
    fsm.handle_spdp(SpdpData {
        participant_guid: remote,
        lease_duration_ms: 100_000,
        domain_id: domain.id(),
        metatraffic_unicast_locators: vec![peer_addr],
        default_unicast_locators: vec![peer_addr],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: None,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    });
    // Its SEDP is its one liveness mark (at least 100 ms after we first heard
    // it), and it must land before the probation boundary: a first mark
    // after the boundary would let its match surface at once.
    std::thread::sleep(Duration::from_millis(120));
    assert!(
        fsm.uptime() < Duration::from_millis(250),
        "fixture: the reader's SEDP lands before the probation boundary"
    );
    fsm.handle_sedp(SedpData {
        topic_name: topic.to_string(),
        type_name: Probe::type_descriptor().type_name.to_string(),
        participant_guid: remote,
        endpoint_guid: reader_guid,
        qos_hash: 1,
        qos: Some(QoS::reliable()),
        type_object: None,
        dependents: Vec::new(),
        type_object_legacy_v1: false,
        unicast_locators: vec![peer_addr],
        user_data: None,
        shm_capability: None,
        has_explicit_reliability: true,
        has_explicit_ownership: false,
        has_ownership_strength: false,
        type_information: None,
        type_consistency: None,
        group_entity_id: None,
        endpoint_security_info: None,
    });
    let sedp_at = Instant::now();
    for x in 1..=3 {
        writer.write(&Probe { x }).expect("write");
    }
    assert_eq!(seqs(&cache), vec![1, 2, 3], "owed from its discovery");
    assert_eq!(writer.matched_reader_count(), 0, "fixture: match deferred");

    // Its next control message, at a distinct instant past the boundary,
    // confirms it and surfaces the match.
    let uptime = fsm.uptime();
    if uptime < Duration::from_millis(320) {
        std::thread::sleep(Duration::from_millis(320) - uptime);
    }
    let mark_due = sedp_at + Duration::from_millis(110);
    if let Some(left) = mark_due.checked_duration_since(Instant::now()) {
        std::thread::sleep(left);
    }
    fsm.touch_participant_by_prefix(&prefix);
    assert_eq!(writer.matched_reader_count(), 1, "the match surfaced");

    let state = writer
        ._heartbeat_scheduler
        .as_ref()
        .expect("reliable writer heartbeat scheduler")
        .state();
    assert_eq!(
        state.heartbeat_first_seq(1),
        1,
        "the HEARTBEAT still advertises what the reader is owed"
    );

    // Sample 2 lost on the way: the reader asks, and it is repaired.
    peer.set_nonblocking(true).expect("nonblocking");
    let mut buf = [0u8; 4096];
    while peer.recv(&mut buf).is_ok() {}
    peer.set_nonblocking(false).expect("blocking");
    peer.set_read_timeout(Some(Duration::from_millis(500)))
        .expect("timeout");
    let writer_entity_id = writer.rtps_endpoint.expect("endpoint").writer_entity_id;
    let nack = AckNackInfo {
        reader_entity_id: READER_EID,
        writer_entity_id,
        missing_ranges: vec![std::ops::Range { start: 2, end: 3 }],
        bitmap_base: 2,
        count: None,
    };
    let panics = participant
        .registry
        .as_ref()
        .expect("registry")
        .deliver_acknack(reader_guid.as_bytes(), &nack);
    assert_eq!(panics, 0);
    let mut repaired = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    while repaired.is_empty() && Instant::now() < deadline {
        let Ok(len) = peer.recv(&mut buf) else {
            continue;
        };
        crate::core::discovery::multicast::classifier::walk::for_each_submessage(
            &buf[..len],
            |sub| {
                // DATA: header (4), extraFlags (2), octetsToInlineQos (2),
                // readerId (4), writerId (4), writerSN high (4) and low (4).
                if sub.id == 0x15 && sub.offset + 24 <= sub.body_end {
                    let low = &buf[sub.offset + 20..sub.offset + 24];
                    let low = if sub.flags & 0x01 != 0 {
                        u32::from_le_bytes([low[0], low[1], low[2], low[3]])
                    } else {
                        u32::from_be_bytes([low[0], low[1], low[2], low[3]])
                    };
                    repaired.push(u64::from(low));
                }
                crate::core::discovery::multicast::classifier::walk::Step::Continue
            },
        );
    }
    assert!(repaired.contains(&2), "sample 2 repaired: {repaired:?}");
}

/// DDS Security v1.1 Sec.8.8.7.1. The reader of an
/// "Unauthenticated" participant on a read-protected topic is not paired
/// (`admits_endpoint` refuses it) and is filtered out of
/// `find_readers_for_topic`. The ACKNACK door `discovered_but_unpaired`
/// recognises an unpaired reader only through that same list: filtered out,
/// it is taken for "a GUID discovery never announced" and SERVED.
#[cfg(feature = "security")]
#[test]
fn verify_unauthenticated_unpaired_readers_acknack_is_not_answered() {
    use super::nack::discovered_but_unpaired;
    use crate::core::discovery::multicast::{DiscoveryFsm, SedpChannel};
    use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
    use crate::security::access::{
        BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
    };
    use crate::security::test_pki::{TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM};
    const LOCAL: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x11; 6]);
    const PEER: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x21; 6]);
    const STRANGER: [u8; 12] = [0x33; 12];
    let machine = crate::security::test_pki::local_machine_with_completed_peer(LOCAL, PEER, None);
    let mut fsm = DiscoveryFsm::new(GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT), 30_000);
    fsm.set_handshake_machine(
        machine,
        TEST_IDENTITY_CERT_PEM.to_vec(),
        TEST_IDENTITY_KEY_PEM.to_vec(),
    );
    fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
        domains: vec![0],
        domain_ranges: vec![],
        allow_unauthenticated: true,
        enable_join_access_control: true,
        discovery_protection_kind: ProtectionKind::Encrypt,
        liveliness_protection_kind: ProtectionKind::None,
        rtps_protection_kind: ProtectionKind::None,
        topic_rules: vec![TopicRule {
            topic_expression: "Open*".to_string(),
            enable_discovery_protection: false,
            enable_liveliness_protection: false,
            enable_read_access_control: true,
            enable_write_access_control: true,
            metadata_protection_kind: ProtectionKind::None,
            data_protection_kind: BasicProtectionKind::None,
        }],
    })));
    fsm.handle_spdp(crate::protocol::discovery::SpdpData {
        participant_guid: GUID::new(STRANGER, RTPS_ENTITYID_PARTICIPANT),
        lease_duration_ms: 30_000,
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
    assert!(fsm.is_participant_known(&STRANGER), "fixture: admitted");
    let reader = GUID::new(STRANGER, [0, 0, 0x12, 0x07]);
    fsm.handle_sedp_on(
        crate::protocol::discovery::SedpData {
            topic_name: "OpenData".to_string(),
            type_name: "Probe".to_string(),
            participant_guid: GUID::new(STRANGER, RTPS_ENTITYID_PARTICIPANT),
            endpoint_guid: reader,
            qos_hash: 1,
            qos: Some(QoS::reliable()),
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
        },
        SedpChannel::Plain,
    );
    let ep = fsm
        .current_endpoint("OpenData", &reader)
        .expect("fixture: registered");
    assert!(!fsm.admits_endpoint(&ep), "fixture: never paired");
    // Never paired: no proxy in the writer's track.
    let track: super::nack::AckTrack = Arc::new(Mutex::new(HashMap::new()));
    assert!(
        discovered_but_unpaired(Some(&track), Some(&fsm), "OpenData", reader.as_bytes()),
        "the unauthenticated, never-paired reader's ACKNACK is served (repairs, durability \
         history) as if from an unknown GUID"
    );
}

/// DDS Security v1.1 Sec.8.8.7.1. The reader of an "Unauthenticated"
/// participant on a read-protected topic is not paired (`admits_endpoint`
/// refuses it) and is left out of `find_readers_for_topic`. The ACKNACK door
/// `discovered_but_unpaired` recognised an unpaired reader only through that
/// same list: left out, it would be taken for "a GUID discovery never
/// announced" and SERVED, repairs and durability history included. It is
/// refused, by the admission itself.
#[cfg(feature = "security")]
#[test]
fn an_unauthenticated_readers_acknack_is_not_answered() {
    use super::nack::discovered_but_unpaired;
    use crate::core::discovery::multicast::{DiscoveryFsm, SedpChannel};
    use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
    use crate::security::access::{
        BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
    };
    use crate::security::test_pki::{TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM};
    const LOCAL: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x11; 6]);
    const PEER: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x21; 6]);
    const STRANGER: [u8; 12] = [0x33; 12];
    let machine = crate::security::test_pki::local_machine_with_completed_peer(LOCAL, PEER, None);
    let mut fsm = DiscoveryFsm::new(GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT), 30_000);
    fsm.set_handshake_machine(
        machine,
        TEST_IDENTITY_CERT_PEM.to_vec(),
        TEST_IDENTITY_KEY_PEM.to_vec(),
    );
    fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
        domains: vec![0],
        domain_ranges: vec![],
        allow_unauthenticated: true,
        enable_join_access_control: true,
        discovery_protection_kind: ProtectionKind::Encrypt,
        liveliness_protection_kind: ProtectionKind::None,
        rtps_protection_kind: ProtectionKind::None,
        topic_rules: vec![TopicRule {
            topic_expression: "Open*".to_string(),
            enable_discovery_protection: false,
            enable_liveliness_protection: false,
            enable_read_access_control: true,
            enable_write_access_control: true,
            metadata_protection_kind: ProtectionKind::None,
            data_protection_kind: BasicProtectionKind::None,
        }],
    })));
    fsm.handle_spdp(crate::protocol::discovery::SpdpData {
        participant_guid: GUID::new(STRANGER, RTPS_ENTITYID_PARTICIPANT),
        lease_duration_ms: 30_000,
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
    assert!(fsm.is_participant_known(&STRANGER), "fixture: admitted");
    let reader = GUID::new(STRANGER, [0, 0, 0x12, 0x07]);
    fsm.handle_sedp_on(
        crate::protocol::discovery::SedpData {
            topic_name: "OpenData".to_string(),
            type_name: "Probe".to_string(),
            participant_guid: GUID::new(STRANGER, RTPS_ENTITYID_PARTICIPANT),
            endpoint_guid: reader,
            qos_hash: 1,
            qos: Some(QoS::reliable()),
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
        },
        SedpChannel::Plain,
    );
    let ep = fsm
        .current_endpoint("OpenData", &reader)
        .expect("fixture: registered");
    assert!(!fsm.admits_endpoint(&ep), "fixture: never paired");
    // Never paired: no proxy in the writer's track.
    let track: super::nack::AckTrack = Arc::new(Mutex::new(HashMap::new()));
    assert!(
        discovered_but_unpaired(Some(&track), Some(&fsm), "OpenData", reader.as_bytes()),
        "the unauthenticated, never-paired reader's ACKNACK is served (repairs, durability \
         history) as if from an unknown GUID"
    );
    // The admission decides, not the registry: a GUID of the participant
    // discovery never announced is refused, and so is the reader once paired
    // (a proxy left from before its refusal), with or without a track.
    let unannounced = GUID::new(STRANGER, [0, 0, 0x99, 0x07]);
    assert!(discovered_but_unpaired(
        Some(&track),
        Some(&fsm),
        "OpenData",
        unannounced.as_bytes()
    ));
    track
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(reader.as_bytes(), 0);
    assert!(discovered_but_unpaired(
        Some(&track),
        Some(&fsm),
        "OpenData",
        reader.as_bytes()
    ));
    assert!(discovered_but_unpaired(
        None,
        Some(&fsm),
        "OpenData",
        reader.as_bytes()
    ));
}

/// DDS Security v1.1 Sec.8.8.7.1: under a governance that admits
/// unauthenticated participants, an unauthenticated participant's reader of
/// a read-protected topic is left unanswered, never paired or (wrongly)
/// paired: the door judges admission first.
#[cfg(feature = "security")]
#[test]
fn an_unauthenticated_unpaired_readers_acknack_is_not_answered() {
    use super::nack::discovered_but_unpaired;
    use crate::core::discovery::multicast::{DiscoveryFsm, SedpChannel};
    use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
    use crate::security::access::{
        BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
    };
    use crate::security::test_pki::{TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM};
    const LOCAL: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x11; 6]);
    const PEER: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x21; 6]);
    const STRANGER: [u8; 12] = [0x33; 12];
    let machine = crate::security::test_pki::local_machine_with_completed_peer(LOCAL, PEER, None);
    let mut fsm = DiscoveryFsm::new(GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT), 30_000);
    fsm.set_handshake_machine(
        machine,
        TEST_IDENTITY_CERT_PEM.to_vec(),
        TEST_IDENTITY_KEY_PEM.to_vec(),
    );
    fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
        domains: vec![0],
        domain_ranges: vec![],
        allow_unauthenticated: true,
        enable_join_access_control: true,
        discovery_protection_kind: ProtectionKind::Encrypt,
        liveliness_protection_kind: ProtectionKind::None,
        rtps_protection_kind: ProtectionKind::None,
        topic_rules: vec![TopicRule {
            topic_expression: "Open*".to_string(),
            enable_discovery_protection: false,
            enable_liveliness_protection: false,
            enable_read_access_control: true,
            enable_write_access_control: true,
            metadata_protection_kind: ProtectionKind::None,
            data_protection_kind: BasicProtectionKind::None,
        }],
    })));
    fsm.handle_spdp(crate::protocol::discovery::SpdpData {
        participant_guid: GUID::new(STRANGER, RTPS_ENTITYID_PARTICIPANT),
        lease_duration_ms: 30_000,
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
    let reader = GUID::new(STRANGER, [0, 0, 0x12, 0x07]);
    fsm.handle_sedp_on(
        crate::protocol::discovery::SedpData {
            topic_name: "OpenData".to_string(),
            type_name: "Probe".to_string(),
            participant_guid: GUID::new(STRANGER, RTPS_ENTITYID_PARTICIPANT),
            endpoint_guid: reader,
            qos_hash: 1,
            qos: Some(QoS::reliable()),
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
        },
        SedpChannel::Plain,
    );
    let track: super::nack::AckTrack = Arc::new(Mutex::new(HashMap::new()));
    assert!(discovered_but_unpaired(
        Some(&track),
        Some(&fsm),
        "OpenData",
        reader.as_bytes()
    ));
    // Also when the reader was (wrongly) paired: the door judges admission first.
    let _ = super::nack::track_reader_proxy(
        &track,
        &volatile_cache(),
        false,
        PeerChange::Matched {
            guid: reader,
            reliable: true,
            volatile: false,
        },
    );
    assert!(discovered_but_unpaired(
        Some(&track),
        Some(&fsm),
        "OpenData",
        reader.as_bytes()
    ));
}

/// An unauthenticated never-paired reader's
/// ACKNACK on a read-protected topic is left unanswered.
#[cfg(feature = "security")]
#[test]
fn recheck_unauthenticated_unpaired_readers_acknack_is_not_answered() {
    use super::nack::discovered_but_unpaired;
    use crate::core::discovery::multicast::{DiscoveryFsm, SedpChannel};
    use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
    use crate::security::access::{
        BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
    };
    use crate::security::test_pki::{TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM};
    const LOCAL: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x11; 6]);
    const PEER: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x21; 6]);
    const STRANGER: [u8; 12] = [0x33; 12];
    let machine = crate::security::test_pki::local_machine_with_completed_peer(LOCAL, PEER, None);
    let mut fsm = DiscoveryFsm::new(GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT), 30_000);
    fsm.set_handshake_machine(
        machine,
        TEST_IDENTITY_CERT_PEM.to_vec(),
        TEST_IDENTITY_KEY_PEM.to_vec(),
    );
    fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
        domains: vec![0],
        domain_ranges: vec![],
        allow_unauthenticated: true,
        enable_join_access_control: true,
        discovery_protection_kind: ProtectionKind::Encrypt,
        liveliness_protection_kind: ProtectionKind::None,
        rtps_protection_kind: ProtectionKind::None,
        topic_rules: vec![TopicRule {
            topic_expression: "Open*".to_string(),
            enable_discovery_protection: false,
            enable_liveliness_protection: false,
            enable_read_access_control: true,
            enable_write_access_control: true,
            metadata_protection_kind: ProtectionKind::None,
            data_protection_kind: BasicProtectionKind::None,
        }],
    })));
    fsm.handle_spdp(crate::protocol::discovery::SpdpData {
        participant_guid: GUID::new(STRANGER, RTPS_ENTITYID_PARTICIPANT),
        lease_duration_ms: 30_000,
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
    let reader = GUID::new(STRANGER, [0, 0, 0x12, 0x07]);
    fsm.handle_sedp_on(
        crate::protocol::discovery::SedpData {
            topic_name: "OpenData".to_string(),
            type_name: "Probe".to_string(),
            participant_guid: GUID::new(STRANGER, RTPS_ENTITYID_PARTICIPANT),
            endpoint_guid: reader,
            qos_hash: 1,
            qos: Some(QoS::reliable()),
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
        },
        SedpChannel::Plain,
    );
    let track: super::nack::AckTrack = Arc::new(Mutex::new(HashMap::new()));
    assert!(discovered_but_unpaired(
        Some(&track),
        Some(&fsm),
        "OpenData",
        reader.as_bytes()
    ));
    // Also when the reader was (wrongly) paired: the door judges admission first.
    let _ = super::nack::track_reader_proxy(
        &track,
        &volatile_cache(),
        false,
        PeerChange::Matched {
            guid: reader,
            reliable: true,
            volatile: false,
        },
    );
    assert!(discovered_but_unpaired(
        Some(&track),
        Some(&fsm),
        "OpenData",
        reader.as_bytes()
    ));
}

// =============================================================================
// wait_for_acknowledgments (DDS v1.4 Sec.2.2.2.4.2.15)
// =============================================================================

/// A RELIABLE writer's `wait_for_acknowledgments` returns once the one
/// matched RELIABLE reader acknowledges everything written, woken by the
/// history cache's condition variable (no busy-wait poll): a background
/// thread acknowledges well before the generous timeout, and the call
/// must return long before that timeout elapses.
#[test]
fn wait_for_acknowledgments_wakes_on_the_ack_not_the_timeout() {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let mut writer = WriterBuilder::<Probe>::new("test/wait_for_ack_success".to_string())
        .qos(QoS::reliable().keep_all())
        .with_transport(transport)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x40; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: WRITER_EID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: false,
    };
    track_reader_proxy(&writer.ack_track, &cache, true, matched);

    writer.write(&Probe { x: 1 }).expect("write 1");
    writer.write(&Probe { x: 2 }).expect("write 2");

    let track = Arc::clone(&writer.ack_track);
    let cache_for_ack = Arc::clone(&cache);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(80));
        let mut map = track.lock().unwrap();
        map.insert(reader(1).as_bytes(), 2);
        cache_for_ack.set_acked_floor(acked_floor(&map));
    });

    let start = Instant::now();
    let result = writer.wait_for_acknowledgments(Duration::from_secs(5));
    let waited = start.elapsed();
    assert!(result.is_ok(), "got {result:?}");
    assert!(
        waited < Duration::from_secs(2),
        "woken by the ack, not the 5s timeout: waited {waited:?}"
    );
    assert!(
        waited >= Duration::from_millis(70),
        "returned before the ack could have landed: waited {waited:?}"
    );
}

/// The ONLY matched reader departing also wakes a blocked
/// `wait_for_acknowledgments`: nobody is left to owe anything to
/// (`a_departed_reader_stops_holding_the_history_back`'s rule, acked_floor
/// -> `u64::MAX`), and `track_reader_proxy`'s `Unmatched` branch calls the
/// SAME `set_acked_floor` notify every ACKNACK does -- one condition
/// variable, not two wake paths to keep in step.
#[test]
fn wait_for_acknowledgments_wakes_when_the_last_reader_departs() {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let mut writer = WriterBuilder::<Probe>::new("test/wait_for_ack_departure".to_string())
        .qos(QoS::reliable().keep_all())
        .with_transport(transport)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x46; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: WRITER_EID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: false,
    };
    track_reader_proxy(&writer.ack_track, &cache, true, matched);

    writer.write(&Probe { x: 1 }).expect("write 1");
    assert!(
        !writer.fully_acked(),
        "the only matched reader has not acked yet"
    );

    let track = Arc::clone(&writer.ack_track);
    let cache_for_departure = Arc::clone(&cache);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(80));
        let left = PeerChange::Unmatched { guid: reader(1) };
        track_reader_proxy(&track, &cache_for_departure, true, left);
    });

    let start = Instant::now();
    let result = writer.wait_for_acknowledgments(Duration::from_secs(5));
    let waited = start.elapsed();
    assert!(result.is_ok(), "got {result:?}");
    assert!(
        waited < Duration::from_secs(2),
        "woken by the departure, not the 5s timeout: waited {waited:?}"
    );
    assert!(
        waited >= Duration::from_millis(70),
        "returned before the departure could have landed: waited {waited:?}"
    );
}

/// No reader ever acknowledges: `wait_for_acknowledgments` times out at
/// `max_wait`, neither early nor late.
#[test]
fn wait_for_acknowledgments_times_out_when_nobody_acks() {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let mut writer = WriterBuilder::<Probe>::new("test/wait_for_ack_timeout".to_string())
        .qos(QoS::reliable().keep_all())
        .with_transport(transport)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x41; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: WRITER_EID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: false,
    };
    track_reader_proxy(&writer.ack_track, &cache, true, matched);
    writer.write(&Probe { x: 1 }).expect("write 1");

    let start = Instant::now();
    let result = writer.wait_for_acknowledgments(Duration::from_millis(150));
    let waited = start.elapsed();
    assert!(
        matches!(result, Err(Error::AcknowledgmentTimeout)),
        "got {result:?}"
    );
    assert!(waited >= Duration::from_millis(150), "waited {waited:?}");
    assert!(waited < Duration::from_millis(400), "waited {waited:?}");
}

/// A BEST_EFFORT reader is never counted: it never gains an `ack_track`
/// entry (RTPS has nothing to retransmit it over), so a RELIABLE writer
/// with only a BEST_EFFORT reader matched has nothing to wait for and
/// returns at once, unwritten samples or not.
#[test]
fn wait_for_acknowledgments_ignores_a_best_effort_reader() {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let mut writer = WriterBuilder::<Probe>::new("test/wait_for_ack_best_effort".to_string())
        .qos(QoS::reliable().keep_all())
        .with_transport(transport)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x42; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: WRITER_EID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    // A BEST_EFFORT match: `track_reader_proxy` returns early and never
    // touches `ack_track` for it (see `a_best_effort_reader_never_holds_the_history_back`).
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: false,
        volatile: false,
    };
    track_reader_proxy(&writer.ack_track, &cache, true, matched);
    writer.write(&Probe { x: 1 }).expect("write 1");

    let start = Instant::now();
    let result = writer.wait_for_acknowledgments(Duration::from_secs(5));
    let waited = start.elapsed();
    assert!(result.is_ok(), "got {result:?}");
    assert!(
        waited < Duration::from_millis(200),
        "a BEST_EFFORT reader is nothing to wait for: waited {waited:?}"
    );
}

/// `track_reader_proxy`'s own contract, at the unit level: ANY reader it
/// is handed a `PeerChange::Matched` for gains an `ack_track` entry and
/// is waited for exactly the same way, whatever notified it. A reader of
/// the same participant is one of them: the local binding feeds the same
/// map when the merger admits a sample into the reader's history
/// (`tests/reliable_readers_acknowledge_under_their_own_name.rs`
/// pins it with a real reader, and `a_slow_local_reader_holds_acknowledgments_until_cache_admission` with a held
/// admission).
#[test]
fn wait_for_acknowledgments_counts_any_reader_the_match_notification_tracks() {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let mut writer = WriterBuilder::<Probe>::new("test/wait_for_ack_intra".to_string())
        .qos(QoS::reliable().keep_all())
        .with_transport(transport)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x43; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: WRITER_EID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: false,
    };
    track_reader_proxy(&writer.ack_track, &cache, true, matched);
    writer.write(&Probe { x: 1 }).expect("write 1");

    assert!(
        !writer.fully_acked(),
        "the tracked reader has not acked yet"
    );
    {
        let mut map = writer.ack_track.lock().unwrap();
        map.insert(reader(1).as_bytes(), 1);
        cache.set_acked_floor(acked_floor(&map));
    }
    assert!(
        writer
            .wait_for_acknowledgments(Duration::from_millis(500))
            .is_ok(),
        "the tracked reader's ack is enough"
    );
}

/// `wait_for_acknowledgments` on a BEST_EFFORT writer returns at once
/// (DDS v1.4 Sec.2.2.2.4.2.15: "intended to be used only if the
/// DataWriter has RELIABILITY QoS kind set to RELIABLE. Otherwise the
/// operation will return immediately with RETCODE_OK"), whatever its
/// history holds unacknowledged.
#[test]
fn wait_for_acknowledgments_on_a_best_effort_writer_returns_at_once() {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    // TRANSIENT_LOCAL so the writer has a history cache to pair with a
    // (deliberately invalid) "unacked RELIABLE reader" entry below:
    // otherwise a no-history BEST_EFFORT+VOLATILE writer would return
    // Ok(()) through the writer's OWN empty `ack_track`/no-cache path,
    // proving nothing about the RELIABILITY gate this test targets.
    let writer = WriterBuilder::<Probe>::new("test/wait_for_ack_qos_gate".to_string())
        .qos(QoS::best_effort().transient_local())
        .with_transport(transport)
        .build()
        .expect("writer build");
    writer.write(&Probe { x: 1 }).expect("write 1");
    // An ack_track entry below `next_seq` makes `fully_acked()` false on
    // its own merits (not because nothing was ever written or matched):
    // only the function's own RELIABILITY check can be what returns
    // Ok(()) here, never `fully_acked`.
    writer
        .ack_track
        .lock()
        .unwrap()
        .insert(reader(1).as_bytes(), 0);
    assert!(
        !writer.fully_acked(),
        "the fixture must leave something genuinely unacked"
    );

    let start = Instant::now();
    let result = writer.wait_for_acknowledgments(Duration::from_secs(5));
    let waited = start.elapsed();
    assert!(result.is_ok(), "got {result:?}");
    assert!(
        waited < Duration::from_millis(200),
        "a BEST_EFFORT writer never waits, whatever ack_track holds: waited {waited:?}"
    );
}

// =============================================================================
// Publisher::wait_for_acknowledgments (DDS v1.4 Sec.2.2.2.4.1.12)
// =============================================================================

/// One writer of a Publisher with a tracked RELIABLE reader (`who`) that has
/// acknowledged nothing of what the writer wrote.
fn unacked_writer(
    participant: &Arc<crate::dds::Participant>,
    publisher: &Arc<crate::dds::Publisher>,
    topic: &str,
    qos: QoS,
    who: u8,
) -> crate::dds::DataWriter<Probe> {
    let writer = participant
        .topic::<Probe>(topic)
        .expect("topic")
        .writer()
        .publisher(publisher)
        .qos(qos)
        .build()
        .expect("writer");
    // An ack_track entry below `next_seq` leaves something genuinely unacked
    // whatever the transport (the participant is intra-process).
    writer.write(&Probe { x: 1 }).expect("write");
    writer
        .ack_track
        .lock()
        .unwrap()
        .insert(reader(who).as_bytes(), 0);
    assert!(!writer.fully_acked(), "the fixture must leave data unacked");
    writer
}

/// What the ACKNACK path does when `who` acknowledges everything written:
/// the watermark moves and the history cache's waiters are woken.
fn acknowledge_everything(writer: &crate::dds::DataWriter<Probe>, who: u8) -> impl FnOnce() + Send {
    let track = Arc::clone(&writer.ack_track);
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    let next_seq = Arc::clone(&writer.next_seq);
    move || {
        let mut map = track.lock().unwrap();
        map.insert(reader(who).as_bytes(), next_seq.load(Ordering::Acquire) - 1);
        cache.set_acked_floor(acked_floor(&map));
    }
}

fn intra_process_publisher(
    name: &str,
) -> (
    Arc<crate::dds::Participant>,
    Arc<crate::dds::Publisher>,
    crate::test_support::domains::DomainLease,
) {
    let lease = crate::test_support::domains::unique_domain();
    let participant = crate::dds::Participant::builder(name)
        .domain_id(lease.id())
        .with_transport(crate::dds::TransportMode::IntraProcess)
        .build()
        .expect("participant");
    let publisher = Arc::new(
        participant
            .create_publisher(QoS::reliable().keep_all())
            .expect("publisher"),
    );
    (participant, publisher, lease)
}

/// The call returns once EVERY writer of the Publisher is acknowledged, and
/// it is the wait of each writer: the second writer is acknowledged only
/// when the call is about to block on it, and the wake is that
/// acknowledgment, not the timeout.
#[test]
fn publisher_wait_for_acknowledgments_waits_for_every_writer() {
    let (participant, publisher, _lease) = intra_process_publisher("pub-wait-all");
    let qos = QoS::reliable().keep_all();
    let a = unacked_writer(&participant, &publisher, "pub_wait_all/a", qos.clone(), 1);
    let b = unacked_writer(&participant, &publisher, "pub_wait_all/b", qos, 2);
    acknowledge_everything(&a, 1)();

    let acked_b = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&acked_b);
    let ack_b = acknowledge_everything(&b, 2);
    *b.history_cache
        .as_ref()
        .unwrap()
        .before_floor_wait
        .lock()
        .unwrap() = Some(Box::new(move || {
        ack_b();
        flag.store(true, Ordering::Release);
    }));

    let start = Instant::now();
    let result = publisher.wait_for_acknowledgments(Duration::from_secs(30));
    let waited = start.elapsed();

    assert!(result.is_ok(), "{result:?}");
    assert!(
        acked_b.load(Ordering::Acquire),
        "the call must have waited on the second writer"
    );
    assert!(waited < Duration::from_secs(10), "waited {waited:?}");
    assert!(a.fully_acked() && b.fully_acked());
}

/// One writer left unacknowledged is a TIMEOUT for the Publisher, however
/// many of its other writers are acknowledged, and it lasts `max_wait`.
#[test]
fn publisher_wait_for_acknowledgments_times_out_on_one_unacked_writer() {
    let (participant, publisher, _lease) = intra_process_publisher("pub-wait-one");
    let qos = QoS::reliable().keep_all();
    let a = unacked_writer(&participant, &publisher, "pub_wait_one/a", qos.clone(), 1);
    let _b = unacked_writer(&participant, &publisher, "pub_wait_one/b", qos, 2);
    acknowledge_everything(&a, 1)();

    let start = Instant::now();
    let result = publisher.wait_for_acknowledgments(Duration::from_millis(150));
    let waited = start.elapsed();

    assert!(
        matches!(result, Err(Error::AcknowledgmentTimeout)),
        "{result:?}"
    );
    assert!(waited >= Duration::from_millis(150), "waited {waited:?}");
    assert!(waited < Duration::from_secs(5), "waited {waited:?}");
}

/// A BEST_EFFORT writer owes nothing (Sec.2.2.2.4.2.15), so it neither
/// holds the Publisher back nor hides an unacknowledged RELIABLE sibling.
#[test]
fn publisher_wait_for_acknowledgments_ignores_a_best_effort_writer() {
    let (participant, publisher, _lease) = intra_process_publisher("pub-wait-be");
    let best_effort = unacked_writer(
        &participant,
        &publisher,
        "pub_wait_be/be",
        QoS::best_effort().transient_local(),
        1,
    );
    assert!(!best_effort.fully_acked());
    publisher
        .wait_for_acknowledgments(Duration::ZERO)
        .expect("only a BEST_EFFORT writer is unacknowledged");

    let _reliable = unacked_writer(
        &participant,
        &publisher,
        "pub_wait_be/rel",
        QoS::reliable().keep_all(),
        2,
    );
    assert!(matches!(
        publisher.wait_for_acknowledgments(Duration::from_millis(50)),
        Err(Error::AcknowledgmentTimeout)
    ));
}

/// "all DataWriter entities" of THE Publisher: an unacknowledged writer of
/// another Publisher is not waited for, and a dropped writer is not either.
#[test]
fn publisher_wait_for_acknowledgments_counts_only_its_own_live_writers() {
    let (participant, publisher, _lease) = intra_process_publisher("pub-wait-scope");
    let qos = QoS::reliable().keep_all();
    let other = Arc::new(
        participant
            .create_publisher(qos.clone())
            .expect("other publisher"),
    );
    let _elsewhere = unacked_writer(&participant, &other, "pub_wait_scope/other", qos.clone(), 1);
    assert!(matches!(
        other.wait_for_acknowledgments(Duration::from_millis(50)),
        Err(Error::AcknowledgmentTimeout)
    ));
    publisher
        .wait_for_acknowledgments(Duration::ZERO)
        .expect("the other Publisher's writer is not ours");

    let dropped = unacked_writer(&participant, &publisher, "pub_wait_scope/gone", qos, 2);
    assert!(matches!(
        publisher.wait_for_acknowledgments(Duration::from_millis(50)),
        Err(Error::AcknowledgmentTimeout)
    ));
    drop(dropped);
    publisher
        .wait_for_acknowledgments(Duration::ZERO)
        .expect("a dropped writer is no longer the Publisher's");
}

// =============================================================================
// write_w_timestamp / dispose_w_timestamp / unregister_instance_w_timestamp
// (DDS v1.4 Sec.2.2.2.4.2.12 / 2.2.2.4.2.13 / 2.2.2.4.2.8)
// =============================================================================

/// `write_w_timestamp` journals the application-supplied timestamp, not
/// the clock's, and the override governs exactly the one change it
/// emits: a following plain `write()` reads the clock itself.
#[test]
fn write_w_timestamp_journals_the_given_timestamp_once() {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let mut writer = WriterBuilder::<Probe>::new("test/write_w_timestamp".to_string())
        .qos(QoS::reliable().keep_all())
        .with_transport(transport)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x44; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: WRITER_EID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    let cache = writer.history_cache.clone().expect("reliable writer cache");

    // 2026-01-01T00:00:00Z, deliberately far from "now" so a fallback to
    // the clock cannot pass for the override by accident.
    let given_ns: u64 = 1_767_225_600 * 1_000_000_000;
    writer
        .write_w_timestamp(&Probe { x: 1 }, given_ns)
        .expect("write_w_timestamp");
    let journaled = cache.get_change(1).expect("seq 1 journaled");
    assert_eq!(
        journaled.metadata.source_ts,
        rtps_timestamp_from_unix_nanos(given_ns),
        "the journaled source_ts is the one write_w_timestamp was given"
    );

    writer.write(&Probe { x: 2 }).expect("write 2");
    let plain = cache.get_change(2).expect("seq 2 journaled");
    assert_ne!(
        plain.metadata.source_ts,
        rtps_timestamp_from_unix_nanos(given_ns),
        "the override must not leak into the next plain write()"
    );
}

/// The source timestamp must be stamped once, unconditionally, before
/// `write()`'s transport branch: a stamp placed inside `if let
/// Some(ref transport) = self.transport` would never be reached by a
/// transport-less writer (`TransportMode::IntraProcess`, or any writer
/// built with no `.with_transport(...)`), so `write_w_timestamp`'s
/// override (and every plain write()'s own timestamp) would never reach
/// the journaled change on that path: the no-transport journal further
/// down in `write()` reads the SAME `live_source_ts`.
#[test]
fn write_w_timestamp_has_an_effect_on_a_transport_less_writer() {
    let writer = WriterBuilder::<Probe>::new("test/write_w_timestamp_no_transport".to_string())
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer build");
    assert!(
        writer.transport.is_none(),
        "no .with_transport(...): this writer has none, like IntraProcess"
    );
    let cache = writer.history_cache.clone().expect("reliable writer cache");

    let given_ns: u64 = 1_767_225_600 * 1_000_000_000;
    writer
        .write_w_timestamp(&Probe { x: 1 }, given_ns)
        .expect("write_w_timestamp");
    let journaled = cache.get_change(1).expect("seq 1 journaled");
    assert_eq!(
        journaled.metadata.source_ts,
        rtps_timestamp_from_unix_nanos(given_ns),
        "write_w_timestamp's override reaches the journal on a \
         transport-less writer too"
    );
    assert!(
        journaled.metadata.source_ts_known,
        "a transport-less writer's journal must know its own timestamp"
    );
}

/// `write_w_timestamp`'s override is cleared even when `write` itself
/// refuses the sample (OUT_OF_RESOURCES here): a following plain write
/// must not inherit a timestamp meant for the one that failed.
#[test]
fn write_w_timestamp_clears_its_override_on_a_refused_write() {
    // Same shape as `a_full_reliable_history_makes_write_wait_then_time_out_without_emitting`:
    // a full RELIABLE KEEP_ALL history refuses a write with `WriteTimeout`
    // BEFORE the clock (or an override) is ever read -- `write`'s
    // `journal_before_emission` rejects it ahead of the stamping branches.
    // This is the one path that exercises the guard for real: a success
    // path already clears the override through `stamp_source_ts`'s own
    // `take()`, so only an early refusal proves the guard, not that call.
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 1;
    qos.resource_limits.max_samples_per_instance = 1;
    let mut writer = WriterBuilder::<Probe>::new("test/write_w_timestamp_refused".to_string())
        .qos(qos)
        .with_transport(transport)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x45; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: WRITER_EID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: false,
    };
    track_reader_proxy(&writer.ack_track, &cache, true, matched);

    writer
        .write(&Probe { x: 1 })
        .expect("room for 1, the one slot");

    let given_ns: u64 = 1_700_000_000 * 1_000_000_000;
    let refused = writer.write_w_timestamp(&Probe { x: 2 }, given_ns);
    assert!(
        matches!(refused, Err(Error::WriteTimeout)),
        "the full history refuses write #2 before any clock read: got {refused:?}"
    );

    // The reader acknowledges #1: room frees, and a PLAIN write goes
    // through next. If the override from the refused call had leaked,
    // this change would carry `given_ns` instead of a fresh timestamp.
    {
        let mut map = writer.ack_track.lock().unwrap();
        map.insert(reader(1).as_bytes(), 1);
        cache.set_acked_floor(acked_floor(&map));
    }
    writer
        .write(&Probe { x: 3 })
        .expect("room after the acknowledgement");
    // The refused write_w_timestamp call consumed no sequence number (see
    // `a_full_reliable_history_makes_write_wait_then_time_out_without_emitting`):
    // the retried write is seq 2, not 3.
    let seq2 = cache.get_change(2).expect("seq 2 journaled");
    assert_ne!(
        seq2.metadata.source_ts,
        rtps_timestamp_from_unix_nanos(given_ns),
        "the refused call's override must not leak into the next write()"
    );
}

/// `dispose_w_timestamp` and `unregister_instance_w_timestamp` journal
/// the given timestamp on their one lifecycle change the same way
/// `write_w_timestamp` does for a sample.
#[test]
fn dispose_and_unregister_w_timestamp_journal_the_given_timestamp() {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let writer = WriterBuilder::<Probe>::new("test/dispose_w_timestamp".to_string())
        .qos(QoS::reliable().keep_all().transient_local())
        .with_transport(transport)
        .build()
        .expect("writer build");
    let cache = writer.history_cache.clone().expect("durable writer cache");

    writer.write(&Probe { x: 7 }).expect("write 1");

    let given_ns: u64 = 1_767_312_000 * 1_000_000_000;
    writer
        .dispose_w_timestamp(&Probe { x: 7 }, given_ns)
        .expect("dispose_w_timestamp");
    let disposed = cache
        .get_change(2)
        .expect("the dispose's own change, seq 2");
    assert_eq!(
        disposed.metadata.source_ts,
        rtps_timestamp_from_unix_nanos(given_ns),
        "dispose_w_timestamp journals the given timestamp"
    );

    let given_ns_2: u64 = 1_767_398_400 * 1_000_000_000;
    writer
        .unregister_instance_w_timestamp(&Probe { x: 7 }, given_ns_2)
        .expect("unregister_instance_w_timestamp");
    let unregistered = cache
        .get_change(3)
        .expect("the unregister's own change, seq 3");
    assert_eq!(
        unregistered.metadata.source_ts,
        rtps_timestamp_from_unix_nanos(given_ns_2),
        "unregister_instance_w_timestamp journals the given timestamp"
    );
}

// =============================================================================
// register_instance / register_instance_w_timestamp (DDS v1.4 Sec.2.2.2.4.2.5/6)
// =============================================================================

/// `register_instance` is idempotent and returns the instance's KeyHash:
/// the same instance registers to the same handle every time, and a
/// different instance (by key) registers to a different one.
#[test]
fn register_instance_is_idempotent_and_keyed() {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let writer = WriterBuilder::<Probe>::new("test/register_instance".to_string())
        .qos(QoS::best_effort())
        .with_transport(transport)
        .build()
        .expect("writer build");

    let a1 = writer
        .register_instance(&Probe { x: 1 })
        .expect("register x=1");
    let a2 = writer
        .register_instance(&Probe { x: 1 })
        .expect("register x=1 again");
    let b = writer
        .register_instance(&Probe { x: 2 })
        .expect("register x=2");

    assert_eq!(a1, a2, "the same instance registers to the same handle");
    // `Probe` has no @key field (`has_key() == false` by default), so
    // every instance's KeyHash is all zeros (DDS v1.4 Sec.2.2.1.2.3): an
    // unkeyed topic has exactly one instance, by spec, not by accident.
    assert_eq!(a1, b, "an unkeyed type has exactly one instance");
    assert!(a1.is_nil(), "an unkeyed type's handle is HANDLE_NIL");
}

/// `register_instance_w_timestamp` returns the identical handle
/// `register_instance` does: the timestamp governs nothing here to
/// differ by.
#[test]
fn register_instance_w_timestamp_matches_register_instance() {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let writer = WriterBuilder::<Probe>::new("test/register_instance_ts".to_string())
        .qos(QoS::best_effort())
        .with_transport(transport)
        .build()
        .expect("writer build");

    let plain = writer
        .register_instance(&Probe { x: 5 })
        .expect("register_instance");
    let timestamped = writer
        .register_instance_w_timestamp(&Probe { x: 5 }, 123_456_789)
        .expect("register_instance_w_timestamp");
    assert_eq!(plain, timestamped);
}

/// DDS 1.4 2.2.2.4.2.15: every matched reliable reader must have admitted
/// the data. A paused local delivery cannot report success, even when an
/// earlier sample reached the same reader and a wire-only close is known.
#[test]
fn a_slow_local_reader_holds_acknowledgments_until_cache_admission() {
    use crate::dds::qos::{Presentation, PresentationAccessScope};
    use crate::dds::{Participant, TransportMode};
    use std::sync::{mpsc, Barrier};

    let domain = crate::test_support::domains::unique_domain();
    let participant = Participant::builder("slow-local-ack")
        .domain_id(domain.id())
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("participant");
    let presentation = Presentation {
        access_scope: PresentationAccessScope::Topic,
        coherent_access: true,
        ordered_access: false,
    };
    let qos = QoS::reliable().keep_all().presentation(presentation);
    let publisher = Arc::new(
        participant
            .create_publisher(qos.clone())
            .expect("publisher"),
    );
    let topic = participant.topic::<Probe>("slow-local-ack").expect("topic");
    let writer = topic
        .writer()
        .publisher(&publisher)
        .qos(qos.clone())
        .build()
        .expect("writer");
    let reader = topic.reader().qos(qos).build().expect("reader");
    writer.write(&Probe { x: 1 }).expect("first write");
    assert_eq!(writer.acked_through(), 1);

    let (paused_tx, paused_rx) = mpsc::channel();
    let resume = Arc::new(Barrier::new(2));
    let resume_hook = resume.clone();
    writer.merger.pause_local_delivery(Arc::new(move |seq| {
        if seq == 2 {
            paused_tx.send(()).unwrap();
            resume_hook.wait();
        }
    }));
    publisher.begin_coherent_changes().expect("begin");
    writer.write(&Probe { x: 2 }).expect("deferred write");
    let closing = publisher.clone();
    let closer = std::thread::spawn(move || closing.end_coherent_changes());
    paused_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("delivery paused");
    let result = writer.wait_for_acknowledgments(Duration::from_millis(20));
    let floor = writer.acked_through();
    resume.wait();
    closer.join().unwrap().expect("end");
    assert!(
        matches!(result, Err(Error::AcknowledgmentTimeout)),
        "{result:?}"
    );
    assert_eq!(floor, 1, "the close cannot acknowledge the missing member");
    writer
        .wait_for_acknowledgments(Duration::ZERO)
        .expect("admitted set and close");
    assert_eq!(writer.acked_through(), 3);
    assert_eq!(reader.take().unwrap().unwrap().x, 1);
    assert_eq!(reader.take().unwrap().unwrap().x, 2);
}

/// Reliable local bindings are separate debts; best-effort readers never
/// participate, and destroying a reader removes precisely its own debt.
#[test]
fn local_acknowledgments_track_each_reliable_reader_and_remove_departures() {
    use crate::dds::{Participant, TransportMode};
    let domain = crate::test_support::domains::unique_domain();
    let participant = Participant::builder("local-ack-membership")
        .domain_id(domain.id())
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("participant");
    let topic = participant.topic::<Probe>("local-ack-membership").unwrap();
    let writer = topic
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .unwrap();
    let first = topic
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .unwrap();
    let second = topic
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .unwrap();
    let _best_effort = topic.reader().qos(QoS::best_effort()).build().unwrap();
    assert_eq!(writer.ack_track.lock().unwrap().len(), 2);
    writer.write(&Probe { x: 1 }).unwrap();
    assert_eq!(writer.acked_through(), 1);
    drop(first);
    assert_eq!(writer.ack_track.lock().unwrap().len(), 1);
    assert_eq!(second.take().unwrap().unwrap().x, 1);
    drop(second);
    assert!(writer.ack_track.lock().unwrap().is_empty());
    writer.wait_for_acknowledgments(Duration::ZERO).unwrap();
    let late = topic
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .unwrap();
    writer.write(&Probe { x: 2 }).unwrap();
    assert_eq!(
        writer.acked_through(),
        2,
        "late volatile reader owes only new data"
    );
    assert_eq!(late.take().unwrap().unwrap().x, 2);
}

/// DDS 1.4 2.2.3.4: durable late joiners acknowledge retained history when
/// replay admits it, without requiring the application to take the sample.
#[test]
fn a_local_durable_late_joiner_acknowledges_replayed_history() {
    use crate::dds::{Participant, TransportMode};
    let domain = crate::test_support::domains::unique_domain();
    let participant = Participant::builder("local-replay-ack")
        .domain_id(domain.id())
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant.topic::<Probe>("local-replay-ack").unwrap();
    let qos = QoS::reliable().keep_all().transient_local();
    let writer = topic.writer().qos(qos.clone()).build().unwrap();
    writer.write(&Probe { x: 1 }).unwrap();
    writer.write(&Probe { x: 2 }).unwrap();
    let reader = topic.reader().qos(qos).build().unwrap();
    assert_eq!(writer.acked_through(), 2);
    writer.wait_for_acknowledgments(Duration::ZERO).unwrap();
    assert_eq!(reader.take().unwrap().unwrap().x, 1);
    assert_eq!(reader.take().unwrap().unwrap().x, 2);
}

/// DDS 1.4 2.2.2.4.2.15: completion wakes the caller even when it arrives
/// between the acknowledgment predicate and the condition-variable wait.
#[test]
fn an_acknowledgment_immediately_before_waiting_is_not_lost() {
    for durable in [false, true] {
        let qos = if durable {
            QoS::reliable().transient_local()
        } else {
            QoS::reliable()
        };
        let writer = WriterBuilder::<Probe>::new("ack-before-wait".to_string())
            .qos(qos.keep_all())
            .build()
            .unwrap();
        let cache = writer.history_cache.as_ref().unwrap();
        let track = writer.ack_track.clone();
        track_reader_proxy(
            &track,
            cache,
            !durable,
            PeerChange::Matched {
                guid: reader(1),
                reliable: true,
                volatile: false,
            },
        );
        writer.write(&Probe { x: 1 }).unwrap();
        assert!(!writer.fully_acked());
        let ack_cache = cache.clone();
        *cache.before_floor_wait.lock().unwrap() = Some(Box::new(move || {
            let mut map = track.lock().unwrap();
            *map.get_mut(&reader(1).as_bytes()).unwrap() = 1;
            ack_cache.set_acked_floor(acked_floor(&map));
        }));
        let start = Instant::now();
        writer
            .wait_for_acknowledgments(Duration::from_secs(2))
            .unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "waited past the completed ack"
        );
    }
}

/// Matching and the reliable writer's commit have one order: a reader
/// published after a write owes only later data; a reader published first
/// receives that write. There must be no sequence owed without delivery.
#[test]
fn local_reader_publication_and_its_acknowledgment_baseline_are_atomic() {
    use crate::dds::{Participant, TransportMode};
    use std::sync::{mpsc, Barrier};
    let domain = crate::test_support::domains::unique_domain();
    let participant = Participant::builder("local-ack-pairing")
        .domain_id(domain.id())
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let writer = participant
        .topic::<Probe>("local-ack-pairing")
        .unwrap()
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .unwrap();
    let (paused_tx, paused_rx) = mpsc::channel();
    let resume = Arc::new(Barrier::new(2));
    let resume_hook = resume.clone();
    writer.merger.pause_reader_publication(Arc::new(move || {
        paused_tx.send(()).unwrap();
        resume_hook.wait();
    }));
    let building = participant.clone();
    let reader_thread = std::thread::spawn(move || {
        building
            .topic::<Probe>("local-ack-pairing")
            .unwrap()
            .reader()
            .qos(QoS::reliable().keep_all())
            .build()
            .unwrap()
    });
    paused_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (written_tx, written_rx) = mpsc::channel();
    let writer_thread = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        let result = writer.write(&Probe { x: 1 });
        written_tx.send(()).unwrap();
        (writer, result)
    });
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    // While the baseline is captured but membership is unpublished, no
    // write may commit outside this reader's delivery snapshot.
    let premature = written_rx.recv_timeout(Duration::from_millis(100)).is_ok();
    resume.wait();
    let reader = reader_thread.join().unwrap();
    let (writer, result) = writer_thread.join().unwrap();
    result.unwrap();
    assert!(!premature, "the write passed the incomplete pairing");
    assert_eq!(writer.acked_through(), 1);
    writer.wait_for_acknowledgments(Duration::ZERO).unwrap();
    assert_eq!(reader.take().unwrap().unwrap().x, 1);
}

/// A local control's consumed number is part of the match watermark even
/// when there is no retained wire payload to replay to a later reader.
#[test]
fn a_local_late_joiner_does_not_owe_a_prior_wire_only_close() {
    use crate::dds::{Participant, TransportMode};
    let domain = crate::test_support::domains::unique_domain();
    let participant = Participant::builder("local-prior-close")
        .domain_id(domain.id())
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant.topic::<Probe>("local-prior-close").unwrap();
    let writer = topic
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .unwrap();
    writer.write(&Probe { x: 1 }).unwrap();
    // A control consumed by the Publisher has no local cache payload.
    // Model the unretained control; the real Publisher path is exercised
    // by a_slow_local_reader_holds_acknowledgments_until_cache_admission.
    let close = writer.next_seq.fetch_add(1, Ordering::AcqRel);
    assert_eq!(close, 2);
    writer.merger.acknowledge_control(close);
    let reader = topic
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .unwrap();
    assert_eq!(writer.acked_through(), 2);
    writer.wait_for_acknowledgments(Duration::ZERO).unwrap();
    writer.write(&Probe { x: 3 }).unwrap();
    assert_eq!(writer.acked_through(), 3);
    assert_eq!(reader.take().unwrap().unwrap().x, 3);
}

/// DDS 1.4 2.2.2.4.2.15: a reader departing before the waiter sleeps
/// completes its obligation even if the minimum watermark returns to the
/// value it had before a durable reader temporarily joined.
#[test]
fn acknowledgment_progress_survives_a_floor_that_returns_to_its_old_value() {
    let cache = volatile_cache();
    cache.set_release_policy(true, true);
    written(&cache, 1);
    let track = Arc::new(Mutex::new(HashMap::new()));
    let observed = cache.ack_progress();
    track_reader_proxy(
        &track,
        &cache,
        false,
        PeerChange::Matched {
            guid: reader(1),
            reliable: true,
            volatile: false,
        },
    );
    assert_eq!(cache.acked_floor(), 0, "the late reader owes retained data");
    track_reader_proxy(
        &track,
        &cache,
        false,
        PeerChange::Unmatched { guid: reader(1) },
    );
    assert_eq!(cache.acked_floor(), u64::MAX, "the original floor returned");
    let start = Instant::now();
    cache.wait_for_floor_change(observed, start + Duration::from_secs(2));
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "missed the reader departure"
    );
}

/// RTPS 2.5 8.4.2.2.3: a RELIABLE writer keeps a change until every matched
/// reader has acknowledged it, and DDS 1.4 2.2.2.4.1.6 makes deleting a
/// DataWriter emit one last lifecycle change (the auto-unregister). That
/// change cannot be repaired afterwards -- its NACK handlers and its
/// HEARTBEATs are dropped with the writer -- and only the ACKNACK proves
/// the reader applied it, so the delete must not announce the departure
/// before it. The history cache fires its wait hook from inside that wait:
/// the acknowledgement is published only once the delete is provably
/// blocked on it, and the delete then ends on the acknowledgement rather
/// than on its grace.
#[test]
fn dropping_a_reliable_writer_waits_for_its_last_lifecycle_change_to_be_acked() {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let mut writer = WriterBuilder::<KeyedProbe>::new("test/drop_ack".to_string())
        .qos(QoS::reliable().keep_all())
        .with_transport(transport)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x47; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: WRITER_EID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: false,
    };
    track_reader_proxy(&writer.ack_track, &cache, true, matched);
    writer.write(&KeyedProbe { k: 1, x: 1 }).expect("write 1");

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    *cache.before_floor_wait.lock().unwrap() = Some(Box::new(move || {
        let _ = entered_tx.send(());
    }));
    let track = Arc::clone(&writer.ack_track);
    let cache_for_ack = Arc::clone(&cache);
    let acker = std::thread::spawn(move || {
        if entered_rx.recv_timeout(Duration::from_secs(2)).is_err() {
            return false;
        }
        // The auto-unregister is the change after the one the test wrote.
        let last = cache_for_ack.highest_inserted();
        let mut map = track.lock().unwrap();
        map.insert(reader(1).as_bytes(), last);
        cache_for_ack.set_acked_floor(acked_floor(&map));
        true
    });

    let start = Instant::now();
    drop(writer);
    let waited = start.elapsed();
    let acked_from_inside_the_wait = acker.join().expect("acker");

    assert!(
        acked_from_inside_the_wait,
        "the delete announced the departure without waiting for its final \
         lifecycle change: no acknowledgement could be published inside it"
    );
    assert!(
        waited < Duration::from_secs(1),
        "the acknowledgement ends the wait, the grace does not bound it: \
         waited {waited:?}"
    );
}

/// A delete that owes no lifecycle change is not held for the grace: DDS 1.4
/// 2.2.2.4.1.6 auto-unregisters only the instances still registered, and a
/// writer that never registered one emits nothing on its way out. The
/// acknowledgement wait DDS offers for the changes it did emit is the
/// application's own call to `wait_for_acknowledgments` (2.2.2.4.2.15),
/// before it deletes.
#[test]
fn dropping_a_reliable_writer_that_never_emitted_a_lifecycle_change_does_not_wait() {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let mut writer = WriterBuilder::<KeyedProbe>::new("test/drop_no_instance".to_string())
        .qos(QoS::reliable().keep_all())
        .with_transport(transport)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x48; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: WRITER_EID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: false,
    };
    track_reader_proxy(&writer.ack_track, &cache, true, matched);
    assert_eq!(
        cache.acked_floor(),
        0,
        "premise: a reliable reader is matched and has acknowledged nothing"
    );

    let start = Instant::now();
    drop(writer);
    let waited = start.elapsed();
    assert!(
        waited < Duration::from_millis(100),
        "no lifecycle change was ever emitted, the delete owes none: \
         waited {waited:?}"
    );
}

/// DDS 1.4 2.2.2.4.1.6: the delete auto-unregisters the instances still
/// registered, and skips the ones the application already disposed (a
/// trailing unregister would flip DISPOSED to NO_WRITERS). The application's
/// dispose is then the writer's LAST lifecycle change, and RTPS 2.5
/// 8.4.2.2.3 makes it just as unrecoverable once the writer is gone: no
/// NACK handler and no HEARTBEAT survives the departure. The delete must
/// wait for that one too, even though it emitted nothing itself.
#[test]
fn dropping_a_reliable_writer_waits_for_the_dispose_the_application_already_sent() {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 1).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 1, mapping).expect("transport"));
    let mut writer = WriterBuilder::<KeyedProbe>::new("test/drop_after_dispose".to_string())
        .qos(QoS::reliable().keep_all())
        .with_transport(transport)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x4a; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: WRITER_EID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    let matched = PeerChange::Matched {
        guid: reader(1),
        reliable: true,
        volatile: false,
    };
    track_reader_proxy(&writer.ack_track, &cache, true, matched);
    let sample = KeyedProbe { k: 1, x: 1 };
    writer.write(&sample).expect("write");
    writer.dispose(&sample).expect("dispose");

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    *cache.before_floor_wait.lock().unwrap() = Some(Box::new(move || {
        let _ = entered_tx.send(());
    }));
    let track = Arc::clone(&writer.ack_track);
    let cache_for_ack = Arc::clone(&cache);
    let acker = std::thread::spawn(move || {
        if entered_rx.recv_timeout(Duration::from_secs(2)).is_err() {
            return false;
        }
        let last = cache_for_ack.highest_inserted();
        let mut map = track.lock().unwrap();
        map.insert(reader(1).as_bytes(), last);
        cache_for_ack.set_acked_floor(acked_floor(&map));
        true
    });

    let start = Instant::now();
    drop(writer);
    let waited = start.elapsed();
    let acked_from_inside_the_wait = acker.join().expect("acker");

    assert!(
        acked_from_inside_the_wait,
        "the delete announced the departure without waiting for the dispose \
         the application had already sent: the instance is skipped by the \
         auto-unregister loop, so nothing else held it back"
    );
    assert!(
        waited < Duration::from_secs(1),
        "the acknowledgement ends the wait, the grace does not bound it: \
         waited {waited:?}"
    );
}

/// A DataWriter deleted from inside a reader listener must not be able to
/// deadlock: the delete waits for an acknowledgement, and it runs on the
/// thread that just delivered a sample. The wait is bounded by its grace
/// and holds no lock the acknowledgement path takes, so the thread comes
/// back even when the acknowledgement never arrives -- the case here, with
/// a matched reader that never acknowledges. The deletion runs under a
/// watchdog: an unbounded wait fails this test instead of hanging it.
#[test]
fn dropping_a_writer_inside_a_reader_listener_is_bounded() {
    use crate::dds::listener::DataReaderListener;
    use crate::{DataWriter, Participant, TransportMode};

    /// Drops the writer it was given, once, on the thread that delivers the
    /// sample it reacts to.
    struct DropOnFirstData {
        writer: Arc<Mutex<Option<DataWriter<KeyedProbe>>>>,
        waited: Arc<Mutex<Option<Duration>>>,
        done: std::sync::mpsc::Sender<()>,
    }

    impl DataReaderListener<KeyedProbe> for DropOnFirstData {
        fn on_data_available(&self, _sample: &KeyedProbe) {
            let Some(writer) = self.writer.lock().unwrap().take() else {
                return;
            };
            let start = Instant::now();
            drop(writer);
            *self.waited.lock().unwrap() = Some(start.elapsed());
            let _ = self.done.send(());
        }
    }

    let lease = crate::test_support::domains::unique_domain();
    let participant = Participant::builder("drop_in_listener")
        .domain_id(lease.id())
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("participant");

    // The reader whose listener does the deleting, on the same participant.
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let waited: Arc<Mutex<Option<Duration>>> = Arc::new(Mutex::new(None));
    let slot: Arc<Mutex<Option<DataWriter<KeyedProbe>>>> = Arc::new(Mutex::new(None));
    let _reader = participant
        .topic::<KeyedProbe>("test/drop_in_listener_reader")
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .with_listener(Arc::new(DropOnFirstData {
            writer: Arc::clone(&slot),
            waited: Arc::clone(&waited),
            done: done_tx,
        }))
        .build()
        .expect("reader");

    // The writer the listener deletes: RELIABLE, with a matched reader that
    // never acknowledges, and a lifecycle change of its own, so its delete
    // provably waits.
    let writer = WriterBuilder::<KeyedProbe>::new("test/drop_in_listener_writer".to_string())
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer build");
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    let matched = PeerChange::Matched {
        guid: reader(2),
        reliable: true,
        volatile: false,
    };
    track_reader_proxy(&writer.ack_track, &cache, true, matched);
    let sample = KeyedProbe { k: 2, x: 2 };
    writer.write(&sample).expect("write");
    writer.dispose(&sample).expect("dispose");
    *slot.lock().unwrap() = Some(writer);

    let feeder = participant
        .topic::<KeyedProbe>("test/drop_in_listener_reader")
        .expect("topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("feeder");
    feeder.write(&KeyedProbe { k: 2, x: 2 }).expect("feed");

    assert!(
        done_rx.recv_timeout(Duration::from_secs(10)).is_ok(),
        "the delete inside the listener has not returned after 10s: the wait \
         is not bounded, or it holds a lock the acknowledgement path needs"
    );
    let waited = waited
        .lock()
        .unwrap()
        .expect("the listener measured the delete");
    assert!(
        waited >= DROP_LIFECYCLE_ACK_GRACE / 2,
        "premise: the unacknowledged lifecycle change holds the delete for \
         its grace ({:?} measured)",
        DROP_LIFECYCLE_ACK_GRACE
    );
    assert!(
        waited < Duration::from_secs(5),
        "the delete inside the listener waited {waited:?}"
    );
}
