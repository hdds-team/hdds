// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A best-effort publisher that leaves right after its last
//! `end_coherent_changes`: its co-located subscriber receives its last set.
//!
//! The members cross over shared memory (two processes on one host,
//! BEST_EFFORT), the departure over UDP. Told to the readers at once, the
//! departure came before the last members, still in the writer's ring: the
//! readers took the writer for gone and discarded its last set, every run.
//! It is now routed behind the writer's data (`engine::departures`).
//!
//! What BEST_EFFORT still loses, and only under load, is legitimate: each
//! set's end marker travels UDP while its members travel the ring, and a
//! starved receive thread lets the end overtake its members past their wait
//! (`BEST_EFFORT_OVERTAKE_WAIT`), lets the last end lag the departure,
//! which arrives on another socket ("late data from a writer that left"),
//! or, at the shared-memory handover, delivers a later member ahead of an
//! earlier one, which the reader then refuses (RTPS v2.5 Sec.8.4.12.1). So
//! each run asserts what such a loss must keep: a set reaches the
//! application whole or not at all, across both topics for GROUP scope,
//! and a reader that lost samples says so (SAMPLE_LOST). The departure's
//! own property, the last set delivered, holds in at least one of three
//! runs: with the departure told at once it is lost in every one.
//!
//! The test re-executes this binary as the publisher (a real process: shared
//! memory between participants of one process is not used).

use hdds::dds::qos::{Presentation, PresentationAccessScope};
use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, TransportMode};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct Item {
    id: u32,
}

const DOMAIN_ENV: &str = "HDDS_SHM_DEPARTURE_DOMAIN";
const SCOPE_ENV: &str = "HDDS_SHM_DEPARTURE_SCOPE";
const TOPICS: [&str; 2] = ["ShmDepartureA", "ShmDepartureB"];
/// Sets written, `PER_SET` samples on each topic.
const SETS: u32 = 20;
const PER_SET: u32 = 3;

fn scope(name: &str) -> PresentationAccessScope {
    match name {
        "group" => PresentationAccessScope::Group,
        _ => PresentationAccessScope::Topic,
    }
}

fn qos(scope: PresentationAccessScope) -> QoS {
    QoS::best_effort()
        .keep_all()
        .presentation(Presentation::new(scope, true, false))
}

fn participant(name: &str, domain: u32) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain)
        .with_transport(TransportMode::UdpMulticast)
        .shm_prefer()
        .build()
        .expect("participant")
}

/// The publisher process: waits for its readers, writes every set at
/// once, and leaves right after the last `end_coherent_changes`.
#[test]
#[ignore = "re-executed as a child process by the tests below"]
fn child_publisher() {
    let domain: u32 = std::env::var(DOMAIN_ENV)
        .expect("domain")
        .parse()
        .expect("numeric");
    let scope = scope(&std::env::var(SCOPE_ENV).expect("scope"));
    let p = participant("shm_departure_pub", domain);
    let publisher = Arc::new(p.create_publisher(qos(scope)).expect("publisher"));
    let writers: Vec<_> = TOPICS
        .iter()
        .map(|topic| {
            p.topic::<Item>(topic)
                .expect("topic")
                .writer()
                .qos(qos(scope))
                .publisher(&publisher)
                .build()
                .expect("writer")
        })
        .collect();
    let deadline = Instant::now() + Duration::from_secs(10);
    while writers.iter().any(|w| w.matched_reader_count() == 0) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    // The shared-memory leg serves a reader once it attached.
    std::thread::sleep(Duration::from_millis(500));
    for set in 0..SETS {
        publisher.begin_coherent_changes().expect("begin");
        for (t, writer) in writers.iter().enumerate() {
            for k in 0..PER_SET {
                let id = (set * 100 + k) * 10 + u32::try_from(t).expect("small");
                writer.write(&Item { id }).expect("write");
            }
        }
        publisher.end_coherent_changes().expect("end");
        if set + 1 < SETS {
            // Paced: a best-effort shared-memory ring a burst overruns loses
            // samples by design; the last set is the one under test.
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    // Leaves at once: the participant's farewell goes out as it drops.
}

/// One run: the ids received, the readers' SAMPLE_LOST counts (per topic),
/// and the publisher's tail of output.
fn run(scope_name: &str) -> (Vec<u32>, Vec<u32>, String) {
    let domain = unique_domain();
    let scope = scope(scope_name);
    let p = participant("shm_departure_sub", domain.id());
    let subscriber = p.create_subscriber(qos(scope)).expect("subscriber");
    let readers: Vec<_> = TOPICS
        .iter()
        .map(|topic| {
            p.topic::<Item>(topic)
                .expect("topic")
                .reader()
                .qos(qos(scope))
                .subscriber(&subscriber)
                .build()
                .expect("reader")
        })
        .collect();
    let child = Command::new(std::env::current_exe().expect("this test binary"))
        .args(["child_publisher", "--exact", "--ignored", "--nocapture"])
        .env(DOMAIN_ENV, domain.id().to_string())
        .env(SCOPE_ENV, scope_name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the publisher");
    let mut got = Vec::new();
    let mut child = Some(child);
    let mut output = String::new();
    let mut quiet_since: Option<Instant> = None;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        subscriber.begin_access().expect("begin access");
        for reader in &readers {
            got.extend(reader.take_all().expect("take").into_iter().map(|s| s.id));
        }
        subscriber.end_access().expect("end access");
        if let Some(c) = child.as_mut() {
            if matches!(c.try_wait(), Ok(Some(_))) {
                let c = child.take().expect("child");
                let out = c.wait_with_output().expect("child output");
                output = String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .rev()
                    .take(20)
                    .collect::<Vec<_>>()
                    .join("\n");
                quiet_since = Some(Instant::now());
            }
        }
        // Done a second after the publisher left.
        if quiet_since.is_some_and(|t| t.elapsed() > Duration::from_secs(1)) {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if let Some(mut c) = child {
        let _ = c.kill();
    }
    let lost = readers
        .iter()
        .map(|r| r.get_sample_lost_status().total_count)
        .collect();
    (got, lost, output)
}

/// The id of sample `k` of set `set` on topic `t`.
fn id(set: u32, k: u32, t: u32) -> u32 {
    (set * 100 + k) * 10 + t
}

/// What a run that lost something must keep (module docs): every set whole
/// or absent, across both topics for GROUP scope; a topic with a sample
/// missing has SAMPLE_LOST. Returns whether the last set was delivered.
fn check_run(scope: &str, got: &[u32], lost: &[u32], output: &str) -> bool {
    let topics = u32::try_from(TOPICS.len()).expect("small");
    let group = scope == "group";
    let has = |set: u32, t: u32| {
        (0..PER_SET)
            .filter(|&k| got.contains(&id(set, k, t)))
            .count()
    };
    for set in 0..SETS {
        let per_topic: Vec<usize> = (0..topics).map(|t| has(set, t)).collect();
        let whole = |n: &usize| *n == 0 || *n == PER_SET as usize;
        assert!(
            per_topic.iter().all(whole),
            "{scope}: set {set} delivered in part: {per_topic:?} of {PER_SET} per topic\n{output}"
        );
        if group {
            assert!(
                per_topic.iter().all(|n| *n == per_topic[0]),
                "{scope}: GROUP set {set} on one topic only: {per_topic:?}\n{output}"
            );
        }
    }
    for t in 0..topics {
        let missing = (0..SETS).any(|set| has(set, t) == 0);
        assert!(
            !missing || lost[t as usize] > 0,
            "{scope}: topic {} lost samples and reported no SAMPLE_LOST\n{output}",
            TOPICS[t as usize]
        );
    }
    (0..topics).all(|t| has(SETS - 1, t) == PER_SET as usize)
}

fn the_last_set_is_received(scope: &str) {
    const RUNS: usize = 3;
    for attempt in 1..=RUNS {
        let (got, lost, output) = run(scope);
        if check_run(scope, &got, &lost, &output) {
            return;
        }
        eprintln!(
            "{scope}: run {attempt}: the last set was lost (reported), BEST_EFFORT under load"
        );
    }
    panic!("{scope}: the last set was lost in {RUNS} runs of {RUNS}: the departure overtook it");
}

#[test]
fn a_group_publisher_leaving_after_its_last_set_delivers_it() {
    the_last_set_is_received("group");
}

#[test]
fn a_topic_publisher_leaving_after_its_last_set_delivers_it() {
    the_last_set_is_received("topic");
}
