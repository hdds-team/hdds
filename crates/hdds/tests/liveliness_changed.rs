// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! LIVELINESS_CHANGED between two participants (DDS v1.4 Sec.2.2.3.11,
//! Sec.2.2.4.1): a matched AUTOMATIC writer is alive while its participant
//! lives, even writing nothing; killed with no farewell, it is not alive
//! within about one lease, long before its participant's own lease ends;
//! deleted, it is no longer counted at all.
//!
//! The killed writer runs in a child process (this binary, re-executed),
//! which the test kills with SIGKILL: nothing of it says goodbye.

use hdds::dds::listener::LivelinessChangedStatus;
use hdds::dds::{Condition, DataReaderListener, StatusMask, WaitSet};
use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, TransportMode};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct Heartbeat {
    n: u32,
}

const DOMAIN_ENV: &str = "HDDS_LIVELINESS_CHANGED_DOMAIN";
const TOPIC: &str = "LivelinessChanged";
const LEASE_MS: u64 = 500;

fn qos() -> QoS {
    QoS::best_effort().liveliness_automatic_millis(LEASE_MS)
}

fn participant(name: &str, domain: u32) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant")
}

/// The writer process: one AUTOMATIC writer that never writes, until it
/// is killed (or 60 s pass).
#[test]
#[ignore = "re-executed as a child process by the tests below"]
fn child_writer() {
    let domain: u32 = std::env::var(DOMAIN_ENV)
        .expect("domain")
        .parse()
        .expect("numeric");
    let p = participant("liveliness_child_writer", domain);
    let _writer = p
        .topic::<Heartbeat>(TOPIC)
        .expect("topic")
        .writer()
        .qos(qos())
        .build()
        .expect("writer");
    println!("ready");
    std::thread::sleep(Duration::from_secs(60));
}

#[derive(Default)]
struct Recorder(Mutex<Vec<LivelinessChangedStatus>>);

impl DataReaderListener<Heartbeat> for Recorder {
    fn on_liveliness_changed(&self, status: LivelinessChangedStatus) {
        self.0.lock().expect("recorder").push(status);
    }
}

fn counts(s: &LivelinessChangedStatus) -> (u32, u32) {
    (s.alive_count, s.not_alive_count)
}

/// Poll `read` until it returns `want`, for at most `within`.
fn until<T: PartialEq + std::fmt::Debug>(within: Duration, want: T, read: impl Fn() -> T) -> T {
    let deadline = Instant::now() + within;
    loop {
        let got = read();
        if got == want || Instant::now() >= deadline {
            return got;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_killed_writer_is_not_alive_within_about_one_lease() {
    let domain = unique_domain();
    let p = participant("liveliness_reader", domain.id());
    let topic = p.topic::<Heartbeat>(TOPIC).expect("topic");
    // One reader with a listener, one read through a WaitSet.
    let recorder = Arc::new(Recorder::default());
    let heard = topic.reader().qos(qos()).build().expect("reader");
    heard.set_listener(
        Some(Arc::clone(&recorder) as Arc<dyn DataReaderListener<Heartbeat>>),
        StatusMask::LIVELINESS_CHANGED,
    );
    let waited = topic.reader().qos(qos()).build().expect("reader");
    let condition = waited.get_status_condition();
    condition.set_enabled_statuses(StatusMask::LIVELINESS_CHANGED);
    let waitset = WaitSet::new();
    waitset
        .attach_condition(Arc::clone(&condition) as Arc<dyn Condition>)
        .expect("attach");

    let mut child = Command::new(std::env::current_exe().expect("this test binary"))
        .args(["child_writer", "--exact", "--ignored", "--nocapture"])
        .env(DOMAIN_ENV, domain.id().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the writer");
    let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines();
    let ready = lines.any(|line| line.is_ok_and(|l| l.contains("ready")));
    assert!(ready, "the writer process started");

    let matched = until(Duration::from_secs(10), (1, 0), || {
        counts(&waited.get_liveliness_changed_status())
    });
    assert_eq!(matched, (1, 0), "matched, alive");
    // Ten leases with nothing written: alive throughout.
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(counts(&waited.get_liveliness_changed_status()), (1, 0));
    }
    assert!(
        !condition
            .get_active_statuses()
            .contains(StatusMask::LIVELINESS_CHANGED),
        "read: cleared"
    );

    child.kill().expect("SIGKILL");
    let killed = Instant::now();
    let woken = waitset.wait(Some(Duration::from_secs(5)));
    let after = killed.elapsed();
    let _ = child.wait();
    eprintln!("not alive {after:?} after the kill (lease {LEASE_MS} ms)");
    assert!(woken.is_ok(), "the WaitSet woke on LIVELINESS_CHANGED");
    let status = waited.get_liveliness_changed_status();
    assert_eq!(counts(&status), (0, 1), "not alive, still matched");
    assert_eq!(status.alive_count_change, -1);
    assert_eq!(status.not_alive_count_change, 1);
    assert!(status.last_publication_handle.is_some());
    // About one lease: never before it (renewed up to the kill), and well
    // within two of them.
    assert!(
        after < Duration::from_millis(2 * LEASE_MS),
        "not alive {after:?} after the kill, lease {LEASE_MS} ms"
    );

    let calls = until(Duration::from_secs(2), 2, || {
        recorder.0.lock().expect("recorder").len()
    });
    assert_eq!(calls, 2, "matched, then not alive");
    let told = recorder.0.lock().expect("recorder").clone();
    assert_eq!(counts(&told[0]), (1, 0));
    assert_eq!(
        (told[0].alive_count_change, told[0].not_alive_count_change),
        (1, 0)
    );
    assert_eq!(counts(&told[1]), (0, 1));
    assert_eq!(
        (told[1].alive_count_change, told[1].not_alive_count_change),
        (-1, 1)
    );
}

#[test]
fn a_deleted_writer_is_no_longer_counted() {
    let domain = unique_domain();
    let a = participant("liveliness_deleted_writer", domain.id());
    let b = participant("liveliness_deleted_reader", domain.id());
    let writer = a
        .topic::<Heartbeat>(TOPIC)
        .expect("topic")
        .writer()
        .qos(qos())
        .build()
        .expect("writer");
    let reader = b
        .topic::<Heartbeat>(TOPIC)
        .expect("topic")
        .reader()
        .qos(qos())
        .build()
        .expect("reader");
    let matched = until(Duration::from_secs(10), (1, 0), || {
        counts(&reader.get_liveliness_changed_status())
    });
    assert_eq!(matched, (1, 0));
    drop(writer);
    let gone = until(Duration::from_secs(5), (0, 0), || {
        counts(&reader.get_liveliness_changed_status())
    });
    assert_eq!(gone, (0, 0), "unmatched: neither alive nor not alive");
}
