// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Dropping a participant releases everything it holds before the drop
//! returns.
//!
//! DDS 1.4 2.2.2.2.2.2 (`delete_participant`) deletes the participant; RTPS
//! 2.5 9.6.1.1 gives its unicast ports to it alone. A participant whose
//! threads, sockets or shared memory outlive its drop holds those ports
//! after the application has let it go: building the next participant with
//! the same participant id on the same domain then fails with
//! "Address already in use", and a long-lived process accumulates threads
//! with every participant it creates.
//!
//! - the same participant id is built again at once, a thousand times;
//! - the thread count of the process is back to its value before the
//!   participant was built (measured in a child process that runs this one
//!   test alone, so no other test's threads are counted, with every thread
//!   lingering after its stop so that only a join waits for it);
//! - its unicast ports can be bound again, and nothing keeps its transport;
//! - dropped from inside one of its own listener callbacks, it neither
//!   deadlocks nor panics, and its resources are released once that
//!   callback returns.

use hdds::dds::{DataReaderListener, SubscriptionMatchedStatus};
use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, TransportMode};
use std::net::UdpSocket;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(hdds::DDS, Debug, Clone)]
struct Beat {
    value: u32,
}

/// Set in the child process that measures threads.
const CHILD_ENV: &str = "HDDS_PARTICIPANT_DROP_CHILD";
/// The domain the child builds on (leased by the parent).
const DOMAIN_ENV: &str = "HDDS_PARTICIPANT_DROP_DOMAIN";

fn udp_participant(name: &str, domain: u32, id: Option<u8>) -> hdds::Result<Arc<Participant>> {
    Participant::builder(name)
        .domain_id(domain)
        .with_transport(TransportMode::UdpMulticast)
        .participant_id(id)
        .build()
}

/// The names of this process's threads, sorted.
fn thread_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir("/proc/self/task")
        .expect("read /proc/self/task")
        .filter_map(Result::ok)
        .map(|task| {
            std::fs::read_to_string(task.path().join("comm"))
                .unwrap_or_default()
                .trim()
                .to_string()
        })
        .collect();
    names.sort();
    names
}

/// The unicast ports of participant `id` on `domain`, bound by nobody.
fn ports_are_free(domain: u32, id: u8) -> Result<(), String> {
    let mapping = hdds::transport::PortMapping::calculate(domain, id).expect("port mapping");
    for port in [mapping.metatraffic_unicast, mapping.user_unicast] {
        UdpSocket::bind(("0.0.0.0", port)).map_err(|e| format!("port {port}: {e}"))?;
    }
    Ok(())
}

#[test]
fn the_same_participant_id_is_built_again_at_once() {
    let domain = unique_domain();
    for round in 0..1000 {
        let participant = udp_participant("drop_rebuild", domain.id(), Some(0))
            .unwrap_or_else(|e| panic!("round {round}: participant id 0 refused: {e}"));
        assert_eq!(participant.participant_id(), 0);
        drop(participant);
    }
}

#[test]
fn its_ports_are_free_and_its_transport_released_when_the_drop_returns() {
    let domain = unique_domain();
    let participant = udp_participant("drop_ports", domain.id(), Some(0)).expect("participant");
    let transport = Arc::downgrade(&participant.transport().expect("a UDP transport"));
    assert!(
        ports_are_free(domain.id(), 0).is_err(),
        "the participant does not hold its own ports"
    );
    drop(participant);
    assert!(
        transport.upgrade().is_none(),
        "something still holds the transport of a dropped participant"
    );
    if let Err(e) = ports_are_free(domain.id(), 0) {
        panic!("a dropped participant still holds its port: {e}");
    }
}

/// Runs in a child process alone (see the parent below).
#[test]
#[ignore = "re-executed as a child process by its_threads_are_gone_when_the_drop_returns"]
fn child_counts_threads() {
    assert!(std::env::var_os(CHILD_ENV).is_some(), "run by the parent");
    let domain: u32 = std::env::var(DOMAIN_ENV)
        .expect("domain")
        .parse()
        .expect("numeric domain");
    // Each thread lingers after it is told to stop, so a thread the drop
    // does not join is still there when the drop returns.
    hdds::test_support::threads::linger_on_exit(Duration::from_secs(2));
    let before = thread_names();
    let participant = udp_participant("drop_threads", domain, None).expect("participant");
    let during = thread_names();
    assert!(
        during.len() > before.len(),
        "the participant runs no thread of its own: {during:?}"
    );
    drop(participant);
    // A joined thread can stay listed for a few milliseconds after its
    // join returns, while the kernel finishes its exit (see `settled`).
    let after = hdds::test_support::threads::settled(&before, thread_names);
    assert_eq!(
        after, before,
        "threads outlived the participant (while it lived: {during:?})"
    );
}

#[test]
fn its_threads_are_gone_when_the_drop_returns() {
    let domain = unique_domain();
    let output = Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            "child_counts_threads",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .args(["--test-threads", "1"])
        .env(CHILD_ENV, "1")
        .env(DOMAIN_ENV, domain.id().to_string())
        .env_remove("HDDS_PARTICIPANT_ID")
        .output()
        .expect("run the child");
    assert!(
        output.status.success(),
        "child failed: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "the child ran nothing: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// Drops the participant it holds from inside its first match callback.
struct DropsItsParticipant {
    participant: Mutex<Option<Arc<Participant>>>,
    done: Mutex<Option<mpsc::Sender<std::thread::ThreadId>>>,
    reentered: AtomicBool,
}

impl DataReaderListener<Beat> for DropsItsParticipant {
    fn on_subscription_matched(&self, _status: SubscriptionMatchedStatus) {
        let Some(participant) = self.participant.lock().unwrap().take() else {
            self.reentered.store(true, Ordering::SeqCst);
            return;
        };
        drop(participant);
        if let Some(done) = self.done.lock().unwrap().take() {
            let _ = done.send(std::thread::current().id());
        }
    }
}

#[test]
fn a_participant_dropped_from_its_own_listener_does_not_deadlock() {
    let domain = unique_domain();
    let local = udp_participant("drop_in_listener", domain.id(), Some(0)).expect("local");
    let transport = Arc::downgrade(&local.transport().expect("a UDP transport"));
    let (done_tx, done_rx) = mpsc::channel();
    let listener = Arc::new(DropsItsParticipant {
        participant: Mutex::new(None),
        done: Mutex::new(Some(done_tx)),
        reentered: AtomicBool::new(false),
    });
    let reader = local
        .topic::<Beat>("DropInListener")
        .expect("topic")
        .reader()
        .qos(QoS::reliable())
        .with_listener(listener.clone())
        .build()
        .expect("reader");
    // From here on the listener holds the only handle of the participant.
    *listener.participant.lock().unwrap() = Some(local);

    let remote = udp_participant("drop_in_listener_peer", domain.id(), Some(1)).expect("remote");
    let writer = remote
        .topic::<Beat>("DropInListener")
        .expect("topic")
        .writer()
        .qos(QoS::reliable())
        .build()
        .expect("writer");

    let dropped_on = done_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the participant dropped from its own listener never finished its drop");
    assert_ne!(
        dropped_on,
        std::thread::current().id(),
        "the callback must run on a thread of the participant for this test to mean anything"
    );
    let _ = writer.write(&Beat { value: 1 });

    // The reader is the application's: once it is gone too, nothing of the
    // participant may remain, the thread that ran the callback included.
    drop(reader);
    drop(listener);
    let deadline = Instant::now() + Duration::from_secs(5);
    while transport.upgrade().is_some() || ports_are_free(domain.id(), 0).is_err() {
        assert!(
            Instant::now() < deadline,
            "the participant dropped from its listener still holds its transport or ports: {:?}",
            ports_are_free(domain.id(), 0)
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
