// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A participant's unicast ports belong to it alone, across processes.
//!
//! DDSI-RTPS 2.5 9.6.1.1 derives the metatraffic and user-data unicast ports
//! from the participant id so that they are unique on the host, and an
//! implementation tries successive participant ids until it finds free ones.
//! Two sockets sharing a unicast UDP port do NOT share its traffic: the
//! kernel hands each datagram to one of them, so one of two subscribers on
//! one port receives nothing at all, with no error anywhere.
//!
//! These tests re-execute this binary as child processes (real processes,
//! real UDP sockets), started back to back so that they build their
//! participants at the same moment:
//!
//! - two auto-assigned subscribers get different participant ids and BOTH
//!   receive what one writer publishes;
//! - two processes asking for the same explicit participant id
//!   (`HDDS_PARTICIPANT_ID`): the second one is refused with an error that
//!   names the port, instead of silently sharing it.

use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, TransportMode};
use std::collections::HashSet;
use std::io::Write;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct Tick {
    value: u32,
}

const TOPIC: &str = "ExclusivePortsTick";

/// Printed by a child once its participant is built: `<id> <meta> <user>`.
const PORTS_MARKER: &str = "HDDS_CHILD_PORTS=";
/// Printed by a reader child when it is done: how many distinct samples.
const GOT_MARKER: &str = "HDDS_CHILD_GOT=";
/// Printed by a child whose participant could not be built: the error.
const REFUSED_MARKER: &str = "HDDS_CHILD_REFUSED=";

/// Distinct samples a reader child must take before it leaves.
const WANTED: usize = 20;

const DOMAIN_ENV: &str = "HDDS_EXCLUSIVE_PORTS_DOMAIN";
const HOLD_ENV: &str = "HDDS_EXCLUSIVE_PORTS_HOLD_MS";

fn child_domain() -> u32 {
    std::env::var(DOMAIN_ENV)
        .expect("child started without its domain")
        .parse()
        .expect("numeric domain")
}

fn print_ports(participant: &Participant) {
    let mapping = participant
        .port_mapping()
        .expect("a UDP participant has a port mapping");
    println!(
        "{PORTS_MARKER}{} {} {}",
        participant.participant_id(),
        mapping.metatraffic_unicast,
        mapping.user_unicast
    );
    std::io::stdout().flush().expect("flush child stdout");
}

fn build_participant(name: &str, domain: u32) -> hdds::Result<std::sync::Arc<Participant>> {
    // SHM off: two processes on one host would otherwise carry the samples
    // over shared memory, and the unicast UDP ports would not matter.
    Participant::builder(name)
        .domain_id(domain)
        .with_transport(TransportMode::UdpMulticast)
        .shm_disable()
        .build()
}

/// Spawned by [`two_processes_started_together_get_their_own_ports`].
#[test]
#[ignore = "re-executed as a child process by two_processes_started_together_get_their_own_ports"]
fn child_reader() {
    let participant =
        build_participant("exclusive_ports_reader", child_domain()).expect("reader participant");
    print_ports(&participant);
    let reader = participant
        .topic::<Tick>(TOPIC)
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_last(100))
        .build()
        .expect("reader");

    let mut seen = HashSet::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    while seen.len() < WANTED && Instant::now() < deadline {
        while let Ok(Some(sample)) = reader.take() {
            seen.insert(sample.value);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    println!("{GOT_MARKER}{}", seen.len());
    std::io::stdout().flush().expect("flush child stdout");
}

/// Spawned by [`a_participant_id_in_use_in_another_process_is_refused`].
/// Builds a participant (the id comes from `HDDS_PARTICIPANT_ID`), reports
/// its ports or the error, and holds it for a while.
#[test]
#[ignore = "re-executed as a child process by a_participant_id_in_use_in_another_process_is_refused"]
fn child_holder() {
    let hold = Duration::from_millis(
        std::env::var(HOLD_ENV)
            .expect("child started without its hold time")
            .parse()
            .expect("numeric hold time"),
    );
    match build_participant("exclusive_ports_holder", child_domain()) {
        Ok(participant) => {
            print_ports(&participant);
            std::thread::sleep(hold);
        }
        Err(error) => {
            println!("{REFUSED_MARKER}{error}");
            std::io::stdout().flush().expect("flush child stdout");
        }
    }
}

fn spawn_child(test: &str, domain: u32, envs: &[(&str, String)]) -> Child {
    let mut command = Command::new(std::env::current_exe().expect("path to this test binary"));
    command
        .args([test, "--exact", "--ignored", "--nocapture"])
        .env(DOMAIN_ENV, domain.to_string())
        .env_remove("HDDS_PARTICIPANT_ID")
        .env_remove("HDDS_REUSEPORT")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }
    command
        .spawn()
        .expect("re-execute this test binary as a child")
}

fn marker_lines<'a>(stdout: &'a str, marker: &str) -> Vec<&'a str> {
    stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix(marker))
        .collect()
}

fn describe(output: &Output) -> String {
    format!(
        "status {}\nstdout:\n{}\nstderr (tail):\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
            .lines()
            .rev()
            .take(30)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n")
    )
}

#[test]
fn two_processes_started_together_get_their_own_ports() {
    let domain = unique_domain();
    let children = [
        spawn_child("child_reader", domain.id(), &[]),
        spawn_child("child_reader", domain.id(), &[]),
    ];

    let publisher = build_participant("exclusive_ports_writer", domain.id()).expect("publisher");
    let writer = publisher
        .topic::<Tick>(TOPIC)
        .expect("topic")
        .writer()
        .qos(QoS::reliable().keep_last(100))
        .build()
        .expect("writer");

    // Publish until both readers have left, or give up.
    let mut children: Vec<Option<Child>> = children.into_iter().map(Some).collect();
    let mut outputs: Vec<Option<Output>> = vec![None, None];
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut value = 0u32;
    while outputs.iter().any(Option::is_none) && Instant::now() < deadline {
        value += 1;
        writer.write(&Tick { value }).expect("write");
        std::thread::sleep(Duration::from_millis(50));
        for (slot, output) in children.iter_mut().zip(outputs.iter_mut()) {
            let finished = slot
                .as_mut()
                .is_some_and(|child| matches!(child.try_wait(), Ok(Some(_))));
            if finished {
                let child = slot.take().expect("child present");
                *output = Some(child.wait_with_output().expect("collect child output"));
            }
        }
    }
    for (slot, output) in children.iter_mut().zip(outputs.iter_mut()) {
        if let Some(mut child) = slot.take() {
            let _ = child.kill();
            *output = Some(child.wait_with_output().expect("collect killed child"));
        }
    }

    let mut ids = Vec::new();
    let mut ports = Vec::new();
    for output in outputs.iter().flatten() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "reader child failed: {}",
            describe(output)
        );
        let reported = marker_lines(&stdout, PORTS_MARKER);
        assert_eq!(reported.len(), 1, "no ports reported: {}", describe(output));
        let fields: Vec<u16> = reported[0]
            .split_whitespace()
            .map(|field| field.parse().expect("numeric field"))
            .collect();
        ids.push(fields[0]);
        ports.extend_from_slice(&fields[1..]);
        let got: usize = marker_lines(&stdout, GOT_MARKER)
            .first()
            .unwrap_or_else(|| panic!("reader did not report: {}", describe(output)))
            .parse()
            .expect("numeric count");
        assert!(
            got >= WANTED,
            "a reader received {got} of {WANTED} samples (participant ids {ids:?}): {}",
            describe(output)
        );
    }
    assert_eq!(ids.len(), 2);
    assert_ne!(
        ids[0], ids[1],
        "two processes started together were given the same participant id"
    );
    let distinct: HashSet<u16> = ports.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        ports.len(),
        "two processes share a unicast port: {ports:?}"
    );
}

#[test]
fn a_participant_id_in_use_in_another_process_is_refused() {
    let domain = unique_domain();
    let explicit = [("HDDS_PARTICIPANT_ID", "7".to_string())];
    let holder = spawn_child(
        "child_holder",
        domain.id(),
        &[explicit[0].clone(), (HOLD_ENV, "6000".to_string())],
    );
    // Wait until the first one has its ports, so the outcome is decided.
    // The holder's stdout is read only at the end, so look at the port.
    let mapping = hdds::transport::PortMapping::calculate(domain.id(), 7).expect("port mapping");
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::net::UdpSocket::bind(("0.0.0.0", mapping.metatraffic_unicast)).is_ok() {
        assert!(Instant::now() < deadline, "the holder never bound its port");
        std::thread::sleep(Duration::from_millis(20));
    }

    let second = spawn_child(
        "child_holder",
        domain.id(),
        &[explicit[0].clone(), (HOLD_ENV, "0".to_string())],
    )
    .wait_with_output()
    .expect("second child");
    let holder = holder.wait_with_output().expect("holder child");

    let holder_out = String::from_utf8_lossy(&holder.stdout);
    assert!(
        holder.status.success(),
        "holder failed: {}",
        describe(&holder)
    );
    assert_eq!(
        marker_lines(&holder_out, PORTS_MARKER).len(),
        1,
        "the first process must get participant id 7: {}",
        describe(&holder)
    );

    let second_out = String::from_utf8_lossy(&second.stdout);
    let refused = marker_lines(&second_out, REFUSED_MARKER);
    assert_eq!(
        refused.len(),
        1,
        "a second process on participant id 7 must be refused, not share the ports: {}",
        describe(&second)
    );
    assert!(
        refused[0].contains(&mapping.metatraffic_unicast.to_string()),
        "the error must name the port: {}",
        refused[0]
    );
}
