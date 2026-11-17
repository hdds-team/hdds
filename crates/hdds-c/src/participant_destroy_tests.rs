// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! `hdds_participant_destroy` is synchronous, as `delete_participant` is
//! (DDS 1.4 2.2.2.2.2.2): when it returns, the participant's threads have
//! ended and its unicast ports (RTPS 2.5 9.6.1.1) are free, so a C
//! application can create the same participant id again at once.

use crate::transport_config::{
    hdds_config_build, hdds_config_create, hdds_config_set_domain_id,
    hdds_config_set_participant_id,
};
use crate::{hdds_participant_destroy, HddsError, HddsParticipant};
use hdds::test_support::domains::unique_domain;
use std::ffi::CString;
use std::net::UdpSocket;
use std::process::Command;

const CHILD_ENV: &str = "HDDS_C_DESTROY_CHILD";
const DOMAIN_ENV: &str = "HDDS_C_DESTROY_DOMAIN";

/// A UDP participant with participant id `id` on `domain`, through the C ABI.
unsafe fn c_participant(domain: u32, id: Option<u8>) -> *mut HddsParticipant {
    let name = CString::new("c_destroy").unwrap();
    let config = hdds_config_create(name.as_ptr());
    assert!(!config.is_null());
    assert_eq!(hdds_config_set_domain_id(config, domain), HddsError::HddsOk);
    if let Some(id) = id {
        assert_eq!(
            hdds_config_set_participant_id(config, id),
            HddsError::HddsOk
        );
    }
    hdds_config_build(config)
}

fn thread_count() -> usize {
    std::fs::read_dir("/proc/self/task")
        .expect("read /proc/self/task")
        .count()
}

fn ports_are_free(domain: u32, id: u8) -> Result<(), String> {
    let mapping = hdds::transport::PortMapping::calculate(domain, id).expect("port mapping");
    for port in [mapping.metatraffic_unicast, mapping.user_unicast] {
        UdpSocket::bind(("0.0.0.0", port)).map_err(|e| format!("port {port}: {e}"))?;
    }
    Ok(())
}

#[test]
fn a_destroyed_participant_id_is_created_again_at_once() {
    let domain = unique_domain();
    for round in 0..100 {
        unsafe {
            let participant = c_participant(domain.id(), Some(0));
            assert!(
                !participant.is_null(),
                "round {round}: participant id 0 refused"
            );
            hdds_participant_destroy(participant);
        }
        if let Err(e) = ports_are_free(domain.id(), 0) {
            panic!("round {round}: a destroyed participant still holds its port: {e}");
        }
    }
}

/// Runs in a child process alone (see the parent below).
#[test]
#[ignore = "re-executed as a child process by destroy_leaves_no_thread_behind"]
fn child_counts_threads_around_destroy() {
    assert!(std::env::var_os(CHILD_ENV).is_some(), "run by the parent");
    let domain: u32 = std::env::var(DOMAIN_ENV)
        .expect("domain")
        .parse()
        .expect("numeric domain");
    // Each thread lingers after it is told to stop, so a thread the destroy
    // does not join is still there when it returns.
    hdds::test_support::threads::linger_on_exit(std::time::Duration::from_secs(2));
    let before = thread_count();
    unsafe {
        let participant = c_participant(domain, None);
        assert!(!participant.is_null(), "participant refused");
        assert!(thread_count() > before, "the participant runs no thread");
        hdds_participant_destroy(participant);
    }
    // A joined thread can stay listed for a few milliseconds after its
    // join returns, while the kernel finishes its exit (see `settled`).
    assert_eq!(
        hdds::test_support::threads::settled(&before, thread_count),
        before,
        "threads outlived hdds_participant_destroy"
    );
}

#[test]
fn destroy_leaves_no_thread_behind() {
    let domain = unique_domain();
    let output = Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            "participant_destroy_tests::child_counts_threads_around_destroy",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(CHILD_ENV, "1")
        .env(DOMAIN_ENV, domain.id().to_string())
        .env_remove("HDDS_PARTICIPANT_ID")
        .output()
        .expect("run the child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "child failed: {}\nstdout:\n{stdout}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}
