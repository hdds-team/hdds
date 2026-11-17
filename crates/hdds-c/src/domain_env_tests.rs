// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The C entry points apply the core domain rule: a domain set through
//! `hdds_config_set_domain_id` wins, else `HDDS_DOMAIN_ID` when it is valid,
//! else 0. A malformed or out-of-range `HDDS_DOMAIN_ID` makes creation return
//! NULL instead of building a participant on domain 0.
//!
//! Every participant here is intra-process (no socket, no multicast) and sits
//! on a domain in 200..=230, never 0. The env cases never touch this process's
//! environment: each one re-runs its test in a child process whose environment
//! is fixed at spawn, so no test thread can race a `set_var`.

use std::ffi::CString;
use std::process::Command;

use crate::info::hdds_participant_domain_id;
use crate::transport_config::{
    hdds_config_build, hdds_config_create, hdds_config_set_domain_id,
    hdds_config_set_transport_mode,
};
use crate::{hdds_participant_create_with_transport, hdds_participant_destroy, HddsTransportMode};

const ENV: &str = "HDDS_DOMAIN_ID";

/// Set only in the child process. It tells `with_env` to run the body in place.
const CHILD_MARK: &str = "HDDS_TEST_ENV_CHILD";

/// Runs `body` with HDDS_DOMAIN_ID set to `value` (`None` = unset).
///
/// In the test process this re-executes the test binary on `test_path` (the
/// full libtest path) with the variable in the child's environment, and fails
/// unless that child ran exactly one test and it passed. In the child it runs
/// `body` directly.
fn with_env(test_path: &str, value: Option<&str>, body: impl FnOnce()) {
    if std::env::var_os(CHILD_MARK).is_some() {
        body();
        return;
    }
    let exe = std::env::current_exe().expect("test binary path");
    let mut child = Command::new(exe);
    child
        .args([test_path, "--exact", "--test-threads=1", "--nocapture"])
        .env(CHILD_MARK, "1");
    if let Some(v) = value {
        child.env(ENV, v);
    } else {
        child.env_remove(ENV);
    }
    let out = child.output().expect("spawn the env test child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "{test_path} failed in its child process:\n{stdout}{stderr}"
    );
    assert!(
        stdout.contains("test result: ok. 1 passed; 0 failed"),
        "the child did not run exactly {test_path}:\n{stdout}"
    );
}

/// Creates an intra-process participant through the one-call C entry point.
/// Returns the handle (null on refusal) and the domain it reports.
fn create_with_transport(name: &str) -> (*mut crate::HddsParticipant, Option<u32>) {
    let cname = CString::new(name).unwrap();
    // SAFETY: `cname` is a valid NUL-terminated string for the whole call.
    let handle = unsafe {
        hdds_participant_create_with_transport(
            cname.as_ptr(),
            HddsTransportMode::HddsTransportIntraProcess,
        )
    };
    if handle.is_null() {
        return (handle, None);
    }
    // SAFETY: `handle` was just returned by the create call and is not freed yet.
    let domain = unsafe { hdds_participant_domain_id(handle) };
    (handle, Some(domain))
}

/// Builds through a config handle with the given explicit domain (`None` = unset).
fn build_config(name: &str, explicit: Option<u32>) -> (*mut crate::HddsParticipant, Option<u32>) {
    let cname = CString::new(name).unwrap();
    // SAFETY: `cname` is a valid NUL-terminated string; the config handle is
    // consumed by `hdds_config_build`, which is the only call that takes it.
    let handle = unsafe {
        let config = hdds_config_create(cname.as_ptr());
        assert!(!config.is_null(), "hdds_config_create failed");
        if let Some(domain) = explicit {
            assert_eq!(
                hdds_config_set_domain_id(config, domain),
                crate::HddsError::HddsOk
            );
        }
        assert_eq!(
            hdds_config_set_transport_mode(config, HddsTransportMode::HddsTransportIntraProcess),
            crate::HddsError::HddsOk
        );
        hdds_config_build(config)
    };
    if handle.is_null() {
        return (handle, None);
    }
    // SAFETY: `handle` was just returned by the build call and is not freed yet.
    let domain = unsafe { hdds_participant_domain_id(handle) };
    (handle, Some(domain))
}

fn destroy(handle: *mut crate::HddsParticipant) {
    // SAFETY: called once per handle returned by a create call in this module.
    unsafe { hdds_participant_destroy(handle) };
}

#[test]
fn create_with_transport_takes_the_environment_domain() {
    with_env(
        "domain_env_tests::create_with_transport_takes_the_environment_domain",
        Some("213"),
        || {
            let (handle, domain) = create_with_transport("c_env_domain");
            assert!(
                !handle.is_null(),
                "a valid HDDS_DOMAIN_ID must create the participant"
            );
            assert_eq!(
                domain,
                Some(213),
                "the environment domain did not reach the participant"
            );
            destroy(handle);
        },
    );
}

#[test]
fn create_with_transport_refuses_a_malformed_environment_domain() {
    with_env(
        "domain_env_tests::create_with_transport_refuses_a_malformed_environment_domain",
        Some("2x1"),
        || {
            let (handle, _) = create_with_transport("c_env_malformed");
            assert!(
                handle.is_null(),
                "a malformed HDDS_DOMAIN_ID must give NULL, not domain 0"
            );
        },
    );
}

#[test]
fn create_with_transport_refuses_an_out_of_range_environment_domain() {
    with_env(
        "domain_env_tests::create_with_transport_refuses_an_out_of_range_environment_domain",
        Some("233"),
        || {
            let (handle, _) = create_with_transport("c_env_out_of_range");
            assert!(handle.is_null(), "HDDS_DOMAIN_ID above 232 must give NULL");
        },
    );
}

#[test]
fn config_build_explicit_domain_wins_over_the_environment() {
    with_env(
        "domain_env_tests::config_build_explicit_domain_wins_over_the_environment",
        Some("215"),
        || {
            let (handle, domain) = build_config("c_cfg_explicit", Some(214));
            assert!(!handle.is_null());
            assert_eq!(
                domain,
                Some(214),
                "an explicit domain must win over HDDS_DOMAIN_ID"
            );
            destroy(handle);
        },
    );
}

#[test]
fn config_build_takes_the_environment_domain_when_none_is_set() {
    with_env(
        "domain_env_tests::config_build_takes_the_environment_domain_when_none_is_set",
        Some("215"),
        || {
            let (handle, domain) = build_config("c_cfg_env", None);
            assert!(!handle.is_null());
            assert_eq!(
                domain,
                Some(215),
                "HDDS_DOMAIN_ID did not reach an unset config"
            );
            destroy(handle);
        },
    );
}

#[test]
fn config_build_refuses_a_malformed_environment_domain() {
    with_env(
        "domain_env_tests::config_build_refuses_a_malformed_environment_domain",
        Some("abc"),
        || {
            let (handle, _) = build_config("c_cfg_malformed", None);
            assert!(
                handle.is_null(),
                "a malformed HDDS_DOMAIN_ID must give NULL, not domain 0"
            );
        },
    );
}

#[test]
fn config_build_ignores_a_malformed_environment_when_a_domain_is_set() {
    with_env(
        "domain_env_tests::config_build_ignores_a_malformed_environment_when_a_domain_is_set",
        Some("abc"),
        || {
            let (handle, domain) = build_config("c_cfg_explicit_over_bad_env", Some(216));
            assert!(
                !handle.is_null(),
                "an explicit domain never reads HDDS_DOMAIN_ID"
            );
            assert_eq!(domain, Some(216));
            destroy(handle);
        },
    );
}
