// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The one domain rule of `ParticipantBuilder::build`: a domain set in code
//! always wins, else `HDDS_DOMAIN_ID` when it is set and valid, else 0.
//!
//! Every participant here is intra-process (no socket, no multicast) and sits
//! on a domain in 200..=230, never 0. This binary is the only one that writes
//! HDDS_DOMAIN_ID, and its env cases share one lock.

use std::ffi::{OsStr, OsString};
use std::sync::Mutex;

use hdds::config::{domain_id_from_env, ENV_DOMAIN_ID};
use hdds::{Error, Participant, TransportMode};

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Puts HDDS_DOMAIN_ID back when dropped, also when the test panics.
struct RestoreEnv(Option<OsString>);

impl Drop for RestoreEnv {
    fn drop(&mut self) {
        match self.0.take() {
            Some(v) => std::env::set_var(ENV_DOMAIN_ID, v),
            None => std::env::remove_var(ENV_DOMAIN_ID),
        }
    }
}

/// Runs `body` with HDDS_DOMAIN_ID set to `value` (`None` = unset).
fn with_env<S: AsRef<OsStr>, T>(value: Option<S>, body: impl FnOnce() -> T) -> T {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _restore = RestoreEnv(std::env::var_os(ENV_DOMAIN_ID));
    match value {
        Some(v) => std::env::set_var(ENV_DOMAIN_ID, v),
        None => std::env::remove_var(ENV_DOMAIN_ID),
    }
    body()
}

#[test]
fn explicit_domain_wins_over_the_environment() {
    with_env(Some("212"), || {
        let participant = Participant::builder("rule_explicit")
            .domain_id(205)
            .with_transport(TransportMode::IntraProcess)
            .build()
            .expect("an explicit domain must build");
        assert_eq!(
            participant.domain_id(),
            205,
            "HDDS_DOMAIN_ID overrode a domain set in code"
        );
    });
}

#[test]
fn environment_domain_is_used_when_no_domain_is_set() {
    with_env(Some("210"), || {
        let participant = Participant::builder("rule_env")
            .with_transport(TransportMode::IntraProcess)
            .build()
            .expect("a valid HDDS_DOMAIN_ID must build");
        assert_eq!(
            participant.domain_id(),
            210,
            "HDDS_DOMAIN_ID did not reach the participant"
        );
    });
}

#[test]
fn malformed_environment_domain_refuses_the_build() {
    with_env(Some("2x1"), || {
        match Participant::builder("rule_malformed")
            .with_transport(TransportMode::IntraProcess)
            .build()
        {
            Err(Error::Config(msg)) => assert!(msg.contains("HDDS_DOMAIN_ID"), "{msg}"),
            Err(other) => panic!("expected Error::Config, got {other:?}"),
            Ok(p) => panic!("malformed HDDS_DOMAIN_ID built on domain {}", p.domain_id()),
        }
    });
}

#[test]
fn out_of_range_environment_domain_refuses_the_build() {
    with_env(Some("233"), || {
        match Participant::builder("rule_out_of_range")
            .with_transport(TransportMode::IntraProcess)
            .build()
        {
            Err(Error::Config(msg)) => assert!(msg.contains("233"), "{msg}"),
            Err(other) => panic!("expected Error::Config, got {other:?}"),
            Ok(p) => panic!("HDDS_DOMAIN_ID=233 built on domain {}", p.domain_id()),
        }
    });
}

#[test]
fn malformed_environment_is_not_read_when_a_domain_is_set() {
    with_env(Some("abc"), || {
        let participant = Participant::builder("rule_explicit_over_bad_env")
            .domain_id(206)
            .with_transport(TransportMode::IntraProcess)
            .build()
            .expect("an explicit domain never reads HDDS_DOMAIN_ID");
        assert_eq!(participant.domain_id(), 206);
    });
}

#[test]
fn explicit_domain_above_232_is_still_refused() {
    with_env(None::<&str>, || {
        match Participant::builder("rule_explicit_233")
            .domain_id(233)
            .with_transport(TransportMode::IntraProcess)
            .build()
        {
            Err(Error::InvalidDomainId(233)) => {}
            Err(other) => panic!("expected InvalidDomainId(233), got {other:?}"),
            Ok(p) => panic!("explicit domain 233 built on domain {}", p.domain_id()),
        }
    });
}

#[test]
fn unset_environment_resolves_to_no_domain() {
    // The build turns "no domain" into 0 (covered by the C and ROS paths
    // through the same rule); here only the resolver's answer is pinned.
    with_env(None::<&str>, || {
        assert_eq!(domain_id_from_env(ENV_DOMAIN_ID).unwrap(), None);
    });
}

#[test]
fn empty_environment_counts_as_unset() {
    with_env(Some(""), || {
        assert_eq!(domain_id_from_env(ENV_DOMAIN_ID).unwrap(), None);
    });
}

#[test]
fn the_rtps_ceiling_is_accepted_and_one_above_is_refused() {
    with_env(Some("232"), || {
        assert_eq!(domain_id_from_env(ENV_DOMAIN_ID).unwrap(), Some(232));
    });
    with_env(Some("233"), || {
        assert!(matches!(
            domain_id_from_env(ENV_DOMAIN_ID),
            Err(Error::Config(_))
        ));
    });
}

#[test]
fn non_decimal_or_overflowing_values_are_refused() {
    for value in [
        "+5",
        " 5",
        "5 ",
        "0x10",
        "1e2",
        "-1",
        "99999999999999999999",
    ] {
        with_env(Some(value), || {
            assert!(
                matches!(domain_id_from_env(ENV_DOMAIN_ID), Err(Error::Config(_))),
                "HDDS_DOMAIN_ID={value:?} must be refused"
            );
        });
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_environment_is_refused() {
    use std::os::unix::ffi::OsStrExt;
    let bytes = OsStr::from_bytes(&[0x32, 0xff]);
    with_env(Some(bytes), || {
        assert!(matches!(
            domain_id_from_env(ENV_DOMAIN_ID),
            Err(Error::Config(_))
        ));
    });
}
