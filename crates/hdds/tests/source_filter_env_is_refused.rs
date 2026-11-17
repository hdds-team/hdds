// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Source filtering is not applied on the receive path in this release, so a
//! participant asked to filter sources through `HDDS_SOURCE_ALLOW` or
//! `HDDS_SOURCE_DENY` must refuse to start instead of ignoring the setting.
//!
//! The environment is process-wide: every case lives in ONE test function of
//! this binary, so no other test can observe the variables while they are set.

use hdds::{Error, Participant};

const ALLOW: &str = "HDDS_SOURCE_ALLOW";
const DENY: &str = "HDDS_SOURCE_DENY";

fn build() -> Result<(), Error> {
    Participant::builder("source-filter-refused")
        .domain_id(7)
        .build()
        .map(|_| ())
}

fn clear() {
    std::env::remove_var(ALLOW);
    std::env::remove_var(DENY);
}

fn assert_refused(var: &str) {
    match build() {
        Err(Error::Config(message)) => {
            assert!(
                message.contains("source filtering is not supported in this release"),
                "{var}: unexpected message: {message}"
            );
            assert!(message.contains(var), "{var} not named in: {message}");
        }
        Err(other) => panic!("{var}: refused with the wrong error: {other:?}"),
        Ok(()) => panic!("{var}: participant creation accepted a source filter it ignores"),
    }
}

#[test]
fn a_source_filter_in_the_environment_refuses_participant_creation() {
    std::env::set_var("HDDS_INTERFACE", "127.0.0.1");
    clear();

    std::env::set_var(DENY, "10.0.0.99/32");
    assert_refused(DENY);
    clear();

    std::env::set_var(ALLOW, "10.0.0.0/8");
    assert_refused(ALLOW);
    clear();

    // An empty value is unset, and with neither variable the build succeeds.
    std::env::set_var(ALLOW, "");
    std::env::set_var(DENY, "");
    let accepted = build();
    clear();
    assert!(
        accepted.is_ok(),
        "empty variables must count as unset: {accepted:?}"
    );
}
