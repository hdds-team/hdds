// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A knob in `config::env_flags` is answered by the FIRST read and never
//! re-read: a variable set after that is not seen.
//!
//! That is the contract the module documents, and it is the one thing its
//! unit tests cannot observe on their own - inside the `--lib` binary the
//! environment never changes, so a cached read and a repeated read give the
//! same answer. Only a process that changes its own environment between two
//! reads can tell them apart.
//!
//! This lives in its own test binary because it mutates process-global
//! state: one test, no parallel reader. `std::env::set_var` races every
//! concurrent `getenv` in the process (which is why edition 2024 made it
//! `unsafe`); with a single `#[test]` in this file, cargo gives it a
//! process where nothing else is running and no HDDS object exists.

/// `HDDS_INTEROP_DIAGNOSTICS` is the knob under test only because it is
/// cheap: it gates diagnostics, so getting it wrong here costs nothing at
/// runtime. The caching it demonstrates is `Knob::get`'s, shared by all
/// four knobs.
const VAR: &str = "HDDS_INTEROP_DIAGNOSTICS";

#[test]
fn a_knob_set_after_the_first_read_is_not_seen() {
    // Do not inherit the operator's environment: this test states its own
    // starting point rather than assuming one.
    std::env::remove_var(VAR);
    assert!(
        !hdds::config::env_flags::interop_diagnostics(),
        "the first read, with {VAR} absent, must answer OFF"
    );

    std::env::set_var(VAR, "1");
    // Without this the test would pass vacuously if the write never landed.
    assert_eq!(
        std::env::var(VAR).ok().as_deref(),
        Some("1"),
        "the environment write itself must have landed"
    );

    assert!(
        !hdds::config::env_flags::interop_diagnostics(),
        "{VAR} was set after the first read, so it must NOT be seen: the \
         answer is fixed for the life of the process"
    );
}
