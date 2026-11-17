// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Cross-process proof for `hdds::test_support::domains`.
//!
//! The unit tests inside the module cover the in-process properties (pool
//! contents, uniqueness across threads, exhaustion). They cannot cover the
//! case the allocator actually exists for: `cargo` runs the lib test binary
//! and every file under `tests/` as SEPARATE processes, in parallel, and a
//! per-process counter would hand all of them the same domain. This file
//! re-executes itself as several child processes that hold a lease at the
//! same time, and asserts they all got different domains.
//!
//! It doubles as the reachability proof for the other half of the
//! requirement: this file is compiled as an external crate against the
//! published `hdds` lib, so the fact that it imports
//! `hdds::test_support::domains` at all shows the helper is visible outside
//! `cfg(test)` (via the `test-support` feature that the self dev-dependency
//! in Cargo.toml turns on).

use std::collections::HashSet;
use std::io::Write;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use hdds::test_support::domains::{unique_domain, DOMAIN_POOL, RESERVED_DOMAINS};

/// Marker the child prints on stdout so the parent can read its domain back.
const MARKER: &str = "HDDS_CHILD_DOMAIN=";

/// Name of the helper test below, as libtest sees it in this binary.
const CHILD_TEST: &str = "child_holds_one_domain";

/// How many children run at once. Well under the pool size, so a failure
/// here means duplicate allocation, never exhaustion.
const CHILDREN: usize = 8;

/// How long a child keeps its lease. Long enough that all children (spawned
/// back to back, in milliseconds) overlap in time; short enough that the
/// whole test stays around a second.
const HOLD: Duration = Duration::from_millis(900);

#[test]
fn allocator_is_reachable_from_an_integration_binary() {
    let lease = unique_domain();
    assert!(
        DOMAIN_POOL.contains(&lease.id()),
        "domain {} is outside the pool",
        lease.id()
    );
    assert!(!RESERVED_DOMAINS.contains(&lease.id()));
    assert!(lease.id() <= 232);
}

/// Spawned by [`cross_process_leases_never_collide`], never run on its own.
#[test]
#[ignore = "re-executed as a child process by cross_process_leases_never_collide"]
fn child_holds_one_domain() {
    let lease = unique_domain();
    println!("{MARKER}{}", lease.id());
    std::io::stdout().flush().expect("flush child stdout");
    // Hold the lease while the siblings take theirs. Without this the
    // children would run one after another and each could legitimately be
    // handed the same domain.
    thread::sleep(HOLD);
    drop(lease);
}

#[test]
fn cross_process_leases_never_collide() {
    let exe = std::env::current_exe().expect("path to this test binary");

    // The parent takes one too: the children must avoid the parent's domain
    // as well as each other's.
    let parent = unique_domain();

    let children: Vec<_> = (0..CHILDREN)
        .map(|_| {
            Command::new(&exe)
                .args([CHILD_TEST, "--exact", "--ignored", "--nocapture"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("re-execute this test binary as a child")
        })
        .collect();

    let mut domains = vec![parent.id()];
    for child in children {
        let out = child.wait_with_output().expect("wait for child");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "child failed ({}):\nstdout:\n{stdout}\nstderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        let reported: Vec<u32> = stdout
            .lines()
            .filter_map(|line| line.trim().strip_prefix(MARKER))
            .map(|id| id.parse().expect("child printed a numeric domain"))
            .collect();
        assert_eq!(
            reported.len(),
            1,
            "child did not report exactly one domain:\n{stdout}"
        );
        domains.push(reported[0]);
    }

    assert_eq!(domains.len(), CHILDREN + 1);
    let unique: HashSet<u32> = domains.iter().copied().collect();
    assert_eq!(
        unique.len(),
        domains.len(),
        "two processes were handed the same domain: {domains:?}"
    );
    for domain in domains {
        assert!(
            DOMAIN_POOL.contains(&domain),
            "domain {domain} is outside the pool"
        );
        assert!(
            !RESERVED_DOMAINS.contains(&domain),
            "domain {domain} belongs to another project on this machine"
        );
        assert!(domain <= 232, "domain {domain} has no RTPS port");
    }
}
