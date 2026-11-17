// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Real memory held by fragment reassembly under a 1-octet fragmentSize.
//!
//! RTPS 2.5 sets no minimum fragmentSize, so anyone may cut a sample into
//! 1-octet fragments. The reassembly budget must bound the memory the buffer
//! actually holds, not the payload octets it counts: one allocation per
//! fragment made a 16 MiB budget cost about 1.5 GiB of RSS.
//!
//! Its own test binary, one test, so the resident set it measures is this
//! test's alone. Linux only (`/proc/self/statm`).

#![cfg(target_os = "linux")]

use hdds::core::discovery::multicast::FragmentGeometry;
use hdds::core::discovery::{FragmentBuffer, GUID};

/// Resident set of this process, in octets.
fn rss() -> usize {
    let statm = std::fs::read_to_string("/proc/self/statm").expect("statm");
    let pages: usize = statm
        .split_whitespace()
        .nth(1)
        .and_then(|field| field.parse().ok())
        .expect("resident pages");
    // SAFETY: sysconf has no preconditions.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    pages * usize::try_from(page).expect("page size")
}

#[test]
fn one_octet_fragments_stay_within_the_reassembly_budget() {
    const BUDGET: usize = 2 << 20;
    const FRAGMENTS: u32 = 1 << 16;
    let geometry = FragmentGeometry {
        fragment_size: 1,
        sample_size: FRAGMENTS,
    };
    let mut buffer = FragmentBuffer::new(256, 600_000).with_max_bytes(BUDGET);
    let before = rss();
    // More sequences than the budget holds (about 74 KiB charged each), each one fragment short of
    // complete, from as many sources: every one is held as long as the
    // budget allows, then evicted for the next.
    for source in 0..48u32 {
        let mut prefix = [0xEEu8; 12];
        prefix[..4].copy_from_slice(&source.to_be_bytes());
        let writer = GUID::new(prefix, [0, 0, 1, 2]);
        for frag in 1..FRAGMENTS {
            assert!(buffer
                .insert_fragment(writer, 1, frag, geometry, vec![5])
                .is_none());
        }
    }
    assert!(buffer.pending_count() > 0);
    let grown = rss().saturating_sub(before);
    eprintln!(
        "RSS growth {} KiB for a {} KiB budget, {} sequences pending",
        grown / 1024,
        BUDGET / 1024,
        buffer.pending_count()
    );
    // The allocator may keep freed sequences resident; three budgets is room
    // for that and the harness, and thirty times under what one allocation
    // per fragment cost (about 98 octets per octet held).
    assert!(
        grown < 3 * BUDGET,
        "{} octets resident for a {}-octet budget",
        grown,
        BUDGET
    );
}
