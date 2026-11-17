// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! `MemoryPolicy::reader_reserve_percent` outside its accepted range is
//! refused when the participant is built, before the process-wide pool is
//! built from it. A RELIABLE KEEP_ALL pair in one process at each end of the
//! range shows why: at 0 the pair stalls (writes time out with a single
//! sample delivered); at 100 the very first write times out, writers having
//! no storage at all.

use hdds::qos::MemoryPolicy;
use hdds::{Error, Participant, TransportMode};

fn build(percent: u8) -> Result<std::sync::Arc<Participant>, Error> {
    Participant::builder("reserve_range")
        .domain_id(hdds::test_support::domains::unique_domain().id())
        .with_transport(TransportMode::IntraProcess)
        .memory_policy(MemoryPolicy {
            reader_reserve_percent: percent,
            ..MemoryPolicy::default()
        })
        .build()
}

#[test]
fn a_readers_share_outside_its_range_is_refused_at_build() {
    for percent in [0u8, 94, 99, 100, 255] {
        match build(percent) {
            Err(Error::Config(why)) => assert!(
                why.contains("MemoryPolicy.reader_reserve_percent"),
                "{percent}: the error names the field: {why}"
            ),
            Err(other) => panic!("{percent}: refused with Error::Config, got {other:?}"),
            Ok(_) => panic!("{percent}: accepted"),
        }
    }
}

#[test]
fn a_readers_share_within_its_range_is_accepted() {
    for percent in [
        MemoryPolicy::READER_RESERVE_PERCENT_MIN,
        MemoryPolicy::default().reader_reserve_percent,
        MemoryPolicy::READER_RESERVE_PERCENT_MAX,
    ] {
        build(percent).unwrap_or_else(|e| panic!("{percent}: {e}"));
    }
}
