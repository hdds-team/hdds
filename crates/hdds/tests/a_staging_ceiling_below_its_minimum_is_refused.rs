// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! `MemoryPolicy::max_staging_bytes` below its minimum is refused when the
//! participant is built, before the process-wide pool is built from it: a
//! ceiling that cannot hold a few large samples rejects coherent sets for
//! nothing else.

use hdds::qos::MemoryPolicy;
use hdds::{Error, Participant, TransportMode};

fn build(bytes: usize) -> Result<std::sync::Arc<Participant>, Error> {
    Participant::builder("staging_ceiling_range")
        .domain_id(hdds::test_support::domains::unique_domain().id())
        .with_transport(TransportMode::IntraProcess)
        .memory_policy(MemoryPolicy {
            max_staging_bytes: bytes,
            ..MemoryPolicy::default()
        })
        .build()
}

#[test]
fn a_staging_ceiling_below_its_minimum_is_refused_at_build() {
    for bytes in [0, 1, MemoryPolicy::MAX_STAGING_BYTES_MIN - 1] {
        match build(bytes) {
            Err(Error::Config(why)) => assert!(
                why.contains("MemoryPolicy.max_staging_bytes"),
                "{bytes}: the error names the field: {why}"
            ),
            Err(other) => panic!("{bytes}: refused with Error::Config, got {other:?}"),
            Ok(_) => panic!("{bytes}: accepted"),
        }
    }
}

#[test]
fn a_staging_ceiling_from_its_minimum_is_accepted() {
    assert_eq!(
        MemoryPolicy::default().max_staging_bytes,
        MemoryPolicy::MAX_STAGING_BYTES_DEFAULT
    );
    for bytes in [
        MemoryPolicy::MAX_STAGING_BYTES_MIN,
        MemoryPolicy::MAX_STAGING_BYTES_DEFAULT,
        usize::MAX,
    ] {
        build(bytes).unwrap_or_else(|e| panic!("{bytes}: {e}"));
    }
}
