// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Intra-process slab-tier roundtrip coverage.
//!
//! The intra-process write fast path has three allocation shapes
//! (`write_intra_process_fast` in `dds/writer/runtime.rs`):
//!
//! 1. **Direct**: payload encodes into the reserved primary 64 KB-class
//!    slot (single copy).
//! 2. **Staged**: payload outgrows the reserved slot (`BufferTooSmall`),
//!    is encoded into the writer scratch, and lands in a larger primary
//!    class via `reserve_and_write` (100 KB -> 128 KB class).
//! 3. **Heap fallback**: payload exceeds every primary class ceiling
//!    (128 KB) and, with no Large pool configured in the default
//!    `MemoryPolicy`, lands in the heap tier (200 KB), which the reader
//!    pump copies out from behind the pool mutex (`get_buffer` owned
//!    path, not `try_borrow`).
//!
//! Each shape must deliver byte-identical payloads through the merger
//! ring. This pins the tier routing + packed `SlabHandle` decode end to
//! end (regression guard for the slab-tier and handle-packing waves).

use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS};

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct TierBlob {
    id: u32,
    data: Vec<u8>,
}

/// Deterministic, seed-shifted byte pattern so cross-tier mixups
/// (stale slot reuse, wrong handle decode) cannot pass by accident.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let low = u8::try_from(i & 0xFF).unwrap_or(0);
            low.wrapping_mul(31).wrapping_add(seed)
        })
        .collect()
}

#[test]
fn test_intra_roundtrip_all_slab_tiers() {
    // Despite the name this participant uses the DEFAULT transport
    // (UdpMulticast), so it binds real RTPS ports; the domain is leased so
    // they are not domain 0's. Declared first so it drops last.
    let domain = unique_domain();
    let participant = Participant::builder("intra_tier_roundtrip")
        .domain_id(domain.id())
        .build()
        .expect("participant");
    let topic = participant
        .topic::<TierBlob>("TierRoundtripTopic")
        .expect("topic");

    let writer = topic
        .writer()
        .qos(QoS::best_effort().keep_last(4))
        .build()
        .expect("writer");
    let reader = topic
        .reader()
        .qos(QoS::best_effort().keep_last(4))
        .build()
        .expect("reader");
    reader.bind_to_writer(writer.merger());

    // (payload_len, seed, expected tier shape) -- see module docs.
    let cases: [(usize, u8, &str); 3] = [
        (64, 1, "direct 64KB-slot encode (primary)"),
        (100_000, 2, "staged encode -> primary 128KB class"),
        (200_000, 3, "staged encode -> heap fallback tier"),
    ];

    for (idx, (len, seed, shape)) in cases.iter().enumerate() {
        let sent = TierBlob {
            id: u32::try_from(idx).expect("case index fits u32"),
            data: pattern(*len, *seed),
        };
        writer.write(&sent).expect("write");

        let got = reader
            .take()
            .expect("take must not error")
            .unwrap_or_else(|| panic!("no sample delivered for {shape}"));

        assert_eq!(got.id, sent.id, "id mismatch for {shape}");
        assert_eq!(
            got.data.len(),
            sent.data.len(),
            "length mismatch for {shape}"
        );
        assert_eq!(got.data, sent.data, "payload bytes differ for {shape}");
    }
}
