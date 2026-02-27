// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![allow(clippy::uninlined_format_args)] // Test/bench code readability over pedantic
#![allow(clippy::cast_precision_loss)] // Stats/metrics need this
#![allow(clippy::cast_sign_loss)] // Test data conversions
#![allow(clippy::cast_possible_truncation)] // Test parameters
#![allow(clippy::float_cmp)] // Test assertions with constants
#![allow(clippy::unreadable_literal)] // Large test constants
#![allow(clippy::doc_markdown)] // Test documentation
#![allow(clippy::missing_panics_doc)] // Tests/examples panic on failure
#![allow(clippy::missing_errors_doc)] // Test documentation
#![allow(clippy::items_after_statements)] // Test helpers
#![allow(clippy::module_name_repetitions)] // Test modules
#![allow(clippy::too_many_lines)] // Example/test code
#![allow(clippy::match_same_arms)] // Test pattern matching
#![allow(clippy::no_effect_underscore_binding)] // Test variables
#![allow(clippy::wildcard_imports)] // Test utility imports
#![allow(clippy::redundant_closure_for_method_calls)] // Test code clarity
#![allow(clippy::similar_names)] // Test variable naming
#![allow(clippy::shadow_unrelated)] // Test scoping
#![allow(clippy::needless_pass_by_value)] // Test functions
#![allow(clippy::cast_possible_wrap)] // Test conversions
#![allow(clippy::single_match_else)] // Test clarity
#![allow(clippy::needless_continue)] // Test logic
#![allow(clippy::cast_lossless)] // Test simplicity
#![allow(clippy::match_wild_err_arm)] // Test error handling
#![allow(clippy::explicit_iter_loop)] // Test iteration
#![allow(clippy::must_use_candidate)] // Test functions
#![allow(clippy::if_not_else)] // Test conditionals
#![allow(clippy::map_unwrap_or)] // Test options
#![allow(clippy::match_wildcard_for_single_variants)] // Test patterns
#![allow(clippy::ignored_unit_patterns)] // Test closures

//! DATA_FRAG integration tests.
//!
//! Validates that large payloads are automatically fragmented via DATA_FRAG
//! submessages and correctly reassembled by the FragmentBuffer.
//!
//! These tests exercise the protocol-level fragmentation path:
//! - `build_data_frag_packets` for packet construction
//! - `FragmentBuffer` for fragment reassembly
//! - Round-trip validation (fragment -> reassemble -> verify)

use hdds::core::discovery::{FragmentBuffer, GUID};
use hdds::protocol::builder::{
    build_data_frag_packets, should_fragment, RtpsEndpointContext, DEFAULT_FRAGMENT_SIZE,
    DEFAULT_MAX_UNFRAGMENTED_SIZE,
};

/// Helper: create a deterministic payload of `size` bytes.
///
/// Each byte is `(index % 251)` to create a non-trivial repeating pattern
/// that is easy to verify after reassembly.
fn make_payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

/// Helper: create a test GUID from a simple seed.
fn test_guid(seed: u8) -> GUID {
    GUID::from_bytes([
        seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, 0x00, 0x00, 0x01,
        0x03,
    ])
}

/// Helper: create a standard RTPS endpoint context for testing.
fn test_ctx() -> RtpsEndpointContext {
    RtpsEndpointContext {
        guid_prefix: [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ],
        reader_entity_id: [0x00, 0x00, 0x00, 0x04],
        writer_entity_id: [0x00, 0x00, 0x00, 0x02],
    }
}

// ---------------------------------------------------------------------------
// Test: should_fragment threshold
// ---------------------------------------------------------------------------

#[test]
fn test_should_fragment_threshold() {
    // Payloads at or below DEFAULT_MAX_UNFRAGMENTED_SIZE should NOT be fragmented
    assert!(
        !should_fragment(DEFAULT_MAX_UNFRAGMENTED_SIZE),
        "Payload exactly at threshold should NOT trigger fragmentation"
    );
    assert!(
        !should_fragment(100),
        "Small payload should NOT trigger fragmentation"
    );
    assert!(
        !should_fragment(0),
        "Empty payload should NOT trigger fragmentation"
    );

    // Payloads above the threshold SHOULD be fragmented
    assert!(
        should_fragment(DEFAULT_MAX_UNFRAGMENTED_SIZE + 1),
        "Payload 1 byte over threshold should trigger fragmentation"
    );
    assert!(
        should_fragment(64 * 1024),
        "64KB payload should trigger fragmentation"
    );
}

// ---------------------------------------------------------------------------
// Test: build_data_frag_packets produces correct fragment count
// ---------------------------------------------------------------------------

#[test]
fn test_data_frag_packet_count() {
    let ctx = test_ctx();
    let payload_size = 10 * 1024; // 10KB
    let payload = make_payload(payload_size);

    let packets = build_data_frag_packets(&ctx, 1, &payload, DEFAULT_FRAGMENT_SIZE);

    // 10240 / 1024 = 10 fragments
    let expected_frags = payload_size.div_ceil(DEFAULT_FRAGMENT_SIZE);
    assert_eq!(
        packets.len(),
        expected_frags,
        "Expected {} DATA_FRAG packets for {} bytes with fragment_size={}",
        expected_frags,
        payload_size,
        DEFAULT_FRAGMENT_SIZE
    );

    // Each packet must start with RTPS magic
    for (i, pkt) in packets.iter().enumerate() {
        assert!(
            pkt.len() > 20,
            "Packet {} is too short ({} bytes)",
            i,
            pkt.len()
        );
        assert_eq!(
            &pkt[0..4],
            b"RTPS",
            "Packet {} does not start with RTPS magic",
            i
        );
    }
}

// ---------------------------------------------------------------------------
// Test: small payload produces no DATA_FRAG packets
// ---------------------------------------------------------------------------

#[test]
fn test_data_frag_small_payload_no_fragmentation() {
    let ctx = test_ctx();
    let small_payload = make_payload(1024); // 1KB - well under threshold

    let packets = build_data_frag_packets(&ctx, 1, &small_payload, DEFAULT_FRAGMENT_SIZE);
    assert!(
        packets.is_empty(),
        "Small payload ({} bytes) should not produce DATA_FRAG packets",
        small_payload.len()
    );
}

// ---------------------------------------------------------------------------
// Test: FragmentBuffer reassembly with in-order fragments
// ---------------------------------------------------------------------------

#[test]
fn test_fragment_buffer_reassembly_in_order() {
    let mut buffer = FragmentBuffer::new(256, 5000);
    let guid = test_guid(0xAA);
    let seq_num = 42u64;

    // Simulate a 5-fragment message
    let frag_size = 100;
    let total_frags = 5u16;
    let original = make_payload(frag_size * total_frags as usize);

    for frag_idx in 0..total_frags {
        let start = frag_idx as usize * frag_size;
        let end = start + frag_size;
        let frag_data = original[start..end].to_vec();
        let frag_num = frag_idx as u32 + 1; // 1-based

        let result = buffer.insert_fragment(guid, seq_num, frag_num, total_frags, frag_data);

        if frag_idx < total_frags - 1 {
            assert!(
                result.is_none(),
                "Fragment {}/{} should not complete reassembly",
                frag_num,
                total_frags
            );
        } else {
            assert!(
                result.is_some(),
                "Final fragment {}/{} should complete reassembly",
                frag_num,
                total_frags
            );
            let reassembled = result.unwrap();
            assert_eq!(
                reassembled, original,
                "Reassembled payload does not match original"
            );
        }
    }

    // Buffer should have no pending sequences after completion
    assert_eq!(
        buffer.pending_count(),
        0,
        "Buffer should have 0 pending sequences after successful reassembly"
    );
}

// ---------------------------------------------------------------------------
// Test: FragmentBuffer reassembly with out-of-order fragments
// ---------------------------------------------------------------------------

#[test]
fn test_fragment_buffer_reassembly_out_of_order() {
    let mut buffer = FragmentBuffer::new(256, 5000);
    let guid = test_guid(0xBB);
    let seq_num = 7u64;

    let frag_size = 200;
    let total_frags = 4u16;
    let original = make_payload(frag_size * total_frags as usize);

    // Insert in reverse order: 4, 3, 2, 1
    for frag_idx in (0..total_frags).rev() {
        let start = frag_idx as usize * frag_size;
        let end = start + frag_size;
        let frag_data = original[start..end].to_vec();
        let frag_num = frag_idx as u32 + 1;

        let result = buffer.insert_fragment(guid, seq_num, frag_num, total_frags, frag_data);

        if frag_idx > 0 {
            assert!(
                result.is_none(),
                "Fragment {} inserted out-of-order should not complete yet",
                frag_num
            );
        } else {
            // frag_idx == 0 means frag_num == 1, the last one inserted
            assert!(
                result.is_some(),
                "Last fragment inserted should complete reassembly"
            );
            let reassembled = result.unwrap();
            assert_eq!(
                reassembled, original,
                "Out-of-order reassembly does not match original"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Test: large payload (64KB) round-trip through FragmentBuffer
// ---------------------------------------------------------------------------

#[test]
#[ignore] // Slow: exercises large payload fragmentation and reassembly
fn test_data_frag_64kb_roundtrip() {
    let mut buffer = FragmentBuffer::new(256, 10000);
    let guid = test_guid(0xCC);
    let seq_num = 1u64;

    let payload_size = 64 * 1024; // 64KB
    let frag_size = DEFAULT_FRAGMENT_SIZE;
    let original = make_payload(payload_size);
    let total_frags = payload_size.div_ceil(frag_size);

    let mut result = None;
    for frag_idx in 0..total_frags {
        let start = frag_idx * frag_size;
        let end = (start + frag_size).min(payload_size);
        let frag_data = original[start..end].to_vec();
        let frag_num = (frag_idx + 1) as u32;

        result = buffer.insert_fragment(guid, seq_num, frag_num, total_frags as u16, frag_data);
    }

    assert!(
        result.is_some(),
        "64KB payload should be fully reassembled after all {} fragments",
        total_frags
    );
    let reassembled = result.unwrap();
    assert_eq!(
        reassembled.len(),
        original.len(),
        "Reassembled length mismatch"
    );
    assert_eq!(reassembled, original, "Reassembled payload data mismatch");
}

// ---------------------------------------------------------------------------
// Test: multiple concurrent sequences in FragmentBuffer
// ---------------------------------------------------------------------------

#[test]
fn test_fragment_buffer_multiple_sequences() {
    let mut buffer = FragmentBuffer::new(256, 5000);
    let guid = test_guid(0xDD);

    let frag_size = 50;
    let total_frags = 3u16;

    // Create 3 different sequences interleaved
    let payloads: Vec<Vec<u8>> = (0..3)
        .map(|i| make_payload(frag_size * total_frags as usize + i * 7))
        .collect();

    // Insert frag #1 for all sequences
    for (seq_idx, payload) in payloads.iter().enumerate() {
        let seq_num = (seq_idx + 1) as u64;
        let frag_data = payload[0..frag_size].to_vec();
        let total = payload.len().div_ceil(frag_size) as u16;
        let r = buffer.insert_fragment(guid, seq_num, 1, total, frag_data);
        assert!(
            r.is_none(),
            "First fragment of seq {} should not complete",
            seq_num
        );
    }

    assert_eq!(buffer.pending_count(), 3, "Should have 3 pending sequences");

    // Complete sequence #2 first
    let payload2 = &payloads[1];
    let total2 = payload2.len().div_ceil(frag_size) as u16;
    for frag_idx in 1..total2 as usize {
        let start = frag_idx * frag_size;
        let end = (start + frag_size).min(payload2.len());
        let frag_data = payload2[start..end].to_vec();
        let frag_num = (frag_idx + 1) as u32;
        let r = buffer.insert_fragment(guid, 2, frag_num, total2, frag_data);
        if frag_idx == (total2 as usize - 1) {
            assert!(r.is_some(), "Final fragment of seq 2 should complete");
            let reassembled = r.unwrap();
            assert_eq!(reassembled, *payload2, "Seq 2 reassembly mismatch");
        }
    }

    // Sequences 1 and 3 should still be pending
    assert_eq!(
        buffer.pending_count(),
        2,
        "After completing seq 2, 2 sequences should remain pending"
    );
}

// ---------------------------------------------------------------------------
// Test: build_data_frag_packets with custom fragment_size
// ---------------------------------------------------------------------------

#[test]
fn test_data_frag_custom_fragment_size() {
    let ctx = test_ctx();
    let payload_size = 16 * 1024; // 16KB
    let payload = make_payload(payload_size);
    let custom_frag_size = 512; // 512 bytes per fragment

    let packets = build_data_frag_packets(&ctx, 1, &payload, custom_frag_size);

    let expected_frags = payload_size.div_ceil(custom_frag_size);
    assert_eq!(
        packets.len(),
        expected_frags,
        "Expected {} fragments with custom fragment_size={}",
        expected_frags,
        custom_frag_size
    );
}

// ---------------------------------------------------------------------------
// Test: payload exactly at fragmentation boundary
// ---------------------------------------------------------------------------

#[test]
fn test_data_frag_exact_boundary() {
    let ctx = test_ctx();

    // Payload exactly at the unfragmented threshold: no fragmentation
    let payload_at_threshold = make_payload(DEFAULT_MAX_UNFRAGMENTED_SIZE);
    let packets = build_data_frag_packets(&ctx, 1, &payload_at_threshold, DEFAULT_FRAGMENT_SIZE);
    assert!(
        packets.is_empty(),
        "Payload at exact threshold should NOT produce DATA_FRAG packets"
    );

    // Payload 1 byte over threshold: must fragment
    let payload_over_threshold = make_payload(DEFAULT_MAX_UNFRAGMENTED_SIZE + 1);
    let packets = build_data_frag_packets(&ctx, 1, &payload_over_threshold, DEFAULT_FRAGMENT_SIZE);
    assert!(
        !packets.is_empty(),
        "Payload 1 byte over threshold MUST produce DATA_FRAG packets"
    );

    let expected_frags = (DEFAULT_MAX_UNFRAGMENTED_SIZE + 1).div_ceil(DEFAULT_FRAGMENT_SIZE);
    assert_eq!(packets.len(), expected_frags);
}

// ---------------------------------------------------------------------------
// Test: RTPS header in DATA_FRAG packets carries correct GUID prefix
// ---------------------------------------------------------------------------

#[test]
fn test_data_frag_guid_prefix_in_header() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ],
        reader_entity_id: [0x00, 0x00, 0x00, 0x04],
        writer_entity_id: [0x00, 0x00, 0x00, 0x02],
    };

    let payload = make_payload(DEFAULT_MAX_UNFRAGMENTED_SIZE + 1);
    let packets = build_data_frag_packets(&ctx, 1, &payload, DEFAULT_FRAGMENT_SIZE);

    for (i, pkt) in packets.iter().enumerate() {
        // RTPS header: magic(4) + version(2) + vendor(2) + guid_prefix(12)
        assert_eq!(
            &pkt[8..20],
            &ctx.guid_prefix,
            "Packet {} GUID prefix mismatch in RTPS header",
            i
        );
    }
}

// ---------------------------------------------------------------------------
// Test: FragmentBuffer handles duplicate fragments gracefully
// ---------------------------------------------------------------------------

#[test]
fn test_fragment_buffer_duplicate_fragments() {
    let mut buffer = FragmentBuffer::new(256, 5000);
    let guid = test_guid(0xEE);
    let seq_num = 10u64;
    let total_frags = 3u16;

    let frag1 = vec![0xAA, 0xBB];
    let frag2 = vec![0xCC, 0xDD];
    let frag3 = vec![0xEE, 0xFF];

    // Insert fragment 1
    let r = buffer.insert_fragment(guid, seq_num, 1, total_frags, frag1.clone());
    assert!(r.is_none());

    // Insert duplicate fragment 1 (should overwrite, not cause issues)
    let r = buffer.insert_fragment(guid, seq_num, 1, total_frags, frag1);
    assert!(
        r.is_none(),
        "Duplicate fragment should not complete reassembly"
    );

    // Insert remaining fragments
    let r = buffer.insert_fragment(guid, seq_num, 2, total_frags, frag2);
    assert!(r.is_none());

    let r = buffer.insert_fragment(guid, seq_num, 3, total_frags, frag3);
    assert!(r.is_some(), "Final fragment should complete reassembly");

    let reassembled = r.unwrap();
    assert_eq!(reassembled, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
}

// ---------------------------------------------------------------------------
// Test: single-fragment message (total_frags = 1)
// ---------------------------------------------------------------------------

#[test]
fn test_fragment_buffer_single_fragment() {
    let mut buffer = FragmentBuffer::new(256, 5000);
    let guid = test_guid(0xFF);
    let seq_num = 99u64;

    let payload = vec![0x01, 0x02, 0x03, 0x04, 0x05];

    // A message with total_frags=1 should complete immediately on first insert
    let result = buffer.insert_fragment(guid, seq_num, 1, 1, payload.clone());
    assert!(
        result.is_some(),
        "Single-fragment message should complete immediately"
    );
    assert_eq!(result.unwrap(), payload);
    assert_eq!(buffer.pending_count(), 0);
}
