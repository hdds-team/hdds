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

//! NACK_FRAG under packet loss - fragment repair tests.
//!
//! Validates that the FragmentBuffer correctly handles various loss patterns
//! and that missing fragment detection works for NACK_FRAG-based repair.
//!
//! Test scenarios:
//! - Skip middle fragments, then deliver them (simulates NACK_FRAG repair)
//! - Reverse-order delivery
//! - First/last only, then fill middle
//! - Duplicate fragment handling
//! - Timeout eviction of incomplete sequences
//! - Large-scale loss and repair simulation

use hdds::core::discovery::{FragmentBuffer, GUID};
use hdds::protocol::builder::build_nack_frag_submessage;

/// Helper: create a deterministic payload of `size` bytes.
fn make_payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

/// Helper: create a test GUID from a seed byte.
fn test_guid(seed: u8) -> GUID {
    GUID::from_bytes([
        seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, 0x00, 0x00, 0x01,
        0x03,
    ])
}

/// Helper: split payload into fragments of `frag_size` bytes.
fn split_into_fragments(payload: &[u8], frag_size: usize) -> Vec<Vec<u8>> {
    payload.chunks(frag_size).map(|c| c.to_vec()).collect()
}

// ---------------------------------------------------------------------------
// Test: Skip middle fragment, detect missing, then deliver it
// ---------------------------------------------------------------------------

#[test]
fn test_loss_skip_middle_fragment() {
    let mut buffer = FragmentBuffer::new(256, 5000);
    let guid = test_guid(0x01);
    let seq_num = 1u64;

    let frag_size = 100;
    let total_frags = 5u16;
    let original = make_payload(frag_size * total_frags as usize);
    let fragments = split_into_fragments(&original, frag_size);

    // Send fragments 1, 2, 4, 5 (skip 3)
    for frag_idx in [0usize, 1, 3, 4] {
        let frag_num = (frag_idx + 1) as u32;
        let r = buffer.insert_fragment(
            guid,
            seq_num,
            frag_num,
            total_frags,
            fragments[frag_idx].clone(),
        );
        assert!(
            r.is_none(),
            "Should NOT be complete without fragment 3 (inserted frag {})",
            frag_num
        );
    }

    // Verify fragment 3 is detected as missing
    let (missing, total) = buffer
        .get_missing_fragments(&guid, seq_num)
        .expect("Should have missing fragment info");
    assert_eq!(total, total_frags);
    assert_eq!(missing, vec![3], "Only fragment 3 should be missing");

    // Simulate NACK_FRAG repair: deliver fragment 3
    let r = buffer.insert_fragment(guid, seq_num, 3, total_frags, fragments[2].clone());
    assert!(
        r.is_some(),
        "Delivering missing fragment 3 should complete reassembly"
    );

    let reassembled = r.unwrap();
    assert_eq!(
        reassembled, original,
        "Reassembled payload after repair should match original"
    );
    assert_eq!(buffer.pending_count(), 0);
}

// ---------------------------------------------------------------------------
// Test: All fragments in reverse order
// ---------------------------------------------------------------------------

#[test]
fn test_loss_reverse_order_delivery() {
    let mut buffer = FragmentBuffer::new(256, 5000);
    let guid = test_guid(0x02);
    let seq_num = 10u64;

    let frag_size = 80;
    let total_frags = 6u16;
    let original = make_payload(frag_size * total_frags as usize);
    let fragments = split_into_fragments(&original, frag_size);

    // Deliver in reverse: 6, 5, 4, 3, 2, 1
    let mut result = None;
    for frag_idx in (0..total_frags as usize).rev() {
        let frag_num = (frag_idx + 1) as u32;
        result = buffer.insert_fragment(
            guid,
            seq_num,
            frag_num,
            total_frags,
            fragments[frag_idx].clone(),
        );

        if frag_idx > 0 {
            assert!(
                result.is_none(),
                "Should not complete until all fragments delivered (at frag {})",
                frag_num
            );

            // Check missing fragments count decreases
            let (missing, _) = buffer
                .get_missing_fragments(&guid, seq_num)
                .expect("Should have pending info");
            assert_eq!(
                missing.len(),
                frag_idx,
                "After inserting frag {}, {} fragments should be missing",
                frag_num,
                frag_idx
            );
        }
    }

    assert!(result.is_some(), "All fragments delivered should complete");
    assert_eq!(result.unwrap(), original);
}

// ---------------------------------------------------------------------------
// Test: Only first and last fragments, then fill middle
// ---------------------------------------------------------------------------

#[test]
fn test_loss_first_and_last_then_middle() {
    let mut buffer = FragmentBuffer::new(256, 5000);
    let guid = test_guid(0x03);
    let seq_num = 20u64;

    let frag_size = 64;
    let total_frags = 7u16;
    let original = make_payload(frag_size * total_frags as usize);
    let fragments = split_into_fragments(&original, frag_size);

    // Phase 1: deliver only first and last
    buffer.insert_fragment(guid, seq_num, 1, total_frags, fragments[0].clone());
    buffer.insert_fragment(
        guid,
        seq_num,
        total_frags as u32,
        total_frags,
        fragments[total_frags as usize - 1].clone(),
    );

    // Verify 5 middle fragments are missing (2, 3, 4, 5, 6)
    let (missing, total) = buffer
        .get_missing_fragments(&guid, seq_num)
        .expect("Should have missing info");
    assert_eq!(total, total_frags);
    assert_eq!(missing, vec![2, 3, 4, 5, 6]);

    // Phase 2: fill middle fragments one by one
    let mut result = None;
    for (frag_idx, frag) in fragments
        .iter()
        .enumerate()
        .skip(1)
        .take(total_frags as usize - 2)
    {
        let frag_num = (frag_idx + 1) as u32;
        result = buffer.insert_fragment(guid, seq_num, frag_num, total_frags, frag.clone());
    }

    assert!(
        result.is_some(),
        "Filling all middle fragments should complete reassembly"
    );
    assert_eq!(result.unwrap(), original);
}

// ---------------------------------------------------------------------------
// Test: Duplicate fragments (same fragment submitted twice)
// ---------------------------------------------------------------------------

#[test]
fn test_loss_duplicate_fragments() {
    let mut buffer = FragmentBuffer::new(256, 5000);
    let guid = test_guid(0x04);
    let seq_num = 30u64;
    let total_frags = 3u16;

    let frag1 = vec![0x11, 0x22];
    let frag2 = vec![0x33, 0x44];
    let frag3 = vec![0x55, 0x66];

    // Insert frag 1
    let r = buffer.insert_fragment(guid, seq_num, 1, total_frags, frag1.clone());
    assert!(r.is_none());

    // Duplicate frag 1 (should overwrite silently)
    let r = buffer.insert_fragment(guid, seq_num, 1, total_frags, frag1.clone());
    assert!(r.is_none(), "Duplicate should not complete");

    // Triple-insert frag 1
    let r = buffer.insert_fragment(guid, seq_num, 1, total_frags, frag1);
    assert!(r.is_none(), "Triple duplicate should not complete");

    // Verify still missing 2 and 3
    let (missing, _) = buffer
        .get_missing_fragments(&guid, seq_num)
        .expect("Should have info");
    assert_eq!(missing, vec![2, 3]);

    // Complete normally
    buffer.insert_fragment(guid, seq_num, 2, total_frags, frag2);
    let r = buffer.insert_fragment(guid, seq_num, 3, total_frags, frag3);
    assert!(r.is_some(), "Final fragment should complete");
    assert_eq!(r.unwrap(), vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
}

// ---------------------------------------------------------------------------
// Test: Timeout eviction of incomplete sequences
// ---------------------------------------------------------------------------

#[test]
fn test_loss_timeout_eviction() {
    // Very short timeout (50ms)
    let mut buffer = FragmentBuffer::new(256, 50);
    let guid = test_guid(0x05);

    // Insert partial fragments for two sequences
    buffer.insert_fragment(guid, 1, 1, 4, vec![0xAA]);
    buffer.insert_fragment(guid, 2, 1, 3, vec![0xBB]);
    assert_eq!(buffer.pending_count(), 2);

    // Wait for timeout
    std::thread::sleep(std::time::Duration::from_millis(80));

    // Evict expired
    let evicted = buffer.evict_expired();
    assert_eq!(evicted, 2, "Both sequences should be evicted");
    assert_eq!(buffer.pending_count(), 0);

    // Missing fragments query should return None now
    assert!(buffer.get_missing_fragments(&guid, 1).is_none());
    assert!(buffer.get_missing_fragments(&guid, 2).is_none());
}

// ---------------------------------------------------------------------------
// Test: Interleaved loss across multiple sequences
// ---------------------------------------------------------------------------

#[test]
fn test_loss_interleaved_multiple_sequences() {
    let mut buffer = FragmentBuffer::new(256, 5000);
    let guid = test_guid(0x06);

    let frag_size = 50;
    let total_frags = 4u16;

    // Create 3 different messages
    let msg1 = make_payload(frag_size * total_frags as usize);
    let msg2 = make_payload(frag_size * total_frags as usize + 1); // Slightly different
    let msg3 = make_payload(frag_size * total_frags as usize + 2);

    let frags1 = split_into_fragments(&msg1, frag_size);
    let frags2 = split_into_fragments(&msg2, frag_size);
    let frags3 = split_into_fragments(&msg3, frag_size);

    let total_frags2 = frags2.len() as u16;
    let total_frags3 = frags3.len() as u16;

    // Interleave: seq1/frag1, seq2/frag1, seq3/frag1, seq1/frag3, seq2/frag2, ...
    // Phase 1: partial delivery with losses
    buffer.insert_fragment(guid, 1, 1, total_frags, frags1[0].clone());
    buffer.insert_fragment(guid, 2, 1, total_frags2, frags2[0].clone());
    buffer.insert_fragment(guid, 3, 1, total_frags3, frags3[0].clone());
    // Skip frag 2 for all, deliver frag 3
    buffer.insert_fragment(guid, 1, 3, total_frags, frags1[2].clone());
    buffer.insert_fragment(guid, 2, 3, total_frags2, frags2[2].clone());

    assert_eq!(
        buffer.pending_count(),
        3,
        "All 3 sequences should be pending"
    );

    // Check missing for seq 1: frags 2, 4
    let (missing1, _) = buffer.get_missing_fragments(&guid, 1).unwrap();
    assert_eq!(missing1, vec![2, 4]);

    // Phase 2: repair seq 1 completely
    buffer.insert_fragment(guid, 1, 2, total_frags, frags1[1].clone());
    let r = buffer.insert_fragment(guid, 1, 4, total_frags, frags1[3].clone());
    assert!(r.is_some(), "Seq 1 should complete after repair");
    assert_eq!(r.unwrap(), msg1);

    assert_eq!(
        buffer.pending_count(),
        2,
        "Only seq 2 and 3 should remain pending"
    );
}

// ---------------------------------------------------------------------------
// Test: Full NACK_FRAG-driven repair cycle
// ---------------------------------------------------------------------------

#[test]
fn test_loss_nack_frag_driven_repair_cycle() {
    let mut buffer = FragmentBuffer::new(256, 5000);
    let guid = test_guid(0x07);
    let seq_num = 100u64;

    let frag_size = 128;
    let total_frags = 10u16;
    let original = make_payload(frag_size * total_frags as usize);
    let fragments = split_into_fragments(&original, frag_size);

    // Phase 1: Initial delivery with 40% loss (skip frags 2, 4, 7, 9)
    let delivered_first = [0usize, 2, 4, 5, 7, 9]; // frags 1, 3, 5, 6, 8, 10
    for &frag_idx in &delivered_first {
        let frag_num = (frag_idx + 1) as u32;
        let r = buffer.insert_fragment(
            guid,
            seq_num,
            frag_num,
            total_frags,
            fragments[frag_idx].clone(),
        );
        assert!(r.is_none());
    }

    // Phase 2: Detect missing and generate NACK_FRAG
    let (missing, total) = buffer
        .get_missing_fragments(&guid, seq_num)
        .expect("Should have missing info");
    assert_eq!(total, total_frags);
    assert_eq!(
        missing,
        vec![2, 4, 7, 9],
        "Should detect 4 missing fragments"
    );

    // Build NACK_FRAG submessage for the missing fragments
    let reader_id = [0x00, 0x00, 0x00, 0x04];
    let writer_id = [0x00, 0x00, 0x00, 0x02];
    let nack_submsg = build_nack_frag_submessage(reader_id, writer_id, seq_num, &missing, 1);

    // Verify NACK_FRAG is valid
    assert_eq!(nack_submsg[0], 0x12, "Should be NACK_FRAG");
    let bitmap_base = u32::from_le_bytes(nack_submsg[20..24].try_into().unwrap());
    assert_eq!(bitmap_base, 2, "bitmapBase = first missing = 2");

    // Phase 3: Retransmit missing fragments (simulate NACK_FRAG response)
    let mut result = None;
    for &frag_num in &missing {
        let frag_idx = (frag_num - 1) as usize;
        result = buffer.insert_fragment(
            guid,
            seq_num,
            frag_num,
            total_frags,
            fragments[frag_idx].clone(),
        );
    }

    assert!(
        result.is_some(),
        "Retransmitting all missing fragments should complete reassembly"
    );
    let reassembled = result.unwrap();
    assert_eq!(
        reassembled, original,
        "Repaired payload should match original"
    );
    assert_eq!(buffer.pending_count(), 0);
}

// ---------------------------------------------------------------------------
// Test: Alternating fragment delivery pattern
// ---------------------------------------------------------------------------

#[test]
fn test_loss_alternating_delivery() {
    let mut buffer = FragmentBuffer::new(256, 5000);
    let guid = test_guid(0x08);
    let seq_num = 50u64;

    let frag_size = 32;
    let total_frags = 8u16;
    let original = make_payload(frag_size * total_frags as usize);
    let fragments = split_into_fragments(&original, frag_size);

    // Phase 1: Deliver odd-numbered fragments (1, 3, 5, 7)
    for frag_idx in (0..total_frags as usize).step_by(2) {
        let frag_num = (frag_idx + 1) as u32;
        buffer.insert_fragment(
            guid,
            seq_num,
            frag_num,
            total_frags,
            fragments[frag_idx].clone(),
        );
    }

    // Verify even-numbered fragments are missing
    let (missing, _) = buffer.get_missing_fragments(&guid, seq_num).unwrap();
    assert_eq!(missing, vec![2, 4, 6, 8]);

    // Phase 2: Deliver even-numbered fragments (2, 4, 6, 8)
    let mut result = None;
    for frag_idx in (1..total_frags as usize).step_by(2) {
        let frag_num = (frag_idx + 1) as u32;
        result = buffer.insert_fragment(
            guid,
            seq_num,
            frag_num,
            total_frags,
            fragments[frag_idx].clone(),
        );
    }

    assert!(result.is_some(), "All fragments delivered should complete");
    assert_eq!(result.unwrap(), original);
}

// ---------------------------------------------------------------------------
// Test: Large-scale loss simulation (100 fragments, 30% loss, repair)
// ---------------------------------------------------------------------------

#[test]
#[ignore] // Slow: exercises large-scale fragmentation with loss simulation
fn test_loss_large_scale_repair() {
    let mut buffer = FragmentBuffer::new(256, 30000);
    let guid = test_guid(0x09);
    let seq_num = 1u64;

    let frag_size = 256;
    let total_frags = 100u16;
    let original = make_payload(frag_size * total_frags as usize);
    let fragments = split_into_fragments(&original, frag_size);

    // Phase 1: Deliver 70% of fragments (skip every 3rd + some random)
    let mut delivered = Vec::new();
    let mut lost = Vec::new();

    for (frag_idx, frag) in fragments.iter().enumerate() {
        if frag_idx % 3 == 1 {
            // Simulate loss: skip fragments at index 1, 4, 7, 10, ...
            lost.push(frag_idx);
        } else {
            delivered.push(frag_idx);
            let frag_num = (frag_idx + 1) as u32;
            let r = buffer.insert_fragment(guid, seq_num, frag_num, total_frags, frag.clone());
            assert!(
                r.is_none(),
                "Should not complete with {} fragments lost",
                lost.len()
            );
        }
    }

    eprintln!(
        "Phase 1: Delivered {}, lost {} fragments",
        delivered.len(),
        lost.len()
    );

    // Phase 2: Detect missing
    let (missing, total) = buffer
        .get_missing_fragments(&guid, seq_num)
        .expect("Should have missing info");
    assert_eq!(total, total_frags);
    assert_eq!(
        missing.len(),
        lost.len(),
        "Missing count should equal lost count"
    );

    // Verify the missing fragment numbers match
    let expected_missing: Vec<u32> = lost.iter().map(|&idx| (idx + 1) as u32).collect();
    assert_eq!(missing, expected_missing);

    // Phase 3: Repair all lost fragments
    let mut result = None;
    for &frag_idx in &lost {
        let frag_num = (frag_idx + 1) as u32;
        result = buffer.insert_fragment(
            guid,
            seq_num,
            frag_num,
            total_frags,
            fragments[frag_idx].clone(),
        );
    }

    assert!(
        result.is_some(),
        "Repairing all lost fragments should complete"
    );
    let reassembled = result.unwrap();
    assert_eq!(reassembled.len(), original.len());
    assert_eq!(
        reassembled, original,
        "Large-scale repair should produce correct payload"
    );
}

// ---------------------------------------------------------------------------
// Test: LRU eviction under pressure
// ---------------------------------------------------------------------------

#[test]
fn test_loss_lru_eviction_under_pressure() {
    // Buffer that holds only 3 pending sequences
    let mut buffer = FragmentBuffer::new(3, 5000);
    let guid = test_guid(0x0A);
    let total_frags = 4u16;

    // Fill buffer with 3 incomplete sequences
    for seq_num in 1..=3 {
        buffer.insert_fragment(guid, seq_num, 1, total_frags, vec![seq_num as u8]);
    }
    assert_eq!(buffer.pending_count(), 3);

    // Insert 4th sequence -> should evict oldest (seq 1)
    buffer.insert_fragment(guid, 4, 1, total_frags, vec![0x04]);

    // seq 1 should be evicted
    assert_eq!(buffer.pending_count(), 3, "Should still have 3 pending");
    assert!(
        buffer.get_missing_fragments(&guid, 1).is_none(),
        "Seq 1 should have been evicted (LRU)"
    );
    assert!(
        buffer.get_missing_fragments(&guid, 2).is_some(),
        "Seq 2 should still be pending"
    );
    assert!(
        buffer.get_missing_fragments(&guid, 3).is_some(),
        "Seq 3 should still be pending"
    );
    assert!(
        buffer.get_missing_fragments(&guid, 4).is_some(),
        "Seq 4 should be pending"
    );
}

// ---------------------------------------------------------------------------
// Test: Rapid sequence of complete/incomplete interleaving
// ---------------------------------------------------------------------------

#[test]
fn test_loss_rapid_complete_incomplete_interleaving() {
    let mut buffer = FragmentBuffer::new(256, 5000);
    let guid = test_guid(0x0B);
    let total_frags = 2u16;

    // Rapidly complete and leave incomplete sequences
    for seq_num in 1u64..=20 {
        buffer.insert_fragment(guid, seq_num, 1, total_frags, vec![seq_num as u8]);

        if seq_num % 2 == 0 {
            // Complete even sequences
            let r =
                buffer.insert_fragment(guid, seq_num, 2, total_frags, vec![(seq_num + 100) as u8]);
            assert!(r.is_some(), "Even seq {} should complete", seq_num);
        }
    }

    // Only odd sequences should remain pending (1, 3, 5, 7, 9, 11, 13, 15, 17, 19)
    assert_eq!(
        buffer.pending_count(),
        10,
        "10 odd-numbered sequences should remain pending"
    );
}

// ---------------------------------------------------------------------------
// Test: Fragment 0 does not exist (fragments are 1-based)
// ---------------------------------------------------------------------------

#[test]
fn test_loss_fragment_numbering_one_based() {
    let mut buffer = FragmentBuffer::new(256, 5000);
    let guid = test_guid(0x0C);
    let seq_num = 1u64;
    let total_frags = 3u16;

    // Insert fragments numbered 1, 2, 3 (correct 1-based numbering)
    buffer.insert_fragment(guid, seq_num, 1, total_frags, vec![0x11]);
    buffer.insert_fragment(guid, seq_num, 2, total_frags, vec![0x22]);
    let r = buffer.insert_fragment(guid, seq_num, 3, total_frags, vec![0x33]);

    assert!(r.is_some(), "1-based fragment numbering should work");
    let reassembled = r.unwrap();
    assert_eq!(reassembled, vec![0x11, 0x22, 0x33]);
}

// ---------------------------------------------------------------------------
// Test: Different writers (GUIDs) with same sequence number
// ---------------------------------------------------------------------------

#[test]
fn test_loss_different_writers_same_seq() {
    let mut buffer = FragmentBuffer::new(256, 5000);
    let guid_a = test_guid(0xA0);
    let guid_b = test_guid(0xB0);
    let seq_num = 1u64; // Same seq_num
    let total_frags = 2u16;

    // Writer A: insert frag 1
    buffer.insert_fragment(guid_a, seq_num, 1, total_frags, vec![0xAA]);
    // Writer B: insert frag 1
    buffer.insert_fragment(guid_b, seq_num, 1, total_frags, vec![0xBB]);

    // Both should be pending independently
    assert_eq!(buffer.pending_count(), 2);

    // Complete writer A
    let r = buffer.insert_fragment(guid_a, seq_num, 2, total_frags, vec![0xCC]);
    assert!(r.is_some());
    assert_eq!(r.unwrap(), vec![0xAA, 0xCC]);

    // Writer B should still be pending
    assert_eq!(buffer.pending_count(), 1);
    let (missing, _) = buffer.get_missing_fragments(&guid_b, seq_num).unwrap();
    assert_eq!(missing, vec![2]);

    // Complete writer B
    let r = buffer.insert_fragment(guid_b, seq_num, 2, total_frags, vec![0xDD]);
    assert!(r.is_some());
    assert_eq!(r.unwrap(), vec![0xBB, 0xDD]);
    assert_eq!(buffer.pending_count(), 0);
}
