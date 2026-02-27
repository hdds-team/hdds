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

//! Reliable QoS demo with packet loss simulation
//!
//! Demonstrates:
//! - Gap detection and NACK protocol
//! - Retransmission and recovery
//! - Metrics tracking
//!
//! Simulates 10,000 messages with 5% packet loss.

use hdds::core::rt::slabpool::SlabPool;
use hdds::qos::History;
use hdds::reliability::*;
use std::collections::HashSet;
use std::sync::Arc;

fn main() {
    println!("[*] Reliable QoS Demo - NACK Protocol with Loss Simulation\n");

    // Simulation parameters
    const TOTAL_MESSAGES: u64 = 10_000;
    const LOSS_RATE_PCT: u32 = 5; // 5% packet loss

    // Setup components
    let pool = Arc::new(SlabPool::new());
    let writer_cache =
        HistoryCache::new_with_limits(pool, 1000, 10_000_000, History::KeepLast(1000));
    let writer_seqgen = SeqNumGenerator::new();
    let writer_metrics = ReliableMetrics::new();

    let mut reader_tracker = GapTracker::new();
    let mut reader_scheduler = NackScheduler::with_window_ms(10);
    let reader_metrics = ReliableMetrics::new();

    let mut lost_packets = HashSet::new();

    println!("[i] Parameters:");
    println!("  - Total messages: {}", TOTAL_MESSAGES);
    println!("  - Loss rate: {}%", LOSS_RATE_PCT);
    println!("  - NACK window: 10 ms");
    println!();

    // Phase 1: Writer sends, simulate packet loss
    println!(
        "[>] Phase 1: Writer sending {} messages (with {}% loss)...",
        TOTAL_MESSAGES, LOSS_RATE_PCT
    );

    for i in 0..TOTAL_MESSAGES {
        let seq = writer_seqgen.next();
        let payload = format!("Message-{}", i);

        // Cache message for potential retransmission (ignore if cache full)
        let _ = writer_cache.insert(seq, payload.as_bytes());

        // Simulate packet loss (pseudo-random based on seq)
        let is_lost = (seq * 7919) % 100 < LOSS_RATE_PCT as u64;

        if is_lost {
            lost_packets.insert(seq);
        } else {
            // Reader receives message
            reader_scheduler.on_receive(seq);
        }
    }

    let lost_count = lost_packets.len();
    let received_count = TOTAL_MESSAGES - lost_count as u64;

    println!("  [OK] Sent: {} messages", TOTAL_MESSAGES);
    println!(
        "  [X] Lost: {} messages ({}%)",
        lost_count,
        (lost_count as f64 / TOTAL_MESSAGES as f64) * 100.0
    );
    println!("  [OK] Received: {} messages", received_count);
    println!();

    // Phase 2: Gap detection
    println!("[?] Phase 2: Gap detection...");

    let pending_gaps = reader_scheduler.pending_gaps();
    let total_missing: u64 = pending_gaps.iter().map(|r| r.end - r.start).sum();

    println!("  [i] Gaps detected: {} ranges", pending_gaps.len());
    println!("  [i] Total missing sequences: {}", total_missing);

    if pending_gaps.len() <= 10 {
        println!("  [*] Gap ranges:");
        for gap in pending_gaps {
            println!("     - [{:?})", gap);
        }
    } else {
        println!(
            "  [*] Gap ranges: {} ranges (showing first 5):",
            pending_gaps.len()
        );
        for gap in &pending_gaps[..5] {
            println!("     - [{:?})", gap);
        }
        println!("     ... ({} more ranges)", pending_gaps.len() - 5);
    }
    println!();

    // Phase 3: NACK and retransmission
    println!("[*] Phase 3: NACK protocol and retransmission...");

    let nack = NackMsg::new(pending_gaps.to_vec());
    let nack_bytes = nack.total_missing();

    println!(
        "  [*] NACK sent: {} ranges, {} sequences",
        nack.ranges.len(),
        nack_bytes
    );

    // Writer processes NACK
    let mut gap_tx = GapTx::new();
    let mut writer_handler =
        WriterRetransmitHandler::new(&writer_cache, &mut gap_tx, &writer_metrics);
    let (retransmits, gaps) = writer_handler.on_nack(&nack);

    println!("  [*] Writer retransmits: {} payloads", retransmits.len());
    println!("  [*] GAP messages: {}", gaps.len());

    // Reader receives retransmissions
    let mut reader_handler = ReaderRetransmitHandler::new(&mut reader_tracker, &reader_metrics);

    for (seq, _payload) in &retransmits {
        reader_handler.on_retransmit(*seq);
        reader_scheduler.on_data_received(*seq);
    }

    println!(
        "  [OK] Reader received: {} retransmissions",
        retransmits.len()
    );
    println!();

    // Phase 4: Verify recovery
    println!("[*] Phase 4: Verify recovery...");

    let final_gaps = reader_scheduler.pending_gaps();
    let recovery_rate = (retransmits.len() as f64 / lost_count as f64) * 100.0;

    println!("  [i] Final gaps remaining: {}", final_gaps.len());
    println!("  [i] Recovery rate: {:.2}%", recovery_rate);

    if final_gaps.is_empty() {
        println!("  [OK] SUCCESS: All gaps recovered!");
    } else {
        println!("  [!]  WARNING: Some gaps not recovered (evicted from cache)");
        if final_gaps.len() <= 5 {
            for gap in final_gaps {
                println!("     - Unrecovered: [{:?})", gap);
            }
        }
    }
    println!();

    // Metrics summary
    println!("[i] Metrics Summary:");
    println!("  Writer:");
    println!(
        "    - Retransmissions sent: {}",
        writer_metrics.retransmit_sent()
    );
    println!("  Reader:");
    println!("    - Gaps detected: {}", reader_metrics.gaps_detected());
    println!("    - Max gap size: {}", reader_metrics.max_gap_size());
    println!(
        "    - Out-of-order packets: {}",
        reader_metrics.out_of_order()
    );
    println!(
        "    - Retransmissions received: {}",
        reader_metrics.retransmit_received()
    );
    println!();

    // Heartbeat protocol demo
    println!("[*] Phase 5: Heartbeat protocol demo...");

    let mut hb_tx = HeartbeatTx::with_period_ms(100, 10);
    let mut hb_rx = HeartbeatRx::new();

    let first_seq = writer_cache.oldest_seq().unwrap_or(1);
    let last_seq = writer_seqgen.current() - 1;

    let hb = hb_tx.build_heartbeat(first_seq, last_seq);
    println!(
        "  [*] Heartbeat TX: first_seq={}, last_seq={}, count={}",
        hb.first_seq, hb.last_seq, hb.count
    );

    // Reader receives heartbeat (simulating all data received)
    let gaps_from_hb = hb_rx.on_heartbeat(&hb, last_seq);

    if let Some(gaps) = gaps_from_hb {
        println!("  [i] Heartbeat RX detected gaps: {:?}", gaps);
    } else {
        println!("  [OK] Heartbeat RX: No gaps (reader up-to-date)");
    }
    println!();

    // Final status
    println!("[*] Demo Complete!");
    println!("   Total messages: {}", TOTAL_MESSAGES);
    println!("   Lost packets: {}", lost_count);
    println!("   Recovered: {}", retransmits.len());
    println!("   Final gaps: {}", final_gaps.len());
    println!("   Success rate: {:.2}%", recovery_rate);
}
