// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use std::sync::Arc;

use hdds::core::rt::slabpool::SlabPool;
use hdds::qos::History;
use hdds::reliability::{
    GapMsg, GapRx, GapTracker, GapTx, HistoryCache, NackMsg, NackScheduler, ReliableMetrics,
    RtpsRange, SeqNumGenerator, WriterRetransmitHandler, ENTITYID_UNKNOWN,
};

fn collect_ranges(tracker: &GapTracker) -> Vec<std::ops::Range<u64>> {
    tracker.pending_gaps().to_vec()
}

#[test]
fn test_gap_advances_reader_seqnum() {
    let mut tracker = GapTracker::new();
    tracker.on_receive(1);
    tracker.on_receive(5); // gap [2..5)

    assert_eq!(collect_ranges(&tracker), vec![2..5]);

    let gap = GapMsg::contiguous(ENTITYID_UNKNOWN, ENTITYID_UNKNOWN, RtpsRange::new(2, 5))
        .expect("valid range");
    let mut rx = GapRx::new();
    let lost = rx.on_gap(&gap);
    for range in lost {
        tracker.mark_lost(range.into());
    }

    assert!(tracker.pending_gaps().is_empty());
    assert_eq!(tracker.last_seen(), 4);
}

#[test]
fn test_gap_stops_nack_loop() {
    let mut tracker = GapTracker::new();
    let mut scheduler = NackScheduler::with_window_ms(0);

    for seq in [1u64, 2, 5] {
        tracker.on_receive(seq);
        scheduler.on_receive(seq);
    }

    let ranges = scheduler.try_flush().expect("flush");
    assert_eq!(ranges, vec![3..5]);
    scheduler.on_nack_sent();

    let mut rx = GapRx::new();
    let gap = GapMsg::contiguous(ENTITYID_UNKNOWN, ENTITYID_UNKNOWN, RtpsRange::new(3, 5))
        .expect("valid range");
    let lost = rx.on_gap(&gap);
    for range in lost.clone() {
        tracker.mark_lost(range.into());
    }
    scheduler.mark_lost_ranges(lost.into_iter().map(RtpsRange::from));

    assert!(scheduler.pending_gaps().is_empty());
    assert!(tracker.pending_gaps().is_empty());
    assert_eq!(scheduler.retry_count(), 0);
}

#[test]
fn test_repair_with_10_percent_loss() {
    const TOTAL: u64 = 1_000;
    const DROP_DIVISOR: u64 = 10; // 10% loss

    let pool = Arc::new(SlabPool::new());
    // Use realistic cache size (100 samples, 64KB quota)
    // This simulates limited writer history - old messages evict and trigger GAP
    let cache = HistoryCache::new_with_limits(pool, 100, 64 * 1024, History::KeepLast(100));
    let metrics = ReliableMetrics::new();
    let mut gap_tx = GapTx::new();
    let mut writer = WriterRetransmitHandler::new(&cache, &mut gap_tx, &metrics);

    let mut tracker = GapTracker::new();
    let mut scheduler = NackScheduler::with_window_ms(0);
    let mut gap_rx = GapRx::new();
    let seqgen = SeqNumGenerator::new();

    let mut dropped = Vec::new();

    for _ in 0..TOTAL {
        let seq = seqgen.next();
        let payload = format!("payload-{seq}");
        cache.insert(seq, payload.as_bytes()).expect("cache insert");

        if seq.is_multiple_of(DROP_DIVISOR) {
            dropped.push(seq);
        } else {
            tracker.on_receive(seq);
            scheduler.on_receive(seq);
        }
    }

    let mut retry_cycles = 0;
    let mut total_retransmits = 0;
    let mut total_gap_sequences = 0;

    while retry_cycles < 6 {
        if let Some(ranges) = scheduler.try_flush() {
            if ranges.is_empty() {
                break;
            }

            let nack = NackMsg::from_ranges(ranges.clone());
            let (payloads, gaps) = writer.on_nack(&nack);

            for change in payloads {
                assert!(!change.payload.is_empty());
                tracker.on_receive(change.seq);
                scheduler.on_data_received(change.seq);
                total_retransmits += 1;
            }

            for gap in &gaps {
                let lost = gap_rx.on_gap(gap);
                for range in lost.clone() {
                    let gap_size = range.end - range.start;
                    total_gap_sequences += gap_size;
                    tracker.mark_lost(range.into());
                }
                scheduler.mark_lost_ranges(lost.into_iter().map(RtpsRange::from));
            }

            scheduler.on_nack_sent();
        }

        if scheduler.pending_gaps().is_empty() {
            break;
        }

        retry_cycles += 1;
    }

    eprintln!("=== Test Repair Results ===");
    eprintln!("Total sequences: {}", TOTAL);
    eprintln!("Dropped (simulated loss): {}", dropped.len());
    eprintln!("Retransmitted from cache: {}", total_retransmits);
    eprintln!("Declared as GAP: {}", total_gap_sequences);
    eprintln!(
        "Total recovered: {}",
        total_retransmits + total_gap_sequences
    );
    eprintln!();
    eprintln!("Recovery breakdown:");
    eprintln!("  - Retransmit path: {} sequences", total_retransmits);
    eprintln!("  - GAP path: {} sequences", total_gap_sequences);
    eprintln!(
        "  - Unrecovered: {} sequences",
        dropped.len() as u64 - (total_retransmits + total_gap_sequences)
    );

    // All gaps should be resolved (either retransmitted or declared lost)
    assert!(
        scheduler.pending_gaps().is_empty(),
        "Scheduler still has pending gaps after {} retry cycles",
        retry_cycles
    );
    assert!(
        tracker.pending_gaps().is_empty(),
        "Tracker still has pending gaps after {} retry cycles",
        retry_cycles
    );

    // Check recovery completeness
    let total_recovered = total_retransmits + total_gap_sequences;
    let expected_recovered = dropped.len() as u64;

    // Note: Without HEARTBEAT, the final sequence may not be detectable if dropped
    // since no future sequence arrives to trigger gap detection. This is expected behavior.
    let final_seq_dropped = dropped.last().copied().unwrap_or(0) == TOTAL;
    let expected_detectable = if final_seq_dropped {
        expected_recovered - 1 // Final sequence undetectable without HEARTBEAT
    } else {
        expected_recovered
    };

    eprintln!(
        "Final sequence ({}): {}",
        TOTAL,
        if final_seq_dropped {
            "DROPPED (undetectable without HEARTBEAT)"
        } else {
            "received"
        }
    );
    eprintln!(
        "Expected detectable: {} / {}",
        expected_detectable, expected_recovered
    );

    assert_eq!(
        total_recovered, expected_detectable,
        "Recovery incomplete: expected {} detectable gaps but got {} ({} retransmits + {} GAPs). \
        Final sequence is undetectable without HEARTBEAT.",
        expected_detectable, total_recovered, total_retransmits, total_gap_sequences
    );
}
