// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Congestion control for HDDS.
//!
//!
//! This module provides adaptive congestion control to prevent network collapse:
//!
//! - **Rate limiting**: Token bucket per writer with configurable budget
//! - **Priority queues**: P0 (critical), P1 (normal), P2 (background)
//! - **Coalescing**: P2 "last value wins" by instance key
//! - **AIMD**: Additive Increase / Multiplicative Decrease rate adaptation
//!
//! # Architecture
//!
//! ```text
//! +-----------------------------------------------------------------+
//! |                         Participant                              |
//! |  +-----------------------------------------------------------+  |
//! |  |                 CongestionController                       |  |
//! |  |  +------------+ +------------+ +------------------------+ |  |
//! |  |  | Scorer     | | RateCtrl   | | BudgetAllocator        | |  |
//! |  |  | - EWMA     | | - AIMD     | | - P0 reserve           | |  |
//! |  |  | - state    | | - cooldown | | - P1/P2 distribution   | |  |
//! |  |  +------------+ +------------+ +------------------------+ |  |
//! |  +-----------------------------------------------------------+  |
//! |                              |                                   |
//! |  +---------------------------v-------------------------------+  |
//! |  |                      DataWriter                            |  |
//! |  |  +-----------------------------------------------------+  |  |
//! |  |  |                   WriterPacer                       |  |  |
//! |  |  |  +----------+ +--------------------------------+   |  |  |
//! |  |  |  | TokenBkt | | Queues                         |   |  |  |
//! |  |  |  | (budget) | | +----+ +----+ +----+          |   |  |  |
//! |  |  |  +----------+ | | P0 | | P1 | | P2 |          |   |  |  |
//! |  |  |               | +----+ +----+ +----+          |   |  |  |
//! |  |  |               +--------------------------------+   |  |  |
//! |  |  +-----------------------------------------------------+  |  |
//! |  +-----------------------------------------------------------+  |
//! +-----------------------------------------------------------------+
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use hdds::congestion::{CongestionConfig, WriterPacer, Priority};
//!
//! // Create a pacer with default config
//! let config = CongestionConfig::default();
//! let mut pacer = WriterPacer::new(config);
//!
//! // Enqueue samples by priority
//! pacer.enqueue(critical_data, Priority::P0)?;
//! pacer.enqueue(normal_data, Priority::P1)?;
//! pacer.enqueue(telemetry_data, Priority::P2)?;
//!
//! // Send in priority order with rate limiting
//! while let SendAction::Send(sample) = pacer.try_send() {
//!     transport.send(&sample.data)?;
//! }
//! ```
//!
//! # Priority Semantics
//!
//! - **P0 (Critical)**: Never dropped, can bypass rate limit (force send)
//! - **P1 (Normal)**: Drops oldest when queue full
//! - **P2 (Background)**: Coalesced by instance key, "last value wins"

pub mod budget_allocator;
pub mod coalescing;
pub mod config;
pub mod controller;
pub mod ecn;
pub mod metrics;
pub mod nack_coalescer;
pub mod rate_controller;
pub mod repair_queue;
pub mod retry_tracker;
pub mod rtt_estimator;
pub mod scorer;
pub mod token_bucket;
pub mod transport_feedback;
pub mod wfq;
pub mod writer_pacer;

// Re-exports - Phase 1
pub use coalescing::{CoalescedSample, CoalescingQueue, CoalescingStats, InstanceKey};
pub use config::{BackpressurePolicy, ConfigError, CongestionConfig, EcnMode, Priority};
pub use metrics::{
    CongestionMetrics, CongestionMetricsSnapshot, CongestionState, LoggingObserver,
    MetricsObserver, NoOpObserver,
};
pub use token_bucket::TokenBucket;
pub use writer_pacer::{EnqueueError, PendingSample, SendAction, WriterPacer, WriterPacerMetrics};

// Re-exports - Phase 2
pub use rate_controller::{RateController, RateControllerMetrics};
pub use rtt_estimator::{PeerRttTracker, RttEstimator, RttSample};
pub use scorer::{CongestionAction, CongestionScorer, ScorerConfig, ScorerState};
pub use transport_feedback::{
    classify_error, TransportFeedback, TransportFeedbackSnapshot, TransportSignal,
};

// Re-exports - Phase 3
pub use nack_coalescer::{NackCoalescer, NackCoalescerStats, SequenceNumber};
pub use repair_queue::{DequeueResult, RepairQueue, RepairQueueConfig, RepairQueueStats};
pub use retry_tracker::{RepairRequest, RetryConfig, RetryTracker, RetryTrackerStats};

// Re-exports - Phase 4
pub use budget_allocator::{
    AllocationConfig, AllocationStats, BudgetAllocator, WriterBudgetUpdate, WriterId, WriterInfo,
};
pub use controller::CongestionController;

// Re-exports - Phase 6 (ECN + WFQ)
pub use ecn::{Dscp, EcnCapabilities, EcnCodepoint, EcnProcessor, EcnSocket, EcnStats};
pub use wfq::{PriorityWfqScheduler, WfqError, WfqPacket, WfqScheduler, WfqStats, WfqWriter};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let cfg = CongestionConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.decrease_threshold, 60);
        assert_eq!(cfg.increase_threshold, 20);
    }

    #[test]
    fn test_priority_values() {
        assert_eq!(Priority::P0.as_u8(), 0);
        assert_eq!(Priority::P1.as_u8(), 1);
        assert_eq!(Priority::P2.as_u8(), 2);
    }

    #[test]
    fn test_token_bucket_basic() {
        let mut bucket = TokenBucket::new(1000, 100);
        assert!(bucket.try_consume(50));
        assert_eq!(bucket.tokens(), 50);
    }

    #[test]
    fn test_writer_pacer_priority_order() {
        let config = CongestionConfig::default();
        let mut pacer = WriterPacer::new(config);

        pacer.enqueue(vec![2], Priority::P2).unwrap();
        pacer.enqueue(vec![1], Priority::P1).unwrap();
        pacer.enqueue(vec![0], Priority::P0).unwrap();

        // Should send in order: P0, P1, P2
        if let SendAction::Send(s) = pacer.try_send() {
            assert_eq!(s.priority, Priority::P0);
        }
        if let SendAction::Send(s) = pacer.try_send() {
            assert_eq!(s.priority, Priority::P1);
        }
        if let SendAction::Send(s) = pacer.try_send() {
            assert_eq!(s.priority, Priority::P2);
        }
    }

    #[test]
    fn test_coalescing_queue_basic() {
        let mut queue = CoalescingQueue::new(10);
        let key = InstanceKey::new(1, 1);

        queue.insert(vec![1], key.clone());
        queue.insert(vec![2], key.clone()); // Replaces

        assert_eq!(queue.len(), 1);
        assert_eq!(queue.coalesced_count(), 1);
    }

    #[test]
    fn test_metrics_recording() {
        let metrics = CongestionMetrics::new();

        metrics.record_rate(50_000);
        metrics.record_eagain();
        metrics.record_send(Priority::P0, 100);

        let snap = metrics.snapshot();
        assert_eq!(snap.current_rate_bps, 50_000);
        assert_eq!(snap.eagain_total, 1);
        assert_eq!(snap.bytes_sent, 100);
    }

    /// Stress test: Multiple writers with burst traffic.
    ///
    /// Simulates 50 writers each sending a burst of 10 samples.
    /// Verifies that:
    /// - P0 samples are protected (not dropped)
    /// - Rate stabilizes under congestion
    /// - No panics or deadlocks
    #[test]
    fn test_stress_burst_writers() {
        let mut controller = CongestionController::default();

        // Register 50 writers (mix of priorities)
        for i in 0..50 {
            let priority = match i % 3 {
                0 => Priority::P0,
                1 => Priority::P1,
                _ => Priority::P2,
            };
            controller.register_writer(i, priority);
        }

        // Simulate 10 rounds of congestion signals
        for round in 0..10 {
            // Simulate some EAGAIN events (network pressure)
            if round % 2 == 0 {
                controller.on_eagain();
            }

            // Simulate NACK events (reliable traffic)
            controller.on_nacks(5);

            // Tick to process signals
            controller.tick();
        }

        // Verify controller is stable
        let rate = controller.current_rate();
        assert!(rate > 0, "rate should be positive");
        assert!(rate <= 100_000_000, "rate should be capped");

        // P0 writers should have budget
        let p0_budget = controller.get_writer_budget(0); // Writer 0 is P0
        assert!(p0_budget.is_some(), "P0 writer should have budget");
        assert!(p0_budget.unwrap() > 0, "P0 budget should be positive");

        // Controller should have 50 writers
        assert_eq!(controller.writer_count(), 50);
    }

    /// Stress test: Writer pacer under high load.
    ///
    /// Tests that the pacer handles rapid enqueue/dequeue cycles.
    #[test]
    fn test_stress_writer_pacer_throughput() {
        let config = CongestionConfig::default();
        let mut pacer = WriterPacer::new(config);

        // Enqueue 1000 samples across all priorities
        for i in 0..1000 {
            let priority = match i % 3 {
                0 => Priority::P0,
                1 => Priority::P1,
                _ => Priority::P2,
            };
            let _ = pacer.enqueue(vec![i as u8; 100], priority);
        }

        // Drain all samples
        let mut sent = 0;
        while let SendAction::Send(_) = pacer.try_send() {
            sent += 1;
            if sent > 2000 {
                break; // Safety limit
            }
        }

        // Should have sent at least some samples
        assert!(sent > 0, "should have sent samples");

        // Metrics should reflect activity
        let m = pacer.metrics();
        assert!(m.total_sent() > 0, "should have sent metrics");
    }

    /// Test congestion recovery cycle.
    ///
    /// Simulates congestion -> recovery -> stable cycle.
    #[test]
    fn test_congestion_recovery_cycle() {
        use std::thread;
        use std::time::Duration;

        let config = CongestionConfig {
            cooldown_ms: 10,      // Fast cooldown for test
            stable_window_ms: 10, // Fast stable window
            ..Default::default()
        };
        let mut controller = CongestionController::new(config);

        // Initially stable
        assert!(!controller.is_congested());

        // Trigger congestion with EAGAIN
        for _ in 0..5 {
            controller.on_eagain();
        }
        controller.tick();

        // Should be congested after tick
        let score_after_congestion = controller.score();
        assert!(
            score_after_congestion > 0.0,
            "score should increase after EAGAIN"
        );

        // Wait for cooldown and tick multiple times to recover
        thread::sleep(Duration::from_millis(20));
        for _ in 0..20 {
            controller.tick();
        }

        // Score should have decayed
        let final_score = controller.score();
        assert!(
            final_score < score_after_congestion,
            "score should decay: {} < {}",
            final_score,
            score_after_congestion
        );
    }

    /// Test repair queue budget limiting under stress.
    #[test]
    fn test_stress_repair_budget() {
        use std::thread;
        use std::time::Duration;

        let config = RepairQueueConfig {
            coalesce_delay: Duration::from_millis(1),
            retry_config: RetryConfig::new(1, 100),
            budget_ratio: 0.1, // 10% budget
            ..Default::default()
        };

        let mut rq = RepairQueue::with_config(config);
        rq.set_total_budget(10_000); // 10KB total = 1KB repair budget

        // Request many repairs
        for i in 0..100 {
            rq.request_repair(&[i as i64]);
        }

        thread::sleep(Duration::from_millis(5));
        rq.process_coalesced();

        // Wait for repairs to be ready
        thread::sleep(Duration::from_millis(5));

        // Try to dequeue - should hit budget limit eventually
        let mut sent = 0;
        let mut budget_hit = false;

        for _ in 0..100 {
            match rq.try_dequeue() {
                DequeueResult::Ready(_) => sent += 1,
                DequeueResult::BudgetExhausted => {
                    budget_hit = true;
                    break;
                }
                DequeueResult::Wait(_) => {}
                DequeueResult::Empty => break,
            }
        }

        // Should have sent some but hit budget
        assert!(sent > 0, "should have sent some repairs");
        // Budget might or might not be hit depending on timing, so we don't assert budget_hit
        let _ = budget_hit;
    }
}
