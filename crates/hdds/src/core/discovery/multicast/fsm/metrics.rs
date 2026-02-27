// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Discovery metrics for SPDP/SEDP packet processing.
//!
//! Atomic counters for received packets, discovered participants,
//! expired leases, and parse errors.

use std::sync::atomic::{AtomicU64, Ordering};

/// Discovery metrics.
///
/// Track SPDP/SEDP events and participant lifecycle stats.
#[derive(Debug)]
pub struct DiscoveryMetrics {
    /// Total SPDP packets received.
    pub spdp_received: AtomicU64,
    /// Total SEDP packets received.
    pub sedp_received: AtomicU64,
    /// Total participants discovered (ever).
    pub participants_discovered: AtomicU64,
    /// Total participants expired (ever).
    pub participants_expired: AtomicU64,
    /// Parse errors (malformed packets).
    pub parse_errors: AtomicU64,
    /// Security validation errors (rejected participants).
    pub security_errors: AtomicU64,
}

impl DiscoveryMetrics {
    #[must_use]
    pub fn new() -> Self {
        crate::trace_fn!("DiscoveryMetrics::new");
        Self {
            spdp_received: AtomicU64::new(0),
            sedp_received: AtomicU64::new(0),
            participants_discovered: AtomicU64::new(0),
            participants_expired: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            security_errors: AtomicU64::new(0),
        }
    }

    /// Get snapshot of metrics.
    ///
    /// Returns tuple: (spdp_received, sedp_received, participants_discovered,
    ///                 participants_expired, parse_errors)
    #[must_use]
    pub fn snapshot(&self) -> (u64, u64, u64, u64, u64) {
        crate::trace_fn!("DiscoveryMetrics::snapshot");
        (
            self.spdp_received.load(Ordering::Relaxed),
            self.sedp_received.load(Ordering::Relaxed),
            self.participants_discovered.load(Ordering::Relaxed),
            self.participants_expired.load(Ordering::Relaxed),
            self.parse_errors.load(Ordering::Relaxed),
        )
    }

    /// Get security errors count.
    #[must_use]
    pub fn security_errors(&self) -> u64 {
        self.security_errors.load(Ordering::Relaxed)
    }
}

impl Default for DiscoveryMetrics {
    fn default() -> Self {
        Self::new()
    }
}
