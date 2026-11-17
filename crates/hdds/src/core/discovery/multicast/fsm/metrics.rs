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
    /// Secure discovery datagrams naming an unresolvable writer key.
    #[cfg(feature = "security")]
    pub secure_sedp_undecodable: AtomicU64,
    /// SEDP datagrams refused by a bound of the queues that hold them
    /// while a participant's keys change or its key material is awaited.
    #[cfg(feature = "security")]
    pub secure_sedp_queue_overflow: AtomicU64,
    /// A secure SEDP writer sent a REPAIR RESPONSE of any shape -- a real
    /// DATA retransmission or a GAP announcing a retired/not-for-this-
    /// participant number -- in answer to an ACKNACK that was itself
    /// DDS-Security submessage-protected (`ControlMessage::was_protected`).
    ///
    /// This counts repair responses, not retransmitted retained history:
    /// `retransmit_sedp_data` increments
    /// its own `sent` tally on a GAP-only answer too (a purged or
    /// not-for-this-participant number), so a datagram carrying nothing
    /// but GAPs moves this counter exactly as a real DATA retransmission
    /// does. [`Self::protected_sedp_data_retransmissions`] is the counter
    /// that answers "did actual DATA cross", narrower and the one a test
    /// proving data crossed must read.
    #[cfg(feature = "security")]
    pub protected_sedp_retransmissions: AtomicU64,
    /// The strict subset of [`Self::protected_sedp_retransmissions`] where
    /// at least one of the repair responses sent was a real DATA
    /// submessage (`!send.is_gap()` in `ControlHandler::retransmit_sedp_
    /// data`), not only a GAP. Zero here while the sibling counter is
    /// non-zero means every protected-ACKNACK-driven repair this process
    /// served was GAP-only -- a legitimate outcome (every number the peer
    /// asked for had already been retired), but a different one from "our
    /// history actually crossed the wire again".
    #[cfg(feature = "security")]
    pub protected_sedp_data_retransmissions: AtomicU64,
    /// New SEDP tracking identities refused because a tracking table is full.
    pub sedp_tracking_refused: AtomicU64,
    /// SEDP endpoints surfaced directly (gate degraded to best-effort)
    /// because the deferred-notification buffer hit
    /// `PENDING_NOTIFICATIONS_CAP` while the FSM was still in the
    /// probation window. Endpoints are surfaced rather than dropped to
    /// avoid losing a legitimate remote endpoint (SEDP is reliable and
    /// non-periodic). Always 0 in normal operation; non-zero indicates
    /// pathological discovery traffic during startup.
    pub sedp_pending_cap_surfaced: AtomicU64,
    /// DATA submessages dropped because their writerEntityId names a BUILTIN
    /// endpoint this implementation does not have (`PacketKind::UnknownBuiltin`).
    ///
    /// Zero against every peer whose builtin set we implement. Non-zero means
    /// a peer is sending us builtin traffic we do not consume - which is a
    /// real answer and not an error: the classifier's debug line carries the
    /// entity id, so a non-zero count here names what to go and read. It
    /// exists because the alternative to counting is GUESSING: treating this
    /// traffic as user data would hand it to a parser that tries the SPDP
    /// reader, then the SEDP reader, on whatever it is given.
    pub unclaimed_builtin_data: AtomicU64,
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
            #[cfg(feature = "security")]
            secure_sedp_undecodable: AtomicU64::new(0),
            #[cfg(feature = "security")]
            secure_sedp_queue_overflow: AtomicU64::new(0),
            #[cfg(feature = "security")]
            protected_sedp_retransmissions: AtomicU64::new(0),
            #[cfg(feature = "security")]
            protected_sedp_data_retransmissions: AtomicU64::new(0),
            sedp_tracking_refused: AtomicU64::new(0),
            sedp_pending_cap_surfaced: AtomicU64::new(0),
            unclaimed_builtin_data: AtomicU64::new(0),
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

    /// Secure SEDP announcements refused because their participant's
    /// tracking table was full.
    #[must_use]
    pub fn sedp_tracking_refused(&self) -> u64 {
        self.sedp_tracking_refused.load(Ordering::Relaxed)
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
