// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SPDP participant discovery state and metadata.
//!
//! Defines FSM states and `ParticipantInfo` for tracking discovered peers.
//! Each participant transitions through: Idle -> Announced -> Discovered -> Active.
//!
//! # Stale SPDP liveness filter
//!
//! When a DDS process is killed, its periodic SPDP announcements may still
//! reside in the OS multicast socket buffer.  A new process on the same domain
//! drains those stale packets in a rapid burst (< 5 ms apart).  To prevent
//! promoting a dead participant we use **time-gated probation**:
//!
//!   1. `spdp_count >= 2`, **and**
//!   2. at least `PROBATION_WINDOW_MS` (100 ms) elapsed since creation.
//!
//! Combined with the socket drain at startup (`MulticastListener::run_loop`),
//! this provides a two-layer defense against stale discovery.
//!
//! # Liveness marks
//!
//! A peer that announces rarely (a startup burst, then one SPDP every few
//! tens of seconds) cannot pass the SPDP count inside our probation window, yet
//! it speaks constantly under its own GUID prefix: SEDP, HEARTBEAT,
//! ACKNACK. Every such emission, and every SPDP, is a liveness mark when it
//! lands at least `PROBATION_WINDOW_MS` after the entry was created AND at
//! least `PROBATION_WINDOW_MS` after the previous mark: packets of a dead
//! process are drained from the socket buffer in one burst and count once
//! at most, a live process speaks again later. Two marks confirm the peer
//! as two counted SPDPs do.

use crate::core::discovery::GUID;
use std::net::SocketAddr;
use std::time::Instant;

/// FSM state for discovered participants
///
/// # States
/// - `Idle`: Initial state, no activity
/// - `Announced`: Local participant sent SPDP announce
/// - `Discovered`: Received remote SPDP, not yet bidirectional
/// - `Active`: Bidirectional communication established
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsmState {
    Idle,
    Announced,
    Discovered,
    Active,
}

/// Participant metadata from SPDP discovery
///
/// Tracks remote DDS participant state including lease management
/// and endpoint information.
///
/// # Lease Management
/// - `lease_duration_ms`: Duration before participant expires (default 100s)
/// - `last_seen`: Timestamp of last SPDP packet received
/// - `is_expired()`: Check if lease has expired
/// - `refresh()`: Update last_seen when receiving SPDP
///
/// # Stale SPDP liveness filter
/// - `created_at`: Timestamp when this entry was first created
/// - `spdp_count`: Number of SPDPs that passed the probation window
/// - `liveness_marks`: Emissions of any kind counted at distinct instants
/// - `is_confirmed_alive()`: `spdp_count >= 2 || liveness_marks >= 2`
/// - `PROBATION_WINDOW_MS`: Minimum elapsed time before counting refreshes,
///   and minimum spacing between two liveness marks
#[derive(Debug, Clone)]
pub struct ParticipantInfo {
    /// Participant GUID (16 bytes)
    pub guid: GUID,
    /// Unicast locators (endpoints) for this participant
    pub endpoints: Vec<SocketAddr>,
    /// Lease duration in milliseconds (typically 100000 ms = 100s)
    pub lease_duration_ms: u64,
    /// Last time we received SPDP from this participant
    pub last_seen: Instant,
    /// Current FSM state
    pub state: FsmState,
    /// Timestamp when this participant entry was first created.
    /// Used by the time-gated probation to distinguish rapid stale bursts
    /// (< PROBATION_WINDOW_MS apart) from live SPDP refreshes (200ms+ apart).
    pub created_at: Instant,
    /// Number of SPDP announcements counted toward liveness.
    /// A participant is considered "live" after 2+ SPDPs that pass the
    /// time-gated probation window (filters stale buffer residue from killed processes).
    pub spdp_count: u32,
    /// Emissions of this participant (SPDP, SEDP, control traffic) counted
    /// at distinct instants: each one at least `PROBATION_WINDOW_MS` after
    /// the entry's creation and after the previous mark (`mark_alive`).
    pub liveness_marks: u32,
    /// When the last liveness mark was counted; `None` before the first.
    pub last_mark: Option<Instant>,
    /// RTPS `PID_VENDORID` (0x0016): the 2-byte vendor id advertised by this
    /// participant in its SPDP announcement. `None` if not present on the wire.
    /// Captured for per-vendor interop adaptation on the send path.
    pub vendor_id: Option<u16>,
    /// HDDS capability bitmask the participant announced in SPDP
    /// (`PID_HDDS_CAPABILITIES`), kept with `vendor_id` to decide its
    /// `GroupDialect` once. `None` when it announced none.
    pub hdds_capabilities: Option<u32>,
    /// The builtin endpoints the participant announced in SPDP
    /// (`PID_BUILTIN_ENDPOINT_SET`); `None` when it announced none.
    pub builtin_endpoint_set: Option<u32>,
}

impl ParticipantInfo {
    /// Whether SEDP announcements to this participant carry
    /// PID_TYPE_OBJECT, from what its SPDP announced (`TypeObjectPid::of`).
    #[must_use]
    pub fn type_object_pid(&self) -> super::TypeObjectPid {
        super::TypeObjectPid::of(&self.guid.prefix, self.vendor_id, self.hdds_capabilities)
    }

    /// Minimum elapsed time (ms) between participant creation and
    /// liveness promotion.  Stale SPDP packets from a killed process arrive
    /// in rapid bursts (< 5 ms).  Live participants send SPDP at 200 ms+
    /// intervals during the startup burst phase (see `spdp_announcer.rs`
    /// `AGGRESSIVE_INTERVAL_MS = 200`).  100 ms is safely between these two
    /// regimes and does not affect interop with other vendors'
    /// initial_announcements.
    const PROBATION_WINDOW_MS: u64 = 100;

    /// Create new ParticipantInfo with current timestamp
    ///
    /// # Arguments
    /// - `guid`: Participant GUID from SPDP
    /// - `endpoints`: Unicast locators (IP:port)
    /// - `lease_duration_ms`: Lease duration in milliseconds
    ///
    /// # Examples
    /// ```
    /// use hdds::core::discovery::GUID;
    /// use hdds::core::discovery::multicast::ParticipantInfo;
    /// use std::net::SocketAddr;
    ///
    /// let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    /// let endpoints = vec!["127.0.0.1:7400".parse::<SocketAddr>()
    ///     .expect("Socket address parsing should succeed")];
    /// let info = ParticipantInfo::new(guid, endpoints, 100_000);
    /// ```
    pub fn new(guid: GUID, endpoints: Vec<SocketAddr>, lease_duration_ms: u64) -> Self {
        let now = Instant::now();
        Self {
            guid,
            endpoints,
            lease_duration_ms,
            last_seen: now,
            created_at: now,
            state: FsmState::Discovered,
            spdp_count: 1,
            liveness_marks: 0,
            last_mark: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        }
    }

    /// Check if participant lease has expired
    ///
    /// Returns true once the elapsed time reaches the advertised lease.
    /// `DURATION_INFINITE` expires only through explicit removal.
    ///
    /// # Examples
    /// ```no_run
    /// # use hdds::core::discovery::GUID;
    /// # use hdds::core::discovery::multicast::ParticipantInfo;
    /// # let guid = GUID::zero();
    /// # let info = ParticipantInfo::new(guid, vec![], 100);
    /// if info.is_expired() {
    ///     // Remove from participant database
    /// }
    /// ```
    pub fn is_expired(&self) -> bool {
        self.lease_duration_ms != u64::MAX
            && self.last_seen.elapsed().as_millis() as u64 >= self.lease_duration_ms
    }

    /// Refresh last_seen timestamp (called on SPDP reception)
    ///
    /// Updates last_seen to current time, resetting the lease timer.
    /// The `spdp_count` is only incremented when enough time has elapsed
    /// since the participant entry was created (`PROBATION_WINDOW_MS`).
    ///
    /// # Rationale
    ///
    /// Stale SPDP packets from a killed process arrive in a rapid burst
    /// (all within a few milliseconds) because they are drained from the OS
    /// socket buffer in one shot.  A live participant sends SPDP at 200 ms+
    /// intervals (burst phase) or 3 s (steady state).  By gating the counter
    /// increment on a 100 ms window we ensure stale bursts never promote a
    /// dead participant while live peers pass through on the very first
    /// refresh after the window.
    ///
    /// # Examples
    /// ```no_run
    /// # use hdds::core::discovery::GUID;
    /// # use hdds::core::discovery::multicast::ParticipantInfo;
    /// # let guid = GUID::zero();
    /// # let mut info = ParticipantInfo::new(guid, vec![], 100_000);
    /// // On receiving SPDP packet
    /// info.refresh();
    /// ```
    pub fn refresh(&mut self) {
        self.last_seen = Instant::now();
        // Only count toward liveness promotion if enough time has
        // elapsed since this entry was first created.  Stale packets from
        // killed processes arrive in < 5 ms bursts; live participants space
        // their SPDP announcements by at least 200 ms (burst) or 3 s (normal).
        if self.created_at.elapsed().as_millis() as u64 >= Self::PROBATION_WINDOW_MS {
            self.spdp_count = self.spdp_count.saturating_add(1);
        }
        self.mark_alive();
    }

    /// Count one liveness mark for an emission observed now, if it lands at
    /// a distinct instant: at least `PROBATION_WINDOW_MS` after the entry
    /// was created AND after the previous mark. Returns whether it counted.
    ///
    /// The first condition keeps a socket-buffer burst (everything drained
    /// in the first milliseconds) from counting at all; the second keeps a
    /// burst that lands later from counting more than once. Unlike
    /// `spdp_count`, whose gate is "since creation" only, N emissions at
    /// 101, 102 and 103 ms are one mark, not three.
    pub fn mark_alive(&mut self) -> bool {
        if !self.mark_would_count() {
            return false;
        }
        self.last_mark = Some(Instant::now());
        self.liveness_marks = self.liveness_marks.saturating_add(1);
        true
    }

    /// Whether an emission observed now would count as a liveness mark
    /// (`mark_alive`): at least `PROBATION_WINDOW_MS` after the entry was
    /// created and after the previous mark.
    pub(crate) fn mark_would_count(&self) -> bool {
        let window = Self::PROBATION_WINDOW_MS;
        (self.created_at.elapsed().as_millis() as u64) >= window
            && self
                .last_mark
                .is_none_or(|last| (last.elapsed().as_millis() as u64) >= window)
    }

    /// Check if this participant has been confirmed alive: two counted SPDPs,
    /// or two liveness marks (emissions of any kind at distinct instants).
    /// A stale participant from a killed process only has 1 SPDP (from the
    /// OS buffer) and no mark.
    ///
    /// The time-gated probation in `refresh()` ensures that rapid stale
    /// bursts cannot reach `spdp_count >= 2`; `mark_alive` holds marks to the
    /// same window and to distinct instants.
    #[inline]
    pub fn is_confirmed_alive(&self) -> bool {
        self.spdp_count >= 2 || self.liveness_marks >= 2
    }

    /// Whether the probation purge keeps this participant: confirmed, or
    /// heard from at least once `PROBATION_WINDOW_MS` after we first heard
    /// it. A process whose packets all came out of one socket-buffer burst
    /// has no mark; a live one that merely announces slowly has spoken
    /// again by then (its SEDP, its HEARTBEATs).
    #[inline]
    pub fn survives_probation(&self) -> bool {
        self.is_confirmed_alive() || self.liveness_marks >= 1
    }

    /// Whether a match deferred during probation may be surfaced for this
    /// participant: three counted SPDPs (the HDDS startup burst) or two
    /// liveness marks.
    #[inline]
    pub fn is_match_eligible(&self) -> bool {
        self.spdp_count >= 3 || self.liveness_marks >= 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_participant_info_new() {
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let endpoints = vec!["127.0.0.1:7400"
            .parse()
            .expect("Socket address parsing should succeed")];
        let info = ParticipantInfo::new(guid, endpoints.clone(), 100_000);

        assert_eq!(info.guid, guid);
        assert_eq!(info.endpoints.len(), 1);
        assert_eq!(info.lease_duration_ms, 100_000);
        assert_eq!(info.state, FsmState::Discovered);
        assert_eq!(info.spdp_count, 1);
        assert!(!info.is_confirmed_alive());
    }

    #[test]
    fn test_participant_not_expired() {
        let guid = GUID::zero();
        let info = ParticipantInfo::new(guid, vec![], 100_000);

        // Should not be expired immediately
        assert!(!info.is_expired());
    }

    #[test]
    fn test_participant_expired() {
        let guid = GUID::zero();
        let info = ParticipantInfo::new(guid, vec![], 50); // 50ms lease

        // Wait for lease to expire
        std::thread::sleep(std::time::Duration::from_millis(60));

        assert!(info.is_expired());
    }

    #[test]
    fn test_infinite_participant_lease_does_not_expire() {
        let mut info = ParticipantInfo::new(GUID::zero(), vec![], u64::MAX);
        info.last_seen = Instant::now() - std::time::Duration::from_secs(1);
        assert!(!info.is_expired());
    }

    #[test]
    fn test_participant_refresh() {
        let guid = GUID::zero();
        let mut info = ParticipantInfo::new(guid, vec![], 100_000);
        assert_eq!(info.spdp_count, 1);

        // Wait a bit (but within probation window)
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Refresh should reset timer but NOT increment spdp_count (within probation)
        info.refresh();

        // Should not be expired
        assert!(!info.is_expired());
    }

    #[test]
    fn test_probation_blocks_rapid_stale_burst() {
        // Simulate stale packets: multiple refresh() calls within < 100ms
        let guid = GUID::zero();
        let mut info = ParticipantInfo::new(guid, vec![], 100_000);
        assert_eq!(info.spdp_count, 1);
        assert!(!info.is_confirmed_alive());

        // Rapid refreshes (simulating stale buffer drain) -- should NOT increment
        for _ in 0..10 {
            info.refresh();
        }
        assert_eq!(
            info.spdp_count, 1,
            "stale burst must not increment spdp_count"
        );
        assert!(
            !info.is_confirmed_alive(),
            "stale burst must not promote participant"
        );
    }

    #[test]
    fn test_probation_allows_live_participant() {
        // Simulate live participant: refresh() after PROBATION_WINDOW_MS
        let guid = GUID::zero();
        let mut info = ParticipantInfo::new(guid, vec![], 100_000);
        assert_eq!(info.spdp_count, 1);
        assert!(!info.is_confirmed_alive());

        // Wait beyond probation window
        std::thread::sleep(std::time::Duration::from_millis(
            ParticipantInfo::PROBATION_WINDOW_MS + 20,
        ));

        info.refresh();
        assert_eq!(info.spdp_count, 2);
        assert!(
            info.is_confirmed_alive(),
            "live participant must be promoted after probation window"
        );
    }

    #[test]
    fn test_probation_mixed_stale_then_live() {
        // Stale burst followed by a legitimate refresh after the window
        let guid = GUID::zero();
        let mut info = ParticipantInfo::new(guid, vec![], 100_000);

        // Rapid stale burst
        for _ in 0..5 {
            info.refresh();
        }
        assert_eq!(info.spdp_count, 1);
        assert!(!info.is_confirmed_alive());

        // Wait beyond probation window, then one legitimate refresh
        std::thread::sleep(std::time::Duration::from_millis(
            ParticipantInfo::PROBATION_WINDOW_MS + 20,
        ));

        info.refresh();
        assert_eq!(info.spdp_count, 2);
        assert!(info.is_confirmed_alive());
    }

    #[test]
    fn liveness_marks_count_distinct_instants_only() {
        let window = std::time::Duration::from_millis(ParticipantInfo::PROBATION_WINDOW_MS + 10);
        let mut info = ParticipantInfo::new(GUID::zero(), vec![], 100_000);
        // Inside the creation window: a socket-buffer burst counts nothing.
        assert!(!info.mark_alive());
        assert_eq!(info.liveness_marks, 0);
        assert!(!info.survives_probation());

        // Past it, a burst of three emissions is ONE mark.
        std::thread::sleep(window);
        assert!(info.mark_alive());
        assert!(!info.mark_alive());
        assert!(!info.mark_alive());
        assert_eq!(info.liveness_marks, 1, "one instant, one mark");
        assert!(info.survives_probation(), "it spoke after the window");
        assert!(!info.is_confirmed_alive(), "one mark confirms nothing");
        assert!(!info.is_match_eligible());

        // A second emission at a distinct instant confirms it.
        std::thread::sleep(window);
        assert!(info.mark_alive());
        assert_eq!(info.liveness_marks, 2);
        assert!(info.is_confirmed_alive());
        assert!(info.is_match_eligible());
        assert_eq!(info.spdp_count, 1, "marks leave the SPDP count alone");
    }

    /// Both thresholds of `mark_alive`, from below: an emission 60 ms after
    /// the entry was created is no mark, and two emissions 60 ms apart past
    /// that window are one mark, not two.
    #[test]
    fn liveness_marks_need_the_full_window_on_both_conditions() {
        let below = std::time::Duration::from_millis(60);
        let mut info = ParticipantInfo::new(GUID::zero(), vec![], 100_000);
        std::thread::sleep(below);
        assert!(!info.mark_alive(), "60 ms after creation: not a mark");
        assert_eq!(info.liveness_marks, 0);

        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(info.mark_alive(), "past the window: a mark");
        std::thread::sleep(below);
        assert!(!info.mark_alive(), "60 ms after the previous mark: not one");
        assert_eq!(info.liveness_marks, 1);
    }

    #[test]
    fn test_fsm_state_transitions() {
        let guid = GUID::zero();
        let mut info = ParticipantInfo::new(guid, vec![], 100_000);

        // Starts in Discovered state
        assert_eq!(info.state, FsmState::Discovered);

        // Can transition to Active
        info.state = FsmState::Active;
        assert_eq!(info.state, FsmState::Active);

        // Can transition to Announced
        info.state = FsmState::Announced;
        assert_eq!(info.state, FsmState::Announced);
    }
}
