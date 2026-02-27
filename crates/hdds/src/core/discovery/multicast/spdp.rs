// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SPDP participant discovery state and metadata.
//!
//! Defines FSM states and `ParticipantInfo` for tracking discovered peers.
//! Each participant transitions through: Idle -> Announced -> Discovered -> Active.

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
}

impl ParticipantInfo {
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
        Self {
            guid,
            endpoints,
            lease_duration_ms,
            last_seen: Instant::now(),
            state: FsmState::Discovered,
        }
    }

    /// Check if participant lease has expired
    ///
    /// Returns true if `Instant::now() > last_seen + lease_duration`
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
        let elapsed = self.last_seen.elapsed();
        elapsed.as_millis() as u64 > self.lease_duration_ms
    }

    /// Refresh last_seen timestamp (called on SPDP reception)
    ///
    /// Updates last_seen to current time, resetting the lease timer.
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
    fn test_participant_refresh() {
        let guid = GUID::zero();
        let mut info = ParticipantInfo::new(guid, vec![], 100_000);

        // Wait a bit
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Refresh should reset timer
        info.refresh();

        // Should not be expired
        assert!(!info.is_expired());
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
