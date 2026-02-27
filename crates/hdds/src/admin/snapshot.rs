// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Snapshot structures for Admin API.
//!
//! Point-in-time views of mesh state (participants, topics, metrics)
//! cloned from Arc-wrapped internal structures using epoch-based retry.

/// Snapshot structures for Admin API
///
/// These structures represent point-in-time views of the mesh state.
/// They are cloned from Arc-wrapped internal structures using epoch-based retry.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard};

/// Mesh snapshot: participants and their endpoints
#[derive(Debug, Clone)]
pub struct MeshSnapshot {
    pub epoch: u64,
    pub participants: Vec<ParticipantView>,
}

/// View of a single participant
#[derive(Debug, Clone)]
pub struct ParticipantView {
    pub guid: String, // Hex format: "01.0f.ac.10..."
    pub name: String,
    pub is_local: bool,

    // T1+ discovery fields (optional for backward compatibility with T0)
    pub state: Option<String>, // FsmState: "Idle", "Announced", "Discovered", "Active"
    pub endpoints: Option<Vec<String>>, // SocketAddr as strings: ["192.168.1.100:7400"]
    pub lease_ms: Option<u64>, // Lease duration in milliseconds
    pub last_seen_ago_ms: Option<u64>, // Time since last SPDP (ms)
}

/// Topics snapshot: active topics and their metadata
#[derive(Debug, Clone)]
pub struct TopicsSnapshot {
    pub epoch: u64,
    pub topics: Vec<TopicView>,
}

/// View of a single topic
#[derive(Debug, Clone)]
pub struct TopicView {
    pub name: String,
    pub type_name: String,
    pub writers_count: usize,
    pub readers_count: usize,
}

/// Endpoint view for Admin API.
#[derive(Debug, Clone)]
pub struct EndpointView {
    pub guid: String,
    pub participant_guid: String,
    pub topic_name: String,
    pub type_name: String,
    pub reliability: String,
    pub durability: String,
    pub history: String,
}

/// Snapshot of endpoints (writers or readers).
#[derive(Debug, Clone)]
pub struct EndpointsSnapshot {
    pub epoch: u64,
    pub endpoints: Vec<EndpointView>,
}

/// Metrics snapshot: counters and statistics
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub epoch: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub messages_dropped: u64,
    pub latency_min_ns: u64,
    pub latency_p50_ns: u64,
    pub latency_p99_ns: u64,
    pub latency_max_ns: u64,
}

impl MetricsSnapshot {
    /// Create zero-initialized MetricsSnapshot for given epoch
    pub(crate) fn empty(epoch: u64) -> Self {
        Self {
            epoch,
            messages_sent: 0,
            messages_received: 0,
            messages_dropped: 0,
            latency_min_ns: 0,
            latency_p50_ns: 0,
            latency_p99_ns: 0,
            latency_max_ns: 0,
        }
    }
}

/// Internal database of participants (placeholder for T1+)
///
/// In Tier 0, there's no real discovery mesh, so this is minimal.
/// In T1+, this will contain SPDP/SEDP discovered participants.
#[derive(Debug, Clone, Default)]
pub struct ParticipantDB {
    pub participants: Vec<ParticipantView>,
}

impl ParticipantDB {
    pub fn new() -> Self {
        Self {
            participants: Vec::new(),
        }
    }

    pub fn set_local(&mut self, name: String) {
        // For Tier 0: add or replace participant with this name
        let exists = self.participants.iter().any(|p| p.name == name);

        if exists {
            // Update existing
            if let Some(p) = self.participants.iter_mut().find(|p| p.name == name) {
                p.name = name;
            }
        } else {
            // Add new participant
            let guid_num = self.participants.len() + 1;
            self.participants.push(ParticipantView {
                guid: format!("00.00.00.00.00.00.00.00.00.00.00.{:02}", guid_num),
                name,
                is_local: true,
                state: None,            // T0: No discovery state
                endpoints: None,        // T0: No endpoints
                lease_ms: None,         // T0: No lease
                last_seen_ago_ms: None, // T0: No last_seen
            });
        }
    }

    pub fn participants(&self) -> Vec<ParticipantView> {
        self.participants.clone()
    }
}

/// Helper: epoch-based snapshot with retry
///
/// Attempts to clone data without holding locks during epoch check.
/// Retries up to 3 times if epoch changes during clone.
pub fn snapshot_with_epoch<T, R, F>(epoch: &AtomicU64, data: &Arc<RwLock<T>>, extractor: F) -> R
where
    T: Clone,
    R: Clone,
    F: Fn(&T) -> R,
{
    const MAX_RETRIES: usize = 3;

    for attempt in 0..MAX_RETRIES {
        let epoch_before = epoch.load(Ordering::SeqCst);
        let snapshot = {
            let guard = recover_read(
                Arc::as_ref(data),
                "snapshot_with_epoch data.read() in_attempt",
            );
            extractor(&*guard)
        };
        let epoch_after = epoch.load(Ordering::SeqCst);

        if epoch_before == epoch_after {
            return snapshot; // Success: epoch stable
        }

        if attempt == MAX_RETRIES - 1 {
            // Max retries reached, return potentially stale snapshot
            log::debug!(
                "WARN: snapshot_with_epoch retry limit exceeded (epoch changed {} times)",
                attempt + 1
            );
        }
    }

    // Fallback: return last snapshot (may be slightly stale)
    let guard = recover_read(
        Arc::as_ref(data),
        "snapshot_with_epoch data.read() fallback",
    );
    extractor(&*guard)
}

/// Snapshot participants from DiscoveryFsm (T1+ multicast discovery)
///
/// Maps ParticipantInfo from DiscoveryFsm to ParticipantView for Admin API.
///
/// # Arguments
/// - `fsm`: Reference to DiscoveryFsm
///
/// # Returns
/// `Vec<ParticipantView>` with T1+ discovery fields populated
///
/// # Examples
/// ```no_run
/// use hdds::core::discovery::GUID;
/// use hdds::core::discovery::multicast::DiscoveryFsm;
/// use hdds::admin::snapshot::snapshot_participants;
///
/// let local_guid = GUID::zero();
/// let fsm = DiscoveryFsm::new(local_guid, 100_000);
/// let participants = snapshot_participants(&fsm);
/// ```
pub fn snapshot_participants(
    fsm: &crate::core::discovery::multicast::DiscoveryFsm,
) -> Vec<ParticipantView> {
    let participants_info = fsm.get_participants();

    participants_info
        .iter()
        .map(|info| {
            // Convert FsmState to string
            let state_str = match info.state {
                crate::core::discovery::multicast::FsmState::Idle => "Idle",
                crate::core::discovery::multicast::FsmState::Announced => "Announced",
                crate::core::discovery::multicast::FsmState::Discovered => "Discovered",
                crate::core::discovery::multicast::FsmState::Active => "Active",
            }
            .to_string();

            // Convert endpoints to Vec<String>
            let endpoints_str: Vec<String> =
                info.endpoints.iter().map(|addr| addr.to_string()).collect();

            // Calculate last_seen_ago_ms
            let last_seen_ago_ms = info.last_seen.elapsed().as_millis() as u64;

            ParticipantView {
                guid: info.guid.to_string(), // Uses GUID Display impl (hex with dots)
                name: String::new(),         // T1+: No name (use GUID)
                is_local: false,             // Remote participants (discovered via SPDP)
                state: Some(state_str),
                endpoints: Some(endpoints_str),
                lease_ms: Some(info.lease_duration_ms),
                last_seen_ago_ms: Some(last_seen_ago_ms),
            }
        })
        .collect()
}

fn recover_read<'a, T>(lock: &'a RwLock<T>, context: &str) -> RwLockReadGuard<'a, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::debug!("[admin] WARNING: {} poisoned, recovering", context);
            poisoned.into_inner()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_participant_db_empty() {
        let db = ParticipantDB::new();
        assert_eq!(db.participants().len(), 0);
    }

    #[test]
    fn test_participant_db_set_local() {
        let mut db = ParticipantDB::new();
        db.set_local("test_participant".to_string());
        let participants = db.participants();
        assert_eq!(participants.len(), 1);
        assert_eq!(participants[0].name, "test_participant");
        assert!(participants[0].is_local);
    }

    #[test]
    fn test_snapshot_with_epoch_stable() {
        let epoch = AtomicU64::new(1);
        let data = Arc::new(RwLock::new(42u64));

        let snapshot = snapshot_with_epoch(&epoch, &data, |val| *val);
        assert_eq!(snapshot, 42);
    }

    #[test]
    fn test_snapshot_with_epoch_retry() {
        use std::sync::atomic::AtomicBool;

        let epoch = AtomicU64::new(1);
        let data = Arc::new(RwLock::new(100u64));
        let mutated = Arc::new(AtomicBool::new(false));

        let epoch_clone = Arc::new(epoch);
        let mutated_clone = mutated.clone();
        let data_clone = data.clone();

        // Simulate concurrent mutation on first read
        let snapshot = snapshot_with_epoch(&epoch_clone, &data_clone, |val| {
            if !mutated_clone.load(Ordering::SeqCst) {
                // Simulate mutation during snapshot
                epoch_clone.fetch_add(1, Ordering::SeqCst);
                mutated_clone.store(true, Ordering::SeqCst);
            }
            *val
        });

        assert_eq!(snapshot, 100);
        // Epoch should have been incremented during retry
        assert_eq!(epoch_clone.load(Ordering::SeqCst), 2);
    }
}
