// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Participant lease expiration tracking.
//!
//! Background thread (1 Hz) monitors participant leases and removes
//! stale entries from the database when their lease duration expires.

use crate::core::discovery::multicast::{DiscoveryFsm, ParticipantDB};
use crate::core::discovery::GUID;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// How often the leases are checked.
const CHECK_PERIOD: Duration = Duration::from_secs(1);

/// Lease tracker for participant expiration
///
/// Spawns background thread (1 Hz) to check for expired participants
/// and remove them from the database.
///
/// # Architecture
/// - Background thread loops every 1 second
/// - Reads ParticipantDB (RwLock::read)
/// - Collects expired GUIDs
/// - Removes expired participants (RwLock::write)
///
/// # Graceful Shutdown
/// Call `stop()` to signal thread to exit and wait for join.
pub struct LeaseTracker {
    /// Stop flag for graceful shutdown
    stop_flag: Arc<AtomicBool>,
    /// Background thread handle
    handle: Option<JoinHandle<()>>,
}

impl LeaseTracker {
    /// Start lease tracker background thread
    ///
    /// Spawns thread that checks for expired participants every second.
    ///
    /// # Arguments
    /// * `db` - Shared participant database (`Arc<RwLock<ParticipantDB>>`).
    ///
    /// # Returns
    /// Lease tracker instance for shutdown control.
    ///
    /// # Examples
    /// ```no_run
    /// use hdds::core::discovery::multicast::{LeaseTracker, ParticipantDB};
    /// use std::sync::{Arc, RwLock};
    /// use std::collections::HashMap;
    ///
    /// let db = Arc::new(RwLock::new(HashMap::new()));
    /// let tracker = LeaseTracker::start(db).expect("Failed to start lease tracker");
    ///
    /// // ... system runs ...
    ///
    /// tracker.stop(); // Graceful shutdown
    /// ```
    pub fn start(db: Arc<RwLock<ParticipantDB>>) -> std::io::Result<Self> {
        Self::start_inner(db, None)
    }

    pub(crate) fn start_with_fsm(fsm: Arc<DiscoveryFsm>) -> std::io::Result<Self> {
        Self::start_inner(fsm.db(), Some(fsm))
    }

    fn start_inner(
        db: Arc<RwLock<ParticipantDB>>,
        fsm: Option<Arc<DiscoveryFsm>>,
    ) -> std::io::Result<Self> {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = Arc::clone(&stop_flag);

        let handle = thread::Builder::new()
            .name("hdds-lease-tracker".to_string())
            .spawn(crate::core::rt::shutdown::owned(move || {
                Self::run_loop(db, fsm, stop_flag_clone);
            }))?;

        Ok(Self {
            stop_flag,
            handle: Some(handle),
        })
    }

    /// Main loop (runs in background thread)
    fn run_loop(
        db: Arc<RwLock<ParticipantDB>>,
        fsm: Option<Arc<DiscoveryFsm>>,
        stop_flag: Arc<AtomicBool>,
    ) {
        while !stop_flag.load(Ordering::Relaxed) {
            // 1 Hz check rate. Parked rather than asleep: `stop` unparks
            // us, so the participant's drop does not wait out the second.
            let wake_at = Instant::now() + CHECK_PERIOD;
            loop {
                if stop_flag.load(Ordering::Relaxed) {
                    return;
                }
                let now = Instant::now();
                if now >= wake_at {
                    break;
                }
                thread::park_timeout(wake_at - now);
            }

            // Check for expired participants
            let expired_guids: Vec<GUID> = {
                let db_guard =
                    recover_read(Arc::as_ref(&db), "LeaseTracker::run_loop collect expired");
                db_guard
                    .iter()
                    .filter(|(_, info)| info.is_expired())
                    .map(|(guid, _)| *guid)
                    .collect()
            };

            // Remove expired participants
            if !expired_guids.is_empty() {
                if let Some(ref fsm) = fsm {
                    for guid in expired_guids {
                        fsm.remove_expired_participant(guid);
                    }
                } else {
                    let mut db_guard =
                        recover_write(Arc::as_ref(&db), "LeaseTracker::run_loop remove expired");
                    for guid in expired_guids {
                        if db_guard.get(&guid).is_some_and(|info| info.is_expired()) {
                            db_guard.remove(&guid);
                        }
                    }
                }
            }
        }
    }

    /// Stop lease tracker gracefully
    ///
    /// Signals background thread to exit and waits for join.
    pub fn stop(mut self) {
        self.shut_down();
    }

    fn shut_down(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.thread().unpark();
            crate::core::rt::shutdown::join_bounded(handle, "lease tracker");
        }
    }
}

impl Drop for LeaseTracker {
    fn drop(&mut self) {
        self.shut_down();
    }
}

/// Macro to generate poisoned lock recovery functions (eliminates duplication)
///
/// Generates `recover_read` and `recover_write` with identical error handling.
macro_rules! impl_recover_lock {
    ($fn_name:ident, $lock_method:ident, $guard_type:ty) => {
        fn $fn_name<'a, T>(lock: &'a RwLock<T>, context: &str) -> $guard_type {
            match lock.$lock_method() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    log::debug!("[discovery] WARNING: {} poisoned, recovering", context);
                    poisoned.into_inner()
                }
            }
        }
    };
}

impl_recover_lock!(recover_read, read, RwLockReadGuard<'a, T>);
impl_recover_lock!(recover_write, write, RwLockWriteGuard<'a, T>);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::discovery::multicast::ParticipantInfo;
    use crate::core::discovery::GUID;
    use crate::protocol::discovery::SedpData;
    use std::collections::HashMap;

    #[test]
    fn test_lease_tracker_start_stop() {
        let db = Arc::new(RwLock::new(HashMap::new()));
        let tracker =
            LeaseTracker::start(Arc::clone(&db)).expect("LeaseTracker start should succeed");

        // Wait briefly
        thread::sleep(Duration::from_millis(100));

        // Stop should be graceful, and prompt: it does not wait out the
        // tracker's one-second period (a participant's drop waits for it).
        let start = std::time::Instant::now();
        tracker.stop();
        let took = start.elapsed();
        assert!(
            took < Duration::from_millis(500),
            "stopping the lease tracker took {took:?}"
        );
    }

    #[test]
    fn test_lease_tracker_removes_expired() {
        let db = Arc::new(RwLock::new(HashMap::new()));

        // Insert participant with very short lease (100ms)
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let info = ParticipantInfo::new(guid, vec![], 100); // 100ms lease

        {
            let mut db_lock =
                super::recover_write(Arc::as_ref(&db), "LeaseTracker::tests insert participant");
            db_lock.insert(guid, info);
        }

        // Start tracker
        let tracker =
            LeaseTracker::start(Arc::clone(&db)).expect("LeaseTracker start should succeed");

        // Wait for lease to expire + tracker to run (1s check interval + margin)
        thread::sleep(Duration::from_millis(1200));

        // Check participant removed
        let db_lock = super::recover_read(
            Arc::as_ref(&db),
            "LeaseTracker::tests check participant removed",
        );
        assert!(!db_lock.contains_key(&guid));

        tracker.stop();
    }

    #[test]
    fn test_lease_tracker_retains_active() {
        let db = Arc::new(RwLock::new(HashMap::new()));

        // Insert participant with long lease (10 seconds)
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let info = ParticipantInfo::new(guid, vec![], 10_000); // 10s lease

        {
            let mut db_lock = db.write().expect("RwLock write should succeed");
            db_lock.insert(guid, info);
        }

        // Start tracker
        let tracker =
            LeaseTracker::start(Arc::clone(&db)).expect("LeaseTracker start should succeed");

        // Wait briefly (much less than lease)
        thread::sleep(Duration::from_millis(1200));

        // Check participant still present
        let db_lock = super::recover_read(
            Arc::as_ref(&db),
            "LeaseTracker::tests check participant retained",
        );
        assert!(db_lock.contains_key(&guid));

        tracker.stop();
    }

    #[test]
    fn fsm_lease_tracker_removes_participant_endpoints() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let participant_guid =
            GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 1, 0xc1]);
        let mut endpoint_bytes = participant_guid.as_bytes();
        endpoint_bytes[15] = 0x02;
        let endpoint_guid = GUID::from_bytes(endpoint_bytes);

        fsm.handle_spdp(crate::protocol::discovery::spdp::SpdpData {
            participant_guid,
            lease_duration_ms: 100,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        fsm.handle_sedp(SedpData {
            topic_name: "lease/cleanup".to_string(),
            type_name: "LeaseCleanupType".to_string(),
            participant_guid,
            endpoint_guid,
            qos_hash: 1,
            qos: None,
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });
        assert_eq!(fsm.find_writers_for_topic("lease/cleanup").len(), 1);

        let tracker =
            LeaseTracker::start_with_fsm(Arc::clone(&fsm)).expect("FSM lease tracker should start");
        thread::sleep(Duration::from_millis(1_200));

        assert!(fsm.get_participants().is_empty());
        assert!(
            fsm.find_writers_for_topic("lease/cleanup").is_empty(),
            "lease expiry must remove participant endpoints through the FSM"
        );
        tracker.stop();
    }
}
