// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Participant lease expiration tracking.
//!
//! Background thread (1 Hz) monitors participant leases and removes
//! stale entries from the database when their lease duration expires.

use crate::core::discovery::multicast::ParticipantDB;
use crate::core::discovery::GUID;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::thread::{self, JoinHandle};
use std::time::Duration;

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
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = Arc::clone(&stop_flag);

        let handle = thread::Builder::new()
            .name("hdds-lease-tracker".to_string())
            .spawn(move || {
                Self::run_loop(db, stop_flag_clone);
            })?;

        Ok(Self {
            stop_flag,
            handle: Some(handle),
        })
    }

    /// Main loop (runs in background thread)
    fn run_loop(db: Arc<RwLock<ParticipantDB>>, stop_flag: Arc<AtomicBool>) {
        while !stop_flag.load(Ordering::Relaxed) {
            // Sleep 1 second (1 Hz check rate)
            thread::sleep(Duration::from_secs(1));

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
                let mut db_guard =
                    recover_write(Arc::as_ref(&db), "LeaseTracker::run_loop remove expired");
                for guid in expired_guids {
                    db_guard.remove(&guid);
                }
            }
        }
    }

    /// Stop lease tracker gracefully
    ///
    /// Signals background thread to exit and waits for join.
    pub fn stop(mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for LeaseTracker {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
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
    use std::collections::HashMap;

    #[test]
    fn test_lease_tracker_start_stop() {
        let db = Arc::new(RwLock::new(HashMap::new()));
        let tracker =
            LeaseTracker::start(Arc::clone(&db)).expect("LeaseTracker start should succeed");

        // Wait briefly
        thread::sleep(Duration::from_millis(100));

        // Stop should be graceful
        tracker.stop();
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
}
