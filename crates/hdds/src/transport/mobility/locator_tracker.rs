// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Locator tracking with hold-down timers.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::detector::LocatorChange;

/// State of a tracked locator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocatorState {
    /// Locator is active (currently present on the system).
    Active,

    /// Locator is in hold-down (recently removed, still advertising).
    HoldDown,

    /// Locator is expired (hold-down complete, can be removed).
    Expired,
}

/// A tracked locator with state and timing information.
#[derive(Clone, Debug)]
pub struct TrackedLocator {
    /// The IP address.
    pub addr: IpAddr,

    /// Interface name this address is on.
    pub interface: String,

    /// Current state.
    pub state: LocatorState,

    /// When this locator was first seen.
    pub first_seen: Instant,

    /// When this locator was last updated.
    pub last_updated: Instant,

    /// When hold-down started (if in hold-down state).
    pub hold_down_start: Option<Instant>,
}

impl TrackedLocator {
    /// Create a new active locator.
    pub fn new(addr: IpAddr, interface: String) -> Self {
        let now = Instant::now();
        Self {
            addr,
            interface,
            state: LocatorState::Active,
            first_seen: now,
            last_updated: now,
            hold_down_start: None,
        }
    }

    /// Mark as active (refresh).
    pub fn mark_active(&mut self) {
        self.state = LocatorState::Active;
        self.last_updated = Instant::now();
        self.hold_down_start = None;
    }

    /// Mark as in hold-down.
    pub fn mark_hold_down(&mut self) {
        if self.state != LocatorState::HoldDown {
            self.state = LocatorState::HoldDown;
            self.hold_down_start = Some(Instant::now());
            self.last_updated = Instant::now();
        }
    }

    /// Check if hold-down has expired.
    pub fn is_hold_down_expired(&self, hold_down_duration: Duration) -> bool {
        match self.hold_down_start {
            Some(start) => start.elapsed() >= hold_down_duration,
            None => false,
        }
    }

    /// Get time remaining in hold-down.
    pub fn hold_down_remaining(&self, hold_down_duration: Duration) -> Option<Duration> {
        self.hold_down_start.map(|start| {
            let elapsed = start.elapsed();
            hold_down_duration.saturating_sub(elapsed)
        })
    }

    /// Get uptime (time since first seen).
    pub fn uptime(&self) -> Duration {
        self.first_seen.elapsed()
    }
}

/// Tracker for IP locators with hold-down support.
///
/// Tracks active IP addresses and applies hold-down timers when addresses
/// are removed to give in-flight messages time to be delivered.
pub struct LocatorTracker {
    /// Tracked locators by IP address.
    locators: HashMap<IpAddr, TrackedLocator>,

    /// Hold-down duration.
    hold_down: Duration,

    /// Last time we checked for expired locators.
    last_expiry_check: Instant,

    /// Minimum interval between expiry checks.
    expiry_check_interval: Duration,
}

impl LocatorTracker {
    /// Create a new locator tracker.
    pub fn new(hold_down: Duration) -> Self {
        Self {
            locators: HashMap::new(),
            hold_down,
            last_expiry_check: Instant::now(),
            expiry_check_interval: Duration::from_secs(1),
        }
    }

    /// Set expiry check interval.
    pub fn with_expiry_check_interval(mut self, interval: Duration) -> Self {
        self.expiry_check_interval = interval;
        self
    }

    /// Process a locator change event.
    ///
    /// Returns true if the change resulted in a state transition.
    pub fn process_change(&mut self, change: &LocatorChange) -> bool {
        use super::detector::LocatorChangeKind;

        match change.kind {
            LocatorChangeKind::Added => self.add_locator(change.addr, change.interface.clone()),
            LocatorChangeKind::Removed => self.remove_locator(&change.addr),
            LocatorChangeKind::Updated => {
                // Refresh existing locator
                if let Some(loc) = self.locators.get_mut(&change.addr) {
                    loc.mark_active();
                    true
                } else {
                    // New locator via update
                    self.add_locator(change.addr, change.interface.clone())
                }
            }
        }
    }

    /// Add or refresh a locator.
    ///
    /// Returns true if this is a new locator.
    pub fn add_locator(&mut self, addr: IpAddr, interface: String) -> bool {
        if let Some(loc) = self.locators.get_mut(&addr) {
            // Existing locator - refresh it
            loc.mark_active();
            false
        } else {
            // New locator
            self.locators
                .insert(addr, TrackedLocator::new(addr, interface));
            true
        }
    }

    /// Remove a locator (starts hold-down).
    ///
    /// Returns true if the locator existed and is now in hold-down.
    pub fn remove_locator(&mut self, addr: &IpAddr) -> bool {
        if let Some(loc) = self.locators.get_mut(addr) {
            if loc.state == LocatorState::Active {
                loc.mark_hold_down();
                return true;
            }
        }
        false
    }

    /// Get a locator by address.
    pub fn get(&self, addr: &IpAddr) -> Option<&TrackedLocator> {
        self.locators.get(addr)
    }

    /// Get all active locators.
    pub fn active_locators(&self) -> impl Iterator<Item = &TrackedLocator> {
        self.locators
            .values()
            .filter(|l| l.state == LocatorState::Active)
    }

    /// Get all advertisable locators (active + hold-down).
    pub fn advertisable_locators(&self) -> impl Iterator<Item = &TrackedLocator> {
        self.locators
            .values()
            .filter(|l| l.state == LocatorState::Active || l.state == LocatorState::HoldDown)
    }

    /// Get all locators in hold-down.
    pub fn hold_down_locators(&self) -> impl Iterator<Item = &TrackedLocator> {
        self.locators
            .values()
            .filter(|l| l.state == LocatorState::HoldDown)
    }

    /// Check for expired locators and remove them.
    ///
    /// Returns the number of expired locators removed.
    pub fn expire_locators(&mut self) -> usize {
        let now = Instant::now();

        // Rate limit expiry checks
        if now.duration_since(self.last_expiry_check) < self.expiry_check_interval {
            return 0;
        }
        self.last_expiry_check = now;

        let hold_down = self.hold_down;
        let expired: Vec<IpAddr> = self
            .locators
            .iter()
            .filter(|(_, loc)| {
                loc.state == LocatorState::HoldDown && loc.is_hold_down_expired(hold_down)
            })
            .map(|(addr, _)| *addr)
            .collect();

        let count = expired.len();
        for addr in expired {
            self.locators.remove(&addr);
        }

        count
    }

    /// Force expire all hold-down locators (for testing/shutdown).
    pub fn force_expire_all(&mut self) -> usize {
        let hold_down: Vec<IpAddr> = self
            .locators
            .iter()
            .filter(|(_, loc)| loc.state == LocatorState::HoldDown)
            .map(|(addr, _)| *addr)
            .collect();

        let count = hold_down.len();
        for addr in hold_down {
            self.locators.remove(&addr);
        }

        count
    }

    /// Sync with current IP addresses.
    ///
    /// Marks missing addresses as hold-down and adds new ones.
    /// Returns (added, removed) counts.
    pub fn sync_with_current(&mut self, current: &[(IpAddr, String)]) -> (usize, usize) {
        let current_set: std::collections::HashSet<IpAddr> =
            current.iter().map(|(addr, _)| *addr).collect();

        // Mark missing as hold-down
        let mut removed = 0;
        for (addr, loc) in self.locators.iter_mut() {
            if !current_set.contains(addr) && loc.state == LocatorState::Active {
                loc.mark_hold_down();
                removed += 1;
            }
        }

        // Add/refresh current
        let mut added = 0;
        for (addr, iface) in current {
            if self.add_locator(*addr, iface.clone()) {
                added += 1;
            }
        }

        (added, removed)
    }

    /// Get the number of tracked locators.
    pub fn len(&self) -> usize {
        self.locators.len()
    }

    /// Check if tracker is empty.
    pub fn is_empty(&self) -> bool {
        self.locators.is_empty()
    }

    /// Get statistics.
    pub fn stats(&self) -> TrackerStats {
        let mut active = 0;
        let mut hold_down = 0;

        for loc in self.locators.values() {
            match loc.state {
                LocatorState::Active => active += 1,
                LocatorState::HoldDown => hold_down += 1,
                LocatorState::Expired => {}
            }
        }

        TrackerStats {
            total: self.locators.len(),
            active,
            hold_down,
        }
    }

    /// Clear all tracked locators.
    pub fn clear(&mut self) {
        self.locators.clear();
    }

    /// Get hold-down duration.
    pub fn hold_down(&self) -> Duration {
        self.hold_down
    }

    /// Set hold-down duration.
    pub fn set_hold_down(&mut self, hold_down: Duration) {
        self.hold_down = hold_down;
    }
}

/// Statistics about tracked locators.
#[derive(Clone, Copy, Debug, Default)]
pub struct TrackerStats {
    /// Total number of tracked locators.
    pub total: usize,

    /// Number of active locators.
    pub active: usize,

    /// Number of locators in hold-down.
    pub hold_down: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn addr(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
    }

    #[test]
    fn test_tracked_locator_new() {
        let loc = TrackedLocator::new(addr(1), "eth0".to_string());
        assert_eq!(loc.addr, addr(1));
        assert_eq!(loc.interface, "eth0");
        assert_eq!(loc.state, LocatorState::Active);
        assert!(loc.hold_down_start.is_none());
    }

    #[test]
    fn test_tracked_locator_mark_active() {
        let mut loc = TrackedLocator::new(addr(1), "eth0".to_string());
        loc.mark_hold_down();
        assert_eq!(loc.state, LocatorState::HoldDown);

        loc.mark_active();
        assert_eq!(loc.state, LocatorState::Active);
        assert!(loc.hold_down_start.is_none());
    }

    #[test]
    fn test_tracked_locator_mark_hold_down() {
        let mut loc = TrackedLocator::new(addr(1), "eth0".to_string());
        loc.mark_hold_down();

        assert_eq!(loc.state, LocatorState::HoldDown);
        assert!(loc.hold_down_start.is_some());
    }

    #[test]
    fn test_tracked_locator_hold_down_expired() {
        let mut loc = TrackedLocator::new(addr(1), "eth0".to_string());
        loc.mark_hold_down();

        // Not expired with long duration
        assert!(!loc.is_hold_down_expired(Duration::from_secs(60)));

        // Expired with zero duration
        assert!(loc.is_hold_down_expired(Duration::ZERO));
    }

    #[test]
    fn test_tracked_locator_hold_down_remaining() {
        let loc = TrackedLocator::new(addr(1), "eth0".to_string());
        assert!(loc.hold_down_remaining(Duration::from_secs(30)).is_none());

        let mut loc2 = TrackedLocator::new(addr(2), "eth0".to_string());
        loc2.mark_hold_down();
        let remaining = loc2.hold_down_remaining(Duration::from_secs(30));
        assert!(remaining.is_some());
        assert!(remaining.unwrap() <= Duration::from_secs(30));
    }

    #[test]
    fn test_locator_tracker_new() {
        let tracker = LocatorTracker::new(Duration::from_secs(30));
        assert!(tracker.is_empty());
        assert_eq!(tracker.len(), 0);
        assert_eq!(tracker.hold_down(), Duration::from_secs(30));
    }

    #[test]
    fn test_locator_tracker_add() {
        let mut tracker = LocatorTracker::new(Duration::from_secs(30));

        // First add returns true (new)
        assert!(tracker.add_locator(addr(1), "eth0".to_string()));
        assert_eq!(tracker.len(), 1);

        // Second add returns false (refresh)
        assert!(!tracker.add_locator(addr(1), "eth0".to_string()));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn test_locator_tracker_remove() {
        let mut tracker = LocatorTracker::new(Duration::from_secs(30));
        tracker.add_locator(addr(1), "eth0".to_string());

        // Remove puts in hold-down
        assert!(tracker.remove_locator(&addr(1)));
        assert_eq!(tracker.len(), 1); // Still tracked

        let loc = tracker.get(&addr(1)).expect("should exist");
        assert_eq!(loc.state, LocatorState::HoldDown);

        // Second remove does nothing
        assert!(!tracker.remove_locator(&addr(1)));
    }

    #[test]
    fn test_locator_tracker_active_locators() {
        let mut tracker = LocatorTracker::new(Duration::from_secs(30));
        tracker.add_locator(addr(1), "eth0".to_string());
        tracker.add_locator(addr(2), "eth0".to_string());
        tracker.remove_locator(&addr(2));

        let active: Vec<_> = tracker.active_locators().collect();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].addr, addr(1));
    }

    #[test]
    fn test_locator_tracker_advertisable_locators() {
        let mut tracker = LocatorTracker::new(Duration::from_secs(30));
        tracker.add_locator(addr(1), "eth0".to_string());
        tracker.add_locator(addr(2), "eth0".to_string());
        tracker.remove_locator(&addr(2));

        let advertisable: Vec<_> = tracker.advertisable_locators().collect();
        assert_eq!(advertisable.len(), 2); // Both active and hold-down
    }

    #[test]
    fn test_locator_tracker_hold_down_locators() {
        let mut tracker = LocatorTracker::new(Duration::from_secs(30));
        tracker.add_locator(addr(1), "eth0".to_string());
        tracker.add_locator(addr(2), "eth0".to_string());
        tracker.remove_locator(&addr(2));

        let hold_down: Vec<_> = tracker.hold_down_locators().collect();
        assert_eq!(hold_down.len(), 1);
        assert_eq!(hold_down[0].addr, addr(2));
    }

    #[test]
    fn test_locator_tracker_expire() {
        let mut tracker = LocatorTracker::new(Duration::ZERO) // Immediate expiry
            .with_expiry_check_interval(Duration::ZERO);

        tracker.add_locator(addr(1), "eth0".to_string());
        tracker.remove_locator(&addr(1));

        let expired = tracker.expire_locators();
        assert_eq!(expired, 1);
        assert!(tracker.is_empty());
    }

    #[test]
    fn test_locator_tracker_force_expire() {
        let mut tracker = LocatorTracker::new(Duration::from_secs(3600)); // Long hold-down

        tracker.add_locator(addr(1), "eth0".to_string());
        tracker.add_locator(addr(2), "eth0".to_string());
        tracker.remove_locator(&addr(1));
        tracker.remove_locator(&addr(2));

        let expired = tracker.force_expire_all();
        assert_eq!(expired, 2);
        assert!(tracker.is_empty());
    }

    #[test]
    fn test_locator_tracker_sync() {
        let mut tracker = LocatorTracker::new(Duration::from_secs(30));
        tracker.add_locator(addr(1), "eth0".to_string());
        tracker.add_locator(addr(2), "eth0".to_string());

        // Sync with new state: addr(1) still there, addr(2) gone, addr(3) new
        let current = vec![(addr(1), "eth0".to_string()), (addr(3), "eth0".to_string())];
        let (added, removed) = tracker.sync_with_current(&current);

        assert_eq!(added, 1); // addr(3)
        assert_eq!(removed, 1); // addr(2)

        let loc2 = tracker.get(&addr(2)).expect("should exist in hold-down");
        assert_eq!(loc2.state, LocatorState::HoldDown);
    }

    #[test]
    fn test_locator_tracker_stats() {
        let mut tracker = LocatorTracker::new(Duration::from_secs(30));
        tracker.add_locator(addr(1), "eth0".to_string());
        tracker.add_locator(addr(2), "eth0".to_string());
        tracker.remove_locator(&addr(2));

        let stats = tracker.stats();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.active, 1);
        assert_eq!(stats.hold_down, 1);
    }

    #[test]
    fn test_locator_tracker_clear() {
        let mut tracker = LocatorTracker::new(Duration::from_secs(30));
        tracker.add_locator(addr(1), "eth0".to_string());
        tracker.add_locator(addr(2), "eth0".to_string());

        tracker.clear();
        assert!(tracker.is_empty());
    }

    #[test]
    fn test_locator_tracker_set_hold_down() {
        let mut tracker = LocatorTracker::new(Duration::from_secs(30));
        tracker.set_hold_down(Duration::from_secs(60));
        assert_eq!(tracker.hold_down(), Duration::from_secs(60));
    }

    #[test]
    fn test_tracked_locator_uptime() {
        let loc = TrackedLocator::new(addr(1), "eth0".to_string());
        std::thread::sleep(Duration::from_millis(10));
        assert!(loc.uptime() >= Duration::from_millis(10));
    }

    #[test]
    fn test_locator_state_variants() {
        assert_eq!(LocatorState::Active, LocatorState::Active);
        assert_ne!(LocatorState::Active, LocatorState::HoldDown);
        assert_ne!(LocatorState::HoldDown, LocatorState::Expired);
    }
}
