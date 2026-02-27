// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Mobility manager - state machine coordinating IP mobility.
//!
//! The `MobilityManager` orchestrates IP change detection, locator tracking,
//! and reannounce bursts to maintain connectivity during IP transitions.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::config::MobilityConfig;
use super::detector::{IpDetector, LocatorChangeKind};
use super::host_id::generate_host_id;
use super::locator_tracker::LocatorTracker;
use super::metrics::MobilityMetrics;
use super::parameter::MobilityParameter;
use super::reannounce::{ReannounceBurst, ReannounceController};

/// Mobility state machine states.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MobilityState {
    /// No recent changes, stable connectivity.
    #[default]
    Stable,

    /// IP change detected, preparing reannounce.
    Changed,

    /// Actively sending reannounce burst.
    Reannouncing,
}

/// Callback for mobility events.
pub trait MobilityCallback: Send {
    /// Called when a reannounce should be sent.
    fn on_reannounce(&mut self, announcement_index: usize);

    /// Called when mobility state changes.
    fn on_state_change(&mut self, old: MobilityState, new: MobilityState);

    /// Called when locators change.
    fn on_locators_changed(&mut self, added: &[IpAddr], removed: &[IpAddr]);
}

/// Default no-op callback that ignores all mobility events.
///
/// Use this when you don't need to react to mobility state changes.
/// For custom behavior, implement [`MobilityCallback`] directly.
pub struct NoopCallback;

impl MobilityCallback for NoopCallback {
    /// No-op: ignores reannounce events.
    fn on_reannounce(&mut self, _announcement_index: usize) {
        // Intentionally empty - NoopCallback discards all events.
    }

    /// No-op: ignores state change events.
    fn on_state_change(&mut self, _old: MobilityState, _new: MobilityState) {
        // Intentionally empty - NoopCallback discards all events.
    }

    /// No-op: ignores locator change events.
    fn on_locators_changed(&mut self, _added: &[IpAddr], _removed: &[IpAddr]) {
        // Intentionally empty - NoopCallback discards all events.
    }
}

/// Manager coordinating IP mobility detection and response.
pub struct MobilityManager<D: IpDetector, C: MobilityCallback = NoopCallback> {
    /// Configuration.
    config: MobilityConfig,

    /// IP change detector.
    detector: D,

    /// Locator tracker with hold-down.
    tracker: LocatorTracker,

    /// Reannounce controller.
    reannounce: ReannounceController,

    /// Current state.
    state: MobilityState,

    /// Mobility epoch (incremented on each IP change).
    epoch: u32,

    /// Stable host ID.
    host_id: u64,

    /// Event callback.
    callback: C,

    /// Metrics.
    metrics: Arc<MobilityMetrics>,

    /// Last poll time.
    last_poll: Instant,

    /// Last state transition time.
    last_transition: Instant,

    /// Whether manager is enabled.
    enabled: bool,
}

impl<D: IpDetector> MobilityManager<D, NoopCallback> {
    /// Create a new mobility manager with default callback.
    pub fn new(config: MobilityConfig, detector: D) -> Self {
        Self::with_callback(config, detector, NoopCallback)
    }
}

impl<D: IpDetector, C: MobilityCallback> MobilityManager<D, C> {
    /// Create a new mobility manager with custom callback.
    pub fn with_callback(config: MobilityConfig, detector: D, callback: C) -> Self {
        let tracker = LocatorTracker::new(config.hold_down);

        let burst_config = ReannounceBurst {
            delays: vec![
                Duration::ZERO,
                config.reannounce_delay,
                config.reannounce_delay * 3,
                Duration::from_secs(1),
                Duration::from_secs(3),
            ],
            jitter_percent: 20,
            min_burst_interval: config.min_burst_interval,
        };
        let reannounce = ReannounceController::new(burst_config);

        let now = Instant::now();

        Self {
            enabled: config.enabled,
            config,
            detector,
            tracker,
            reannounce,
            state: MobilityState::Stable,
            epoch: 0,
            host_id: generate_host_id(),
            callback,
            metrics: Arc::new(MobilityMetrics::new()),
            last_poll: now,
            last_transition: now,
        }
    }

    /// Poll for IP changes and process them.
    ///
    /// Returns true if any changes were detected.
    pub fn poll(&mut self) -> bool {
        if !self.enabled {
            return false;
        }

        self.last_poll = Instant::now();
        self.metrics.record_poll();

        // Poll detector for changes
        let changes = match self.detector.poll_changes() {
            Ok(changes) => changes,
            Err(_e) => {
                // Log error in production
                return false;
            }
        };

        if changes.is_empty() {
            // Still poll reannounce controller
            self.poll_reannounce();
            return false;
        }

        // Process changes
        let mut has_significant_change = false;
        let mut added = Vec::new();
        let mut removed = Vec::new();

        for change in &changes {
            // Apply filters
            if !self.config.should_track_interface(&change.interface) {
                continue;
            }
            if !self.config.should_track_address(&change.addr) {
                continue;
            }

            let was_change = self.tracker.process_change(change);
            if was_change {
                has_significant_change = true;

                match change.kind {
                    LocatorChangeKind::Added => {
                        self.metrics.record_address_added();
                        added.push(change.addr);
                    }
                    LocatorChangeKind::Removed => {
                        self.metrics.record_address_removed();
                        removed.push(change.addr);
                    }
                    LocatorChangeKind::Updated => {
                        // Updated doesn't trigger reannounce
                    }
                }
            }
        }

        // Update metrics with current counts
        let stats = self.tracker.stats();
        self.metrics
            .update_locator_counts(stats.active as u64, stats.hold_down as u64);

        // Expire old locators
        let expired = self.tracker.expire_locators();
        if expired > 0 {
            self.metrics.record_locators_expired(expired as u64);
        }

        // Notify callback of locator changes
        if !added.is_empty() || !removed.is_empty() {
            self.callback.on_locators_changed(&added, &removed);
        }

        // Trigger reannounce if significant changes
        if has_significant_change && (!added.is_empty() || !removed.is_empty()) {
            self.on_ip_change();
        }

        // Poll reannounce controller
        self.poll_reannounce();

        has_significant_change
    }

    /// Handle IP change - transition state and start reannounce.
    fn on_ip_change(&mut self) {
        let old_state = self.state;

        // Increment epoch
        self.epoch = self.epoch.wrapping_add(1);

        // Transition to Changed state
        self.set_state(MobilityState::Changed);

        // Start reannounce burst
        if self.reannounce.start_burst() {
            self.set_state(MobilityState::Reannouncing);
        }

        if old_state != self.state {
            self.callback.on_state_change(old_state, self.state);
        }
    }

    /// Poll reannounce controller and send announcements.
    fn poll_reannounce(&mut self) {
        if self.state != MobilityState::Reannouncing {
            return;
        }

        // Poll for next announcement
        if let Some(index) = self.reannounce.poll() {
            self.callback.on_reannounce(index);
        }

        // Check if burst is complete
        if self.reannounce.is_complete() {
            let burst_count = self.reannounce.config().count() as u64;
            self.metrics.record_reannounce_burst(burst_count);
            self.reannounce.reset();
            self.set_state(MobilityState::Stable);
        }
    }

    /// Set state with transition tracking.
    fn set_state(&mut self, new_state: MobilityState) {
        if self.state != new_state {
            let old = self.state;
            self.state = new_state;
            self.last_transition = Instant::now();
            self.callback.on_state_change(old, new_state);
        }
    }

    /// Manually trigger reannounce (e.g., from application callback).
    pub fn trigger_reannounce(&mut self) {
        if !self.enabled {
            return;
        }

        // Increment epoch
        self.epoch = self.epoch.wrapping_add(1);

        if self.reannounce.start_burst() {
            self.set_state(MobilityState::Reannouncing);
        }
    }

    /// Manually notify of IP change.
    ///
    /// Useful when application knows about IP change before detector.
    pub fn notify_ip_change(&mut self) {
        if !self.enabled {
            return;
        }

        // Get current addresses from detector and sync
        if let Ok(current) = self.detector.current_addresses() {
            let (added, removed) = self.tracker.sync_with_current(&current);
            if added > 0 || removed > 0 {
                self.on_ip_change();
            }
        }
    }

    /// Get current mobility state.
    pub fn state(&self) -> MobilityState {
        self.state
    }

    /// Get current epoch.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Get host ID.
    pub fn host_id(&self) -> u64 {
        self.host_id
    }

    /// Get mobility parameter for SPDP announcements.
    pub fn mobility_parameter(&self) -> MobilityParameter {
        let locators: Vec<IpAddr> = self.tracker.active_locators().map(|l| l.addr).collect();

        MobilityParameter::from_state(self.epoch, self.host_id, &locators)
    }

    /// Get all advertisable locators (active + hold-down).
    pub fn advertisable_locators(&self) -> Vec<IpAddr> {
        self.tracker
            .advertisable_locators()
            .map(|l| l.addr)
            .collect()
    }

    /// Get active locators only.
    pub fn active_locators(&self) -> Vec<IpAddr> {
        self.tracker.active_locators().map(|l| l.addr).collect()
    }

    /// Get time in current state.
    pub fn time_in_state(&self) -> Duration {
        self.last_transition.elapsed()
    }

    /// Get time until next announcement (if reannouncing).
    pub fn time_until_next_announce(&self) -> Option<Duration> {
        if self.state == MobilityState::Reannouncing {
            self.reannounce.time_until_next()
        } else {
            None
        }
    }

    /// Check if manager is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the manager.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            // Cancel any in-progress burst
            self.reannounce.cancel();
            self.state = MobilityState::Stable;
        }
    }

    /// Get reference to configuration.
    pub fn config(&self) -> &MobilityConfig {
        &self.config
    }

    /// Get reference to tracker.
    pub fn tracker(&self) -> &LocatorTracker {
        &self.tracker
    }

    /// Get reference to detector.
    pub fn detector(&self) -> &D {
        &self.detector
    }

    /// Get mutable reference to detector.
    pub fn detector_mut(&mut self) -> &mut D {
        &mut self.detector
    }

    /// Get reference to reannounce controller.
    pub fn reannounce_controller(&self) -> &ReannounceController {
        &self.reannounce
    }

    /// Get metrics.
    pub fn metrics(&self) -> Arc<MobilityMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Get statistics snapshot.
    pub fn stats(&self) -> MobilityManagerStats {
        MobilityManagerStats {
            state: self.state,
            epoch: self.epoch,
            host_id: self.host_id,
            active_locators: self.tracker.stats().active,
            hold_down_locators: self.tracker.stats().hold_down,
            time_in_state: self.time_in_state(),
            reannounce_progress: if self.state == MobilityState::Reannouncing {
                Some(self.reannounce.progress())
            } else {
                None
            },
            metrics: self.metrics.snapshot(),
        }
    }

    /// Update hold-down duration.
    pub fn set_hold_down(&mut self, duration: Duration) {
        self.tracker.set_hold_down(duration);
    }

    /// Update reannounce configuration.
    pub fn set_reannounce_config(&mut self, config: ReannounceBurst) {
        self.reannounce.set_config(config);
    }
}

/// Statistics for mobility manager.
#[derive(Clone, Debug)]
pub struct MobilityManagerStats {
    /// Current state.
    pub state: MobilityState,

    /// Current epoch.
    pub epoch: u32,

    /// Host ID.
    pub host_id: u64,

    /// Number of active locators.
    pub active_locators: usize,

    /// Number of hold-down locators.
    pub hold_down_locators: usize,

    /// Time in current state.
    pub time_in_state: Duration,

    /// Reannounce progress (if reannouncing).
    pub reannounce_progress: Option<f32>,

    /// Metrics snapshot.
    pub metrics: super::metrics::MobilityMetricsSnapshot,
}

impl MobilityManagerStats {
    /// Total locators (active + hold-down).
    pub fn total_locators(&self) -> usize {
        self.active_locators + self.hold_down_locators
    }

    /// Check if stable.
    pub fn is_stable(&self) -> bool {
        self.state == MobilityState::Stable
    }

    /// Check if reannouncing.
    pub fn is_reannouncing(&self) -> bool {
        self.state == MobilityState::Reannouncing
    }
}

#[cfg(test)]
mod tests {
    use super::super::detector::LocatorChange;
    use super::*;
    use std::io;
    use std::net::Ipv4Addr;

    /// Mock detector for testing.
    struct MockDetector {
        changes: Vec<LocatorChange>,
        addresses: Vec<(IpAddr, String)>,
    }

    impl MockDetector {
        fn new() -> Self {
            Self {
                changes: Vec::new(),
                addresses: Vec::new(),
            }
        }

        fn add_change(&mut self, change: LocatorChange) {
            self.changes.push(change);
        }

        fn set_addresses(&mut self, addresses: Vec<(IpAddr, String)>) {
            self.addresses = addresses;
        }
    }

    impl IpDetector for MockDetector {
        fn poll_changes(&mut self) -> io::Result<Vec<LocatorChange>> {
            Ok(std::mem::take(&mut self.changes))
        }

        fn current_addresses(&self) -> io::Result<Vec<(IpAddr, String)>> {
            Ok(self.addresses.clone())
        }

        fn name(&self) -> &str {
            "mock"
        }
    }

    /// Tracking callback for testing.
    struct TrackingCallback {
        reannounces: Vec<usize>,
        state_changes: Vec<(MobilityState, MobilityState)>,
        locator_changes: Vec<(Vec<IpAddr>, Vec<IpAddr>)>,
    }

    impl TrackingCallback {
        fn new() -> Self {
            Self {
                reannounces: Vec::new(),
                state_changes: Vec::new(),
                locator_changes: Vec::new(),
            }
        }
    }

    impl MobilityCallback for TrackingCallback {
        fn on_reannounce(&mut self, index: usize) {
            self.reannounces.push(index);
        }

        fn on_state_change(&mut self, old: MobilityState, new: MobilityState) {
            self.state_changes.push((old, new));
        }

        fn on_locators_changed(&mut self, added: &[IpAddr], removed: &[IpAddr]) {
            self.locator_changes
                .push((added.to_vec(), removed.to_vec()));
        }
    }

    fn addr(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
    }

    fn make_config() -> MobilityConfig {
        use super::super::config::{AddressFilter, InterfaceFilter};

        MobilityConfig {
            enabled: true,
            hold_down: Duration::from_millis(100),
            min_burst_interval: Duration::ZERO,
            interface_filter: InterfaceFilter::all(),
            address_filter: AddressFilter::all(),
            ..Default::default()
        }
    }

    #[test]
    fn test_manager_new() {
        let config = make_config();
        let detector = MockDetector::new();
        let manager = MobilityManager::new(config, detector);

        assert_eq!(manager.state(), MobilityState::Stable);
        assert_eq!(manager.epoch(), 0);
        assert!(manager.is_enabled());
    }

    #[test]
    fn test_manager_poll_no_changes() {
        let config = make_config();
        let detector = MockDetector::new();
        let mut manager = MobilityManager::new(config, detector);

        let changed = manager.poll();
        assert!(!changed);
        assert_eq!(manager.state(), MobilityState::Stable);
    }

    #[test]
    fn test_manager_poll_with_add() {
        let config = make_config();
        let mut detector = MockDetector::new();
        detector.add_change(LocatorChange::added(addr(1), "eth0".to_string()));

        let mut manager = MobilityManager::new(config, detector);

        let changed = manager.poll();
        assert!(changed);
        assert_eq!(manager.epoch(), 1);
        // Should transition through Changed to Reannouncing
        assert!(
            manager.state() == MobilityState::Changed
                || manager.state() == MobilityState::Reannouncing
        );
    }

    #[test]
    fn test_manager_poll_with_remove() {
        let config = make_config();
        let mut detector = MockDetector::new();

        // First add an address
        detector.add_change(LocatorChange::added(addr(1), "eth0".to_string()));
        let mut manager = MobilityManager::new(config, detector);
        manager.poll();

        // Complete reannounce
        while manager.state() == MobilityState::Reannouncing {
            manager.poll();
        }

        // Now remove it
        manager
            .detector_mut()
            .add_change(LocatorChange::removed(addr(1), "eth0".to_string()));
        let changed = manager.poll();

        assert!(changed);
        assert!(manager.epoch() >= 2);
    }

    #[test]
    fn test_manager_callback_reannounce() {
        use super::super::config::{AddressFilter, InterfaceFilter};

        let config = MobilityConfig {
            enabled: true,
            hold_down: Duration::from_millis(100),
            min_burst_interval: Duration::ZERO,
            reannounce_delay: Duration::ZERO, // Immediate
            interface_filter: InterfaceFilter::all(),
            address_filter: AddressFilter::all(),
            ..Default::default()
        };
        let mut detector = MockDetector::new();
        detector.add_change(LocatorChange::added(addr(1), "eth0".to_string()));

        let callback = TrackingCallback::new();
        let mut manager = MobilityManager::with_callback(config, detector, callback);

        // Poll multiple times to process burst
        for _ in 0..10 {
            manager.poll();
        }

        // Should have received reannounces
        assert!(!manager.callback.reannounces.is_empty());
    }

    #[test]
    fn test_manager_callback_state_changes() {
        let config = make_config();
        let mut detector = MockDetector::new();
        detector.add_change(LocatorChange::added(addr(1), "eth0".to_string()));

        let callback = TrackingCallback::new();
        let mut manager = MobilityManager::with_callback(config, detector, callback);

        manager.poll();

        // Should have state change records
        assert!(!manager.callback.state_changes.is_empty());
    }

    #[test]
    fn test_manager_callback_locator_changes() {
        let config = make_config();
        let mut detector = MockDetector::new();
        detector.add_change(LocatorChange::added(addr(1), "eth0".to_string()));

        let callback = TrackingCallback::new();
        let mut manager = MobilityManager::with_callback(config, detector, callback);

        manager.poll();

        // Should have locator change records
        assert!(!manager.callback.locator_changes.is_empty());
        let (added, removed) = &manager.callback.locator_changes[0];
        assert!(added.contains(&addr(1)));
        assert!(removed.is_empty());
    }

    #[test]
    fn test_manager_trigger_reannounce() {
        let config = make_config();
        let detector = MockDetector::new();
        let mut manager = MobilityManager::new(config, detector);

        assert_eq!(manager.state(), MobilityState::Stable);

        manager.trigger_reannounce();

        assert_eq!(manager.state(), MobilityState::Reannouncing);
        assert_eq!(manager.epoch(), 1);
    }

    #[test]
    fn test_manager_notify_ip_change() {
        let config = make_config();
        let mut detector = MockDetector::new();
        detector.set_addresses(vec![(addr(1), "eth0".to_string())]);

        let mut manager = MobilityManager::new(config, detector);

        manager.notify_ip_change();

        // Should have triggered reannounce
        assert!(
            manager.state() == MobilityState::Changed
                || manager.state() == MobilityState::Reannouncing
        );
    }

    #[test]
    fn test_manager_mobility_parameter() {
        let config = make_config();
        let mut detector = MockDetector::new();
        detector.add_change(LocatorChange::added(addr(1), "eth0".to_string()));

        let mut manager = MobilityManager::new(config, detector);
        manager.poll();

        let param = manager.mobility_parameter();
        assert_eq!(param.epoch, manager.epoch());
        assert_eq!(param.host_id, manager.host_id());
    }

    #[test]
    fn test_manager_advertisable_locators() {
        use super::super::config::{AddressFilter, InterfaceFilter};

        let config = MobilityConfig {
            enabled: true,
            hold_down: Duration::from_secs(3600), // Long hold-down
            min_burst_interval: Duration::ZERO,
            interface_filter: InterfaceFilter::all(),
            address_filter: AddressFilter::all(),
            ..Default::default()
        };
        let mut detector = MockDetector::new();
        detector.add_change(LocatorChange::added(addr(1), "eth0".to_string()));

        let mut manager = MobilityManager::new(config, detector);
        manager.poll();

        // Complete reannounce
        while manager.state() == MobilityState::Reannouncing {
            manager.poll();
        }

        // Add another, remove first
        manager
            .detector_mut()
            .add_change(LocatorChange::added(addr(2), "eth0".to_string()));
        manager
            .detector_mut()
            .add_change(LocatorChange::removed(addr(1), "eth0".to_string()));
        manager.poll();

        // Should have both (one active, one hold-down)
        let advertisable = manager.advertisable_locators();
        assert_eq!(advertisable.len(), 2);

        // Active should only have addr(2)
        let active = manager.active_locators();
        assert_eq!(active.len(), 1);
        assert!(active.contains(&addr(2)));
    }

    #[test]
    fn test_manager_disabled() {
        let mut config = make_config();
        config.enabled = false;

        let mut detector = MockDetector::new();
        detector.add_change(LocatorChange::added(addr(1), "eth0".to_string()));

        let mut manager = MobilityManager::new(config, detector);

        let changed = manager.poll();
        assert!(!changed);
        assert_eq!(manager.state(), MobilityState::Stable);
        assert_eq!(manager.epoch(), 0);
    }

    #[test]
    fn test_manager_set_enabled() {
        let config = make_config();
        let detector = MockDetector::new();
        let mut manager = MobilityManager::new(config, detector);

        manager.trigger_reannounce();
        assert_eq!(manager.state(), MobilityState::Reannouncing);

        // Disable cancels reannounce
        manager.set_enabled(false);
        assert_eq!(manager.state(), MobilityState::Stable);
        assert!(!manager.is_enabled());

        // Re-enable
        manager.set_enabled(true);
        assert!(manager.is_enabled());
    }

    #[test]
    fn test_manager_stats() {
        let config = make_config();
        let mut detector = MockDetector::new();
        detector.add_change(LocatorChange::added(addr(1), "eth0".to_string()));

        let mut manager = MobilityManager::new(config, detector);
        manager.poll();

        let stats = manager.stats();
        assert!(stats.epoch >= 1);
        assert_eq!(stats.active_locators, 1);
    }

    #[test]
    fn test_manager_time_in_state() {
        let config = make_config();
        let detector = MockDetector::new();
        let manager = MobilityManager::new(config, detector);

        std::thread::sleep(Duration::from_millis(10));
        assert!(manager.time_in_state() >= Duration::from_millis(10));
    }

    #[test]
    fn test_manager_set_hold_down() {
        let config = make_config();
        let detector = MockDetector::new();
        let mut manager = MobilityManager::new(config, detector);

        manager.set_hold_down(Duration::from_secs(60));
        assert_eq!(manager.tracker().hold_down(), Duration::from_secs(60));
    }

    #[test]
    fn test_manager_set_reannounce_config() {
        let config = make_config();
        let detector = MockDetector::new();
        let mut manager = MobilityManager::new(config, detector);

        let new_burst = ReannounceBurst::fast();
        manager.set_reannounce_config(new_burst.clone());
        assert_eq!(
            manager.reannounce_controller().config().count(),
            new_burst.count()
        );
    }

    #[test]
    fn test_mobility_state_variants() {
        assert_eq!(MobilityState::default(), MobilityState::Stable);
        assert_ne!(MobilityState::Stable, MobilityState::Changed);
        assert_ne!(MobilityState::Changed, MobilityState::Reannouncing);
    }

    #[test]
    fn test_manager_stats_helpers() {
        let stats = MobilityManagerStats {
            state: MobilityState::Stable,
            epoch: 1,
            host_id: 12345,
            active_locators: 2,
            hold_down_locators: 1,
            time_in_state: Duration::from_secs(5),
            reannounce_progress: None,
            metrics: super::super::metrics::MobilityMetricsSnapshot::default(),
        };

        assert_eq!(stats.total_locators(), 3);
        assert!(stats.is_stable());
        assert!(!stats.is_reannouncing());
    }

    #[test]
    fn test_manager_filter_interface() {
        use super::super::config::{AddressFilter, InterfaceFilter};

        let config = MobilityConfig {
            enabled: true,
            interface_filter: InterfaceFilter::only(vec!["eth0".to_string()]),
            address_filter: AddressFilter::all(),
            ..Default::default()
        };

        let mut detector = MockDetector::new();
        // Add on eth0 (should be tracked)
        detector.add_change(LocatorChange::added(addr(1), "eth0".to_string()));
        // Add on wlan0 (should be filtered)
        detector.add_change(LocatorChange::added(addr(2), "wlan0".to_string()));

        let mut manager = MobilityManager::new(config, detector);
        manager.poll();

        // Only eth0 address should be tracked
        let active = manager.active_locators();
        assert_eq!(active.len(), 1);
        assert!(active.contains(&addr(1)));
    }

    #[test]
    fn test_noop_callback() {
        let mut callback = NoopCallback;
        // Should not panic
        callback.on_reannounce(0);
        callback.on_state_change(MobilityState::Stable, MobilityState::Changed);
        callback.on_locators_changed(&[], &[]);
    }
}
