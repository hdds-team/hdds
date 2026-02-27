// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

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
