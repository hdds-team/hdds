// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! End-to-end tests for IP mobility.
//!
//! These tests simulate network roaming scenarios using:
//! - Linux network namespaces (`ip netns`)
//! - Virtual ethernet pairs (`veth`)
//! - Traffic control (`tc netem`) for delay/loss simulation
//!
//! # Requirements
//!
//! - Root privileges (or CAP_NET_ADMIN)
//! - Linux kernel with namespace support
//! - `iproute2` package installed
//!
//! # Running
//!
//! ```bash
//! # Run all mobility tests (requires root)
//! sudo cargo test --test mobility_e2e -- --ignored
//!
//! # Run specific test
//! sudo cargo test --test mobility_e2e test_roaming_between_networks -- --ignored
//! ```

use std::io;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Check if we have root privileges.
fn has_root_privileges() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Check if network namespaces are available.
/// Execute a shell command and check success.
fn exec(cmd: &str) -> io::Result<()> {
    let status = Command::new("sh").arg("-c").arg(cmd).status()?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("Command failed: {}", cmd)))
    }
}

/// Execute a command and capture output.
fn exec_output(cmd: &str) -> io::Result<String> {
    let output = Command::new("sh").arg("-c").arg(cmd).output()?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(io::Error::other(format!(
            "Command failed: {} - {}",
            cmd,
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

/// Execute a command in a network namespace.
fn exec_in_ns(ns: &str, cmd: &str) -> io::Result<()> {
    exec(&format!("ip netns exec {} {}", ns, cmd))
}

/// Network namespace helper for testing.
struct TestNetns {
    name: String,
    created: bool,
}

impl TestNetns {
    /// Create a new network namespace.
    fn new(name: &str) -> io::Result<Self> {
        exec(&format!("ip netns add {}", name))?;

        // Bring up loopback in the namespace
        exec_in_ns(name, "ip link set lo up")?;

        Ok(Self {
            name: name.to_string(),
            created: true,
        })
    }

    /// Get namespace name.
    fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for TestNetns {
    fn drop(&mut self) {
        if self.created {
            let _ = exec(&format!("ip netns delete {}", self.name));
        }
    }
}

/// Virtual ethernet pair for connecting namespaces.
struct VethPair {
    veth0: String,
    _veth1: String,
    created: bool,
}

impl VethPair {
    /// Create a veth pair.
    fn new(name0: &str, name1: &str) -> io::Result<Self> {
        exec(&format!(
            "ip link add {} type veth peer name {}",
            name0, name1
        ))?;

        Ok(Self {
            veth0: name0.to_string(),
            _veth1: name1.to_string(),
            created: true,
        })
    }

    /// Move one end to a namespace.
    fn move_to_ns(&self, veth: &str, ns: &str) -> io::Result<()> {
        exec(&format!("ip link set {} netns {}", veth, ns))
    }

    /// Configure IP address on an interface.
    fn configure_ip(&self, veth: &str, ip: &str, ns: Option<&str>) -> io::Result<()> {
        let cmd = format!("ip addr add {} dev {}", ip, veth);
        match ns {
            Some(ns) => exec_in_ns(ns, &cmd),
            None => exec(&cmd),
        }
    }

    /// Bring up an interface.
    fn up(&self, veth: &str, ns: Option<&str>) -> io::Result<()> {
        let cmd = format!("ip link set {} up", veth);
        match ns {
            Some(ns) => exec_in_ns(ns, &cmd),
            None => exec(&cmd),
        }
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        if self.created {
            // Deleting one end deletes the pair
            let _ = exec(&format!("ip link delete {}", self.veth0));
        }
    }
}

/// Test network setup with two networks.
struct DualNetworkSetup {
    _ns: TestNetns,
    _veth_a: VethPair,
    _veth_b: VethPair,
}

impl DualNetworkSetup {
    /// Create a setup with:
    /// - Host has 10.0.1.1/24 on veth-a0 and 10.0.2.1/24 on veth-b0
    /// - Namespace "mobile" has veth-a1 (10.0.1.2) and veth-b1 (10.0.2.2)
    fn new() -> io::Result<Self> {
        let ns = TestNetns::new("hdds_mobile")?;

        let veth_a = VethPair::new("hdds-a0", "hdds-a1")?;
        let veth_b = VethPair::new("hdds-b0", "hdds-b1")?;

        // Move one end of each pair to the namespace
        veth_a.move_to_ns("hdds-a1", "hdds_mobile")?;
        veth_b.move_to_ns("hdds-b1", "hdds_mobile")?;

        // Configure IPs on host side
        veth_a.configure_ip("hdds-a0", "10.0.1.1/24", None)?;
        veth_b.configure_ip("hdds-b0", "10.0.2.1/24", None)?;

        // Configure IPs on namespace side
        veth_a.configure_ip("hdds-a1", "10.0.1.2/24", Some("hdds_mobile"))?;
        veth_b.configure_ip("hdds-b1", "10.0.2.2/24", Some("hdds_mobile"))?;

        // Bring up all interfaces
        veth_a.up("hdds-a0", None)?;
        veth_a.up("hdds-a1", Some("hdds_mobile"))?;
        veth_b.up("hdds-b0", None)?;
        veth_b.up("hdds-b1", Some("hdds_mobile"))?;

        Ok(Self {
            _ns: ns,
            _veth_a: veth_a,
            _veth_b: veth_b,
        })
    }

    /// Simulate roaming by bringing down network A and up network B.
    fn roam_to_network_b(&self) -> io::Result<()> {
        exec_in_ns("hdds_mobile", "ip link set hdds-a1 down")?;
        // Small delay to let the change propagate
        thread::sleep(Duration::from_millis(100));
        Ok(())
    }

    /// Simulate roaming back to network A.
    fn roam_to_network_a(&self) -> io::Result<()> {
        exec_in_ns("hdds_mobile", "ip link set hdds-b1 down")?;
        exec_in_ns("hdds_mobile", "ip link set hdds-a1 up")?;
        thread::sleep(Duration::from_millis(100));
        Ok(())
    }

    /// Add network delay using tc netem.
    fn add_delay(&self, interface: &str, delay_ms: u32, ns: Option<&str>) -> io::Result<()> {
        let cmd = format!(
            "tc qdisc add dev {} root netem delay {}ms",
            interface, delay_ms
        );
        match ns {
            Some(ns) => exec_in_ns(ns, &cmd),
            None => exec(&cmd),
        }
    }

    /// Add packet loss using tc netem.
    fn add_loss(&self, interface: &str, loss_percent: u32, ns: Option<&str>) -> io::Result<()> {
        let cmd = format!(
            "tc qdisc add dev {} root netem loss {}%",
            interface, loss_percent
        );
        match ns {
            Some(ns) => exec_in_ns(ns, &cmd),
            None => exec(&cmd),
        }
    }

    /// Remove tc qdisc.
    fn remove_qdisc(&self, interface: &str, ns: Option<&str>) -> io::Result<()> {
        let cmd = format!("tc qdisc del dev {} root", interface);
        match ns {
            Some(ns) => exec_in_ns(ns, &cmd),
            None => exec(&cmd),
        }
    }
}

// ============================================================================
// Unit tests (no privileges required)
// ============================================================================

#[test]
fn test_mobility_module_imports() {
    // Just verify the module is accessible
    use hdds::transport::mobility::MobilityConfig;

    let config = MobilityConfig::default();
    assert!(!config.enabled);
}

#[test]
fn test_mobility_parameter_encoding() {
    use hdds::transport::mobility::{
        encode_mobility_parameter, find_mobility_parameter, MobilityParameter,
    };

    let param = MobilityParameter::new(42, 0x123456789ABCDEF0, 0xDEADBEEF);
    let encoded = encode_mobility_parameter(&param);

    let found = find_mobility_parameter(&encoded).expect("should find");
    assert_eq!(found.epoch, 42);
    assert_eq!(found.host_id, 0x123456789ABCDEF0);
    assert_eq!(found.locator_hash, 0xDEADBEEF);
}

#[test]
fn test_reannounce_burst_timing() {
    use hdds::transport::mobility::{BurstState, ReannounceBurst, ReannounceController};

    let config = ReannounceBurst {
        delays: vec![Duration::ZERO, Duration::from_millis(10)],
        jitter_percent: 0,
        min_burst_interval: Duration::ZERO,
    };

    let mut ctrl = ReannounceController::new(config);
    ctrl.start_burst();

    // First should be immediate
    assert!(ctrl.should_announce());
    ctrl.mark_announced();

    // Wait a bit for second
    thread::sleep(Duration::from_millis(15));
    assert!(ctrl.should_announce());
    ctrl.mark_announced();

    assert_eq!(ctrl.state(), BurstState::Completed);
}

#[test]
fn test_locator_tracker_hold_down() {
    use hdds::transport::mobility::{LocatorState, LocatorTracker};
    use std::net::Ipv4Addr;

    // Use zero expiry check interval to ensure immediate checks
    let mut tracker =
        LocatorTracker::new(Duration::from_millis(50)).with_expiry_check_interval(Duration::ZERO);

    // Add a locator
    let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    tracker.add_locator(addr, "eth0".to_string());

    // Remove it (enters hold-down)
    tracker.remove_locator(&addr);

    let loc = tracker.get(&addr).expect("should exist");
    assert_eq!(loc.state, LocatorState::HoldDown);

    // Should still be advertisable
    assert_eq!(tracker.advertisable_locators().count(), 1);

    // Wait for hold-down to expire
    thread::sleep(Duration::from_millis(100));
    let expired = tracker.expire_locators();

    // Now should be gone
    assert!(expired > 0, "should have expired locators");
    assert!(tracker.get(&addr).is_none());
}

// ============================================================================
// Integration tests (require root privileges)
// ============================================================================

#[test]
#[ignore = "requires root privileges"]
fn test_netns_creation() {
    if !has_root_privileges() {
        eprintln!("Skipping test: requires root");
        return;
    }

    let ns = TestNetns::new("hdds_test_ns").expect("create netns");
    assert_eq!(ns.name(), "hdds_test_ns");

    // Verify it exists
    let output = exec_output("ip netns list").expect("list netns");
    assert!(output.contains("hdds_test_ns"));
}

#[test]
#[ignore = "requires root privileges"]
fn test_veth_pair_creation() {
    if !has_root_privileges() {
        eprintln!("Skipping test: requires root");
        return;
    }

    let veth = VethPair::new("hdds-test0", "hdds-test1").expect("create veth");
    veth.up("hdds-test0", None).expect("bring up veth0");
    veth.up("hdds-test1", None).expect("bring up veth1");

    // Verify they exist
    let output = exec_output("ip link show hdds-test0").expect("show link");
    assert!(output.contains("hdds-test0"));
}

#[test]
#[ignore = "requires root privileges"]
fn test_dual_network_setup() {
    if !has_root_privileges() {
        eprintln!("Skipping test: requires root");
        return;
    }

    let _setup = DualNetworkSetup::new().expect("create setup");

    // Verify connectivity from host to namespace via network A
    let output = exec_output("ping -c 1 -W 1 10.0.1.2").expect("ping network A");
    assert!(output.contains("1 received"));

    // Verify connectivity via network B
    let output = exec_output("ping -c 1 -W 1 10.0.2.2").expect("ping network B");
    assert!(output.contains("1 received"));
}

#[test]
#[ignore = "requires root privileges"]
fn test_roaming_simulation() {
    if !has_root_privileges() {
        eprintln!("Skipping test: requires root");
        return;
    }

    let setup = DualNetworkSetup::new().expect("create setup");

    // Initially both networks should work
    assert!(exec_output("ping -c 1 -W 1 10.0.1.2").is_ok());
    assert!(exec_output("ping -c 1 -W 1 10.0.2.2").is_ok());

    // Roam to network B (disable A)
    setup.roam_to_network_b().expect("roam to B");

    // Network A should fail, B should work
    assert!(exec_output("ping -c 1 -W 1 10.0.1.2").is_err());
    assert!(exec_output("ping -c 1 -W 1 10.0.2.2").is_ok());

    // Roam back to network A
    setup.roam_to_network_a().expect("roam to A");

    // Network A should work again
    assert!(exec_output("ping -c 1 -W 1 10.0.1.2").is_ok());
}

#[test]
#[ignore = "requires root privileges"]
fn test_netem_delay() {
    if !has_root_privileges() {
        eprintln!("Skipping test: requires root");
        return;
    }

    let setup = DualNetworkSetup::new().expect("create setup");

    // Add 50ms delay on network A
    setup.add_delay("hdds-a0", 50, None).expect("add delay");

    // Measure ping time
    let start = Instant::now();
    exec_output("ping -c 1 -W 2 10.0.1.2").expect("ping");
    let elapsed = start.elapsed();

    // Should be at least 50ms (both directions = 100ms minimum for round trip)
    assert!(elapsed >= Duration::from_millis(50));

    // Clean up
    setup.remove_qdisc("hdds-a0", None).ok();
}

#[test]
#[ignore = "requires root privileges"]
fn test_netem_loss() {
    if !has_root_privileges() {
        eprintln!("Skipping test: requires root");
        return;
    }

    let setup = DualNetworkSetup::new().expect("create setup");

    // Add 50% loss on network A
    setup.add_loss("hdds-a0", 50, None).expect("add loss");

    // Send multiple pings, expect some to fail
    let mut success = 0;
    let mut failure = 0;

    for _ in 0..20 {
        if exec_output("ping -c 1 -W 1 10.0.1.2").is_ok() {
            success += 1;
        } else {
            failure += 1;
        }
    }

    // With 50% loss, we should see roughly half succeed
    // Allow wide margin due to randomness
    assert!(success > 2, "too few successes: {}", success);
    assert!(failure > 2, "too few failures: {}", failure);

    // Clean up
    setup.remove_qdisc("hdds-a0", None).ok();
}

/// Test UDP communication with roaming.
#[test]
#[ignore = "requires root privileges"]
fn test_udp_roaming() {
    if !has_root_privileges() {
        eprintln!("Skipping test: requires root");
        return;
    }

    let setup = DualNetworkSetup::new().expect("create setup");

    // Start a UDP server on the host bound to 0.0.0.0
    let server = UdpSocket::bind("0.0.0.0:7500").expect("bind server");
    server
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set timeout");

    let running = Arc::new(AtomicBool::new(true));
    let received = Arc::new(AtomicU32::new(0));

    let running_clone = Arc::clone(&running);
    let received_clone = Arc::clone(&received);

    let server_thread = thread::spawn(move || {
        let mut buf = [0u8; 1024];
        while running_clone.load(Ordering::Relaxed) {
            if let Ok((len, src)) = server.recv_from(&mut buf) {
                received_clone.fetch_add(1, Ordering::Relaxed);
                // Echo back
                let _ = server.send_to(&buf[..len], src);
            }
        }
    });

    // Small delay to let server start
    thread::sleep(Duration::from_millis(100));

    // Send from namespace via network A
    let result = exec_in_ns("hdds_mobile", "echo 'test1' | nc -u -w1 10.0.1.1 7500");
    assert!(result.is_ok(), "send via network A");

    thread::sleep(Duration::from_millis(200));
    let count1 = received.load(Ordering::Relaxed);
    assert!(count1 >= 1, "should receive via network A");

    // Roam to network B
    setup.roam_to_network_b().expect("roam");

    // Send from namespace via network B
    let result = exec_in_ns("hdds_mobile", "echo 'test2' | nc -u -w1 10.0.2.1 7500");
    assert!(result.is_ok(), "send via network B");

    thread::sleep(Duration::from_millis(200));
    let count2 = received.load(Ordering::Relaxed);
    assert!(count2 > count1, "should receive via network B");

    // Stop server
    running.store(false, Ordering::Relaxed);
    let _ = server_thread.join();
}

/// Test IP change detection with PollIpDetector.
#[test]
#[ignore = "requires root privileges"]
fn test_poll_detector_with_netns() {
    use hdds::transport::mobility::{
        AddressFilter, InterfaceFilter, IpDetector, LocatorChangeKind, PollIpDetector,
    };

    if !has_root_privileges() {
        eprintln!("Skipping test: requires root");
        return;
    }

    let _setup = DualNetworkSetup::new().expect("create setup");

    // Create detector for host interfaces
    let iface_filter = InterfaceFilter::only(vec!["hdds-a0".to_string(), "hdds-b0".to_string()]);
    let addr_filter = AddressFilter::all();

    let mut detector = PollIpDetector::new(Duration::from_millis(100))
        .with_interface_filter(iface_filter)
        .with_address_filter(addr_filter);

    // Initial poll should find addresses
    let initial = detector.current_addresses().expect("get addresses");
    assert!(initial.len() >= 2, "should find both networks");

    // The detector tracks changes, so first poll establishes baseline
    let _ = detector.poll_changes();

    // Simulate roaming - bring down network A on host side
    exec("ip link set hdds-a0 down").expect("down");
    thread::sleep(Duration::from_millis(200));

    // Force a poll
    let _ = detector.force_poll();
    let changes = detector.poll_changes().expect("poll");

    // Should detect the removal
    let removed: Vec<_> = changes
        .iter()
        .filter(|c| c.kind == LocatorChangeKind::Removed)
        .collect();

    assert!(!removed.is_empty(), "should detect address removal");

    // Bring it back up
    exec("ip link set hdds-a0 up").expect("up");
}

/// Simulated mobility manager test with mock detector.
#[test]
fn test_mobility_manager_roaming_scenario() {
    use hdds::transport::mobility::{
        AddressFilter, InterfaceFilter, IpDetector, LocatorChange, MobilityConfig, MobilityManager,
        MobilityState,
    };
    use std::sync::atomic::AtomicU32;
    use std::sync::Arc;

    // Mock detector that simulates roaming with controlled phase
    struct RoamingDetector {
        phase: Arc<AtomicU32>,
        last_reported_phase: u32,
    }

    impl IpDetector for RoamingDetector {
        fn poll_changes(&mut self) -> io::Result<Vec<LocatorChange>> {
            let current_phase = self.phase.load(Ordering::Relaxed);

            // Only report changes when phase changes
            if current_phase == self.last_reported_phase {
                return Ok(vec![]);
            }

            let changes = match current_phase {
                0 => {
                    // Initial: network A only
                    vec![LocatorChange::added(
                        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)),
                        "eth0".to_string(),
                    )]
                }
                1 => {
                    // Roam: lose A, gain B
                    vec![
                        LocatorChange::removed(
                            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)),
                            "eth0".to_string(),
                        ),
                        LocatorChange::added(
                            IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2)),
                            "eth1".to_string(),
                        ),
                    ]
                }
                _ => vec![],
            };

            self.last_reported_phase = current_phase;
            Ok(changes)
        }

        fn current_addresses(&self) -> io::Result<Vec<(IpAddr, String)>> {
            Ok(vec![])
        }

        fn name(&self) -> &str {
            "roaming_mock"
        }
    }

    let config = MobilityConfig {
        enabled: true,
        hold_down: Duration::from_secs(60), // Long hold-down for this test
        min_burst_interval: Duration::ZERO,
        interface_filter: InterfaceFilter::all(),
        address_filter: AddressFilter::all(),
        ..Default::default()
    };

    let phase = Arc::new(AtomicU32::new(0));
    let detector = RoamingDetector {
        phase: Arc::clone(&phase),
        last_reported_phase: u32::MAX, // Ensure first poll reports
    };
    let mut manager = MobilityManager::new(config, detector);

    // Phase 0: Initial network
    let changed = manager.poll();
    assert!(changed, "should detect initial address");
    assert_eq!(manager.epoch(), 1);

    // Complete reannounce burst
    while manager.state() == MobilityState::Reannouncing {
        manager.poll();
    }
    assert_eq!(manager.state(), MobilityState::Stable);

    // Verify we have 1 active locator
    assert_eq!(manager.active_locators().len(), 1);

    // Transition to phase 1: Roam to new network
    phase.store(1, Ordering::Relaxed);

    let changed = manager.poll();
    assert!(changed, "should detect roaming change");
    assert!(manager.epoch() >= 2, "epoch should increase");

    // Should have both locators (one active, one hold-down)
    let advertisable = manager.advertisable_locators();
    assert_eq!(advertisable.len(), 2, "should have 2 advertisable locators");

    // Active should only have the new address
    let active = manager.active_locators();
    assert_eq!(active.len(), 1);
    assert!(active.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2))));
}

// ============================================================================
// Metrics tests
// ============================================================================

#[test]
fn test_mobility_metrics_collection() {
    use hdds::transport::mobility::MobilityMetrics;

    let metrics = MobilityMetrics::new();

    // Record some events
    metrics.record_address_added();
    metrics.record_address_added();
    metrics.record_address_removed();
    metrics.record_reannounce_burst(5);
    metrics.record_poll();

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.addresses_added, 2);
    assert_eq!(snapshot.addresses_removed, 1);
    assert_eq!(snapshot.reannounce_bursts, 1);
    assert_eq!(snapshot.reannounce_packets, 5);
    assert_eq!(snapshot.polls_performed, 1);
    assert_eq!(snapshot.total_changes(), 3);
}

#[test]
fn test_mobility_metrics_rates() {
    use hdds::transport::mobility::MobilityMetricsSnapshot;

    let snapshot = MobilityMetricsSnapshot {
        addresses_added: 10,
        addresses_removed: 5,
        reannounce_bursts: 3,
        reannounce_packets: 15,
        polls_performed: 120,
        locators_expired: 2,
        locators_active: 2,
        locators_hold_down: 1,
        uptime: Duration::from_secs(60),
    };

    // 15 changes in 60 seconds = 15 per minute
    assert!((snapshot.change_rate_per_minute() - 15.0).abs() < 0.1);

    // 120 polls in 60 seconds = 2 per second
    assert!((snapshot.poll_rate() - 2.0).abs() < 0.1);

    // 15 packets / 3 bursts = 5 per burst
    assert!((snapshot.avg_packets_per_burst() - 5.0).abs() < 0.1);
}
