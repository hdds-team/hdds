// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::{Liveliness, LivelinessKind, LivelinessMonitor};
use std::thread;
use std::time::Duration;

#[test]
fn test_liveliness_constructors() {
    let automatic = Liveliness::automatic(Duration::from_secs(5));
    assert_eq!(automatic.kind, LivelinessKind::Automatic);
    assert_eq!(automatic.lease_duration, Duration::from_secs(5));

    let manual_participant = Liveliness::manual_by_participant(Duration::from_secs(10));
    assert_eq!(manual_participant.kind, LivelinessKind::ManualByParticipant);

    let manual_topic = Liveliness::manual_by_topic(Duration::from_secs(15));
    assert_eq!(manual_topic.kind, LivelinessKind::ManualByTopic);

    let infinite = Liveliness::infinite();
    assert!(infinite.is_infinite());
}

#[test]
fn test_liveliness_compatibility() {
    let writer = Liveliness::automatic(Duration::from_secs(1));
    let reader = Liveliness::automatic(Duration::from_secs(2));
    assert!(writer.is_compatible_with(&reader));

    let slower_writer = Liveliness::automatic(Duration::from_secs(3));
    assert!(!slower_writer.is_compatible_with(&reader));

    let manual = Liveliness::manual_by_participant(Duration::from_secs(2));
    assert!(!writer.is_compatible_with(&manual));
}

#[test]
fn test_liveliness_monitor_basic() {
    let mut monitor = LivelinessMonitor::new(LivelinessKind::Automatic, Duration::from_millis(100));
    assert!(monitor.is_alive());
    thread::sleep(Duration::from_millis(50));
    assert!(monitor.is_alive());
    monitor.assert();
    assert!(monitor.is_alive());
}

#[test]
fn test_liveliness_monitor_timeout() {
    let mut monitor = LivelinessMonitor::new(LivelinessKind::Automatic, Duration::from_millis(50));
    thread::sleep(Duration::from_millis(60));
    assert!(!monitor.check());
    assert!(!monitor.is_alive());
}

#[test]
fn test_liveliness_monitor_infinite() {
    let mut monitor =
        LivelinessMonitor::new(LivelinessKind::Automatic, Duration::from_secs(u64::MAX));
    thread::sleep(Duration::from_millis(10));
    assert!(monitor.check());
    assert!(monitor.is_alive());
    assert_eq!(monitor.time_until_expiry(), None);
}
