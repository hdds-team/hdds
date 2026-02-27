// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![allow(clippy::expect_used)]

use super::{TimeBasedFilter, TimeBasedFilterChecker};
use std::thread;
use std::time::Duration;

#[test]
fn filter_default_is_zero() {
    let filter = TimeBasedFilter::default();
    assert_eq!(filter.minimum_separation, Duration::ZERO);
    assert!(filter.is_disabled());
}

#[test]
fn filter_new_preserves_value() {
    let filter = TimeBasedFilter::new(Duration::from_millis(100));
    assert_eq!(filter.minimum_separation, Duration::from_millis(100));
    assert!(!filter.is_disabled());
}

#[test]
fn filter_zero_is_disabled() {
    let filter = TimeBasedFilter::zero();
    assert!(filter.is_disabled());
    assert_eq!(filter, TimeBasedFilter::default());
}

#[test]
fn checker_accepts_first_sample() {
    let filter = TimeBasedFilter::new(Duration::from_millis(100));
    let checker = TimeBasedFilterChecker::new(filter);

    assert!(checker.should_accept());
}

#[test]
fn checker_rejects_until_separation_elapsed() {
    let filter = TimeBasedFilter::new(Duration::from_millis(50));
    let mut checker = TimeBasedFilterChecker::new(filter);

    checker.mark_accepted();
    assert!(!checker.should_accept());
    thread::sleep(Duration::from_millis(60));
    assert!(checker.should_accept());
}

#[test]
fn checker_reset_allows_next_sample() {
    let filter = TimeBasedFilter::new(Duration::from_millis(100));
    let mut checker = TimeBasedFilterChecker::new(filter);

    checker.mark_accepted();
    assert!(!checker.should_accept());
    checker.reset();
    assert!(checker.should_accept());
}

#[test]
fn checker_time_until_next_accept_behaviour() {
    let filter = TimeBasedFilter::new(Duration::from_millis(100));
    let mut checker = TimeBasedFilterChecker::new(filter);

    assert!(checker.time_until_next_accept().is_none());
    checker.mark_accepted();

    let remaining = checker
        .time_until_next_accept()
        .expect("remaining time should be known");
    assert!(remaining <= Duration::from_millis(100));

    thread::sleep(Duration::from_millis(110));
    assert!(checker.time_until_next_accept().is_none());
}

#[test]
fn checker_zero_filter_accepts_everything() {
    let filter = TimeBasedFilter::zero();
    let mut checker = TimeBasedFilterChecker::new(filter);

    for _ in 0..5 {
        assert!(checker.should_accept());
        checker.mark_accepted();
    }
}

#[test]
fn checker_debug_contains_type_name() {
    let filter = TimeBasedFilter::new(Duration::from_millis(5));
    let checker = TimeBasedFilterChecker::new(filter);
    let debug_str = format!("{checker:?}");
    assert!(debug_str.contains("TimeBasedFilterChecker"));
}

#[test]
fn filter_equality_reflects_duration() {
    let a = TimeBasedFilter::new(Duration::from_millis(25));
    let b = TimeBasedFilter::new(Duration::from_millis(25));
    let c = TimeBasedFilter::new(Duration::from_millis(50));

    assert_eq!(a, b);
    assert_ne!(a, c);
}
