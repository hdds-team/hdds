// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![allow(clippy::unwrap_used)] // test scaffolding

use super::{driver::internal, WaitsetDriver, WAITSET_DEFAULT_MAX_SLOTS};
use std::sync::Arc;
use std::time::Duration;

#[test]
fn register_slot_increments_table() {
    let driver = WaitsetDriver::new(8).expect("driver");
    assert_eq!(internal::slots_len(&driver), 0);

    let reg = driver.register_slot().expect("register");
    let (_slot, _id, signal) = reg.into_trait();
    signal.signal();

    let signaled = driver.wait(Some(Duration::from_millis(10))).expect("wait");
    assert_eq!(signaled.len(), 1);
}

#[test]
fn manual_notify_wakes_wait() {
    let driver = WaitsetDriver::new(WAITSET_DEFAULT_MAX_SLOTS).expect("driver");
    let reg = driver.register_slot().expect("register");
    let (slot_index, slot_id, _signal) = reg.into_trait();

    driver.manual_notify();
    let _ = driver.wait(Some(Duration::from_millis(10)));

    assert!(driver.unregister_slot(slot_index, slot_id));
}

#[test]
fn signal_multiple_slots_once() {
    let driver = Arc::new(WaitsetDriver::new(16).expect("driver"));

    let (slot_a, _, signal_a) = driver.register_slot().expect("slot a").into_trait();
    let (slot_b, _, signal_b) = driver.register_slot().expect("slot b").into_trait();

    signal_a.signal();
    signal_b.signal();

    let mut signaled = driver.wait(Some(Duration::from_millis(10))).expect("wait");
    signaled.sort_unstable();

    assert_eq!(signaled, vec![slot_a, slot_b]);
}
