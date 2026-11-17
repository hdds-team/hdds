// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Deterministic reproduction of the intra-process coherent-set staging
//! race (`dds::writer::intra_coherent`): widens, for tests only, the window
//! between a coherent write's stamp (under the Publisher's `set_lock`) and
//! the stage of its sample.
//!
//! The race itself needs no help to exist -- any OS-scheduled preemption
//! landing in that window is enough -- but the window is a few
//! non-blocking instructions wide, so on an idle, many-core machine the
//! odds of a scheduler quantum landing inside it are negligible. A test
//! that wants to OBSERVE the race (rather than trust it happened
//! somewhere across a very large number of trials) sets a delay here.

use std::time::Duration;

/// Make every subsequent intra-process coherent write sleep for `delay`
/// after its stamp and before its sample is staged.
/// Process-wide, like every other knob in this module: set it only in a
/// test process that owns the writers it affects. `Duration::ZERO`
/// disables it again (the default).
pub fn inject_stage_delay(delay: Duration) {
    crate::dds::writer::set_coherent_stage_delay_for_test(delay);
}

/// Invoke `hook` once on this thread after the next coherent member has
/// been stamped, before it is journaled or staged. Use channels or barriers
/// in the hook to select a close/replay interleaving without sleeping.
pub fn before_next_stage(hook: impl FnOnce() + 'static) {
    crate::dds::writer::before_next_coherent_stage(Box::new(hook));
}

/// Invoke `hook` once on this thread after the Publisher has collected
/// pending replay, before it snapshots a ready live set's readers.
pub fn before_next_group_delivery(hook: impl FnOnce() + 'static) {
    crate::dds::writer::before_next_group_delivery(Box::new(hook));
}

/// Invoke `hook` once immediately after a coherent ring push, before
/// the transaction updates its delivery cursor or raises notifications.
pub fn after_next_push(hook: impl FnOnce() + 'static) {
    crate::dds::writer::after_next_coherent_push(Box::new(hook));
}

/// Run after the next false condition scan, immediately before blocking in
/// the driver. A channel handoff here makes publication tests deterministic.
pub fn before_next_wait(waitset: &crate::WaitSet, hook: impl FnOnce() + Send + 'static) {
    waitset.before_next_driver_wait(Box::new(hook));
}

/// Run before the coordinator updates ownership of the next local stream.
/// No stream, registry, producer or publication mutex is held.
pub fn before_next_stream_retention(hook: impl FnOnce() + 'static) {
    crate::dds::writer::before_next_stream_retention(Box::new(hook));
}

/// Run once after the reader's initial liveness check and before its next
/// order registration. The hook belongs to this reader, whichever thread
/// publishes the coherent set, and runs without the order mutex held.
pub fn before_next_order_registration<T: crate::dds::DDS>(
    reader: &crate::DataReader<T>,
    hook: impl FnOnce() + Send + 'static,
) {
    reader.before_next_order_registration(Box::new(hook));
}

/// Pause reader teardown after its ordered members are forgotten, before
/// its registrations are tombstoned. The test hook holds the consumer gate.
pub fn after_next_order_forget<T: crate::dds::DDS>(
    reader: &crate::DataReader<T>,
    hook: impl FnOnce() + Send + 'static,
) {
    reader.after_next_order_forget(Box::new(hook));
}

/// Run after the next ordered GROUP write takes its GSN and reserves its
/// position, before serialization or admission. No Publisher lock is held.
pub fn before_next_ordered_write(hook: impl FnOnce() + 'static) {
    crate::dds::writer::before_next_ordered_write(Box::new(hook));
}

/// Run once on this thread after admission found no room, before its wait.
pub fn before_next_room_wait(hook: impl FnOnce() + 'static) {
    crate::core::rt::merger::before_next_room_wait(Box::new(hook));
}
