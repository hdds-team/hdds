// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # DDS DataWriter
//!
//! The [`DataWriter`] publishes typed data samples to a DDS topic.
//!
//! ## Overview
//!
//! A DataWriter:
//! - Serializes and publishes typed data samples
//! - Supports QoS policies (reliability, history, durability)
//! - Handles both intra-process and network delivery
//! - Maintains a history cache for late-joining readers (transient-local)
//!
//! ## Example
//!
//! ```rust,no_run
//! use hdds::{Participant, QoS, Result};
//!
//! fn main() -> Result<()> {
//!     let participant = Participant::builder("publisher")
//!         .domain_id(0)
//!         .build()?;
//!
//!     let writer = participant.create_writer::<SensorData>(
//!         "sensors/temperature",
//!         QoS::reliable(),
//!     )?;
//!
//!     // Publish a sample
//!     writer.write(&SensorData { value: 23.5 })?;
//!
//!     Ok(())
//! }
//! # #[derive(hdds::DDS)] struct SensorData { value: f64 }
//! ```
//!
//! ## Reliability
//!
//! With `QoS::reliable()`, the writer:
//! - Assigns monotonic sequence numbers to each sample
//! - Sends periodic HEARTBEAT messages
//! - Responds to ACKNACK by retransmitting missed samples
//! - Maintains a history cache for retransmission
//!
//! ## Delivery Path
//!
//! ```text
//! write() -+-> Intra-process (TopicMerger) -> Local readers
//!          |
//!          +-> UDP transport -+-> Unicast to discovered endpoints
//!                             +-> Multicast fallback
//! ```
//!
//! ## See Also
//!
//! - [`DataReader`](crate::DataReader) - The subscribing counterpart
//! - [`QoS`](crate::QoS) - Quality of Service configuration
//! - [DDS Spec Sec.2.2.2.4](https://www.omg.org/spec/DDS/1.4/) - DataWriter

#[cfg(test)]
mod acknowledgement_tests;
mod builder;
/// DurabilityService cleanup timer.
///
/// Implements the cleanup half of the public `DurabilityService` QoS
/// (see `docs/qos-guide.md`).
mod cleanup_timer;
mod coherent;
#[cfg(test)]
mod coherent_dispose_tests;
#[cfg(test)]
#[path = "durability_service_tests.rs"]
mod durability_service_tests;
#[cfg(test)]
mod emission_parity_tests;
mod emit_canonical;
mod frag_route;
#[cfg(test)]
mod group_seq_tests;
mod heartbeat_scheduler;
mod intra_coherent;
#[cfg(test)]
mod key_payload_tests;
#[cfg(test)]
mod lifecycle_heartbeat_tests;
pub(super) mod local_group;
mod nack;
#[cfg(test)]
mod ordered_notice_tests;
#[cfg(test)]
mod participant_heartbeat_tests;
#[cfg(test)]
mod plain_group_tests;
#[cfg(test)]
mod realpath_parity_probes;
mod runtime;
#[cfg(test)]
mod tests;

pub use builder::WriterBuilder;
pub(crate) use runtime::deadline_after;
#[allow(unused_imports)]
pub use runtime::{DataWriter, WriterStats};

/// Tests only: artificial delay injected into the intra-process coherent
/// write path, between a sample's stamp (`coherent_context_held`, under
/// the Publisher's `set_lock`) and its stage (`CoherentStamp::stage`) --
/// same style as `core::rt::shutdown`'s exit linger: a process-wide knob,
/// zero cost (not even compiled) outside `cfg(test)` / the `test-support`
/// feature, defaulting to zero (no delay, no behavior change).
///
/// The window it widens exists without it: a writer thread can be
/// preempted there by ordinary OS scheduling, and a concurrent
/// `end_coherent_changes` then closes a set one of whose members has not
/// staged yet. But the window is a handful of non-blocking instructions
/// wide, so on an idle, many-core test machine a scheduler quantum almost
/// never lands inside it; `intra_coherent_atomicity.rs` sets this to a few
/// hundred microseconds to make the close-before-stage interleaving occur
/// in every round.
#[cfg(any(test, feature = "test-support"))]
static COHERENT_STAGE_DELAY_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Tests only: set the delay `coherent_stage_delay_for_test` sleeps for.
/// Zero (the default) disables it entirely.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn set_coherent_stage_delay_for_test(delay: std::time::Duration) {
    let ns = u64::try_from(delay.as_nanos()).unwrap_or(u64::MAX);
    COHERENT_STAGE_DELAY_NS.store(ns, std::sync::atomic::Ordering::Relaxed);
}

/// Tests only: sleep for the duration set by
/// `set_coherent_stage_delay_for_test`, if any. Called from
/// `runtime::DataWriter::commit_intra_process_entry`, only on the two
/// branches that stage a coherent sample (never on the non-coherent path,
/// and never on the wire path, which has no staging step to widen).
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn coherent_stage_delay_for_test() {
    let ns = COHERENT_STAGE_DELAY_NS.load(std::sync::atomic::Ordering::Relaxed);
    if ns != 0 {
        std::thread::sleep(std::time::Duration::from_nanos(ns));
    }
}

#[cfg(any(test, feature = "test-support"))]
std::thread_local! {
    // @audit-ok: test-only thread-local hook, consumed once; never shared.
    static NEXT_STAGE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn before_next_coherent_stage(hook: Box<dyn FnOnce()>) {
    NEXT_STAGE_HOOK.with(|slot| *slot.borrow_mut() = Some(hook));
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn run_coherent_stage_hook() {
    let hook = NEXT_STAGE_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(any(test, feature = "test-support"))]
std::thread_local! {
    // @audit-ok: test-only thread-local hook, consumed once; never shared.
    static NEXT_GROUP_DELIVERY_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn before_next_group_delivery(hook: Box<dyn FnOnce()>) {
    NEXT_GROUP_DELIVERY_HOOK.with(|slot| *slot.borrow_mut() = Some(hook));
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn run_group_delivery_hook() {
    let hook = NEXT_GROUP_DELIVERY_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(any(test, feature = "test-support"))]
std::thread_local! {
    // @audit-ok: test-only thread-local hook, consumed once; never shared.
    static NEXT_VISIBLE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn after_next_coherent_push(hook: Box<dyn FnOnce()>) {
    NEXT_VISIBLE_HOOK.with(|slot| *slot.borrow_mut() = Some(hook));
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn run_coherent_visible_hook() {
    let hook = NEXT_VISIBLE_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(any(test, feature = "test-support"))]
std::thread_local! {
    // @audit-ok: test-only thread-local hook, consumed once; never shared.
    static NEXT_RETENTION_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn before_next_stream_retention(hook: Box<dyn FnOnce()>) {
    NEXT_RETENTION_HOOK.with(|slot| *slot.borrow_mut() = Some(hook));
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn run_stream_retention_hook() {
    let hook = NEXT_RETENTION_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
std::thread_local! {
    // @audit-ok: test-only thread-local hook, consumed once; never shared.
    static NEXT_LOCAL_PREPARE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn before_next_local_prepare(hook: Box<dyn FnOnce()>) {
    NEXT_LOCAL_PREPARE_HOOK.with(|slot| *slot.borrow_mut() = Some(hook));
}

#[cfg(test)]
pub(crate) fn run_local_prepare_hook() {
    let hook = NEXT_LOCAL_PREPARE_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
pub(crate) fn clear_local_prepare_hook() {
    let _ = NEXT_LOCAL_PREPARE_HOOK.with(|slot| slot.borrow_mut().take());
}

#[cfg(any(test, feature = "test-support"))]
std::thread_local! {
    // @audit-ok: one-shot test-only thread-local hook, never shared.
    static NEXT_ORDERED_WRITE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn before_next_ordered_write(hook: Box<dyn FnOnce()>) {
    NEXT_ORDERED_WRITE_HOOK.with(|slot| *slot.borrow_mut() = Some(hook));
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn run_ordered_write_hook() {
    let hook = NEXT_ORDERED_WRITE_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}
