// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! One lock between a Subscriber's access brackets and the local delivery
//! of a Publisher's coherent set (DDS v1.4 Sec.2.2.2.5.2.8 `begin_access`,
//! GROUP access scope).
//!
//! A GROUP reader may only read inside a bracket. A coherent set that
//! arrives while one is open must therefore wait for the next one; and a
//! set delivered while none is open must be in before the next bracket's
//! first read. The two sides are in different entities (the writer knows
//! the set, the reader knows the bracket), so the transition
//! `begin_access`/`end_access` and the "no bracket open, deliver now"
//! decision run under this one lock:
//!
//! * a delivery holds it across its decision and every push, so a bracket
//!   opened meanwhile starts after the set is in;
//! * `begin_access` takes it across its depth increment, so a delivery
//!   that already passed its decision finishes first.
//!
//! The wire leg needs none of this: its deliveries run on the Subscriber's
//! publishing thread under `CoherentPresentationBarrier::publishing`, and
//! its own `publish` performs the same "is a bracket open" decision.
//!
//! Held for the length of one set (a handful of pushes), never by a
//! writer's plain `write`, so it costs the certified intra-process path
//! nothing. Nothing takes another lock of this sort inside it that could
//! take it back: the delivery's listener calls are held by
//! `notices::Delivering` until it is released.

use std::sync::{Mutex, MutexGuard};

// Process-wide by design: the bracket (a Subscriber) and the set (a
// Publisher) are two entities of this process with no owner above them. It
// guards one transition, holds no data, and is taken at most once per
// begin_access/end_access and once per coherent set.
// @audit-ok: the lock is the mechanism itself, not shared state; it is the
// only way a bracket and a Publisher's delivery can exclude each other.
static PUBLICATION: Mutex<()> = Mutex::new(());

/// The lock described above. A poison of the lock is a panic in a
/// listener, which `notices` catches; the mutual exclusion is what
/// matters, not the flag.
pub(crate) fn lock() -> MutexGuard<'static, ()> {
    PUBLICATION.lock().unwrap_or_else(|e| e.into_inner())
}
