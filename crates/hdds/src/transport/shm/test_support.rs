// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Test-only cleanup helper shared by every `shm` test module.
//!
//! Every test that creates a named shared-memory segment (ring, notify, or
//! a raw `ShmSegment`) must unlink it on EVERY exit path, including a
//! panicking `assert!`. A trailing `writer.unlink().ok();` at the bottom of
//! a test only runs if nothing above it panicked, which is exactly backward
//! for a test: the segments most worth cleaning up are the ones a failing
//! assertion left behind, because that is the run most likely to be
//! followed by someone re-running the same test (and the same name clash)
//! a minute later.
//!
//! `UnlinkOnDrop` fixes that by making cleanup a destructor instead of a
//! statement: declare it right after computing the name(s), before calling
//! `create`/`new`, and it unlinks every name it holds no matter how the
//! test function returns (`Ok`, a failing `assert!`, an early `?`, or a
//! panic that unwinds).

use super::segment::ShmSegment;

/// Unlinks every given shm name when dropped.
///
/// Declare this BEFORE creating the segment(s) it names: drop order is
/// LIFO, so a guard declared first runs its `Drop` LAST, after whatever in
/// the test actually holds the segment mapped. Unlinking while still mapped
/// is POSIX-safe either way (the mapping stays valid until unmapped), but
/// dropping in this order means the guard's own log output, if any is ever
/// added, would describe a segment nothing in the test still references.
pub(crate) struct UnlinkOnDrop(Vec<String>);

impl UnlinkOnDrop {
    /// Guard a single segment name.
    pub(crate) fn one(name: impl Into<String>) -> Self {
        Self(vec![name.into()])
    }
}

impl Drop for UnlinkOnDrop {
    fn drop(&mut self) {
        for name in &self.0 {
            let _ = ShmSegment::unlink(name);
        }
    }
}

/// Asserts, when dropped, that a topic's notify segment is gone.
///
/// Notify segments are released by their last user (see `notify.rs`), so a
/// test must not unlink one itself: doing so would hide exactly the leak
/// this check exists to catch. Declare it BEFORE the writers and readers of
/// the topic, so it runs after they have all been dropped. Skipped while
/// unwinding from another failure, so that failure is the one reported.
pub(crate) struct NotifyGoneOnDrop(String);

impl NotifyGoneOnDrop {
    /// Check the notify segment of `topic` on `domain_id`.
    pub(crate) fn topic(domain_id: u32, topic: &str) -> Self {
        Self(super::notify::TopicNotify::segment_name(domain_id, topic))
    }
}

impl Drop for NotifyGoneOnDrop {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            assert!(
                !ShmSegment::exists(&self.0),
                "notify segment {} outlived every user of its topic",
                self.0
            );
        }
    }
}
