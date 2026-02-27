// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::TimeBasedFilter;
use std::time::{Duration, Instant};

/// Stateful helper that enforces a [`TimeBasedFilter`] at runtime.
#[derive(Debug)]
pub struct TimeBasedFilterChecker {
    filter: TimeBasedFilter,
    last_accepted: Option<Instant>,
}

impl TimeBasedFilterChecker {
    /// Create a checker for the provided filter policy.
    #[must_use]
    pub fn new(filter: TimeBasedFilter) -> Self {
        Self {
            filter,
            last_accepted: None,
        }
    }

    /// Returns whether the next sample is allowed by the filter.
    #[must_use]
    pub fn should_accept(&self) -> bool {
        if self.filter.is_disabled() {
            return true;
        }

        let Some(last) = self.last_accepted else {
            return true;
        };

        let elapsed = Instant::now().saturating_duration_since(last);
        elapsed >= self.filter.minimum_separation
    }

    /// Records that the current sample has been accepted.
    pub fn mark_accepted(&mut self) {
        self.last_accepted = Some(Instant::now());
    }

    /// Clears the internal state so the next sample is accepted.
    pub fn reset(&mut self) {
        self.last_accepted = None;
    }

    /// Time remaining until the next sample will be accepted.
    ///
    /// Returns `None` if filtering is disabled, if no samples were
    /// accepted yet, or if the separation has already elapsed.
    #[must_use]
    pub fn time_until_next_accept(&self) -> Option<Duration> {
        if self.filter.is_disabled() {
            return None;
        }

        let last = self.last_accepted?;
        let elapsed = Instant::now().saturating_duration_since(last);
        self.filter.minimum_separation.checked_sub(elapsed)
    }
}
