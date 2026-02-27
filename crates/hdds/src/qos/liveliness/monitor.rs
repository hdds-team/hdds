// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::{Liveliness, LivelinessKind};
use std::time::{Duration, Instant};

/// Liveliness monitor for tracking entity health.
#[derive(Debug)]
pub struct LivelinessMonitor {
    kind: LivelinessKind,
    lease_duration: Duration,
    last_assert: Instant,
    alive: bool,
}

impl LivelinessMonitor {
    #[must_use]
    pub fn new(kind: LivelinessKind, lease_duration: Duration) -> Self {
        Self {
            kind,
            lease_duration,
            last_assert: Instant::now(),
            alive: true,
        }
    }

    #[must_use]
    pub fn from_policy(policy: &Liveliness) -> Self {
        Self::new(policy.kind, policy.lease_duration)
    }

    pub fn assert(&mut self) {
        self.last_assert = Instant::now();
        self.alive = true;
    }

    pub fn check(&mut self) -> bool {
        if self.lease_duration == Duration::from_secs(u64::MAX) {
            return true;
        }
        if self.last_assert.elapsed() > self.lease_duration {
            self.alive = false;
        }
        self.alive
    }

    #[must_use]
    pub fn is_alive(&self) -> bool {
        if self.lease_duration == Duration::from_secs(u64::MAX) {
            return true;
        }
        self.alive && self.last_assert.elapsed() <= self.lease_duration
    }

    #[must_use]
    pub fn kind(&self) -> LivelinessKind {
        self.kind
    }

    #[must_use]
    pub fn time_until_expiry(&self) -> Option<Duration> {
        if self.lease_duration == Duration::from_secs(u64::MAX) {
            return None;
        }
        let elapsed = self.last_assert.elapsed();
        if elapsed < self.lease_duration {
            Some(self.lease_duration - elapsed)
        } else {
            Some(Duration::ZERO)
        }
    }

    #[must_use]
    pub fn time_since_last_assert(&self) -> Duration {
        self.last_assert.elapsed()
    }
}
