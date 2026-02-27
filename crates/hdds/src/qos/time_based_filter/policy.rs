// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use std::time::Duration;

/// TIME_BASED_FILTER QoS policy.
///
/// Reader-side filtering that enforces a minimum separation between
/// accepted samples. A zero separation disables filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeBasedFilter {
    /// Minimum time between successive accepted samples.
    pub minimum_separation: Duration,
}

impl Default for TimeBasedFilter {
    /// Default: no filtering (zero separation).
    fn default() -> Self {
        Self {
            minimum_separation: Duration::ZERO,
        }
    }
}

impl TimeBasedFilter {
    /// Construct a filter with the requested minimum separation.
    #[must_use]
    pub fn new(minimum_separation: Duration) -> Self {
        Self { minimum_separation }
    }

    /// Construct a filter that accepts all samples (no throttling).
    #[must_use]
    pub fn zero() -> Self {
        Self::default()
    }

    /// Whether filtering is disabled.
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        self.minimum_separation == Duration::ZERO
    }

    /// Create TIME_BASED_FILTER from milliseconds.
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::time_based_filter::TimeBasedFilter;
    ///
    /// let filter = TimeBasedFilter::from_millis(100);
    /// assert_eq!(filter.minimum_separation.as_millis(), 100);
    /// ```
    #[must_use]
    pub fn from_millis(ms: u64) -> Self {
        Self {
            minimum_separation: Duration::from_millis(ms),
        }
    }

    /// Create TIME_BASED_FILTER from seconds.
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::time_based_filter::TimeBasedFilter;
    ///
    /// let filter = TimeBasedFilter::from_secs(1);
    /// assert_eq!(filter.minimum_separation.as_secs(), 1);
    /// ```
    #[must_use]
    pub fn from_secs(secs: u64) -> Self {
        Self {
            minimum_separation: Duration::from_secs(secs),
        }
    }
}
