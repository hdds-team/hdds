// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! LIFESPAN QoS policy (DDS v1.4 Sec.2.2.3.9)
//!
//! Specifies the maximum duration a sample remains valid.
//! Samples older than the lifespan are considered expired and must be discarded.
//!
//! # QoS Compatibility (Request vs Offered)
//!
//! **Rule:** Writer offers >= Reader requests (RxO semantics)
//!
//! Example:
//! - Writer offers 10s lifespan -> Reader requests 5s -> Compatible \[OK\]
//! - Writer offers 5s lifespan -> Reader requests 10s -> Incompatible \[X\]
//!   (Reader would receive expired samples)
//!
//! # Use Cases
//!
//! - Time-sensitive commands (expire after 1s if not processed)
//! - Sensor readings that become stale (IMU data older than 100ms)
//! - Cache invalidation (historical data expires after N seconds)
//! - Event notifications (alerts expire after 5s)
//!
//! # Difference from DEADLINE
//!
//! - **DEADLINE**: Time BETWEEN samples (publication rate)
//! - **LIFESPAN**: Time FOR a sample (validity duration)
//!
//! # Examples
//!
//! ```no_run
//! use hdds::qos::lifespan::Lifespan;
//! use std::time::Duration;
//!
//! // Writer: samples expire after 10 seconds
//! let writer_lifespan = Lifespan::new(Duration::from_secs(10));
//!
//! // Reader: reject samples older than 5 seconds
//! let reader_lifespan = Lifespan::new(Duration::from_secs(5));
//!
//! // Check compatibility (Writer 10s >= Reader 5s -> Compatible)
//! assert!(writer_lifespan.is_compatible_with(&reader_lifespan));
//! ```

use std::time::{Duration, Instant};

/// LIFESPAN QoS policy
///
/// Specifies the maximum duration a sample remains valid.
/// Default: Infinite (samples never expire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifespan {
    /// Maximum sample validity duration
    pub duration: Duration,
}

impl Default for Lifespan {
    /// Default: Infinite lifespan (no expiration)
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(u64::MAX),
        }
    }
}

impl Lifespan {
    /// Create new lifespan policy with specified duration
    ///
    /// # Arguments
    ///
    /// * `duration` - Maximum sample validity duration
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::lifespan::Lifespan;
    /// use std::time::Duration;
    ///
    /// let lifespan = Lifespan::new(Duration::from_secs(5));
    /// assert_eq!(lifespan.duration, Duration::from_secs(5));
    /// ```
    pub fn new(duration: Duration) -> Self {
        Self { duration }
    }

    /// Create lifespan with infinite duration (no expiration)
    pub fn infinite() -> Self {
        Self::default()
    }

    /// Check if lifespan is infinite (no expiration)
    pub fn is_infinite(&self) -> bool {
        self.duration == Duration::from_secs(u64::MAX)
    }

    /// Create lifespan from milliseconds
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::lifespan::Lifespan;
    ///
    /// let lifespan = Lifespan::from_millis(500);
    /// assert_eq!(lifespan.duration.as_millis(), 500);
    /// ```
    pub fn from_millis(ms: u64) -> Self {
        Self {
            duration: Duration::from_millis(ms),
        }
    }

    /// Create lifespan from seconds
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::lifespan::Lifespan;
    ///
    /// let lifespan = Lifespan::from_secs(10);
    /// assert_eq!(lifespan.duration.as_secs(), 10);
    /// ```
    pub fn from_secs(secs: u64) -> Self {
        Self {
            duration: Duration::from_secs(secs),
        }
    }

    /// Check QoS compatibility between offered (writer) and requested (reader)
    ///
    /// **Rule (RxO):** Writer offers >= Reader requests
    ///
    /// # Arguments
    ///
    /// * `requested` - Reader's requested lifespan
    ///
    /// # Returns
    ///
    /// `true` if compatible (writer keeps samples long enough for reader)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::lifespan::Lifespan;
    /// use std::time::Duration;
    ///
    /// // Writer keeps samples for 10s
    /// let writer = Lifespan::new(Duration::from_secs(10));
    ///
    /// // Reader wants samples valid for at least 5s
    /// let reader = Lifespan::new(Duration::from_secs(5));
    ///
    /// assert!(writer.is_compatible_with(&reader)); // 10s >= 5s \[OK\]
    /// ```
    pub fn is_compatible_with(&self, requested: &Lifespan) -> bool {
        // Infinite lifespan satisfies any request
        if self.is_infinite() {
            return true;
        }

        // If reader requests infinite but writer offers finite -> incompatible
        if requested.is_infinite() {
            return false;
        }

        // Writer must offer >= Reader requests
        self.duration >= requested.duration
    }
}

/// Lifespan checker for tracking sample expiration
///
/// Validates whether samples have expired based on their timestamp.
#[derive(Debug)]
pub struct LifespanChecker {
    /// Lifespan duration
    lifespan: Lifespan,
}

impl LifespanChecker {
    /// Create new lifespan checker
    ///
    /// # Arguments
    ///
    /// * `lifespan` - Lifespan policy to enforce
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::lifespan::{Lifespan, LifespanChecker};
    /// use std::time::Duration;
    ///
    /// let lifespan = Lifespan::new(Duration::from_secs(5));
    /// let checker = LifespanChecker::new(lifespan);
    /// ```
    pub fn new(lifespan: Lifespan) -> Self {
        Self { lifespan }
    }

    /// Check if a sample has expired
    ///
    /// # Arguments
    ///
    /// * `sample_timestamp` - When the sample was created
    ///
    /// # Returns
    ///
    /// `true` if sample has expired (age > lifespan)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::lifespan::{Lifespan, LifespanChecker};
    /// use std::time::{Duration, Instant};
    ///
    /// let lifespan = Lifespan::new(Duration::from_millis(100));
    /// let checker = LifespanChecker::new(lifespan);
    ///
    /// let old_timestamp = Instant::now()
    ///     .checked_sub(Duration::from_millis(200))
    ///     .expect("Time subtraction should succeed");
    /// assert!(checker.is_expired(old_timestamp)); // Expired (200ms > 100ms)
    ///
    /// let recent_timestamp = Instant::now();
    /// assert!(!checker.is_expired(recent_timestamp)); // Not expired
    /// ```
    pub fn is_expired(&self, sample_timestamp: Instant) -> bool {
        if self.lifespan.is_infinite() {
            return false; // Never expires
        }

        let age = Instant::now().saturating_duration_since(sample_timestamp);
        age > self.lifespan.duration
    }

    /// Check if a sample is still valid (not expired)
    ///
    /// # Arguments
    ///
    /// * `sample_timestamp` - When the sample was created
    ///
    /// # Returns
    ///
    /// `true` if sample is still valid (age <= lifespan)
    pub fn is_valid(&self, sample_timestamp: Instant) -> bool {
        !self.is_expired(sample_timestamp)
    }

    /// Get remaining time before expiration
    ///
    /// # Arguments
    ///
    /// * `sample_timestamp` - When the sample was created
    ///
    /// # Returns
    ///
    /// Remaining duration, or None if already expired or infinite lifespan
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::lifespan::{Lifespan, LifespanChecker};
    /// use std::time::{Duration, Instant};
    ///
    /// let lifespan = Lifespan::new(Duration::from_secs(10));
    /// let checker = LifespanChecker::new(lifespan);
    ///
    /// let timestamp = Instant::now();
    /// if let Some(remaining) = checker.remaining_time(timestamp) {
    ///     println!("Sample expires in {:?}", remaining);
    /// }
    /// ```
    pub fn remaining_time(&self, sample_timestamp: Instant) -> Option<Duration> {
        if self.lifespan.is_infinite() {
            return None; // Never expires
        }

        let age = Instant::now().saturating_duration_since(sample_timestamp);
        self.lifespan.duration.checked_sub(age)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_lifespan_default() {
        let lifespan = Lifespan::default();
        assert!(lifespan.is_infinite());
    }

    #[test]
    fn test_lifespan_infinite() {
        let lifespan = Lifespan::infinite();
        assert!(lifespan.is_infinite());
        assert_eq!(lifespan.duration, Duration::from_secs(u64::MAX));
    }

    #[test]
    fn test_lifespan_new() {
        let lifespan = Lifespan::new(Duration::from_secs(5));
        assert!(!lifespan.is_infinite());
        assert_eq!(lifespan.duration, Duration::from_secs(5));
    }

    #[test]
    fn test_lifespan_is_infinite() {
        let infinite = Lifespan::infinite();
        let finite = Lifespan::new(Duration::from_secs(10));

        assert!(infinite.is_infinite());
        assert!(!finite.is_infinite());
    }

    #[test]
    fn test_compatibility_writer_greater_than_reader() {
        // Writer keeps samples for 10s, Reader wants 5s validity
        let writer = Lifespan::new(Duration::from_secs(10));
        let reader = Lifespan::new(Duration::from_secs(5));

        assert!(writer.is_compatible_with(&reader)); // 10s >= 5s \[OK\]
    }

    #[test]
    fn test_compatibility_writer_less_than_reader() {
        // Writer keeps samples for 5s, Reader wants 10s validity
        let writer = Lifespan::new(Duration::from_secs(5));
        let reader = Lifespan::new(Duration::from_secs(10));

        assert!(!writer.is_compatible_with(&reader)); // 5s < 10s \[X\]
    }

    #[test]
    fn test_compatibility_equal() {
        let writer = Lifespan::new(Duration::from_secs(5));
        let reader = Lifespan::new(Duration::from_secs(5));

        assert!(writer.is_compatible_with(&reader)); // 5s == 5s \[OK\]
    }

    #[test]
    fn test_compatibility_writer_infinite() {
        let writer = Lifespan::infinite();
        let reader = Lifespan::new(Duration::from_secs(5));

        assert!(writer.is_compatible_with(&reader)); // Infinite satisfies any
    }

    #[test]
    fn test_compatibility_reader_infinite_writer_finite() {
        let writer = Lifespan::new(Duration::from_secs(10));
        let reader = Lifespan::infinite();

        assert!(!writer.is_compatible_with(&reader)); // Finite cannot satisfy infinite
    }

    #[test]
    fn test_compatibility_both_infinite() {
        let writer = Lifespan::infinite();
        let reader = Lifespan::infinite();

        assert!(writer.is_compatible_with(&reader)); // Both infinite \[OK\]
    }

    #[test]
    fn test_checker_new() {
        let lifespan = Lifespan::new(Duration::from_secs(5));
        let checker = LifespanChecker::new(lifespan);

        assert_eq!(checker.lifespan.duration, Duration::from_secs(5));
    }

    #[test]
    fn test_checker_is_expired_infinite() {
        let lifespan = Lifespan::infinite();
        let checker = LifespanChecker::new(lifespan);

        let old_timestamp = Instant::now()
            .checked_sub(Duration::from_secs(1000))
            .expect("test timestamp subtraction should succeed");
        assert!(!checker.is_expired(old_timestamp)); // Never expires
    }

    #[test]
    fn test_checker_is_expired_recent() {
        let lifespan = Lifespan::new(Duration::from_millis(100));
        let checker = LifespanChecker::new(lifespan);

        let recent_timestamp = Instant::now();
        assert!(!checker.is_expired(recent_timestamp)); // Not expired
    }

    #[test]
    fn test_checker_is_expired_old() {
        let lifespan = Lifespan::new(Duration::from_millis(50));
        let checker = LifespanChecker::new(lifespan);

        let old_timestamp = Instant::now()
            .checked_sub(Duration::from_millis(100))
            .expect("test timestamp subtraction should succeed");
        assert!(checker.is_expired(old_timestamp)); // Expired (100ms > 50ms)
    }

    #[test]
    fn test_checker_is_valid() {
        let lifespan = Lifespan::new(Duration::from_millis(100));
        let checker = LifespanChecker::new(lifespan);

        let recent_timestamp = Instant::now();
        assert!(checker.is_valid(recent_timestamp)); // Valid

        let old_timestamp = Instant::now()
            .checked_sub(Duration::from_millis(200))
            .expect("test timestamp subtraction should succeed");
        assert!(!checker.is_valid(old_timestamp)); // Invalid (expired)
    }

    #[test]
    fn test_checker_remaining_time_infinite() {
        let lifespan = Lifespan::infinite();
        let checker = LifespanChecker::new(lifespan);

        let timestamp = Instant::now();
        assert!(checker.remaining_time(timestamp).is_none()); // Infinite -> None
    }

    #[test]
    fn test_checker_remaining_time_valid() {
        let lifespan = Lifespan::new(Duration::from_secs(10));
        let checker = LifespanChecker::new(lifespan);

        let timestamp = Instant::now();
        let remaining = checker
            .remaining_time(timestamp)
            .expect("remaining time should be Some for fresh timestamp");

        assert!(remaining <= Duration::from_secs(10));
        assert!(remaining > Duration::from_secs(9)); // Should be close to 10s
    }

    #[test]
    fn test_checker_remaining_time_expired() {
        let lifespan = Lifespan::new(Duration::from_millis(50));
        let checker = LifespanChecker::new(lifespan);

        let old_timestamp = Instant::now()
            .checked_sub(Duration::from_millis(100))
            .expect("test timestamp subtraction should succeed");
        assert!(checker.remaining_time(old_timestamp).is_none()); // Expired -> None
    }

    #[test]
    fn test_checker_expiration_edge_case() {
        let lifespan = Lifespan::new(Duration::from_millis(100));
        let checker = LifespanChecker::new(lifespan);

        let timestamp = Instant::now();

        // Sleep slightly past expiration
        thread::sleep(Duration::from_millis(110));

        assert!(checker.is_expired(timestamp)); // Should be expired
        assert!(!checker.is_valid(timestamp));
        assert!(checker.remaining_time(timestamp).is_none());
    }

    #[test]
    fn test_lifespan_clone() {
        let lifespan1 = Lifespan::new(Duration::from_secs(5));
        let lifespan2 = lifespan1;

        assert_eq!(lifespan1.duration, lifespan2.duration);
    }

    #[test]
    fn test_lifespan_debug() {
        let lifespan = Lifespan::new(Duration::from_secs(5));
        let debug_str = format!("{:?}", lifespan);

        assert!(debug_str.contains("Lifespan"));
    }

    #[test]
    fn test_checker_debug() {
        let lifespan = Lifespan::new(Duration::from_secs(5));
        let checker = LifespanChecker::new(lifespan);
        let debug_str = format!("{:?}", checker);

        assert!(debug_str.contains("LifespanChecker"));
    }
}
