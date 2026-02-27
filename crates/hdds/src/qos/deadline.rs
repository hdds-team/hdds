// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DEADLINE QoS policy (DDS v1.4 Sec.2.2.3.7)
//!
//! Specifies the expected sample publication/reception rate.
//! If no sample is received/published within the deadline period,
//! a deadline missed event is triggered.
//!
//! # QoS Compatibility (Request vs Offered)
//!
//! **Rule:** Writer offers <= Reader requests (RxO semantics)
//!
//! Example:
//! - Writer offers 100ms deadline -> Reader requests 200ms -> Compatible \[OK\]
//! - Writer offers 200ms deadline -> Reader requests 100ms -> Incompatible \[X\]
//!
//! # Use Cases
//!
//! - Periodic sensor data (e.g., IMU at 100 Hz)
//! - Heartbeat monitoring (detect stalled publishers)
//! - Real-time control loops (enforce sample rate)
//!
//! # Examples
//!
//! ```no_run
//! use hdds::qos::deadline::Deadline;
//! use std::time::Duration;
//!
//! // Writer must publish every 100ms
//! let writer_deadline = Deadline::new(Duration::from_millis(100));
//!
//! // Reader expects samples within 200ms
//! let reader_deadline = Deadline::new(Duration::from_millis(200));
//!
//! // Check compatibility
//! assert!(writer_deadline.is_compatible_with(&reader_deadline));
//! ```

use std::time::{Duration, Instant};

/// DEADLINE QoS policy
///
/// Specifies the maximum time between samples.
/// Default: Infinite (no deadline enforcement).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    /// Maximum time between samples
    pub period: Duration,
}

impl Default for Deadline {
    /// Default: Infinite deadline (no enforcement)
    fn default() -> Self {
        Self {
            period: Duration::from_secs(u64::MAX),
        }
    }
}

impl Deadline {
    /// Create new deadline policy with specified period
    ///
    /// # Arguments
    ///
    /// * `period` - Maximum time between samples
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::deadline::Deadline;
    /// use std::time::Duration;
    ///
    /// let deadline = Deadline::new(Duration::from_millis(100));
    /// assert_eq!(deadline.period, Duration::from_millis(100));
    /// ```
    pub fn new(period: Duration) -> Self {
        Self { period }
    }

    /// Create deadline with infinite period (no enforcement)
    pub fn infinite() -> Self {
        Self::default()
    }

    /// Check if deadline is infinite (no enforcement)
    pub fn is_infinite(&self) -> bool {
        self.period == Duration::from_secs(u64::MAX)
    }

    /// Create deadline from milliseconds
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::deadline::Deadline;
    ///
    /// let deadline = Deadline::from_millis(100);
    /// assert_eq!(deadline.period.as_millis(), 100);
    /// ```
    pub fn from_millis(ms: u64) -> Self {
        Self {
            period: Duration::from_millis(ms),
        }
    }

    /// Create deadline from seconds
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::deadline::Deadline;
    ///
    /// let deadline = Deadline::from_secs(5);
    /// assert_eq!(deadline.period.as_secs(), 5);
    /// ```
    pub fn from_secs(secs: u64) -> Self {
        Self {
            period: Duration::from_secs(secs),
        }
    }

    /// Check QoS compatibility between offered (writer) and requested (reader)
    ///
    /// **Rule (RxO):** Writer offers <= Reader requests
    ///
    /// # Arguments
    ///
    /// * `requested` - Reader's requested deadline
    ///
    /// # Returns
    ///
    /// `true` if compatible (writer can satisfy reader's requirement)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::deadline::Deadline;
    /// use std::time::Duration;
    ///
    /// let writer = Deadline::new(Duration::from_millis(100));
    /// let reader = Deadline::new(Duration::from_millis(200));
    ///
    /// assert!(writer.is_compatible_with(&reader)); // 100ms <= 200ms \[OK\]
    /// assert!(!reader.is_compatible_with(&writer)); // 200ms > 100ms \[X\]
    /// ```
    pub fn is_compatible_with(&self, requested: &Deadline) -> bool {
        // Writer offers <= Reader requests
        self.period <= requested.period
    }
}

/// Macro to generate deadline tracker implementations (eliminates 90+ lines of duplication)
///
/// Generates identical tracker logic for Writer and Reader with only field names differing.
///
/// # Parameters
/// - `$struct_name`: Name of the tracker struct (e.g., `DeadlineTracker`)
/// - `$doc`: Doc comment for the struct
/// - `$field`: Name of the timestamp field (e.g., `last_write` or `last_sample`)
/// - `$on_event`: Name of the event recording method (e.g., `on_write` or `on_sample`)
/// - `$event_doc`: Doc comment for the event method
/// - `$is_missed_doc`: Doc comment for is_missed (event-specific wording)
/// - `$time_doc`: Doc comment for time_until_deadline
macro_rules! impl_deadline_tracker {
    (
        $struct_name:ident,
        $doc:expr,
        $field:ident,
        $on_event:ident,
        $event_doc:expr,
        $is_missed_doc:expr,
        $time_doc:expr
    ) => {
        #[doc = $doc]
        #[derive(Debug)]
        pub struct $struct_name {
            deadline: Duration,
            $field: Option<Instant>,
            missed_count: u64,
        }

        impl $struct_name {
            /// Create new deadline tracker
            ///
            /// # Arguments
            ///
            /// * `deadline` - Maximum time between events
            pub fn new(deadline: Duration) -> Self {
                Self {
                    deadline,
                    $field: None,
                    missed_count: 0,
                }
            }

            #[doc = $event_doc]
            pub fn $on_event(&mut self) {
                self.$field = Some(Instant::now());
            }

            #[doc = $is_missed_doc]
            pub fn is_missed(&self) -> bool {
                if self.deadline == Duration::from_secs(u64::MAX) {
                    return false; // Infinite deadline, never missed
                }

                if let Some(last) = self.$field {
                    last.elapsed() > self.deadline
                } else {
                    false // No event yet, not missed
                }
            }

            /// Check deadline and increment missed count if violated
            ///
            /// Should be called periodically (e.g., from timer wheel).
            ///
            /// # Returns
            ///
            /// `true` if deadline was missed (count incremented)
            pub fn check(&mut self) -> bool {
                if self.is_missed() {
                    self.missed_count += 1;
                    true
                } else {
                    false
                }
            }

            /// Get total number of deadline misses
            pub fn missed_count(&self) -> u64 {
                self.missed_count
            }

            /// Reset missed count (e.g., after user acknowledgment)
            pub fn reset_missed_count(&mut self) {
                self.missed_count = 0;
            }

            #[doc = $time_doc]
            pub fn time_until_deadline(&self) -> Option<Duration> {
                if self.deadline == Duration::from_secs(u64::MAX) {
                    return None; // Infinite deadline
                }

                self.$field.map(|last| {
                    let elapsed = last.elapsed();
                    if elapsed < self.deadline {
                        self.deadline - elapsed
                    } else {
                        Duration::ZERO // Already missed
                    }
                })
            }
        }
    };
}

// Generate DeadlineTracker (for DataWriter)
impl_deadline_tracker!(
    DeadlineTracker,
    "Deadline tracker for DataWriter\n\nMonitors writer-side deadline violations.\nRecords last write timestamp and checks if deadline exceeded.",
    last_write,
    on_write,
    "Record write event\n\nUpdates last_write timestamp.",
    "Check if deadline is currently missed\n\n# Returns\n\n`true` if time since last write exceeds deadline",
    "Time remaining until next deadline\n\n# Returns\n\n- `Some(duration)` - Time until deadline\n- `None` - No write yet, or deadline already missed"
);

// Generate ReaderDeadlineTracker (for DataReader)
impl_deadline_tracker!(
    ReaderDeadlineTracker,
    "Deadline tracker for DataReader\n\nMonitors reader-side deadline violations.\nTracks last sample reception and detects missing samples.",
    last_sample,
    on_sample,
    "Record sample reception\n\nUpdates last_sample timestamp.",
    "Check if deadline is currently missed\n\n# Returns\n\n`true` if time since last sample exceeds deadline",
    "Time remaining until next deadline\n\n# Returns\n\n- `Some(duration)` - Time until deadline\n- `None` - No sample yet, or deadline already missed"
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_deadline_default() {
        let deadline = Deadline::default();
        assert_eq!(deadline.period, Duration::from_secs(u64::MAX));
        assert!(deadline.is_infinite());
    }

    #[test]
    fn test_deadline_new() {
        let deadline = Deadline::new(Duration::from_millis(100));
        assert_eq!(deadline.period, Duration::from_millis(100));
        assert!(!deadline.is_infinite());
    }

    #[test]
    fn test_deadline_infinite() {
        let deadline = Deadline::infinite();
        assert!(deadline.is_infinite());
    }

    #[test]
    fn test_compatibility_writer_faster() {
        // Writer publishes every 100ms, Reader expects within 200ms -> Compatible
        let writer = Deadline::new(Duration::from_millis(100));
        let reader = Deadline::new(Duration::from_millis(200));
        assert!(writer.is_compatible_with(&reader));
    }

    #[test]
    fn test_compatibility_writer_slower() {
        // Writer publishes every 200ms, Reader expects within 100ms -> Incompatible
        let writer = Deadline::new(Duration::from_millis(200));
        let reader = Deadline::new(Duration::from_millis(100));
        assert!(!writer.is_compatible_with(&reader));
    }

    #[test]
    fn test_compatibility_equal() {
        let writer = Deadline::new(Duration::from_millis(100));
        let reader = Deadline::new(Duration::from_millis(100));
        assert!(writer.is_compatible_with(&reader));
    }

    #[test]
    fn test_compatibility_infinite() {
        let infinite = Deadline::infinite();
        let finite = Deadline::new(Duration::from_millis(100));

        // Infinite offered (u64::MAX) vs finite requested (100ms)
        // u64::MAX > 100ms -> Incompatible (writer too slow)
        assert!(!infinite.is_compatible_with(&finite));

        // Infinite offered vs infinite requested -> Compatible
        assert!(infinite.is_compatible_with(&infinite));

        // Finite offered (100ms) vs infinite requested (u64::MAX)
        // 100ms <= u64::MAX -> Compatible
        assert!(finite.is_compatible_with(&infinite));
    }

    #[test]
    fn test_writer_tracker_no_write_not_missed() {
        let tracker = DeadlineTracker::new(Duration::from_millis(100));
        assert!(!tracker.is_missed());
        assert_eq!(tracker.missed_count(), 0);
    }

    #[test]
    fn test_writer_tracker_write_not_missed() {
        let mut tracker = DeadlineTracker::new(Duration::from_millis(100));
        tracker.on_write();
        assert!(!tracker.is_missed());
        assert_eq!(tracker.missed_count(), 0);
    }

    #[test]
    fn test_writer_tracker_deadline_missed() {
        let mut tracker = DeadlineTracker::new(Duration::from_millis(50));
        tracker.on_write();

        // Wait longer than deadline
        thread::sleep(Duration::from_millis(60));

        assert!(tracker.is_missed());
        assert!(tracker.check()); // Increment count
        assert_eq!(tracker.missed_count(), 1);
    }

    #[test]
    fn test_writer_tracker_multiple_misses() {
        let mut tracker = DeadlineTracker::new(Duration::from_millis(50));
        tracker.on_write();

        thread::sleep(Duration::from_millis(60));
        assert!(tracker.check());
        assert_eq!(tracker.missed_count(), 1);

        // Miss again
        thread::sleep(Duration::from_millis(60));
        assert!(tracker.check());
        assert_eq!(tracker.missed_count(), 2);
    }

    #[test]
    fn test_writer_tracker_reset() {
        let mut tracker = DeadlineTracker::new(Duration::from_millis(50));
        tracker.on_write();
        thread::sleep(Duration::from_millis(60));
        tracker.check();
        assert_eq!(tracker.missed_count(), 1);

        tracker.reset_missed_count();
        assert_eq!(tracker.missed_count(), 0);
    }

    #[test]
    fn test_writer_tracker_time_until_deadline() {
        let mut tracker = DeadlineTracker::new(Duration::from_millis(100));
        tracker.on_write();

        // Immediately after write, should have ~100ms remaining
        let remaining = tracker
            .time_until_deadline()
            .expect("Time until deadline should be available after write");
        assert!(remaining.as_millis() >= 90 && remaining.as_millis() <= 100);

        thread::sleep(Duration::from_millis(50));

        // After 50ms, should have ~50ms remaining
        let remaining = tracker
            .time_until_deadline()
            .expect("Time until deadline should be available after write");
        assert!(remaining.as_millis() >= 40 && remaining.as_millis() <= 60);
    }

    #[test]
    fn test_writer_tracker_infinite_never_missed() {
        let mut tracker = DeadlineTracker::new(Duration::from_secs(u64::MAX));
        tracker.on_write();
        thread::sleep(Duration::from_millis(10));
        assert!(!tracker.is_missed());
        assert!(!tracker.check());
    }

    #[test]
    fn test_reader_tracker_no_sample_not_missed() {
        let tracker = ReaderDeadlineTracker::new(Duration::from_millis(100));
        assert!(!tracker.is_missed());
        assert_eq!(tracker.missed_count(), 0);
    }

    #[test]
    fn test_reader_tracker_sample_not_missed() {
        let mut tracker = ReaderDeadlineTracker::new(Duration::from_millis(100));
        tracker.on_sample();
        assert!(!tracker.is_missed());
        assert_eq!(tracker.missed_count(), 0);
    }

    #[test]
    fn test_reader_tracker_deadline_missed() {
        let mut tracker = ReaderDeadlineTracker::new(Duration::from_millis(50));
        tracker.on_sample();

        thread::sleep(Duration::from_millis(60));

        assert!(tracker.is_missed());
        assert!(tracker.check());
        assert_eq!(tracker.missed_count(), 1);
    }

    #[test]
    fn test_reader_tracker_multiple_misses() {
        let mut tracker = ReaderDeadlineTracker::new(Duration::from_millis(50));
        tracker.on_sample();

        thread::sleep(Duration::from_millis(60));
        tracker.check();
        assert_eq!(tracker.missed_count(), 1);

        thread::sleep(Duration::from_millis(60));
        tracker.check();
        assert_eq!(tracker.missed_count(), 2);
    }

    #[test]
    fn test_reader_tracker_reset() {
        let mut tracker = ReaderDeadlineTracker::new(Duration::from_millis(50));
        tracker.on_sample();
        thread::sleep(Duration::from_millis(60));
        tracker.check();
        assert_eq!(tracker.missed_count(), 1);

        tracker.reset_missed_count();
        assert_eq!(tracker.missed_count(), 0);
    }

    #[test]
    fn test_reader_tracker_sample_resets_timer() {
        let mut tracker = ReaderDeadlineTracker::new(Duration::from_millis(100));
        tracker.on_sample();

        thread::sleep(Duration::from_millis(60));
        assert!(!tracker.is_missed()); // Still within deadline

        // New sample resets timer
        tracker.on_sample();
        thread::sleep(Duration::from_millis(60));
        assert!(!tracker.is_missed()); // Still within deadline after reset
    }

    #[test]
    fn test_reader_tracker_infinite_never_missed() {
        let mut tracker = ReaderDeadlineTracker::new(Duration::from_secs(u64::MAX));
        tracker.on_sample();
        thread::sleep(Duration::from_millis(10));
        assert!(!tracker.is_missed());
        assert!(!tracker.check());
    }
}
