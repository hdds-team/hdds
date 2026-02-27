// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS Listener Traits
//!
//! Listeners provide callback-based notification for DDS entity events.
//! This is an alternative to the polling-based StatusCondition/WaitSet pattern.
//!
//! # Usage
//!
//! ```ignore
//! use hdds::{Participant, QoS, DataReaderListener};
//! use std::sync::Arc;
//!
//! struct MyListener;
//!
//! impl<T: hdds::DdsTrait> DataReaderListener<T> for MyListener {
//!     fn on_data_available(&self, sample: &T) {
//!         println!("Received sample!");
//!     }
//! }
//!
//! let reader = participant
//!     .create_reader::<Temperature>("temp", QoS::default())
//!     .with_listener(Arc::new(MyListener))
//!     .build()?;
//! ```
//!
//! # Thread Safety
//!
//! Listeners are called from background threads (router, discovery).
//! They must be `Send + Sync` and should not block or panic.
//!
//! # DDS Specification
//!
//! See DDS v1.4 Section 2.2.4 - Listeners, Conditions, and Wait-sets.

use crate::core::discovery::GUID;
use crate::dds::DDS;

/// Status information for subscription matching events.
#[derive(Debug, Clone, Default)]
pub struct SubscriptionMatchedStatus {
    /// Total cumulative count of matched publications.
    pub total_count: u32,
    /// Change in total_count since last callback.
    pub total_count_change: i32,
    /// Current number of matched publications.
    pub current_count: u32,
    /// Change in current_count since last callback.
    pub current_count_change: i32,
    /// GUID of the last matched/unmatched publication.
    pub last_publication_handle: Option<GUID>,
}

/// Status information for publication matching events.
#[derive(Debug, Clone, Default)]
pub struct PublicationMatchedStatus {
    /// Total cumulative count of matched subscriptions.
    pub total_count: u32,
    /// Change in total_count since last callback.
    pub total_count_change: i32,
    /// Current number of matched subscriptions.
    pub current_count: u32,
    /// Change in current_count since last callback.
    pub current_count_change: i32,
    /// GUID of the last matched/unmatched subscription.
    pub last_subscription_handle: Option<GUID>,
}

/// Status information for liveliness changes.
#[derive(Debug, Clone, Default)]
pub struct LivelinessChangedStatus {
    /// Number of publications currently asserting liveliness.
    pub alive_count: u32,
    /// Change in alive_count since last callback.
    pub alive_count_change: i32,
    /// Number of publications that have lost liveliness.
    pub not_alive_count: u32,
    /// Change in not_alive_count since last callback.
    pub not_alive_count_change: i32,
    /// GUID of the last publication to change liveliness.
    pub last_publication_handle: Option<GUID>,
}

/// Status information for sample lost events.
#[derive(Debug, Clone, Default)]
pub struct SampleLostStatus {
    /// Total cumulative count of lost samples.
    pub total_count: u32,
    /// Change in total_count since last callback.
    pub total_count_change: i32,
}

/// Status information for sample rejected events.
#[derive(Debug, Clone)]
pub struct SampleRejectedStatus {
    /// Total cumulative count of rejected samples.
    pub total_count: u32,
    /// Change in total_count since last callback.
    pub total_count_change: i32,
    /// Reason for rejection.
    pub last_reason: SampleRejectedReason,
}

impl Default for SampleRejectedStatus {
    fn default() -> Self {
        Self {
            total_count: 0,
            total_count_change: 0,
            last_reason: SampleRejectedReason::NotRejected,
        }
    }
}

/// Reason why a sample was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SampleRejectedReason {
    /// Sample was not rejected.
    #[default]
    NotRejected,
    /// Sample rejected due to resource limits (max_samples).
    ResourceLimit,
    /// Sample rejected due to instance limits (max_instances).
    InstanceLimit,
    /// Sample rejected due to samples-per-instance limit.
    SamplesPerInstanceLimit,
}

/// Status information for deadline missed events.
#[derive(Debug, Clone, Default)]
pub struct RequestedDeadlineMissedStatus {
    /// Total cumulative count of missed deadlines.
    pub total_count: u32,
    /// Change in total_count since last callback.
    pub total_count_change: i32,
    /// Handle of the instance that missed the deadline.
    pub last_instance_handle: Option<u64>,
}

/// Status information for incompatible QoS events.
#[derive(Debug, Clone, Default)]
pub struct RequestedIncompatibleQosStatus {
    /// Total cumulative count of incompatible QoS offers.
    pub total_count: u32,
    /// Change in total_count since last callback.
    pub total_count_change: i32,
    /// ID of the last incompatible QoS policy.
    pub last_policy_id: u32,
}

/// Listener for DataReader events.
///
/// Implement this trait to receive callbacks when events occur on a DataReader.
/// All methods have default no-op implementations, so you only need to override
/// the events you care about.
///
/// # Thread Safety
///
/// Callbacks are invoked from background threads. Implementations must be
/// `Send + Sync` and should avoid blocking operations.
///
/// # Example
///
/// ```ignore
/// struct MyReaderListener;
///
/// impl<T: DDS> DataReaderListener<T> for MyReaderListener {
///     fn on_data_available(&self, sample: &T) {
///         println!("Got data!");
///     }
///
///     fn on_subscription_matched(&self, status: SubscriptionMatchedStatus) {
///         println!("Matched with {} writers", status.current_count);
///     }
/// }
/// ```
pub trait DataReaderListener<T: DDS>: Send + Sync {
    /// Called when new data is available to read.
    ///
    /// This is the most commonly used callback. It's invoked when a sample
    /// arrives and passes content filtering (if configured).
    ///
    /// # Arguments
    ///
    /// * `sample` - The deserialized sample data
    ///
    /// # Notes
    ///
    /// - Called from router background thread
    /// - Should return quickly (non-blocking)
    /// - Sample is valid only for the duration of the callback
    fn on_data_available(&self, sample: &T) {
        let _ = sample;
    }

    /// Called when the reader matches or unmatches with a writer.
    ///
    /// # Arguments
    ///
    /// * `status` - Current subscription matched status
    fn on_subscription_matched(&self, status: SubscriptionMatchedStatus) {
        let _ = status;
    }

    /// Called when liveliness of a matched writer changes.
    ///
    /// # Arguments
    ///
    /// * `status` - Current liveliness status
    fn on_liveliness_changed(&self, status: LivelinessChangedStatus) {
        let _ = status;
    }

    /// Called when samples are lost (gap in sequence numbers).
    ///
    /// # Arguments
    ///
    /// * `status` - Sample lost status
    fn on_sample_lost(&self, status: SampleLostStatus) {
        let _ = status;
    }

    /// Called when samples are rejected due to resource limits.
    ///
    /// # Arguments
    ///
    /// * `status` - Sample rejected status with reason
    fn on_sample_rejected(&self, status: SampleRejectedStatus) {
        let _ = status;
    }

    /// Called when the requested deadline is missed.
    ///
    /// # Arguments
    ///
    /// * `status` - Deadline missed status
    fn on_requested_deadline_missed(&self, status: RequestedDeadlineMissedStatus) {
        let _ = status;
    }

    /// Called when QoS is incompatible with a matched writer.
    ///
    /// # Arguments
    ///
    /// * `status` - Incompatible QoS status
    fn on_requested_incompatible_qos(&self, status: RequestedIncompatibleQosStatus) {
        let _ = status;
    }
}

/// Listener for DataWriter events.
///
/// Implement this trait to receive callbacks when events occur on a DataWriter.
/// All methods have default no-op implementations.
///
/// # Example
///
/// ```ignore
/// struct MyWriterListener;
///
/// impl<T: DDS> DataWriterListener<T> for MyWriterListener {
///     fn on_publication_matched(&self, status: PublicationMatchedStatus) {
///         println!("Matched with {} readers", status.current_count);
///     }
/// }
/// ```
pub trait DataWriterListener<T: DDS>: Send + Sync {
    /// Called after a sample is successfully written.
    ///
    /// # Arguments
    ///
    /// * `sample` - The sample that was written
    /// * `sequence_number` - The assigned sequence number
    fn on_sample_written(&self, sample: &T, sequence_number: u64) {
        let _ = (sample, sequence_number);
    }

    /// Called when the writer matches or unmatches with a reader.
    ///
    /// # Arguments
    ///
    /// * `status` - Current publication matched status
    fn on_publication_matched(&self, status: PublicationMatchedStatus) {
        let _ = status;
    }

    /// Called when an offered deadline is missed.
    ///
    /// # Arguments
    ///
    /// * `instance_handle` - Handle of the instance that missed the deadline
    fn on_offered_deadline_missed(&self, instance_handle: Option<u64>) {
        let _ = instance_handle;
    }

    /// Called when QoS is incompatible with a matched reader.
    ///
    /// # Arguments
    ///
    /// * `policy_id` - ID of the incompatible QoS policy
    /// * `policy_name` - Name of the policy (e.g., "RELIABILITY")
    fn on_offered_incompatible_qos(&self, policy_id: u32, policy_name: &str) {
        let _ = (policy_id, policy_name);
    }

    /// Called when liveliness is lost (MANUAL_BY_* only).
    /// Default: no-op (user overrides if needed)
    fn on_liveliness_lost(&self) { /* @audit-ok: intentional no-op default */
    }
}

/// Closure-based listener for simple data callbacks.
///
/// Use this when you only need `on_data_available` and want a simple closure.
///
/// # Example
///
/// ```ignore
/// let listener = ClosureListener::new(|sample: &Temperature| {
///     println!("Temperature: {}", sample.value);
/// });
///
/// let reader = participant
///     .create_reader::<Temperature>("temp", QoS::default())
///     .with_listener(Arc::new(listener))
///     .build()?;
/// ```
pub struct ClosureListener<T: DDS, F: Fn(&T) + Send + Sync> {
    callback: F,
    _phantom: core::marker::PhantomData<T>,
}

impl<T: DDS, F: Fn(&T) + Send + Sync> ClosureListener<T, F> {
    /// Create a new closure-based listener.
    pub fn new(callback: F) -> Self {
        Self {
            callback,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<T: DDS, F: Fn(&T) + Send + Sync> DataReaderListener<T> for ClosureListener<T, F> {
    fn on_data_available(&self, sample: &T) {
        (self.callback)(sample);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    // Mock DDS type for testing
    #[derive(Clone, Debug, PartialEq)]
    struct TestData {
        value: u32,
    }

    const TEST_TYPE_ID: u32 = 0x1234_5678;

    impl DDS for TestData {
        fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
            static DESC: crate::core::types::TypeDescriptor = crate::core::types::TypeDescriptor {
                type_id: TEST_TYPE_ID,
                type_name: "TestData",
                size_bytes: 4,
                alignment: 4,
                is_variable_size: false,
                fields: &[],
            };
            &DESC
        }

        fn encode_cdr2(&self, buf: &mut [u8]) -> crate::dds::Result<usize> {
            if buf.len() < 4 {
                return Err(crate::dds::Error::BufferTooSmall);
            }
            buf[..4].copy_from_slice(&self.value.to_le_bytes());
            Ok(4)
        }

        fn decode_cdr2(buf: &[u8]) -> crate::dds::Result<Self> {
            if buf.len() < 4 {
                return Err(crate::dds::Error::SerializationError);
            }
            let value = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            Ok(TestData { value })
        }
    }

    #[test]
    fn test_closure_listener() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let listener = ClosureListener::new(move |_sample: &TestData| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        let sample = TestData { value: 42 };
        listener.on_data_available(&sample);
        listener.on_data_available(&sample);

        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_subscription_matched_status_default() {
        let status = SubscriptionMatchedStatus::default();
        assert_eq!(status.total_count, 0);
        assert_eq!(status.current_count, 0);
        assert!(status.last_publication_handle.is_none());
    }

    #[test]
    fn test_publication_matched_status_default() {
        let status = PublicationMatchedStatus::default();
        assert_eq!(status.total_count, 0);
        assert_eq!(status.current_count, 0);
    }

    #[test]
    fn test_sample_rejected_reason_default() {
        let reason = SampleRejectedReason::default();
        assert_eq!(reason, SampleRejectedReason::NotRejected);
    }

    // Test that default implementations don't panic
    struct NoOpListener;

    impl DataReaderListener<TestData> for NoOpListener {}
    impl DataWriterListener<TestData> for NoOpListener {}

    #[test]
    fn test_noop_reader_listener() {
        let listener = NoOpListener;
        let sample = TestData { value: 1 };

        // All these should do nothing but not panic
        listener.on_data_available(&sample);
        listener.on_subscription_matched(SubscriptionMatchedStatus::default());
        listener.on_liveliness_changed(LivelinessChangedStatus::default());
        listener.on_sample_lost(SampleLostStatus::default());
        listener.on_sample_rejected(SampleRejectedStatus::default());
        listener.on_requested_deadline_missed(RequestedDeadlineMissedStatus::default());
        listener.on_requested_incompatible_qos(RequestedIncompatibleQosStatus::default());
    }

    #[test]
    fn test_noop_writer_listener() {
        let listener = NoOpListener;
        let sample = TestData { value: 1 };

        // All these should do nothing but not panic
        listener.on_sample_written(&sample, 1);
        listener.on_publication_matched(PublicationMatchedStatus::default());
        listener.on_offered_deadline_missed(None);
        listener.on_offered_incompatible_qos(0, "RELIABILITY");
        listener.on_liveliness_lost();
    }
}
