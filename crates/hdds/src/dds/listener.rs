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

use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use arc_swap::ArcSwapOption;

use crate::core::discovery::GUID;
use crate::dds::condition::StatusMask;
use crate::dds::reader::InstanceHandle;
use crate::dds::DDS;

/// Bit set in a [`ListenerSlot`]'s hint whenever a listener is installed,
/// whatever its mask: what the non-status callbacks (`on_sample_written`)
/// check.
const INSTALLED_HINT: u32 = 1 << 31;

/// A listener together with the statuses it was installed for.
pub(crate) struct InstalledListener<L: ?Sized> {
    listener: Arc<L>,
    mask: StatusMask,
}

/// The listener of one entity, replaceable at runtime (DDS v1.4
/// Sec.2.2.2.1.1 `set_listener`).
///
/// Every place that calls a listener holds the entity's slot, never the
/// listener itself, so a listener installed (or removed) after the entity
/// was built reaches every callback site at once: the data path, the
/// match-notification callbacks registered at build time, the deadline
/// checks.
///
/// A callback site loads the current listener, then calls it with no
/// slot lock held. A listener replaced while one of its callbacks runs
/// therefore finishes that callback (it holds its own `Arc`): replacing a
/// listener does not wait for callbacks already running. A caller that
/// must know none is running (a foreign-language binding about to free
/// the state its callbacks use) drains them itself.
///
/// Cost on a callback site with no listener: one relaxed load of the hint.
pub(crate) struct ListenerSlot<L: ?Sized> {
    current: ArcSwapOption<InstalledListener<L>>,
    /// The installed mask's bits plus [`INSTALLED_HINT`], 0 with no
    /// listener. A fast negative only: the mask that decides is the one
    /// stored with the listener.
    hint: Arc<AtomicU32>,
    /// Serializes `set`, so the hint always describes the stored listener
    /// once every `set` has returned.
    set_lock: Mutex<()>,
}

impl<L: ?Sized> ListenerSlot<L> {
    /// A slot holding `initial` for every status (a listener given to the
    /// builder), or empty.
    pub(crate) fn new(initial: Option<Arc<L>>) -> Self {
        let slot = Self {
            current: ArcSwapOption::empty(),
            hint: Arc::new(AtomicU32::new(0)),
            set_lock: Mutex::new(()),
        };
        if initial.is_some() {
            slot.set(initial, StatusMask::ALL);
        }
        slot
    }

    /// Install `listener` for the statuses in `mask`, or remove the
    /// current one (`None`). Does not wait for callbacks already running.
    pub(crate) fn set(&self, listener: Option<Arc<L>>, mask: StatusMask) {
        let _serial = self.set_lock.lock().unwrap_or_else(|e| e.into_inner());
        match listener {
            Some(listener) => {
                self.current
                    .store(Some(Arc::new(InstalledListener { listener, mask })));
                self.hint
                    .store(mask.bits() | INSTALLED_HINT, Ordering::Release);
            }
            None => {
                self.hint.store(0, Ordering::Release);
                self.current.store(None);
            }
        }
    }

    /// The listener installed for `status`, if any.
    #[inline]
    pub(crate) fn get(&self, status: StatusMask) -> Option<Arc<L>> {
        if self.hint.load(Ordering::Relaxed) & status.bits() == 0 {
            return None;
        }
        self.get_slow(Some(status))
    }

    /// The installed listener whatever its mask (for the callbacks that
    /// have no DDS status, such as `on_sample_written`).
    #[inline]
    pub(crate) fn get_any(&self) -> Option<Arc<L>> {
        if self.hint.load(Ordering::Relaxed) == 0 {
            return None;
        }
        self.get_slow(None)
    }

    #[inline(never)]
    fn get_slow(&self, status: Option<StatusMask>) -> Option<Arc<L>> {
        let guard = self.current.load();
        let installed = guard.as_ref()?;
        if let Some(status) = status {
            if !installed.mask.contains(status) {
                return None;
            }
        }
        Some(Arc::clone(&installed.listener))
    }

    /// The slot's hint, for a callback site that cannot hold the slot
    /// itself (the intra-process delivery observer in a writer's merger):
    /// `hint & status.bits() != 0` is the same fast negative [`Self::get`]
    /// takes.
    pub(crate) fn hint(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.hint)
    }
}

/// The listener slot of a `DataReader<T>`.
pub(crate) type ReaderListenerSlot<T> = ListenerSlot<dyn DataReaderListener<T>>;

/// The listener slot of a `DataWriter<T>`.
pub(crate) type WriterListenerSlot<T> = ListenerSlot<dyn DataWriterListener<T>>;

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

/// Status information for liveliness lost events (DDS v1.4 Sec.2.2.4.1,
/// Figure 2.14): how many times this writer failed to assert its
/// liveliness within its offered LIVELINESS lease (MANUAL_BY_PARTICIPANT,
/// MANUAL_BY_TOPIC only -- AUTOMATIC is asserted by the middleware itself).
#[derive(Debug, Clone, Default)]
pub struct LivelinessLostStatus {
    /// Total cumulative count of liveliness losses.
    pub total_count: u32,
    /// Change in total_count since last callback.
    pub total_count_change: i32,
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
///
/// Shape matches DDS v1.4 Sec.2.2.4.1.9 (Figure 2.13 SampleRejectedStatus):
/// `total_count`, `total_count_change`, `last_reason`, `last_instance_handle`.
#[derive(Debug, Clone)]
pub struct SampleRejectedStatus {
    /// Total cumulative count of rejected samples.
    pub total_count: u32,
    /// The incremental number of samples rejected since the last time the
    /// listener was called or the status was read (DDS v1.4 Sec.2.2.4.1.9).
    pub total_count_change: i32,
    /// Reason for rejecting the last sample rejected. `NotRejected` if no
    /// sample has ever been rejected.
    pub last_reason: SampleRejectedReason,
    /// Handle to the instance updated by the last sample that was
    /// rejected: the same `InstanceHandle` that instance's samples carry
    /// in `SampleInfo::instance_handle`, usable with
    /// `DataReader::take_instance` / `read_instance`. `None` when the
    /// type has no key (a keyless topic has a single, unidentified
    /// instance) -- see `T::has_key()`.
    pub last_instance_handle: Option<InstanceHandle>,
}

impl Default for SampleRejectedStatus {
    fn default() -> Self {
        Self {
            total_count: 0,
            total_count_change: 0,
            last_reason: SampleRejectedReason::NotRejected,
            last_instance_handle: None,
        }
    }
}

/// Reason why a sample was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SampleRejectedReason {
    /// Sample was not rejected.
    #[default]
    NotRejected,
    /// Sample rejected on a reader-side resource bound (DDS
    /// REJECTED_BY_SAMPLES_LIMIT): the sample was received -- dedup'd and
    /// credited to the control-plane proxy registry -- and then discarded
    /// because either this reader's own history ring was full, or the
    /// process-wide slab byte budget (shared with every other reader in
    /// the process, so an idle reader can be rejected by a neighbour's
    /// traffic) had no room left. The two `samples_rejected_ring_full` /
    /// `samples_rejected_slab_exhausted` telemetry counters are the only
    /// way to tell the two apart; this reason alone does not.
    ResourceLimit,
    /// Sample rejected due to instance limits (max_instances).
    InstanceLimit,
    /// Sample rejected due to samples-per-instance limit.
    SamplesPerInstanceLimit,
}

/// Status information for offered deadline missed events (writer-side).
#[derive(Debug, Clone, Default)]
pub struct OfferedDeadlineMissedStatus {
    /// Total cumulative count of missed deadlines.
    pub total_count: u32,
    /// Change in total_count since last callback.
    pub total_count_change: i32,
    /// Handle of the instance that missed the deadline.
    pub last_instance_handle: Option<InstanceHandle>,
}

/// Status information for deadline missed events.
#[derive(Debug, Clone, Default)]
pub struct RequestedDeadlineMissedStatus {
    /// Total cumulative count of missed deadlines.
    pub total_count: u32,
    /// Change in total_count since last callback.
    pub total_count_change: i32,
    /// Handle of the instance that missed the deadline.
    pub last_instance_handle: Option<InstanceHandle>,
}

/// Status information for incompatible QoS events.
#[derive(Debug, Clone, Default)]
pub struct RequestedIncompatibleQosStatus {
    /// Total cumulative count of incompatible QoS offers.
    pub total_count: u32,
    /// Change in total_count since last callback.
    pub total_count_change: i32,
    /// QosPolicyId_t of the last incompatible QoS policy (DDS v1.4
    /// Sec.2.3.3; `crate::dds::qos::policy_id`).
    pub last_policy_id: u32,
}

/// Status information for a DataWriter's incompatible QoS events (DDS v1.4
/// Sec.2.2.4.1 `OFFERED_INCOMPATIBLE_QOS`): the writer-side counterpart of
/// [`RequestedIncompatibleQosStatus`], read by
/// `DataWriter::get_offered_incompatible_qos_status`. The listener callback
/// `DataWriterListener::on_offered_incompatible_qos` keeps its existing
/// `(policy_id, policy_name)` signature; this struct only backs the getter.
#[derive(Debug, Clone, Default)]
pub struct OfferedIncompatibleQosStatus {
    /// Total cumulative count of incompatible QoS matches refused.
    pub total_count: u32,
    /// Change in total_count since last callback or getter read.
    pub total_count_change: i32,
    /// QosPolicyId_t of the last incompatible QoS policy (DDS v1.4
    /// Sec.2.3.3; `crate::dds::qos::policy_id`).
    pub last_policy_id: u32,
}

/// Status information for inconsistent topic type events.
///
/// Fired on a DataWriter (or DataReader) when a remote endpoint on the
/// same topic announces a type name or type hash that is structurally
/// incompatible with the local type, per DDS-XTypes v1.3 sec. 7.6.3.4.3.
/// The status accumulates across all such remote endpoints observed
/// during the lifetime of the local entity.
#[derive(Debug, Clone, Default)]
pub struct InconsistentTopicStatus {
    /// Total cumulative count of inconsistent-type discoveries.
    pub total_count: u32,
    /// Change in total_count since the last callback invocation.
    pub total_count_change: i32,
}

/// Logs, once per listener type, that a reader delivering through
/// `on_data_available_notification` reached a listener that does not
/// implement it (the trait default).
fn warn_notification_not_implemented<L: ?Sized>() {
    static WARNED: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let name = std::any::type_name::<L>();
    let mut warned = WARNED
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if warned.insert(name) {
        log::warn!(
            "DataReaderListener {name}: this listener's reader delivers through \
             on_data_available_notification (BY_SOURCE_TIMESTAMP or TIME_BASED_FILTER), \
             and the listener does not implement it: it gets no data callback. Implement \
             on_data_available_notification and read or take from the reader."
        );
    }
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
    /// - Not called for a reader whose DESTINATION_ORDER is
    ///   BY_SOURCE_TIMESTAMP: such a reader accepts or refuses a sample
    ///   when the application reads it (DDS v1.4 Sec.2.2.3.17), so no
    ///   sample is handed out on arrival. Instead,
    ///   [`Self::on_data_available_notification`] is invoked; use it to
    ///   read the accepted samples with `take`/`read`.
    fn on_data_available(&self, sample: &T) {
        let _ = sample;
    }

    /// Called when data may be read, without exposing an unaccepted payload.
    ///
    /// A BY_SOURCE_TIMESTAMP reader, and a reader with a TIME_BASED_FILTER,
    /// use this DATA_AVAILABLE callback on network, coherent and
    /// intra-process delivery (DDS v1.4 Sec.2.2.4.3.2). A filtered reader
    /// also gets it when a held sample's window ends. Read or take from the associated reader to obtain
    /// accepted samples: a newer change may have superseded an arrival.
    /// A listener can retain a weak reference to its reader for this purpose.
    /// The callback runs outside reader and delivery locks, on the delivering
    /// thread, and should return quickly. The DATA_AVAILABLE listener mask
    /// controls it, including listeners installed with `set_listener`.
    /// Other readers keep using `on_data_available`.
    ///
    /// The default only logs, once per listener type: a listener that does
    /// not implement it on such a reader gets no data callback at all.
    fn on_data_available_notification(&self) {
        warn_notification_not_implemented::<Self>();
    }

    /// Called when the reader matches or unmatches with a writer.
    ///
    /// # Arguments
    ///
    /// * `status` - Current subscription matched status
    fn on_subscription_matched(&self, status: SubscriptionMatchedStatus) {
        let _ = status;
    }

    /// Called when liveliness of a matched writer changes (DDS v1.4
    /// Sec.2.2.4.1): it matches (alive), its lease ends unrenewed (not
    /// alive), it is renewed again (alive), or it unmatches (no longer
    /// counted). Runs on an HDDS thread, never the participant's liveliness
    /// thread, with no lock of the reader held; the status's changes are
    /// reset before the call.
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

    /// Called when a remote DataWriter on the same topic announces a type
    /// that is structurally incompatible with the local reader's type.
    ///
    /// Corresponds to `on_inconsistent_topic` per DDS v1.4 sec. 2.2.4.4.
    ///
    /// # Arguments
    ///
    /// * `status` - Accumulated inconsistent-topic status
    fn on_inconsistent_topic(&self, status: InconsistentTopicStatus) {
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
    /// * `status` - Current offered deadline missed status
    fn on_offered_deadline_missed(&self, status: OfferedDeadlineMissedStatus) {
        let _ = status;
    }

    /// Called when QoS is incompatible with a matched reader.
    ///
    /// # Arguments
    ///
    /// * `policy_id` - QosPolicyId_t of the incompatible QoS policy (DDS v1.4
    ///   Sec.2.3.3; `crate::dds::qos::policy_id`)
    /// * `policy_name` - Name of the policy (e.g., "RELIABILITY")
    fn on_offered_incompatible_qos(&self, policy_id: u32, policy_name: &str) {
        let _ = (policy_id, policy_name);
    }

    /// Called when liveliness is lost (MANUAL_BY_* only): this writer did
    /// not assert (write, dispose, unregister or `assert_liveliness`)
    /// within its offered LIVELINESS lease (DDS v1.4 Sec.2.2.4.1).
    /// Default: no-op (user overrides if needed)
    fn on_liveliness_lost(&self, status: LivelinessLostStatus) {
        let _ = status; /* @audit-ok: intentional no-op default */
    }

    /// Called when a remote DataReader on the same topic announces a type
    /// that is structurally incompatible with the local writer's type.
    ///
    /// Corresponds to `on_inconsistent_topic` per DDS v1.4 sec. 2.2.4.4.
    ///
    /// # Arguments
    ///
    /// * `status` - Accumulated inconsistent-topic status
    fn on_inconsistent_topic(&self, status: InconsistentTopicStatus) {
        let _ = status;
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

    // @audit-ok: arbitrary type ID for test DDS impl
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

        fn encode(
            &self,
            buf: &mut [u8],
            _version: crate::dds::CdrVersion,
        ) -> crate::dds::Result<usize> {
            if buf.len() < 4 {
                return Err(crate::dds::Error::BufferTooSmall);
            }
            buf[..4].copy_from_slice(&self.value.to_le_bytes());
            Ok(4)
        }

        fn decode(buf: &[u8], _version: crate::dds::CdrVersion) -> crate::dds::Result<Self> {
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
        <NoOpListener as DataReaderListener<TestData>>::on_inconsistent_topic(
            &listener,
            InconsistentTopicStatus::default(),
        );
    }

    #[test]
    fn test_noop_writer_listener() {
        let listener = NoOpListener;
        let sample = TestData { value: 1 };

        // All these should do nothing but not panic
        listener.on_sample_written(&sample, 1);
        listener.on_publication_matched(PublicationMatchedStatus::default());
        listener.on_offered_deadline_missed(OfferedDeadlineMissedStatus::default());
        listener.on_offered_incompatible_qos(0, "RELIABILITY");
        listener.on_liveliness_lost(LivelinessLostStatus::default());
        <NoOpListener as DataWriterListener<TestData>>::on_inconsistent_topic(
            &listener,
            InconsistentTopicStatus::default(),
        );
    }

    #[test]
    fn liveliness_lost_status_default_is_zero() {
        let status = LivelinessLostStatus::default();
        assert_eq!(status.total_count, 0);
        assert_eq!(status.total_count_change, 0);
    }

    #[test]
    fn inconsistent_topic_status_default_is_zero() {
        let status = InconsistentTopicStatus::default();
        assert_eq!(status.total_count, 0);
        assert_eq!(status.total_count_change, 0);
    }

    #[test]
    fn on_inconsistent_topic_fires_on_writer_listener() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        struct CountingWriterListener {
            fire_count: Arc<AtomicU32>,
            last_total: Arc<AtomicU32>,
        }

        impl DataWriterListener<TestData> for CountingWriterListener {
            fn on_inconsistent_topic(&self, status: InconsistentTopicStatus) {
                self.fire_count.fetch_add(1, Ordering::SeqCst);
                self.last_total.store(status.total_count, Ordering::SeqCst);
            }
        }

        let fire_count = Arc::new(AtomicU32::new(0));
        let last_total = Arc::new(AtomicU32::new(0));
        let listener = CountingWriterListener {
            fire_count: Arc::clone(&fire_count),
            last_total: Arc::clone(&last_total),
        };

        listener.on_inconsistent_topic(InconsistentTopicStatus {
            total_count: 1,
            total_count_change: 1,
        });
        assert_eq!(fire_count.load(Ordering::SeqCst), 1);
        assert_eq!(last_total.load(Ordering::SeqCst), 1);

        listener.on_inconsistent_topic(InconsistentTopicStatus {
            total_count: 2,
            total_count_change: 1,
        });
        assert_eq!(fire_count.load(Ordering::SeqCst), 2);
        assert_eq!(last_total.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn on_inconsistent_topic_fires_on_reader_listener() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        struct CountingReaderListener {
            fire_count: Arc<AtomicU32>,
        }

        impl DataReaderListener<TestData> for CountingReaderListener {
            fn on_inconsistent_topic(&self, _status: InconsistentTopicStatus) {
                self.fire_count.fetch_add(1, Ordering::SeqCst);
            }
        }

        let fire_count = Arc::new(AtomicU32::new(0));
        let listener = CountingReaderListener {
            fire_count: Arc::clone(&fire_count),
        };

        listener.on_inconsistent_topic(InconsistentTopicStatus {
            total_count: 3,
            total_count_change: 3,
        });
        assert_eq!(fire_count.load(Ordering::SeqCst), 1);
    }
}
