// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS Publisher entity - creates and manages DataWriter instances
//!
//!
//! # Code Duplication Note (ANSSI Audit Exception)
//!
//! Publisher and Subscriber are ~95% identical (structural duplication).
//! This is **intentional** and follows DDS v1.4 specification design:
//!
//! ## Why NOT factored:
//! 1. **API Clarity**: Users expect symmetric Publisher/Subscriber types
//! 2. **DDS Spec Compliance**: DDS v1.4 defines them as separate entities
//! 3. **Documentation**: Each needs detailed, role-specific docs (50+ lines)
//! 4. **Type Safety**: Separate types prevent mixing Writers/Readers
//! 5. **Maintainability**: Clear separation > clever abstraction
//!
//! ## Audit Trail:
//! - Duplication detected: 49 lines (28% of file)
//! - Refactor attempted: 2025-01-27 (macro-based elimination)
//! - Decision: ROLLBACK - Documentation quality critical
//! - Justification: DDS API symmetry is a feature, not a bug
//!
//! This duplication is **approved** for ANSSI/IGI-1300 compliance.
//! jscpd: ignore (intentional API symmetry per DDS v1.4 spec)

use super::{DataWriter, QoS, Result, Topic};
use crate::engine::TopicRegistry;
use crate::transport::UdpTransport;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

/// Trait that hides the generic `T` parameter of `DataWriter<T>` so the
/// Publisher can hold a registry of writers across heterogeneous types.
///
/// Implementations live alongside `DataWriter<T>` and expose only the
/// methods the GSN runtime needs (RTPS v2.5 §8.7.5): the writer's
/// last-sample SN in the active set and the ECS DATA broadcast at
/// `end_coherent_changes`.
pub trait CoherentWriter: Send + Sync {
    /// Snapshot the writer-scoped sequence number of the last sample
    /// written into the active coherent set, then reset the per-set
    /// counter. Returns `None` if the writer wrote nothing inside the
    /// set; in that case the publisher skips ECS emission for this
    /// writer (no need to advertise a closed set the writer never
    /// contributed to).
    fn take_last_sn_in_active_set(&self) -> Option<u64>;

    /// Emit the ECS DATA submessage closing GSN `group_sn` (when GROUP
    /// scope) and the writer-scoped `coherent_sn` (the last sample SN
    /// returned by `take_last_sn_in_active_set`). Consumes the writer's
    /// next SN, sends to all matched readers, and inserts into the
    /// writer's history cache so it participates in reliable retransmit.
    fn emit_ecs_data(&self, coherent_sn: u64, group_sn: Option<u64>);
}

/// DDS Publisher - intermediate entity between Participant and DataWriter
///
/// A Publisher is created by a DomainParticipant and is responsible for creating
/// and managing DataWriter entities. Publishers can have their own QoS policies
/// that are inherited by their DataWriters.
///
/// # DDS v1.4 Specification
///
/// Per the DDS specification:
/// - A Publisher is used to create DataWriter objects
/// - Each DataWriter is associated with a single Topic
/// - Publishers support QoS policies: PARTITION, GROUP_DATA, ENTITY_FACTORY, PRESENTATION
/// - Publishers provide a logical grouping for related DataWriters
///
/// # Example
///
/// ```ignore
/// use hdds::api::{Participant, QoS};
///
/// let participant = Participant::builder("example").build()?;
///
/// // Create publisher with default QoS
/// let publisher = participant.create_publisher(QoS::default())?;
///
/// // Create writer through publisher (YourDataType must implement DDS trait)
/// let writer = publisher.create_writer::<YourDataType>("temperature", QoS::reliable())?;
/// ```
pub struct Publisher {
    /// Publisher QoS policies (PARTITION, GROUP_DATA, ENTITY_FACTORY, PRESENTATION)
    qos: QoS,

    /// UDP transport (if participant uses UdpMulticast mode)
    transport: Option<Arc<UdpTransport>>,

    /// Topic registry for message routing (if participant uses UdpMulticast mode)
    registry: Option<Arc<TopicRegistry>>,

    /// Reference to parent Participant for SEDP announcements
    participant: Option<Arc<crate::Participant>>,

    /// Whether we're currently in a coherent change set
    /// Used by begin_coherent_changes() / end_coherent_changes()
    in_coherent_set: AtomicBool,

    /// Next Group Sequence Number to assign to a coherent set
    /// (RTPS v2.5 §8.7.5). Monotonic across all coherent sets opened by
    /// this Publisher; bumped at `begin_coherent_changes`.
    gsn: AtomicU64,

    /// GSN of the coherent set currently being assembled (0 when
    /// `in_coherent_set` is false). DataWriter::write() reads this to
    /// decide whether to tag samples with `PID_GROUP_COHERENT_SET`.
    current_set_gsn: AtomicU64,

    /// Registry of writers attached to this Publisher. Each writer
    /// registers itself once at build time so `end_coherent_changes`
    /// can iterate and emit per-writer ECS DATA submessages
    /// (RTPS v2.5 §8.7.5).
    ///
    /// Stored as `Weak<dyn CoherentWriter>` so writer drop doesn't
    /// require the Publisher to be poked: stale weaks are pruned at
    /// `end_coherent_changes` time.
    writers: Mutex<Vec<Weak<dyn CoherentWriter>>>,

    /// Per-set serialization barrier. Held during
    /// `begin_coherent_changes` (transition open) and
    /// `end_coherent_changes` (transition close + ECS emission).
    /// `DataWriter::write` acquires it briefly in `coherent_context`
    /// so a concurrent `end_coherent_changes` cannot swap the GSN out
    /// between the writer reading `current_set_gsn` and storing
    /// `last_sn_in_active_set`. Without this lock the writer could
    /// stamp a sample with GSN=N while the publisher already closed N
    /// and opened N+1, leaving the sample orphaned in the receiver's
    /// per-GSN buffer (race observed as CS_11 ~40% flake on
    /// self-interop before the lock was added).
    pub(crate) set_lock: Mutex<()>,
}

impl Publisher {
    /// Create a new Publisher with specified QoS
    ///
    /// This is typically called by `Participant::create_publisher()` rather than directly.
    ///
    /// # Arguments
    ///
    /// * `qos` - Quality of Service policies for this Publisher
    /// * `transport` - Optional UDP transport (from parent Participant)
    /// * `registry` - Optional topic registry (from parent Participant)
    /// * `participant` - Optional reference to parent Participant for SEDP
    pub(crate) fn new(
        qos: QoS,
        transport: Option<Arc<UdpTransport>>,
        registry: Option<Arc<TopicRegistry>>,
        participant: Option<Arc<crate::Participant>>,
    ) -> Self {
        Self {
            qos,
            transport,
            registry,
            participant,
            in_coherent_set: AtomicBool::new(false),
            gsn: AtomicU64::new(0),
            current_set_gsn: AtomicU64::new(0),
            writers: Mutex::new(Vec::new()),
            set_lock: Mutex::new(()),
        }
    }

    /// Register a writer with the publisher for ECS DATA broadcast at
    /// `end_coherent_changes` time (RTPS v2.5 §8.7.5).
    ///
    /// Called once at `DataWriter` build time by the builder when the
    /// writer is created via the `publisher.create_writer(...)` /
    /// `topic.writer().publisher(...)` path. Idempotent re-registration is
    /// safe but pointless; the registry holds weak references so writer
    /// drop automatically prunes the entry on the next sweep.
    pub fn register_writer(&self, writer: Weak<dyn CoherentWriter>) {
        let mut guard = self
            .writers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.push(writer);
    }

    /// Read the GSN of the coherent set currently being assembled.
    /// Returns 0 when `is_coherent()` is false.
    #[inline]
    pub fn current_set_gsn(&self) -> u64 {
        self.current_set_gsn.load(Ordering::Acquire)
    }

    /// Convenience: returns `Some(gsn)` if the publisher is inside a
    /// coherent set with GROUP access_scope, else `None`. The writer
    /// uses this to tag samples with `PID_GROUP_COHERENT_SET`.
    pub fn group_coherent_gsn(&self) -> Option<u64> {
        if !self.is_coherent() {
            return None;
        }
        if !matches!(
            self.qos.presentation.access_scope,
            crate::dds::qos::PresentationAccessScope::Group
        ) {
            return None;
        }
        let gsn = self.current_set_gsn();
        if gsn == 0 {
            None
        } else {
            Some(gsn)
        }
    }

    /// Get the QoS policies for this Publisher
    pub fn qos(&self) -> &QoS {
        &self.qos
    }

    /// Get a reference to the parent Participant (if available).
    pub fn participant(&self) -> Option<&Arc<crate::Participant>> {
        self.participant.as_ref()
    }

    /// Create a DataWriter for the specified topic
    ///
    /// The DataWriter will inherit the Publisher's PARTITION QoS policy (if not explicitly overridden).
    /// The DataWriter's QoS can be customized via the `qos` parameter.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The data type for this DataWriter (must implement `DDS` trait)
    ///
    /// # Arguments
    ///
    /// * `topic_name` - Name of the topic to publish on
    /// * `qos` - Quality of Service policies for this DataWriter
    ///
    /// # Returns
    ///
    /// Returns a configured `DataWriter<T>` ready for publishing data.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hdds::api::{Participant, QoS};
    ///
    /// let participant = Participant::builder("example").build()?;
    /// let publisher = participant.create_publisher(
    ///     QoS::default().partition_single("production")
    /// )?;
    ///
    /// // Writer inherits "production" partition from publisher (YourDataType must implement DDS)
    /// let writer = publisher.create_writer::<YourDataType>("alerts", QoS::reliable())?;
    /// ```
    #[deprecated(
        since = "1.0.10",
        note = "Use participant.topic::<T>(name).writer().build() instead"
    )]
    pub fn create_writer<T: crate::dds::DDS>(
        &self,
        topic_name: &str,
        mut qos: QoS,
    ) -> Result<DataWriter<T>> {
        // Inherit PARTITION from publisher if not explicitly set in writer QoS
        if qos.partition.is_default() && !self.qos.partition.is_default() {
            qos.partition = self.qos.partition.clone();
        }

        // Create topic with participant reference (required for SEDP announcements)
        let participant = self.participant.as_ref().ok_or_else(|| {
            crate::dds::Error::InvalidState(
                "Publisher created without Participant reference".to_string(),
            )
        })?;
        let topic = Topic::<T>::new(topic_name.to_string(), Arc::clone(participant));
        let mut builder = topic.writer().qos(qos);

        // Attach registry for NACK RX (Reliable QoS retransmission)
        if let Some(ref registry) = self.registry {
            builder = builder.with_registry(registry.clone());
        }

        // Attach transport for UDP TX
        if let Some(ref transport) = self.transport {
            builder = builder.with_transport(transport.clone());
        }

        builder.build()
    }

    /// Set new QoS policies for this Publisher
    ///
    /// **Note:** Changing QoS at runtime may not be supported by all implementations.
    /// Some QoS policies are immutable after entity creation per DDS specification.
    pub fn set_qos(&mut self, qos: QoS) {
        self.qos = qos;
    }

    /// Begin a coherent change set.
    ///
    /// All writes performed between `begin_coherent_changes()` and `end_coherent_changes()`
    /// are grouped as an atomic unit. Readers will either see all changes or none.
    ///
    /// # DDS v1.4 Specification
    ///
    /// Coherent changes require `Presentation` QoS with `coherent_access = true`.
    /// The access scope determines the granularity:
    /// - `Instance`: Coherent per instance (same key)
    /// - `Topic`: Coherent per topic
    /// - `Group`: Coherent across all topics in this Publisher
    ///
    /// # Errors
    ///
    /// Returns an error if already in a coherent set (nested calls not supported).
    ///
    /// # Example
    ///
    /// ```ignore
    /// publisher.begin_coherent_changes()?;
    /// writer_pos.write(Position { x: 10.0, y: 20.0 })?;
    /// writer_vel.write(Velocity { vx: 1.0, vy: 2.0 })?;
    /// publisher.end_coherent_changes()?;
    /// ```
    pub fn begin_coherent_changes(&self) -> Result<()> {
        // Hold the set lock for the full begin transition so concurrent
        // writers cannot observe a half-open set
        // (in_coherent_set=true while current_set_gsn still 0, or vice
        // versa). The lock is released before this function returns; the
        // active set itself does not hold a lock for its duration.
        let _guard = self
            .set_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Check if already in a coherent set. Nested begin would orphan
        // samples from the still-open set in
        // receivers' per-GSN buffers because no ECS would ever close
        // the old GSN).
        if self.in_coherent_set.swap(true, Ordering::SeqCst) {
            return Err(crate::dds::Error::InvalidState(
                "Already in a coherent change set (nested calls not supported)".to_string(),
            ));
        }
        // Allocate a fresh GSN for this set. Wrap on overflow per RTPS
        // SequenceNumber_t semantics; u64 effectively never wraps in
        // practice but the explicit AcqRel ordering keeps the read in
        // write() in sync with this store.
        let gsn = self.gsn.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        self.current_set_gsn.store(gsn, Ordering::Release);
        log::debug!("[Publisher] Begin coherent changes gsn={}", gsn);
        Ok(())
    }

    /// End a coherent change set and commit all pending changes.
    ///
    /// After this call, readers will be able to see all changes made since
    /// `begin_coherent_changes()` as an atomic unit.
    ///
    /// # Errors
    ///
    /// Returns an error if not currently in a coherent set.
    ///
    /// # Example
    ///
    /// ```ignore
    /// publisher.begin_coherent_changes()?;
    /// writer.write(data)?;
    /// publisher.end_coherent_changes()?; // Commit
    /// ```
    pub fn end_coherent_changes(&self) -> Result<()> {
        // Take the set lock across the entire close transition so any
        // `DataWriter::write` currently inside `coherent_context` either
        // (a) has already stored `last_sn_in_active_set` before we
        //     snapshot the registry, in which case we drain it and emit
        //     ECS, or
        // (b) is still waiting for the lock when we exit, in which case
        //     it will read `in_coherent_set = false` / `current_set_gsn
        //     = 0` and return (None, None) — i.e. it correctly stamps
        //     the sample as belonging to NO coherent set.
        // (race observed as CS_11 ~40% flake before the lock was added).
        let _guard = self
            .set_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // M4 fix: a no-op `end_coherent_changes` (no matching `begin`)
        // would otherwise emit ECS with group_sn = 0, which subscribers
        // could misinterpret as "close set 0" and trigger spurious
        // flushes. Bail early.
        if !self.in_coherent_set.swap(false, Ordering::SeqCst) {
            return Err(crate::dds::Error::InvalidState(
                "Not in a coherent change set".to_string(),
            ));
        }

        let close_gsn = self.current_set_gsn.swap(0, Ordering::AcqRel);
        let is_group_scope = matches!(
            self.qos.presentation.access_scope,
            crate::dds::qos::PresentationAccessScope::Group
        );
        let group_sn_opt = if is_group_scope {
            Some(close_gsn)
        } else {
            None
        };

        // Snapshot the registry under lock, then iterate without the
        // writers-list lock held so writer `emit_ecs_data` (which sends
        // on UDP) is free to run concurrently with re-registrations.
        // Prune stale weaks (writers dropped since registration) in the
        // same pass.
        let writers: Vec<Arc<dyn CoherentWriter>> = {
            let mut guard = self
                .writers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.retain(|w| w.strong_count() > 0);
            guard.iter().filter_map(|w| w.upgrade()).collect()
        };

        let mut emitted = 0usize;
        for writer in &writers {
            if let Some(last_sn) = writer.take_last_sn_in_active_set() {
                writer.emit_ecs_data(last_sn, group_sn_opt);
                emitted += 1;
            }
        }

        log::debug!(
            "[Publisher] End coherent changes gsn={} group_scope={} writers={} ecs_emitted={}",
            close_gsn,
            is_group_scope,
            writers.len(),
            emitted
        );
        Ok(())
    }

    /// Check if currently in a coherent change set.
    #[inline]
    pub fn is_coherent(&self) -> bool {
        self.in_coherent_set.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_publisher_default() {
        let publisher = Publisher::new(QoS::default(), None, None, None);
        assert!(publisher.transport.is_none());
        assert!(publisher.registry.is_none());
    }

    #[test]
    fn test_publisher_qos() {
        let qos = QoS::default().partition_single("test-partition");
        let publisher = Publisher::new(qos.clone(), None, None, None);
        assert_eq!(publisher.qos().partition, qos.partition);
    }

    #[test]
    fn test_partition_inheritance() {
        // Publisher with partition QoS
        let pub_qos = QoS::default().partition_single("production");
        let publisher = Publisher::new(pub_qos, None, None, None);

        // Writer QoS without partition (should inherit from publisher)
        let writer_qos = QoS::reliable();
        assert!(writer_qos.partition.is_default());

        // This would be tested in integration tests with actual writer creation
        // For now, we verify the publisher has the partition set
        assert!(!publisher.qos().partition.is_default());
    }

    #[test]
    fn test_coherent_changes_basic() {
        let publisher = Publisher::new(QoS::default(), None, None, None);

        // Not in coherent set initially
        assert!(!publisher.is_coherent());

        // Begin coherent changes
        publisher.begin_coherent_changes().unwrap();
        assert!(publisher.is_coherent());

        // End coherent changes
        publisher.end_coherent_changes().unwrap();
        assert!(!publisher.is_coherent());
    }

    #[test]
    fn test_coherent_changes_nested_error() {
        let publisher = Publisher::new(QoS::default(), None, None, None);

        // Begin coherent changes
        publisher.begin_coherent_changes().unwrap();

        // Nested begin should fail
        let result = publisher.begin_coherent_changes();
        assert!(result.is_err());

        // Still in coherent set
        assert!(publisher.is_coherent());

        // End should work
        publisher.end_coherent_changes().unwrap();
    }

    #[test]
    fn test_coherent_changes_end_without_begin() {
        let publisher = Publisher::new(QoS::default(), None, None, None);

        // End without begin should fail
        let result = publisher.end_coherent_changes();
        assert!(result.is_err());
    }
}
