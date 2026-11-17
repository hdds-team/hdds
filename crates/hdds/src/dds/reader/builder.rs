// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Builder pattern for DataReader configuration.
//!
//!
//! Provides fluent API for configuring QoS, transport, and runtime options
//! before constructing a DataReader instance.

use super::cache::InstanceTable;
use super::coherent_barrier::CoherentPresentationBarrier;
use super::conditions::FieldExtractor;
use super::heartbeat::ReaderHeartbeatHandler;
use super::reorder::ReorderGate;
use super::runtime::{DataReader, ReaderBindings};
use super::subscriber::{DisposeQueue, ReaderSubscriber};
use crate::config::READER_HISTORY_RING_SIZE;
use crate::core::discovery::GUID;
use crate::core::reader::ReaderAckCredit;
use crate::core::rt;
use crate::dds::filter::FilterEvaluator;
use crate::dds::listener::{DataReaderListener, ReaderListenerSlot};
use crate::dds::match_notification::{LivelinessPeer, PeerCallback, PeerChange};
use crate::dds::qos::{Durability, History, Reliability};
use crate::dds::{
    DomainState, Error, GuardCondition, MatchKey, QoS, Result, StatusCondition, StatusMask, TypeId,
    DDS,
};
use crate::engine::TopicRegistry;
use crate::transport::shm::ShmPolicy;
use crate::transport::UdpTransport;
use crate::xtypes::CompleteTypeObject;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

pub struct ReaderBuilder<T: DDS> {
    pub(super) topic: String,
    pub(super) qos: QoS,
    pub(super) registry: Option<Arc<TopicRegistry>>,
    pub(super) transport: Option<Arc<UdpTransport>>,
    pub(super) participant_guard: Option<Arc<GuardCondition>>,
    pub(super) participant: Option<Arc<crate::Participant>>,
    pub(super) domain_state: Option<Arc<DomainState>>,
    pub(super) type_name_override: Option<String>,
    pub(super) type_object_override: Option<CompleteTypeObject>,
    /// The reader has no type of its own and adopts the name its topic's
    /// writers announce (`adopting_type_name`).
    pub(super) adopt_type_name: bool,
    /// `type_name_override` is announced alone: no TypeObject registered
    /// under that name is attached (set when the name was adopted).
    pub(super) type_name_only: bool,
    /// Per-ENDPOINT shared-memory policy. `None` inherits the participant's,
    /// which is what every existing caller gets; `Some` is this reader's own
    /// override. An Option because `ShmPolicy::default()` is `Disable`, so a
    /// plain field cannot tell "never asked" from "asked for Disable".
    ///
    /// Not `#[cfg(target_os = "linux")]`: shared memory is Linux-only, but
    /// `ShmPolicy` and `ShmPolicy::resolve` exist on every platform (a
    /// no-op stub elsewhere), and `resolve()` below is called
    /// unconditionally, so gating this field alone would fail every
    /// non-Linux build.
    pub(super) shm_policy: Option<ShmPolicy>,
    /// Content filter for ContentFilteredTopic
    pub(super) content_filter: Option<FilterEvaluator>,
    /// How the content filter reads a sample's fields; `None` means
    /// `DDS::get_fields` (see [`with_field_extractor`](Self::with_field_extractor)).
    pub(super) field_extractor: Option<FieldExtractor<T>>,
    /// Listener for data callbacks
    pub(super) listener: Option<Arc<dyn DataReaderListener<T>>>,
    /// Coherent presentation barrier of the Subscriber entity this reader
    /// is attached to (see [`subscriber`](Self::subscriber)). `None` when
    /// the reader is not attached to a Subscriber.
    pub(super) subscriber_barrier: Option<Arc<CoherentPresentationBarrier>>,
    /// Test seam: build the dedicated network ring with no transport
    /// behind it, so a unit test can replay the RX producer on a reader
    /// that binds no socket (a fixed UDP port inside a unit test is a
    /// port-collision flake, not a topology).
    #[cfg(test)]
    pub(super) network_ring_for_test: bool,
    #[cfg(test)]
    pub(super) ack_credit_for_test: Option<ReaderAckCredit>,
    pub(super) _phantom: core::marker::PhantomData<T>,
}

impl<T: DDS> ReaderBuilder<T> {
    pub(crate) fn new(topic: String) -> Self {
        Self {
            topic,
            qos: QoS::best_effort(),
            registry: None,
            transport: None,
            participant_guard: None,
            participant: None,
            domain_state: None,
            type_name_override: None,
            type_object_override: None,
            adopt_type_name: false,
            type_name_only: false,
            shm_policy: None,
            content_filter: None,
            field_extractor: None,
            listener: None,
            subscriber_barrier: None,
            #[cfg(test)]
            network_ring_for_test: false,
            #[cfg(test)]
            ack_credit_for_test: None,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Give the reader a dedicated network ring with no transport
    /// behind it (see the field docs).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn network_ring_for_test(mut self) -> Self {
        self.network_ring_for_test = true;
        self
    }

    /// Supply real reliable receive credit without binding a transport.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_ack_credit_for_test(mut self, credit: ReaderAckCredit) -> Self {
        self.ack_credit_for_test = Some(credit);
        self
    }

    /// Attach this reader to a [`Subscriber`](crate::dds::Subscriber)
    /// entity's presentation group.
    ///
    /// When the reader's Presentation QoS enables `coherent_access`
    /// (DDS v1.4 sec. 2.2.3.6), the reader joins the Subscriber's cross-reader
    /// coherent presentation barrier: its completed coherent sets are
    /// released to the application aligned with the sets of the
    /// Subscriber's other coherent readers fed by the same remote
    /// publisher, one complete cross-topic group per `take_all` read cycle
    /// (see the `coherent_barrier` module docs for the exact release
    /// rules). For a non-coherent reader this attachment is inert.
    ///
    /// Readers built without this call keep the direct commit-to-ring
    /// delivery unchanged.
    #[must_use]
    pub fn subscriber(mut self, subscriber: &crate::dds::Subscriber) -> Self {
        self.subscriber_barrier = Some(Arc::clone(subscriber.coherent_barrier()));
        self
    }

    pub(crate) fn with_participant(mut self, participant: Arc<crate::Participant>) -> Self {
        self.participant = Some(participant);
        self
    }

    pub fn qos(mut self, q: QoS) -> Self {
        self.qos = q;
        self
    }

    /// Override the participant's shared-memory policy FOR THIS READER.
    ///
    /// - `Prefer`: use shared memory when the pairing qualifies (same realm,
    ///   both sides BEST_EFFORT); UDP otherwise. On a platform with no SHM
    ///   data path this always resolves to UDP.
    /// - `Require`: refuse to fall back to UDP behind your back. On a
    ///   platform with no SHM data path this is refused at
    ///   `ParticipantBuilder::build()`, never silently downgraded.
    /// - `Disable`: always UDP.
    ///
    /// Left unset, the reader follows its participant. A reader that asks for
    /// `Disable` never gets shared memory.
    pub fn shm_policy(mut self, policy: ShmPolicy) -> Self {
        self.shm_policy = Some(policy);
        self
    }

    pub fn with_registry(mut self, registry: Arc<TopicRegistry>) -> Self {
        self.registry = Some(registry);
        self
    }

    pub fn with_transport(mut self, transport: Arc<UdpTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    pub fn with_participant_guard(mut self, guard: Arc<GuardCondition>) -> Self {
        log::debug!(
            "[READER-BUILDER] attaching participant guard for topic='{}'",
            self.topic
        );
        self.participant_guard = Some(guard);
        self
    }

    pub fn with_domain_state(mut self, domain_state: Arc<DomainState>) -> Self {
        self.domain_state = Some(domain_state);
        self
    }

    pub(crate) fn with_type_name_override(mut self, type_name: impl Into<String>) -> Self {
        self.type_name_override = Some(type_name.into());
        self
    }

    /// Mark this reader as having no type of its own (a byte-payload
    /// reader): with no type name given, it announces the type registered
    /// for its topic, else the name its topic's writers already announce
    /// (XTypes 1.3 Sec.7.6.3.4.2 Step 2), else the placeholder `RawBytes`.
    /// An endpoint created for a type must not call this: it announces its
    /// own type's name. Decided once, at `build()`. Blocks `build()` for up
    /// to `HDDS_TYPE_ADOPT_WAIT_MS` when set and nothing is announced yet.
    pub fn adopting_type_name(mut self) -> Self {
        self.adopt_type_name = true;
        self
    }

    pub(crate) fn with_type_object_override(mut self, type_object: CompleteTypeObject) -> Self {
        self.type_object_override = Some(type_object);
        self
    }

    /// Set content filter for ContentFilteredTopic.
    ///
    /// When set, the reader will only receive samples that match the filter.
    /// This is typically set automatically when creating a reader from a
    /// ContentFilteredTopic.
    pub fn with_content_filter(mut self, filter: FilterEvaluator) -> Self {
        self.content_filter = Some(filter);
        self
    }

    /// Set how the content filter reads a sample's fields, in place of
    /// `DDS::get_fields`.
    ///
    /// For sample types whose schema lives outside the type (an opaque
    /// byte payload decoded through a dynamic type descriptor, as the C
    /// binding does). The extractor runs on the writer's thread for
    /// intra-process delivery and on the router thread for the network
    /// path, once per filtered reader per sample; it must not call back
    /// into the reader. A sample it returns `None` for is rejected before
    /// the filter runs (dropped, counted, logged at debug), whatever the
    /// expression. Without a content filter it is unused.
    pub fn with_field_extractor(mut self, extractor: FieldExtractor<T>) -> Self {
        self.field_extractor = Some(extractor);
        self
    }

    /// Announce `type_name` for this reader in discovery instead of the
    /// type's own name, so it matches a remote writer announcing that
    /// name (the same override `Participant::create_reader_with_type`
    /// applies).
    pub fn with_type_name(self, type_name: impl Into<String>) -> Self {
        self.with_type_name_override(type_name)
    }

    /// Set a listener for data callbacks.
    ///
    /// The listener will be called when data arrives, when subscriptions
    /// are matched, and for other reader events.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hdds::{Participant, QoS, DataReaderListener, ClosureListener};
    /// use std::sync::Arc;
    ///
    /// // Simple closure-based listener
    /// let listener = ClosureListener::new(|sample: &Temperature| {
    ///     println!("Received: {:?}", sample);
    /// });
    ///
    /// let reader = participant
    ///     .create_reader::<Temperature>("temp", QoS::default())
    ///     .with_listener(Arc::new(listener))
    ///     .build()?;
    /// ```
    pub fn with_listener(mut self, listener: Arc<dyn DataReaderListener<T>>) -> Self {
        self.listener = Some(listener);
        self
    }

    pub fn build(mut self) -> Result<DataReader<T>> {
        // DATA_REPRESENTATION a reader of a type that cannot decode XCDR
        // requests, resolved before anything reads the QoS
        // (DDS-XTypes v1.3 Sec.7.6.3.1.1). `Err` when the reader explicitly
        // requested XCDR1 and its type cannot decode it: refused here so a
        // remote writer that reads the SEDP list alone never disagrees with
        // this reader about whether the pair is compatible.
        crate::dds::cdr_negotiation::resolve_reader_data_representation(
            &mut self.qos,
            crate::dds::cdr_negotiation::Xcdr1Encoding::of::<T>(),
        )
        .map_err(|_| {
            Error::InvalidQos(format!(
                "DATA_REPRESENTATION {:?}: a reader may request XCDR (0) only when its \
                 type's encode/decode actually produces the XCDR1 layout \
                 (DDS::encodes_xcdr1_natively); DDS-XTypes v1.3 Sec.7.6.3.1.1 requires a \
                 reader to request XCDR only in addition to XCDR2, when it can deserialize \
                 version 1 encodings",
                self.qos.data_representation
            ))
        })?;
        if let Some(filter) = &self.content_filter {
            filter.validate_parameters().map_err(|error| {
                Error::InvalidState(format!("Invalid content filter parameters: {error}"))
            })?;
        }
        // Extract configs from participant if not explicitly provided
        // (mirrors WriterBuilder behavior for API consistency)
        if let Some(ref participant) = self.participant {
            if self.transport.is_none() {
                if let Some(ref transport) = participant.transport {
                    self.transport = Some(transport.clone());
                }
            }
            if self.registry.is_none() {
                if let Some(ref registry) = participant.registry {
                    self.registry = Some(registry.clone());
                }
            }
            if self.participant_guard.is_none() {
                self.participant_guard = Some(participant.graph_guard());
            }
            if self.domain_state.is_none() {
                self.domain_state = Some(participant.domain_state.clone());
            }
            // TypeLookup is participant-scoped, not writer-scoped: a
            // read-only consumer must be able to serve its type too. See
            // `Participant::register_served_type`.
            #[cfg(feature = "xtypes-structural-assignability")]
            participant.register_served_type::<T>();
            // The name announced in SEDP and the one the intra-process
            // match key is built from are settled here, once.
            let settled = participant.settle_type(
                &self.topic,
                crate::dds::DiscoveredEndpointKind::Reader,
                self.type_name_override.take(),
                self.type_object_override.take(),
                self.adopt_type_name,
            );
            self.type_name_override = settled.name;
            self.type_object_override = settled.object;
            self.type_name_only = settled.name_only;
        }

        // A zero period asks for an unbounded number of periodic events.
        // Refuse it explicitly instead of pinning the scheduler in place.
        if self.qos.deadline.period.is_zero() {
            return Err(Error::InvalidQos(
                "deadline period must be positive".to_string(),
            ));
        }

        // DataTagQosPolicy (DDS-Security v1.1 Sec.7.2.5): HDDS does not
        // announce an endpoint's data tags (PID_DATA_TAGS) in this release,
        // and a peer would judge the endpoint as untagged. Refused rather
        // than ignored.
        if !self.qos.data_tags.is_empty() {
            return Err(Error::InvalidQos(
                "data_tags on a local endpoint: this release does not announce data tags \
                 (PID_DATA_TAGS), so no peer could apply a permissions <data_tags> condition \
                 to them"
                    .to_string(),
            ));
        }

        // DDS Security: Check access control permissions for reader creation
        #[cfg(feature = "security")]
        if let Some(ref participant) = self.participant {
            // Every partition the endpoint names, and its data tags
            // (DDS-Security v1.1 Sec.9.4.1.3.2.3.1.4, 9.4.1.3.2.3.1.5).
            participant.check_create_reader(
                &self.topic,
                &self.qos,
                crate::dds::participant::EndpointKeyHooks {
                    has_key: T::has_key(),
                    keys_round_trip: T::keys_round_trip(),
                },
            )?;
        }

        #[cfg(test)]
        let network_ring_for_test = self.network_ring_for_test;
        let ReaderBuilder {
            topic,
            qos,
            registry,
            transport,
            participant_guard,
            participant,
            domain_state,
            type_name_override,
            type_object_override,
            type_name_only,
            content_filter,
            field_extractor,
            listener,
            subscriber_barrier,
            ..
        } = self;

        // DDS 1.4 2.2.3.18 / 2.2.3.19: the same consistency rules, and the
        // same function, as DataWriter creation.
        crate::dds::qos::check_history_and_limits("DataReader", qos.history, &qos.resource_limits)?;

        // Ring must be larger than history depth to buffer incoming samples
        // before the cache keeps the newest of each instance at read time.
        // Use READER_HISTORY_RING_SIZE
        // as minimum to handle writer bursts without dropping newest samples.
        // KEEP_ALL under LENGTH_UNLIMITED `max_samples` (the DDS default)
        // still needs a finite ring: keep the size a KEEP_ALL reader had
        // when that default was 100 000. What a full ring does to an
        // incoming sample is a separate question from the default.
        const UNLIMITED_KEEP_ALL_RING: usize = 100_000;
        let ring_capacity = match qos.history {
            // One more than `depth`: a ring of `n` holds `n - 1` entries, and
            // a full KEEP_LAST ring must still hold `depth` of one instance.
            History::KeepLast(depth) => {
                std::cmp::max((depth as usize).saturating_add(1), READER_HISTORY_RING_SIZE)
            }
            // One more than `max_samples` too: the history room grants at
            // most the ring's usable capacity, one slot less than the ring.
            History::KeepAll => {
                let max_samples =
                    if qos.resource_limits.max_samples == crate::reliability::LENGTH_UNLIMITED {
                        UNLIMITED_KEEP_ALL_RING
                    } else {
                        qos.resource_limits.max_samples.saturating_add(1)
                    };
                std::cmp::max(max_samples, READER_HISTORY_RING_SIZE)
            }
        };
        let ring = Arc::new(rt::IndexRing::with_capacity(ring_capacity));
        #[cfg(test)]
        let has_network_source = transport.is_some() || network_ring_for_test;
        #[cfg(not(test))]
        let has_network_source = transport.is_some();
        let network_ring =
            has_network_source.then(|| Arc::new(rt::IndexRing::with_capacity(ring_capacity)));
        let status_condition = Arc::new(StatusCondition::new());
        status_condition.set_enabled_statuses(StatusMask::DATA_AVAILABLE);

        // Shared with the `DataReader` below exactly like `status_condition`:
        // the subscriber writes SAMPLE_REJECTED state here in
        // `report_sample_rejected`, and `DataReader::get_sample_rejected_status`
        // reads and resets the same `Arc`.
        let sample_rejected = Arc::new(Mutex::new(
            crate::dds::listener::SampleRejectedStatus::default(),
        ));
        // Likewise SAMPLE_LOST: what the subscriber discards of a coherent
        // set that can never be whole (`report_sample_lost`).
        let sample_lost = Arc::new(Mutex::new(crate::dds::listener::SampleLostStatus::default()));
        // The reader's `ReaderStats::drops`: every door of this reader that
        // discards a sample after arrival adds to it (the local doors, the
        // content filter here, the network subscriber once it is built).
        let dropped = Arc::new(AtomicU64::new(0));
        // Likewise SUBSCRIPTION_MATCHED and REQUESTED_INCOMPATIBLE_QOS: the
        // match callbacks built below (when this reader has a participant)
        // write here on every event from either source that can report one
        // for this reader. Created unconditionally so a reader with no
        // participant still has a (permanently default) status to return.
        let subscription_matched = Arc::new(Mutex::new(
            crate::dds::listener::SubscriptionMatchedStatus::default(),
        ));
        let requested_incompatible_qos = Arc::new(Mutex::new(
            crate::dds::listener::RequestedIncompatibleQosStatus::default(),
        ));

        // Intra-process content filter. The network path evaluates the
        // reader's filter in `ReaderSubscriber::process_admitted`, before
        // its ring insertion; the intra-process path never goes through
        // that subscriber, so without this closure the writer's merger
        // would fan EVERY sample into a ContentFilteredTopic reader's
        // ring. The merger asks this predicate on the writer's thread
        // before the push: a rejected sample takes no ring slot and raises
        // no DATA_AVAILABLE. A decode or evaluation failure rejects, the
        // same fail-safe the network path applies. The cost moves to the
        // producer: one decode + evaluation per filtered reader per write.
        // `T::get_fields` is application code; the merger catches a panic
        // in it and rejects the sample, so it cannot unwind through the
        // writer's write().
        let sample_filter: Option<rt::SampleFilter> = content_filter.as_ref().map(|filter| {
            let filter = filter.clone();
            let topic = topic.clone();
            let extract = field_extractor.clone();
            let dropped = Arc::clone(&dropped);
            let predicate = move |bytes: &[u8], version: crate::dds::CdrVersion| -> bool {
                let sample = match T::decode(&T::capture_wire_data(bytes, None), version) {
                    Ok(sample) => sample,
                    Err(e) => {
                        log::debug!(
                            "[ReaderBuilder] content filter: decode failed topic='{topic}': {e:?}"
                        );
                        return false;
                    }
                };
                let fields = match &extract {
                    Some(extract) => match extract(&sample) {
                        Some(fields) => fields,
                        None => {
                            // The extractor could not read the sample (its
                            // descriptor does not decode the payload): a
                            // filter rejects what it cannot look into.
                            log::debug!(
                                "[ReaderBuilder] content filter: sample has no field map, \
                                 rejected topic='{topic}'"
                            );
                            dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if let Some(metrics) = crate::telemetry::get_metrics_opt() {
                                metrics.increment_dropped(1);
                            }
                            return false;
                        }
                    },
                    None => T::get_fields(&sample),
                };
                match filter.matches(&fields) {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        log::debug!(
                            "[ReaderBuilder] content filter: evaluation error topic='{topic}': {e:?}"
                        );
                        false
                    }
                }
            };
            Arc::new(predicate) as rt::SampleFilter
        });

        // Per-writer ring binding table (A2): every intra-process
        // binding gets its own SPSC ring (the first one reuses the
        // primary ring above; fresh rings share its capacity policy).
        // Shared with the domain auto-bind callback below and with
        // DataReader::bind_to_writer; DataReader::drop tombstones each
        // binding in its still-alive merger. The table builds the
        // DATA_AVAILABLE notify closures itself: each merger raises the
        // wake word of the ring it feeds, and hands every registration
        // the content filter above.
        // A reader refuses what it has no room for, unacknowledged, rather
        // than acknowledge it and drop it (DDS v1.4 Sec.2.2.3.19). The room
        // covers what arrives from the network: its producer reserves a
        // place before the credit. A KEEP_ALL reader's place goes with the
        // sample from the network ring to the cache, where `take` gives it
        // back, and the room holds at most RESOURCE_LIMITS `max_samples`
        // places. A KEEP_LAST reader's cache keeps the newest samples per
        // instance rather than refuse them: its places bound the network
        // ring only, and are given back as the samples leave it; a full ring
        // drops the samples newer ones replace before it refuses any.
        // RESOURCE_LIMITS `max_instances` and `max_samples_per_instance`
        // bound the same history, per instance (`HistoryRoom::reserve_for`).
        //
        // The same room bounds what the reader's local writers deliver
        // (`local_door`): a RELIABLE KEEP_ALL reader's local samples take
        // places in it, and every local sample counts for its instance when
        // the room bounds instances. A reader with no network ring sizes it
        // by its primary ring, of the same capacity.
        let reliable = matches!(qos.reliability, Reliability::Reliable);
        // A KEEP_ALL history that does not discard its old values bounds its
        // places by `max_samples` (a BEST_EFFORT one only under coherent
        // access, see `HistoryRoom::discards_old_values`).
        let local_places = matches!(qos.history, History::KeepAll)
            && !super::admission::HistoryRoom::discards_old_values(&qos);
        // Where the local writers of a RELIABLE reader wait for room.
        let room_wait = Arc::new(super::admission::RoomWait::new());
        let history_room = Some(super::admission::HistoryRoom::bounded(
            network_ring.as_ref().unwrap_or(&ring),
            qos.history,
            super::admission::HistoryRoom::discards_old_values(&qos),
            &qos.resource_limits,
            Some(Arc::clone(&room_wait)),
        ));
        // The reader's writer registrations, one table for its network
        // subscriber and, under EXCLUSIVE ownership, for the ownership gates
        // of its intra-process bindings: a local and a remote writer contend
        // for an instance as two remote writers do (DDS v1.4 Sec.2.2.3.9.2).
        // A finite DEADLINE lets a contender take an instance from an owner
        // that let it pass (Sec.2.2.3.9.2 (d)).
        let exclusive = qos.ownership.kind == crate::qos::ownership::OwnershipKind::Exclusive;
        let registrations = Arc::new(super::registrations::ReaderRegistrations::new(
            exclusive,
            (!qos.deadline.is_infinite()).then_some(qos.deadline.period),
            registry.clone(),
        ));
        let listener = Arc::new(ReaderListenerSlot::<T>::new(listener));
        // This reader's per-instance DEADLINE watches (DDS v1.4
        // Sec.2.2.3.7), built before `dispose_events` so its dispose
        // queue can unwatch an instance that leaves ALIVE
        // (`crate::dds::liveliness::deadline` module doc). `None` with
        // an infinite deadline (the default): zero cost, nothing created
        // at all.
        //
        // A reader with a participant shares its SAME scheduler and
        // clock, the one LIVELINESS uses -- its thread detects a miss
        // asynchronously, with no take()/read() call at all. A reader
        // built with no participant (a standalone unit, bypassing
        // `Participant::topic()`) gets its OWN `Shared`, with no
        // scheduler thread: lazy-only detection (LIVELINESS itself
        // tracks nothing for such a reader either).
        let deadlines = (!qos.deadline.is_infinite()).then(|| {
            let shared = participant
                .as_ref()
                .and_then(|p| p.liveliness.as_ref())
                .map(|l| Arc::clone(l.shared()))
                .unwrap_or_else(|| {
                    crate::dds::liveliness::Shared::new(Arc::new(
                        crate::dds::liveliness::MonotonicClock::new(),
                    ))
                });
            let slot = Arc::clone(&listener);
            crate::dds::liveliness::ReaderDeadlines::new(
                shared,
                qos.deadline.period,
                Arc::clone(&status_condition),
                Box::new(move |status| {
                    let l = slot.get(StatusMask::REQUESTED_DEADLINE_MISSED)?;
                    Some(Box::new(move || l.on_requested_deadline_missed(status))
                        as crate::dds::reader::notices::Notice)
                }),
            )
        });
        let local_ownership = super::runtime::LocalOwnership {
            registrations: Arc::clone(&registrations),
            deadlines: deadlines.as_ref().map(Arc::downgrade),
            by_source_timestamp: qos.destination_order.uses_source_timestamp(),
            key_of: (exclusive || deadlines.is_some()).then(|| {
                Arc::new(|bytes: &[u8], version: crate::dds::CdrVersion| {
                    T::decode(&T::capture_wire_data(bytes, None), version)
                        .ok()
                        .map(|sample| sample.compute_key())
                }) as super::runtime::KeyOf
            }),
        };
        // The reader's listener slot: every callback site below holds it,
        // so `DataReader::set_listener` reaches them all at runtime.
        // `on_data_available` for intra-process deliveries, which the
        // writer's merger makes without passing through the network
        // subscriber. Armed only while a listener covers DATA_AVAILABLE;
        // runs on the writer's thread. Weak: the observer lives in the
        // writer's merger, which can outlive this reader.
        //
        // A BY_SOURCE_TIMESTAMP reader (DDS v1.4 Sec.2.2.3.17) admits a
        // local sample only when its pump decodes it, after this call:
        // its value is not known to be part of the instance's history
        // here, so no payload reaches the listener from this path. The
        // observer delivers a payload-less DATA_AVAILABLE notification;
        // the application reads what was admitted.
        let by_source = qos.destination_order.uses_source_timestamp();
        // A reader that orders by source timestamp or filters by time tells
        // its listener that data is available without a payload: which sample
        // the application sees is decided when it enters the history.
        let notify_only = by_source || !qos.time_based_filter.is_disabled();
        let delivery_observer = {
            let slot = Arc::downgrade(&listener);
            let topic_for_observer = topic.clone();
            let deadline_watch = deadlines.as_ref().map(Arc::downgrade);
            // A finite deadline observes arrivals even without a listener.
            let hint = if deadlines.is_some() {
                Arc::new(std::sync::atomic::AtomicU32::new(
                    StatusMask::DATA_AVAILABLE.bits(),
                ))
            } else {
                listener.hint()
            };
            let notice_slot = slot.clone();
            let notice_topic = topic_for_observer.clone();
            let observer = rt::DeliveryObserver::new(
                hint,
                StatusMask::DATA_AVAILABLE.bits(),
                Box::new(move |bytes: &[u8], version: crate::dds::CdrVersion| {
                    let Some(slot) = slot.upgrade() else {
                        return;
                    };
                    let listener = slot.get(StatusMask::DATA_AVAILABLE);
                    // Neither a panicking decode (application codec) nor a
                    // panicking listener may unwind through the writer's
                    // merger: it owes slab references. The merger calls it
                    // with none of its locks held.
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        if notify_only && deadline_watch.is_none() {
                            return;
                        }
                        if let Ok(sample) = T::decode(&T::capture_wire_data(bytes, None), version) {
                            if !T::captures_wire_identity() {
                                if let Some(watch) = deadline_watch.as_ref().and_then(std::sync::Weak::upgrade) {
                                    watch.on_sample(super::InstanceHandle::new(sample.compute_key()));
                                }
                            }
                            if let Some(listener) = listener.filter(|_| !notify_only) {
                                listener.on_data_available(&sample);
                            }
                        }
                    }))
                    .is_err()
                    {
                        log::error!(
                            "[reader] decode or on_data_available panicked (intra-process delivery, topic='{}')",
                            topic_for_observer
                        );
                    }
                }),
            )
            .deferring(super::notices::notify_boxed);
            let observer = if notify_only {
                observer.notifying(Arc::new(move || {
                    let Some(slot) = notice_slot.upgrade() else { return };
                    let Some(listener) = slot.get(StatusMask::DATA_AVAILABLE) else { return };
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        listener.on_data_available_notification();
                    })).is_err() {
                        log::error!(
                            "[reader] on_data_available_notification panicked (intra-process delivery, topic='{}')",
                            notice_topic
                        );
                    }
                }), deadlines.is_some())
            } else {
                observer
            };
            Arc::new(observer)
        };
        // The reader's history as the writers' mergers see it
        // (`local_door`): a KEEP_LAST reader drops what newer samples of
        // their instance replace rather than the newest sample, a RELIABLE
        // KEEP_ALL reader's local samples take places in its history room,
        // and the writer of a RELIABLE reader with no room waits for some.
        let keep = match qos.history {
            History::KeepLast(depth) => super::local_door::Keep::Last(depth as usize),
            History::KeepAll if super::admission::HistoryRoom::discards_old_values(&qos) => {
                super::local_door::Keep::AllDiscardingOld(
                    qos.resource_limits.max_samples_per_instance,
                )
            }
            History::KeepAll => super::local_door::Keep::All,
        };
        // The local path's SAMPLE_REJECTED snapshots, told in order
        // (`notices::Ordered`), one queue for every door of the reader.
        let local_rejections = Arc::new(super::notices::Ordered::default());
        let door = |bindings: std::sync::Weak<ReaderBindings>| {
            super::local_door::LocalDoor::<T>::new(
                bindings,
                keep,
                reliable,
                history_room.as_ref().map(Arc::clone),
                local_places,
                Arc::downgrade(&registrations),
                Arc::clone(&room_wait),
                super::local_door::RejectionReport {
                    status: Arc::downgrade(&sample_rejected),
                    condition: Arc::downgrade(&status_condition),
                    listener: Arc::downgrade(&listener),
                    dropped: Arc::clone(&dropped),
                    notices: Arc::clone(&local_rejections),
                },
                qos.destination_order.uses_source_timestamp(),
                qos.presentation.access_scope == crate::dds::qos::PresentationAccessScope::Group
                    && qos.presentation.ordered_access,
            )
        };
        let local_hold = door(std::sync::Weak::new()).hold();
        let bindings = Arc::new_cyclic(|bindings| {
            let door: Arc<dyn rt::ReaderDoor> = Arc::new(door(bindings.clone()));
            ReaderBindings::new(
                Arc::clone(&ring),
                network_ring.as_ref().map(Arc::clone),
                history_room.as_ref().map(Arc::clone),
                ring_capacity,
                &status_condition,
                sample_filter,
                local_ownership,
                Some(delivery_observer),
                Some(door),
                Arc::clone(&room_wait),
                local_hold,
                T::captures_wire_identity(),
                subscriber_barrier.clone(),
            )
        });
        // A local coherent set that found an access bracket open waits for
        // it to close: the bracket's `end_access` asks this reader's
        // writers' coordinators to deliver again (`retry_local_groups`).
        if let Some(barrier) = subscriber_barrier.as_ref() {
            barrier.attach_local_retry(Arc::downgrade(&bindings));
        }

        // Shared dispose event queue between ReaderSubscriber and
        // DataReader; it raises the dispose wake word on the condition.
        // The reader's instance table: the cache stamps samples with it,
        // the dispose queue records the NOT_ALIVE transitions in it.
        // DESTINATION_ORDER (DDS v1.4 Sec.2.2.3.17) resolved ONCE here,
        // at reader creation, into the table's flag: the hot push path
        // then reads it instead of doing a per-sample QoS lookup.
        let instances = Arc::new(InstanceTable::with_destination_order(
            qos.destination_order.uses_source_timestamp(),
        ));
        let dispose_events = Arc::new(DisposeQueue::with_instances(
            Arc::clone(&status_condition),
            Arc::clone(&instances),
            deadlines.clone(),
        ));
        // BY_SOURCE_TIMESTAMP: an unregister applied whatever its own
        // ordering asks writer presence again under the instance lock.
        if instances.by_source_timestamp() {
            dispose_events.revalidate_presence_with(Arc::clone(&registrations));
        }
        // A deleted local writer whose unregisters never reached the reader
        // leaves its instances without writers: announced like a remote
        // writer's departure, after everything the local writers sent
        // (`u64::MAX`, no writer GUID on the local path).
        {
            let queue = Arc::downgrade(&dispose_events);
            let guard = participant_guard.as_ref().map(Arc::downgrade);
            registrations.on_orphaned(Box::new(move |keys| {
                let Some(queue) = queue.upgrade() else {
                    return;
                };
                for key_hash in keys {
                    queue.push(super::subscriber::DisposeEvent {
                        key_hash,
                        kind: crate::engine::subscriber::DisposeKind::Unregistered,
                        seq: 0,
                        writer_guid: None,
                        order_seq: u64::MAX,
                        announced: false,
                        read: false,
                        from_local_writer: true,
                        disposed_generation_count: 0,
                        no_writers_generation_count: 0, // overwritten by `push`
                        source_timestamp_ns: None,      // synthesized, not received
                    });
                }
                if let Some(guard) = guard.as_ref().and_then(std::sync::Weak::upgrade) {
                    guard.set_trigger_value(true);
                }
            }));
        }

        // Per-writer reorder gate, shared between the subscriber (writes
        // arriving samples) and the heartbeat handler (seeds the expected
        // base seq from `HeartbeatSubmessage.firstSN`). A RELIABLE VOLATILE
        // reader seeds it from its first DATA instead (it is owed no
        // history, DDS v1.4 Sec.2.2.3.4).
        //
        // A BEST_EFFORT reader, whatever its durability, gets the RTPS
        // best-effort acceptance rule instead (`ReorderGate::new_best_effort`).
        let is_reliable_reader = matches!(qos.reliability, Reliability::Reliable);
        let is_volatile = matches!(qos.durability, Durability::Volatile);
        let reorder_gate = Arc::new(Mutex::new(if is_reliable_reader {
            ReorderGate::new(true, is_volatile)
        } else {
            ReorderGate::new_best_effort()
        }));

        // Coherent-access runtime config (RTPS v2.5 sec. 8.7.5). Captured
        // here so the subscriber can buffer per-(writer, set) and
        // flush atomically on ECS receipt. Presentation QoS is
        // immutable per DDS spec 2.2.3.6 so a snapshot at build time
        // is safe.
        let coherent_cfg = super::subscriber::CoherentConfig {
            coherent_access: qos.presentation.coherent_access,
            is_group_scope: matches!(
                qos.presentation.access_scope,
                crate::dds::qos::PresentationAccessScope::Group
            ),
        };

        // Cross-reader coherent presentation barrier: a coherent reader
        // attached to a Subscriber entity joins that Subscriber's shared
        // barrier so its per-topic coherent sets are released aligned with
        // the other coherent readers fed by the same remote publisher (one
        // complete cross-topic group per read cycle, DDS v1.4 sec. 2.2.3.6).
        // Non-coherent readers and readers built without a Subscriber never
        // reserve a slot, so their delivery is unchanged.
        let access_gate = subscriber_barrier.clone();
        let (coherent_barrier, barrier_member) = match subscriber_barrier {
            Some(barrier)
                if coherent_cfg.coherent_access
                    || (coherent_cfg.is_group_scope && qos.presentation.ordered_access) =>
            {
                // The reader's Durability kind feeds the barrier's
                // generation-alignment rule: only a VOLATILE member's
                // unreachable past generations may be discarded (see the
                // coherent_barrier module docs).
                let member = barrier.reserve(topic.clone(), is_volatile);
                // A remote writer's Publisher, from its SEDP
                // (PID_GROUP_ENTITY_ID): the barrier keys sets by Publisher.
                //
                // A writer discovery does not know the Publisher of is
                // asked again at its next deposit, on the router thread: it
                // is asked of discovery again only once discovery's topic
                // registry changed (`UnresolvedWriters`), not per deposit.
                if let Some(fsm) = participant.as_ref().and_then(|p| p.discovery()) {
                    let topic = topic.clone();
                    let unresolved = std::sync::Mutex::new(UnresolvedWriters::default());
                    barrier.attach_resolver(
                        member,
                        Arc::new(move |writer: &[u8; 16]| {
                            let generation = fsm.topic_registry_generation();
                            if unresolved
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .asked(generation, writer)
                            {
                                return None;
                            }
                            let publisher = fsm
                                .find_writers_for_topic(&topic)
                                .iter()
                                .find(|w| w.endpoint_guid.as_bytes() == *writer)
                                .and_then(|w| w.group_entity_id);
                            if publisher.is_none() {
                                unresolved
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .note(generation, *writer);
                            }
                            publisher
                        }),
                    );
                }
                (Some(barrier), Some(member))
            }
            _ => (None, None),
        };

        let is_reliable = matches!(qos.reliability, Reliability::Reliable);

        // The reader's entity id is allocated before anything that answers
        // for the reader is built: a reliable reader acknowledges under its
        // own readerId (RTPS 2.5 8.4.12), so its HEARTBEAT handler and its
        // proxies must carry the id SEDP will announce.
        let reservation = participant.as_ref().map(|p| match type_name_override {
            Some(ref type_name) => p.reserve_reader_endpoint::<T>(
                &topic,
                Some(type_name),
                type_object_override.clone(),
                type_name_only,
            ),
            None => p.reserve_reader_endpoint::<T>(&topic, None, None, false),
        });
        let reader_guid: Option<[u8; 16]> =
            participant
                .as_ref()
                .zip(reservation.as_ref())
                .map(|(p, reservation)| {
                    let mut guid = p.guid().as_bytes();
                    guid[12..16].copy_from_slice(&reservation.entity_id());
                    guid
                });
        if is_reliable {
            if let Some(guid) = reader_guid {
                bindings.set_ack_identity(
                    guid,
                    qos.durability == crate::dds::qos::Durability::Volatile,
                );
            }
        }
        // Only a RELIABLE reader keeps WriterProxies and acknowledges.
        let ack_credit = if is_reliable {
            participant
                .as_ref()
                .zip(reader_guid)
                .map(|(p, guid)| ReaderAckCredit::new(p.user_data_registry.clone(), guid))
        } else {
            None
        };
        #[cfg(test)]
        let ack_credit = self.ack_credit_for_test.or(ack_credit);
        // Retires the reader's proxies when dropped: held by the DataReader,
        // or dropped here if the build stops early.
        let proxy_lease = ack_credit.as_ref().map(ReaderAckCredit::lease);

        // A RELIABLE reader still gets a heartbeat handler registered so the
        // fallback ACKNACK path (no `control_tx`, e.g. intra-vendor
        // multicast / unit tests) keeps working; the production repair path
        // for a real socket is the per-writer proxy registry wired into
        // ReaderSubscriber below plus the control-plane ACKNACK. See the
        // KEYSTONE NOTE on `HeartbeatHandler` in `heartbeat.rs`.
        //
        // The registration is held open by `heartbeat_token`, handed to
        // DataReader::new: `TopicRegistry::heartbeat_handlers` never
        // expired an entry on its own, so a reader that rebuilt (e.g.
        // across a reconnect) piled up one dead handler per build, each
        // still reachable from `deliver_heartbeat`'s broadcast loop.
        let mut heartbeat_token: Option<crate::engine::HeartbeatHandlerToken> = None;
        if is_reliable {
            if let Some(ref registry) = registry {
                // Create heartbeat handler with ACKNACK context if we have transport and participant
                let handler: Arc<dyn crate::engine::HeartbeatHandler> =
                    match (&transport, &participant, &ack_credit) {
                        (Some(ref xport), Some(ref part), Some(ref credit)) => {
                            log::debug!(
                            "[reader] Creating ACKNACK-capable heartbeat handler for topic='{}'",
                            topic
                        );
                            // It answers under the id SEDP announces for this
                            // reader (reserved above), and only the writers
                            // this reader is matched with.
                            Arc::new(ReaderHeartbeatHandler::with_acknack_context(
                                credit.clone(),
                                xport.clone(),
                                part.discovery(),
                                &topic,
                            ))
                        }
                        _ => Arc::new(ReaderHeartbeatHandler::new()),
                    };
                let id = registry.register_heartbeat_handler(handler);
                heartbeat_token = Some(crate::engine::HeartbeatHandlerToken::new(registry, id));
            }
        }

        // Construct the subscriber up-front so the heartbeat handler can
        // share a strong reference for the gate release sink.
        let mut reader_subscriber = ReaderSubscriber::<T>::new_with_coherent(
            topic.clone(),
            Arc::clone(network_ring.as_ref().unwrap_or(&ring)),
            Arc::clone(&status_condition),
            participant_guard.as_ref().map(Arc::clone),
            content_filter.clone(),
            None,
            Arc::clone(&dispose_events),
            Arc::clone(&reorder_gate),
            coherent_cfg,
            participant.as_ref().and_then(|p| p.match_registry.clone()),
            // Reliable readers advance THEIR OWN ACKNACK contiguous-prefix
            // base via on_data (RTPS v2.5 Sec.8.4.12). None for a
            // BEST_EFFORT reader and on the participant-less path.
            ack_credit.clone(),
            Arc::clone(&sample_rejected),
            qos.data_representation.clone(),
            qos.partition.clone(),
            qos.ownership.kind,
            // Engine TopicRegistry: primary OWNERSHIP-gate resolution source
            // (SEDP-time record, survives FSM zombie purges).
            registry.clone(),
            coherent_barrier.as_ref().map(Arc::clone),
            barrier_member,
            // Security suite for the data-plane decrypt gate: a secured
            // payload is opened with the (writer GUID, key id) entry the
            // volatile channel installed, before any reception bookkeeping.
            #[cfg(feature = "security")]
            participant.as_ref().and_then(|p| p.security()),
        );
        reader_subscriber.time_based_filter = qos.time_based_filter;
        reader_subscriber.dropped = Arc::clone(&dropped);
        // A parked TIME_BASED_FILTER sample is announced at its window's end
        // by the participant's liveliness scheduler thread. Without one (a
        // standalone reader), it is shown at the application's next access.
        reader_subscriber.filter_waker = (!qos.time_based_filter.is_disabled())
            .then(|| {
                participant
                    .as_ref()
                    .and_then(|p| p.liveliness.as_ref())
                    .map(|l| Arc::new(super::filter_wake::FilterWaker::new(Arc::clone(l.shared()))))
            })
            .flatten();
        // The leases of the writers it matches (DDS v1.4 Sec.2.2.3.11), on
        // its participant's liveliness thread.
        let liveliness = participant
            .as_ref()
            .and_then(|p| p.liveliness.as_ref())
            .map(|l| {
                let slot = Arc::clone(&listener);
                let registrations_for_liveliness = Arc::downgrade(&registrations);
                let dispose_events_for_liveliness = Arc::downgrade(&dispose_events);
                crate::dds::liveliness::ReaderLiveliness::new(
                    Arc::clone(l.shared()),
                    Arc::clone(&status_condition),
                    Box::new(move |status| {
                        let l = slot.get(StatusMask::LIVELINESS_CHANGED)?;
                        Some(Box::new(move || l.on_liveliness_changed(status))
                            as crate::dds::reader::notices::Notice)
                    }),
                    Box::new(move |guid, alive| {
                        let (Some(registrations), Some(dispose_events)) = (
                            registrations_for_liveliness.upgrade(),
                            dispose_events_for_liveliness.upgrade(),
                        ) else {
                            return;
                        };
                        super::subscriber::on_writer_alive(
                            &registrations,
                            &dispose_events,
                            guid.as_bytes(),
                            alive,
                        );
                    }),
                )
            });
        reader_subscriber.liveliness = liveliness.clone();
        // The network path reads fields through the same extractor as the
        // intra-process filter above.
        reader_subscriber.field_extractor = field_extractor;
        reader_subscriber.listener = Arc::clone(&listener);
        reader_subscriber.reader_entity_id =
            reader_guid.map(|[.., e0, e1, e2, e3]| [e0, e1, e2, e3]);
        reader_subscriber.room = history_room;
        reader_subscriber.wire_reliable = is_reliable;
        if coherent_cfg.is_group_scope && qos.presentation.ordered_access {
            reader_subscriber.wire_bindings = Some(Arc::downgrade(&bindings));
            reader_subscriber.wire_durable = !is_volatile;
        }
        // The budget its coherent sets are staged in, its own, from its
        // RESOURCE_LIMITS (`staging_budget`).
        if coherent_cfg.coherent_access {
            reader_subscriber.staging = super::staging_budget::StagingBudget::new(
                super::staging_budget::StagingBudget::samples_for(&qos),
            );
        }
        reader_subscriber.sample_lost = Arc::clone(&sample_lost);
        reader_subscriber.writer_instances = Arc::clone(&registrations);
        // A GROUP set of the spec dialect is decided against discovery's
        // writers of its Publisher (RTPS v2.5 Sec.8.7.6).
        if coherent_cfg.is_group_scope
            && (coherent_cfg.coherent_access || qos.presentation.ordered_access)
        {
            if let Some((fsm, registry)) = participant
                .as_ref()
                .and_then(|p| Some((p.discovery()?, p.match_registry.clone()?)))
            {
                let roster = super::subscriber::DiscoveryRoster {
                    fsm,
                    registry,
                    entry: Arc::clone(&reader_subscriber.match_entry),
                };
                let _ = reader_subscriber
                    .group_roster
                    .set(Arc::new(roster) as Arc<dyn super::subscriber::GroupRoster>);
            }
        }
        let departed_lifespans = Arc::clone(&reader_subscriber.departed_lifespans);
        let mut listener_queues = reader_subscriber.listener_queues();
        listener_queues.push(Arc::clone(&local_rejections));
        let reader_subscriber = Arc::new(reader_subscriber);
        if let Some(waker) = reader_subscriber.filter_waker.as_ref() {
            waker.set_reader(Arc::downgrade(&reader_subscriber));
        }

        // Attach the barrier release closure now that the
        // Arc<ReaderSubscriber> exists (the closure captures a Weak, so no
        // reference cycle). No-op for readers without a barrier.
        if !reader_subscriber.attach_barrier_delivery() {
            return Err(Error::ResourceLimitExceeded(
                "ordered history has no room for this reader's sample obligations".into(),
            ));
        }
        // Another reader's member may reject this reader's staged sets, to
        // keep the process within its staging ceiling
        // (`MemoryPolicy::max_staging_bytes`). Weak: the budget is the
        // subscriber's.
        {
            let owner: std::sync::Weak<dyn super::staging_budget::StagedOwner> =
                Arc::downgrade(&reader_subscriber) as _;
            reader_subscriber.staging.set_owner(owner);
        }
        // Room given back schedules a retry of the coherent sets that wait
        // for it (`HistoryRoom::came_back`). Weak: the room is the
        // subscriber's.
        if let Some(room) = reader_subscriber.room.as_ref() {
            let subscriber = Arc::downgrade(&reader_subscriber);
            room.on_room(Box::new(move || {
                if let Some(subscriber) = subscriber.upgrade() {
                    subscriber.retry_waiting_sets();
                }
            }));
        }

        let subscriber_token = if let Some(ref registry) = registry {
            let as_sub: Arc<dyn crate::engine::Subscriber> =
                Arc::clone(&reader_subscriber) as Arc<dyn crate::engine::Subscriber>;
            match registry.register_subscriber_scoped(as_sub) {
                Ok(token) => Some(token),
                Err(err) => {
                    log::debug!("Failed to register subscriber: {}", err);
                    None
                }
            }
        } else {
            None
        };

        // Registering this reader in domain state (intra-process
        // auto-binding) is deferred to just after the match/incompatible-QoS
        // callbacks are built below (`bind_token`): a participant with no
        // `match_registry` (IntraProcess) drives SUBSCRIPTION_MATCHED /
        // REQUESTED_INCOMPATIBLE_QOS from THAT registration instead, and
        // catching up to a writer already registered on this key must
        // report the match before any TRANSIENT_LOCAL history the same call
        // replays into this reader (DDS v1.4 Sec.2.2.4.1; see
        // `domain_registry::LocalMatchStatus`).

        // Get security plugin from participant if available
        #[cfg(feature = "security")]
        let security = participant.as_ref().and_then(|p| p.security());

        // Shared effective lifespan, tightened by the match-notification
        // registry when a remote writer announces a finite Lifespan.
        let lifespan_nanos = {
            use std::sync::atomic::AtomicU64;
            let initial = if qos.lifespan.is_infinite() {
                u64::MAX
            } else {
                u64::try_from(qos.lifespan.duration.as_nanos()).unwrap_or(u64::MAX)
            };
            Arc::new(AtomicU64::new(initial))
        };

        // Register match notification (on_subscription_matched + on_requested_incompatible_qos
        // + inconsistent-topic counter) when a participant is present. Counters are tracked
        // even without a listener so counter-only OMG tests see accurate values via the
        // MatchEntry status fields. The inconsistent-topic callback is wired when a listener
        // is installed; counter increments always happen regardless (register_reader_full
        // tracks inconsistent_type_count unconditionally).
        // `match_cb` / `incompat_cb` are shared between whichever
        // registries end up driving them: `match_registry` (SEDP: remote
        // peers, and a local peer caught by the loopback self-announce)
        // when the participant has one, and `domain_registry::
        // LocalMatchStatus` (this reader's own `bind_token` below) ALWAYS
        // -- not only when there is no `match_registry`. A reader with a
        // real transport can still be matched, through domain_registry.rs
        // alone, with a writer that has none at all (IntraProcess): such a
        // writer is never announced over SEDP, so `match_registry` can
        // never report it, and SUBSCRIPTION_MATCHED for it stayed at 0
        // forever without this fallback (the mixed-transport gap).
        // domain_registry.rs fires this status only for a pair where the
        // peer has no wire path either (`local_status_applies`): a
        // same-participant pair where BOTH sides are wire-capable is
        // SEDP's loopback to report, never double-counted here.
        let (match_token, match_status) = if let Some(ref p) = participant {
            let listener_for_match = Arc::clone(&listener);
            // Presentation barrier membership (discovery cold path): a
            // coherent reader becomes required for a remote publisher's
            // aligned release the moment one of that publisher's
            // writers matches (DDS v1.4 sec. 2.2.3.6). Resolving membership
            // here keeps the data path free of any per-message
            // publisher lookup. None when this reader has no barrier.
            let barrier_for_match = coherent_barrier.as_ref().map(Arc::clone);
            let barrier_member_for_match = barrier_member;
            // A writer of this participant is matched like any other
            // (`MatchNotificationRegistry::on_endpoint_discovered`), but
            // its samples come through its merger, never through the
            // barrier's remote release: not a member's to wait for.
            let own_prefix = p.guid().prefix;

            {
                let subscription_matched_for_match = Arc::clone(&subscription_matched);
                let status_condition_for_match = Arc::clone(&status_condition);
                #[allow(clippy::type_complexity)]
                let match_cb: Arc<
                    dyn Fn(u32, i32, u32, i32, Option<GUID>) + Send + Sync,
                > = Arc::new(
                    move |total,
                          total_change,
                          current,
                          current_change,
                          last_handle: Option<GUID>| {
                        if current_change > 0 {
                            if let (Some(barrier), Some(member), Some(guid)) = (
                                barrier_for_match.as_ref(),
                                barrier_member_for_match,
                                last_handle.filter(|guid| guid.prefix != own_prefix),
                            ) {
                                barrier.register_matched_writer(member, guid.as_bytes());
                            }
                        }
                        // SUBSCRIPTION_MATCHED (DDS v1.4 Sec.2.2.4.1):
                        // accumulate here always, whether or not a
                        // listener is installed, so a later
                        // `get_subscription_matched_status` sees every
                        // event -- same rule as
                        // `ReaderSubscriber::report_sample_rejected`.
                        let listener = listener_for_match.get(StatusMask::SUBSCRIPTION_MATCHED);
                        let mut status = subscription_matched_for_match
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        status.total_count = total;
                        status.total_count_change =
                            status.total_count_change.saturating_add(total_change);
                        status.current_count = current;
                        status.current_count_change =
                            status.current_count_change.saturating_add(current_change);
                        status.last_publication_handle = last_handle;
                        if let Some(l) = listener {
                            let snap = status.clone();
                            status.total_count_change = 0;
                            status.current_count_change = 0;
                            drop(status);
                            status_condition_for_match
                                .clear_active_status(StatusMask::SUBSCRIPTION_MATCHED);
                            // Out of the match registry's dispatch (`notices`).
                            super::notices::notify(move || l.on_subscription_matched(snap));
                        } else {
                            drop(status);
                            status_condition_for_match
                                .raise_active_statuses(StatusMask::SUBSCRIPTION_MATCHED);
                            let sc = Arc::clone(&status_condition_for_match);
                            super::notices::notify(move || {
                                sc.notify_waitsets_for(StatusMask::SUBSCRIPTION_MATCHED);
                            });
                        }
                    },
                );

                #[allow(clippy::type_complexity)]
                // Always registered: a listener installed after the build
                // must be reached (the registry counts only while a
                // callback is registered).
                let incompat_cb: Arc<dyn Fn(u32, i32, u32) + Send + Sync> = {
                    let slot = Arc::clone(&listener);
                    let requested_incompatible_qos_for_match =
                        Arc::clone(&requested_incompatible_qos);
                    let status_condition_for_incompat = Arc::clone(&status_condition);
                    Arc::new(move |total: u32, total_change: i32, policy_id: u32| {
                        // REQUESTED_INCOMPATIBLE_QOS (DDS v1.4
                        // Sec.2.2.4.1): same always-accumulate rule as
                        // SUBSCRIPTION_MATCHED above.
                        let listener = slot.get(StatusMask::REQUESTED_INCOMPATIBLE_QOS);
                        let mut status = requested_incompatible_qos_for_match
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        status.total_count = total;
                        status.total_count_change =
                            status.total_count_change.saturating_add(total_change);
                        status.last_policy_id = policy_id;
                        if let Some(l) = listener {
                            let snap = status.clone();
                            status.total_count_change = 0;
                            drop(status);
                            status_condition_for_incompat
                                .clear_active_status(StatusMask::REQUESTED_INCOMPATIBLE_QOS);
                            super::notices::notify(move || {
                                l.on_requested_incompatible_qos(snap);
                            });
                        } else {
                            drop(status);
                            status_condition_for_incompat
                                .raise_active_statuses(StatusMask::REQUESTED_INCOMPATIBLE_QOS);
                            let sc = Arc::clone(&status_condition_for_incompat);
                            super::notices::notify(move || {
                                sc.notify_waitsets_for(StatusMask::REQUESTED_INCOMPATIBLE_QOS);
                            });
                        }
                    })
                };

                // ALWAYS built: this reader's own `bind_token` registration
                // (below) is the ONLY source of SUBSCRIPTION_MATCHED /
                // REQUESTED_INCOMPATIBLE_QOS for a peer domain_registry.rs
                // can see but SEDP cannot (no wire path on either side at
                // all), whether or not this participant ALSO has a
                // `match_registry` for its wire-reachable peers.
                let status_match_cb = Arc::clone(&match_cb);
                let status_incompat_cb = Arc::clone(&incompat_cb);
                let match_status = Some(crate::dds::domain_registry::LocalMatchStatus::new(
                    reader_guid.map_or_else(GUID::zero, GUID::from_bytes),
                    Box::new(move |a, b, c, d, e| status_match_cb(a, b, c, d, e)),
                    Some(Box::new(move |a, b, c| status_incompat_cb(a, b, c))),
                ));

                let match_token = if let Some(ref reg) = p.match_registry {
                    let local_type_object = type_object_override
                        .clone()
                        .or_else(|| T::get_type_object());

                    // A reliable reader keeps one WriterProxy per matched
                    // writer (RTPS 2.5 8.4.12, `matched_writer_add` /
                    // `matched_writer_remove`). Every writer it matches is
                    // RELIABLE: RELIABILITY is requested/offered with
                    // BEST_EFFORT < RELIABLE (DDS 1.4 2.2.3.14), so a
                    // RELIABLE reader never matches a best-effort writer.
                    let peer_cb: Option<PeerCallback> = ack_credit.clone().map(|credit| {
                        Box::new(move |change: PeerChange| match change {
                            PeerChange::Matched { guid, .. } => {
                                credit.match_writer(guid.as_bytes())
                            }
                            PeerChange::Unmatched { guid } => {
                                credit.unmatch_writer(&guid.as_bytes())
                            }
                        }) as PeerCallback
                    });

                    let inconsistent_cb: Option<Box<dyn Fn(u32, i32) + Send + Sync>> = {
                        let slot = Arc::clone(&listener);
                        Some(Box::new(move |total: u32, total_change: i32| {
                            if let Some(l) = slot.get(StatusMask::INCONSISTENT_TOPIC) {
                                l.on_inconsistent_topic(
                                    crate::dds::listener::InconsistentTopicStatus {
                                        total_count: total,
                                        total_count_change: total_change,
                                    },
                                );
                            }
                        })
                            as Box<dyn Fn(u32, i32) + Send + Sync>)
                    };

                    let reg_match_cb = Arc::clone(&match_cb);
                    let reg_incompat_cb = Arc::clone(&incompat_cb);
                    let liveliness_hook = liveliness.clone().map(|l| {
                        Box::new(move |change: LivelinessPeer| match change {
                            LivelinessPeer::Matched {
                                guid,
                                liveliness,
                                local,
                            } => l.matched(guid, liveliness, local),
                            LivelinessPeer::Unmatched { guid } => l.unmatched(guid),
                        }) as crate::dds::match_notification::LivelinessHook
                    });
                    // The name announced in SEDP: Step 2 compares it.
                    let announced_type_name = type_name_override
                        .clone()
                        .unwrap_or_else(|| T::type_descriptor().type_name.to_string());
                    let token = reg.register_reader_with_liveliness(
                        topic.clone(),
                        qos.clone(),
                        crate::dds::match_notification::LocalType::new(
                            crate::dds::cdr_negotiation::Xcdr1Encoding::of::<T>(),
                            announced_type_name,
                        ),
                        local_type_object,
                        move |a, b, c, d, e| reg_match_cb(a, b, c, d, e),
                        peer_cb,
                        Some(Box::new(move |a, b, c| reg_incompat_cb(a, b, c))
                            as Box<dyn Fn(u32, i32, u32) + Send + Sync>),
                        inconsistent_cb,
                        Arc::clone(&lifespan_nanos),
                        ShmPolicy::resolve(self.shm_policy, Some(p.shm_policy())),
                        liveliness_hook,
                    );
                    // The reader's GUID, for the CryptoTokens addressed to
                    // it or by it (DDS Security v1.1 Sec.7.4.4.6.2-3).
                    if let Some(guid) = reader_guid {
                        token.bind_local_guid(crate::core::discovery::GUID::from_bytes(guid));
                    }
                    Some(token)
                } else {
                    None
                };

                (match_token, match_status)
            }
        } else {
            (None, None)
        };

        // Register reader in domain state for intra-process auto-binding.
        // `match_status` (built above, ALWAYS `Some` when this reader
        // has a participant) makes this call the source of
        // SUBSCRIPTION_MATCHED / REQUESTED_INCOMPATIBLE_QOS for any peer
        // with no wire path at all, whether or not this reader's OWN
        // participant also has a `match_registry` for its wire-reachable
        // peers (`local_status_applies` in domain_registry.rs is what
        // keeps the two sources from double-counting a same-participant
        // pair).
        //
        // Retained separately from the `match_status` moved into
        // `register_reader_with_match` below: `DataReader::
        // get_matched_publications` reads it directly, exactly like
        // `DataWriter::_match_status`.
        let match_status_for_reader = match_status.clone();
        let bind_token = if let Some(ref domain_state) = domain_state {
            let type_name = type_name_override
                .as_deref()
                .unwrap_or(T::type_descriptor().type_name);
            let type_id = TypeId::from_type_name(type_name);
            let key = MatchKey::new(topic.as_str(), type_id);

            // Generate a GUID for this reader endpoint (use zero if no participant)
            let guid = GUID::zero();

            log::debug!(
                "[ReaderBuilder] Registering reader in domain {} for topic='{}' type='{}'",
                domain_state.domain_id,
                topic,
                type_name
            );

            // Create bind callback that will be called for each matching
            // writer. ReaderBindings dedups per merger, creates the
            // binding's ring (primary for the first binding, fresh
            // after) and registers it with the writer's merger.
            let bindings_for_bind = Arc::clone(&bindings);

            // A writer's history replayed into this reader as it binds is
            // announced to its listener (`DeliveryObserver::observe_later`)
            // once the registration's locks are released: held until this
            // value drops, at the end of the statement.
            let _replay_notices = super::notices::Delivering::enter();
            Some(domain_state.register_reader_with_match(
                key,
                guid,
                ring.clone(),
                crate::dds::domain_registry::EndpointQos::new(
                    &qos,
                    crate::dds::cdr_negotiation::Xcdr1Encoding::of::<T>(),
                ),
                crate::dds::domain_registry::EndpointContext::new(
                    participant.as_ref().map(|p| p.participant_token()),
                    transport.is_some(),
                ),
                match_status,
                move |writer_merger| {
                    bindings_for_bind.bind(&writer_merger);
                },
            ))
        } else {
            None
        };

        // The reader half of the data-plane gate's (writer, reader) key.
        if let Some(ref token) = match_token {
            let _ = reader_subscriber.match_entry.set(token.id());
        }

        // Announce Reader endpoint via SEDP (if participant available),
        // under the entity id reserved above. Only now: from its announcement
        // on a peer's writer may send to it, and until its entry is
        // registered and judged against the writers already known (just
        // above) the reader is matched with nothing and drops everything
        // (`ReaderSubscriber::writer_refused`).
        //
        // The announcement's retirement goes to the reader, whose Drop runs it
        // (`SedpRetirement`); an error below drops it here, which retires the
        // endpoint that was announced but never built.
        let sedp_retirement = match (&participant, reservation) {
            (Some(ref p), Some(reservation)) => {
                Some(p.announce_reserved_reader(&topic, &qos, reservation)?)
            }
            _ => None,
        };

        // Every reader of a Subscriber is held to its access brackets when
        // the Subscriber's access scope is GROUP (`DataReader::consume`).
        Ok(DataReader::new(
            topic,
            qos,
            ring,
            registry,
            status_condition,
            sample_rejected,
            sample_lost,
            Arc::clone(&dropped),
            Arc::clone(&reader_subscriber),
            subscription_matched,
            requested_incompatible_qos,
            bind_token,
            subscriber_token,
            heartbeat_token,
            listener,
            match_token,
            match_status_for_reader,
            proxy_lease,
            #[cfg(feature = "security")]
            security,
            dispose_events,
            instances,
            lifespan_nanos,
            departed_lifespans,
            bindings,
            access_gate,
            listener_queues,
            sedp_retirement,
            liveliness,
            deadlines,
        ))
    }
}

/// The writers discovery did not know the Publisher of, when its topic
/// registry was at `generation`: asked again only once it moved.
#[derive(Default)]
struct UnresolvedWriters {
    generation: u64,
    writers: std::collections::HashSet<[u8; 16]>,
}

impl UnresolvedWriters {
    /// Whether `writer` was asked already, unresolved, at `generation`.
    fn asked(&mut self, generation: u64, writer: &[u8; 16]) -> bool {
        if self.generation != generation {
            self.generation = generation;
            self.writers.clear();
            return false;
        }
        self.writers.contains(writer)
    }

    /// `writer` was asked at `generation`, unresolved.
    fn note(&mut self, generation: u64, writer: [u8; 16]) {
        if self.generation == generation {
            self.writers.insert(writer);
        }
    }
}

#[cfg(test)]
mod unresolved_tests {
    use super::UnresolvedWriters;

    /// A writer whose Publisher discovery did not know is not asked of it
    /// again until discovery's topic registry moves.
    #[test]
    fn an_unresolved_writer_is_asked_again_only_when_discovery_moves() {
        let mut u = UnresolvedWriters::default();
        let w = [7u8; 16];
        assert!(!u.asked(3, &w), "first time");
        u.note(3, w);
        assert!(u.asked(3, &w), "same generation: not asked again");
        assert!(!u.asked(3, &[8u8; 16]), "another writer");
        assert!(!u.asked(4, &w), "discovery moved: asked again");
        u.note(3, w);
        assert!(!u.asked(4, &w), "noted at an older generation: ignored");
    }
}
