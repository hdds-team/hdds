// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Subscriber trait and implementations for receiving topic data

/// Dispose/unregister kind for instance lifecycle changes.
///
/// Maps to the PID_STATUS_INFO (0x0071) value in RTPS inline QoS.
/// DDS-RTPS Sec.9.6.4.9: StatusInfo_t.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisposeKind {
    /// Instance disposed by writer (NOT_ALIVE_DISPOSED_INSTANCE_STATE)
    Disposed = 1,
    /// Writer no longer claims ownership (NOT_ALIVE_NO_WRITERS_INSTANCE_STATE)
    Unregistered = 2,
    /// Both disposed and unregistered
    DisposedUnregistered = 3,
}

/// The instance a received dispose or unregister names, as the DATA gives
/// it: its PID_KEY_HASH and its serialized key (the K=1 payload).
///
/// The key is "the value of the key that identifies the registered
/// instance" (RTPS v2.5 8.3.7.2); the PID_KEY_HASH is "a hint for the key"
/// (8.7.10). Each subscriber therefore names the instance by the key when
/// its type can read it ([`Subscriber::instance_of_key_payload`]), and by the
/// hash otherwise: [`LifecycleKey::for_subscriber`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct LifecycleKey<'a> {
    /// PID_KEY_HASH. With none and a key the subscriber's type does not
    /// read, the change names no instance for it: no guess.
    pub(crate) key_hash: Option<[u8; 16]>,
    /// The serializedPayload of the K=1 DATA, encapsulation header
    /// included.
    pub(crate) serialized_key: Option<&'a [u8]>,
    /// The REAL instance `key_hash` names, already resolved by the caller
    /// (`engine::router::route_data_packet`) through
    /// `TopicRegistry::resolve_legacy_key_hash_instance` when the writer is
    /// flagged legacy (vendor HDDS, pre-`CAP_CONFORMANT_KEY_HASH`: a 1.4.x
    /// peer). `None` for a conforming writer, or a legacy one whose
    /// instance this reader never saw ALIVE (nothing to resolve against,
    /// record 385). Consulted before the raw `key_hash`, never instead of a
    /// readable serialized key.
    pub(crate) legacy_resolved: Option<[u8; 16]>,
}

impl<'a> LifecycleKey<'a> {
    /// A change named by its hash alone.
    pub(crate) const fn hash(key_hash: [u8; 16]) -> Self {
        Self {
            key_hash: Some(key_hash),
            serialized_key: None,
            legacy_resolved: None,
        }
    }

    /// Whether the DATA named an instance at all.
    pub(crate) const fn is_some(&self) -> bool {
        self.key_hash.is_some() || self.serialized_key.is_some()
    }

    /// The instance `sub` names: by the serialized key when its type reads
    /// it; else the real instance a legacy writer's own ordinary samples
    /// already resolved its hash to (`legacy_resolved`); else the hash
    /// itself; `None` when none of the three names one.
    pub(crate) fn for_subscriber(
        &self,
        sub: &dyn Subscriber,
        writer: Option<[u8; 16]>,
        seq: u64,
    ) -> Option<[u8; 16]> {
        sub.resolve_lifecycle_key(
            writer,
            seq,
            self.serialized_key,
            self.legacy_resolved.or(self.key_hash),
        )
    }
}

/// Why a remote DataWriter left (`Subscriber::on_writer_departure`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriterDeparture {
    /// It said so: its SEDP dispose, or its participant's SPDP dispose or
    /// lease-0 farewell. A writer seen again under its GUID is a new one.
    Deleted,
    /// It fell silent: its participant's lease expired, a probation purge,
    /// any removal it did not announce. It may come back as the same
    /// writer, its sequence numbers going on.
    Unheard,
}

/// What a change of a GROUP coherent set of the spec dialect says of its
/// set (`Subscriber::on_group_change`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupChange {
    /// The change's SN.
    pub seq: u64,
    /// The set: its first GSN (PID_GROUP_COHERENT_SET).
    pub group_sn: u64,
    /// The writer's Publisher.
    pub publisher_entity_id: [u8; 4],
    /// PID_WRITER_GROUP_INFO.
    pub writer_set: [u8; 4],
    /// PID_GROUP_SEQ_NUM, when the change carries it.
    pub gsn: Option<u64>,
    /// For the writer's end of the set: the first SN of its part.
    pub part_first_sn: Option<u64>,
}

/// How the router framed one received SerializedPayload: decided once per
/// sample, before any CDR is interpreted, and carried with the sample so the
/// reader reads the bytes the way the router left them.
///
/// Ordered by strength: when several subscribers of a topic answer, the
/// router applies the strongest answer (`Clear < Sealed < Unresolved`).
///
/// Internal routing detail, not part of the supported API: hidden from the
/// docs and `non_exhaustive` so it can grow without a breaking change.
#[doc(hidden)]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PayloadFraming {
    /// The writer speaks in the clear: the CDR encapsulation header is
    /// stripped and the sample is delivered as plain CDR.
    Clear,
    /// The payload is protected (or may be, by topic policy): the bytes are
    /// kept whole for the crypto decoder.
    Sealed,
    /// The writer was not resolved when the router decided: the bytes are
    /// kept whole and the sample is treated as key-unknown, dropped without
    /// acknowledging it, so the reliable writer repairs it once resolved.
    Unresolved,
}

/// Subscriber trait for receiving topic data
///
/// # Thread Safety
/// Implementations must be Send + Sync as callbacks are invoked
/// from the Router background thread.
///
/// # Examples
/// ```no_run
/// use hdds::engine::Subscriber;
///
/// struct MySubscriber {
///     topic: String,
/// }
///
/// impl Subscriber for MySubscriber {
///     fn on_data(&self, topic: &str, seq: u64, data: &[u8]) {
///         println!("Received seq {} ({} bytes) on topic: {}", seq, data.len(), topic);
///     }
///
///     fn topic_name(&self) -> &str {
///         &self.topic
///     }
/// }
/// ```
/// Ticks of the join clock (`join_clock_tick`).
static JOIN_CLOCK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The next tick of a process-wide clock that orders the events a join hint
/// is judged by (`Subscriber::on_dropped_before_discovery`): a reader's
/// creation, a drop recorded before discovery, a writer's binding.
/// Strictly increasing, never 0; taken on cold
/// paths only.
pub(crate) fn join_clock_tick() -> u64 {
    JOIN_CLOCK.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
}

pub trait Subscriber: Send + Sync {
    /// Whether this registration consumes Publisher order for GROUP access.
    /// Queried when the topic's subscriber list changes, never per sample.
    fn requires_ordered_group(&self) -> bool {
        false
    }

    /// A GROUP writer departed, including writers on other topics of the
    /// same Publisher. Called only for ordered GROUP registrations, after
    /// departure proof is visible and outside the registry locks.
    // @audit-ok: unordered registrations intentionally ignore GROUP-only departures.
    fn on_group_writer_departure(&self, _writer: [u8; 16], _publisher: [u8; 4]) {}

    /// Whether the announced writer requires its complete SerializedPayload
    /// to reach the crypto decoder untouched, including any leading bytes.
    /// Routers must select this from endpoint policy before stripping CDR.
    fn payload_protected_for_writer(&self, _writer: &[u8; 16]) -> bool {
        false
    }

    /// The framing the router applies to this writer's SerializedPayload,
    /// decided ONCE per sample and carried with it to the reader (see
    /// [`PayloadFraming`]). The default derives it from
    /// [`Self::payload_protected_for_writer`] and never answers
    /// [`PayloadFraming::Unresolved`].
    ///
    /// Internal routing hook, hidden from the docs: external implementers
    /// should leave the default. Overriding it to return
    /// [`PayloadFraming::Unresolved`] makes the topic drop every sample
    /// (each is treated as key-unknown and never acknowledged).
    #[doc(hidden)]
    fn payload_framing_for_writer(&self, writer: &[u8; 16]) -> PayloadFraming {
        if self.payload_protected_for_writer(writer) {
            PayloadFraming::Sealed
        } else {
            PayloadFraming::Clear
        }
    }

    /// Called when data is received for this subscriber's topic
    ///
    /// # Arguments
    /// - `topic`: Topic name (for multi-topic subscribers)
    /// - `seq`: RTPS writer sequence number (for reliability tracking, Task 2.1)
    /// - `data`: Payload bytes (CDR2 payload from RTPS DATA submessage)
    ///
    /// # Panics
    /// If this method panics, Router will catch it and continue
    /// delivery to other subscribers (logged as delivery_error metric).
    fn on_data(&self, topic: &str, seq: u64, data: &[u8]);

    /// Same as [`Self::on_data`] but also receives the CDR encoding
    /// version extracted from the RTPS encapsulation header per
    /// DDS-RTPS v2.5 sec. 10.7. The default implementation delegates to
    /// `on_data` (version ignored); implementors needing version-aware
    /// decoding should override this method instead.
    fn on_data_with_version(
        &self,
        topic: &str,
        seq: u64,
        data: &[u8],
        _version: crate::dds::CdrVersion,
    ) {
        self.on_data(topic, seq, data);
    }

    /// Same as [`Self::on_data_with_version`] but also forwards the 16-byte
    /// writer GUID (`guid_prefix || entity_id`). Implementations that need
    /// per-writer state (e.g. late-joiner sample reordering for non-Volatile
    /// durability per DDS-RTPS v2.5 sec. 8.4.2.2) override this; others rely on
    /// the default forwarding.
    fn on_data_with_writer(
        &self,
        topic: &str,
        _writer_guid: [u8; 16],
        seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
    ) {
        self.on_data_with_version(topic, seq, data, version);
    }

    /// Coherent-aware data delivery (RTPS v2.5 sec. 8.7.5). Carries the
    /// optional `coherent_sn` (writer-scoped set marker), `group_sn`
    /// (Publisher GSN for GROUP-scope coherent_access), and
    /// `publisher_entity_id` (the EntityId of the owning Publisher,
    /// extracted from `PID_GROUP_ENTITY_ID` per RTPS v2.5 sec. 9.3.2.1
    /// -- required so GROUP-scope buffers can bucket per-Publisher GSN
    /// without aliasing across two Publishers hosted by the same
    /// Participant). Subscribers configured with
    /// `Presentation { coherent_access = true }` use these to buffer
    /// per-(publisher, gsn) samples until `on_ecs` arrives; the
    /// default implementation discards the coherent metadata and
    /// forwards to `on_data_with_writer` to preserve pre-coherent
    /// behaviour for readers that don't opt in.
    #[allow(clippy::too_many_arguments)]
    fn on_data_coherent(
        &self,
        topic: &str,
        writer_guid: [u8; 16],
        seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
        _coherent_sn: Option<u64>,
        _group_sn: Option<u64>,
        _publisher_entity_id: Option<[u8; 4]>,
    ) {
        self.on_data_with_writer(topic, writer_guid, seq, data, version);
    }

    /// Data delivery retaining PID_KEY_HASH for opaque readers. Typed readers
    /// continue to resolve their instance from serialized key fields.
    #[allow(clippy::too_many_arguments)]
    fn on_data_keyed(
        &self,
        topic: &str,
        writer_guid: [u8; 16],
        seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
        _key_hash: Option<[u8; 16]>,
        coherent_sn: Option<u64>,
        group_sn: Option<u64>,
        publisher_entity_id: Option<[u8; 4]>,
    ) {
        if coherent_sn.is_some() || group_sn.is_some() {
            self.on_data_coherent(
                topic,
                writer_guid,
                seq,
                data,
                version,
                coherent_sn,
                group_sn,
                publisher_entity_id,
            );
        } else {
            self.on_data_with_writer(topic, writer_guid, seq, data, version);
        }
    }

    /// The entity id of the reader this subscriber delivers to, when it has
    /// one. A DATA, DATA_FRAG, HEARTBEAT or GAP whose readerId names a reader
    /// is handed only to the subscriber reporting that id (RTPS v2.5
    /// Sec.8.3.8.2, 8.3.8.3, 8.3.8.4, 8.3.8.6); one addressed to
    /// ENTITYID_UNKNOWN reaches every subscriber of the topic. The default,
    /// `None`, names no reader, so it receives only the latter: a writer that
    /// matched readers of this participant addresses its samples to them.
    fn reader_entity_id(&self) -> Option<[u8; 4]> {
        None
    }

    /// Notification that a HEARTBEAT was observed from the given writer
    /// advertising `first_seq` as its oldest available sample (RTPS v2.5
    /// sec. 8.3.8.6). The default implementation is a no-op; subscribers that
    /// need to seed late-joiner ordering state for non-Volatile durability
    /// override this hook. Called from the discovery control thread, NOT
    /// the data-routing thread.
    fn on_writer_heartbeat(&self, _writer_guid: [u8; 16], _first_seq: u64) {
        // Volatile readers ignore HB seeding -- the reorder gate is disabled.
    }

    /// [`on_writer_heartbeat`](Self::on_writer_heartbeat) with the
    /// HEARTBEAT's lastSN (RTPS v2.5 Sec.8.3.8.6): the highest sequence the
    /// writer has written. The default implementation ignores it.
    fn on_writer_heartbeat_range(&self, writer_guid: [u8; 16], first_seq: u64, last_seq: u64) {
        let _ = last_seq;
        self.on_writer_heartbeat(writer_guid, first_seq);
    }

    /// Notification that a HEARTBEAT with the Liveliness flag set was
    /// received from `writer_guid` (RTPS v2.5 Sec.8.3.7.5): a
    /// MANUAL_BY_TOPIC writer asserted its liveliness without writing new
    /// data. The default implementation is a no-op; a subscriber with a
    /// liveliness watch (`ReaderLiveliness`) overrides it.
    fn on_writer_heartbeat_liveliness(&self, _writer_guid: [u8; 16]) {
        // @audit-ok: intentional no-op default, like `on_writer_gap` below
        // and `on_writer_heartbeat` above: a subscriber with nothing to
        // renew (no liveliness watch) has nothing to do with this flag.
    }

    /// Notification that a GAP submessage was received from `writer_guid`
    /// declaring the contiguous range `[gap_start, gap_list_base)` and the
    /// additional sequences in `gap_list_seqs` as irrelevant (RTPS v2.5
    /// sec 8.3.8.4). Subscribers with non-Volatile durability override
    /// this to advance their late-joiner reorder gate past the
    /// declared-lost sequences so buffered live samples are released.
    /// Default implementation is a no-op (Volatile readers do not buffer).
    fn on_writer_gap(
        &self,
        _writer_guid: [u8; 16],
        _gap_start: u64,
        _gap_list_base: u64,
        _gap_list_seqs: Vec<u64>,
    ) {
        // Volatile readers do not buffer -- nothing to unblock.
    }

    /// [`on_writer_gap`](Self::on_writer_gap) for a GAP that carries a
    /// filteredCount (RTPS v2.5 Sec.8.3.8.4): `filtered_count` of the
    /// changes it declares are still in the writer's history but filtered
    /// for this reader. Not samples lost; not part of the reader's coherent
    /// sets (Sec.8.7.6). The default implementation ignores the count.
    fn on_writer_gap_filtered(
        &self,
        writer_guid: [u8; 16],
        gap_start: u64,
        gap_list_base: u64,
        gap_list_seqs: Vec<u64>,
        filtered_count: u64,
    ) {
        let _ = filtered_count;
        self.on_writer_gap(writer_guid, gap_start, gap_list_base, gap_list_seqs);
    }

    /// Notification that a DATA submessage consumed a writer sequence number
    /// but carried no application sample. Key-only instance registration is
    /// one such shape. Reliable readers use this hook to credit reception and
    /// advance their ordering frontier without invoking [`Self::on_data`].
    fn on_writer_non_data(&self, _writer_guid: [u8; 16], _seq: u64) {
        // Stateless subscribers have no reliable frontier to advance.
    }

    /// Notification that a DATA submessage with neither serialized payload
    /// nor key (D=0, K=0) and none of the end-of-set or lifecycle forms
    /// consumed writer sequence `seq`: a change of no coherent set, which
    /// ends the set its writer has open (RTPS v2.5 Sec.8.7.6).
    ///
    /// Default implementation: [`Self::on_writer_non_data`].
    fn on_change_without_sample(&self, writer_guid: [u8; 16], seq: u64) {
        self.on_writer_non_data(writer_guid, seq);
    }

    /// Notification that the remote writer's SEDP announcement has just been
    /// processed into the discovery FSM, so per-writer QoS (OWNERSHIP kind,
    /// PARTITION, ...) is now resolvable. Subscribers that DEFER samples
    /// while a writer's QoS is still unknown (a burst racing its own SEDP,
    /// e.g. a TRANSIENT_LOCAL late-joiner history push) override this hook
    /// to re-run their RxO verdict and either flush or discard the deferred
    /// samples. Called from the discovery/SEDP thread, NOT the data-routing
    /// thread. Default implementation is a no-op.
    fn on_writer_qos_resolved(&self, _writer_guid: [u8; 16]) {
        // Default: no deferred-samples machinery -- nothing to re-evaluate.
    }

    /// Notification that DATA of `writer_guid` addressed to every reader of
    /// this topic (readerId ENTITYID_UNKNOWN), the lowest at `seq` (from
    /// its coherent set's start for a set's member), was dropped
    /// unacknowledged before discovery bound the writer to this topic. A
    /// writer that has discovered this reader sends it DATA before this
    /// participant has discovered the writer (discovery is asymmetric): the
    /// writer sends it again, and a reliable reader owes it. Called before
    /// any DATA of the writer is routed to this topic by its binding, or,
    /// when the drop raced the binding, after. `dropped_at` is a tick of
    /// `join_clock_tick` no later than the drop: a reader created after it
    /// was owed nothing by the drop. Nothing authenticates the DATA dropped.
    /// Default implementation is a no-op.
    fn on_dropped_before_discovery(&self, _writer_guid: [u8; 16], _seq: u64, _dropped_at: u64) {
        // Default: no reliable join point to keep.
    }

    /// Notification that an End-of-Coherent-Set DATA submessage was
    /// observed from `writer_guid` closing the writer-scoped coherent
    /// set up to `coherent_sn` (mandatory) and the Publisher Group
    /// Sequence Number `group_sn` (Some when access_scope is GROUP).
    /// `publisher_entity_id` is the EntityId of the owning Publisher
    /// extracted from `PID_GROUP_ENTITY_ID` (RTPS v2.5 Table 9.18).
    /// Per RTPS v2.5 sec. 8.7.5.
    ///
    /// Implementations under GROUP-scope coherent_access buffer
    /// per-(publisher, gsn) samples and flush atomically on this hook
    /// once every writer in the same Publisher with buffered samples
    /// has been observed in `closers`. Default implementation: no-op
    /// for subscribers not configured with coherent_access.
    fn on_ecs(
        &self,
        _topic: &str,
        _writer_guid: [u8; 16],
        _ecs_seq: u64,
        _coherent_sn: u64,
        _group_sn: Option<u64>,
        _publisher_entity_id: Option<[u8; 4]>,
    ) {
        // Default: ignore ECS markers (Volatile / non-coherent readers).
    }

    /// A change of a GROUP coherent set of a writer of the spec GROUP
    /// dialect (RTPS v2.5 Sec.8.7.5, Sec.8.7.6): its set, Publisher, writer
    /// set (PID_WRITER_GROUP_INFO, D5), group sequence number
    /// (PID_GROUP_SEQ_NUM) and, for the writer's end of the set, the first
    /// SN of its part (Table 9.23, D6). Delivered before the change itself.
    /// Default: ignored.
    fn on_group_change(&self, _writer_guid: [u8; 16], _change: GroupChange) {
        // Default: a subscriber with no GROUP sets has nothing to check.
    }

    /// The GroupInfo of a HEARTBEAT of a writer of the spec GROUP dialect
    /// (RTPS v2.5 Sec.8.3.8.6, Sec.9.4.5.7, D15): the Publisher's last GSN,
    /// and the GSNs of the HEARTBEAT's firstSN and lastSN. Default:
    /// ignored.
    fn on_writer_group_heartbeat(
        &self,
        _writer_guid: [u8; 16],
        _current_gsn: u64,
        _first_gsn: u64,
        _last_gsn: u64,
    ) {
    }

    /// Publisher ordering proof with the optional writer-set digests,
    /// delivered after the writer's receive gate processes the heartbeat floor.
    fn on_writer_group_heartbeat_roster(
        &self,
        _writer_guid: [u8; 16],
        _info: [u64; 3],
        _writer_set: Option<([u8; 4], [u8; 4])>,
    ) {
        // Subscribers without ordered GROUP presentation need no roster proof.
    }

    /// A validated GROUP GAP interval used by Publisher ordering.
    fn on_writer_group_gap(&self, _writer_guid: [u8; 16], _start_gsn: u64, _end_gsn: u64) {
        // Subscribers without ordered GROUP presentation need no GAP proof.
    }

    /// Notification that a normal coherent DATA sample (`D=1`) carried
    /// `PID_END_COHERENT_SET` (0x8022) from `writer_guid`, marking it the
    /// LAST sample of its set. This is an explicit set-completion form
    /// (riding the closing PID on a real data sample) instead of a
    /// dedicated ECS marker submessage per RTPS v2.5 Sec.8.7.5.
    /// TOPIC/INSTANCE-scope `coherent_access` subscribers commit the
    /// writer's buffered set atomically on this hook instead of waiting for
    /// the next set to begin. `group_sn` and `publisher_entity_id` mirror the
    /// sample's coherent metadata. `end_sn` is the closing set's first SN
    /// (`PID_END_COHERENT_SET` value) so the commit can be scoped to exactly
    /// that set, and `end_count` the set's expected sample count
    /// (`PID_END_COHERENT_SET_SAMPLE_COUNT` 0x8024) so a commit can be
    /// deferred when the END overtook some of its own DATA on the wire --
    /// coherent_access is all-or-nothing per DDS v1.4 sec. 2.2.3.6. Also called,
    /// by default, for a standalone END marker (see
    /// `on_coherent_end_marker`). Default implementation: no-op for
    /// subscribers not configured with coherent_access.
    fn on_coherent_end(
        &self,
        _topic: &str,
        _writer_guid: [u8; 16],
        _group_sn: Option<u64>,
        _publisher_entity_id: Option<[u8; 4]>,
        _end_sn: Option<u64>,
        _end_count: Option<u32>,
    ) {
        // Default: ignore explicit coherent-set-completion (non-coherent readers).
    }

    /// Called for a standalone END marker: a DATA without a sample carrying
    /// `PID_END_COHERENT_SET` (RTPS v2.5 Sec.8.7.5). Unlike an END riding a
    /// sample, the marker is a change of its own, and `marker_seq` is its
    /// sequence number, which a reliable reader acknowledges whatever it
    /// does with the marker (Sec.8.4.12); it is at least 1. `end_sn` is the
    /// closing set's first SN, which a marker always carries; the other
    /// arguments are those of `on_coherent_end`.
    ///
    /// Default implementation: `on_coherent_end`, dropping `marker_seq`. A
    /// subscriber that acknowledges what it receives must override this
    /// method and acknowledge `marker_seq`: left unacknowledged, the writer
    /// repairs the marker for as long as its history holds it.
    #[allow(clippy::too_many_arguments)]
    fn on_coherent_end_marker(
        &self,
        topic: &str,
        writer_guid: [u8; 16],
        group_sn: Option<u64>,
        publisher_entity_id: Option<[u8; 4]>,
        end_sn: u64,
        end_count: Option<u32>,
        marker_seq: u64,
    ) {
        let _ = marker_seq;
        self.on_coherent_end(
            topic,
            writer_guid,
            group_sn,
            publisher_entity_id,
            Some(end_sn),
            end_count,
        );
    }

    /// A key-only change with no lifecycle flag still consumes a sequence.
    /// Payload-protected readers authenticate its serialized key first.
    fn on_key_only(&self, writer: [u8; 16], seq: u64, _payload: Option<&[u8]>) {
        self.on_writer_non_data(writer, seq);
    }

    /// Resolve lifecycle identity before crediting its sequence. A protected
    /// reader can refuse an unauthenticated payload without a hash fallback.
    fn resolve_lifecycle_key(
        &self,
        _writer: Option<[u8; 16]>,
        _seq: u64,
        payload: Option<&[u8]>,
        fallback: Option<[u8; 16]>,
    ) -> Option<[u8; 16]> {
        payload
            .and_then(|p| self.instance_of_key_payload(p))
            .or(fallback)
    }

    /// The instance key (the KeyHash this subscriber names instances by) of
    /// the serialized key of a dispose or unregister: `payload` is the
    /// serializedPayload of a DATA with K=1, its encapsulation header
    /// included. `None` when this subscriber cannot read it; the change is
    /// then named by its PID_KEY_HASH ([`LifecycleKey`]).
    ///
    /// Default implementation: `None`.
    fn instance_of_key_payload(&self, payload: &[u8]) -> Option<[u8; 16]> {
        let _ = payload;
        None
    }

    /// Called when a dispose or unregister lifecycle change is received.
    ///
    /// # Arguments
    /// - `topic`: Topic name
    /// - `seq`: RTPS writer sequence number
    /// - `key_hash`: 16-byte instance key hash from PID_KEY_HASH
    /// - `kind`: Dispose or unregister
    ///
    /// Default implementation: no-op (silently ignores lifecycle changes).
    fn on_dispose(&self, _topic: &str, _seq: u64, _key_hash: [u8; 16], _kind: DisposeKind) {
        // Default: silently ignore lifecycle changes
    }

    /// Called when a dispose or unregister lifecycle change is received
    /// from a known DataWriter: `writer_guid` is the writer that sent it
    /// (the RTPS header's prefix and the DATA's writerId), `seq` its
    /// writerSN.
    ///
    /// An unregister is a fact about ONE writer: it no longer writes the
    /// instance, and the instance loses its writers only when no other
    /// DataWriter is writing it (DDS v1.4 Sec.2.2.2.4.2.7). A subscriber
    /// that tracks which writers hold each instance needs the sender to
    /// apply that rule.
    ///
    /// Default implementation: `on_dispose`, dropping `writer_guid`.
    fn on_dispose_from_writer(
        &self,
        topic: &str,
        writer_guid: [u8; 16],
        seq: u64,
        key_hash: [u8; 16],
        kind: DisposeKind,
    ) {
        let _ = writer_guid;
        self.on_dispose(topic, seq, key_hash, kind);
    }

    /// A dispose or unregister (a key-only DATA, RTPS v2.5 Sec.9.4.5.3)
    /// that carries coherent-set tags (`PID_COHERENT_SET`, and under GROUP
    /// scope the group set number and `PID_GROUP_ENTITY_ID`): a change of
    /// that coherent set (Sec.8.7.6: every change of the Publisher between
    /// begin and end_coherent_changes). The default implementation takes it
    /// as an untagged lifecycle change: `on_dispose_from_writer`, then
    /// `on_writer_non_data`.
    ///
    /// It is also reached for an untagged key-only DATA, both tags `None`:
    /// the receiver orders a network lifecycle change against its history
    /// and takes it as the change of no set it is.
    #[allow(clippy::too_many_arguments)]
    fn on_lifecycle_coherent(
        &self,
        topic: &str,
        writer_guid: [u8; 16],
        seq: u64,
        key_hash: [u8; 16],
        kind: DisposeKind,
        coherent_sn: Option<u64>,
        group_sn: Option<u64>,
        publisher_entity_id: Option<[u8; 4]>,
    ) {
        let _ = (coherent_sn, group_sn, publisher_entity_id);
        self.on_dispose_from_writer(topic, writer_guid, seq, key_hash, kind);
        self.on_writer_non_data(writer_guid, seq);
    }

    /// Called when a remote DataWriter's endpoint is disposed (SEDP DATA(d)
    /// on `ENTITYID_BUILTIN_PUBLICATIONS_WRITER`). Implementations that
    /// track per-(writer, instance) state should iterate the instances
    /// they have ever received from `writer_guid` on `topic` and synthesize
    /// one `on_dispose` per such instance, so the application sees the
    /// per-instance `NOT_ALIVE_*` transition required by DDS v1.4 sec. 2.2.4.2.2.
    ///
    /// Default implementation: no-op (subscribers that don't track per-writer
    /// instance state silently ignore writer-endpoint disposes).
    fn on_writer_dispose(&self, _topic: &str, _writer_guid: [u8; 16], _kind: DisposeKind) {
        // Default: silently ignore writer-endpoint disposals.
    }

    /// [`on_writer_dispose`](Self::on_writer_dispose), with why the writer
    /// left. Default: `on_writer_dispose`, which takes every departure for
    /// one the writer did not announce ([`WriterDeparture::Unheard`]).
    fn on_writer_departure(
        &self,
        topic: &str,
        writer_guid: [u8; 16],
        kind: DisposeKind,
        cause: WriterDeparture,
    ) {
        let _ = cause;
        self.on_writer_dispose(topic, writer_guid, kind);
    }

    /// Returns the topic name this subscriber is registered for
    fn topic_name(&self) -> &str;
}

/// Callback-based subscriber wrapper
///
/// Wraps a closure/function as a Subscriber implementation.
/// Useful for simple callbacks without creating custom types.
///
/// # Examples
/// ```no_run
/// use hdds::engine::CallbackSubscriber;
/// use std::sync::Arc;
///
/// let subscriber = Arc::new(CallbackSubscriber::new(
///     "sensor/temperature".to_string(),
///     |topic, seq, data| {
///         println!("Callback: seq {} ({} bytes) on {}", seq, data.len(), topic);
///     },
/// ));
/// ```
pub struct CallbackSubscriber<F>
where
    F: Fn(&str, u64, &[u8]) + Send + Sync,
{
    topic: String,
    callback: F,
}

impl<F> CallbackSubscriber<F>
where
    F: Fn(&str, u64, &[u8]) + Send + Sync,
{
    /// Create new callback subscriber
    ///
    /// # Arguments
    /// - `topic`: Topic name to subscribe to
    /// - `callback`: Function called on data reception (topic, seq, data)
    ///
    /// # Examples
    /// ```no_run
    /// use hdds::engine::CallbackSubscriber;
    ///
    /// let sub = CallbackSubscriber::new(
    ///     "my_topic".to_string(),
    ///     |topic, seq, data| {
    ///         println!("Data seq {} on {}: {:?}", seq, topic, data);
    ///     },
    /// );
    /// ```
    pub fn new(topic: String, callback: F) -> Self {
        Self { topic, callback }
    }
}

impl<F> Subscriber for CallbackSubscriber<F>
where
    F: Fn(&str, u64, &[u8]) + Send + Sync,
{
    fn on_data(&self, topic: &str, seq: u64, data: &[u8]) {
        (self.callback)(topic, seq, data);
    }

    fn topic_name(&self) -> &str {
        &self.topic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_callback_subscriber_creation() {
        let sub = CallbackSubscriber::new("test_topic".to_string(), |_topic, _seq, _data| {
            // Callback body
        });

        assert_eq!(sub.topic_name(), "test_topic");
    }

    #[test]
    fn test_callback_subscriber_on_data_invoked() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        let sub = CallbackSubscriber::new("test_topic".to_string(), move |topic, seq, data| {
            assert_eq!(topic, "test_topic");
            assert_eq!(seq, 42);
            assert_eq!(data.len(), 10);
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        let test_data = vec![0u8; 10];
        sub.on_data("test_topic", 42, &test_data);

        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_callback_subscriber_multiple_invocations() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        let sub = Arc::new(CallbackSubscriber::new(
            "test_topic".to_string(),
            move |_topic, _seq, _data| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            },
        ));

        let test_data = vec![1, 2, 3];

        // Simulate multiple deliveries
        sub.on_data("test_topic", 1, &test_data);
        sub.on_data("test_topic", 2, &test_data);
        sub.on_data("test_topic", 3, &test_data);

        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }
}
