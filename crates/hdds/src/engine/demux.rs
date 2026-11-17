// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Topic-based demultiplexing and fanout
//!
//! Manages topic registration, subscriber lists, and data delivery.
//! Provides GUID->topic mapping for cross-vendor interoperability.

use crate::core::discovery::fragment_buffer::SampleAudience;
use crate::core::discovery::multicast::control_types::ENTITYID_UNKNOWN;
use crate::core::discovery::multicast::Origin;
use crate::engine::subscriber::Subscriber;
use crate::engine::subscriber::{DisposeKind, LifecycleKey, WriterDeparture};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak};

// ============================================================================
// Handler Traits
// ============================================================================

/// The connection a message arrived on, for a transport with no datagram
/// address to answer at (TCP, QUIC): an answer goes back on it.
///
/// RTPS 2.5 8.3.4: the reply locator starts as the source of the message
/// "assuming the Transport used supports this". A connection is that
/// source; answering anywhere else (the UDP multicast group, say) reaches
/// the peer only by accident, if at all.
pub trait StreamReply {
    /// Send `message`, a whole RTPS message, back on the connection.
    fn send_reply(&self, message: &[u8]) -> std::io::Result<()>;
}

/// Handler trait for Heartbeat messages (Reliable QoS control)
///
/// Implemented by DataReader to receive periodic liveness messages from writers.
pub trait HeartbeatHandler: Send + Sync {
    /// Called when a Heartbeat message is received.
    ///
    /// # Arguments
    /// - `heartbeat_bytes`: Raw Heartbeat message payload (CDR2 encoded).
    /// - `origin`: where the HEARTBEAT came from, and where a reply may go.
    ///   `None` keeps its existing meaning: the transport has no address at
    ///   all (TCP/QUIC, intra), so an answer goes to multicast. RTPS 2.5
    ///   8.3.4 / 8.3.8.10: `Some(origin)` with `origin.reply() == None` means
    ///   a real address exists but names only a forwarder (behind an
    ///   INFO_SRC) -- a handler must resolve the writer by GUID prefix
    ///   instead, and send nothing if it cannot, never fall back to
    ///   multicast or to the forwarder's address.
    fn on_heartbeat(&self, heartbeat_bytes: &[u8], origin: Option<Origin>);

    /// [`on_heartbeat`](Self::on_heartbeat) for a HEARTBEAT that arrived
    /// on a connection (TCP, QUIC) whose source is its sender: the answer
    /// goes back on `connection`. The default answers as
    /// `on_heartbeat(heartbeat_bytes, None)` does.
    fn on_heartbeat_over_stream(&self, heartbeat_bytes: &[u8], connection: &dyn StreamReply) {
        let _ = connection;
        self.on_heartbeat(heartbeat_bytes, None);
    }
}

/// Opaque id for one `register_heartbeat_handler` registration, returned by
/// the registry and used only to remove that exact entry later
/// (`unregister_heartbeat_handler`). Deliberately not `Arc` pointer
/// identity: two registrations can wrap distinct `Arc`s that happen to
/// share a vtable/data layout, and pointer comparison of trait objects is
/// not a reliable identity test. A monotonic counter is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatHandlerId(u64);

/// Opaque id for one `register_nack_handler` or `register_nack_frag_handler`
/// registration, used only to remove that exact entry later
/// (`unregister_nack_handlers`), for the reason `HeartbeatHandlerId` gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NackHandlerId(u64);

/// Handler trait for NACK messages (Reliable QoS control)
///
/// Implemented by DataWriter to receive retransmission requests from readers.
pub trait NackHandler: Send + Sync {
    /// Called when a NACK message is received.
    ///
    /// # Arguments
    /// - `nack_bytes`: Raw NACK message payload (RTPS or CDR2 encoded)
    /// - `reader_guid`: Optional 16-byte reader GUID of the NACKing reader.
    ///   When `Some`, the handler SHOULD retransmit unicast to that reader's
    ///   discovered locator.  When `None` the handler falls back to multicast.
    fn on_nack(&self, nack_bytes: &[u8], reader_guid: Option<[u8; 16]>);

    /// Called with ONE ACKNACK already parsed, as the UDP control path
    /// receives it: which writer it names, which reader sent it, its
    /// `bitmapBase` (everything below is acknowledged) and its holes. Pure
    /// acknowledgements (no hole) arrive here too.
    ///
    /// The default re-encodes the holes for [`on_nack`](Self::on_nack),
    /// which is what that path did before this method existed, so an
    /// implementation that only reads `on_nack` keeps its behaviour.
    fn on_acknack(
        &self,
        reader_guid: [u8; 16],
        acknack: &crate::core::discovery::multicast::control_types::AckNackInfo,
    ) {
        if acknack.missing_ranges.is_empty() {
            return;
        }
        let bytes = crate::reliability::NackMsg::from_ranges(acknack.missing_ranges.clone())
            .encode_cdr2_le();
        self.on_nack(&bytes, Some(reader_guid));
    }
}

/// Handler trait for NACK_FRAG messages (Fragment retransmission)
///
/// Implemented by DataWriter to receive fragment retransmission requests from readers.
pub trait NackFragHandler: Send + Sync {
    /// Called when a NACK_FRAG message is received.
    ///
    /// # Arguments
    /// - `writer_entity_id`: Entity ID of the target writer
    /// - `writer_sn`: Sequence number of the fragmented message
    /// - `missing_fragments`: List of missing fragment numbers (1-based)
    /// - `reader_guid`: Optional 16-byte reader GUID of the NACKing reader.
    ///   When `Some`, the handler SHOULD retransmit unicast to that reader's
    ///   discovered locator.  When `None` the handler falls back to multicast.
    fn on_nack_frag(
        &self,
        writer_entity_id: &[u8; 4],
        writer_sn: u64,
        missing_fragments: &[u32],
        reader_guid: Option<[u8; 16]>,
    );
}

// ============================================================================
// Topic
// ============================================================================

/// Topic metadata and subscriber list.
///
/// Represents a single topic with its registered subscribers and ensures panic
/// isolation when delivering data.
#[derive(Clone)]
struct TopicSubscriber {
    subscriber: Arc<dyn Subscriber>,
    ordered_group: bool,
}

impl std::ops::Deref for TopicSubscriber {
    type Target = Arc<dyn Subscriber>;

    fn deref(&self) -> &Self::Target {
        &self.subscriber
    }
}

#[derive(Clone)]
pub struct Topic {
    name: String,
    pub(crate) type_name: Option<String>,
    subscribers: Vec<TopicSubscriber>,
    ordered_group: bool,
}

impl Topic {
    #[must_use]
    pub fn new(name: String, type_name: Option<String>) -> Self {
        Self {
            name,
            type_name,
            subscribers: Vec::new(),
            ordered_group: false,
        }
    }

    #[must_use]
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn type_name(&self) -> Option<&str> {
        self.type_name.as_deref()
    }

    pub fn add_subscriber(&mut self, sub: Arc<dyn Subscriber>) -> bool {
        let ordered_group = sub.requires_ordered_group();
        self.add_subscriber_with_interest(sub, ordered_group)
    }

    fn add_subscriber_with_interest(
        &mut self,
        sub: Arc<dyn Subscriber>,
        ordered_group: bool,
    ) -> bool {
        let sub_ptr = Arc::as_ptr(&sub) as *const () as usize;
        if self
            .subscribers
            .iter()
            .any(|existing| Arc::as_ptr(existing) as *const () as usize == sub_ptr)
        {
            return false;
        }

        self.ordered_group |= ordered_group;
        self.subscribers.push(TopicSubscriber {
            subscriber: sub,
            ordered_group,
        });
        true
    }

    pub fn remove_subscriber(&mut self, topic_name: &str) -> bool {
        if let Some(index) = self
            .subscribers
            .iter()
            .position(|s| s.topic_name() == topic_name)
        {
            self.subscribers.remove(index);
            self.refresh_ordered_group();
            true
        } else {
            false
        }
    }

    fn remove_subscriber_by_ptr(&mut self, subscriber_ptr: usize) -> bool {
        if let Some(index) = self
            .subscribers
            .iter()
            .position(|sub| Arc::as_ptr(sub) as *const () as usize == subscriber_ptr)
        {
            self.subscribers.remove(index);
            self.refresh_ordered_group();
            true
        } else {
            false
        }
    }

    #[must_use]
    #[inline]
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    /// Interest of the registered topic snapshot, retained by directed views.
    #[inline]
    pub(crate) fn requires_ordered_group(&self) -> bool {
        self.ordered_group
    }

    fn refresh_ordered_group(&mut self) {
        self.ordered_group = self
            .subscribers
            .iter()
            .any(|subscriber| subscriber.ordered_group);
    }

    /// Deliver payload to all subscribers with panic isolation.
    ///
    /// Returns number of delivery errors (panic count).
    ///
    /// # Performance
    /// HOT PATH: Called for every DATA packet delivery.
    #[inline]
    pub fn deliver(&self, seq: u64, data: &[u8], version: crate::dds::CdrVersion) -> usize {
        let mut errors = 0;

        for sub in &self.subscribers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_data_with_version(&self.name, seq, data, version);
            }));

            if result.is_err() {
                errors += 1;
                log::debug!(
                    "[demux] Subscriber '{}' panicked during delivery",
                    sub.topic_name()
                );
            }
        }

        errors
    }

    /// Deliver payload along with the originating writer GUID.
    ///
    /// Same contract as [`Self::deliver`] but routes through the
    /// `Subscriber::on_data_with_writer` overload so subscribers that need
    /// per-writer state (e.g. TRANSIENT_LOCAL late-joiner reordering) can
    /// see which writer the sample came from.
    #[inline]
    pub fn deliver_with_writer(
        &self,
        writer_guid: [u8; 16],
        seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
    ) -> usize {
        let mut errors = 0;

        for sub in &self.subscribers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_data_with_writer(&self.name, writer_guid, seq, data, version);
            }));

            if result.is_err() {
                errors += 1;
                log::debug!(
                    "[demux] Subscriber '{}' panicked during writer-tagged delivery",
                    sub.topic_name()
                );
            }
        }

        errors
    }

    /// Coherent-aware delivery: same as [`Self::deliver_with_writer`] but
    /// also forwards `coherent_sn` (writer-scoped), `group_sn` (Publisher
    /// GSN), and `publisher_entity_id` (owning Publisher EntityId per
    /// RTPS v2.5 sec. 9.3.2.1) extracted from inline QoS so coherent_access
    /// subscribers can buffer per-(publisher, gsn) and flush atomically
    /// on ECS arrival per RTPS v2.5 sec. 8.7.5 and DDS v1.4 sec. 2.2.3.6.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn deliver_with_writer_coherent(
        &self,
        writer_guid: [u8; 16],
        seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
        coherent_sn: Option<u64>,
        group_sn: Option<u64>,
        publisher_entity_id: Option<[u8; 4]>,
    ) -> usize {
        let mut errors = 0;
        for sub in &self.subscribers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_data_coherent(
                    &self.name,
                    writer_guid,
                    seq,
                    data,
                    version,
                    coherent_sn,
                    group_sn,
                    publisher_entity_id,
                );
            }));
            if result.is_err() {
                errors += 1;
                log::debug!(
                    "[demux] Subscriber '{}' panicked during coherent delivery",
                    sub.topic_name()
                );
            }
        }
        errors
    }

    /// Deliver a DATA value with its optional wire KeyHash and set tags.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn deliver_keyed(
        &self,
        writer_guid: [u8; 16],
        seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
        key_hash: Option<[u8; 16]>,
        coherent_sn: Option<u64>,
        group_sn: Option<u64>,
        publisher_entity_id: Option<[u8; 4]>,
    ) -> usize {
        let mut errors = 0;
        for sub in &self.subscribers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_data_keyed(
                    &self.name,
                    writer_guid,
                    seq,
                    data,
                    version,
                    key_hash,
                    coherent_sn,
                    group_sn,
                    publisher_entity_id,
                );
            }));
            if result.is_err() {
                errors += 1;
                log::debug!(
                    "[demux] Subscriber '{}' panicked during keyed delivery",
                    sub.topic_name()
                );
            }
        }
        errors
    }

    /// Notify all subscribers of this topic that a HEARTBEAT was received
    /// from the given writer advertising the given `first_seq`. Lets
    /// non-Volatile readers seed their late-joiner reordering buffer
    /// (DDS-RTPS v2.5 sec. 8.3.8.6 `firstSN`).
    #[inline]
    pub fn deliver_writer_heartbeat(&self, writer_guid: [u8; 16], first_seq: u64) -> usize {
        self.deliver_writer_heartbeat_to(writer_guid, first_seq, None, ENTITYID_UNKNOWN)
    }

    /// [`deliver_writer_heartbeat`](Self::deliver_writer_heartbeat) for the
    /// reader the HEARTBEAT's readerId names (ENTITYID_UNKNOWN: all), with
    /// its lastSN when known.
    pub(crate) fn deliver_writer_heartbeat_to(
        &self,
        writer_guid: [u8; 16],
        first_seq: u64,
        last_seq: Option<u64>,
        reader_entity_id: [u8; 4],
    ) -> usize {
        let mut errors = 0;
        for sub in self.subscribers_addressed(reader_entity_id) {
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match last_seq {
                    Some(last) => sub.on_writer_heartbeat_range(writer_guid, first_seq, last),
                    None => sub.on_writer_heartbeat(writer_guid, first_seq),
                }));
            if result.is_err() {
                errors += 1;
                log::debug!(
                    "[demux] Subscriber '{}' panicked during writer-heartbeat hook",
                    sub.topic_name()
                );
            }
        }
        errors
    }

    /// Notify all subscribers of this topic that a HEARTBEAT with the
    /// Liveliness flag set (RTPS v2.5 Sec.8.3.7.5) was received from
    /// `writer_guid`: a MANUAL_BY_TOPIC writer asserted without new data.
    /// Only the reader its matched-writer liveliness watches; a no-op for
    /// any other kind (`ReaderLiveliness::on_heartbeat_liveliness`).
    #[inline]
    pub fn deliver_writer_heartbeat_liveliness(&self, writer_guid: [u8; 16]) -> usize {
        let mut errors = 0;
        for sub in self.subscribers_addressed(ENTITYID_UNKNOWN) {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_writer_heartbeat_liveliness(writer_guid);
            }));
            if result.is_err() {
                errors += 1;
                log::debug!(
                    "[demux] Subscriber '{}' panicked during writer-heartbeat-liveliness hook",
                    sub.topic_name()
                );
            }
        }
        errors
    }

    /// Notify all subscribers of this topic that a GAP was received from
    /// `writer_guid` declaring the contiguous range `[gap_start,
    /// gap_list_base)` and the sequences in `gap_list_seqs` as irrelevant
    /// (RTPS v2.5 sec 8.3.8.4).  Non-Volatile readers advance their
    /// late-joiner reorder gate to release buffered live samples that were
    /// waiting for the now-declared-lost sequences.
    #[inline]
    pub fn deliver_writer_gap(
        &self,
        writer_guid: [u8; 16],
        gap_start: u64,
        gap_list_base: u64,
        gap_list_seqs: Vec<u64>,
    ) -> usize {
        self.deliver_writer_gap_to(
            writer_guid,
            gap_start,
            gap_list_base,
            gap_list_seqs,
            ENTITYID_UNKNOWN,
            None,
        )
    }

    /// [`deliver_writer_gap`](Self::deliver_writer_gap) for the reader the
    /// GAP's readerId names (ENTITYID_UNKNOWN: all). A GAP addressed to one
    /// reader states what that reader will not receive, not the others: a
    /// writer filtering content per reader sends exactly that.
    /// `filtered_count` is the GAP's filteredCount, when it carries one.
    pub(crate) fn deliver_writer_gap_to(
        &self,
        writer_guid: [u8; 16],
        gap_start: u64,
        gap_list_base: u64,
        gap_list_seqs: Vec<u64>,
        reader_entity_id: [u8; 4],
        filtered_count: Option<u64>,
    ) -> usize {
        let mut errors = 0;
        for sub in self.subscribers_addressed(reader_entity_id) {
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match filtered_count {
                    Some(count) => sub.on_writer_gap_filtered(
                        writer_guid,
                        gap_start,
                        gap_list_base,
                        gap_list_seqs.clone(),
                        count,
                    ),
                    None => sub.on_writer_gap(
                        writer_guid,
                        gap_start,
                        gap_list_base,
                        gap_list_seqs.clone(),
                    ),
                }));
            if result.is_err() {
                errors += 1;
                log::debug!(
                    "[demux] Subscriber '{}' panicked during writer-gap hook",
                    sub.topic_name()
                );
            }
        }
        errors
    }

    /// The reader entity id each subscriber reports, in registration order.
    #[cfg(test)]
    pub(crate) fn reader_entity_ids(&self) -> Vec<Option<[u8; 4]>> {
        self.subscribers
            .iter()
            .map(|sub| sub.reader_entity_id())
            .collect()
    }

    /// The subscribers a HEARTBEAT or GAP with this readerId addresses:
    /// every subscriber of the topic for ENTITYID_UNKNOWN, otherwise the
    /// one reporting that reader's id. A subscriber that names no reader is
    /// not the reader a readerId names.
    ///
    /// ENTITYID_UNKNOWN reaches every subscriber of the topic, matched with
    /// the writer or not; a subscriber decides for itself what a writer it
    /// does not track means to it.
    fn subscribers_addressed(
        &self,
        reader_entity_id: [u8; 4],
    ) -> impl Iterator<Item = &Arc<dyn Subscriber>> {
        self.subscribers
            .iter()
            .filter(move |sub| addresses(sub.as_ref(), reader_entity_id))
            .map(|sub| &sub.subscriber)
    }

    /// This topic narrowed to the subscribers a DATA sent to `reader`
    /// reaches (RTPS 2.5 8.3.8.2 readerId), by the rule of
    /// [`subscribers_addressed`](Self::subscribers_addressed): ENTITYID_UNKNOWN
    /// reaches every subscriber here now, a named reader only its own.
    ///
    /// A TRANSIENT_LOCAL writer replays its history to one late-joining
    /// reader under that reader's id; a VOLATILE reader of the same topic in
    /// the same participant shares the locator the replay is sent to, and
    /// must not receive samples written before it matched (DDS 1.4 2.2.3.4).
    #[must_use]
    pub(crate) fn addressed_to(mut self, reader: [u8; 4]) -> Self {
        self.subscribers
            .retain(|sub| addresses(sub.as_ref(), reader));
        self
    }

    /// This topic narrowed to the audience of a reassembled sample (see
    /// `SampleAudience`: the readers its fragments were sent to, taken when
    /// its first fragment arrived).
    #[must_use]
    pub(crate) fn for_audience(mut self, audience: &SampleAudience) -> Self {
        self.subscribers.retain(|sub| match sub.reader_entity_id() {
            Some(reader) => audience.names(reader),
            None => audience.reaches_unnamed(),
        });
        self
    }

    /// The ids of the subscribers here that name their reader.
    pub(crate) fn named_reader_ids(&self) -> Vec<[u8; 4]> {
        self.subscribers
            .iter()
            .filter_map(|sub| sub.reader_entity_id())
            .collect()
    }

    /// Select crypto framing from writer policy before interpreting any CDR:
    /// the strongest answer of the subscribers here (`PayloadFraming` order).
    pub(crate) fn payload_framing_for_writer(
        &self,
        writer: &[u8; 16],
    ) -> crate::engine::subscriber::PayloadFraming {
        use crate::engine::subscriber::PayloadFraming;
        let mut framing = PayloadFraming::Clear;
        for sub in self.subscribers.iter() {
            framing = framing.max(sub.payload_framing_for_writer(writer));
            if framing == PayloadFraming::Unresolved {
                break;
            }
        }
        framing
    }

    /// Deliver a key-only change before acknowledging its sequence.
    pub(crate) fn deliver_key_only(
        &self,
        writer: [u8; 16],
        seq: u64,
        payload: Option<&[u8]>,
    ) -> usize {
        self.subscribers
            .iter()
            .filter(|sub| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    sub.on_key_only(writer, seq, payload)
                }))
                .is_err()
            })
            .count()
    }

    /// Deliver a change without a sample (`Subscriber::on_change_without_sample`).
    #[inline]
    pub fn deliver_change_without_sample(&self, writer_guid: [u8; 16], seq: u64) -> usize {
        self.subscribers
            .iter()
            .filter(|sub| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    sub.on_change_without_sample(writer_guid, seq)
                }))
                .is_err()
            })
            .count()
    }

    /// Credit a writer sequence that carries no application sample.
    #[inline]
    pub fn deliver_writer_non_data(&self, writer_guid: [u8; 16], seq: u64) -> usize {
        let mut errors = 0;
        for sub in &self.subscribers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_writer_non_data(writer_guid, seq);
            }));
            if result.is_err() {
                errors += 1;
                log::debug!(
                    "[demux] Subscriber '{}' panicked during writer non-data hook",
                    sub.topic_name()
                );
            }
        }
        errors
    }

    /// Tell every subscriber of this topic that DATA of `writer_guid` from
    /// `seq` on was dropped before discovery bound the writer here, at
    /// `dropped_at` or later (`Subscriber::on_dropped_before_discovery`).
    fn deliver_dropped_before_discovery(&self, writer_guid: [u8; 16], seq: u64, dropped_at: u64) {
        for sub in &self.subscribers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_dropped_before_discovery(writer_guid, seq, dropped_at);
            }));
            if result.is_err() {
                log::debug!(
                    "[demux] Subscriber '{}' panicked during dropped-before-discovery hook",
                    sub.topic_name()
                );
            }
        }
    }

    /// Notify all subscribers of this topic that `writer_guid`'s SEDP has
    /// just been processed into the discovery FSM, making the writer's QoS
    /// resolvable. Subscribers holding samples deferred while the writer was
    /// unresolved (OWNERSHIP data-plane gate) re-run their verdict and flush
    /// or discard the deferred samples.
    #[inline]
    pub fn deliver_writer_qos_resolved(&self, writer_guid: [u8; 16]) -> usize {
        let mut errors = 0;
        for sub in &self.subscribers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_writer_qos_resolved(writer_guid);
            }));
            if result.is_err() {
                errors += 1;
                log::debug!(
                    "[demux] Subscriber '{}' panicked during writer-qos-resolved hook",
                    sub.topic_name()
                );
            }
        }
        errors
    }

    /// Deliver a dispose/unregister lifecycle notification to all subscribers.
    ///
    /// Returns number of delivery errors (panic count).
    ///
    /// # Arguments
    /// - `seq`: RTPS writer sequence number
    /// - `key_hash`: 16-byte instance key hash from PID_KEY_HASH
    /// - `kind`: Dispose, Unregister, or both
    #[inline]
    pub fn deliver_dispose(&self, seq: u64, key_hash: [u8; 16], kind: DisposeKind) -> usize {
        self.deliver_lifecycle(None, seq, LifecycleKey::hash(key_hash), kind)
    }

    /// A dispose or unregister of `writer_guid` (when known), to every
    /// subscriber of the topic, each naming the instance as
    /// [`LifecycleKey::for_subscriber`] says: a subscriber for which it names
    /// none is skipped.
    ///
    /// Returns number of delivery errors (panic count).
    pub(crate) fn deliver_lifecycle(
        &self,
        writer_guid: Option<[u8; 16]>,
        seq: u64,
        key: LifecycleKey<'_>,
        kind: DisposeKind,
    ) -> usize {
        self.deliver_lifecycle_counted(writer_guid, seq, key, kind)
            .0
    }

    /// [`deliver_lifecycle`](Self::deliver_lifecycle), returning the number
    /// of delivery errors (panic count) and the number of subscribers the
    /// change named no instance for (skipped).
    pub(crate) fn deliver_lifecycle_counted(
        &self,
        writer_guid: Option<[u8; 16]>,
        seq: u64,
        key: LifecycleKey<'_>,
        kind: DisposeKind,
    ) -> (usize, usize) {
        let mut errors = 0;
        let mut unnamed = 0;

        for sub in &self.subscribers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let Some(key_hash) = key.for_subscriber(sub.as_ref(), writer_guid, seq) else {
                    // The change still consumes a sequence when unprotected.
                    // Protected readers authenticate it in on_key_only first.
                    if let Some(guid) = writer_guid {
                        sub.on_key_only(guid, seq, key.serialized_key);
                    }
                    unnamed += 1;
                    return;
                };
                match writer_guid {
                    Some(guid) => {
                        sub.on_dispose_from_writer(&self.name, guid, seq, key_hash, kind);
                        sub.on_writer_non_data(guid, seq);
                    }
                    None => sub.on_dispose(&self.name, seq, key_hash, kind),
                }
            }));

            if result.is_err() {
                errors += 1;
                log::debug!(
                    "[demux] Subscriber '{}' panicked during dispose delivery",
                    sub.topic_name()
                );
            }
        }

        (errors, unnamed)
    }

    /// A dispose or unregister tagged as a member of a coherent set
    /// (`Subscriber::on_lifecycle_coherent`), to every subscriber of the
    /// topic, named as [`deliver_lifecycle`](Self::deliver_lifecycle) names
    /// it. Returns the delivery errors (panic count) and the number of
    /// subscribers it named no instance for.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn deliver_lifecycle_coherent(
        &self,
        writer_guid: [u8; 16],
        seq: u64,
        key: LifecycleKey<'_>,
        kind: DisposeKind,
        coherent_sn: Option<u64>,
        group_sn: Option<u64>,
        publisher_entity_id: Option<[u8; 4]>,
    ) -> (usize, usize) {
        let mut errors = 0;
        let mut unnamed = 0;
        for sub in &self.subscribers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let Some(key_hash) = key.for_subscriber(sub.as_ref(), Some(writer_guid), seq)
                else {
                    unnamed += 1;
                    if coherent_sn.is_none() && group_sn.is_none() {
                        // A missing instance can also mean authentication
                        // failed. Only the key-only hook may credit it after
                        // checking the protected payload (DDS-Security 1.1
                        // Sec.8.5.1.9.4, 9.5.3.3).
                        sub.on_key_only(writer_guid, seq, key.serialized_key);
                    }
                    return;
                };
                sub.on_lifecycle_coherent(
                    &self.name,
                    writer_guid,
                    seq,
                    key_hash,
                    kind,
                    coherent_sn,
                    group_sn,
                    publisher_entity_id,
                );
            }));
            if result.is_err() {
                errors += 1;
                log::debug!(
                    "[demux] Subscriber '{}' panicked during coherent lifecycle delivery",
                    sub.topic_name()
                );
            }
        }
        (errors, unnamed)
    }

    /// [`deliver_dispose`](Self::deliver_dispose) for a lifecycle change whose
    /// writer is known: `writer_guid` sent it, as its change `seq`.
    ///
    /// Returns number of delivery errors (panic count).
    pub fn deliver_dispose_from_writer(
        &self,
        writer_guid: [u8; 16],
        seq: u64,
        key_hash: [u8; 16],
        kind: DisposeKind,
    ) -> usize {
        self.deliver_lifecycle(Some(writer_guid), seq, LifecycleKey::hash(key_hash), kind)
    }

    /// Hand every subscriber of the topic a change of a GROUP set of the
    /// spec dialect (`Subscriber::on_group_change`). Returns how many
    /// subscribers panicked.
    pub(crate) fn deliver_group_change(
        &self,
        writer_guid: [u8; 16],
        change: crate::engine::subscriber::GroupChange,
    ) -> usize {
        let mut errors = 0;
        for sub in &self.subscribers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_group_change(writer_guid, change);
            }));
            if result.is_err() {
                errors += 1;
            }
        }
        errors
    }

    /// Hand the subscribers `reader_entity_id` addresses the GroupInfo of a
    /// HEARTBEAT of `writer_guid` (`Subscriber::on_writer_group_heartbeat`).
    pub(crate) fn deliver_writer_group_heartbeat_to(
        &self,
        writer_guid: [u8; 16],
        info: [u64; 3],
        reader_entity_id: [u8; 4],
    ) -> usize {
        let mut errors = 0;
        for sub in self.subscribers_addressed(reader_entity_id) {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_writer_group_heartbeat(writer_guid, info[0], info[1], info[2]);
            }));
            if result.is_err() {
                errors += 1;
            }
        }
        errors
    }

    pub(crate) fn deliver_writer_group_heartbeat_proof_to(
        &self,
        writer_guid: [u8; 16],
        info: [u64; 3],
        writer_set: Option<([u8; 4], [u8; 4])>,
        reader_entity_id: [u8; 4],
    ) -> usize {
        let mut errors = 0;
        for sub in self.subscribers_addressed(reader_entity_id) {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_writer_group_heartbeat_roster(writer_guid, info, writer_set);
            }));
            if result.is_err() {
                errors += 1;
            }
        }
        errors
    }

    pub(crate) fn deliver_writer_group_gap_to(
        &self,
        writer: [u8; 16],
        start: u64,
        end: u64,
        reader: [u8; 4],
    ) {
        for sub in self.subscribers_addressed(reader) {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_writer_group_gap(writer, start, end)
            }));
        }
    }

    /// Deliver an End-of-Coherent-Set notification to all subscribers on
    /// this topic. Triggered when the router recognises a DATA submessage
    /// with `D=0 K=0 Q=1` carrying `PID_COHERENT_SET` (and optionally
    /// `PID_GROUP_COHERENT_SET` + `PID_GROUP_ENTITY_ID`) per
    /// RTPS v2.5 sec. 8.7.5. Subscribers with
    /// `Presentation { coherent_access = true }` flush their
    /// per-(publisher, gsn) buffer atomically on this hook.
    #[inline]
    pub fn deliver_ecs(
        &self,
        writer_guid: [u8; 16],
        ecs_seq: u64,
        coherent_sn: u64,
        group_sn: Option<u64>,
        publisher_entity_id: Option<[u8; 4]>,
    ) -> usize {
        let mut errors = 0;
        for sub in &self.subscribers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_ecs(
                    &self.name,
                    writer_guid,
                    ecs_seq,
                    coherent_sn,
                    group_sn,
                    publisher_entity_id,
                );
            }));
            if result.is_err() {
                errors += 1;
                log::debug!(
                    "[demux] Subscriber '{}' panicked during ECS delivery",
                    sub.topic_name()
                );
            }
        }
        errors
    }

    /// Deliver an explicit coherent-set-completion notification to all
    /// subscribers on this topic. Triggered when the router recognises a
    /// normal coherent DATA sample (`D=1`) that ALSO carries
    /// `PID_END_COHERENT_SET` (0x8022) -- the form a writer with vendor id
    /// 0x0101 may use to signal that the sample is the LAST of its set, instead of a dedicated ECS
    /// marker submessage (RTPS v2.5 sec. 8.7.5). TOPIC/INSTANCE-scope
    /// `coherent_access` subscribers commit the writer's currently-buffered
    /// set atomically on this hook rather than waiting for the next set to
    /// begin (flush-on-new-set), which races the subscriber read cycle.
    #[inline]
    pub fn deliver_coherent_end(
        &self,
        writer_guid: [u8; 16],
        group_sn: Option<u64>,
        publisher_entity_id: Option<[u8; 4]>,
        end_sn: Option<u64>,
        end_count: Option<u32>,
    ) -> usize {
        let mut errors = 0;
        for sub in &self.subscribers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_coherent_end(
                    &self.name,
                    writer_guid,
                    group_sn,
                    publisher_entity_id,
                    end_sn,
                    end_count,
                );
            }));
            if result.is_err() {
                errors += 1;
                log::debug!(
                    "[demux] Subscriber '{}' panicked during coherent-end delivery",
                    sub.topic_name()
                );
            }
        }
        errors
    }

    /// Deliver a standalone END marker (a DATA without a sample, RTPS v2.5
    /// Sec.8.7.5) to all subscribers on this topic: the notification of
    /// `deliver_coherent_end`, plus `marker_seq`, the marker's own sequence
    /// number (see `Subscriber::on_coherent_end_marker`).
    #[inline]
    pub fn deliver_coherent_end_marker(
        &self,
        writer_guid: [u8; 16],
        group_sn: Option<u64>,
        publisher_entity_id: Option<[u8; 4]>,
        end_sn: u64,
        end_count: Option<u32>,
        marker_seq: u64,
    ) -> usize {
        let mut errors = 0;
        for sub in &self.subscribers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_coherent_end_marker(
                    &self.name,
                    writer_guid,
                    group_sn,
                    publisher_entity_id,
                    end_sn,
                    end_count,
                    marker_seq,
                );
            }));
            if result.is_err() {
                errors += 1;
                log::debug!(
                    "[demux] Subscriber '{}' panicked during coherent-end marker delivery",
                    sub.topic_name()
                );
            }
        }
        errors
    }

    /// Deliver a writer-endpoint dispose notification to all subscribers on
    /// this topic. A remote writer (for example when its publisher exits
    /// without per-instance unregister) may emit SEDP DATA(d) on
    /// `ENTITYID_BUILTIN_PUBLICATIONS_WRITER` carrying `PID_STATUS_INFO` +
    /// `PID_KEY_HASH` = disposed-writer GUID. Subscribers iterate the
    /// instances they have ever received from `writer_guid` and synthesize
    /// one `on_dispose` per (writer, instance) tuple so the application
    /// sees the per-instance NOT_ALIVE transition that DDS v1.4
    /// sec. 2.2.4.2.2 mandates regardless of explicit per-instance dispose.
    #[inline]
    pub fn deliver_writer_dispose(&self, writer_guid: [u8; 16], kind: DisposeKind) -> usize {
        self.deliver_writer_departure(writer_guid, kind, WriterDeparture::Unheard)
    }

    /// [`deliver_writer_dispose`](Self::deliver_writer_dispose), with why
    /// the writer left (`Subscriber::on_writer_departure`).
    pub fn deliver_writer_departure(
        &self,
        writer_guid: [u8; 16],
        kind: DisposeKind,
        cause: WriterDeparture,
    ) -> usize {
        let mut errors = 0;
        for sub in &self.subscribers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_writer_departure(&self.name, writer_guid, kind, cause);
            }));
            if result.is_err() {
                errors += 1;
                log::debug!(
                    "[demux] Subscriber '{}' panicked during writer-dispose delivery",
                    sub.topic_name()
                );
            }
        }
        errors
    }
}

/// Whether a submessage sent to `reader` reaches `sub`: ENTITYID_UNKNOWN
/// reaches every subscriber, a named reader only the subscriber reporting
/// that id.
fn addresses(sub: &dyn Subscriber, reader: [u8; 4]) -> bool {
    reader == ENTITYID_UNKNOWN || sub.reader_entity_id() == Some(reader)
}

// ============================================================================
// Topic Registry
// ============================================================================

/// Bound diagnostic state even if a hostile peer rotates writer GUIDs.
const MISSING_SEQUENCE_WARN_WRITER_CAPACITY: usize = 1024;

/// The most writers whose DATA dropped before their binding the registry
/// keeps a record of (`TopicRegistry::note_dropped_before_discovery`).
pub(crate) const DROPPED_BEFORE_DISCOVERY_KEPT: usize = 256;

/// What `TopicRegistry` keeps of DATA dropped before its writer was bound
/// to a topic (`TopicRegistry::note_dropped_before_discovery`).
#[derive(Default)]
struct DroppedBeforeDiscovery {
    /// Per writer, the lowest sequence dropped and the join-clock tick of
    /// the drop that recorded it (`join_clock_tick`), oldest first, at most
    /// `DROPPED_BEFORE_DISCOVERY_KEPT`: handed to the topic's readers when
    /// the writer is bound (`register_writer_guid`).
    records: std::collections::VecDeque<([u8; 16], u64, u64)>,
    /// The latest writers bound, each with the tick of its binding, at most
    /// `DROPPED_BEFORE_DISCOVERY_KEPT`: a drop recorded after its writer
    /// was bound (the router looked before the binding) happened before
    /// that tick.
    bound: std::collections::VecDeque<([u8; 16], u64)>,
}

/// Thread-safe registry for demultiplexed topics and auxiliary reliability handlers.
///
/// The registry guards access to topic definitions and multicast heartbeat/NACK callbacks
/// with `RwLock`s so readers never block each other while still allowing synchronous
/// updates during discovery.
///
/// # GUID-based Routing (Interop Fix)
///
/// A writer may send DATA packets WITHOUT inline QoS (flag=0) to save bandwidth.
/// Instead, it relies on the writer GUID (guidPrefix + writerEntityId) announced via SEDP.
/// We maintain a GUID->topic mapping populated during SEDP discovery to route these packets.
/// Per legacy writer: its own wire `PID_KEY_HASH` values, mapped to the real
/// instance they name. See `TopicRegistry::legacy_key_hash_instances`'s doc.
// None is an ambiguous hash. It stays ambiguous until the writer leaves;
// forgetting one colliding instance cannot make the hash unique again.
type LegacyKeyHashInstances = HashMap<([u8; 16], [u8; 16]), Option<[u8; 16]>>;

/// A participant-wide compatibility budget, independent of reader QoS.
/// Additional hashes are refused without evicting known mappings.
pub(crate) const MAX_LEGACY_KEY_HASH_INSTANCES: usize = 4096;

#[derive(Clone, Copy)]
enum WriterGroupContext {
    Spec(Option<[u8; 4]>),
    DepartedSpec(Option<[u8; 4]>, bool),
    Other,
}

/// Affirmative terminal evidence for a previously validated GROUP writer.
/// An announced replacement invalidates the same cell held by its readers.
pub(crate) struct GroupWriterTerminal {
    deleted: AtomicBool,
    departed: AtomicBool,
    participant_departed: AtomicBool,
    domain: Arc<RwLock<GroupWriterTerminals>>,
}

impl GroupWriterTerminal {
    pub(crate) fn is_deleted(&self) -> bool {
        self.deleted.load(Ordering::Acquire)
    }

    pub(crate) fn is_departed(&self) -> bool {
        self.departed.load(Ordering::Acquire)
    }

    /// Read one provider domain once and keep its incarnation stable through commit.
    pub(crate) fn proof_guard(&self) -> GroupWriterTerminalGuard<'_> {
        GroupWriterTerminalGuard {
            domain: &self.domain,
            _guard: recover_read(&self.domain, "GROUP availability proof domain"),
        }
    }

    pub(crate) fn same_proof_domain(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.domain, &other.domain)
    }

    pub(crate) fn proof_domain_id(&self) -> usize {
        Arc::as_ptr(&self.domain) as usize
    }

    #[cfg(test)]
    pub(crate) fn proof_read_available_for_test(&self) -> bool {
        self.domain.try_read().is_ok()
    }

    /// Departure is a proof of unavailable data, even when a silent writer
    /// can return later. Keep reannouncement excluded through cursor commit.
    pub(crate) fn all_departed(states: &[Arc<Self>]) -> Option<GroupWriterTerminalGuard<'_>> {
        let first = states.first()?;
        let guard = recover_read(&first.domain, "GROUP departure proof domain");
        if states
            .iter()
            .any(|state| !Arc::ptr_eq(&state.domain, &first.domain) || !state.is_departed())
        {
            return None;
        }
        Some(GroupWriterTerminalGuard {
            domain: &first.domain,
            _guard: guard,
        })
    }

    /// A participant departure proves the whole Publisher unavailable even
    /// when no complete writer roster was ever announced.
    pub(crate) fn all_participant_departed(
        states: &[Arc<Self>],
    ) -> Option<GroupWriterTerminalGuard<'_>> {
        let first = states.first()?;
        let guard = recover_read(&first.domain, "GROUP participant departure domain");
        if states.iter().any(|state| {
            !Arc::ptr_eq(&state.domain, &first.domain)
                || !state.participant_departed.load(Ordering::Acquire)
        }) {
            return None;
        }
        Some(GroupWriterTerminalGuard {
            domain: &first.domain,
            _guard: guard,
        })
    }

    /// Hold one consistent terminal view through the caller's local commit.
    /// Mixed registries and missing evidence cannot resolve a GROUP fence.
    #[cfg(test)]
    pub(crate) fn all_deleted(states: &[Arc<Self>]) -> Option<GroupWriterTerminalGuard<'_>> {
        let first = states.first()?;
        let guard = recover_read(&first.domain, "GROUP terminal proof domain");
        if states
            .iter()
            .any(|state| !Arc::ptr_eq(&state.domain, &first.domain) || !state.is_deleted())
        {
            return None;
        }
        Some(GroupWriterTerminalGuard {
            domain: &first.domain,
            _guard: guard,
        })
    }
}

pub(crate) struct GroupWriterTerminalGuard<'a> {
    domain: &'a Arc<RwLock<GroupWriterTerminals>>,
    _guard: RwLockReadGuard<'a, GroupWriterTerminals>,
}

impl GroupWriterTerminalGuard<'_> {
    pub(crate) fn is_departed(&self, state: &GroupWriterTerminal) -> bool {
        Arc::ptr_eq(self.domain, &state.domain) && state.is_departed()
    }

    pub(crate) fn is_participant_departed(&self, state: &GroupWriterTerminal) -> bool {
        Arc::ptr_eq(self.domain, &state.domain)
            && state.participant_departed.load(Ordering::Acquire)
    }
}

struct GroupWriterTerminalEntry {
    publisher: [u8; 4],
    state: Weak<GroupWriterTerminal>,
    generation: u64,
    // None never certifies a participant departure after counter exhaustion.
    participant_generation: Option<u64>,
    // A retained arrival cannot revoke a subsequently published loss proof.
    availability_revision: Option<u64>,
    participant_admission_pending: bool,
    exhausted: bool,
}

type GroupWriterTerminals = HashMap<[u8; 16], GroupWriterTerminalEntry>;

struct GroupWriterDeparture {
    guid: [u8; 16],
    publisher: [u8; 4],
    participant: bool,
    state: Arc<GroupWriterTerminal>,
    generation: u64,
    participant_generation: Option<u64>,
}

/// One arriving event can fan out to several readers and control hooks.
/// Its original arrival identity never changes when one recipient revives it.
#[derive(Clone)]
pub(crate) struct GroupArrivalStamp(Arc<GroupArrivalState>);

struct GroupArrivalState {
    cell: Arc<GroupWriterTerminal>,
    generation: u64,
    availability_revision: u64,
    // Read or changed only while the cell's provider domain is locked.
    applied_generation: Mutex<Option<u64>>,
}

impl std::fmt::Debug for GroupArrivalStamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupArrivalStamp")
            .field("generation", &self.0.generation)
            .field("availability_revision", &self.0.availability_revision)
            .finish_non_exhaustive()
    }
}

pub struct TopicRegistry {
    /// The route of remote writers' departures behind their data
    /// (`engine::departures`), set once by the participant's discovery
    /// setup; without it a departure is applied at once.
    departure_route: std::sync::OnceLock<Arc<super::departures::DepartureRoute>>,
    pub(crate) topics: RwLock<HashMap<String, Topic>>,
    pub(crate) heartbeat_handlers: RwLock<Vec<(HeartbeatHandlerId, Arc<dyn HeartbeatHandler>)>>,
    /// Monotonic id source for `heartbeat_handlers` entries (see
    /// `HeartbeatHandlerId`).
    heartbeat_handler_next_id: AtomicU64,
    pub(crate) nack_handlers: RwLock<Vec<(NackHandlerId, Arc<dyn NackHandler>)>>,
    pub(crate) nack_frag_handlers: RwLock<Vec<(NackHandlerId, Arc<dyn NackFragHandler>)>>,
    /// Monotonic id source for `nack_handlers` and `nack_frag_handlers`.
    nack_handler_next_id: AtomicU64,
    /// Writer GUID -> topic name mapping for DATA routing (interop)
    writer_guid_to_topic: RwLock<HashMap<[u8; 16], String>>,
    /// Writers whose DATA addressed to every reader (readerId
    /// ENTITYID_UNKNOWN) the router dropped because no binding names their
    /// topic yet, and the latest bindings (`DroppedBeforeDiscovery`). Also
    /// the lock that orders a drop against a binding, so none is left
    /// behind.
    dropped_before_discovery: Mutex<DroppedBeforeDiscovery>,
    /// The remote writers of the spec GROUP class (`GroupDialect::Spec`,
    /// decided once at their discovery): their end of a GROUP set is in
    /// the RTPS v2.5 form (`writer_speaks_spec_group`).
    spec_group_writers: RwLock<HashMap<[u8; 16], WriterGroupContext>>,
    /// The remote writers of a vendor that writes the RTPS v2.5 GROUP form
    /// with a bare end of set and no PID_COHERENT_SET (Dust DDS, vendor
    /// 0x0114, `GroupDialect::SpecReceive`), decided once at their discovery
    /// like `spec_group_writers`. Kept apart so no other writer pays for it.
    spec_receive_writers: RwLock<HashSet<[u8; 16]>>,
    /// Only consumers of validated GROUP rosters retain strong evidence.
    /// Cold registration/departure events prune expired weak entries.
    group_writer_terminals: Arc<RwLock<GroupWriterTerminals>>,
    any_group_writer_unheard: AtomicBool,
    /// Evidence belongs to each queued deletion's admission generation.
    /// Receipts live only until their departure is applied, not forever.
    pending_group_writer_departures: RwLock<HashMap<u64, Vec<GroupWriterDeparture>>>,
    next_group_writer_departure: AtomicU64,
    /// Writers already diagnosed for a missing DATA writerSN.
    missing_sequence_warned_writers: RwLock<HashSet<[u8; 16]>>,
    missing_sequence_warning_saturated: AtomicBool,
    /// Writer GUID -> OWNERSHIP_STRENGTH as its SEDP last announced it, read
    /// by an EXCLUSIVE reader when a writer contends an instance it does not
    /// own (DDS v1.4 Sec.2.2.3.9.2, Sec.2.2.3.10).
    writer_ownership_strengths: RwLock<HashMap<[u8; 16], i32>>,
    /// Writer GUID -> effective OWNERSHIP kind, inferred from the writer's
    /// SEDP PIDs at parse time (PID_OWNERSHIP present -> use it; absent +
    /// PID_OWNERSHIP_STRENGTH present -> EXCLUSIVE; both absent -> SHARED).
    /// This is the DURABLE record the reader-side OWNERSHIP data-plane gate
    /// resolves against: unlike the discovery FSM's endpoint registry it is
    /// never purged by the unconfirmed-participant zombie sweep, so a
    /// slow-announcing vendor (one SPDP inside the probation window, SEDP
    /// already ACKed and never re-sent) stays resolvable after the sweep.
    /// Same lifetime discipline as `writer_guid_to_topic`, which the router
    /// relies on for exactly the same reason.
    writer_ownership_kinds: RwLock<HashMap<[u8; 16], crate::qos::ownership::OwnershipKind>>,
    /// SEDP PARTITION metadata with the same durable lifetime as OWNERSHIP.
    /// Final coherent controls can arrive after discovery removed an endpoint.
    writer_partitions: RwLock<HashMap<[u8; 16], crate::qos::partition::Partition>>,
    /// Writer GUIDs an application blocked by hand (`block_writer`): the
    /// router drops their samples for every reader. HDDS itself does not
    /// write here: a writer's QoS is judged per (writer, local reader)
    /// pair by the match registry, and each reader drops what a writer it
    /// is not matched with sends (DDS v1.4 Sec.2.2.3).
    blocked_writers: RwLock<std::collections::HashSet<[u8; 16]>>,
    /// Whether `blocked_writers` holds anything: one relaxed load keeps its
    /// lock off the router's path while no application blocked a writer.
    any_writer_blocked: AtomicBool,
    /// Topic name -> smallest finite writer Lifespan (ns) announced via SEDP.
    /// Lets a reader tighten its effective lifespan from a matched writer
    /// BEFORE the async match-notification fires, closing the startup race
    /// where the first catch-up burst is read with lifespan still infinite
    /// (DDS v1.4 sec. 2.2.3.16 + RTPS v2.5 sec. 8.7.7).
    writer_lifespans_by_topic: RwLock<HashMap<String, u64>>,
    /// Monotonic mutation counter for `writer_lifespans_by_topic`.
    ///
    /// Bumped with Release ordering after every map mutation
    /// (`register_writer_lifespan`). Readers gate their per-take lifespan
    /// probe on it (Acquire load via `writer_lifespan_epoch`): an unchanged
    /// epoch proves the map has not changed since the reader's last probe,
    /// so the cached answer (including "no finite lifespan known") is still
    /// valid and the RwLock + topic-hash probe is skipped on the hot
    /// take() path.
    writer_lifespans_epoch: AtomicU64,
    /// Writer GUID -> its finite Lifespan (ns), announced via SEDP. LIFESPAN
    /// is a DataWriter QoS (DDS v1.4 Sec.2.2.3.16): a sample expires by the
    /// lifespan of the writer that wrote it, not by the smallest of its
    /// topic. A reader that knows which writer a sample came from reads this.
    writer_lifespans: RwLock<HashMap<[u8; 16], u64>>,
    /// Whether `writer_lifespans` holds anything: one relaxed load keeps the
    /// lookup off the take path of every reader when no writer announced a
    /// finite lifespan.
    any_writer_lifespan: AtomicBool,
    /// Remote writers of vendor HDDS whose participant did NOT announce
    /// `CAP_CONFORMANT_KEY_HASH` (a 1.4.x peer, or an unreleased pre-bit
    /// 1.5.0 snapshot): its generated keyed types compute the pre-1.5.0
    /// FNV-1a `PID_KEY_HASH` instead of the RTPS-conformant one (record
    /// 385), set once at SEDP writer discovery
    /// (`sedp_handler::record_writer_vendor`). Gates both
    /// `legacy_key_hash_instances`'s bookkeeping and its consultation at
    /// dispose/unregister dispatch off the hot path for every other writer
    /// (the overwhelming majority: any foreign vendor, and every HDDS 1.5.0+
    /// peer).
    legacy_key_hash_writers: RwLock<HashSet<[u8; 16]>>,
    /// Whether `legacy_key_hash_writers` holds anything: one relaxed load
    /// keeps the lookup (and the inline-QoS re-scan it would otherwise gate)
    /// off the DATA hot path while no peer needs it.
    any_legacy_key_hash_writer: AtomicBool,
    /// For each writer in `legacy_key_hash_writers`: the wire `PID_KEY_HASH`
    /// values its own ordinary ALIVE samples carried, mapped to the REAL
    /// instance this reader decoded for them (`T::compute_key()`), learned
    /// once per instance (`TopicRegistry::note_legacy_key_hash_instance`,
    /// called after reader admission). A dispose or
    /// unregister whose serialized key this reader cannot read (RTPS v2.5
    /// 9.4.5.3.2's K-only form, empty for a 1.4.x `hdds_gen` type) resolves
    /// its `PID_KEY_HASH` through this map instead of trusting it as the
    /// instance handle verbatim -- the SAME writer already put the SAME
    /// wire value beside a sample this reader decoded itself, so the lookup
    /// is exact, never a re-derivation of the hash algorithm.
    legacy_key_hash_instances: RwLock<LegacyKeyHashInstances>,
    legacy_key_hash_refused: AtomicU64,
    #[cfg(test)]
    legacy_key_hash_retirement_locks: AtomicU64,
}

/// Scoped registration for one exact subscriber instance.
///
/// The registry owns subscribers for packet fanout, so readers must remove
/// their own instance on drop. Matching by pointer keeps multiple readers on
/// the same topic independent.
pub(crate) struct SubscriberToken {
    registry: Weak<TopicRegistry>,
    topic_name: String,
    subscriber_ptr: usize,
}

impl Drop for SubscriberToken {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.unregister_subscriber_by_ptr(&self.topic_name, self.subscriber_ptr);
        }
    }
}

/// Scoped registration for one heartbeat handler. `register_heartbeat_handler`
/// never expired its entries before this token existed: a reader that
/// rebuilt (e.g. across a reconnect) piled up one dead handler per
/// build, each still reachable from `deliver_heartbeat`'s broadcast loop.
/// Holding this token for the handler's lifetime and dropping it with the
/// owning `DataReader` keeps the registry's list matching live readers.
pub struct HeartbeatHandlerToken {
    registry: Weak<TopicRegistry>,
    id: HeartbeatHandlerId,
}

impl HeartbeatHandlerToken {
    /// Wrap the id `register_heartbeat_handler` returned so the handler is
    /// unregistered when this token (held by the owning `DataReader`) drops.
    pub(crate) fn new(registry: &Arc<TopicRegistry>, id: HeartbeatHandlerId) -> Self {
        Self {
            registry: Arc::downgrade(registry),
            id,
        }
    }
}

impl Drop for HeartbeatHandlerToken {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.unregister_heartbeat_handler(self.id);
        }
    }
}

/// Scoped registration of one writer's NACK and NACK_FRAG handlers, held
/// by the `DataWriter`. Before it existed nothing removed them: a deleted
/// reliable writer kept answering ACKNACKs with retransmissions of its
/// history (which the handler keeps alive) after its SEDP dispose, and the
/// registry kept one dead handler per writer ever created.
pub(crate) struct NackHandlerToken {
    registry: Weak<TopicRegistry>,
    ids: Vec<NackHandlerId>,
}

impl NackHandlerToken {
    pub(crate) fn new(registry: &Arc<TopicRegistry>, ids: Vec<NackHandlerId>) -> Self {
        Self {
            registry: Arc::downgrade(registry),
            ids,
        }
    }
}

impl Drop for NackHandlerToken {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.unregister_nack_handlers(&self.ids);
        }
    }
}

#[inline]
fn recover_write<'a, T>(lock: &'a RwLock<T>, context: &str) -> RwLockWriteGuard<'a, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::debug!("[demux] WARNING: {} poisoned, recovering", context);
            poisoned.into_inner()
        }
    }
}

#[inline]
fn recover_read<'a, T>(lock: &'a RwLock<T>, context: &str) -> RwLockReadGuard<'a, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::debug!("[demux] WARNING: {} poisoned, recovering", context);
            poisoned.into_inner()
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Tests only: a one-shot hook run synchronously inside
    /// `TopicRegistry::recompute_topic_lifespan_after_departure`, right
    /// between its snapshot of the topic's remaining writers and its
    /// publish of the recomputed minimum -- lets a test interpose a
    /// concurrent registration exactly in that window.
    // @audit-ok: cfg(test) only, one hook per test thread
    static AFTER_LIFESPAN_SNAPSHOT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Tests only: run `hook` once, the next time
/// `recompute_topic_lifespan_after_departure` reaches the point between
/// its snapshot and its publish.
#[cfg(test)]
pub(crate) fn after_lifespan_snapshot_for_test(hook: Box<dyn FnOnce()>) {
    AFTER_LIFESPAN_SNAPSHOT.with(|h| *h.borrow_mut() = Some(hook));
}

impl TopicRegistry {
    pub fn new() -> Self {
        Self {
            departure_route: std::sync::OnceLock::new(),
            topics: RwLock::new(HashMap::new()),
            heartbeat_handlers: RwLock::new(Vec::new()),
            heartbeat_handler_next_id: AtomicU64::new(0),
            nack_handlers: RwLock::new(Vec::new()),
            nack_frag_handlers: RwLock::new(Vec::new()),
            nack_handler_next_id: AtomicU64::new(0),
            spec_group_writers: RwLock::new(HashMap::new()),
            spec_receive_writers: RwLock::new(HashSet::new()),
            group_writer_terminals: Arc::new(RwLock::new(HashMap::new())),
            any_group_writer_unheard: AtomicBool::new(false),
            pending_group_writer_departures: RwLock::new(HashMap::new()),
            next_group_writer_departure: AtomicU64::new(0),
            writer_guid_to_topic: RwLock::new(HashMap::new()),
            dropped_before_discovery: Mutex::new(DroppedBeforeDiscovery::default()),
            missing_sequence_warned_writers: RwLock::new(HashSet::new()),
            missing_sequence_warning_saturated: AtomicBool::new(false),
            writer_ownership_strengths: RwLock::new(HashMap::new()),
            writer_ownership_kinds: RwLock::new(HashMap::new()),
            writer_partitions: RwLock::new(HashMap::new()),
            blocked_writers: RwLock::new(std::collections::HashSet::new()),
            any_writer_blocked: AtomicBool::new(false),
            writer_lifespans_by_topic: RwLock::new(HashMap::new()),
            writer_lifespans_epoch: AtomicU64::new(0),
            writer_lifespans: RwLock::new(HashMap::new()),
            any_writer_lifespan: AtomicBool::new(false),
            legacy_key_hash_writers: RwLock::new(HashSet::new()),
            any_legacy_key_hash_writer: AtomicBool::new(false),
            legacy_key_hash_instances: RwLock::new(HashMap::new()),
            legacy_key_hash_refused: AtomicU64::new(0),
            #[cfg(test)]
            legacy_key_hash_retirement_locks: AtomicU64::new(0),
        }
    }

    pub fn register_topic(
        &self,
        name: String,
        type_name: Option<String>,
    ) -> Result<(), RegistryError> {
        let mut topics = recover_write(&self.topics, "TopicRegistry::topics.write()");

        if topics.contains_key(&name) {
            log::debug!("[REGISTRY] register_topic skip (exists) topic='{}'", name);
            return Ok(());
        }

        let type_display = type_name
            .as_deref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "<none>".to_string());

        topics.insert(name.clone(), Topic::new(name.clone(), type_name));
        log::debug!(
            "[REGISTRY] register_topic inserted topic='{}' type={}",
            name,
            type_display
        );
        Ok(())
    }

    pub fn register_subscriber(&self, sub: Arc<dyn Subscriber>) -> Result<(), RegistryError> {
        let topic_name = sub.topic_name().to_string();
        let ordered_group = sub.requires_ordered_group();

        let mut topics = recover_write(&self.topics, "TopicRegistry::topics.write()");

        let topic = topics
            .entry(topic_name.clone())
            .or_insert_with(|| Topic::new(topic_name, None));

        if !topic.add_subscriber_with_interest(sub, ordered_group) {
            log::debug!(
                "[REGISTRY] register_subscriber skip (duplicate handle) topic='{}'",
                topic.name()
            );
            return Ok(());
        }
        log::debug!(
            "[REGISTRY] register_subscriber topic='{}' subscriber_count={}",
            topic.name(),
            topic.subscriber_count()
        );
        Ok(())
    }

    pub(crate) fn register_subscriber_scoped(
        self: &Arc<Self>,
        sub: Arc<dyn Subscriber>,
    ) -> Result<SubscriberToken, RegistryError> {
        let topic_name = sub.topic_name().to_string();
        let subscriber_ptr = Arc::as_ptr(&sub) as *const () as usize;
        self.register_subscriber(sub)?;
        Ok(SubscriberToken {
            registry: Arc::downgrade(self),
            topic_name,
            subscriber_ptr,
        })
    }

    fn unregister_subscriber_by_ptr(&self, topic_name: &str, subscriber_ptr: usize) -> bool {
        let mut topics = recover_write(&self.topics, "TopicRegistry::topics.write()");
        topics
            .get_mut(topic_name)
            .is_some_and(|topic| topic.remove_subscriber_by_ptr(subscriber_ptr))
    }

    pub fn unregister_subscriber(&self, topic_name: &str) -> Result<bool, RegistryError> {
        let mut topics = recover_write(&self.topics, "TopicRegistry::topics.write()");

        if let Some(topic) = topics.get_mut(topic_name) {
            Ok(topic.remove_subscriber(topic_name))
        } else {
            Ok(false)
        }
    }

    #[must_use]
    #[inline]
    pub fn get_topic(&self, name: &str) -> Option<Topic> {
        let topics = recover_read(&self.topics, "TopicRegistry::topics.read()");
        topics.get(name).cloned()
    }

    /// Resolve a directed DATA before its writer's SEDP has arrived (RTPS
    /// 2.5 8.3.8.2). The readerId identifies a local endpoint, hence its
    /// topic, without guessing which topic an unknown writer publishes.
    /// The subscriber still defers the sample until discovery judges the
    /// pair; this lookup neither admits nor binds the writer.
    ///
    /// Only the discovery-miss path scans readers. Announced writers keep
    /// their GUID lookup, and ENTITYID_UNKNOWN cannot identify a topic.
    pub(crate) fn topic_for_reader(&self, reader: [u8; 4]) -> Option<String> {
        if reader == ENTITYID_UNKNOWN {
            return None;
        }
        // Subscriber hooks are user code: snapshot before calling one so
        // a hook can re-enter the registry without holding its read lock.
        let topics: Vec<Topic> = recover_read(&self.topics, "TopicRegistry::topics.read()")
            .values()
            .cloned()
            .collect();
        let mut matches = topics.iter().filter(|topic| {
            topic
                .subscribers
                .iter()
                .any(|sub| sub.reader_entity_id() == Some(reader))
        });
        let topic = matches.next()?;
        // Entity ids are unique within a participant. Refuse an ambiguous
        // registry rather than route to an arbitrary topic.
        matches.next().is_none().then(|| topic.name.clone())
    }

    #[must_use]
    pub fn topic_count(&self) -> usize {
        let topics = recover_read(&self.topics, "TopicRegistry::topics.read()");
        topics.len()
    }

    /// Register a heartbeat handler and return an id that
    /// `unregister_heartbeat_handler` can later use to remove exactly this
    /// entry (see `HeartbeatHandlerId`).
    pub fn register_heartbeat_handler(
        &self,
        handler: Arc<dyn HeartbeatHandler>,
    ) -> HeartbeatHandlerId {
        let id = HeartbeatHandlerId(
            self.heartbeat_handler_next_id
                .fetch_add(1, Ordering::Relaxed),
        );
        let mut handlers = recover_write(
            &self.heartbeat_handlers,
            "TopicRegistry::heartbeat_handlers.write()",
        );
        handlers.push((id, handler));
        id
    }

    /// Remove one heartbeat handler by id (never by `Arc` pointer identity,
    /// see `HeartbeatHandlerId`). A no-op if the id was already removed.
    pub fn unregister_heartbeat_handler(&self, id: HeartbeatHandlerId) {
        // Remove under the write guard, destroy after it: the registry
        // may hold the handler's final `Arc` (a `DataReader` keeps only
        // its token), and a handler destructor that reaches this registry
        // (a token it owns, `HeartbeatHandlerToken::drop`) would re-enter
        // the same lock and deadlock if it ran inside the guard.
        let removed = {
            let mut handlers = recover_write(
                &self.heartbeat_handlers,
                "TopicRegistry::heartbeat_handlers.write()",
            );
            handlers
                .iter()
                .position(|(hid, _)| *hid == id)
                .map(|index| handlers.remove(index))
        };
        drop(removed);
    }

    /// Number of currently registered heartbeat handlers. Test-only
    /// diagnostic for `HeartbeatHandlerToken` lifecycle tests.
    #[cfg(test)]
    pub(crate) fn heartbeat_handler_count(&self) -> usize {
        recover_read(
            &self.heartbeat_handlers,
            "TopicRegistry::heartbeat_handlers.read()",
        )
        .len()
    }

    /// Notify the subscribers of the topic bound to `writer_guid` that the
    /// writer just advertised `first_seq` in a HEARTBEAT submessage. The
    /// control-channel HEARTBEAT path uses this to seed late-joiner
    /// reorder buffers in user-data readers, since the original
    /// `deliver_heartbeat` path is bypassed for HBs that arrive via the
    /// control channel (see `core::discovery::multicast::control`).
    #[must_use]
    pub fn notify_writer_heartbeat(&self, writer_guid: [u8; 16], first_seq: u64) -> bool {
        self.notify_writer_heartbeat_to(writer_guid, first_seq, None, ENTITYID_UNKNOWN)
    }

    /// [`notify_writer_heartbeat`](Self::notify_writer_heartbeat) for the
    /// reader the HEARTBEAT's readerId names (ENTITYID_UNKNOWN: all).
    /// Notify the subscribers of the topic bound to `writer_guid` that
    /// `reader_entity_id` addresses of the GroupInfo `[currentGSN,
    /// firstGSN, lastGSN]` of the writer's HEARTBEAT. Returns `true` when
    /// the writer resolves to a topic.
    pub(crate) fn notify_writer_group_gap_to(
        &self,
        writer: [u8; 16],
        start: u64,
        end: u64,
        reader: [u8; 4],
    ) {
        if let Some(topic) = self
            .get_topic_by_guid(&writer)
            .and_then(|name| self.get_topic(&name))
        {
            topic.deliver_writer_group_gap_to(writer, start, end, reader);
        }
    }

    pub(crate) fn notify_writer_heartbeat_to(
        &self,
        writer_guid: [u8; 16],
        first_seq: u64,
        last_seq: Option<u64>,
        reader_entity_id: [u8; 4],
    ) -> bool {
        let Some(topic_name) = self.get_topic_by_guid(&writer_guid) else {
            return false;
        };
        let Some(topic) = self.get_topic(&topic_name) else {
            return false;
        };
        let _ =
            topic.deliver_writer_heartbeat_to(writer_guid, first_seq, last_seq, reader_entity_id);
        true
    }

    /// Notify the subscribers of the topic bound to `writer_guid` that a
    /// HEARTBEAT with the Liveliness flag set was received from it (RTPS
    /// v2.5 Sec.8.3.7.5). Returns `true` when the writer resolves to
    /// a topic.
    pub(crate) fn notify_writer_heartbeat_liveliness(&self, writer_guid: [u8; 16]) -> bool {
        let Some(topic_name) = self.get_topic_by_guid(&writer_guid) else {
            return false;
        };
        let Some(topic) = self.get_topic(&topic_name) else {
            return false;
        };
        let _ = topic.deliver_writer_heartbeat_liveliness(writer_guid);
        true
    }

    /// Notify the subscribers of the topic bound to `writer_guid` that the
    /// writer sent a GAP submessage declaring the contiguous range
    /// `[gap_start, gap_list_base)` and the sequences in `gap_list_seqs`
    /// as irrelevant (RTPS v2.5 sec 8.3.8.4).  The control-channel GAP
    /// path uses this to advance late-joiner reorder gates in user-data
    /// readers so buffered live samples are released.  Returns `true`
    /// when the writer GUID resolves to a known topic.
    pub fn notify_writer_gap(
        &self,
        writer_guid: [u8; 16],
        gap_start: u64,
        gap_list_base: u64,
        gap_list_seqs: Vec<u64>,
    ) -> bool {
        self.notify_writer_gap_to(
            writer_guid,
            gap_start,
            gap_list_base,
            gap_list_seqs,
            ENTITYID_UNKNOWN,
            None,
        )
    }

    /// [`notify_writer_gap`](Self::notify_writer_gap) for the reader the
    /// GAP's readerId names (ENTITYID_UNKNOWN: all).
    pub(crate) fn notify_writer_gap_to(
        &self,
        writer_guid: [u8; 16],
        gap_start: u64,
        gap_list_base: u64,
        gap_list_seqs: Vec<u64>,
        reader_entity_id: [u8; 4],
        filtered_count: Option<u64>,
    ) -> bool {
        let Some(topic_name) = self.get_topic_by_guid(&writer_guid) else {
            return false;
        };
        let Some(topic) = self.get_topic(&topic_name) else {
            return false;
        };
        let _ = topic.deliver_writer_gap_to(
            writer_guid,
            gap_start,
            gap_list_base,
            gap_list_seqs,
            reader_entity_id,
            filtered_count,
        );
        true
    }

    /// Notify the subscribers of the topic bound to `writer_guid` that the
    /// writer's SEDP announcement has just been processed into the discovery
    /// FSM, so its QoS (OWNERSHIP kind in particular) is now resolvable.
    /// Subscribers deferring samples for this writer re-run their RxO
    /// verdict and flush or discard the deferred samples. Returns `true`
    /// when the writer GUID resolves to a known topic.
    pub fn notify_writer_qos_resolved(&self, writer_guid: [u8; 16]) -> bool {
        let Some(topic_name) = self.get_topic_by_guid(&writer_guid) else {
            return false;
        };
        let Some(topic) = self.get_topic(&topic_name) else {
            return false;
        };
        let _ = topic.deliver_writer_qos_resolved(writer_guid);
        true
    }

    /// Route remote writers' departures behind their data from now on
    /// (`engine::departures`).
    pub(crate) fn set_departure_route(&self, route: Arc<super::departures::DepartureRoute>) {
        let _ = self.departure_route.set(route);
    }

    /// The departure route, when one is set.
    pub(crate) fn departure_route(&self) -> Option<&Arc<super::departures::DepartureRoute>> {
        self.departure_route.get()
    }

    /// A remote writer, or all of a participant's, gone: told to the
    /// subscribers behind the data queued before it, through the departure
    /// route (`engine::departures`), or at once without one.
    pub(crate) fn post_departure(&self, departure: super::departures::Departure) {
        // Capture GROUP evidence before this event waits behind queued DATA.
        // A later accepted announcement cannot be deleted by an older fence.
        let departure = self.capture_terminal_departure(departure);
        match self.departure_route.get() {
            Some(route) => {
                route.post(departure);
                for departure in route.take_overflow() {
                    self.apply_departure(departure);
                }
            }
            None => self.apply_departure(departure),
        }
    }

    /// Tell the subscribers of a departure (`post_departure`).
    pub(crate) fn apply_departure(&self, departure: super::departures::Departure) {
        match departure {
            super::departures::Departure::TerminalParticipant {
                prefix,
                proof,
                cause,
            } => {
                let captured = self.take_group_writer_departure(proof);
                self.notify_participant_departure_with_terminal(&prefix, cause, &captured);
                drop(captured);
                self.prune_group_writer_terminals();
            }
            super::departures::Departure::TerminalWriter {
                guid,
                kind,
                proof,
                cause,
            } => {
                let captured = self.take_group_writer_departure(proof);
                self.notify_writer_departure_with_terminal(guid, kind, cause, &captured);
                drop(captured);
                self.prune_group_writer_terminals();
            }
            super::departures::Departure::Participant { prefix, cause } => {
                let writers = self.notify_participant_departure(&prefix, cause);
                log::debug!(
                    "[departures] participant {:02x?} left: {} writer(s) gone with it",
                    prefix,
                    writers
                );
            }
            super::departures::Departure::Writer { guid, kind, cause } => {
                if !self.notify_writer_departure(guid, kind, cause) {
                    log::debug!(
                        "[departures] writer {:02x?} left, unknown here (no SEDP DATA(w) seen)",
                        guid
                    );
                }
            }
        }
        if let Some(route) = self.departure_route.get() {
            route.note_applied();
        }
    }

    /// Tests only: wait (two seconds at most) until every departure posted
    /// so far reached the readers, behind the data queued before it.
    #[cfg(test)]
    pub(crate) fn settle_departures(&self) {
        let Some(route) = self.departure_route.get() else {
            return;
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !route.settled() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    /// The Router popped a departure's fence: the departure is told now,
    /// behind the data queued before it.
    pub(crate) fn apply_next_departure(&self) {
        if let Some(departure) = self.departure_route.get().and_then(|route| route.next()) {
            self.apply_departure(departure);
        }
    }

    /// Notify the subscribers of the topic bound to `writer_guid` that the
    /// remote DataWriter is being disposed (SEDP DATA(d) on
    /// `ENTITYID_BUILTIN_PUBLICATIONS_WRITER`). Subscribers emit per-instance
    /// `NOT_ALIVE_*` events for every instance they have seen from this writer.
    pub fn notify_writer_dispose(&self, writer_guid: [u8; 16], kind: DisposeKind) -> bool {
        self.notify_writer_departure(writer_guid, kind, WriterDeparture::Unheard)
    }

    /// [`notify_writer_dispose`](Self::notify_writer_dispose), with why the
    /// writer left: one that announced it ([`WriterDeparture::Deleted`]) is
    /// never taken back for the same writer.
    pub fn notify_writer_departure(
        &self,
        writer_guid: [u8; 16],
        kind: DisposeKind,
        cause: WriterDeparture,
    ) -> bool {
        let captured = self.capture_group_writer_departures(|guid| *guid == writer_guid);
        let known = self.notify_writer_departure_with_terminal(writer_guid, kind, cause, &captured);
        drop(captured);
        if cause == WriterDeparture::Deleted {
            self.prune_group_writer_terminals();
        }
        known
    }

    fn notify_writer_departure_with_terminal(
        &self,
        writer_guid: [u8; 16],
        kind: DisposeKind,
        cause: WriterDeparture,
        captured: &[GroupWriterDeparture],
    ) -> bool {
        // Publish terminal evidence before reader callbacks. Holding this
        // strong notice through metadata retirement also lets a callback
        // acquire the evidence without a mark-to-retirement gap.
        let terminal = captured
            .iter()
            .find(|notice| notice.guid == writer_guid)
            .and_then(|notice| self.mark_group_writer_departed(notice, cause));
        // An admission-scoped event owns only the writer generation it
        // captured. Its rejected proof must not destroy a replacement's data.
        let had_notice = captured.iter().any(|notice| notice.guid == writer_guid);
        if (had_notice && terminal.is_none())
            || (!had_notice && self.writer_speaks_spec_group(&writer_guid))
        {
            return self.get_topic_by_guid(&writer_guid).is_some();
        }
        let known = self
            .get_topic_by_guid(&writer_guid)
            .and_then(|topic_name| self.get_topic(&topic_name))
            .map(|topic| topic.deliver_writer_departure(writer_guid, kind, cause))
            .is_some();
        if terminal.is_some() {
            let publisher = captured
                .iter()
                .find(|notice| notice.guid == writer_guid)
                .map(|notice| notice.publisher);
            if let Some(publisher) = publisher {
                self.notify_group_writer_departure(writer_guid, publisher);
            }
        }
        // A callback can accept a replacement announcement. Revalidate the
        // old notice after callbacks, then exclude replacement discovery
        // only through metadata retirement, where no callback runs.
        let _retirement_generation = if let Some(notice) =
            captured.iter().find(|notice| notice.guid == writer_guid)
        {
            let guard = recover_write(&self.group_writer_terminals, "GROUP metadata retirement");
            if self
                .current_group_writer_departure(&guard, notice)
                .is_none()
            {
                return known;
            }
            Some(guard)
        } else {
            None
        };
        // The writer's lifespan record goes with it, AFTER its readers heard
        // of the departure: each keeps the lifespan for the samples of the
        // writer it still holds (`DepartedLifespans`), which expire by it
        // whenever the application reads them (DDS v1.4 Sec.2.2.3.16).
        let had_lifespan = {
            let mut lifespans = recover_write(
                &self.writer_lifespans,
                "TopicRegistry::writer_lifespans.write()",
            );
            let had = lifespans.remove(&writer_guid).is_some();
            // The last finite lifespan gone, the take path skips the lookup
            // again.
            if lifespans.is_empty() {
                self.any_writer_lifespan.store(false, Ordering::Release);
            }
            had
        };
        // The topic's minimum (`writer_lifespans_by_topic`, read by a
        // reader that does not know which writer a sample came from) only
        // ever shrank when a writer announced a shorter one: nothing
        // recomputed it when the writer holding that minimum left, so a
        // later, infinite-lifespan writer's samples kept expiring against
        // a minimum that belonged to a writer no longer here (DDS v1.4
        // Sec.2.2.3.16: a sample expires by ITS writer's lifespan). Only
        // worth the rescan when this writer actually had one.
        if had_lifespan {
            self.recompute_topic_lifespan_after_departure(&writer_guid);
        }
        // The writer's other durable per-writer records (OWNERSHIP kind
        // and strength) go with it too, but ONLY when it is truly gone
        // (`WriterDeparture::Deleted`): one that merely fell `Unheard`
        // (its participant's lease expired, a probation purge) may come
        // back under the same GUID with no new SEDP at all, and these are
        // exactly the records -- each one's own doc calls them durable,
        // "never purged by the ... zombie sweep" -- that keep it
        // resolvable when it does. This is the one place both of this
        // function's callers retire them: an explicit writer dispose
        // (`sedp_handler.rs`) and a participant's own departure
        // (`notify_participant_departure`'s loop), which therefore retires
        // the kind and the strength as well.
        //
        // NOT `writer_guid_to_topic`: `notify_participant_departure`'s own
        // loop finds a departed participant's writers by filtering THAT
        // map on the prefix, so retiring an individual writer's entry
        // here would make a later participant-level departure of the
        // SAME writer invisible to it (confirmed by
        // `an_announced_departure_reaches_the_reader_as_a_deletion`, which
        // departs one writer explicitly and then its whole participant,
        // and expects both to reach the subscriber).
        self.clear_writer_legacy_instances(&writer_guid);
        if cause == WriterDeparture::Deleted {
            self.retire_deleted_writer(&writer_guid);
        }
        drop(terminal);
        known
    }

    /// Retire every durable per-writer record of `guid` this registry
    /// still holds, once it is `WriterDeparture::Deleted` for good (see
    /// [`notify_writer_departure`](Self::notify_writer_departure)): its
    /// OWNERSHIP strength and kind, and PARTITION. Never called for an `Unheard`
    /// departure.
    fn retire_deleted_writer(&self, guid: &[u8; 16]) {
        // The OWNERSHIP record goes first: `settle_writer_legacy_key_hash`
        // sets the legacy flag only of a writer that still has one, so the
        // flag forgotten just below cannot be set again by a settle racing
        // this departure.
        recover_write(
            &self.writer_ownership_kinds,
            "TopicRegistry::writer_ownership_kinds.write()",
        )
        .remove(guid);
        self.forget_writer_legacy_key_hash(guid);
        self.forget_writer_ownership_strength(guid);
        recover_write(
            &self.writer_partitions,
            "TopicRegistry::writer_partitions.write()",
        )
        .remove(guid);
        // Its GROUP dialect (`record_writer_group_dialect`) goes with it
        // too: left behind, a writer re-created later under the same GUID
        // (a new DataWriter, possibly of a different dialect) would
        // inherit a stale `writer_speaks_spec_group` verdict from one
        // that no longer exists.
        recover_write(
            &self.spec_group_writers,
            "TopicRegistry::spec_group_writers.write()",
        )
        .remove(guid);
    }

    /// Every remote DataWriter of the participant whose GUID prefix is
    /// `participant_prefix` is gone with it: its subscribers move the
    /// instances it wrote to NOT_ALIVE_NO_WRITERS, unless another writer
    /// still writes them (`notify_writer_dispose`, DDS v1.4
    /// Sec.2.2.2.5.1.3). Returns how many writers were known here.
    pub fn notify_participant_departed(&self, participant_prefix: &[u8; 12]) -> usize {
        self.notify_participant_departure(participant_prefix, WriterDeparture::Unheard)
    }

    /// [`notify_participant_departed`](Self::notify_participant_departed),
    /// with why the participant left.
    pub fn notify_participant_departure(
        &self,
        participant_prefix: &[u8; 12],
        cause: WriterDeparture,
    ) -> usize {
        let captured = self.capture_group_participant_departures(participant_prefix);
        let count =
            self.notify_participant_departure_with_terminal(participant_prefix, cause, &captured);
        drop(captured);
        if cause == WriterDeparture::Deleted {
            self.prune_group_writer_terminals();
        }
        count
    }

    fn notify_participant_departure_with_terminal(
        &self,
        participant_prefix: &[u8; 12],
        cause: WriterDeparture,
        captured: &[GroupWriterDeparture],
    ) -> usize {
        let writers: Vec<[u8; 16]> = recover_read(
            &self.writer_guid_to_topic,
            "TopicRegistry::writer_guid_to_topic.read()",
        )
        .keys()
        .filter(|guid| guid[..12] == participant_prefix[..])
        .copied()
        .collect();
        for writer in &writers {
            self.notify_writer_departure_with_terminal(
                *writer,
                DisposeKind::Unregistered,
                cause,
                captured,
            );
        }
        writers.len()
    }

    /// Register a NACK handler; the id removes exactly this entry
    /// (`unregister_nack_handlers`).
    pub fn register_nack_handler(&self, handler: Arc<dyn NackHandler>) -> NackHandlerId {
        let id = self.next_nack_handler_id();
        let mut handlers =
            recover_write(&self.nack_handlers, "TopicRegistry::nack_handlers.write()");
        handlers.push((id, handler));
        id
    }

    /// Register a NACK_FRAG handler; the id removes exactly this entry
    /// (`unregister_nack_handlers`).
    pub fn register_nack_frag_handler(&self, handler: Arc<dyn NackFragHandler>) -> NackHandlerId {
        let id = self.next_nack_handler_id();
        let mut handlers = recover_write(
            &self.nack_frag_handlers,
            "TopicRegistry::nack_frag_handlers.write()",
        );
        handlers.push((id, handler));
        id
    }

    fn next_nack_handler_id(&self) -> NackHandlerId {
        NackHandlerId(self.nack_handler_next_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Remove the NACK and NACK_FRAG handlers registered under `ids`. A
    /// delivery holds the list's read lock across its handlers, so none of
    /// the removed handlers runs once this returns. The removed handlers
    /// are destroyed after the locks are released, for the reason
    /// `unregister_heartbeat_handler` gives.
    pub fn unregister_nack_handlers(&self, ids: &[NackHandlerId]) {
        let removed_nack: Vec<Arc<dyn NackHandler>> = {
            let mut handlers =
                recover_write(&self.nack_handlers, "TopicRegistry::nack_handlers.write()");
            let (gone, kept) = std::mem::take(&mut *handlers)
                .into_iter()
                .partition::<Vec<_>, _>(|(id, _)| ids.contains(id));
            *handlers = kept;
            gone.into_iter().map(|(_, handler)| handler).collect()
        };
        let removed_frag: Vec<Arc<dyn NackFragHandler>> = {
            let mut handlers = recover_write(
                &self.nack_frag_handlers,
                "TopicRegistry::nack_frag_handlers.write()",
            );
            let (gone, kept) = std::mem::take(&mut *handlers)
                .into_iter()
                .partition::<Vec<_>, _>(|(id, _)| ids.contains(id));
            *handlers = kept;
            gone.into_iter().map(|(_, handler)| handler).collect()
        };
        drop(removed_nack);
        drop(removed_frag);
    }

    /// Number of registered NACK and NACK_FRAG handlers. Test-only.
    #[cfg(test)]
    pub(crate) fn nack_handler_counts(&self) -> (usize, usize) {
        (
            recover_read(&self.nack_handlers, "TopicRegistry::nack_handlers.read()").len(),
            recover_read(
                &self.nack_frag_handlers,
                "TopicRegistry::nack_frag_handlers.read()",
            )
            .len(),
        )
    }

    /// Register a writer GUID -> topic name mapping for DATA packet routing.
    ///
    /// Called during SEDP discovery when a remote writer is announced.
    /// Enables routing of DATA packets without inline QoS.
    ///
    /// DATA of the writer dropped before this binding
    /// (`note_dropped_before_discovery`) is owed to the topic's readers
    /// first, so no DATA routed by the binding reaches them before it.
    pub fn register_writer_guid(&self, guid: [u8; 16], topic_name: String) {
        let mut dropped = self
            .dropped_before_discovery
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(index) = dropped
            .records
            .iter()
            .position(|(writer, ..)| *writer == guid)
        {
            if let Some((_, seq, dropped_at)) = dropped.records.remove(index) {
                if let Some(topic) = self.get_topic(&topic_name) {
                    topic.deliver_dropped_before_discovery(guid, seq, dropped_at);
                }
            }
        }
        let bound_at = crate::engine::subscriber::join_clock_tick();
        dropped.bound.retain(|(writer, _)| *writer != guid);
        dropped.bound.push_back((guid, bound_at));
        while dropped.bound.len() > DROPPED_BEFORE_DISCOVERY_KEPT {
            dropped.bound.pop_front();
        }
        let mut mapping = recover_write(
            &self.writer_guid_to_topic,
            "TopicRegistry::writer_guid_to_topic.write()",
        );
        mapping.insert(guid, topic_name.clone());
        drop(dropped);
        log::debug!(
            "[REGISTRY] register_writer_guid guid={:02x?} topic='{}'",
            &guid[..],
            topic_name
        );
    }

    /// The router dropped DATA `seq` of `writer_guid`, addressed to every
    /// reader (readerId ENTITYID_UNKNOWN), because no binding names the
    /// writer's topic yet. Recorded (the lowest sequence per writer, at most
    /// `DROPPED_BEFORE_DISCOVERY_KEPT` writers, the oldest forgotten first:
    /// a GUID nobody announces is never bound) and handed to the topic's
    /// readers when the writer is bound (`register_writer_guid`); handed at
    /// once if the binding arrived since the router looked, as dropped
    /// before the binding's tick (the router looked before it).
    ///
    /// Stamped with the join-clock tick of the drop (`join_clock_tick`): a
    /// reader created after it is owed nothing by it. A record lowered by a
    /// later drop takes that drop's tick.
    pub(crate) fn note_dropped_before_discovery(&self, writer_guid: [u8; 16], seq: u64) {
        let mut dropped = self
            .dropped_before_discovery
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(topic_name) = self.get_topic_by_guid(&writer_guid) {
            let dropped_at = dropped
                .bound
                .iter()
                .rev()
                .find(|(writer, _)| *writer == writer_guid)
                .map_or_else(crate::engine::subscriber::join_clock_tick, |&(_, at)| at);
            if let Some(topic) = self.get_topic(&topic_name) {
                topic.deliver_dropped_before_discovery(writer_guid, seq, dropped_at);
            }
            return;
        }
        let dropped_at = crate::engine::subscriber::join_clock_tick();
        if let Some(entry) = dropped
            .records
            .iter_mut()
            .find(|(writer, ..)| *writer == writer_guid)
        {
            if seq < entry.1 {
                entry.1 = seq;
                entry.2 = dropped_at;
            }
            return;
        }
        dropped.records.push_back((writer_guid, seq, dropped_at));
        while dropped.records.len() > DROPPED_BEFORE_DISCOVERY_KEPT {
            dropped.records.pop_front();
        }
    }

    /// Tests only: how many writers have DATA recorded as dropped before
    /// their binding.
    #[cfg(test)]
    pub(crate) fn dropped_before_discovery_count(&self) -> usize {
        self.dropped_before_discovery
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .records
            .len()
    }

    /// Lookup topic name by writer GUID for DATA packet routing.
    ///
    /// Returns `None` if the GUID is unknown (writer not announced via SEDP yet).
    ///
    /// # Performance
    /// HOT PATH: Called for every DATA packet without inline QoS.
    #[must_use]
    #[inline]
    /// The ids of the local readers of `writer_guid`'s topic, as the SEDP
    /// mapping names it; while the writer is not known, of every topic here
    /// (a reader of another topic never receives this writer's sample, so
    /// the wider list only stands in until the mapping arrives).
    pub(crate) fn local_reader_ids(&self, writer_guid: &[u8; 16]) -> Vec<[u8; 4]> {
        if let Some(topic) = self.get_topic_by_guid(writer_guid) {
            return self
                .get_topic(&topic)
                .map(|topic| topic.named_reader_ids())
                .unwrap_or_default();
        }
        let topics = match self.topics.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        topics.values().flat_map(Topic::named_reader_ids).collect()
    }

    pub fn get_topic_by_guid(&self, guid: &[u8; 16]) -> Option<String> {
        let mapping = recover_read(
            &self.writer_guid_to_topic,
            "TopicRegistry::writer_guid_to_topic.read()",
        );
        mapping.get(guid).cloned()
    }

    /// Return true only for the first missing-sequence diagnostic from a writer.
    ///
    /// The zero key groups packets whose GUID cannot be decoded. State is capped
    /// so malformed traffic cannot grow the registry indefinitely; the exact
    /// event count remains available in `RouterMetrics` after saturation.
    pub(crate) fn should_warn_missing_sequence_fallback(
        &self,
        writer_guid: Option<[u8; 16]>,
    ) -> bool {
        let warning_key = writer_guid.unwrap_or([0; 16]);
        let mut warned = recover_write(
            &self.missing_sequence_warned_writers,
            "TopicRegistry::missing_sequence_warned_writers.write()",
        );
        if warned.contains(&warning_key) {
            return false;
        }
        if warned.len() >= MISSING_SEQUENCE_WARN_WRITER_CAPACITY {
            if !self
                .missing_sequence_warning_saturated
                .swap(true, Ordering::Relaxed)
            {
                log::warn!(
                    "[ROUTER] missing-sequence warning registry saturated at {} writers; counter remains exact",
                    MISSING_SEQUENCE_WARN_WRITER_CAPACITY
                );
            }
            return false;
        }
        warned.insert(warning_key)
    }

    /// Record whether remote writer `guid` is of the spec GROUP class,
    /// decided at its discovery from its participant's dialect, and
    /// its Publisher (`publisher`, its SEDP group entity id): a writer of
    /// that class with no announced Publisher is read as of no spec class.
    pub(crate) fn record_writer_group_dialect(
        &self,
        guid: [u8; 16],
        dialect: crate::protocol::group::GroupDialect,
        publisher: Option<[u8; 4]>,
    ) {
        self.write_writer_group_dialect(guid, dialect, publisher, false);
    }

    /// The one writer of the GROUP class maps. `settle` is set when the class
    /// is decided again for a writer already recorded
    /// (`settle_writer_group_dialect`): then nothing is written unless the
    /// writer is recorded, not departed, and its class differs. The check and
    /// the write run under the same write locks, so a departure that lands
    /// meanwhile (its `DepartedSpec`, its removal) is never overwritten.
    fn write_writer_group_dialect(
        &self,
        guid: [u8; 16],
        dialect: crate::protocol::group::GroupDialect,
        publisher: Option<[u8; 4]>,
        settle: bool,
    ) {
        let spec_class = matches!(
            dialect,
            crate::protocol::group::GroupDialect::Spec
                | crate::protocol::group::GroupDialect::SpecReceive
        );
        let receive_class = dialect == crate::protocol::group::GroupDialect::SpecReceive;
        // Taken in the order these maps are always taken: the terminal cells,
        // then the class, then the receive set.
        // Only accepted discovery publishes this classification. A plain
        // GUID-to-topic routing fallback is not a new writer announcement.
        // Serialize invalidation with terminal watches and deletion marks.
        let mut terminals = recover_write(
            &self.group_writer_terminals,
            "TopicRegistry::group_writer_terminals.write()",
        );
        let mut spec = recover_write(
            &self.spec_group_writers,
            "TopicRegistry::spec_group_writers.write()",
        );
        let mut receive = recover_write(
            &self.spec_receive_writers,
            "TopicRegistry::spec_receive_writers.write()",
        );
        if settle {
            let class_same = match spec.get(&guid) {
                // Not recorded (yet, or no longer), or departed: a departure
                // is not decided again.
                None | Some(WriterGroupContext::DepartedSpec(..)) => return,
                Some(WriterGroupContext::Spec(recorded)) => spec_class && *recorded == publisher,
                Some(WriterGroupContext::Other) => !spec_class,
            };
            if class_same && receive.contains(&guid) == receive_class {
                return;
            }
        }
        Self::invalidate_group_writer_terminal(&mut terminals, &guid);
        Self::invalidate_group_participant_terminal(&mut terminals, &mut spec, &guid);
        let context = if spec_class {
            WriterGroupContext::Spec(publisher)
        } else {
            WriterGroupContext::Other
        };
        spec.insert(guid, context);
        if receive_class {
            receive.insert(guid);
        } else {
            receive.remove(&guid);
        }
    }

    /// Whether remote writer `guid` was recorded as `GroupDialect::SpecReceive`
    /// (Dust DDS): its bare end of a GROUP set is the one a writer of that
    /// class sends without PID_COHERENT_SET (`extract_group_end_without_coherent_set`).
    pub(crate) fn writer_is_spec_receive(&self, guid: &[u8; 16]) -> bool {
        recover_read(
            &self.spec_receive_writers,
            "TopicRegistry::spec_receive_writers.read()",
        )
        .contains(guid)
    }

    /// Settle the GROUP class recorded for remote writer `guid` to what
    /// `record_writer_group_dialect` would record for `dialect` and
    /// `publisher`, now that its participant is known. Nothing is written
    /// unless the writer is recorded, not departed, and its class differs
    /// (`write_writer_group_dialect`, one write lock for the check and the
    /// write).
    pub(crate) fn settle_writer_group_dialect(
        &self,
        guid: [u8; 16],
        dialect: crate::protocol::group::GroupDialect,
        publisher: Option<[u8; 4]>,
    ) {
        self.write_writer_group_dialect(guid, dialect, publisher, true);
    }

    /// Watch one writer from a validated spec Publisher roster. Absence
    /// from this registry is never evidence of deletion. A caller keeps
    /// the returned cell while its roster/fence still needs that proof.
    pub(crate) fn group_writer_terminal(
        &self,
        guid: &[u8; 16],
        publisher: [u8; 4],
    ) -> Option<Arc<GroupWriterTerminal>> {
        let mut terminals = recover_write(
            &self.group_writer_terminals,
            "TopicRegistry::group_writer_terminals.write()",
        );
        terminals.retain(|_, entry| entry.state.strong_count() > 0);
        if let Some(state) = terminals.get(guid).and_then(|entry| {
            (entry.publisher == publisher)
                .then(|| entry.state.upgrade())
                .flatten()
        }) {
            if state.is_departed() {
                return Some(state);
            }
        }
        let (announced, departed, participant_departed) = match recover_read(
            &self.spec_group_writers,
            "TopicRegistry::spec_group_writers.read()",
        )
        .get(guid)
        {
            Some(WriterGroupContext::Spec(Some(publisher))) => (Some(*publisher), false, false),
            Some(WriterGroupContext::DepartedSpec(Some(publisher), participant)) => {
                (Some(*publisher), true, *participant)
            }
            _ => (None, false, false),
        };
        if announced != Some(publisher) {
            return None;
        }
        let state = terminals
            .get(guid)
            .and_then(|entry| entry.state.upgrade())
            .unwrap_or_else(|| {
                Arc::new(GroupWriterTerminal {
                    deleted: AtomicBool::new(false),
                    departed: AtomicBool::new(departed),
                    participant_departed: AtomicBool::new(participant_departed),
                    domain: self.group_writer_terminals.clone(),
                })
            });
        let generation = terminals.get(guid).map_or(0, |entry| entry.generation);
        let participant_generation = terminals
            .get(guid)
            .map_or(Some(0), |entry| entry.participant_generation);
        let availability_revision = terminals
            .get(guid)
            .map_or(Some(0), |entry| entry.availability_revision);
        let participant_admission_pending = terminals
            .get(guid)
            .is_some_and(|entry| entry.participant_admission_pending);
        let exhausted = terminals.get(guid).is_some_and(|entry| entry.exhausted);
        terminals.insert(
            *guid,
            GroupWriterTerminalEntry {
                publisher,
                state: Arc::downgrade(&state),
                generation,
                participant_generation,
                availability_revision,
                participant_admission_pending,
                exhausted,
            },
        );
        Some(state)
    }

    /// Freeze writers announced before a reader joins, including their
    /// evidence cells, under one registry view. Roster validation is not
    /// required to remember that a known writer subsequently departed.
    pub(crate) fn snapshot_group_writers(
        &self,
        publisher: [u8; 16],
    ) -> Vec<([u8; 4], Arc<GroupWriterTerminal>)> {
        let mut terminals = recover_write(&self.group_writer_terminals, "GROUP join snapshot");
        terminals.retain(|_, entry| entry.state.strong_count() > 0);
        let spec = recover_read(&self.spec_group_writers, "GROUP announced join snapshot");
        let mut result = Vec::new();
        for (guid, context) in spec.iter() {
            let WriterGroupContext::Spec(Some(entity)) = context else {
                continue;
            };
            if guid[..12] != publisher[..12] || entity[..] != publisher[12..] {
                continue;
            }
            let state = terminals
                .get(guid)
                .and_then(|entry| entry.state.upgrade())
                .unwrap_or_else(|| {
                    Arc::new(GroupWriterTerminal {
                        deleted: AtomicBool::new(false),
                        departed: AtomicBool::new(false),
                        participant_departed: AtomicBool::new(false),
                        domain: self.group_writer_terminals.clone(),
                    })
                });
            let generation = terminals.get(guid).map_or(0, |entry| entry.generation);
            let participant_generation = terminals
                .get(guid)
                .map_or(Some(0), |entry| entry.participant_generation);
            let availability_revision = terminals
                .get(guid)
                .map_or(Some(0), |entry| entry.availability_revision);
            let participant_admission_pending = terminals
                .get(guid)
                .is_some_and(|entry| entry.participant_admission_pending);
            let exhausted = terminals.get(guid).is_some_and(|entry| entry.exhausted);
            terminals.insert(
                *guid,
                GroupWriterTerminalEntry {
                    publisher: *entity,
                    state: Arc::downgrade(&state),
                    generation,
                    participant_generation,
                    availability_revision,
                    participant_admission_pending,
                    exhausted,
                },
            );
            let [.., e0, e1, e2, e3] = *guid;
            result.push(([e0, e1, e2, e3], state));
        }
        result.sort_by_key(|(entity, _)| *entity);
        result
    }

    /// Capture once before an event reaches user decoding or any recipient.
    /// Unknown writers create no entry; the strong cell pins revision identity
    /// until the event and any deferred copy have finished.
    pub(crate) fn capture_group_arrival(&self, guid: &[u8; 16]) -> Option<GroupArrivalStamp> {
        let publisher = self.writer_spec_group(guid)?;
        let cell = self.group_writer_terminal(guid, publisher)?;
        let terminals = recover_read(&self.group_writer_terminals, "GROUP arrival identity");
        let entry = terminals.get(guid)?;
        if entry.exhausted
            || !std::ptr::eq(entry.state.as_ptr(), Arc::as_ptr(&cell))
            || !Arc::ptr_eq(&cell.domain, &self.group_writer_terminals)
            || cell.is_deleted()
        {
            return None;
        }
        Some(GroupArrivalStamp(Arc::new(GroupArrivalState {
            cell,
            generation: entry.generation,
            availability_revision: entry.availability_revision?,
            applied_generation: Mutex::new(None),
        })))
    }

    /// Apply a validated arrival once across its complete recipient fanout.
    /// A later proof invalidates even an event a previous recipient accepted.
    /// No user callback runs under the provider domain or event-state locks.
    pub(crate) fn note_group_writer_alive_stamped(
        &self,
        guid: &[u8; 16],
        stamp: &GroupArrivalStamp,
    ) -> bool {
        let mut terminals = recover_write(&self.group_writer_terminals, "GROUP stamped return");
        let Some(entry) = terminals.get(guid) else {
            return false;
        };
        let arrival = &stamp.0;
        if entry.exhausted
            || !std::ptr::eq(entry.state.as_ptr(), Arc::as_ptr(&arrival.cell))
            || !Arc::ptr_eq(&arrival.cell.domain, &self.group_writer_terminals)
            || entry.availability_revision != Some(arrival.availability_revision)
            || arrival.cell.is_deleted()
        {
            return false;
        }
        let mut applied = arrival
            .applied_generation
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(generation) = *applied {
            return entry.generation == generation;
        }
        if entry.generation != arrival.generation {
            return false;
        }
        let pending_participant = entry.participant_admission_pending;
        if pending_participant || self.any_group_writer_unheard.load(Ordering::Acquire) {
            let mut spec = recover_write(&self.spec_group_writers, "GROUP writer return context");
            self.revive_group_writer_under_lock(
                &mut terminals,
                &mut spec,
                guid,
                pending_participant,
            );
        }
        // The entry was pinned above; a missing one refuses the arrival.
        let pinned = terminals.get(guid);
        debug_assert!(
            pinned.is_some(),
            "a pinned GROUP arrival has its terminal entry"
        );
        let Some(current) = pinned else {
            return false;
        };
        if current.exhausted {
            return false;
        }
        *applied = Some(current.generation);
        true
    }

    // Fresh standalone events in provider tests have no outer routing scope.
    #[cfg(test)]
    fn note_group_writer_alive(&self, guid: &[u8; 16]) {
        if let Some(stamp) = self.capture_group_arrival(guid) {
            self.note_group_writer_alive_stamped(guid, &stamp);
        }
    }

    fn revive_group_writer_under_lock(
        &self,
        terminals: &mut GroupWriterTerminals,
        spec: &mut HashMap<[u8; 16], WriterGroupContext>,
        guid: &[u8; 16],
        pending_participant: bool,
    ) {
        if pending_participant
            || spec.iter().any(|(writer, context)| {
                writer[..12] == guid[..12]
                    && matches!(context, WriterGroupContext::DepartedSpec(_, _))
            })
        {
            Self::invalidate_group_participant_terminal(terminals, spec, guid);
        }
        if let Some(context) = spec.get_mut(guid) {
            if let WriterGroupContext::DepartedSpec(publisher, _) = *context {
                *context = WriterGroupContext::Spec(publisher);
                Self::invalidate_group_writer_terminal(terminals, guid);
            }
        }
        self.any_group_writer_unheard.store(
            spec.values()
                .any(|context| matches!(context, WriterGroupContext::DepartedSpec(_, _))),
            Ordering::Release,
        );
    }

    fn notify_group_writer_departure(&self, writer: [u8; 16], publisher: [u8; 4]) {
        let topics: Vec<_> = recover_read(&self.topics, "GROUP departure subscribers")
            .values()
            .filter(|topic| topic.requires_ordered_group())
            .cloned()
            .collect();
        for topic in topics {
            for sub in topic.subscribers.iter().filter(|sub| sub.ordered_group) {
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    sub.on_group_writer_departure(writer, publisher);
                }))
                .is_err()
                {
                    log::debug!("[demux] GROUP departure subscriber panicked");
                }
            }
        }
    }

    /// A writer returning proves its participant is active, including for
    /// sibling writers whose individual departure evidence remains valid.
    /// Both held cells and metadata used to recreate weak cells are revoked.
    fn invalidate_group_participant_terminal(
        terminals: &mut GroupWriterTerminals,
        spec: &mut HashMap<[u8; 16], WriterGroupContext>,
        guid: &[u8; 16],
    ) {
        terminals.retain(|_, entry| entry.state.strong_count() > 0);
        for (writer, entry) in terminals.iter_mut() {
            if writer[..12] != guid[..12] {
                continue;
            }
            entry.participant_admission_pending = false;
            if let Some(state) = entry.state.upgrade() {
                state.participant_departed.store(false, Ordering::Release);
            }
            entry.participant_generation = entry
                .participant_generation
                .and_then(|old| old.checked_add(1));
        }
        for (writer, context) in spec.iter_mut() {
            if writer[..12] == guid[..12] {
                if let WriterGroupContext::DepartedSpec(_, participant) = context {
                    *participant = false;
                }
            }
        }
    }

    fn invalidate_group_writer_terminal(terminals: &mut GroupWriterTerminals, guid: &[u8; 16]) {
        terminals.retain(|_, entry| entry.state.strong_count() > 0);
        if let Some(entry) = terminals.get_mut(guid) {
            if let Some(state) = entry.state.upgrade() {
                state.deleted.store(false, Ordering::Release);
                state.departed.store(false, Ordering::Release);
                state.participant_departed.store(false, Ordering::Release);
            }
            if let Some(next) = entry.generation.checked_add(1) {
                entry.generation = next;
            } else {
                // An exhausted identity stays unknown rather than accepting
                // an old queued generation after a counter wrap.
                entry.exhausted = true;
                entry.availability_revision = None;
            }
        }
    }

    fn capture_group_writer_departures(
        &self,
        selected: impl Fn(&[u8; 16]) -> bool,
    ) -> Vec<GroupWriterDeparture> {
        self.capture_group_writer_departures_scoped(selected, false)
    }

    fn capture_group_participant_departures(&self, prefix: &[u8; 12]) -> Vec<GroupWriterDeparture> {
        self.capture_group_writer_departures_scoped(|guid| guid[..12] == prefix[..], true)
    }

    fn capture_group_writer_departures_scoped(
        &self,
        selected: impl Fn(&[u8; 16]) -> bool,
        participant_notice: bool,
    ) -> Vec<GroupWriterDeparture> {
        let mut terminals = recover_write(
            &self.group_writer_terminals,
            "TopicRegistry::group_writer_terminals.write()",
        );
        terminals.retain(|_, entry| entry.state.strong_count() > 0);
        let mut announced: HashMap<_, _> = recover_read(
            &self.spec_group_writers,
            "TopicRegistry::spec_group_writers.read()",
        )
        .iter()
        .filter_map(|(guid, context)| match context {
            WriterGroupContext::Spec(Some(publisher)) if selected(guid) => {
                Some((*guid, (*publisher, false, false)))
            }
            WriterGroupContext::DepartedSpec(Some(publisher), participant) if selected(guid) => {
                Some((*guid, (*publisher, true, *participant)))
            }
            _ => None,
        })
        .collect();
        for (&guid, entry) in &*terminals {
            if selected(&guid) {
                announced
                    .entry(guid)
                    .or_insert((entry.publisher, false, false));
            }
        }
        // Admission orders this notice after every earlier event, even
        // while an older individual Unheard verdict still permits return.
        // Capture its generations in this same domain transaction; do not
        // publish any new absence until the notice is actually applied.
        if participant_notice {
            for (_, entry) in terminals.iter_mut().filter(|(guid, _)| selected(guid)) {
                entry.availability_revision = entry
                    .availability_revision
                    .and_then(|old| old.checked_add(1));
                entry.participant_admission_pending = true;
                if entry.availability_revision.is_none() {
                    if let Some(cell) = entry.state.upgrade() {
                        cell.departed.store(false, Ordering::Release);
                        cell.participant_departed.store(false, Ordering::Release);
                    }
                }
            }
            let exhausted = terminals
                .iter()
                .any(|(guid, entry)| selected(guid) && entry.availability_revision.is_none());
            if exhausted {
                for (_, entry) in terminals.iter().filter(|(guid, _)| selected(guid)) {
                    if let Some(cell) = entry.state.upgrade() {
                        cell.participant_departed.store(false, Ordering::Release);
                    }
                }
                let mut spec = recover_write(&self.spec_group_writers, "GROUP exhausted admission");
                for (_, context) in spec.iter_mut().filter(|(guid, _)| selected(guid)) {
                    if let WriterGroupContext::DepartedSpec(_, participant) = context {
                        *participant = false;
                    }
                }
                for (_, _, participant) in announced.values_mut() {
                    *participant = false;
                }
            }
        }
        let mut captured = Vec::new();
        for (guid, (publisher, departed, participant)) in announced {
            if terminals.get(&guid).is_some_and(|entry| entry.exhausted) {
                continue;
            }
            let state = terminals
                .get(&guid)
                .and_then(|entry| entry.state.upgrade())
                .unwrap_or_else(|| {
                    Arc::new(GroupWriterTerminal {
                        deleted: AtomicBool::new(false),
                        departed: AtomicBool::new(departed),
                        participant_departed: AtomicBool::new(participant),
                        domain: self.group_writer_terminals.clone(),
                    })
                });
            let generation = terminals.get(&guid).map_or(0, |entry| entry.generation);
            let participant_generation = terminals
                .get(&guid)
                .map_or(Some(0), |entry| entry.participant_generation);
            let availability_revision = terminals
                .get(&guid)
                .map_or(Some(0), |entry| entry.availability_revision);
            let participant_admission_pending = participant_notice
                || terminals
                    .get(&guid)
                    .is_some_and(|entry| entry.participant_admission_pending);
            terminals.insert(
                guid,
                GroupWriterTerminalEntry {
                    publisher,
                    state: Arc::downgrade(&state),
                    generation,
                    participant_generation,
                    availability_revision,
                    participant_admission_pending,
                    exhausted: false,
                },
            );
            captured.push(GroupWriterDeparture {
                guid,
                publisher,
                participant: participant_notice,
                state,
                generation,
                participant_generation,
            });
        }
        captured
    }

    fn current_group_writer_departure(
        &self,
        terminals: &GroupWriterTerminals,
        captured: &GroupWriterDeparture,
    ) -> Option<Arc<GroupWriterTerminal>> {
        let entry = terminals.get(&captured.guid)?;
        let current = entry.state.upgrade()?;
        if entry.exhausted
            || entry.generation != captured.generation
            || !Arc::ptr_eq(&current, &captured.state)
            || !Arc::ptr_eq(&current.domain, &self.group_writer_terminals)
        {
            return None;
        }
        Some(current)
    }

    fn mark_group_writer_departed(
        &self,
        captured: &GroupWriterDeparture,
        cause: WriterDeparture,
    ) -> Option<Arc<GroupWriterTerminal>> {
        let mut terminals = recover_write(
            &self.group_writer_terminals,
            "TopicRegistry::group_writer_terminals.write()",
        );
        let current = self.current_group_writer_departure(&terminals, captured)?;
        debug_assert!(
            terminals.contains_key(&captured.guid),
            "a current GROUP writer has a terminal entry"
        );
        if let Some(entry) = terminals.get_mut(&captured.guid) {
            entry.participant_admission_pending = false;
        }
        current.departed.store(true, Ordering::Release);
        let participant = captured.participant
            && captured.participant_generation.is_some()
            && terminals.get(&captured.guid).is_some_and(|entry| {
                entry.participant_generation == captured.participant_generation
            });
        if participant {
            current.participant_departed.store(true, Ordering::Release);
        }
        if cause == WriterDeparture::Deleted {
            current.deleted.store(true, Ordering::Release);
        }
        // An older sibling event must not erase a newly published whole-
        // participant proof. Its pinned cell participates even if this
        // notice marks another writer first.
        for (writer, entry) in terminals.iter_mut() {
            if *writer == captured.guid || (participant && writer[..12] == captured.guid[..12]) {
                entry.availability_revision = entry
                    .availability_revision
                    .and_then(|old| old.checked_add(1));
                if entry.availability_revision.is_none() {
                    if let Some(cell) = entry.state.upgrade() {
                        cell.departed.store(false, Ordering::Release);
                        cell.participant_departed.store(false, Ordering::Release);
                    }
                }
            }
        }
        let scope_exhausted = terminals.iter().any(|(writer, entry)| {
            writer[..12] == captured.guid[..12] && entry.availability_revision.is_none()
        });
        if scope_exhausted {
            for (writer, entry) in terminals.iter() {
                if writer[..12] == captured.guid[..12] {
                    if let Some(cell) = entry.state.upgrade() {
                        cell.participant_departed.store(false, Ordering::Release);
                    }
                }
            }
        }
        let mut spec = recover_write(&self.spec_group_writers, "GROUP writer departure");
        if let Some(context) = spec.get_mut(&captured.guid) {
            if let WriterGroupContext::Spec(publisher) = context {
                *context =
                    WriterGroupContext::DepartedSpec(*publisher, participant && !scope_exhausted);
                if cause == WriterDeparture::Unheard {
                    self.any_group_writer_unheard.store(true, Ordering::Release);
                }
            } else if let WriterGroupContext::DepartedSpec(_, prior_participant) = context {
                *prior_participant |= participant && !scope_exhausted;
            }
        }
        // Exhaustion cannot leave a durable scope bit that recreates a
        // consumable absence proof after its weak cell disappears.
        for (writer, entry) in terminals.iter() {
            if entry.availability_revision.is_none()
                || (scope_exhausted && writer[..12] == captured.guid[..12])
            {
                if let Some(WriterGroupContext::DepartedSpec(_, participant)) = spec.get_mut(writer)
                {
                    *participant = false;
                }
            }
        }
        Some(current)
    }

    fn retain_group_writer_departure(&self, captured: Vec<GroupWriterDeparture>) -> u64 {
        if captured.is_empty() {
            return 0;
        }
        let Ok(before) = self.next_group_writer_departure.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |next| next.checked_add(1),
        ) else {
            return 0;
        };
        let id = before + 1;
        recover_write(
            &self.pending_group_writer_departures,
            "TopicRegistry::pending_group_writer_departures.write()",
        )
        .insert(id, captured);
        id
    }

    fn capture_terminal_departure(
        &self,
        departure: super::departures::Departure,
    ) -> super::departures::Departure {
        use super::departures::Departure;
        match departure {
            Departure::Writer { guid, kind, cause } => {
                let captured = self.capture_group_writer_departures(|writer| *writer == guid);
                Departure::TerminalWriter {
                    guid,
                    kind,
                    cause,
                    proof: self.retain_group_writer_departure(captured),
                }
            }
            Departure::Participant { prefix, cause } => {
                let captured = self.capture_group_participant_departures(&prefix);
                Departure::TerminalParticipant {
                    prefix,
                    cause,
                    proof: self.retain_group_writer_departure(captured),
                }
            }
            other => other,
        }
    }

    fn take_group_writer_departure(&self, id: u64) -> Vec<GroupWriterDeparture> {
        if id == 0 {
            return Vec::new();
        }
        recover_write(
            &self.pending_group_writer_departures,
            "TopicRegistry::pending_group_writer_departures.write()",
        )
        .remove(&id)
        .unwrap_or_default()
    }

    fn prune_group_writer_terminals(&self) {
        recover_write(
            &self.group_writer_terminals,
            "TopicRegistry::group_writer_terminals.write()",
        )
        .retain(|_, entry| entry.state.strong_count() > 0);
    }

    /// Whether remote writer `guid` is of the spec GROUP class. Read once
    /// per GROUP change, never for any other.
    pub(crate) fn writer_speaks_spec_group(&self, guid: &[u8; 16]) -> bool {
        self.writer_spec_group(guid).is_some()
    }

    #[cfg(test)]
    pub(crate) fn with_spec_group_writers_locked_for_test<R>(
        &self,
        operation: impl FnOnce() -> R,
    ) -> R {
        let _guard = recover_write(&self.spec_group_writers, "GROUP classification test");
        operation()
    }

    /// The Publisher (its EntityId, from the writer's SEDP) of remote writer
    /// `guid` when it is of the spec GROUP class: its GROUP changes carry no
    /// `PID_GROUP_ENTITY_ID`.
    pub(crate) fn writer_spec_group(&self, guid: &[u8; 16]) -> Option<[u8; 4]> {
        let spec = recover_read(
            &self.spec_group_writers,
            "TopicRegistry::spec_group_writers.read()",
        );
        if spec.is_empty() {
            return None;
        }
        match spec.get(guid) {
            Some(
                WriterGroupContext::Spec(publisher)
                | WriterGroupContext::DepartedSpec(publisher, _),
            ) => *publisher,
            _ => None,
        }
    }

    /// Raw GROUP metadata cannot be interpreted before its class and
    /// Publisher are known. A known other dialect keeps its existing path.
    pub(crate) fn writer_group_context_pending(&self, guid: &[u8; 16]) -> bool {
        recover_read(&self.spec_group_writers, "GROUP context discovery")
            .get(guid)
            .is_none_or(|context| {
                matches!(
                    context,
                    WriterGroupContext::Spec(None) | WriterGroupContext::DepartedSpec(None, _)
                )
            })
    }

    /// Register a writer's OWNERSHIP_STRENGTH (its SEDP announcement; a
    /// re-announcement replaces it).
    pub fn register_writer_ownership_strength(&self, guid: [u8; 16], strength: i32) {
        log::debug!(
            "[OWNERSHIP] register_strength writer={:02x}{:02x}{:02x}{:02x} strength={}",
            guid[12],
            guid[13],
            guid[14],
            guid[15],
            strength
        );
        let mut strengths = recover_write(
            &self.writer_ownership_strengths,
            "TopicRegistry::writer_ownership_strengths.write()",
        );
        strengths.insert(guid, strength);
    }

    /// Forget a deleted writer's OWNERSHIP_STRENGTH.
    pub(crate) fn forget_writer_ownership_strength(&self, guid: &[u8; 16]) {
        recover_write(
            &self.writer_ownership_strengths,
            "TopicRegistry::writer_ownership_strengths.write()",
        )
        .remove(guid);
    }

    /// Record whether remote writer `guid` is of vendor HDDS and its
    /// participant did NOT announce `CAP_CONFORMANT_KEY_HASH`: a 1.4.x peer
    /// (see `legacy_key_hash_writers`'s doc). Called once per writer, at its
    /// SEDP discovery (`sedp_handler::record_writer_vendor`); re-announcing
    /// the same writer with `legacy = false` clears it (a participant's
    /// capabilities do not regress in practice, but this stays correct if
    /// SEDP ever replays a stale announcement after a fresher one).
    pub fn register_writer_legacy_key_hash(&self, guid: [u8; 16], legacy: bool) {
        let mut writers = recover_write(
            &self.legacy_key_hash_writers,
            "TopicRegistry::legacy_key_hash_writers.write()",
        );
        if legacy {
            writers.insert(guid);
            self.any_legacy_key_hash_writer
                .store(true, Ordering::Relaxed);
        } else {
            writers.remove(&guid);
            self.clear_writer_legacy_instances(&guid);
        }
    }

    /// Settle the legacy key-hash flag of remote writer `guid` to `legacy`
    /// once its participant's vendor is known. Written only where it differs
    /// (`register_writer_legacy_key_hash` clears the writer's instances on
    /// `false`, which must not happen for nothing), under the flag's own write
    /// lock. A writer takes the flag only while it is registered, that is
    /// while its OWNERSHIP record (`writer_ownership_kinds`, written with its
    /// SEDP) is there: `retire_deleted_writer` removes that record before it
    /// forgets the flag, so a settle cannot set the flag of a writer already
    /// departed and retired.
    pub(crate) fn settle_writer_legacy_key_hash(&self, guid: [u8; 16], legacy: bool) {
        let mut writers = recover_write(
            &self.legacy_key_hash_writers,
            "TopicRegistry::legacy_key_hash_writers.write()",
        );
        if writers.contains(&guid) == legacy {
            return;
        }
        if !legacy {
            writers.remove(&guid);
            self.clear_writer_legacy_instances(&guid);
            return;
        }
        let registered = recover_read(
            &self.writer_ownership_kinds,
            "TopicRegistry::writer_ownership_kinds.read()",
        )
        .contains_key(&guid);
        if registered {
            writers.insert(guid);
            self.any_legacy_key_hash_writer
                .store(true, Ordering::Relaxed);
        }
    }

    /// Whether `guid` was flagged by [`Self::register_writer_legacy_key_hash`].
    /// One relaxed load when no peer ever was (the common case), before the
    /// lock.
    #[must_use]
    pub(crate) fn writer_uses_legacy_key_hash(&self, guid: &[u8; 16]) -> bool {
        if !self.any_legacy_key_hash_writer.load(Ordering::Relaxed) {
            return false;
        }
        recover_read(
            &self.legacy_key_hash_writers,
            "TopicRegistry::legacy_key_hash_writers.read()",
        )
        .contains(guid)
    }

    /// Forget a deleted writer behind the same data fence as its readers.
    pub(crate) fn forget_writer_legacy_key_hash(&self, guid: &[u8; 16]) {
        let mut writers = recover_write(
            &self.legacy_key_hash_writers,
            "TopicRegistry::legacy_key_hash_writers.write()",
        );
        writers.remove(guid);
        self.clear_writer_legacy_instances(guid);
    }

    fn clear_writer_legacy_instances(&self, guid: &[u8; 16]) {
        if !self.any_legacy_key_hash_writer.load(Ordering::Relaxed) {
            return;
        }
        recover_write(
            &self.legacy_key_hash_instances,
            "TopicRegistry::legacy_key_hash_instances.write()",
        )
        .retain(|(writer, _), _| writer != guid);
    }

    /// Retire a writer's instance once its unregister has been admitted.
    pub(crate) fn forget_legacy_key_hash_instance(&self, writer: [u8; 16], instance: [u8; 16]) {
        if !self.writer_uses_legacy_key_hash(&writer) {
            return;
        }
        let mut instances = recover_write(
            &self.legacy_key_hash_instances,
            "TopicRegistry::legacy_key_hash_instances.write()",
        );
        #[cfg(test)]
        self.legacy_key_hash_retirement_locks
            .fetch_add(1, Ordering::Relaxed);
        instances.retain(|(guid, _), key| *guid != writer || *key != Some(instance));
    }

    #[cfg(test)]
    pub(crate) fn legacy_key_hash_retirement_locks(&self) -> u64 {
        self.legacy_key_hash_retirement_locks
            .load(Ordering::Relaxed)
    }

    /// Compatibility mappings refused at the participant-wide fixed budget.
    #[must_use]
    pub fn legacy_key_hash_refused(&self) -> u64 {
        self.legacy_key_hash_refused.load(Ordering::Relaxed)
    }

    /// Learn only from an admitted sample, retaining at most the fixed
    /// compatibility budget. Keep the flag locked through insertion so a
    /// departure cannot clear the map and then have it recreated in flight.
    pub(crate) fn note_legacy_key_hash_instance(
        &self,
        writer: [u8; 16],
        wire_hash: [u8; 16],
        real_instance: [u8; 16],
    ) {
        let writers = recover_read(
            &self.legacy_key_hash_writers,
            "TopicRegistry::legacy_key_hash_writers.read()",
        );
        if !writers.contains(&writer) {
            return;
        }
        let mut instances = recover_write(
            &self.legacy_key_hash_instances,
            "TopicRegistry::legacy_key_hash_instances.write()",
        );
        if !instances.contains_key(&(writer, wire_hash))
            && instances.len() >= MAX_LEGACY_KEY_HASH_INSTANCES
        {
            self.legacy_key_hash_refused.fetch_add(1, Ordering::Relaxed);
            return;
        }
        instances
            .entry((writer, wire_hash))
            .and_modify(|known| {
                if *known != Some(real_instance) {
                    *known = None;
                }
            })
            .or_insert(Some(real_instance));
    }

    /// The REAL instance `writer`'s wire `PID_KEY_HASH` value `wire_hash`
    /// names, if [`Self::note_legacy_key_hash_instance`] has seen it before.
    /// `None` when the writer never wrote that instance where this reader
    /// could read its key (nothing to resolve it against yet) or is not a
    /// flagged legacy writer, or when distinct instances made it ambiguous.
    #[must_use]
    pub(crate) fn resolve_legacy_key_hash_instance(
        &self,
        writer: &[u8; 16],
        wire_hash: &[u8; 16],
    ) -> Option<[u8; 16]> {
        if !self.any_legacy_key_hash_writer.load(Ordering::Relaxed) {
            return None;
        }
        recover_read(
            &self.legacy_key_hash_instances,
            "TopicRegistry::legacy_key_hash_instances.read()",
        )
        .get(&(*writer, *wire_hash))
        .copied()
        .flatten()
    }

    /// Record a remote writer's effective OWNERSHIP kind as inferred from its
    /// SEDP PIDs at parse time. Durable for the writer's lifetime in this
    /// participant (never removed by discovery-FSM zombie purges); resolved by
    /// the reader-side OWNERSHIP data-plane gate.
    pub fn register_writer_ownership_kind(
        &self,
        guid: [u8; 16],
        kind: crate::qos::ownership::OwnershipKind,
    ) {
        let mut kinds = recover_write(
            &self.writer_ownership_kinds,
            "TopicRegistry::writer_ownership_kinds.write()",
        );
        kinds.insert(guid, kind);
    }

    /// Look up a remote writer's SEDP-recorded OWNERSHIP kind. `None` when
    /// the writer's SEDP has not been processed by this participant yet.
    #[must_use]
    pub fn writer_ownership_kind(
        &self,
        guid: &[u8; 16],
    ) -> Option<crate::qos::ownership::OwnershipKind> {
        let kinds = recover_read(
            &self.writer_ownership_kinds,
            "TopicRegistry::writer_ownership_kinds.read()",
        );
        kinds.get(guid).copied()
    }

    /// Record the remote writer's SEDP PARTITION, retained across FSM purges
    /// and unheard departures so queued final coherent controls remain valid.
    pub fn register_writer_partition(
        &self,
        guid: [u8; 16],
        partition: crate::qos::partition::Partition,
    ) {
        recover_write(
            &self.writer_partitions,
            "TopicRegistry::writer_partitions.write()",
        )
        .insert(guid, partition);
    }

    /// Resolve a remote writer's announced PARTITION, if SEDP recorded it.
    #[must_use]
    pub fn writer_partition(&self, guid: &[u8; 16]) -> Option<crate::qos::partition::Partition> {
        recover_read(
            &self.writer_partitions,
            "TopicRegistry::writer_partitions.read()",
        )
        .get(guid)
        .cloned()
    }

    /// Record the finite Lifespan (ns) of `writer_guid`, a writer of `topic`.
    ///
    /// Kept per writer (`writer_lifespan`): a reader that knows which writer
    /// a sample came from expires it by that writer's lifespan only. Also
    /// kept as the smallest of the topic, for the samples whose writer the
    /// reader does not know (the intra-process leg), read immediately on
    /// first data even if the async match-notification has not fired yet
    /// (startup catch-up-burst race).
    pub fn register_writer_lifespan_of(
        &self,
        topic: &str,
        writer_guid: [u8; 16],
        lifespan_ns: u64,
    ) {
        {
            // The flag moves under the map's lock, here and in
            // `notify_writer_dispose`, so it never says empty over a record.
            let mut lifespans = recover_write(
                &self.writer_lifespans,
                "TopicRegistry::writer_lifespans.write()",
            );
            lifespans.insert(writer_guid, lifespan_ns);
            self.any_writer_lifespan.store(true, Ordering::Release);
        }
        self.register_topic_lifespan(topic, lifespan_ns);
    }

    /// Record a matched writer's finite Lifespan (ns) for `topic` only,
    /// keeping the smallest seen: the 1.4 form, which knows no writer.
    #[deprecated(
        since = "1.5.0",
        note = "a sample expires by the lifespan of its own writer: use \
                `register_writer_lifespan_of`, which records it per writer"
    )]
    pub fn register_writer_lifespan(&self, topic: &str, lifespan_ns: u64) {
        self.register_topic_lifespan(topic, lifespan_ns);
    }

    fn register_topic_lifespan(&self, topic: &str, lifespan_ns: u64) {
        let mut map = recover_write(
            &self.writer_lifespans_by_topic,
            "TopicRegistry::writer_lifespans_by_topic.write()",
        );
        map.entry(topic.to_string())
            .and_modify(|cur| {
                if lifespan_ns < *cur {
                    *cur = lifespan_ns;
                }
            })
            .or_insert(lifespan_ns);
        // Publish the mutation to epoch-gated readers. Release pairs with
        // the Acquire load in `writer_lifespan_epoch()`: a reader that
        // observes the bumped epoch re-probes the map (the RwLock read
        // then guarantees it sees this entry). Bumped while still holding
        // the write guard so the epoch is ordered with the map write.
        self.writer_lifespans_epoch.fetch_add(1, Ordering::Release);
    }

    /// Recompute `writer_lifespans_by_topic`'s minimum for `writer_guid`'s
    /// topic from the writers still recorded, after `writer_guid`'s own
    /// finite lifespan was just removed from `writer_lifespans`
    /// (`notify_writer_departure`): the running minimum only ever shrinks
    /// on registration, so the writer that held it leaving must rescan
    /// the topic's remaining writers rather than leave a stale value a
    /// later, infinite-lifespan writer's samples would otherwise expire
    /// against.
    ///
    /// The snapshot (`writer_guid_to_topic` + `writer_lifespans`) and the
    /// publish (`writer_lifespans_by_topic`) are two different locks, taken
    /// one after the other, never nested: a concurrent SEDP registration
    /// publishing a NEW writer's finite lifespan for this same topic
    /// (`register_topic_lifespan`, its own writer entirely, no shared lock
    /// with this scan) between this snapshot and this publish would have
    /// its result overwritten by this call's now-stale one -- a
    /// just-registered finite minimum erased back to "no limit" by a
    /// departure that computed `None` before that registration happened.
    /// `writer_lifespans_epoch` is bumped under `writer_lifespans_by_topic`'s
    /// write lock by every publisher of that map (`register_topic_lifespan`
    /// and this function alike), so re-reading it AFTER taking that same
    /// lock tells this call, authoritatively, whether any publish slipped
    /// in since the snapshot; if one did, the snapshot is retaken fresh
    /// rather than published stale.
    fn recompute_topic_lifespan_after_departure(&self, writer_guid: &[u8; 16]) {
        let Some(topic) = self.get_topic_by_guid(writer_guid) else {
            return;
        };
        loop {
            let epoch_before = self.writer_lifespans_epoch.load(Ordering::Acquire);
            let new_min = {
                let guid_to_topic = recover_read(
                    &self.writer_guid_to_topic,
                    "TopicRegistry::writer_guid_to_topic.read()",
                );
                let lifespans = recover_read(
                    &self.writer_lifespans,
                    "TopicRegistry::writer_lifespans.read()",
                );
                guid_to_topic
                    .iter()
                    .filter(|(_, t)| **t == topic)
                    .filter_map(|(guid, _)| lifespans.get(guid).copied())
                    .min()
            };
            // Tests only: a seam right between the snapshot above and the
            // publish below, where a test can interpose a concurrent
            // registration this call must not then overwrite.
            #[cfg(test)]
            if let Some(hook) = AFTER_LIFESPAN_SNAPSHOT.with(|h| h.borrow_mut().take()) {
                hook();
            }
            let mut by_topic = recover_write(
                &self.writer_lifespans_by_topic,
                "TopicRegistry::writer_lifespans_by_topic.write()",
            );
            if self.writer_lifespans_epoch.load(Ordering::Acquire) != epoch_before {
                // Something else published to this same map since the
                // snapshot was taken (while this call held no lock at
                // all): that snapshot is stale, and nothing it computed
                // can be trusted. Drop the write lock and retake the
                // snapshot from scratch.
                drop(by_topic);
                continue;
            }
            match new_min {
                Some(min) => {
                    by_topic.insert(topic, min);
                }
                None => {
                    by_topic.remove(&topic);
                }
            }
            drop(by_topic);
            self.writer_lifespans_epoch.fetch_add(1, Ordering::Release);
            break;
        }
    }

    /// Whether the take path still looks writers' lifespans up.
    #[cfg(test)]
    pub(crate) fn looks_up_writer_lifespans(&self) -> bool {
        self.any_writer_lifespan.load(Ordering::Acquire)
    }

    /// The finite Lifespan (ns) `writer_guid` announced, if any.
    #[inline]
    pub fn writer_lifespan(&self, writer_guid: &[u8; 16]) -> Option<u64> {
        if !self.any_writer_lifespan.load(Ordering::Acquire) {
            return None;
        }
        recover_read(
            &self.writer_lifespans,
            "TopicRegistry::writer_lifespans.read()",
        )
        .get(writer_guid)
        .copied()
    }

    /// Smallest finite writer Lifespan (ns) announced for `topic`, if any.
    pub fn min_writer_lifespan_for_topic(&self, topic: &str) -> Option<u64> {
        let map = recover_read(
            &self.writer_lifespans_by_topic,
            "TopicRegistry::writer_lifespans_by_topic.read()",
        );
        map.get(topic).copied()
    }

    /// Current epoch of the writer-lifespan map (see
    /// `writer_lifespans_epoch`). Starts at 0, incremented on every
    /// mutation; readers cache the last epoch they probed at and skip
    /// the probe while it is unchanged.
    #[inline]
    pub fn writer_lifespan_epoch(&self) -> u64 {
        self.writer_lifespans_epoch.load(Ordering::Acquire)
    }

    /// Block a remote writer by hand: the router drops its samples for
    /// every reader of this participant.
    ///
    /// HDDS does not call this: blocking a writer incompatible with
    /// EVERY local reader of its topic would, with one compatible sibling,
    /// let a reader the writer is incompatible with receive its samples all
    /// the same. QoS is judged per (writer, reader) pair, on the reader's
    /// delivery path. Kept for the applications that call it.
    #[deprecated(
        since = "1.5.0",
        note = "QoS incompatibility is enforced per (writer, reader) pair by the reader itself"
    )]
    pub fn block_writer(&self, guid: [u8; 16]) {
        let mut blocked = recover_write(
            &self.blocked_writers,
            "TopicRegistry::blocked_writers.write()",
        );
        blocked.insert(guid);
        self.any_writer_blocked.store(true, Ordering::Release);
        log::debug!("[REGISTRY] Blocked writer {:02x?} by hand", &guid[..]);
    }

    /// Lift a block set by hand (`block_writer`).
    #[deprecated(
        since = "1.5.0",
        note = "QoS incompatibility is enforced per (writer, reader) pair by the reader itself"
    )]
    pub fn unblock_writer(&self, guid: [u8; 16]) {
        let mut blocked = recover_write(
            &self.blocked_writers,
            "TopicRegistry::blocked_writers.write()",
        );
        if blocked.remove(&guid) {
            log::debug!("[REGISTRY] Unblocked writer {:02x?}", &guid[..]);
        }
        self.any_writer_blocked
            .store(!blocked.is_empty(), Ordering::Release);
    }

    /// Whether a writer was blocked by hand (`block_writer`).
    #[deprecated(
        since = "1.5.0",
        note = "QoS incompatibility is enforced per (writer, reader) pair by the reader itself"
    )]
    #[must_use]
    #[inline]
    pub fn is_writer_blocked(&self, guid: &[u8; 16]) -> bool {
        self.blocked_by_hand(guid)
    }

    /// `is_writer_blocked`, for the router: one relaxed load while no
    /// application blocked a writer.
    #[inline]
    pub(crate) fn blocked_by_hand(&self, guid: &[u8; 16]) -> bool {
        if !self.any_writer_blocked.load(Ordering::Acquire) {
            return false;
        }
        recover_read(
            &self.blocked_writers,
            "TopicRegistry::blocked_writers.read()",
        )
        .contains(guid)
    }

    /// The OWNERSHIP_STRENGTH a remote writer's SEDP announced, `None` for a
    /// writer this registry has none for (DDS v1.4 Sec.2.2.3.10: the
    /// default is 0).
    pub(crate) fn writer_ownership_strength(&self, guid: &[u8; 16]) -> Option<i32> {
        recover_read(
            &self.writer_ownership_strengths,
            "TopicRegistry::writer_ownership_strengths.read()",
        )
        .get(guid)
        .copied()
    }

    /// How many writers have a recorded strength (tests: the record leaves
    /// with its writer).
    #[cfg(test)]
    pub(crate) fn writer_ownership_strength_count(&self) -> usize {
        recover_read(
            &self.writer_ownership_strengths,
            "TopicRegistry::writer_ownership_strengths.read()",
        )
        .len()
    }

    /// Does nothing: the registry has no EXCLUSIVE ownership filter for a
    /// topic. Ownership is arbitrated by each EXCLUSIVE DataReader (DDS v1.4
    /// Sec.2.2.3.10: "The arbitration is performed by the DataReader"), on
    /// the instance key it decodes.
    #[deprecated(
        since = "1.5.0",
        note = "EXCLUSIVE ownership is arbitrated by each DataReader; this does nothing"
    )]
    pub fn enable_exclusive_ownership(&self, topic_name: &str) {
        let _ = topic_name;
    }

    /// Always answers `true`: ownership is arbitrated by each EXCLUSIVE
    /// DataReader (DDS v1.4 Sec.2.2.3.10) on the instance key it decodes,
    /// where an unregister, a departure or a lapsed DEADLINE can release it;
    /// the registry filters nothing.
    #[deprecated(
        since = "1.5.0",
        note = "EXCLUSIVE ownership is arbitrated by each DataReader; the registry filters nothing"
    )]
    #[must_use]
    pub fn check_ownership(
        &self,
        topic_name: &str,
        writer_guid: &[u8; 16],
        instance_hash: u64,
    ) -> bool {
        let _ = (topic_name, writer_guid, instance_hash);
        true
    }

    /// Fallback GUID->topic mapping for interop scenarios where remote writers
    /// do not announce SEDP Publications, but there is a single local topic
    /// with active subscribers.
    ///
    /// Enabled via `HDDS_ROUTE_UNKNOWN_WRITER_TO_SINGLE_TOPIC=1` environment variable.
    /// When enabled, if there is exactly one topic with subscribers, unknown writer
    /// GUIDs will be automatically bound to that topic and future DATA packets will
    /// be routed correctly.
    ///
    /// This is useful for:
    /// - Multi-machine setups where SEDP may not be delivered reliably
    /// - Testing scenarios with minimal discovery
    /// - Interop with stacks that don't send SEDP Publications
    pub fn fallback_map_unknown_writer_to_single_topic(&self, guid: [u8; 16]) -> Option<String> {
        // DISABLED unless the operator asks for it. The knob is answered
        // once per process (see `config::env_flags`); this call sits on
        // every DATA whose writer GUID is not yet bound to a topic, which
        // during a discovery race is every DATA.
        //
        // The polarity is pinned from BOTH sides by two integration
        // binaries that own their process (the knob is cached, so one
        // process can only see one side): `env_flags_fallback_off_by_default`
        // asserts None on a registry that would otherwise answer Some, and
        // `env_flags_fallback_on_when_set` asserts Some on the same fixture.
        if !crate::config::env_flags::route_unknown_writer_to_single_topic() {
            return None;
        }

        let topics = recover_read(&self.topics, "TopicRegistry::topics.read()");

        // Find topics with at least one subscriber
        let topics_with_subs: Vec<_> = topics
            .values()
            .filter(|t| t.subscriber_count() > 0)
            .collect();

        if topics_with_subs.len() == 1 {
            let topic_name = topics_with_subs[0].name().to_string();
            drop(topics); // Release read lock before acquiring write lock

            // Register this GUID -> topic mapping for future packets
            self.register_writer_guid(guid, topic_name.clone());

            log::debug!(
                "[REGISTRY] fallback_route: bound unknown writer GUID {:02x?} -> topic '{}'",
                &guid[..],
                topic_name
            );
            Some(topic_name)
        } else {
            log::debug!(
                "[REGISTRY] fallback_route: cannot bind GUID {:02x?}, {} topics with subscribers",
                &guid[..],
                topics_with_subs.len()
            );
            None
        }
    }

    #[must_use]
    #[inline]
    pub fn deliver_heartbeat(&self, heartbeat_bytes: &[u8], origin: Option<Origin>) -> usize {
        self.each_heartbeat_handler(|handler| handler.on_heartbeat(heartbeat_bytes, origin))
    }

    /// [`deliver_heartbeat`](Self::deliver_heartbeat) for HEARTBEATs that
    /// arrived on `connection` (see [`HeartbeatHandler::on_heartbeat_over_stream`]).
    #[must_use]
    pub fn deliver_heartbeat_over_stream(
        &self,
        heartbeat_bytes: &[u8],
        connection: &dyn StreamReply,
    ) -> usize {
        self.each_heartbeat_handler(|handler| {
            handler.on_heartbeat_over_stream(heartbeat_bytes, connection);
        })
    }

    /// Run `deliver` for every heartbeat handler; the number that panicked.
    fn each_heartbeat_handler(&self, deliver: impl Fn(&dyn HeartbeatHandler)) -> usize {
        // Clone the Arc list under the read guard, then drop the guard
        // before dispatching: `HeartbeatHandlerToken::drop` takes a WRITE
        // lock on this same `RwLock` to unregister itself, so a handler
        // that drops its own token from inside `on_heartbeat` (e.g. a
        // reader tearing itself down in reaction to a heartbeat) would
        // deadlock against a read guard held across the callback loop.
        let handlers: Vec<Arc<dyn HeartbeatHandler>> = {
            let guard = recover_read(
                &self.heartbeat_handlers,
                "TopicRegistry::heartbeat_handlers.read()",
            );
            guard
                .iter()
                .map(|(_id, handler)| Arc::clone(handler))
                .collect()
        };
        let mut errors = 0;

        for handler in &handlers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                deliver(handler.as_ref());
            }));

            if result.is_err() {
                errors += 1;
                log::debug!("[demux] Heartbeat handler panicked");
            }
        }

        errors
    }

    /// Deliver one parsed ACKNACK to every nack handler; each keeps only
    /// the ones naming its writer (see [`NackHandler::on_acknack`]).
    #[must_use]
    pub fn deliver_acknack(
        &self,
        reader_guid: [u8; 16],
        acknack: &crate::core::discovery::multicast::control_types::AckNackInfo,
    ) -> usize {
        let handlers = recover_read(&self.nack_handlers, "TopicRegistry::nack_handlers.read()");
        let mut errors = 0;
        for (_, handler) in handlers.iter() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handler.on_acknack(reader_guid, acknack);
            }));
            if result.is_err() {
                errors += 1;
                log::debug!("[demux] ACKNACK handler panicked");
            }
        }
        errors
    }

    #[must_use]
    #[inline]
    pub fn deliver_nack(&self, nack_bytes: &[u8], reader_guid: Option<[u8; 16]>) -> usize {
        let handlers = recover_read(&self.nack_handlers, "TopicRegistry::nack_handlers.read()");
        let mut errors = 0;

        // Log handler count to track registration issues
        log::debug!(
            "[demux] deliver_nack called with {} bytes, {} handlers registered, reader_guid={:?}",
            nack_bytes.len(),
            handlers.len(),
            reader_guid.map(|g| format!("{:02x?}", &g[..4]))
        );

        for (_, handler) in handlers.iter() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handler.on_nack(nack_bytes, reader_guid);
            }));

            if result.is_err() {
                errors += 1;
                log::debug!("[demux] NACK handler panicked");
            }
        }

        errors
    }

    #[must_use]
    #[inline]
    pub fn deliver_nack_frag(
        &self,
        writer_entity_id: &[u8; 4],
        writer_sn: u64,
        missing_fragments: &[u32],
        reader_guid: Option<[u8; 16]>,
    ) -> usize {
        let handlers = recover_read(
            &self.nack_frag_handlers,
            "TopicRegistry::nack_frag_handlers.read()",
        );
        let mut errors = 0;

        log::debug!(
            "[demux] deliver_nack_frag: writer_eid={:02x?} sn={} frags={:?}, {} handlers, reader_guid={:?}",
            writer_entity_id,
            writer_sn,
            missing_fragments,
            handlers.len(),
            reader_guid.map(|g| format!("{:02x?}", &g[..4]))
        );

        for (_, handler) in handlers.iter() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handler.on_nack_frag(writer_entity_id, writer_sn, missing_fragments, reader_guid);
            }));

            if result.is_err() {
                errors += 1;
                log::debug!("[demux] NACK_FRAG handler panicked");
            }
        }

        errors
    }
}

impl Default for TopicRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Error Types
// ============================================================================

use std::fmt;

/// Registry operation errors
#[derive(Debug, Clone)]
pub enum RegistryError {
    TopicNotFound { name: String },
    OperationFailed { reason: String },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::TopicNotFound { name } => write!(f, "Topic not found: {}", name),
            RegistryError::OperationFailed { reason } => write!(f, "Operation failed: {}", reason),
        }
    }
}

impl std::error::Error for RegistryError {}

#[cfg(test)]
mod writer_block_tests {
    #![allow(deprecated)]
    use super::TopicRegistry;

    const W1: [u8; 16] = [1; 16];
    const W2: [u8; 16] = [2; 16];

    /// A block set by hand holds for its writer only, until it is lifted;
    /// the router's check reads the same set.
    #[test]
    fn a_block_by_hand_holds_until_it_is_lifted() {
        let registry = TopicRegistry::new();
        assert!(!registry.blocked_by_hand(&W1), "nothing blocked yet");
        registry.block_writer(W1);
        registry.block_writer(W2);
        assert!(registry.is_writer_blocked(&W1));
        assert!(registry.blocked_by_hand(&W2));
        assert!(!registry.blocked_by_hand(&[3; 16]));
        registry.unblock_writer(W1);
        assert!(!registry.is_writer_blocked(&W1));
        assert!(
            registry.blocked_by_hand(&W2),
            "another writer stays blocked"
        );
        registry.unblock_writer(W2);
        assert!(!registry.blocked_by_hand(&W2));
    }
}

#[cfg(test)]
mod group_writer_terminal_tests {
    use super::{
        DisposeKind, GroupWriterTerminal, Subscriber, TopicRegistry, WriterDeparture,
        WriterGroupContext,
    };
    use crate::protocol::group::GroupDialect;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    const WRITER: [u8; 16] = [0x61; 16];
    const PUBLISHER: [u8; 4] = [0, 0, 0x31, 8];
    const TOPIC: &str = "group-terminal-proof";

    fn announce(registry: &TopicRegistry, writer: [u8; 16]) {
        registry.register_writer_guid(writer, TOPIC.to_string());
        registry.record_writer_group_dialect(writer, GroupDialect::Spec, Some(PUBLISHER));
    }

    fn departed(registry: &TopicRegistry, writer: [u8; 16]) -> bool {
        matches!(
            registry
                .spec_group_writers
                .read()
                .expect("fixture: the class map")
                .get(&writer),
            Some(WriterGroupContext::DepartedSpec(..))
        )
    }

    /// A writer's class settled after its departure keeps the departure: the
    /// check and the write are one step under the class map's write lock, so
    /// no class and no Publisher brings a departed writer back to a live one.
    #[test]
    fn a_class_settled_after_the_departure_leaves_the_writer_departed() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Unheard,
        );
        assert!(
            departed(&registry, WRITER),
            "fixture: an unheard Spec writer"
        );
        registry.settle_writer_group_dialect(WRITER, GroupDialect::Spec, Some([9; 4]));
        registry.settle_writer_group_dialect(WRITER, GroupDialect::Classic, None);
        assert!(
            departed(&registry, WRITER),
            "settled after its departure: still departed"
        );
    }

    /// The legacy key-hash flag settled after its writer's Deleted departure
    /// is not set again: the departure retires the OWNERSHIP record of the
    /// writer before it forgets the flag, and a settle sets the flag only of
    /// a writer that still has one.
    #[test]
    fn a_legacy_flag_settled_after_the_writer_was_deleted_stays_forgotten() {
        let registry = TopicRegistry::new();
        registry
            .register_writer_ownership_kind(WRITER, crate::qos::ownership::OwnershipKind::Shared);
        registry.register_writer_legacy_key_hash(WRITER, true);
        assert!(
            registry.writer_uses_legacy_key_hash(&WRITER),
            "fixture: a legacy writer"
        );
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Deleted,
        );
        assert!(
            !registry.writer_uses_legacy_key_hash(&WRITER),
            "fixture: the deletion forgets the flag"
        );
        registry.settle_writer_legacy_key_hash(WRITER, true);
        assert!(
            !registry.writer_uses_legacy_key_hash(&WRITER),
            "settled after the deletion: not set again"
        );
    }

    /// A writer that was never announced (no OWNERSHIP record) takes no
    /// legacy flag from a settle.
    #[test]
    fn a_legacy_flag_is_not_settled_onto_a_writer_never_announced() {
        let registry = TopicRegistry::new();
        registry.settle_writer_legacy_key_hash(WRITER, true);
        assert!(!registry.writer_uses_legacy_key_hash(&WRITER));
    }

    #[test]
    fn terminal_evidence_requires_a_validated_writer_and_publisher() {
        let registry = TopicRegistry::new();
        assert!(registry.group_writer_terminal(&WRITER, PUBLISHER).is_none());
        registry.register_writer_guid(WRITER, TOPIC.to_string());
        assert!(registry.group_writer_terminal(&WRITER, PUBLISHER).is_none());
        registry.record_writer_group_dialect(WRITER, GroupDialect::Classic, Some(PUBLISHER));
        assert!(registry.group_writer_terminal(&WRITER, PUBLISHER).is_none());
        registry.record_writer_group_dialect(WRITER, GroupDialect::Spec, None);
        assert!(registry.group_writer_terminal(&WRITER, PUBLISHER).is_none());
        registry.record_writer_group_dialect(WRITER, GroupDialect::Spec, Some(PUBLISHER));
        assert!(registry.group_writer_terminal(&WRITER, [9; 4]).is_none());
        let proof = registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap();
        assert!(!proof.is_deleted());
    }

    #[test]
    fn only_explicit_deletion_is_terminal_and_live_discovery_invalidates_the_same_cell() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        let proof = registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap();
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Unheard,
        );
        assert!(!proof.is_deleted(), "an unheard writer can return");
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Deleted,
        );
        assert!(proof.is_deleted());
        assert!(Arc::ptr_eq(
            &proof,
            &registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap()
        ));
        // DATA routing can learn a topic too; it cannot revive a writer.
        registry.register_writer_guid(WRITER, TOPIC.to_string());
        assert!(proof.is_deleted(), "routing is not a live announcement");
        registry.record_writer_group_dialect(WRITER, GroupDialect::Spec, Some(PUBLISHER));
        assert!(
            !proof.is_deleted(),
            "retained evidence survived reannouncement"
        );
        assert!(Arc::ptr_eq(
            &proof,
            &registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap()
        ));
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Deleted,
        );
        assert!(proof.is_deleted());
        registry.record_writer_group_dialect(WRITER, GroupDialect::Classic, None);
        assert!(
            !proof.is_deleted(),
            "a replacement of another class is live too"
        );
        assert!(registry.group_writer_terminal(&WRITER, PUBLISHER).is_none());
    }

    #[test]
    fn an_announced_participant_deletion_marks_even_an_unmatched_writers_proof() {
        let registry = TopicRegistry::new();
        let mut other = WRITER;
        other[15] = 0x62;
        announce(&registry, WRITER);
        announce(&registry, other);
        let first = registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap();
        let second = registry.group_writer_terminal(&other, PUBLISHER).unwrap();
        // No subscriber of either topic is needed for authoritative deletion.
        assert!(registry.topics.read().unwrap().is_empty());
        let count = registry.notify_participant_departure(
            &WRITER[..12].try_into().unwrap(),
            WriterDeparture::Deleted,
        );
        assert_eq!(count, 2);
        assert!(first.is_deleted());
        assert!(
            second.is_deleted(),
            "terminal evidence depended on a matched reader"
        );
    }

    struct DepartureObserver(Box<dyn Fn() + Send + Sync>);

    impl Subscriber for DepartureObserver {
        fn on_data(&self, _: &str, _: u64, _: &[u8]) {}

        fn topic_name(&self) -> &str {
            TOPIC
        }

        fn on_writer_departure(&self, _: &str, _: [u8; 16], _: DisposeKind, _: WriterDeparture) {
            (self.0)();
        }
    }

    #[test]
    fn a_departure_callback_can_acquire_terminal_evidence_before_metadata_retirement() {
        let registry = Arc::new(TopicRegistry::new());
        announce(&registry, WRITER);
        let observed: Arc<Mutex<Option<Arc<GroupWriterTerminal>>>> = Arc::default();
        let saved = observed.clone();
        let weak = Arc::downgrade(&registry);
        registry
            .register_subscriber(Arc::new(DepartureObserver(Box::new(move || {
                *saved.lock().unwrap() = weak
                    .upgrade()
                    .and_then(|registry| registry.group_writer_terminal(&WRITER, PUBLISHER));
            }))))
            .unwrap();
        let (sent, done) = std::sync::mpsc::channel();
        let worker = registry.clone();
        let deleting = std::thread::spawn(move || {
            worker.notify_writer_departure(
                WRITER,
                DisposeKind::Unregistered,
                WriterDeparture::Deleted,
            );
            sent.send(()).unwrap();
        });
        done.recv_timeout(Duration::from_secs(2))
            .expect("terminal proof callback ran under a registry lock");
        deleting.join().unwrap();
        let proof = observed.lock().unwrap().take().expect("terminal evidence");
        assert!(
            proof.is_deleted(),
            "the deletion notice expired before its callback"
        );
        assert!(registry.writer_spec_group(&WRITER).is_none());
        assert!(Arc::ptr_eq(
            &proof,
            &registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap()
        ));
    }

    #[test]
    fn expired_terminal_cells_are_not_kept_as_deleted_guid_tombstones() {
        let registry = TopicRegistry::new();
        for index in 0..128u32 {
            let mut writer = WRITER;
            writer[12..].copy_from_slice(&index.to_be_bytes());
            announce(&registry, writer);
            let proof = registry.group_writer_terminal(&writer, PUBLISHER).unwrap();
            let weak = Arc::downgrade(&proof);
            registry.notify_writer_departure(
                writer,
                DisposeKind::Unregistered,
                WriterDeparture::Deleted,
            );
            assert!(proof.is_deleted());
            assert_eq!(registry.group_writer_terminals.read().unwrap().len(), 1);
            drop(proof);
            assert!(
                weak.upgrade().is_none(),
                "the registry retained terminal evidence"
            );
        }
        registry.record_writer_group_dialect(WRITER, GroupDialect::Classic, None);
        assert!(registry.group_writer_terminals.read().unwrap().is_empty());
    }

    #[test]
    fn aggregate_terminal_proof_excludes_reannouncement_until_its_commit() {
        let registry = TopicRegistry::new();
        let mut other = WRITER;
        other[15] = 0x62;
        announce(&registry, WRITER);
        announce(&registry, other);
        let first = registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap();
        let second = registry.group_writer_terminal(&other, PUBLISHER).unwrap();
        let states = [first, second];
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Deleted,
        );
        assert!(GroupWriterTerminal::all_deleted(&states).is_none());
        registry.notify_writer_departure(
            other,
            DisposeKind::Unregistered,
            WriterDeparture::Deleted,
        );
        let proof = GroupWriterTerminal::all_deleted(&states).expect("all writers terminal");
        assert!(matches!(
            registry.group_writer_terminals.try_write(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        // The receiver's cursor is committed while the proof guard lives.
        drop(proof);
        registry.record_writer_group_dialect(WRITER, GroupDialect::Spec, Some(PUBLISHER));
        assert!(GroupWriterTerminal::all_deleted(&states).is_none());
        assert!(GroupWriterTerminal::all_deleted(&[]).is_none());
    }

    #[test]
    fn terminal_proofs_from_different_registries_are_not_one_roster_snapshot() {
        let first = TopicRegistry::new();
        let second = TopicRegistry::new();
        announce(&first, WRITER);
        announce(&second, WRITER);
        let states = [
            first.group_writer_terminal(&WRITER, PUBLISHER).unwrap(),
            second.group_writer_terminal(&WRITER, PUBLISHER).unwrap(),
        ];
        first.notify_writer_departure(WRITER, DisposeKind::Unregistered, WriterDeparture::Deleted);
        second.notify_writer_departure(WRITER, DisposeKind::Unregistered, WriterDeparture::Deleted);
        assert!(states.iter().all(|state| state.is_deleted()));
        assert!(GroupWriterTerminal::all_deleted(&states).is_none());
    }

    fn publisher_guid() -> [u8; 16] {
        let mut publisher = WRITER;
        publisher[12..].copy_from_slice(&PUBLISHER);
        publisher
    }

    #[test]
    fn an_unvalidated_roster_join_snapshot_resolves_on_lease_departure() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        let joined = registry.snapshot_group_writers(publisher_guid());
        assert_eq!(joined.len(), 1);
        assert_eq!(joined[0].0, WRITER[12..]);
        let states = [joined[0].1.clone()];
        assert!(GroupWriterTerminal::all_departed(&states).is_none());
        registry.notify_participant_departure(
            &WRITER[..12].try_into().unwrap(),
            WriterDeparture::Unheard,
        );
        assert!(
            GroupWriterTerminal::all_departed(&states).is_some(),
            "lease departure must resolve even without a validated roster"
        );
        assert!(
            !states[0].is_deleted(),
            "lease loss does not delete writer identity"
        );
        assert!(
            registry.snapshot_group_writers(publisher_guid()).is_empty(),
            "an already absent writer cannot create new prejoin debt"
        );
        assert!(
            GroupWriterTerminal::all_departed(&[]).is_none(),
            "unknown GSN holes are not departure evidence"
        );
    }

    #[test]
    fn participant_admission_fences_earlier_data_without_publishing_absence() {
        use crate::engine::departures::Departure;
        let registry = TopicRegistry::new();
        let ring = route(&registry);
        announce(&registry, WRITER);
        let mut sibling = WRITER;
        sibling[15] ^= 1;
        announce(&registry, sibling);
        registry.notify_writer_departure(
            sibling,
            DisposeKind::Unregistered,
            WriterDeparture::Unheard,
        );
        let proof = [registry.group_writer_terminal(&sibling, PUBLISHER).unwrap()];
        let old = registry.capture_group_arrival(&WRITER).unwrap();
        registry.post_departure(Departure::Participant {
            prefix: WRITER[..12].try_into().unwrap(),
            cause: WriterDeparture::Unheard,
        });
        assert!(
            !old.0.cell.is_departed(),
            "admission published writer absence before applying the notice"
        );
        assert!(GroupWriterTerminal::all_participant_departed(&proof).is_none());
        assert!(
            !registry.note_group_writer_alive_stamped(&WRITER, &old),
            "pre-admission DATA invalidated the admitted participant notice"
        );
        assert!(ring.pop().is_some());
        registry.apply_next_departure();
        assert!(
            GroupWriterTerminal::all_participant_departed(&proof).is_some(),
            "old DATA permanently stalled genuine participant departure proof"
        );
    }

    #[test]
    fn data_arriving_after_participant_admission_can_revoke_that_notice() {
        use crate::engine::departures::Departure;
        for prior_unheard in [false, true] {
            let registry = TopicRegistry::new();
            let ring = route(&registry);
            announce(&registry, WRITER);
            let mut sibling = WRITER;
            sibling[15] ^= 1;
            announce(&registry, sibling);
            if prior_unheard {
                registry.notify_writer_departure(
                    sibling,
                    DisposeKind::Unregistered,
                    WriterDeparture::Unheard,
                );
            }
            let proof = [registry.group_writer_terminal(&sibling, PUBLISHER).unwrap()];
            registry.post_departure(Departure::Participant {
                prefix: WRITER[..12].try_into().unwrap(),
                cause: WriterDeparture::Unheard,
            });
            let fresh = registry.capture_group_arrival(&WRITER).unwrap();
            assert!(registry.note_group_writer_alive_stamped(&WRITER, &fresh));
            assert!(ring.pop().is_some());
            registry.apply_next_departure();
            assert!(GroupWriterTerminal::all_participant_departed(&proof).is_none(), "post-admission activity failed to invalidate its older notice (prior_unheard={prior_unheard})");
            assert!(
                proof[0].is_departed(),
                "another writer's return erased individual departure"
            );
        }
    }

    #[test]
    fn data_arriving_before_a_writer_departure_cannot_revoke_its_proof() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        let old = registry.capture_group_arrival(&WRITER).unwrap();
        let proof = old.0.cell.clone();
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Unheard,
        );
        assert!(proof.is_departed());
        assert!(
            !registry.note_group_writer_alive_stamped(&WRITER, &old),
            "old decoded DATA revoked a newer departure"
        );
        assert!(proof.is_departed());
        let fresh = registry.capture_group_arrival(&WRITER).unwrap();
        assert!(registry.note_group_writer_alive_stamped(&WRITER, &fresh));
        assert!(
            !proof.is_departed(),
            "fresh post-departure DATA did not revive its writer"
        );
    }

    #[test]
    fn old_sibling_data_cannot_revoke_a_new_participant_proof() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        let mut sibling = WRITER;
        sibling[15] ^= 1;
        announce(&registry, sibling);
        let proof = [registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap()];
        // Pause a real participant notice after its first writer's proof is
        // published, before the sibling's notification reaches the Source.
        let admitted =
            registry.capture_group_participant_departures(&WRITER[..12].try_into().unwrap());
        let old = registry.capture_group_arrival(&sibling).unwrap();
        let notice = admitted
            .iter()
            .find(|notice| notice.guid == WRITER)
            .unwrap();
        registry
            .mark_group_writer_departed(notice, WriterDeparture::Unheard)
            .unwrap();
        assert!(GroupWriterTerminal::all_participant_departed(&proof).is_some());
        assert!(
            !registry.note_group_writer_alive_stamped(&sibling, &old),
            "old sibling DATA erased a later participant proof"
        );
        assert!(GroupWriterTerminal::all_participant_departed(&proof).is_some());
        let fresh = registry.capture_group_arrival(&sibling).unwrap();
        assert!(registry.note_group_writer_alive_stamped(&sibling, &fresh));
        assert!(
            proof[0].is_departed(),
            "a sibling return revived an individual writer"
        );
        assert!(GroupWriterTerminal::all_participant_departed(&proof).is_none());
    }

    #[test]
    fn independent_departures_do_not_stale_an_unaffected_arrival() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        let stamp = registry.capture_group_arrival(&WRITER).unwrap();
        let mut sibling = WRITER;
        sibling[15] ^= 1;
        announce(&registry, sibling);
        registry.notify_writer_departure(
            sibling,
            DisposeKind::Unregistered,
            WriterDeparture::Unheard,
        );
        let sibling_proof = registry.group_writer_terminal(&sibling, PUBLISHER).unwrap();
        assert!(
            registry.note_group_writer_alive_stamped(&WRITER, &stamp),
            "individual sibling loss invalidated an unrelated arrival"
        );
        assert!(sibling_proof.is_departed());
        let fresh = registry.capture_group_arrival(&WRITER).unwrap();
        let mut unrelated = WRITER;
        unrelated[0] ^= 1;
        announce(&registry, unrelated);
        registry.notify_participant_departure(
            &unrelated[..12].try_into().unwrap(),
            WriterDeparture::Unheard,
        );
        assert!(
            registry.note_group_writer_alive_stamped(&WRITER, &fresh),
            "another participant invalidated an arrival"
        );
        assert!(sibling_proof.is_departed());
    }

    #[test]
    fn shared_arrival_application_is_idempotent_but_not_after_another_proof() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        let mut sibling = WRITER;
        sibling[15] ^= 1;
        announce(&registry, sibling);
        registry.notify_writer_departure(
            sibling,
            DisposeKind::Unregistered,
            WriterDeparture::Unheard,
        );
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Unheard,
        );
        let first = registry.capture_group_arrival(&WRITER).unwrap();
        let other = first.clone();
        assert!(Arc::ptr_eq(&first.0, &other.0));
        assert!(registry.note_group_writer_alive_stamped(&WRITER, &first));
        let generation = registry.group_writer_terminals.read().unwrap()[&WRITER].generation;
        let participant_generation =
            registry.group_writer_terminals.read().unwrap()[&WRITER].participant_generation;
        assert!(
            registry.note_group_writer_alive_stamped(&WRITER, &other),
            "a second recipient rejected the same accepted event"
        );
        assert_eq!(
            registry.group_writer_terminals.read().unwrap()[&WRITER].generation,
            generation
        );
        assert_eq!(
            registry.group_writer_terminals.read().unwrap()[&WRITER].participant_generation,
            participant_generation
        );
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Unheard,
        );
        assert!(
            !registry.note_group_writer_alive_stamped(&WRITER, &other),
            "cached event acceptance ignored a later proof"
        );
        assert!(first.0.cell.is_departed());
    }

    #[test]
    fn capture_and_applied_arrivals_both_expire_at_reannouncement() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        let before = registry.capture_group_arrival(&WRITER).unwrap();
        let applied = registry.capture_group_arrival(&WRITER).unwrap();
        assert!(registry.note_group_writer_alive_stamped(&WRITER, &applied));
        announce(&registry, WRITER);
        assert!(!registry.note_group_writer_alive_stamped(&WRITER, &before));
        assert!(!registry.note_group_writer_alive_stamped(&WRITER, &applied));
        let fresh = registry.capture_group_arrival(&WRITER).unwrap();
        assert!(registry.note_group_writer_alive_stamped(&WRITER, &fresh));
    }

    #[test]
    fn arrivals_pin_only_known_writer_cells_and_keep_registry_identity() {
        let registry = TopicRegistry::new();
        assert!(registry.capture_group_arrival(&WRITER).is_none());
        assert!(registry.group_writer_terminals.read().unwrap().is_empty());
        announce(&registry, WRITER);
        let stamp = registry.capture_group_arrival(&WRITER).unwrap();
        let weak = Arc::downgrade(&stamp.0.cell);
        registry.prune_group_writer_terminals();
        assert!(registry
            .group_writer_terminals
            .read()
            .unwrap()
            .contains_key(&WRITER));
        let foreign = TopicRegistry::new();
        announce(&foreign, WRITER);
        let _foreign_cell = foreign.group_writer_terminal(&WRITER, PUBLISHER).unwrap();
        assert!(!foreign.note_group_writer_alive_stamped(&WRITER, &stamp));
        let mut sibling = WRITER;
        sibling[15] ^= 1;
        announce(&registry, sibling);
        let _sibling_cell = registry.group_writer_terminal(&sibling, PUBLISHER).unwrap();
        assert!(!registry.note_group_writer_alive_stamped(&sibling, &stamp));
        assert!(registry.note_group_writer_alive_stamped(&WRITER, &stamp));
        drop(stamp);
        registry.prune_group_writer_terminals();
        assert!(weak.upgrade().is_none());
        assert!(!registry
            .group_writer_terminals
            .read()
            .unwrap()
            .contains_key(&WRITER));
    }

    #[test]
    fn availability_revision_exhaustion_never_wraps_or_leaves_usable_proof() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        let stamp = registry.capture_group_arrival(&WRITER).unwrap();
        registry
            .group_writer_terminals
            .write()
            .unwrap()
            .get_mut(&WRITER)
            .unwrap()
            .availability_revision = Some(u64::MAX);
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Unheard,
        );
        assert!(!registry.note_group_writer_alive_stamped(&WRITER, &stamp));
        assert!(registry.capture_group_arrival(&WRITER).is_none());
        assert!(
            !stamp.0.cell.is_departed(),
            "an exhausted arrival identity left consumable writer absence"
        );
        assert!(GroupWriterTerminal::all_departed(std::slice::from_ref(&stamp.0.cell)).is_none());
    }

    #[test]
    fn a_revival_exhausting_writer_generation_cannot_accept_an_arrival() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        let proof = registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap();
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Unheard,
        );
        registry
            .group_writer_terminals
            .write()
            .unwrap()
            .get_mut(&WRITER)
            .unwrap()
            .generation = u64::MAX;
        let stamp = registry.capture_group_arrival(&WRITER).unwrap();
        assert!(
            !registry.note_group_writer_alive_stamped(&WRITER, &stamp),
            "an exhausted revival accepted one recipient but refused the next"
        );
        assert!(!registry.note_group_writer_alive_stamped(&WRITER, &stamp));
        assert!(!proof.is_departed());
        assert!(registry.capture_group_arrival(&WRITER).is_none());
        let mut sibling = WRITER;
        sibling[15] ^= 1;
        announce(&registry, sibling);
        let sibling_proof = [registry.group_writer_terminal(&sibling, PUBLISHER).unwrap()];
        registry.notify_participant_departure(
            &WRITER[..12].try_into().unwrap(),
            WriterDeparture::Unheard,
        );
        assert!(
            GroupWriterTerminal::all_participant_departed(&sibling_proof).is_none(),
            "an unrevivable sibling left consumable whole-participant absence"
        );
    }

    #[test]
    fn exhausted_sibling_availability_suppresses_participant_scope_only() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        let mut sibling = WRITER;
        sibling[15] ^= 1;
        announce(&registry, sibling);
        let stamp = registry.capture_group_arrival(&sibling).unwrap();
        let proof = [registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap()];
        registry
            .group_writer_terminals
            .write()
            .unwrap()
            .get_mut(&sibling)
            .unwrap()
            .availability_revision = Some(u64::MAX);
        let mut admitted =
            registry.capture_group_writer_departures(|writer| writer[..12] == WRITER[..12]);
        for notice in &mut admitted {
            notice.participant = true;
        }
        let notice = admitted
            .iter()
            .find(|notice| notice.guid == WRITER)
            .unwrap();
        registry
            .mark_group_writer_departed(notice, WriterDeparture::Unheard)
            .unwrap();
        assert!(
            proof[0].is_departed(),
            "sibling exhaustion erased valid individual absence"
        );
        assert!(
            GroupWriterTerminal::all_participant_departed(&proof).is_none(),
            "an exhausted sibling could not revoke consumable participant proof"
        );
        assert!(!registry.note_group_writer_alive_stamped(&sibling, &stamp));
        assert!(registry.capture_group_arrival(&sibling).is_none());
    }

    #[test]
    fn a_sibling_announcement_revokes_only_participant_departure_evidence() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        let proof = [registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap()];
        registry.notify_participant_departure(
            &WRITER[..12].try_into().unwrap(),
            WriterDeparture::Unheard,
        );
        assert!(GroupWriterTerminal::all_participant_departed(&proof).is_some());
        let mut sibling = WRITER;
        sibling[15] ^= 1;
        announce(&registry, sibling);
        assert!(
            proof[0].is_departed(),
            "sibling return erased individual writer departure"
        );
        assert!(
            GroupWriterTerminal::all_participant_departed(&proof).is_none(),
            "a live sibling retained whole-participant absence proof"
        );
        registry.notify_participant_departure(
            &WRITER[..12].try_into().unwrap(),
            WriterDeparture::Unheard,
        );
        assert!(GroupWriterTerminal::all_participant_departed(&proof).is_some());
        let mut unrelated = WRITER;
        unrelated[0] ^= 1;
        announce(&registry, unrelated);
        assert!(
            GroupWriterTerminal::all_participant_departed(&proof).is_some(),
            "another participant revoked this participant's proof"
        );
    }

    #[test]
    fn a_siblings_accepted_traffic_revokes_participant_proof_without_sedp() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        let mut sibling = WRITER;
        sibling[15] ^= 1;
        announce(&registry, sibling);
        let proof = [registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap()];
        // Pause a participant notice after the first writer is marked and
        // before its sibling is marked; that sibling still has live context.
        let mut admitted = registry.capture_group_writer_departures(|writer| *writer == WRITER);
        admitted[0].participant = true;
        assert!(registry
            .mark_group_writer_departed(&admitted[0], WriterDeparture::Unheard)
            .is_some());
        assert!(GroupWriterTerminal::all_participant_departed(&proof).is_some());
        registry.note_group_writer_alive(&sibling);
        assert!(proof[0].is_departed());
        assert!(
            GroupWriterTerminal::all_participant_departed(&proof).is_none(),
            "accepted traffic from a live-context sibling did not revoke participant evidence"
        );
    }

    #[test]
    fn a_queued_participant_notice_cannot_outlive_a_sibling_announcement() {
        use crate::engine::departures::Departure;
        let registry = TopicRegistry::new();
        let ring = route(&registry);
        announce(&registry, WRITER);
        let proof = [registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap()];
        registry.post_departure(Departure::Participant {
            prefix: WRITER[..12].try_into().unwrap(),
            cause: WriterDeparture::Unheard,
        });
        let mut sibling = WRITER;
        sibling[15] ^= 1;
        announce(&registry, sibling);
        assert!(ring.pop().is_some());
        registry.apply_next_departure();
        assert!(
            proof[0].is_departed(),
            "the sibling did not revive the departed writer"
        );
        assert!(
            GroupWriterTerminal::all_participant_departed(&proof).is_none(),
            "an admitted notice reasserted a revoked participant generation"
        );
    }

    #[test]
    fn a_sibling_announcement_preserves_an_admitted_individual_deletion() {
        use crate::engine::departures::Departure;
        let registry = TopicRegistry::new();
        let ring = route(&registry);
        announce(&registry, WRITER);
        let proof = registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap();
        registry.post_departure(Departure::Writer {
            guid: WRITER,
            kind: DisposeKind::Unregistered,
            cause: WriterDeparture::Deleted,
        });
        let mut sibling = WRITER;
        sibling[15] ^= 1;
        announce(&registry, sibling);
        assert!(ring.pop().is_some());
        registry.apply_next_departure();
        assert!(
            proof.is_deleted(),
            "unrelated writer activity revoked an individual deletion"
        );
        assert_eq!(registry.writer_spec_group(&sibling), Some(PUBLISHER));
    }

    #[test]
    fn sibling_activity_revokes_participant_metadata_after_cell_expiry() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        registry.notify_participant_departure(
            &WRITER[..12].try_into().unwrap(),
            WriterDeparture::Unheard,
        );
        let mut sibling = WRITER;
        sibling[15] ^= 1;
        announce(&registry, sibling);
        let proof = [registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap()];
        assert!(proof[0].is_departed());
        assert!(
            GroupWriterTerminal::all_participant_departed(&proof).is_none(),
            "weak-cell metadata recreated a revoked participant proof"
        );
    }

    #[test]
    fn participant_departure_generations_never_wrap_to_an_old_notice() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        let proof = [registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap()];
        let mut admitted = registry.capture_group_writer_departures(|writer| *writer == WRITER);
        admitted[0].participant = true;
        registry
            .group_writer_terminals
            .write()
            .unwrap()
            .get_mut(&WRITER)
            .unwrap()
            .participant_generation = Some(u64::MAX);
        let mut sibling = WRITER;
        sibling[15] ^= 1;
        announce(&registry, sibling);
        assert!(registry
            .mark_group_writer_departed(&admitted[0], WriterDeparture::Unheard)
            .is_some());
        assert!(proof[0].is_departed());
        assert!(
            GroupWriterTerminal::all_participant_departed(&proof).is_none(),
            "participant counter exhaustion accepted an old notice"
        );
    }

    #[test]
    fn a_departure_callback_reannouncement_keeps_replacement_metadata() {
        let registry = Arc::new(TopicRegistry::new());
        announce(&registry, WRITER);
        let proof = registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap();
        let weak = Arc::downgrade(&registry);
        registry
            .register_subscriber(Arc::new(DepartureObserver(Box::new(move || {
                let registry = weak.upgrade().unwrap();
                announce(&registry, WRITER);
                registry.register_writer_lifespan_of(TOPIC, WRITER, 77);
                registry.register_writer_ownership_strength(WRITER, 91);
            }))))
            .unwrap();
        let worker = registry.clone();
        let (sent, done) = std::sync::mpsc::channel();
        let departing = std::thread::spawn(move || {
            worker.notify_writer_departure(
                WRITER,
                DisposeKind::Unregistered,
                WriterDeparture::Deleted,
            );
            sent.send(()).unwrap();
        });
        done.recv_timeout(Duration::from_secs(2))
            .expect("departure callback could not reannounce its writer");
        departing.join().unwrap();
        assert!(
            !proof.is_departed(),
            "replacement retained old departure evidence"
        );
        assert_eq!(
            registry.writer_spec_group(&WRITER),
            Some(PUBLISHER),
            "old cleanup retired replacement GROUP metadata"
        );
        assert_eq!(
            registry.writer_lifespan(&WRITER),
            Some(77),
            "old cleanup retired replacement lifespan"
        );
        assert_eq!(
            registry
                .writer_ownership_strengths
                .read()
                .unwrap()
                .get(&WRITER),
            Some(&91),
            "old cleanup retired replacement ownership strength"
        );
    }

    #[test]
    fn a_recreated_per_writer_notice_never_becomes_participant_proof() {
        use crate::engine::departures::Departure;
        let registry = TopicRegistry::new();
        let ring = route(&registry);
        announce(&registry, WRITER);
        // No reader retains the first departure cell. Only durable writer
        // context survives when the next queued notice recreates its cell.
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Unheard,
        );
        registry.post_departure(Departure::Writer {
            guid: WRITER,
            kind: DisposeKind::Unregistered,
            cause: WriterDeparture::Unheard,
        });
        let recreated = [registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap()];
        assert!(GroupWriterTerminal::all_departed(&recreated).is_some());
        assert!(
            GroupWriterTerminal::all_participant_departed(&recreated).is_none(),
            "a recreated writer notice widened its proof to the whole participant"
        );
        assert!(ring.pop().is_some());
        registry.apply_next_departure();
        assert!(GroupWriterTerminal::all_participant_departed(&recreated).is_none());
        registry.notify_participant_departure(
            &WRITER[..12].try_into().unwrap(),
            WriterDeparture::Unheard,
        );
        assert!(GroupWriterTerminal::all_participant_departed(&recreated).is_some());
    }

    #[test]
    fn individual_departures_do_not_prove_an_unknown_publishers_roster_gone() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        let proof = registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap();
        let states = [proof];
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Unheard,
        );
        assert!(GroupWriterTerminal::all_departed(&states).is_some());
        assert!(
            GroupWriterTerminal::all_participant_departed(&states).is_none(),
            "a missing writer may still belong to this live participant"
        );
        registry.notify_participant_departure(
            &WRITER[..12].try_into().unwrap(),
            WriterDeparture::Unheard,
        );
        assert!(GroupWriterTerminal::all_participant_departed(&states).is_some());
        drop(states);
        let recreated = [registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap()];
        assert!(
            GroupWriterTerminal::all_participant_departed(&recreated).is_some(),
            "durable metadata lost participant departure after weak cell cleanup"
        );
        registry.note_group_writer_alive(&WRITER);
        assert!(GroupWriterTerminal::all_participant_departed(&recreated).is_none());
    }

    #[test]
    fn join_snapshot_never_acquires_writers_announced_after_join() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        let joined = registry.snapshot_group_writers(publisher_guid());
        let mut later = WRITER;
        later[15] ^= 1;
        announce(&registry, later);
        assert_eq!(registry.snapshot_group_writers(publisher_guid()).len(), 2);
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Deleted,
        );
        assert!(
            joined[0].1.is_departed(),
            "captured witness survived retirement"
        );
        assert!(GroupWriterTerminal::all_departed(&[joined[0].1.clone()]).is_some());
        assert!(!registry
            .group_writer_terminal(&later, PUBLISHER)
            .unwrap()
            .is_departed());
    }

    #[test]
    fn a_queued_lease_departure_cannot_mark_a_reannounced_writer() {
        use crate::engine::departures::Departure;
        let registry = TopicRegistry::new();
        let ring = route(&registry);
        announce(&registry, WRITER);
        let joined = registry.snapshot_group_writers(publisher_guid());
        registry.post_departure(Departure::Participant {
            prefix: WRITER[..12].try_into().unwrap(),
            cause: WriterDeparture::Unheard,
        });
        announce(&registry, WRITER);
        assert!(ring.pop().is_some());
        registry.apply_next_departure();
        assert!(
            !joined[0].1.is_departed(),
            "an old lease proof outlived reannouncement"
        );
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Unheard,
        );
        assert!(
            joined[0].1.is_departed(),
            "current lease proof was not delivered"
        );
    }

    #[test]
    fn accepted_group_traffic_revokes_an_unheard_witness_without_sedp() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        let proof = registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap();
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Unheard,
        );
        assert!(proof.is_departed());
        registry.note_group_writer_alive(&WRITER);
        assert!(
            !proof.is_departed(),
            "accepted traffic retained stale lease evidence"
        );
        assert_eq!(registry.snapshot_group_writers(publisher_guid()).len(), 1);
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Deleted,
        );
        registry.note_group_writer_alive(&WRITER);
        assert!(
            proof.is_deleted(),
            "data cannot revive an explicitly deleted endpoint"
        );
        assert!(proof.is_departed());
    }

    #[test]
    fn lease_evidence_survives_cell_recreation_and_uses_one_commit_guard() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Unheard,
        );
        let proof = registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap();
        assert!(proof.is_departed(), "weak cell cleanup lost lease evidence");
        let states = [proof];
        let guard = GroupWriterTerminal::all_departed(&states).expect("departure proof");
        assert!(matches!(
            registry.group_writer_terminals.try_write(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        drop(guard);
        registry.note_group_writer_alive(&WRITER);
        assert!(GroupWriterTerminal::all_departed(&states).is_none());
    }

    struct GroupDepartureObserver {
        topic: &'static str,
        ordered: bool,
        notify: Box<dyn Fn([u8; 16], [u8; 4]) + Send + Sync>,
    }

    impl Subscriber for GroupDepartureObserver {
        fn on_data(&self, _: &str, _: u64, _: &[u8]) {}
        fn topic_name(&self) -> &str {
            self.topic
        }
        fn requires_ordered_group(&self) -> bool {
            self.ordered
        }
        fn on_group_writer_departure(&self, writer: [u8; 16], publisher: [u8; 4]) {
            (self.notify)(writer, publisher);
        }
    }

    #[test]
    fn departure_wakes_ordered_readers_on_other_topics_outside_registry_locks() {
        let registry = Arc::new(TopicRegistry::new());
        announce(&registry, WRITER);
        let proof = registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap();
        let (sent, done) = std::sync::mpsc::channel();
        let weak = Arc::downgrade(&registry);
        registry
            .register_subscriber(Arc::new(GroupDepartureObserver {
                topic: "other-group-topic",
                ordered: true,
                notify: Box::new(move |writer, publisher| {
                    let registry = weak.upgrade().unwrap();
                    assert!(
                        registry.topics.try_write().is_ok(),
                        "topic registry held in callback"
                    );
                    assert!(
                        registry.group_writer_terminals.try_write().is_ok(),
                        "proof domain held in callback"
                    );
                    sent.send((writer, publisher)).unwrap();
                }),
            }))
            .unwrap();
        let unexpected = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for topic in ["other-group-topic", "unrelated-topic"] {
            let observed = unexpected.clone();
            registry
                .register_subscriber(Arc::new(GroupDepartureObserver {
                    topic,
                    ordered: false,
                    notify: Box::new(move |_, _| {
                        observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }),
                }))
                .unwrap();
        }
        let worker = registry.clone();
        let departing = std::thread::spawn(move || {
            worker.notify_writer_departure(
                WRITER,
                DisposeKind::Unregistered,
                WriterDeparture::Unheard,
            )
        });
        assert_eq!(
            done.recv_timeout(Duration::from_secs(2))
                .expect("sibling reader never woke"),
            (WRITER, PUBLISHER)
        );
        departing.join().unwrap();
        assert_eq!(
            unexpected.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a non-GROUP registration received a GROUP-only callback"
        );
        assert!(proof.is_departed());
    }

    fn route(
        registry: &TopicRegistry,
    ) -> Arc<crossbeam::queue::ArrayQueue<(crate::core::discovery::multicast::RxMeta, u8)>> {
        let ring = Arc::new(crossbeam::queue::ArrayQueue::new(8));
        registry.set_departure_route(Arc::new(crate::engine::departures::DepartureRoute::new(
            ring.clone(),
            None,
        )));
        ring
    }

    #[test]
    fn a_queued_deletion_does_not_mark_a_reannounced_writer_terminal() {
        use crate::engine::departures::Departure;
        let registry = TopicRegistry::new();
        let ring = route(&registry);
        announce(&registry, WRITER);
        let notifications = Arc::new(Mutex::new(0usize));
        let observed = notifications.clone();
        registry
            .register_subscriber(Arc::new(DepartureObserver(Box::new(move || {
                *observed.lock().unwrap() += 1;
            }))))
            .unwrap();
        let proof = registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap();
        registry.post_departure(Departure::Writer {
            guid: WRITER,
            kind: DisposeKind::Unregistered,
            cause: WriterDeparture::Deleted,
        });
        registry.record_writer_group_dialect(WRITER, GroupDialect::Spec, Some(PUBLISHER));
        assert!(ring.pop().is_some());
        registry.apply_next_departure();
        assert_eq!(
            *notifications.lock().unwrap(),
            0,
            "a stale notice reached the replacement reader"
        );
        assert!(
            !proof.is_deleted(),
            "an older fence deleted the replacement proof"
        );
        assert_eq!(
            registry.writer_spec_group(&WRITER),
            Some(PUBLISHER),
            "an older fence retired replacement metadata"
        );
        assert!(registry
            .pending_group_writer_departures
            .read()
            .unwrap()
            .is_empty());
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Deleted,
        );
        assert!(
            proof.is_deleted(),
            "a new deletion must still resolve the proof"
        );
        assert_eq!(
            *notifications.lock().unwrap(),
            1,
            "a current deletion did not reach its reader"
        );
    }

    #[test]
    fn a_queued_participant_deletion_owns_only_its_admitted_writer_generations() {
        use crate::engine::departures::Departure;
        let registry = TopicRegistry::new();
        let ring = route(&registry);
        announce(&registry, WRITER);
        let first = registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap();
        registry.post_departure(Departure::Participant {
            prefix: WRITER[..12].try_into().unwrap(),
            cause: WriterDeparture::Deleted,
        });
        announce(&registry, WRITER);
        let mut other = WRITER;
        other[15] = 0x62;
        announce(&registry, other);
        let second = registry.group_writer_terminal(&other, PUBLISHER).unwrap();
        assert!(ring.pop().is_some());
        registry.apply_next_departure();
        assert!(!first.is_deleted(), "the queued incarnation was replaced");
        assert!(
            !second.is_deleted(),
            "the writer did not exist at departure admission"
        );
        assert!(registry
            .pending_group_writer_departures
            .read()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_deletion_admitted_without_group_context_cannot_delete_a_later_group_writer() {
        use crate::engine::departures::Departure;
        let registry = TopicRegistry::new();
        let ring = route(&registry);
        registry.post_departure(Departure::Writer {
            guid: WRITER,
            kind: DisposeKind::Unregistered,
            cause: WriterDeparture::Deleted,
        });
        announce(&registry, WRITER);
        let proof = registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap();
        assert!(ring.pop().is_some());
        registry.apply_next_departure();
        assert!(
            !proof.is_deleted(),
            "missing admission evidence was fabricated at apply"
        );
    }

    #[test]
    fn a_roster_can_retain_a_queued_deletions_original_evidence_before_apply() {
        use crate::engine::departures::Departure;
        let registry = TopicRegistry::new();
        let ring = route(&registry);
        announce(&registry, WRITER);
        registry.post_departure(Departure::Writer {
            guid: WRITER,
            kind: DisposeKind::Unregistered,
            cause: WriterDeparture::Deleted,
        });
        // The earlier DATA may validate its roster while the deletion waits.
        let proof = registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap();
        assert!(!proof.is_deleted());
        assert!(ring.pop().is_some());
        registry.apply_next_departure();
        assert!(proof.is_deleted());
        assert!(registry
            .pending_group_writer_departures
            .read()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn exhausted_terminal_generations_remain_unknown_instead_of_wrapping() {
        let registry = TopicRegistry::new();
        announce(&registry, WRITER);
        let proof = registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap();
        registry
            .group_writer_terminals
            .write()
            .unwrap()
            .get_mut(&WRITER)
            .unwrap()
            .generation = u64::MAX;
        let pending = registry.capture_group_writer_departures(|guid| *guid == WRITER);
        registry.record_writer_group_dialect(WRITER, GroupDialect::Spec, Some(PUBLISHER));
        assert!(registry
            .mark_group_writer_departed(&pending[0], WriterDeparture::Deleted)
            .is_none());
        registry.notify_writer_departure(
            WRITER,
            DisposeKind::Unregistered,
            WriterDeparture::Deleted,
        );
        assert!(!proof.is_deleted());
    }

    #[test]
    fn queued_terminal_evidence_has_no_ownership_cycle_with_its_registry() {
        use crate::engine::departures::Departure;
        let registry = TopicRegistry::new();
        let _ring = route(&registry);
        announce(&registry, WRITER);
        registry.post_departure(Departure::Writer {
            guid: WRITER,
            kind: DisposeKind::Unregistered,
            cause: WriterDeparture::Deleted,
        });
        let proof = registry.group_writer_terminal(&WRITER, PUBLISHER).unwrap();
        let weak = Arc::downgrade(&proof);
        let domain = Arc::downgrade(&registry.group_writer_terminals);
        drop(proof);
        drop(registry);
        assert!(weak.upgrade().is_none());
        assert!(domain.upgrade().is_none());
    }
}

#[cfg(test)]
mod writer_retirement_tests {
    use super::{DisposeKind, TopicRegistry, WriterDeparture};
    use crate::qos::ownership::OwnershipKind;

    const W: [u8; 16] = [7; 16];
    const TOPIC: &str = "writer-retirement";

    fn registered() -> TopicRegistry {
        let registry = TopicRegistry::new();
        registry.register_writer_guid(W, TOPIC.to_string());
        registry.register_writer_ownership_kind(W, OwnershipKind::Exclusive);
        registry.register_writer_partition(W, crate::qos::partition::Partition::single("a"));
        registry.register_writer_ownership_strength(W, 7);
        registry.register_writer_lifespan_of(TOPIC, W, 1_000_000);
        registry
    }

    /// A writer that fell `Unheard` (its participant's lease expired, a
    /// probation purge) keeps every durable record except its lifespan:
    /// it may come back under the same GUID with no new SEDP at all, and
    /// these are exactly what keeps it resolvable when it does.
    #[test]
    fn an_unheard_departure_keeps_ownership_and_routing() {
        let registry = registered();
        registry.notify_writer_departure(W, DisposeKind::Unregistered, WriterDeparture::Unheard);
        assert_eq!(
            registry.writer_partition(&W),
            Some(crate::qos::partition::Partition::single("a"))
        );
        assert_eq!(
            registry.writer_ownership_kind(&W),
            Some(OwnershipKind::Exclusive),
            "unheard: OWNERSHIP kind survives"
        );
        assert_eq!(
            registry.writer_ownership_strength(&W),
            Some(7),
            "unheard: OWNERSHIP strength survives"
        );
        assert_eq!(
            registry.get_topic_by_guid(&W),
            Some(TOPIC.to_string()),
            "unheard: the GUID -> topic routing entry survives"
        );
        assert_eq!(
            registry.writer_lifespan(&W),
            None,
            "lifespan always retires, unheard or deleted"
        );
    }

    /// A writer that announced its own departure (`Deleted`) is gone for
    /// good: its OWNERSHIP kind and strength retire with its lifespan, not
    /// only the lifespan alone. The GUID -> topic routing entry does NOT
    /// (see `retire_deleted_writer`'s doc).
    #[test]
    fn a_deleted_writer_retires_every_durable_record() {
        let registry = registered();
        registry.notify_writer_departure(W, DisposeKind::Unregistered, WriterDeparture::Deleted);
        assert_eq!(registry.writer_partition(&W), None);
        assert_eq!(
            registry.writer_ownership_kind(&W),
            None,
            "deleted: OWNERSHIP kind retires"
        );
        assert_eq!(
            registry.writer_ownership_strength(&W),
            None,
            "deleted: OWNERSHIP strength retires"
        );
        assert_eq!(
            registry.get_topic_by_guid(&W),
            Some(TOPIC.to_string()),
            "the GUID -> topic routing entry is NOT retired here:              notify_participant_departure's own loop finds a departed              participant's writers through it"
        );
        assert_eq!(registry.writer_lifespan(&W), None);
    }

    /// The same retirement reached through a participant's own departure
    /// (`notify_participant_departure`'s loop), not just a lone writer's:
    /// that path retires the lifespan, the partition and the OWNERSHIP kind
    /// and strength alike.
    #[test]
    fn a_deleted_participants_writer_retires_too() {
        let registry = registered();
        registry
            .notify_participant_departure(&W[..12].try_into().unwrap(), WriterDeparture::Deleted);
        assert_eq!(registry.writer_partition(&W), None);
        assert_eq!(
            registry.writer_ownership_kind(&W),
            None,
            "the participant's own departure retires its writer's OWNERSHIP kind too"
        );
        assert_eq!(
            registry.get_topic_by_guid(&W),
            Some(TOPIC.to_string()),
            "routing entry stays for the same reason as the solo-writer case"
        );
    }

    /// A deleted writer's GROUP dialect record goes with it: left behind,
    /// a writer re-created under the same GUID would inherit a stale
    /// `writer_speaks_spec_group` verdict from one that no longer exists.
    #[test]
    fn a_deleted_writer_drops_its_group_dialect() {
        let registry = registered();
        registry.record_writer_group_dialect(
            W,
            crate::protocol::group::GroupDialect::Spec,
            Some([0, 0, 1, 8]),
        );
        registry.notify_writer_departure(W, DisposeKind::Unregistered, WriterDeparture::Deleted);
        assert_eq!(
            registry.writer_spec_group(&W),
            None,
            "a deleted writer's GROUP dialect record must retire too"
        );
    }

    /// The topic's minimum finite Lifespan (`writer_lifespans_by_topic`,
    /// read by a reader that does not know which writer a sample came
    /// from) is recomputed when the writer holding it departs: left
    /// stale, a later infinite-lifespan writer's samples would expire
    /// against a minimum that belonged to a writer no longer here (DDS
    /// v1.4 Sec.2.2.3.16: a sample expires by ITS OWN writer's lifespan).
    #[test]
    fn a_departed_writers_topic_minimum_lifespan_is_recomputed() {
        let registry = registered();
        let other: [u8; 16] = [9; 16];
        registry.register_writer_guid(other, TOPIC.to_string());
        registry.register_writer_lifespan_of(TOPIC, other, 5_000_000_000);
        assert_eq!(
            registry.min_writer_lifespan_for_topic(TOPIC),
            Some(1_000_000), // W's lifespan, registered in `registered()`
            "fixture: W's shorter lifespan is the topic's minimum"
        );
        registry.notify_writer_departure(W, DisposeKind::Unregistered, WriterDeparture::Deleted);
        assert_eq!(
            registry.min_writer_lifespan_for_topic(TOPIC),
            Some(5_000_000_000),
            "the minimum must recompute from the writer still here, not stay at W's"
        );
    }

    /// The topic's minimum retires entirely once no writer of it has a
    /// finite Lifespan left -- not a stale value with nothing backing it.
    #[test]
    fn a_topics_minimum_lifespan_retires_once_no_writer_has_one() {
        let registry = registered();
        registry.notify_writer_departure(W, DisposeKind::Unregistered, WriterDeparture::Deleted);
        assert_eq!(
            registry.min_writer_lifespan_for_topic(TOPIC),
            None,
            "no writer of this topic has a finite lifespan left"
        );
    }

    /// P2 (round 3 review, finding 6): the recompute's snapshot of the
    /// topic's remaining writers and its publish of the recomputed minimum
    /// are two different locks, taken one after the other. A registration
    /// landing in that window -- a NEW writer's SEDP, running on an
    /// entirely separate path with no lock shared with this scan --
    /// publishes its own finite minimum first; this recompute, computing
    /// `None` from a snapshot that predates it, must not then overwrite
    /// that minimum back to "no limit".
    #[test]
    fn a_concurrent_registration_survives_a_stale_departure_recompute() {
        let registry = std::sync::Arc::new(registered());
        let other: [u8; 16] = [9; 16];
        super::after_lifespan_snapshot_for_test(Box::new({
            let registry = std::sync::Arc::clone(&registry);
            move || {
                registry.register_writer_guid(other, TOPIC.to_string());
                registry.register_writer_lifespan_of(TOPIC, other, 5_000_000_000);
            }
        }));
        registry.notify_writer_departure(W, DisposeKind::Unregistered, WriterDeparture::Deleted);
        assert_eq!(
            registry.min_writer_lifespan_for_topic(TOPIC),
            Some(5_000_000_000),
            "the concurrently registered writer's finite lifespan must survive \
             the departure's own, now-stale recompute"
        );
    }
}

#[cfg(test)]
mod legacy_hash_budget_tests {
    use super::*;

    /// A fixed compatibility cap bounds total retained state across writers,
    /// including streams that change only their wire hash for the same key.
    #[test]
    fn legacy_hash_budget_is_global_and_refusals_are_counted() {
        let registry = TopicRegistry::new();
        let a = [1; 16];
        let b = [2; 16];
        registry.register_writer_legacy_key_hash(a, true);
        registry.register_writer_legacy_key_hash(b, true);
        for n in 0..MAX_LEGACY_KEY_HASH_INSTANCES {
            registry.note_legacy_key_hash_instance(
                if n % 2 == 0 { a } else { b },
                (n as u128).to_be_bytes(),
                [3; 16],
            );
        }
        let overflow = u128::MAX.to_be_bytes();
        registry.note_legacy_key_hash_instance(a, overflow, [3; 16]);
        assert_eq!(
            registry.resolve_legacy_key_hash_instance(&a, &overflow),
            None
        );
        assert_eq!(registry.legacy_key_hash_refused(), 1);
        assert_eq!(
            recover_read(&registry.legacy_key_hash_instances, "test").len(),
            MAX_LEGACY_KEY_HASH_INSTANCES
        );
        // A full budget must still detect ambiguity for a retained hash.
        let first = 0u128.to_be_bytes();
        registry.note_legacy_key_hash_instance(a, first, [4; 16]);
        assert_eq!(registry.resolve_legacy_key_hash_instance(&a, &first), None);
        registry.note_legacy_key_hash_instance(a, first, [3; 16]);
        assert_eq!(registry.resolve_legacy_key_hash_instance(&a, &first), None);
        assert_eq!(registry.legacy_key_hash_refused(), 1);
        registry.forget_writer_legacy_key_hash(&b);
        registry.note_legacy_key_hash_instance(a, overflow, [3; 16]);
        assert_eq!(
            registry.resolve_legacy_key_hash_instance(&a, &overflow),
            Some([3; 16])
        );
    }
}
