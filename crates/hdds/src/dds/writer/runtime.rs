// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::heartbeat_scheduler::HeartbeatPeriodic;
use super::intra_coherent::{CoherentStamp, IntraCoherentSets};

/// Fragment-burst pacing knobs (DATA_FRAG unicast path only).
///
/// Only bursts longer than the threshold are paced, so ordinary samples and
/// short fragment runs (up to 32 datagrams) are untouched. Beyond it, a pause
/// is inserted every `FRAG_BURST_CHUNK` datagrams so a receiver draining a
/// default-sized socket buffer (Linux rmem_default 212992, charged at skb
/// truesize, i.e. 2-4x payload) is never handed more than one chunk per
/// scheduling quantum. Cost for a 100 KB sample (98 fragments): 6 pauses of
/// 150 us = 0.9 ms, negligible at harness rates and absent from the intra
/// paths (which never fragment over UDP).
const FRAG_BURST_PACING_THRESHOLD: usize = 32;
const FRAG_BURST_CHUNK: usize = 16;
const FRAG_BURST_PAUSE_US: u64 = 150;
/// Length of the write-time clock an intra-process write with an
/// application-supplied source timestamp lays down ahead of its encoded
/// sample (`IndexEntry::mark_reception_ts_prefix`).
const RECEPTION_TS_LEN: usize = 8;
use crate::core::discovery::ReplayToken;
use crate::core::discovery::GUID;
use crate::core::rt;
use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
use crate::dds::listener::DataWriterListener;
#[cfg(feature = "security")]
use crate::dds::CdrVersion;
use crate::dds::{BindToken, Error, QoS, Result, DDS};
use crate::protocol::builder;
use crate::protocol::constants::is_zzdds_vendor;
use crate::protocol::group::GroupTag;
use crate::reliability::{ChangeKind, ChangeMetadata, HeartbeatTx, HistoryCache, ReliableMetrics};
use crate::telemetry;
use crate::telemetry::metrics::current_time_ns;
use crate::transport::UdpTransport;
use std::cell::RefCell; // heartbeat_tx (pre-existing)
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Clears a GROUP writer's pending GSN when dropped: the change taken
/// with it is made, or abandoned (`PublisherCore::take_sn_and_gsn`).
struct PendingGsn<'a>(Option<&'a AtomicU64>);

/// A write's hold on its change until the change is emitted: its slot in
/// the history's in-flight table (`HistoryCache::taking`) and its pending
/// GSN. Released before the co-located readers are pushed to: their
/// listeners run on this thread, and one that writes again through the same
/// writer takes a change of its own (one in flight per producer).
struct ChangeGuards<'a, M: LocalWriteMode> {
    _in_flight: Option<crate::reliability::InFlight<'a>>,
    _pending_gsn: PendingGsn<'a>,
    _local_pairing: Option<parking_lot::RwLockReadGuard<'a, ()>>,
    _local_notices: M::Notices,
}

/// The ordinary path has neither a coherent guard payload nor its drop
/// dispatch. Only the controlled specialization carries these resources.
trait LocalWriteMode {
    type Notices: Default;
    type Orders: Default;
    fn reserve_order(
        core: &crate::dds::publisher::PublisherCore,
        merger: &rt::TopicMerger,
        seq: u64,
        coherent: bool,
    ) -> Self::Orders;
    fn pending(orders: Self::Orders) -> rt::merger::PendingOrders;
    type Ticket<'m>;
    const CONTROLLED: bool;
    fn notices(enabled: bool) -> Self::Notices;
    fn admit<'m>(
        merger: &'m rt::TopicMerger,
        entry: &rt::IndexEntry,
        pool: &rt::SlabPool,
        key: &dyn Fn() -> Option<[u8; 16]>,
        wait: Option<&rt::WriteDeadline>,
        ordering: Option<(u64, u64)>,
    ) -> std::result::Result<Self::Ticket<'m>, rt::RoomTimeout>;
    fn deliver(
        merger: &rt::TopicMerger,
        ticket: Self::Ticket<'_>,
        entry: rt::IndexEntry,
        pool: &rt::SlabPool,
        key: &dyn Fn() -> Option<[u8; 16]>,
        ordering: Option<(u64, u64)>,
        orders: Self::Orders,
    ) -> bool;
    fn push_waiting(
        merger: &rt::TopicMerger,
        entry: rt::IndexEntry,
        pool: &rt::SlabPool,
        key: &dyn Fn() -> Option<[u8; 16]>,
        wait: impl FnOnce() -> Option<std::time::Duration>,
    ) -> std::result::Result<bool, rt::RoomTimeout>;
}

struct PlainWrite;
struct ControlledWrite;

impl LocalWriteMode for PlainWrite {
    type Notices = ();
    type Orders = ();
    // @audit-ok: the plain specialization owns no Publisher order resources.
    #[inline]
    fn reserve_order(
        _: &crate::dds::publisher::PublisherCore,
        _: &rt::TopicMerger,
        _: u64,
        _: bool,
    ) {
    }
    #[inline]
    fn pending(_: ()) -> rt::merger::PendingOrders {
        rt::merger::PendingOrders::default()
    }
    type Ticket<'m> = rt::merger::PlainAdmission<'m>;
    const CONTROLLED: bool = false;
    // @audit-ok: unit erases coherent notice storage and teardown here.
    #[inline]
    fn notices(_: bool) {}
    #[inline]
    fn admit<'m>(
        merger: &'m rt::TopicMerger,
        entry: &rt::IndexEntry,
        pool: &rt::SlabPool,
        key: &dyn Fn() -> Option<[u8; 16]>,
        wait: Option<&rt::WriteDeadline>,
        ordering: Option<(u64, u64)>,
    ) -> std::result::Result<Self::Ticket<'m>, rt::RoomTimeout> {
        let _ = ordering;
        merger.admit_plain(entry, pool, key, wait)
    }
    #[inline]
    fn deliver(
        merger: &rt::TopicMerger,
        ticket: Self::Ticket<'_>,
        entry: rt::IndexEntry,
        pool: &rt::SlabPool,
        key: &dyn Fn() -> Option<[u8; 16]>,
        ordering: Option<(u64, u64)>,
        orders: Self::Orders,
    ) -> bool {
        let _ = (ordering, orders);
        merger.deliver_plain(ticket, entry, pool, key)
    }
    #[inline]
    fn push_waiting(
        merger: &rt::TopicMerger,
        entry: rt::IndexEntry,
        pool: &rt::SlabPool,
        key: &dyn Fn() -> Option<[u8; 16]>,
        wait: impl FnOnce() -> Option<std::time::Duration>,
    ) -> std::result::Result<bool, rt::RoomTimeout> {
        merger.push_waiting_plain(entry, pool, key, wait)
    }
}

impl LocalWriteMode for ControlledWrite {
    type Notices = Option<crate::dds::LocalDelivery>;
    type Orders = rt::merger::PendingOrders;
    fn reserve_order(
        core: &crate::dds::publisher::PublisherCore,
        merger: &rt::TopicMerger,
        seq: u64,
        coherent: bool,
    ) -> Self::Orders {
        core.local_group()
            .map(|group| merger.reserve_order(group.identity(), core.current_gsn(), seq, coherent))
            .unwrap_or_default()
    }
    #[inline]
    fn pending(orders: Self::Orders) -> rt::merger::PendingOrders {
        orders
    }
    type Ticket<'m> = rt::merger::Admission<'m>;
    const CONTROLLED: bool = true;
    #[inline]
    fn notices(enabled: bool) -> Self::Notices {
        enabled.then(crate::dds::LocalDelivery::enter)
    }
    #[inline]
    fn admit<'m>(
        merger: &'m rt::TopicMerger,
        entry: &rt::IndexEntry,
        pool: &rt::SlabPool,
        key: &dyn Fn() -> Option<[u8; 16]>,
        wait: Option<&rt::WriteDeadline>,
        ordering: Option<(u64, u64)>,
    ) -> std::result::Result<Self::Ticket<'m>, rt::RoomTimeout> {
        merger.admit_ordered(entry, pool, key, wait, ordering)
    }
    #[inline]
    fn deliver(
        merger: &rt::TopicMerger,
        ticket: Self::Ticket<'_>,
        entry: rt::IndexEntry,
        pool: &rt::SlabPool,
        key: &dyn Fn() -> Option<[u8; 16]>,
        ordering: Option<(u64, u64)>,
        orders: Self::Orders,
    ) -> bool {
        merger.deliver(ticket, entry, pool, key, ordering, orders)
    }
    #[inline]
    fn push_waiting(
        merger: &rt::TopicMerger,
        entry: rt::IndexEntry,
        pool: &rt::SlabPool,
        key: &dyn Fn() -> Option<[u8; 16]>,
        wait: impl FnOnce() -> Option<std::time::Duration>,
    ) -> std::result::Result<bool, rt::RoomTimeout> {
        merger.push_waiting(entry, pool, key, wait)
    }
}

/// What a writer's change did to its coherent set, to undo if the change is
/// abandoned (`DataWriter::undo_set_context`).
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct SetUndo {
    /// The change's SN.
    seq: u64,
    /// The set's last SN before the change (0: none).
    last: u64,
}

impl Drop for PendingGsn<'_> {
    fn drop(&mut self) {
        if let Some(pending) = self.0 {
            pending.store(0, Ordering::Release);
        }
    }
}

/// Build a change with the writer's next sequence number, then take that
/// number, building again if another producer took it in between.
///
/// Returns `None`, taking no number, when `build` refuses (an empty
/// packet). A number taken and then refused would leave a hole RELIABLE
/// readers NACK forever.
pub(super) fn take_sequence_number_for(
    next_seq: &AtomicU64,
    mut build: impl FnMut(u64) -> Vec<u8>,
) -> Option<(u64, Vec<u8>)> {
    loop {
        let seq = next_seq.load(Ordering::Acquire);
        let packet = build(seq);
        if packet.is_empty() {
            return None;
        }
        if next_seq
            .compare_exchange(seq, seq + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some((seq, packet));
        }
    }
}

/// Whether every sample written so far (`next_seq` is the next number to
/// take) has been acknowledged by every reader of `ack_track`. Trivially
/// true before the first write or when no reliable reader is tracked.
pub(super) fn all_acked(next_seq: &AtomicU64, ack_track: &super::nack::AckTrack) -> bool {
    let last = next_seq.load(Ordering::Acquire).saturating_sub(1);
    if last == 0 {
        return true;
    }
    let map = match ack_track.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if map.is_empty() {
        return true;
    }
    map.values().all(|&acked| acked >= last)
}

/// The instant `max_wait` from now; far in the future when the sum does
/// not fit an `Instant`, so an effectively unbounded wait does not panic.
pub(crate) fn deadline_after(max_wait: std::time::Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(max_wait)
        .unwrap_or_else(|| now + std::time::Duration::from_secs(100 * 365 * 24 * 3600))
}

/// DDS v1.4 Sec.2.2.2.4.2.15 for one writer, bounded by `deadline`:
/// returns `Ok(())` once `all_acked`, `Err(Error::AcknowledgmentTimeout)`
/// when `deadline` passes first. A writer that is not RELIABLE returns at
/// once. Blocked on the history cache's own condition variable, which every
/// ACKNACK that advances the floor signals.
pub(super) fn wait_acked_until(
    reliable: bool,
    next_seq: &AtomicU64,
    ack_track: &super::nack::AckTrack,
    history_cache: Option<&HistoryCache>,
    deadline: Instant,
) -> Result<()> {
    if !reliable {
        return Ok(());
    }
    if all_acked(next_seq, ack_track) {
        return Ok(());
    }
    let Some(cache) = history_cache else {
        // RELIABLE with no history at all does not arise in this
        // writer (RELIABLE always allocates one, see `WriterBuilder`),
        // but a reader matched and nothing to wait for either way.
        return Ok(());
    };
    loop {
        let observed = cache.ack_progress();
        if all_acked(next_seq, ack_track) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Error::AcknowledgmentTimeout);
        }
        cache.wait_for_floor_change(observed, deadline);
    }
}

/// Whether this writer's shared-memory ring may serve a reader of the spec
/// GROUP class `spec_reader`: the ring carries one form, the one of the
/// first reader it served (`shm_class`); a reader of the other class goes
/// by UDP.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn shm_serves(shm_class: Option<bool>, spec_reader: bool) -> bool {
    shm_class.is_none_or(|class| class == spec_reader)
}

/// Whether the GROUP classes (spec or not) of the readers a shared-memory
/// ring would serve are all one: a ring drained by readers of both
/// classes carries no GROUP change.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn shm_audience_is_one_class(classes: &mut impl Iterator<Item = bool>) -> bool {
    match classes.next() {
        Some(first) => classes.all(|class| class == first),
        None => true,
    }
}

/// The plain form of a GROUP change (`GroupForm::Plain`), built by the first
/// reader that selects it and never before: a change whose audience has no
/// plain reader never builds it, and a plain peer learned after the change
/// was prepared still gets the plain form. An empty result means the form
/// could not be built, and every plain reader is then skipped, never sent
/// the legacy form.
pub(super) struct LazyForm<'a, T> {
    build: &'a dyn Fn() -> T,
    built: std::cell::OnceCell<T>,
}

impl<'a, T> LazyForm<'a, T> {
    pub(super) fn new(build: &'a dyn Fn() -> T) -> Self {
        Self {
            build,
            built: std::cell::OnceCell::new(),
        }
    }

    /// The form, built on the first call.
    pub(super) fn get(&self) -> &T {
        self.built.get_or_init(|| (self.build)())
    }
}

/// Whether a change goes to the multicast fallback (`send_multicast_unless_group`):
/// any change but a GROUP one (`group`) while a participant of the spec
/// class, or one taking plain DATA (`GroupForm::Plain`), is known: neither
/// form may reach an audience whose readers are not known.
pub(super) fn multicasts(
    group: bool,
    fsm: Option<&crate::core::discovery::multicast::DiscoveryFsm>,
) -> bool {
    !(group && fsm.is_some_and(|fsm| fsm.any_spec_group_peer() || fsm.any_plain_group_peer()))
}

/// The multicast fallback of a change of `topic` whose audience is not
/// known: today's form, but for a change of a GROUP Publisher's writer
/// (`spec_packet`) while a participant of the spec class is known, which
/// goes nowhere. Its two forms cannot share a leg whose readers' classes
/// are unknown: a reader of the spec class given the 1.4.x form keys
/// the set apart from the end of set it receives in the spec form. A
/// reliable reader gets the change once matched (HEARTBEAT, NACK). Nothing
/// of a topic whose multicast fallback is closed goes there
/// (`multicast_fallback_closed`).
pub(super) fn send_multicast_unless_group(
    transport: &UdpTransport,
    packet: &[u8],
    spec_packet: Option<&[u8]>,
    fsm: Option<&crate::core::discovery::multicast::DiscoveryFsm>,
    topic: &str,
) -> std::result::Result<(), std::io::Error> {
    if !multicasts(spec_packet.is_some(), fsm) {
        log::debug!("[writer] GROUP change: no multicast to an audience of unknown class");
        return Ok(());
    }
    if multicast_fallback_closed(fsm, topic) {
        log::debug!(
            "[writer] protected topic '{}': no multicast fallback",
            topic
        );
        return Ok(());
    }
    transport.send_user_data_multicast(packet)
}

/// Whether the participant fallback sends to `participant` (`DiscoveryFsm::
/// admits_participant_fallback`): DDS Security v1.1 Sec.8.8.7.1, 9.4.3, the
/// admission every reader of the topic is judged by, for a participant whose
/// readers are not known yet. Always true without the security feature.
pub(super) fn fallback_admits(
    fsm: Option<&crate::core::discovery::multicast::DiscoveryFsm>,
    participant: &GUID,
    topic: &str,
) -> bool {
    #[cfg(feature = "security")]
    if let Some(fsm) = fsm {
        return fsm.admits_participant_fallback(&participant.prefix, topic);
    }
    let _ = (fsm, participant, topic);
    true
}

/// Whether the multicast fallback, whose audience is not known, is closed to
/// a change of `topic`: our governance refuses an unauthenticated
/// participant - one we know nothing of - on it
/// (`DiscoveryFsm::unauthenticated_gate_applies`, Sec.8.8.2.2, 8.8.7.1).
/// Always false without the security feature.
pub(super) fn multicast_fallback_closed(
    fsm: Option<&crate::core::discovery::multicast::DiscoveryFsm>,
    topic: &str,
) -> bool {
    #[cfg(feature = "security")]
    if let Some(fsm) = fsm {
        return fsm.unauthenticated_gate_applies(topic);
    }
    let _ = (fsm, topic);
    false
}

/// Whether the history replay goes to the late joiner `reader_guid`: the
/// door of the data plane (`DiscoveryFsm::admits_remote_endpoint`, DDS
/// Security v1.1 Sec.8.8.7.1, 9.4.3). A replay that names no reader is sent
/// only where no security plugin judges a remote reader. Always true
/// without the security feature.
fn replay_admits(
    fsm: Option<&crate::core::discovery::multicast::DiscoveryFsm>,
    topic: &str,
    reader_guid: Option<[u8; 16]>,
) -> bool {
    #[cfg(feature = "security")]
    if let Some(fsm) = fsm {
        if fsm.admission_gate_active() {
            return reader_guid.is_some_and(|guid| {
                fsm.admits_remote_endpoint(topic, &GUID::from_bytes(guid), false)
            });
        }
    }
    let _ = (fsm, topic, reader_guid);
    true
}

/// Global counter for HEARTBEAT_FRAG messages (RTPS v2.5 Sec.8.3.8.7)
static HEARTBEAT_FRAG_COUNT: AtomicU32 = AtomicU32::new(1);

/// The outcome of one `WriterReplayState::replay_to` attempt to replay an
/// `EcsClose` cache entry to one late-joining reader: the actual reason it
/// was sent or skipped, each with its own per-writer counter on
/// `WriterReplayState` surfaced through `WriterStats`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EcsReplayOutcome {
    /// The dialect-correct close form was built and the unicast send
    /// succeeded.
    BuiltAndSent,
    /// No reader identity at all (`reader_guid` unknown), or a reader
    /// identity whose RTPS vendor id never resolved: never guess a close
    /// dialect. A Reliable reader will NACK the hole and `on_nack`
    /// retries once the vendor resolves.
    UnresolvedVendor,
    /// The vendor DID resolve, but the cached `ChangeMetadata` lacked
    /// what building this reader's close form needs (e.g. no cached
    /// `coherent_sn` for the HDDS-native form), or the builder otherwise
    /// returned an empty packet.
    IncompleteMetadata,
    /// `History::KeepLast` evicted every `UserData` member of this
    /// close's own coherent set individually, leaving the close alone in
    /// the snapshot (item 5). Replaying it would close a set the late
    /// joiner never saw any part of.
    OrphanClose,
    /// The close form was built successfully but the unicast transport
    /// send itself failed (e.g. a transient socket error). DISTINCT from
    /// every "we could not build a packet" outcome above.
    SendError,
}

/// Resolved per-reader wire-shape parameters for [`finalize_for_reader`]:
/// the RTPS reader entity id to patch into a DATA submessage, and the
/// reader's RTPS vendor id (when known) that selects the per-vendor wire
/// transforms.
///
/// Built once by whichever leg discovers the reader (the live per-reader
/// send loop's SEDP-matched `EndpointInfo`, `on_nack`'s NACKing-reader GUID
/// resolution, or `replay_to`'s late-joiner reader GUID), then applied
/// identically by `finalize_for_reader`.
#[derive(Debug, Clone, Copy)]
pub(super) struct ReaderWireProfile {
    pub(super) entity_id: [u8; 4],
    pub(super) vendor: Option<u16>,
}

/// Apply the post-build, per-reader wire transforms a DATA (or DATA_FRAG)
/// submessage needs before it reaches a specific reader:
///
/// 1. Patch the reader entity id at `READER_ENTITY_ID_OFFSET` (RTPS v2.5
///    Sec.8.3.8.2: unicast DATA must target the specific reader entity id,
///    not ENTITYID_UNKNOWN). Applied to EVERY leg, fragmented or not.
/// 2. For the zzdds dialect (`is_zzdds_vendor`, e.g. vendorId 0x0123):
///    downgrade the encapsulation from D_CDR2_LE (0x0009) to
///    PLAIN_CDR2_LE (0x0007); this dialect's profile sends user DATA with
///    the plain CDR2 code only.
/// 3. For vendorId 0x0105 (InterCOM dialect): prepend an RTPS
///    HEADER_EXTENSION submessage (DDSI-RTPS 2.5 8.3.7) to the user DATA;
///    this dialect's profile sends it on every non-fragmented user DATA.
///
/// `fragmented` gates (2) and (3): they apply ONLY when `fragmented ==
/// false`. This is a deliberate boundary, not an oversight -- the live
/// per-reader DATA_FRAG leg (`send_packets_to_endpoints`) has never
/// applied the vendor transforms to a fragmented burst, and live wire
/// bytes must never change without a measurement backing the change.
/// Until one exists (tracked as a follow-up: measure whether the 0x0105
/// dialect needs the HEADER_EXTENSION on DATA_FRAG the same way as on
/// small DATA), every DATA_FRAG leg calls this with
/// `fragmented = true` and gets ONLY the entity id patch, matching the
/// live leg exactly.
///
/// ALL FOUR emission legs that address one specific reader with a small
/// (non-fragmented) DATA submessage -- the live per-reader send
/// (`send_packet_to_endpoints`), `on_nack`'s small-payload retransmit, and
/// `replay_to`'s small-payload replay -- call this with `fragmented =
/// false` and get the full transform set. ALL FOUR DATA_FRAG legs -- the
/// live per-reader DATA_FRAG send (`send_packets_to_endpoints`),
/// `on_nack`'s DATA_FRAG retransmit, `WriterNackFragHandler::on_nack_frag`,
/// and `replay_to`'s fragmented replay -- call this with `fragmented =
/// true` and get ONLY the entity id patch. Do not inline any of these
/// transforms elsewhere.
pub(super) fn finalize_for_reader(
    mut packet: Vec<u8>,
    profile: ReaderWireProfile,
    fragmented: bool,
) -> Vec<u8> {
    if packet.len() >= builder::READER_ENTITY_ID_OFFSET + 4 {
        packet[builder::READER_ENTITY_ID_OFFSET..builder::READER_ENTITY_ID_OFFSET + 4]
            .copy_from_slice(&profile.entity_id);
    }
    if fragmented {
        // See the `fragmented` doc above: vendor transforms are withheld
        // on every fragmented leg until measured, to match what the live
        // DATA_FRAG leg has always sent.
        return packet;
    }
    // zzdds (either of its vendor IDs, `is_zzdds_vendor`): flip ONLY the
    // two encap bytes, keeping the DHEADER and payload byte-identical. A
    // no-op (returns false, unmodified) on a DATA_FRAG packet, which
    // carries no top-level encapsulation header of its own to find.
    if profile.vendor.is_some_and(is_zzdds_vendor) {
        builder::downgrade_data_encap_to_plain_cdr2(&mut packet);
    }
    // InterCOM (0x0105): prepend AFTER the readerEntityId patch (which
    // assumes the un-shifted offset), so only this per-reader copy is
    // shifted by the extension.
    if profile.vendor == Some(crate::core::rtps_constants::INTERCOM_VENDOR_ID_U16) {
        packet = builder::prepend_header_extension(&packet);
    }
    packet
}

/// The ONE fail-closed predicate every NON-ENCRYPTING emission leg consults.
///
/// The wire leg encrypts (`DataWriter::seal_payload_for_wire`, which
/// dispose/unregister K-payloads also go through); this covers what still has
/// no cipher: the intra-process slab and the no-transport history-cache
/// route. **Fails closed**: encryption requested and no cipher on this leg
/// means `Error::EncryptionUnavailable`, never cleartext.
///
/// Protection can be requested by the explicit crypto configuration or by
/// governance. A missing crypto plugin cannot override governance.
///
/// One predicate rather than a check per leg, because emission paths that must
/// agree on the security posture WILL drift apart otherwise -- this subsystem
/// has been rebuilt out of exactly that failure twice (the classifier's two
/// lists; step 0 covering one of three emitters). `leg` only labels the logs;
/// the returned error is deliberately identical across legs so no caller can
/// grow to depend on which leg refused.
#[cfg(feature = "security")]
fn refuse_cleartext_leg(protection_required: bool, topic: &str, leg: &str) -> Result<()> {
    if !protection_required {
        return Ok(());
    }
    log::error!(
        "[writer] topic='{}': encryption is enabled and the {} leg has no cipher -- \
         refusing to emit cleartext",
        topic,
        leg
    );
    Err(Error::EncryptionUnavailable(format!(
        "topic '{}': the {} leg has no cipher -- refusing to emit cleartext",
        topic, leg
    )))
}

/// The writer half of the shared-memory data path.
///
/// Holds what is needed to create the ring on first use (the segment is
/// named from the domain id and the writer GUID, so a reader can
/// reconstruct the name from discovery alone) and the ring itself once
/// created. `attempted` distinguishes "not created yet" from "creation
/// failed, do not keep hammering `shm_open` on every write": a failure to
/// create the segment is permanent for this writer, and the UDP leg is a
/// complete answer.
#[cfg(target_os = "linux")]
pub(super) struct ShmWriterLeg {
    domain_id: u32,
    writer_guid: GUID,
    ring: RefCell<Option<crate::transport::shm::ShmWriterTransport>>,
    attempted: std::cell::Cell<bool>,
}

#[cfg(target_os = "linux")]
impl ShmWriterLeg {
    pub(super) fn new(domain_id: u32, writer_guid: GUID) -> Self {
        Self {
            domain_id,
            writer_guid,
            ring: RefCell::new(None),
            attempted: std::cell::Cell::new(false),
        }
    }

    /// Create this writer's segment if it does not exist yet, returning
    /// whether a ring is available afterwards.
    ///
    /// Split out of `push` because the segment must exist BEFORE the
    /// writer has anything to push: a reader cannot prove it is attached to a
    /// segment that was never created, and the writer will not push for a peer
    /// that has not proven it. Created lazily, on the first matched
    /// shared-memory reader rather than on the first sample.
    fn ensure_ring(
        ring: &mut Option<crate::transport::shm::ShmWriterTransport>,
        attempted: &std::cell::Cell<bool>,
        domain_id: u32,
        writer_guid: GUID,
        topic: &str,
    ) -> bool {
        if ring.is_some() {
            return true;
        }
        if attempted.get() {
            // The one failure path below disables the leg for good rather
            // than leaving it to be retried per packet.
            return false;
        }
        attempted.set(true);
        match crate::transport::shm::ShmWriterTransport::new(domain_id, writer_guid, topic) {
            Ok(transport) => {
                *ring = Some(transport);
                true
            }
            Err(err) => {
                crate::transport::shm::global_metrics().inc_writer_segment_failures();
                log::error!(
                    "[writer] topic='{}' writer={}: the shared-memory segment could not be \
                     created ({}). This writer is giving up on shared memory for good and \
                     moving every reader back to UDP; the per-peer SHM verdict for this \
                     writer is now false.",
                    topic,
                    writer_guid,
                    err
                );
                false
            }
        }
    }

    /// The ring sequence `participant` starts reading from, or `None` when it
    /// has not PROVEN it is draining this writer's ring.
    ///
    /// Creates the segment as a side effect when it does not exist yet, which
    /// is deliberate: until the segment exists there is nothing for the peer to
    /// attach to, so a writer that waited for proof before creating it would
    /// wait forever and the leg would never engage.
    fn participant_cursor(&self, topic: &str, participant: [u8; 16]) -> Option<u64> {
        let mut ring = self.ring.borrow_mut();
        if !Self::ensure_ring(
            &mut ring,
            &self.attempted,
            self.domain_id,
            self.writer_guid,
            topic,
        ) {
            return None;
        }
        ring.as_ref()
            .and_then(|t| t.participant_cursor(participant))
    }

    /// Push one COMPLETE framed RTPS packet into the ring.
    ///
    /// The packet, not the bare sample: framing is already hoisted out of
    /// the per-reader send loop, and whatever a UDP leg would have carried
    /// for this reader (including the ciphertext produced by
    /// `seal_payload_for_wire`, which happens before framing) is exactly
    /// what crosses here. The receiving side runs the standard Router
    /// pipeline, so anything else would be a second, divergent wire format.
    ///
    /// Returns [`ShmPushOutcome`]. A `false`-ish outcome is NEVER silent:
    /// every one of them increments a counter readable through
    /// `transport::shm::global_metrics()` and logs at error level, because
    /// a shared-memory leg that quietly turns back into UDP is exactly the
    /// standing false promise this whole path exists to end.
    fn push(&self, topic: &str, packet: &[u8]) -> ShmPushOutcome {
        // The slot is sized (see `SLOT_PAYLOAD_SIZE`) so that every packet
        // the UDP path emits as a single DATA fits, and everything larger is
        // already fragmented into 1 KB pieces. Reaching this branch means
        // that budget has been outgrown -- an extreme topic name, or a
        // change to DEFAULT_MAX_UNFRAGMENTED_SIZE -- so it is an error, not
        // a routine fallback, and it says so.
        if packet.len() > crate::transport::shm::SLOT_PAYLOAD_SIZE {
            crate::transport::shm::global_metrics().inc_oversize_refused();
            log::error!(
                "[writer] topic='{}': a {} byte framed packet does not fit the {} byte \
                 shared-memory slot, so this sample goes to co-located readers over UDP \
                 instead. The slot budget is sized for every unfragmented DATA \
                 (DEFAULT_MAX_UNFRAGMENTED_SIZE + framing), so this means the budget has \
                 been outgrown, not that the sample is unusual.",
                topic,
                packet.len(),
                crate::transport::shm::SLOT_PAYLOAD_SIZE
            );
            return ShmPushOutcome::Oversize;
        }

        let mut ring = self.ring.borrow_mut();
        // Sampled BEFORE the attempt: once `ensure_ring` has run, "attempted
        // and no ring" is true both for a creation that just failed and for
        // one that failed long ago, and the caller distinguishes them.
        let already_retired = self.attempted.get() && ring.is_none();
        if !Self::ensure_ring(
            &mut ring,
            &self.attempted,
            self.domain_id,
            self.writer_guid,
            topic,
        ) {
            return if already_retired {
                ShmPushOutcome::LegDisabled
            } else {
                ShmPushOutcome::SegmentUnavailable
            };
        }

        let Some(transport) = ring.as_mut() else {
            return ShmPushOutcome::LegDisabled;
        };
        match transport.write(packet) {
            Ok(msg_seq) => {
                crate::transport::shm::global_metrics().inc_writes();
                ShmPushOutcome::Pushed(msg_seq)
            }
            // `ShmRingWriter::push` overwrites rather than blocking, so its
            // only error is a payload that does not fit -- which the size
            // guard above already refused. Kept explicit (counted, logged)
            // rather than collapsed into the success path.
            Err(err) => {
                crate::transport::shm::global_metrics().inc_oversize_refused();
                log::error!(
                    "[writer] topic='{}': the shared-memory ring refused a packet the size \
                     guard admitted ({}) -- this sample goes over UDP",
                    topic,
                    err
                );
                ShmPushOutcome::Oversize
            }
        }
    }
}

/// What one [`ShmWriterLeg::push`] did. Distinguishes "this packet went over
/// shared memory" from the two ways it did not, because they are handled
/// differently: an oversized packet is a per-sample event (this reader gets
/// its UDP copy, the leg stays live), whereas a segment that cannot be
/// created is a verdict that has become false and must be retired once, at
/// the cold path, not re-tried per packet.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ShmPushOutcome {
    /// The packet is in the ring at this sequence. A peer is served from the
    /// ring for it only when the peer's published start cursor is at or before
    /// this number; see `transport::shm::presence`.
    Pushed(u64),
    /// The packet does not fit one slot. Counted and logged at error level.
    Oversize,
    /// The segment could not be created. The leg must be retired.
    SegmentUnavailable,
    /// The leg was already retired.
    LegDisabled,
}

/// A typed DDS DataWriter that publishes samples to a topic.
///
/// `DataWriter<T>` serializes data samples of type `T` and delivers them to matching
/// [`DataReader<T>`](crate::DataReader) instances via the configured transport.
///
/// # Type Parameter
///
/// * `T` - The data type, must implement [`DDS`](crate::dds::DDS) (derive with `#[derive(hdds::DDS)]`)
///
/// # Example
///
/// ```rust,no_run
/// use hdds::{Participant, QoS, Result, DDS};
///
/// #[derive(DDS)]
/// struct Temperature {
///     sensor_id: u32,
///     value: f32,
/// }
///
/// fn main() -> Result<()> {
///     let participant = Participant::builder("temp_sensor")
///         .domain_id(0)
///         .build()?;
///
///     let writer = participant.create_writer::<Temperature>(
///         "sensors/temp",
///         QoS::reliable(),
///     )?;
///
///     writer.write(&Temperature {
///         sensor_id: 42,
///         value: 23.5,
///     })?;
///
///     Ok(())
/// }
/// ```
///
/// # Delivery Guarantees
///
/// - **Best-effort**: Fire-and-forget, no retransmission
/// - **Reliable**: Sequence tracking, heartbeats, retransmission on ACKNACK
///
/// # Thread Safety
///
/// `DataWriter<T>` is `Send` (move it into a thread) but NOT `Sync`:
/// `write()` feeds single-producer reader rings, so one writer must
/// have exactly one producing thread at a time. Sharing a writer
/// across threads is a compile error; wrap it in a `Mutex` at the
/// boundary that needs sharing, or create one writer per thread.
///
/// ```compile_fail
/// fn assert_sync<T: Sync>() {}
/// #[derive(Debug, Clone, Copy, PartialEq, hdds::DDS)]
/// struct M { x: u64 }
/// assert_sync::<hdds::DataWriter<M>>();
/// ```
///
/// # See Also
///
/// - `WriterBuilder` - For advanced configuration
/// - [`DataReader`](crate::DataReader) - Subscribing counterpart
pub struct DataWriter<T: DDS> {
    pub(super) serialized_keys: bool,
    pub(super) topic: String,
    /// QoS policy - stored for introspection, used during build()
    pub(super) qos: QoS,
    /// RTPS endpoint context used to align DATA packets with SEDP announcements.
    pub(super) rtps_endpoint: Option<crate::protocol::builder::RtpsEndpointContext>,
    pub(super) merger: Arc<rt::TopicMerger>,
    pub(super) transport: Option<Arc<UdpTransport>>,
    /// Monotonic writer-scoped SequenceNumber_t counter (RTPS v2.5
    /// sec. 8.3.5.4). Shared via `Arc` so the coherent-set bridge can
    /// reserve a fresh SN for the ECS DATA submessage without racing
    /// with the writer's own `write()` path.
    pub(super) next_seq: Arc<AtomicU64>,
    pub(super) history_cache: Option<Arc<HistoryCache>>,
    pub(super) reliable_metrics: Option<Arc<ReliableMetrics>>,
    pub(super) heartbeat_tx: Option<RefCell<HeartbeatTx>>,
    /// This writer's periodic HEARTBEAT (RTPS 2.5 Section 8.4.7.2): an
    /// entry on its participant's liveliness scheduler, or a dedicated
    /// thread for a standalone writer (`HeartbeatPeriodic`). Sends
    /// HEARTBEAT messages independently of write() calls for reliable
    /// recovery.
    pub(super) _heartbeat_scheduler: Option<HeartbeatPeriodic>,
    /// This writer's NACK and NACK_FRAG handlers in the topic registry,
    /// removed with the writer (`Drop`): until then a deleted reliable
    /// writer's handlers kept retransmitting its history on every ACKNACK.
    pub(super) nack_handlers: Option<crate::engine::NackHandlerToken>,
    /// DurabilityService cleanup timer (DDS v1.4 Sec.2.2.3.5), `None` unless
    /// the writer is durable AND its `service_cleanup_delay` is non-zero.
    ///
    /// HELD, not ignored: `CleanupTimerHandle::drop` signals the thread to
    /// stop and joins it, so binding the handle to `_` would start a timer and
    /// stop it on the next line. The underscore prefix says "no reader", not
    /// "no purpose" - the lifetime IS the purpose.
    pub(super) _cleanup_timer: Option<super::cleanup_timer::CleanupTimerHandle>,
    pub(super) endpoint_registry: Option<crate::core::discovery::EndpointRegistry>,
    /// Discovery FSM for partition-aware data routing.
    /// When set, `send_packet_to_endpoints_classed()` filters destinations by QoS compatibility
    /// (including partition matching) instead of broadcasting to all participants.
    pub(super) discovery_fsm: Option<Arc<crate::core::discovery::multicast::DiscoveryFsm>>,
    /// Large-payload route (fragment size + optional multicast dest),
    /// resolved from the matched readers' vendor id and shared with the
    /// NACK/NACK_FRAG retransmit handlers (see `frag_route` module docs).
    pub(super) frag_route: Arc<super::frag_route::FragRouteProfile>,
    /// BindToken for intra-process auto-binding (unregisters on drop)
    pub(super) _bind_token: Option<BindToken>,
    /// Transient-local replay registration token (removes hook on drop).
    pub(super) _replay_token: Option<ReplayToken>,
    /// Same instance the replay callback closure captures (see
    /// `WriterBuilder::build`), kept here so `stats()` can read this
    /// writer's OWN ECS-replay outcome counters instead of a process-wide
    /// static (item 7c). `None` for a writer with no replay hook (not
    /// TRANSIENT_LOCAL/TRANSIENT/PERSISTENT, or missing a cache/transport/
    /// registry) -- `stats()` then reports all-zero ECS-replay counters.
    pub(super) _replay_state: Option<Arc<WriterReplayState>>,
    /// The writer's listener slot, shared with its match callbacks. See
    /// [`DataWriter::set_listener`].
    pub(super) listener: Arc<crate::dds::listener::WriterListenerSlot<T>>,
    /// Match notification token (fires on_publication_matched; unregisters on drop)
    pub(super) _match_token: Option<crate::dds::match_notification::MatchToken>,
    /// This writer's PUBLICATION_MATCHED bookkeeping when it has no
    /// `_match_token` to read instead -- IntraProcess, whose participant
    /// has no `MatchNotificationRegistry` (see
    /// `domain_registry::LocalMatchStatus`). `None` otherwise: the data it
    /// would report is `_match_token`'s.
    pub(super) _match_status: Option<Arc<crate::dds::domain_registry::LocalMatchStatus>>,
    /// This writer's StatusCondition (DDS v1.4 Sec.2.2.2.1.1.5
    /// `get_statuscondition`), raised by PUBLICATION_MATCHED,
    /// OFFERED_INCOMPATIBLE_QOS and OFFERED_DEADLINE_MISSED, cleared by
    /// the matching getter or an installed listener call, exactly like
    /// `DataReader::status_condition`. No DATA_AVAILABLE word: a writer
    /// has nothing to read.
    pub(super) status_condition: Arc<crate::dds::StatusCondition>,
    /// Cumulative PUBLICATION_MATCHED status, written by the match
    /// callback (`WriterBuilder::build`) on every event from either
    /// source that can report one for this writer (the SEDP registry or
    /// `domain_registry::LocalMatchStatus`), read-and-reset by
    /// `get_publication_matched_status` exactly like
    /// `DataReader::subscription_matched`.
    pub(super) publication_matched: Arc<Mutex<crate::dds::listener::PublicationMatchedStatus>>,
    /// OFFERED_INCOMPATIBLE_QOS, shared with the incompatible-QoS callback
    /// like `publication_matched`.
    pub(super) offered_incompatible_qos:
        Arc<Mutex<crate::dds::listener::OfferedIncompatibleQosStatus>>,
    /// Per-reader cumulative acknowledgment watermarks (reader GUID ->
    /// highest SN acknowledged), fed by the ACKNACK handler. Empty until
    /// the first reader ACKNACK arrives; always empty on intra-only
    /// writers. See [`DataWriter::fully_acked`].
    pub(super) ack_track: Arc<std::sync::Mutex<std::collections::HashMap<[u8; 16], u64>>>,
    /// Latched true by the match registry the first time a matched remote
    /// reader of this writer resolves to `TransportSelection::Shm`.
    ///
    /// The ENTIRE cost of the shared-memory leg on an all-UDP writer is one
    /// relaxed load of this flag per emitted packet. Only when it is true
    /// does `send_packet_to_endpoints` consult the per-reader verdict.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(super) shm_selected: Arc<AtomicBool>,
    /// Lazily created shared-memory ring for this writer's DATA, plus the
    /// domain id its segment is named after.
    ///
    /// Lazy on purpose: the segment is a megabyte of `/dev/shm` per writer,
    /// and the overwhelming majority of BEST_EFFORT writers never pair with
    /// a co-located reader. `None` on a writer that cannot have one (no
    /// RTPS endpoint context, no domain, SHM disabled by policy, Reliable
    /// QoS, or a platform / container where co-location is not provable);
    /// the leg is then never even considered.
    ///
    /// `RefCell` rather than `Mutex` because `DataWriter<T>` is already
    /// `!Sync` by contract (see the type docs) and the ring is
    /// single-producer by design.
    #[cfg(target_os = "linux")]
    pub(super) shm_leg: Option<ShmWriterLeg>,
    /// This writer's per-instance DEADLINE watches (DDS v1.4 Sec.2.2.3.7),
    /// on the participant's liveliness scheduler: `None` with an infinite
    /// deadline (the default) -- zero cost. See
    /// `crate::dds::liveliness::deadline` for the design.
    pub(super) deadlines: Option<Arc<crate::dds::liveliness::WriterDeadlines>>,
    /// Security plugin suite for encryption (DDS Security v1.1)
    #[cfg(feature = "security")]
    pub(super) security: Option<Arc<crate::security::SecurityPluginSuite>>,
    /// This writer's topic protection, resolved once per document generation
    /// (`security::protection_cache`): sealing, the protected KeyHash and the
    /// cleartext refusal all read it, and a governance walk per sample is
    /// what this removes.
    #[cfg(feature = "security")]
    pub(super) protection: crate::security::protection_cache::EndpointProtection,
    /// (key_hash -> (CDR version, serialized key bytes)) of every instance
    /// ever written; the version is the one the bytes were encoded with, so
    /// the Drop-time unregister frames them as they are.
    /// The serialized bytes are needed for the Drop-time auto-unregister
    /// path: a spec-conformant subscriber takes the instance identity from
    /// the K-payload (the serialized key), so a lifecycle sample that ships
    /// only an encapsulation header identifies no instance. Storing the
    /// encoded key once per `write()` trades a small memory footprint for
    /// cross-vendor final-instance-state support.
    /// Shared (weakly) with the readers of this process through the
    /// merger's `MergerWriter`: they ask it before declaring an instance
    /// without writers.
    pub(super) written_instances: Arc<rt::WriterInstances>,
    /// Protected wire identity retained for Drop-time lifecycle changes.
    #[cfg(feature = "security")]
    pub(super) protected_key_hashes: Mutex<std::collections::HashMap<[u8; 16], [u8; 16]>>,

    /// Key hashes of instances explicitly disposed (bare Dispose) without a
    /// subsequent write. Drop skips these: a trailing UNREGISTER after DISPOSE
    /// would flip a subscriber that applies the latest lifecycle change from
    /// DISPOSED to NO_WRITERS, losing the disposal the application asked for.
    /// Cleared on explicit unregister or when the instance is written again.
    pub(super) disposed_instances: Mutex<std::collections::HashSet<[u8; 16]>>,
    /// Sequence number of the last lifecycle change this writer emitted
    /// (`dispose`, `unregister_instance`, or the Drop-time auto-unregister),
    /// 0 before the first. `Drop` waits for its acknowledgement: a lifecycle
    /// change the application emitted just before the delete is as
    /// unrecoverable once the writer is gone as the auto-unregister itself,
    /// and no instance is left for the auto-unregister loop to notice it.
    pub(super) last_lifecycle_sn: AtomicU64,
    /// Weak back-reference to the parent Publisher when the writer was
    /// created via `topic.writer().publisher(&pub).build()`. Used at
    /// write() time to read the active Group Sequence Number
    /// (RTPS v2.5 sec. 8.7.5) and to look up the publisher access_scope so
    /// the writer knows whether to tag samples with
    /// `PID_GROUP_COHERENT_SET`. `Weak` to avoid reference cycles --
    /// the writer is owned by the application code, the publisher is
    /// owned by the participant.
    pub(super) publisher: Option<Arc<crate::dds::publisher::PublisherCore>>,
    /// The writer-scoped sequence number of the last sample written
    /// into the active coherent set. Reset to 0 when the publisher
    /// closes the set in `end_coherent_changes` (RTPS v2.5 sec. 8.7.5).
    /// Tracked per writer because each writer's SequenceNumber_t space
    /// is independent. Shared with the coherent-set bridge so the
    /// publisher can drain it without going through the generic
    /// `DataWriter<T>` type.
    pub(super) last_sn_in_active_set: Arc<AtomicU64>,
    /// Writer-scoped SN of the FIRST sample stamped into the currently
    /// open coherent set, plus the publisher GSN that set was opened
    /// under. Every sample of a coherent set carries `PID_COHERENT_SET =
    /// the set's first SN` (constant across the set, DDSI-RTPS 2.5 8.7.6:
    /// "all sample updates belonging to the same coherent set contain an
    /// in-line QoS parameter with this same sequence number"); classic-model
    /// subscribers group by that value and close the set when it advances.
    /// Stamping each sample with its own SN would read, to such a
    /// subscriber, as a series of one-sample sets. Tracking the first SN per
    /// open set lets the writer emit the constant value classic vendors need.
    /// The GSN companion detects set rollover so the first SN is reset
    /// exactly once per set, without a separate begin/end hook on the
    /// writer. The HDDS self path ignores the per-sample value (it commits
    /// by `remote_seq <= ecs.coherent_sn` on ECS arrival), so the change
    /// is byte-irrelevant to HDDS<->HDDS interop.
    pub(super) coherent_set_first_sn: Arc<AtomicU64>,
    pub(super) coherent_set_gsn_seen: AtomicU64,
    /// What the writer's last change did to its coherent set
    /// (`coherent_context_held`), undone if that change is abandoned and
    /// its SN given back (`undo_set_context`). Written and read under the
    /// Publisher's lock.
    pub(super) set_undo: Mutex<SetUndo>,
    pub(super) wire_windows: Arc<crate::protocol::dialect::sequence_window::WriterWindows>,
    /// This writer's coherent sets awaiting local (merger) delivery
    /// (`intra_coherent::IntraCoherentSets`): stamped here, staged by
    /// `commit_intra_process_entry`, closed and delivered at the Publisher's
    /// `end_coherent_changes` through the `WriterCoherentBridge`, which
    /// shares this `Arc`.
    pub(super) intra_coherent_sets: Arc<IntraCoherentSets>,
    /// The version every sample of this writer is serialized in, for
    /// every reader, the history and its repairs: the first element of its
    /// DATA_REPRESENTATION, resolved once at creation
    /// (`cdr_negotiation::resolve_writer_data_representation`). DDS-XTypes
    /// v1.3 Sec.7.6.3.1.1: "Writers offer a single representation. A writer
    /// will use its offered policy to communicate with its matched readers."
    pub(super) cdr_version: crate::dds::CdrVersion,
    /// Reusable scratch for the staged intra-process encode path
    /// (payload outgrew the direct-encode slot or the primary 64/128 KB
    /// classes were exhausted). Grown geometrically and retained across
    /// writes so the staged path never pays a fresh zeroed allocation
    /// per write; the zero-fill cost is paid only when the buffer
    /// actually grows.
    pub(super) intra_scratch: Mutex<Vec<u8>>,
    /// Reusable encode buffer for the wire leg of `write()`, kept all zero
    /// at rest (see `dds::encode_scratch`): replaces a fresh zeroed 64 KiB
    /// allocation per write.
    pub(super) wire_scratch: Mutex<Vec<u8>>,
    /// Strong reference to the type-erased coherent-set bridge so the
    /// publisher's `Weak<dyn CoherentWriter>` stays upgradeable while
    /// the writer is alive. Dropped with the writer; the publisher
    /// prunes the stale entry on the next `end_coherent_changes`
    /// sweep. `None` for writers built without a publisher.
    pub(super) _coherent_bridge: Option<Arc<dyn crate::dds::publisher::CoherentWriter>>,
    /// The retirement of this writer's SEDP announcement, run by `Drop`
    /// after the auto-unregisters (`SedpRetirement`). `None` for a writer
    /// with no participant, which announced nothing.
    pub(super) sedp_retirement: Option<crate::dds::participant::SedpRetirement>,
    /// Its finite AUTOMATIC liveliness lease, which its participant
    /// asserts while the writer lives (DDS v1.4 Sec.2.2.3.11): nothing on
    /// the write path.
    pub(super) _liveliness: Option<crate::dds::liveliness::LocalWriterLease>,
    /// Its finite MANUAL_BY_PARTICIPANT liveliness lease, which gates the
    /// participant's wire assertion (RTPS v2.5 Sec.8.4.13.5): kept
    /// alive only, nothing on the write path (`_liveliness_assert` below
    /// is what `write()` touches).
    pub(super) _liveliness_manual: Option<crate::dds::liveliness::ManualWriterLease>,
    /// This writer's own hand on its MANUAL_BY_PARTICIPANT or
    /// MANUAL_BY_TOPIC liveliness (DDS v1.4 Sec.2.2.3.11): `write()`,
    /// `dispose()`, `unregister_instance()` and `assert_liveliness()`
    /// renew it. `None` for AUTOMATIC or an infinite lease: one `Option`
    /// check, nothing else, on the write path.
    pub(super) _liveliness_assert: Option<crate::dds::liveliness::WriterAssert>,
    /// This writer's own LIVELINESS_LOST watch (MANUAL_BY_PARTICIPANT,
    /// MANUAL_BY_TOPIC only): raises LIVELINESS_LOST when
    /// `_liveliness_assert` above was not renewed within the writer's
    /// lease. Read by `get_liveliness_lost_status`.
    pub(super) liveliness_lost: Option<Arc<crate::dds::liveliness::WriterLiveliness>>,
    /// An explicit source timestamp for the NEXT emitted change only, set by
    /// `write_w_timestamp` / `dispose_w_timestamp` / `unregister_instance_w_timestamp`
    /// (DDS v1.4 Sec.2.2.2.4.2.12/2.2.2.4.2.13/2.2.2.4.2.8) and consumed by
    /// `stamp_source_ts`, which takes it so a later plain `write()` never
    /// inherits a stale override. A `Cell`, not an `Arc<Mutex<_>>`: the
    /// writer is already `!Sync` (see `_phantom`), so no other thread can
    /// observe it between the setter and the one read.
    pub(super) pending_source_ts: core::cell::Cell<Option<(u32, u32)>>,
    /// Per-writer figures for [`WriterStats`] (see [`WriterCounters`]).
    pub(super) counts: WriterCounters,
    /// `Cell<()>` keeps the writer `Send` but suppresses `Sync`:
    /// `write()` produces into single-producer rings, so a writer must
    /// never be shared by reference across threads (soundness, not
    /// style -- see the Thread Safety section above).
    pub(super) _phantom: core::marker::PhantomData<(T, core::cell::Cell<()>)>,
}

/// `source_timestamp_ns` (nanoseconds since the Unix epoch, the same unit
/// `SampleInfo::source_timestamp_ns` reports) as an RTPS `Time_t`
/// (seconds, fraction of a second as a 32-bit binary fraction) --
/// [`builder::now_rtps_timestamp`]'s own representation, so a
/// `_w_timestamp` override and the clock it replaces are interchangeable
/// everywhere a source timestamp is staged or stamped.
pub(super) fn rtps_timestamp_from_unix_nanos(source_timestamp_ns: u64) -> (u32, u32) {
    let sec = u32::try_from(source_timestamp_ns / 1_000_000_000).unwrap_or(u32::MAX);
    let subsec_ns = source_timestamp_ns % 1_000_000_000;
    // Same fraction conversion as `now_rtps_timestamp`: subsec_ns is below
    // 1e9 by construction (the `%` above), so (subsec_ns << 32) / 1e9 fits
    // a u32; the fallback can only be reached by that invariant breaking.
    let frac = u32::try_from((subsec_ns << 32) / 1_000_000_000).unwrap_or(u32::MAX);
    (sec, frac)
}

// Capture APIs expose integer nanoseconds. Choose a binary fraction that
// decodes to that same value, avoiding another nanosecond of truncation on
// every relay or local-history replay.
fn rtps_timestamp_preserving_unix_nanos(source_timestamp_ns: u64) -> (u32, u32) {
    let sec = u32::try_from(source_timestamp_ns / 1_000_000_000).unwrap_or(u32::MAX);
    // subsec is below 1e9, so the ceiling stays below 2^32 and always fits.
    let fraction = ((source_timestamp_ns % 1_000_000_000) << 32).div_ceil(1_000_000_000);
    let fits = u32::try_from(fraction);
    debug_assert!(
        fits.is_ok(),
        "the binary fraction of a sub-second stamp fits 32 bits"
    );
    let fraction = fits.unwrap_or_else(|_| {
        log::error!("RTPS fraction saturated: a sub-second stamp exceeded 32 bits");
        u32::MAX
    });
    (sec, fraction)
}

/// The inverse of [`rtps_timestamp_from_unix_nanos`]: an RTPS `Time_t`
/// (seconds, 32-bit binary fraction of a second) back to epoch
/// nanoseconds, the unit `SampleInfo::source_timestamp_ns` reports. Same
/// fraction math as the wire decoder (`engine::router::info_ts_ns_at`),
/// so a stamp built from an application's `_w_timestamp` override and one
/// decoded off the wire answer identically for the same instant.
pub(super) fn unix_nanos_from_rtps_timestamp(stamp: (u32, u32)) -> u64 {
    let (sec, frac) = stamp;
    u64::from(sec) * 1_000_000_000 + ((u64::from(frac) * 1_000_000_000) >> 32)
}

/// Clears `DataWriter::pending_source_ts` when a `_w_timestamp` call
/// returns, on every exit path (success, an error returned before the
/// override was ever read, or a panic unwinding through it): the next
/// plain `write()` or lifecycle call must read the clock itself, never a
/// stale override left behind by an early return.
struct PendingSourceTsGuard<'a, T: DDS>(&'a DataWriter<T>);

impl<T: DDS> Drop for PendingSourceTsGuard<'_, T> {
    fn drop(&mut self) {
        self.0.pending_source_ts.set(None);
    }
}

/// Build the dialect-correct ECS close replay packet for one late
/// joiner, or `None` when the replay must be SKIPPED (see `replay_to`'s
/// `ChangeKind::EcsClose` doc: unresolved vendor, or incomplete ECS
/// metadata -- never guess a close dialect).
///
/// Reuses `nack::build_ecs_repair_packet`'s exact HDDS-native-form
/// regeneration when the vendor resolves to HDDS (unchanged from
/// on_nack's own repair of this same slot). For EVERY classic-model
/// vendor -- InterCOM (0x0105) INCLUDED -- this returns the bare close
/// MARKER via `coherent::ecs_close_form_for`, the SAME decision the live
/// path (`WriterCoherentBridge::dispatch_ecs`) makes. This is the one
/// deliberate divergence from `nack::build_ecs_repair_packet`: on_nack's
/// InterCOM branch builds a single-SN GAP instead, which retires a
/// SPECIFIC already-NACKed SN -- a repair concept that does not apply to
/// a late joiner seeing the close for the FIRST time. See
/// `ecs_close_form_for`'s doc for the full rationale.
fn build_ecs_close_replay_packet(
    ctx: &crate::protocol::builder::RtpsEndpointContext,
    topic: &str,
    change: &crate::reliability::CachedChange,
    reader_entity_id: [u8; 4],
    reader_vendor: Option<u16>,
) -> Option<Vec<u8>> {
    let vendor = reader_vendor?;

    if vendor == crate::core::rtps_constants::HDDS_VENDOR_ID_U16 {
        return super::nack::build_ecs_repair_packet(
            ctx,
            topic,
            change,
            reader_entity_id,
            Some(vendor),
        );
    }

    let source_ts = if !change.metadata.source_ts_known {
        builder::now_rtps_timestamp()
    } else {
        change.metadata.source_ts
    };
    super::coherent::ecs_close_form_for(
        Some(vendor),
        Some(ctx),
        reader_entity_id,
        change.seq,
        source_ts,
        &[],
    )
}

pub(super) struct WriterReplayState {
    topic: String,
    rtps_endpoint: Option<crate::protocol::builder::RtpsEndpointContext>,
    transport: Arc<UdpTransport>,
    history_cache: Arc<HistoryCache>,
    /// Vendor resolution for the late joiner's reader entity id / RTPS
    /// vendor id (see `reader_wire_profile`), mirroring
    /// `RetransmitCfg::discovery_fsm`. `None` when the writer was built
    /// without a discovery FSM (e.g. no participant); every replay then
    /// falls back to the un-finalized canonical packet, exactly as
    /// before this field existed.
    discovery_fsm: Option<Arc<crate::core::discovery::multicast::DiscoveryFsm>>,
    /// Per-writer ECS-replay outcome counters (item 7c): one `AtomicU64`
    /// per `EcsReplayOutcome` variant, indexed by `EcsReplayOutcome as
    /// usize`. Cheap to own here (no allocation beyond this fixed-size
    /// array) and scoped to exactly the writer this `WriterReplayState`
    /// belongs to, unlike the process-wide statics this replaced.
    ecs_replay_counters: [AtomicU64; 5],
}

impl WriterReplayState {
    pub(super) fn new(
        topic: String,
        rtps_endpoint: Option<crate::protocol::builder::RtpsEndpointContext>,
        transport: Arc<UdpTransport>,
        history_cache: Arc<HistoryCache>,
        discovery_fsm: Option<Arc<crate::core::discovery::multicast::DiscoveryFsm>>,
    ) -> Self {
        Self {
            topic,
            rtps_endpoint,
            transport,
            history_cache,
            discovery_fsm,
            ecs_replay_counters: Default::default(),
        }
    }

    /// Bump the counter for `outcome` (item 7c: per-writer, see
    /// `ecs_replay_counters`'s doc).
    fn record_ecs_replay_outcome(&self, outcome: EcsReplayOutcome) {
        self.ecs_replay_counters[outcome as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot this writer's ECS-replay outcome counters, in
    /// `EcsReplayOutcome` declaration order, for `DataWriter::stats()`.
    pub(super) fn ecs_replay_counters(&self) -> [u64; 5] {
        std::array::from_fn(|i| self.ecs_replay_counters[i].load(Ordering::Relaxed))
    }

    /// Resolve the late joiner's `ReaderWireProfile` from its GUID, when
    /// known. `None` propagates through to "send the canonical packet
    /// as-is" at every call site (unresolved reader = today's behavior).
    fn reader_wire_profile(&self, reader_guid: Option<[u8; 16]>) -> Option<ReaderWireProfile> {
        let guid = reader_guid?;
        let vendor = self
            .discovery_fsm
            .as_deref()
            .and_then(|fsm| fsm.vendor_id_for_participant(&super::nack::participant_guid_of(guid)));
        Some(ReaderWireProfile {
            entity_id: super::nack::reader_entity_id_of(guid),
            vendor,
        })
    }

    pub(super) fn replay_to(&self, endpoint: SocketAddr, reader_guid: Option<[u8; 16]>) {
        // The door, here too: whoever asks for a replay, a reader the
        // security plugins do not admit gets none of the history.
        if !replay_admits(self.discovery_fsm.as_deref(), &self.topic, reader_guid) {
            log::debug!(
                "[writer] history replay on topic '{}' to {:?}: refused by the security plugins",
                self.topic,
                reader_guid
            );
            return;
        }
        let changes = self.history_cache.snapshot_changes_for_replay();
        if changes.is_empty() {
            return;
        }

        log::debug!(
            "[writer] Replaying {} cached sample(s) on topic '{}' to {} (reader_guid={:?})",
            changes.len(),
            self.topic,
            endpoint,
            reader_guid
        );

        let reader_profile = self.reader_wire_profile(reader_guid);
        let classic_window = super::nack::requires_classic_window(
            &self.history_cache,
            self.discovery_fsm.as_deref(),
            reader_guid,
        );
        // The late joiner's GROUP class: the form its changes replay in.
        // `base_form` is refined per change (`GroupForm::for_change`).
        let base_form = super::nack::reader_form(self.discovery_fsm.as_deref(), reader_guid);
        let spec = base_form == super::nack::GroupForm::Spec;

        // Coherent sets whose replay actually has a member left in THIS
        // snapshot. `History::KeepLast` evicts cache entries individually
        // (not by coherent set), so an `EcsClose` entry can survive after
        // every `UserData` change of its own set was evicted -- replaying
        // that close would tell a late joiner a set is closed when it
        // never saw ANY member of it. Computed once, from the same
        // snapshot every change below is drawn from, so it can never see
        // a different cache state than the close it gates (see the
        // `ChangeKind::EcsClose` branch below).
        //
        // A close's `coherent_sn` is the LAST SN of the set it closes (what
        // `emit_ecs_data` is given), a member's is the set's FIRST: a close
        // at `seq` with last `L` has a member left when a tagged change lies
        // after the previous close and at or below `L`. Matched by value,
        // the two never meet for a set of more than one change, which would
        // make the close of every such set an orphan.
        let mut members: Vec<u64> = changes
            .iter()
            .filter(|c| c.metadata.kind == ChangeKind::UserData && c.metadata.coherent_sn.is_some())
            .map(|c| c.seq)
            .collect();
        members.sort_unstable();
        let mut closes: Vec<(u64, Option<u64>)> = changes
            .iter()
            .filter(|c| c.metadata.kind == ChangeKind::EcsClose)
            .map(|c| (c.seq, c.metadata.coherent_sn))
            .collect();
        closes.sort_unstable();
        let mut live_closes: std::collections::HashSet<u64> = std::collections::HashSet::new();
        let mut previous_close = 0u64;
        for &(close_seq, last) in &closes {
            if let Some(last) = last {
                let from = members.partition_point(|&m| m <= previous_close);
                if members.get(from).is_some_and(|&m| m <= last) {
                    live_closes.insert(close_seq);
                }
            }
            previous_close = close_seq;
        }

        for change in changes {
            let seq = change.seq;

            // An ECS close slot must NEVER be regenerated as a plain empty
            // user DATA here: its cached payload is empty, and a classic
            // receiver may materialize a payload-less user DATA as
            // an extra sample (one more than the writer wrote: the defect the
            // on_nack path guards against, see history_cache.rs's
            // insert_ecs_close doc comment). Instead, emit the dialect-
            // correct close form for the late joiner's dialect
            // (`build_ecs_close_replay_packet`), since the reader's
            // entity id and RTPS vendor id are resolved right here from
            // `reader_guid`. This matters for BestEffort durable writers:
            // they have a replay callback but NO NACK handler at all
            // (BestEffort registers no `WriterNackHandler`), so a
            // BestEffort late joiner that never gets the close here would
            // never get it -- there is no on_nack fallback to catch it.
            // Reliable late joiners still benefit: less often relying on
            // a round-trip NACK to learn the set is closed. Only when the
            // reader (or its vendor) is unresolved, or the ECS metadata
            // is incomplete (`build_ecs_close_replay_packet` returns
            // `None`), does this fall back to skipping + counting --
            // exactly today's behavior for that case, and still safe for
            // Reliable readers (they NACK the hole and on_nack retries
            // once the vendor resolves). UNLIKE on_nack's repair of this
            // same slot, InterCOM gets the bare close MARKER here, not a
            // single-SN GAP -- see `build_ecs_close_replay_packet`'s doc.
            if change.metadata.kind == ChangeKind::EcsClose {
                // Orphan gate (item 5): `KEEP_LAST` evicts individually, so
                // this close slot can outlive every `UserData` member of
                // its own coherent set. Replaying it then would tell the
                // late joiner a set closed that it never received any part
                // of -- skip and count it DISTINCTLY from "vendor
                // unresolved" below, since this is not a dialect problem.
                // No coherent_sn at all: nothing to match against, treated
                // as orphaned rather than guessed (`live_closes`).
                //
                // A plain reader takes no end-of-set marker: the close SN is
                // retired with a GAP (`plain_close_gap`), whether or not the
                // set it closes survives in this snapshot.
                if base_form.for_change(change.group.is_some()) == super::nack::GroupForm::Plain {
                    let gap = match (self.rtps_endpoint, reader_profile) {
                        (Some(ctx), Some(profile)) => {
                            super::nack::plain_close_gap(&ctx, profile.entity_id, seq)
                        }
                        _ => Vec::new(),
                    };
                    let outcome = if gap.is_empty() {
                        EcsReplayOutcome::UnresolvedVendor
                    } else {
                        match self.history_cache.wire_windows.send_profile(
                            &self.transport,
                            &gap,
                            &endpoint,
                            reader_guid.map(GUID::from_bytes),
                            classic_window,
                        ) {
                            Ok(_) => EcsReplayOutcome::BuiltAndSent,
                            Err(_) => EcsReplayOutcome::SendError,
                        }
                    };
                    self.record_ecs_replay_outcome(outcome);
                    continue;
                }
                let is_orphaned = !live_closes.contains(&seq);

                // The end of a set its writer had no part in: replayed to a
                // late joiner of the spec class only (it has no member to
                // be an orphan of); any other late joiner asks for it and is
                // answered with a GAP (nack.rs).
                let idle = change
                    .group
                    .is_some_and(|tag| tag.part_first_sn == Some(seq));
                let is_orphaned = is_orphaned && !(idle && spec);
                let outcome = if is_orphaned || (idle && !spec) {
                    EcsReplayOutcome::OrphanClose
                } else {
                    match reader_profile
                        .filter(|profile| profile.vendor.is_some())
                        .zip(self.rtps_endpoint)
                    {
                        // No reader identity at all, or a resolved identity
                        // whose RTPS vendor never resolved: never guess a
                        // close dialect (also covers "no RTPS endpoint
                        // context", too rare/degenerate a writer state to
                        // warrant its own variant).
                        None => EcsReplayOutcome::UnresolvedVendor,
                        Some((profile, ctx)) => match spec
                            .then(|| {
                                super::nack::spec_ecs_packet(
                                    &ctx,
                                    &self.topic,
                                    &change,
                                    profile.entity_id,
                                )
                            })
                            .flatten()
                            .or_else(|| {
                                build_ecs_close_replay_packet(
                                    &ctx,
                                    &self.topic,
                                    &change,
                                    profile.entity_id,
                                    profile.vendor,
                                )
                            }) {
                            None => EcsReplayOutcome::IncompleteMetadata,
                            Some(packet) => {
                                match self.history_cache.wire_windows.send_profile(
                                    &self.transport,
                                    &packet,
                                    &endpoint,
                                    reader_guid.map(GUID::from_bytes),
                                    classic_window,
                                ) {
                                    Ok(_) => EcsReplayOutcome::BuiltAndSent,
                                    Err(_) => EcsReplayOutcome::SendError,
                                }
                            }
                        },
                    }
                };
                self.record_ecs_replay_outcome(outcome);

                match outcome {
                    EcsReplayOutcome::BuiltAndSent => {
                        log::debug!(
                            "[writer] Replayed dialect-correct ECS close form for seq {} \
                             topic='{}' to {}",
                            seq,
                            self.topic,
                            endpoint
                        );
                    }
                    EcsReplayOutcome::OrphanClose => {
                        log::debug!(
                            "[writer] Skipping ECS close-slot replay for seq {} topic='{}': \
                             ORPHANED (no member of coherent_sn={:?} survives in this \
                             snapshot; KEEP_LAST evicted it individually) -- replaying \
                             the close alone would close a set the late joiner never saw",
                            seq,
                            self.topic,
                            change.metadata.coherent_sn
                        );
                    }
                    EcsReplayOutcome::UnresolvedVendor => {
                        log::debug!(
                            "[writer] Skipping ECS close-slot replay for seq {} topic='{}': \
                             reader vendor unresolved (never guess a close dialect); a \
                             Reliable reader will NACK the SN and on_nack retries once \
                             its vendor resolves",
                            seq,
                            self.topic
                        );
                    }
                    EcsReplayOutcome::IncompleteMetadata => {
                        log::debug!(
                            "[writer] Skipping ECS close-slot replay for seq {} topic='{}': \
                             ECS metadata incomplete (e.g. no cached coherent_sn for the \
                             native form); a Reliable reader will NACK the SN and on_nack \
                             retries",
                            seq,
                            self.topic
                        );
                    }
                    EcsReplayOutcome::SendError => {
                        log::debug!(
                            "[writer] ECS close-slot replay for seq {} topic='{}' built \
                             successfully but the unicast send to {} failed",
                            seq,
                            self.topic,
                            endpoint
                        );
                    }
                }
                continue;
            }

            // A dispose or unregister in the history replays as the key-only
            // DATA it was live, through the same per-reader transforms as a
            // sample (the live path sends it through the same helper).
            if let Some(packet) = super::nack::lifecycle_change_packet_form(
                self.rtps_endpoint,
                &self.topic,
                &change,
                base_form,
            ) {
                if packet.is_empty() {
                    log::debug!(
                        "[writer] lifecycle replay for seq {} could not be built",
                        seq
                    );
                    continue;
                }
                let packet = match reader_profile {
                    Some(profile) => finalize_for_reader(packet, profile, false),
                    None => packet,
                };
                if let Err(err) = self.history_cache.wire_windows.send_profile(
                    &self.transport,
                    &packet,
                    &endpoint,
                    reader_guid.map(GUID::from_bytes),
                    classic_window,
                ) {
                    log::debug!("[writer] History replay failed for seq {}: {}", seq, err);
                }
                continue;
            }
            let payload = &change.payload;
            // Replay the journaled wire INFO_TS so a repair reproduces the
            // exact live timestamp instead of stamping a fresh one.
            // `source_ts_known == false` means the change was inserted
            // through a helper that never learned a real source_ts -- fall
            // back to now() in that case only. NOT an in-band `(0, 0)` check: `(0, 0)` is a legal
            // wire timestamp (the RTPS epoch), see
            // `ChangeMetadata::source_ts_known`.
            let source_ts = if !change.metadata.source_ts_known {
                builder::now_rtps_timestamp()
            } else {
                change.metadata.source_ts
            };
            // Check if payload needs fragmentation
            if builder::should_fragment(payload.len()) {
                if let Some(ctx) = self.rtps_endpoint {
                    // Reuse the live write()'s journaled fragment size when
                    // known (0 means the change was never fragmented or
                    // carries no journaled size): a different
                    // fragment size renumbers fragments and corrupts the
                    // reader's reassembly.
                    let fragment_size = if change.metadata.frag_size != 0 {
                        change.metadata.frag_size as usize
                    } else {
                        builder::DEFAULT_FRAGMENT_SIZE
                    };
                    let frag_packets = super::nack::change_frag_packets_form(
                        &ctx,
                        &self.topic,
                        seq,
                        payload,
                        &change.metadata,
                        change.group.as_ref(),
                        fragment_size,
                        source_ts,
                        base_form,
                    );
                    log::debug!(
                        "[writer] Replaying {} DATA_FRAG packets for seq {} ({} bytes)",
                        frag_packets.len(),
                        seq,
                        payload.len()
                    );
                    for packet in frag_packets {
                        // Entity id patch only (see `finalize_for_reader`'s
                        // `fragmented` doc): every DATA_FRAG leg withholds
                        // the vendor transforms until measured. Unresolved
                        // reader keeps sending the canonical packet as-is.
                        let packet = match reader_profile {
                            Some(profile) => finalize_for_reader(packet, profile, true),
                            None => packet,
                        };
                        if let Err(err) = self.history_cache.wire_windows.send_profile(
                            &self.transport,
                            &packet,
                            &endpoint,
                            reader_guid.map(GUID::from_bytes),
                            classic_window,
                        ) {
                            log::debug!(
                                "[writer] History replay failed for seq {} fragment: {}",
                                seq,
                                err
                            );
                        }
                    }
                } else {
                    log::debug!(
                        "[writer] Skipping large payload replay (no RTPS context) for seq {}",
                        seq
                    );
                }
            } else {
                // Small payload: single DATA packet, rebuilt with the
                // journaled coherent markers, key hash, source timestamp
                // and CDR version so a replayed sample is byte-identical
                // to the original live emission.
                let packet = if let Some(ctx) = self.rtps_endpoint {
                    super::nack::user_data_change_packet_form(
                        ctx,
                        &self.topic,
                        &change,
                        source_ts,
                        base_form,
                    )
                } else {
                    builder::build_data_packet(&self.topic, seq, payload)
                };

                if packet.is_empty() {
                    log::debug!(
                        "[writer] Skipping history replay for seq {} (packet build failed)",
                        seq
                    );
                    continue;
                }

                // Same per-reader wire transforms the live path and on_nack
                // apply (readerEntityId patch, zzdds encap downgrade,
                // InterCOM HEADER_EXTENSION); see `finalize_for_reader`.
                // Unresolved reader (profile = None) keeps sending the
                // canonical packet as-is.
                let packet = match reader_profile {
                    Some(profile) => finalize_for_reader(packet, profile, false),
                    None => packet,
                };

                if let Err(err) = self.history_cache.wire_windows.send_profile(
                    &self.transport,
                    &packet,
                    &endpoint,
                    reader_guid.map(GUID::from_bytes),
                    classic_window,
                ) {
                    log::debug!("[writer] History replay failed for seq {}: {}", seq, err);
                }
            }
        }
    }
}

/// The per-writer figures behind [`WriterStats`], raised at the same door as
/// the process telemetry counter of the same meaning (see
/// `telemetry::metrics::MetricsCollector`), whether or not telemetry is
/// enabled.
///
/// Plain `Cell`s, not atomics: a `DataWriter` is `!Sync` (see `_phantom`),
/// so only the thread that owns it can write or read them. Two relaxed
/// `fetch_add` per `write()` were a locked read-modify-write each and cost
/// about 9 ns p50 on the one-thread write-then-take path.
#[derive(Default)]
pub(super) struct WriterCounters {
    pub(super) messages_sent: core::cell::Cell<u64>,
    pub(super) bytes_sent: core::cell::Cell<u64>,
    pub(super) drops: core::cell::Cell<u64>,
}

impl WriterCounters {
    /// Count one successful write of `len` serialized bytes.
    #[inline]
    pub(super) fn sent(&self, len: usize) {
        self.messages_sent
            .set(self.messages_sent.get().wrapping_add(1));
        self.bytes_sent
            .set(self.bytes_sent.get().wrapping_add(len as u64));
    }
}

/// Per-`DataWriter` telemetry snapshot. `#[non_exhaustive]`: new counters
/// get added here over time (as this ECS-replay set already did once);
/// external construction must go through `..Default::default()` or a
/// future builder so adding a field is never a breaking change.
#[derive(Default, Debug, Clone, Copy)]
#[non_exhaustive]
pub struct WriterStats {
    /// Successful writes of this writer (every `write*` variant), whether
    /// or not a reader is matched. Dispose and unregister are not counted.
    pub messages_sent: u64,
    /// Serialized payload bytes of those writes (before RTPS framing,
    /// fragmentation or encryption).
    pub bytes_sent: u64,
    /// Intra-process deliveries this writer abandoned because the sequence
    /// number or the payload length does not fit the ring entry. A
    /// timeout or a would-block refusal is returned to the caller as an
    /// error and is not a drop.
    pub drops: u64,
    /// Count of ECS close-slot entries `replay_to` built and sent
    /// successfully. See `EcsReplayOutcome::BuiltAndSent`.
    ///
    /// This and the four counters below are PER-WRITER (`WriterReplayState`
    /// owns its own counters), not a process-wide static shared by every
    /// writer in the process. All five are zero for a writer with no
    /// replay hook at all (not TRANSIENT_LOCAL/TRANSIENT/PERSISTENT, or
    /// missing a cache/transport/registry at build time).
    pub replay_ecs_close_sent: u64,
    /// Count of ECS close-slot replays skipped because the late joiner's
    /// reader identity or RTPS vendor id never resolved: never guess a
    /// close dialect. See `EcsReplayOutcome::UnresolvedVendor`.
    pub replay_ecs_close_unresolved_vendor: u64,
    /// Count of ECS close-slot replays skipped because the vendor DID
    /// resolve but the cached metadata was incomplete (e.g. no cached
    /// `coherent_sn`), or the builder returned an empty packet. DISTINCT
    /// from `replay_ecs_close_unresolved_vendor`: this is not a dialect
    /// problem. See `EcsReplayOutcome::IncompleteMetadata`.
    pub replay_ecs_close_incomplete_metadata: u64,
    /// Count of ECS close-slot replays skipped because they are ORPHANED
    /// (no `UserData` member of their own `coherent_sn` survives in the
    /// same snapshot -- `KEEP_LAST` evicts individually, item 5).
    /// DISTINCT from the two counters above: this is not a dialect or
    /// metadata problem, there is simply nothing left to close. See
    /// `EcsReplayOutcome::OrphanClose`.
    pub replay_ecs_close_orphaned: u64,
    /// Count of ECS close-slot replays where the close form built
    /// successfully but the unicast transport send itself failed.
    /// DISTINCT from every "could not build a packet" counter above. See
    /// `EcsReplayOutcome::SendError`.
    pub replay_ecs_close_send_error: u64,
}

impl<T: DDS> DataWriter<T> {
    /// Tests only: the RTPS context the writer emits with.
    #[cfg(test)]
    pub(crate) fn rtps_endpoint_for_test(
        &self,
    ) -> Option<crate::protocol::builder::RtpsEndpointContext> {
        self.rtps_endpoint
    }

    /// Tests only: a write abandoned inside an open set, through the
    /// writer's own decision (`take_group_change`), after another writer
    /// (`other_next_seq`) took the next GSN, as a refused write does.
    /// Returns the (SN, GSN) taken.
    #[cfg(test)]
    pub(crate) fn abandon_in_set_for_test(&self, other_next_seq: &AtomicU64) -> (u64, u64) {
        let core = self.publisher.as_ref().expect("a Publisher");
        let (seq, tag, _coherent, _stamp, _orders) =
            self.take_group_change::<ControlledWrite>(core);
        core.take_sn_and_gsn(other_next_seq, None);
        self.abandon_unpublished_sequence(seq, Some(tag));
        (seq, tag.gsn)
    }

    /// Tests only: take this writer's next SN and GSN, let another writer
    /// (`other_next_seq`) take the next GSN, and with `then_self` this
    /// writer its next SN, then abandon the change, as a refused write
    /// does. Returns the (SN, GSN) taken and the holes the
    /// history then records for that SN.
    /// Tests only: a write of a writer of a Publisher of TOPIC or INSTANCE
    /// scope abandoned after its SN and its coherent context were taken, as
    /// a refused write does. Returns the SN taken.
    #[cfg(test)]
    pub(crate) fn abandon_topic_change_for_test(&self) -> u64 {
        let seq = self.next_seq.fetch_add(1, Ordering::AcqRel);
        let _ = self.coherent_context(seq);
        self.abandon_unpublished_sequence(seq, None);
        seq
    }

    #[cfg(test)]
    pub(crate) fn abandon_past_another_change_for_test(
        &self,
        other_next_seq: &AtomicU64,
        then_self: bool,
    ) -> ((u64, u64), Vec<(u64, u64)>) {
        let core = self.publisher.as_ref().expect("a Publisher");
        let (seq, tag) = core.take_sn_and_gsn(&self.next_seq, self.pending_gsn_slot());
        core.take_sn_and_gsn(other_next_seq, None);
        if then_self {
            core.take_sn_and_gsn(&self.next_seq, None);
        }
        self.abandon_unpublished_sequence(seq, Some(tag));
        let holes = self
            .history_cache
            .as_ref()
            .map(|cache| cache.group_holes_in(seq, seq))
            .unwrap_or_default();
        ((seq, tag.gsn), holes)
    }

    /// Identity of the writer's announced RTPS endpoint, used for RPC correlation.
    #[cfg(feature = "rpc")]
    pub(crate) fn rpc_endpoint_guid(&self) -> Option<crate::core::discovery::GUID> {
        self.rtps_endpoint.map(|context| {
            crate::core::discovery::GUID::new(context.guid_prefix, context.writer_entity_id)
        })
    }

    /// Identity of the writer's announced RTPS endpoint (the security tests,
    /// the TCP reply test).
    #[cfg(test)]
    pub(crate) fn endpoint_guid_for_test(&self) -> Option<crate::core::discovery::GUID> {
        self.rtps_endpoint.map(|context| {
            crate::core::discovery::GUID::new(context.guid_prefix, context.writer_entity_id)
        })
    }

    /// Whether this opaque writer requires per-operation serialized key metadata.
    #[must_use]
    pub fn accepts_serialized_keys(&self) -> bool {
        self.serialized_keys
    }

    #[must_use]
    pub fn qos(&self) -> &QoS {
        &self.qos
    }

    /// Install `listener` for the statuses in `mask`, replacing the
    /// current one, or remove it (`None`) -- DDS v1.4 Sec.2.2.2.1.1
    /// `set_listener`.
    ///
    /// Takes effect for every callback of this writer, including the match
    /// notifications registered when the writer was built.
    /// `on_sample_written` has no DDS status: it is called whenever a
    /// listener is installed, whatever `mask`.
    ///
    /// Callbacks run on HDDS threads: the discovery threads for match and
    /// QoS events, and the application thread that calls `write()` for
    /// `on_sample_written` and `on_offered_deadline_missed`. No writer lock
    /// is held across a callback.
    ///
    /// Does not wait for callbacks already running: a callback that loaded
    /// the previous listener before this call keeps its own reference and
    /// finishes.
    pub fn set_listener(
        &self,
        listener: Option<Arc<dyn DataWriterListener<T>>>,
        mask: crate::dds::StatusMask,
    ) {
        self.listener.set(listener, mask);
    }

    #[must_use]
    pub fn topic_name(&self) -> &str {
        &self.topic
    }

    /// Number of readers currently matched with this writer, remote or of
    /// this participant (DDS v1.4 Sec.2.2.4.1, PUBLICATION_MATCHED
    /// `current_count`). Sums `_match_token` (SEDP: wire-reachable peers)
    /// and `_match_status` (domain_registry.rs: peers with no wire path at
    /// all, otherwise invisible to SEDP) -- disjoint peer sets by
    /// construction (`local_status_applies`), so the sum is never a
    /// double-count of the same peer.
    #[must_use]
    pub fn matched_reader_count(&self) -> u32 {
        let from_token = self._match_token.as_ref().map_or(
            0,
            crate::dds::match_notification::MatchToken::current_match_count,
        );
        let from_status = self
            ._match_status
            .as_ref()
            .map_or(0, |status| status.current_count());
        from_token + from_status
    }

    #[must_use]
    pub fn get_status_condition(&self) -> Arc<crate::dds::StatusCondition> {
        Arc::clone(&self.status_condition)
    }

    /// Manually assert this writer's liveliness (DDS v1.4 Sec.2.2.3.11,
    /// Sec.2.2.2.4.2.22 `assert_liveliness`): renews its LIVELINESS lease
    /// without writing a sample. For MANUAL_BY_PARTICIPANT this renews
    /// the lease every writer of this participant with that kind shares,
    /// and rate-limits a `ParticipantMessage` of kind MANUAL to peers
    /// (RTPS v2.5 Sec.8.4.13.5). For MANUAL_BY_TOPIC this writer's own
    /// lease alone, and -- since there is nothing new to write -- a
    /// HEARTBEAT with the Final and Liveliness flags set, to every
    /// matched reader, BEST_EFFORT writers included. A no-op for
    /// AUTOMATIC (the participant keeps it alive on its own, DDS v1.4
    /// Sec.2.2.3.11: "This operation need only be used if ... MANUAL") and
    /// for an infinite lease.
    pub fn assert_liveliness(&self) -> Result<()> {
        if let Some(ref assert) = self._liveliness_assert {
            assert.assert();
        }
        if self.qos.liveliness.kind == crate::dds::qos::LivelinessKind::ManualByTopic {
            self.assert_liveliness_heartbeat();
        }
        Ok(())
    }

    /// The LIVELINESS_LOST status (DDS v1.4 Sec.2.2.4.1): how many times
    /// this writer (MANUAL_BY_PARTICIPANT, MANUAL_BY_TOPIC only) failed to
    /// assert within its offered lease. `total_count_change` resets to 0
    /// and `StatusMask::LIVELINESS_LOST` clears on the status condition
    /// when this returns, as for `get_offered_deadline_missed_status`.
    /// All-zero for AUTOMATIC or an infinite lease, which never raise it.
    #[must_use]
    pub fn get_liveliness_lost_status(&self) -> crate::dds::listener::LivelinessLostStatus {
        self.liveliness_lost
            .as_ref()
            .map_or_else(crate::dds::listener::LivelinessLostStatus::default, |l| {
                l.status()
            })
    }

    /// MANUAL_BY_TOPIC's `assert_liveliness()` wire effect: a
    /// HEARTBEAT with Final and Liveliness set, to every matched reader --
    /// BEST_EFFORT writers included, unlike the periodic/on-write
    /// HEARTBEAT scheduler, which only RELIABLE writers run.
    ///
    /// Count allocation and the send it names run inside `with_next_count`
    /// (blocking -- this runs on the application's own `assert_liveliness()`
    /// call, never the shared `hdds-hb-sender` worker), so this HEARTBEAT's
    /// count cannot be allocated between the periodic origin's own
    /// allocate-and-send for this writer and reach the wire out of order
    /// (RTPS v2.5 Sec.8.3.8.6: one monotonic count per writer, on the wire).
    /// `send_heartbeat_to_readers` is always called with `best_effort =
    /// false` here: this origin keeps the ordinary blocking send, unchanged.
    fn assert_liveliness_heartbeat(&self) {
        let Some(ctx) = self.rtps_endpoint else {
            return;
        };
        let Some(ref transport) = self.transport else {
            return;
        };
        let last_seq = self
            ._heartbeat_scheduler
            .as_ref()
            .map_or(0, |s| s.state().announced_last_seq());
        let first_seq = if let Some(ref cache) = self.history_cache {
            let cache_oldest =
                super::heartbeat_scheduler::advertised_first_seq(cache.oldest_seq(), last_seq);
            self._heartbeat_scheduler
                .as_ref()
                .map_or(cache_oldest, |s| {
                    s.state().heartbeat_first_seq(cache_oldest)
                })
        } else {
            1
        };

        let send_with_count = |count: u32| {
            let packet =
                builder::build_heartbeat_packet_with_context(&ctx, first_seq, last_seq, count);
            let packet = builder::with_liveliness_assertion_flags(packet);
            if packet.is_empty() {
                return;
            }
            super::heartbeat_scheduler::send_heartbeat_to_readers(
                transport,
                self._heartbeat_scheduler.as_ref().map(|s| &**s.state()),
                self.discovery_fsm.as_deref(),
                self.endpoint_registry.as_ref(),
                &self.topic,
                Some(ctx.guid_prefix),
                &packet,
                None,
                &self.wire_windows,
                false,
            );
        };

        if let Some(ref scheduler) = self._heartbeat_scheduler {
            scheduler.state().with_next_count(send_with_count);
        } else {
            send_with_count(1);
        }
    }

    /// The OFFERED_DEADLINE_MISSED status (DDS v1.4 Sec.2.2.2.4.2.17): how
    /// many times this writer went silent on an instance for longer than
    /// its `deadline` period, piggybacked on `check_offered_deadline` at
    /// the start of each write(). `total_count_change` resets to 0 and
    /// `StatusMask::OFFERED_DEADLINE_MISSED` clears on the status
    /// condition when this returns, as for
    /// `DataReader::get_sample_rejected_status`.
    #[must_use]
    pub fn get_offered_deadline_missed_status(
        &self,
    ) -> crate::dds::listener::OfferedDeadlineMissedStatus {
        self.deadlines.as_ref().map_or_else(
            crate::dds::listener::OfferedDeadlineMissedStatus::default,
            |d| d.status(),
        )
    }

    /// The OFFERED_INCOMPATIBLE_QOS status (DDS v1.4 Sec.2.2.2.4.2.18): how
    /// many matched readers this writer was refused for an incompatible
    /// QoS policy, and the last such policy. Shared with the match
    /// registry's incompatible-QoS callback (`WriterBuilder::build`)
    /// exactly like `publication_matched`. Read-and-reset like
    /// `DataReader::get_sample_rejected_status`.
    #[must_use]
    pub fn get_offered_incompatible_qos_status(
        &self,
    ) -> crate::dds::listener::OfferedIncompatibleQosStatus {
        let mut status = self
            .offered_incompatible_qos
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let snapshot = status.clone();
        status.total_count_change = 0;
        self.status_condition
            .clear_active_status(crate::dds::StatusMask::OFFERED_INCOMPATIBLE_QOS);
        snapshot
    }

    /// The PUBLICATION_MATCHED status (DDS v1.4 Sec.2.2.2.4.2.19): how many
    /// readers this writer has matched, the changes since the last read or
    /// listener call, and the last reader that changed it. Shared with the
    /// match callback (`WriterBuilder::build`), fed by either source that
    /// can report a match for this writer (the SEDP registry or
    /// `domain_registry::LocalMatchStatus`, for a peer with no wire path on
    /// either side). Read-and-reset like
    /// `DataReader::get_sample_rejected_status`.
    #[must_use]
    pub fn get_publication_matched_status(&self) -> crate::dds::listener::PublicationMatchedStatus {
        let mut status = self
            .publication_matched
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let snapshot = status.clone();
        status.total_count_change = 0;
        status.current_count_change = 0;
        self.status_condition
            .clear_active_status(crate::dds::StatusMask::PUBLICATION_MATCHED);
        snapshot
    }

    /// GUIDs of the readers currently matched with this writer (DDS v1.4
    /// Sec.2.2.2.4.2.24 `get_matched_subscriptions`). Not a status (no
    /// read-and-reset, no StatusCondition involvement): a live snapshot of
    /// the match registry's and `domain_registry::LocalMatchStatus`'s
    /// matched-peer sets, which are disjoint by construction, exactly
    /// like `matched_reader_count` above.
    #[must_use]
    pub fn get_matched_subscriptions(&self) -> Vec<crate::core::discovery::GUID> {
        let mut guids = self
            ._match_token
            .as_ref()
            .map(crate::dds::match_notification::MatchToken::matched_remote_guids)
            .unwrap_or_default();
        if let Some(ref status) = self._match_status {
            guids.extend(status.matched_guids());
        }
        guids
    }

    /// How long this writer, deleted after a lifecycle change its readers
    /// acknowledged, stays announced before its SEDP dispose: the longest
    /// `protocol::dialect::retirement::lifecycle_retirement_linger` over the
    /// vendors of its matched remote readers, read once, at deletion.
    pub(super) fn lifecycle_retirement_linger(&self) -> std::time::Duration {
        let Some(fsm) = self.discovery_fsm.as_deref() else {
            return std::time::Duration::ZERO;
        };
        self.get_matched_subscriptions()
            .iter()
            .map(|reader| {
                let vendor = fsm.vendor_id_for_participant(&super::nack::participant_guid_of(
                    reader.as_bytes(),
                ));
                crate::protocol::dialect::retirement::lifecycle_retirement_linger(vendor)
            })
            .max()
            .unwrap_or(std::time::Duration::ZERO)
    }

    pub fn merger(&self) -> Arc<rt::TopicMerger> {
        Arc::clone(&self.merger)
    }

    /// Resolve the coherent-set tags to attach to the next outgoing
    /// DATA sample (RTPS v2.5 sec. 8.7.5).
    ///
    /// Returns `(coherent_sn, group_sn)`:
    /// * `coherent_sn = Some(sample_seq)` when the writer's own QoS has
    ///   `presentation.coherent_access == true` AND the parent publisher
    ///   has an active coherent set; the receiver uses this to associate
    ///   the sample with the writer-scoped set.
    /// * `group_sn = Some(gsn)` when additionally the publisher's
    ///   access_scope is GROUP; the receiver buffers per-(writer, gsn)
    ///   and flushes on ECS arrival.
    ///
    /// Both fields are `None` when the writer is not in any coherent
    /// set; the inline-QoS layout matches the non-coherent path
    /// bit-for-bit so no extra parser cost on the regular DATA hot
    /// path.
    fn coherent_context(
        &self,
        sample_seq: u64,
    ) -> (Option<u64>, Option<u64>, Option<CoherentStamp>) {
        if !self.qos.presentation.coherent_access {
            return (None, None, None);
        }
        let Some(ref publisher) = self.publisher else {
            return (None, None, None);
        };
        // Serialise the (read GSN, store last_sn) sequence with the
        // publisher's open/close transitions. Without this lock a
        // concurrent `end_coherent_changes` could swap `current_set_gsn`
        // out between the `is_coherent()` check and the
        // `last_sn_in_active_set.store(seq)` below, leaving the sample
        // tagged with a closed GSN (an intermittent HDDS<->HDDS
        // coherent-set failure). The lock is held
        // only for the duration of two atomic reads and one atomic
        // store -- well below a microsecond -- and is never held across
        // the actual UDP send (which happens after `coherent_context`
        // returns in the caller).
        let _set_guard = publisher
            .set_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.coherent_context_held(publisher, sample_seq)
    }

    /// A GROUP Publisher's writer takes its change's SN, its GSN and its
    /// coherent context in ONE critical section of the Publisher's lock
    /// (`PublisherCore::take_sn_and_gsn_then`): the GSN tag's set and the
    /// PID_COHERENT_SET (and the end of set's last SN) describe the same
    /// set. Decided apart, a begin or an end between the two gave a change
    /// 0x0063 without 0x0056 or the converse, and an end of set naming a
    /// change of no set. A writer whose QoS has no coherent access tags no
    /// set either way.
    #[allow(clippy::type_complexity)]
    fn take_group_change<M: LocalWriteMode>(
        &self,
        core: &crate::dds::publisher::PublisherCore,
    ) -> (
        u64,
        GroupTag,
        (Option<u64>, Option<u64>),
        Option<CoherentStamp>,
        M::Orders,
    ) {
        let (seq, mut tag, ((coherent_sn, group_sn, stamp), orders)) =
            core.take_sn_and_gsn_then(&self.next_seq, self.pending_gsn_slot(), |seq| {
                let context = if self.qos.presentation.coherent_access {
                    self.coherent_context_held(core, seq)
                } else {
                    (None, None, None)
                };
                let orders = if self.qos.presentation.ordered_access {
                    M::reserve_order(core, &self.merger, seq, context.0.is_some())
                } else {
                    M::Orders::default()
                };
                (context, orders)
            });
        let coherent = (coherent_sn, group_sn);
        if coherent.0.is_none() {
            tag.set_first_gsn = None;
        }
        (seq, tag, coherent, stamp, orders)
    }

    /// `coherent_context` with the Publisher's lock held by the caller.
    fn coherent_context_held(
        &self,
        publisher: &crate::dds::publisher::PublisherCore,
        sample_seq: u64,
    ) -> (Option<u64>, Option<u64>, Option<CoherentStamp>) {
        if !publisher.is_coherent() {
            return (None, None, None);
        }
        // Emit PID_COHERENT_SET = the set's FIRST writer SN, constant across
        // every sample of the set (DDSI-RTPS 2.5 8.7.6), so classic-model
        // subscribers group all samples into one set instead of seeing
        // singletons. `current_set_gsn()` is a non-zero set identity for the
        // whole begin/end window (any access_scope) and resets to 0 at close,
        // so a change signals a new set: anchor the first SN once per set.
        let set_gsn = publisher.current_set_gsn();
        let raw_group_sn = publisher.group_coherent_gsn();
        let coherent_first_sn = if self.coherent_set_gsn_seen.load(Ordering::Acquire) != set_gsn {
            self.coherent_set_gsn_seen.store(set_gsn, Ordering::Release);
            self.coherent_set_first_sn
                .store(sample_seq, Ordering::Release);

            sample_seq
        } else {
            self.coherent_set_first_sn.load(Ordering::Acquire)
        };
        let coherent_sn = Some(coherent_first_sn);
        let group_sn = raw_group_sn;
        // Track this sample as the latest in the active set so that
        // Publisher::end_coherent_changes can read it via
        // `take_last_sn_in_active_set` (WriterCoherentBridge).
        let last = self
            .last_sn_in_active_set
            .swap(sample_seq, Ordering::AcqRel);
        *self
            .set_undo
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = SetUndo {
            seq: sample_seq,
            last,
        };
        // A member of the open set from here: its local delivery waits for
        // this stamp to stage or be withdrawn (`intra_coherent`), registered
        // in the same `set_lock` critical section as the tags above, so the
        // set's close always finds it.
        let stamp = Some(self.intra_coherent_sets.stamp(
            coherent_first_sn,
            group_sn,
            group_sn.map(|_| publisher.current_gsn()),
        ));
        (coherent_sn, group_sn, stamp)
    }

    /// Undo what the change `seq`, abandoned with its SN given back, did to
    /// the writer's coherent set: the set's last SN goes back to the
    /// writer's previous change in it (none: 0). Without it, the end of set
    /// would take the given-back SN and name it as the set's last member:
    /// itself, a member that was never made. (A part of the set the change
    /// opened stays anchored at its SN: the writer's next change in the set
    /// takes that SN again, and an end of set with no change of the writer
    /// before it is the end of a writer with no change in the set.) Called
    /// under the Publisher's lock, before any other change of the writer can
    /// take an SN.
    fn undo_set_context(&self, seq: u64) {
        let undo = *self
            .set_undo
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if undo.seq != seq || self.last_sn_in_active_set.load(Ordering::Acquire) != seq {
            // The change took no part in a set.
            return;
        }
        self.last_sn_in_active_set
            .store(undo.last, Ordering::Release);
    }

    /// The writer is about to take an SN for a change it journals
    /// (`HistoryCache::taking`): held until the change is journaled or
    /// abandoned. Only a writer of a Publisher has another producer of its
    /// SNs (the Publisher's ends of set, `WriterCoherentBridge`); any other
    /// takes and journals its changes in order on its one thread, and pays
    /// nothing.
    pub(super) fn taking_change(&self) -> Option<crate::reliability::InFlight<'_>> {
        self.publisher.as_ref()?;
        self.history_cache.as_deref().map(|cache| {
            cache.taking(
                crate::reliability::Producer::Writer,
                self.next_seq.load(Ordering::Acquire),
            )
        })
    }

    /// Give back the SN and GSN of a GROUP change that was not made, and
    /// with the SN, what the change did to its coherent set
    /// (`undo_set_context`).
    fn give_back_group_change(
        &self,
        core: &crate::dds::publisher::PublisherCore,
        seq: u64,
        gsn: u64,
    ) -> crate::dds::publisher::GiveBack {
        core.give_back_sn_and_gsn_then(&self.next_seq, seq, gsn, || self.undo_set_context(seq))
    }

    /// Store change `seq` in the history cache BEFORE it is emitted on any
    /// leg (wire, shared memory, intra-process).
    ///
    /// DDS 1.4 2.2.2.4.2.11: a RELIABLE write "may block if the modification
    /// would cause data to be lost or else cause one of the limits specified
    /// in the RESOURCE_LIMITS to be exceeded", for at most
    /// `max_blocking_time`, then "fail and return TIMEOUT". The change must
    /// not be emitted first and journaled after (a refusal logged and
    /// `write()` returning Ok): that leaves a sample on the wire that can be
    /// neither repaired nor replayed, and, while it sits between the two, a
    /// NACK for it is answered with a GAP.
    ///
    /// On `Err` nothing has been emitted; the caller gives back what it
    /// reserved (see [`abandon_before_emission`](Self::abandon_before_emission)).
    ///
    /// `deadline` is the write's: a wait here shares it with every other
    /// wait of the same `write()`.
    fn journal_before_emission<M: LocalWriteMode>(
        &self,
        seq: u64,
        payload: &[u8],
        metadata: (ChangeMetadata, Option<GroupTag>),
        deadline: &rt::WriteDeadline,
    ) -> Result<()> {
        self.journal_change_in_mode::<M>(seq, payload, metadata, Some(deadline))
    }

    /// [`journal_before_emission`](Self::journal_before_emission), which
    /// may wait only when `may_block`: the Drop-time auto-unregister runs
    /// once per registered instance while the writer is being torn down, and
    /// must not stall that for `max_blocking_time` each.
    fn journal_change(
        &self,
        seq: u64,
        payload: &[u8],
        metadata: (ChangeMetadata, Option<GroupTag>),
        may_block: Option<&rt::WriteDeadline>,
    ) -> Result<()> {
        self.journal_change_in_mode::<ControlledWrite>(seq, payload, metadata, may_block)
    }

    fn journal_change_in_mode<M: LocalWriteMode>(
        &self,
        seq: u64,
        payload: &[u8],
        metadata: (ChangeMetadata, Option<GroupTag>),
        may_block: Option<&rt::WriteDeadline>,
    ) -> Result<()> {
        let (metadata, group) = metadata;
        let Some(ref cache) = self.history_cache else {
            self.wire_windows.record_unretained(seq);
            return Ok(());
        };
        let deadline = may_block
            .filter(|_| {
                matches!(
                    self.qos.reliability,
                    super::super::qos::Reliability::Reliable
                )
            })
            .map(rt::WriteDeadline::instant);
        let inserted = if M::CONTROLLED {
            cache.insert_grouped_until(seq, payload, 0, metadata, group, deadline)
        } else {
            cache.insert_plain_until(seq, payload, 0, metadata, group, deadline)
        };
        match inserted {
            Ok(()) => Ok(()),
            Err(e) => {
                log::debug!(
                    "[writer] topic='{}' seq={} refused by the history before emission: {}",
                    self.topic,
                    seq,
                    e
                );
                // `WouldBlock` once the deadline has passed is the blocked
                // write that ran out of time; before it (the slab pool
                // itself is exhausted) it stays `WouldBlock`.
                match e {
                    Error::WouldBlock if deadline.is_some_and(|d| Instant::now() >= d) => {
                        Err(Error::WriteTimeout)
                    }
                    other => {
                        // The write comes back `WouldBlock` to the
                        // application, as it does from `reserve_local_leg`.
                        if matches!(other, Error::WouldBlock) {
                            if let Some(m) = telemetry::get_metrics_opt() {
                                m.increment_would_block(1);
                            }
                        }
                        Err(other)
                    }
                }
            }
        }
    }

    /// Undo what `write()` reserved for a change that will not be emitted:
    /// the intra-process slab entry and the sequence number.
    fn abandon_before_emission(
        &self,
        seq: u64,
        intra_handle: Option<rt::SlabHandle>,
        group: Option<GroupTag>,
    ) {
        if let Some(handle) = intra_handle {
            rt::get_slab_pool_ref().release(handle);
        }
        self.abandon_unpublished_sequence(seq, group);
    }

    /// Give back the SN of a change that was not made, and with it, for a
    /// GROUP Publisher's writer, the GSN taken with it when it is still the
    /// Publisher's last (`PublisherCore::give_back_sn_and_gsn`).
    fn abandon_unpublished_sequence(&self, seq: u64, group: Option<GroupTag>) {
        if let (Some(tag), Some(core)) = (group, self.publisher.as_ref()) {
            if self.give_back_group_change(core, seq, tag.gsn)
                == crate::dds::publisher::GiveBack::Neither
            {
                log::warn!(
                    "[writer] Could not give back unpublished seq={} gsn={} topic='{}'",
                    seq,
                    tag.gsn,
                    self.topic
                );
                // A hole in both numberings: the GAP that repairs the SN
                // names the GSN to readers of the spec class.
                if let Some(cache) = self.history_cache.as_ref() {
                    cache.record_group_hole(seq, tag.gsn);
                }
            }
            return;
        }
        // A writer of a Publisher of another scope: the SN given back under
        // the Publisher's lock with what the change did to its coherent set
        // (`undo_set_context`), as a GROUP writer's is: else the end of set
        // took the SN and named it as the set's last member, itself.
        if let Some(core) = self.publisher.as_ref() {
            if !core.give_back_sn_then(&self.next_seq, seq, || self.undo_set_context(seq)) {
                log::warn!(
                    "[writer] Could not give back unpublished seq={} topic='{}'",
                    seq,
                    self.topic
                );
            }
            return;
        }
        let expected_next = seq.wrapping_add(1);
        if let Err(actual) =
            self.next_seq
                .compare_exchange(expected_next, seq, Ordering::AcqRel, Ordering::Acquire)
        {
            log::warn!(
                "[writer] Could not give back unpublished seq={} topic='{}' next_seq={} expected={}",
                seq,
                self.topic,
                actual,
                expected_next
            );
        }
    }

    /// The version this writer serializes every sample in (`cdr_version`):
    /// a field read, no lookup of the readers discovery knows.
    pub fn effective_cdr_version(&self) -> crate::dds::CdrVersion {
        self.cdr_version
    }

    /// Send this writer's DATA to `addr` only, in place of the readers
    /// discovery matched: a test reads back the datagrams the writer puts
    /// on the wire, through whichever path created it. See
    /// [`crate::test_support::wire::capture_data`].
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn send_data_to_for_test(&mut self, addr: std::net::SocketAddr) {
        let registry = crate::core::discovery::EndpointRegistry::new();
        registry.register(
            crate::core::discovery::GUID::new([0x7E; 12], [0x00, 0x00, 0x01, 0xC1]),
            addr,
        );
        self.endpoint_registry = Some(registry);
        self.discovery_fsm = None;
    }

    /// The protection this writer's topic is created under, from the cache
    /// (`security::protection_cache`). The generation is read BEFORE the
    /// governance rule walk it files, so a reload landing in between can only
    /// file an answer under a generation that is already stale, never serve
    /// one under a generation it was not resolved at.
    #[cfg(feature = "security")]
    fn endpoint_protection(
        &self,
        suite: &crate::security::SecurityPluginSuite,
    ) -> Result<crate::protocol::discovery::EndpointSecurityInfo> {
        let generation = suite.local_restriction_generation();
        self.protection.get(generation, || {
            crate::security::crypto::user_data::endpoint_security_info(suite, &self.topic)
                .map_err(|e| Error::EncryptionUnavailable(e.to_string()))
        })
    }

    /// MD5 of the CDR big-endian key fields when key protection is announced.
    ///
    /// DDS-Security v1.1 Sec.7.3.4 computes the KeyHash "for the Instance
    /// Key": a type without one has no KeyHash to announce, and an empty
    /// holder would announce the digest of nothing.
    #[cfg(feature = "security")]
    fn protected_key_hash(&self, msg: &T) -> Result<Option<[u8; 16]>> {
        let Some(suite) = self.security.as_ref() else {
            return Ok(None);
        };
        if !T::has_key() && msg.instance_key().is_none() {
            return Ok(None);
        }
        let attributes = self.endpoint_protection(suite)?;
        if !attributes.is_key_protected() {
            return Ok(None);
        }
        let hash = msg.protected_key().ok_or_else(|| {
            Error::EncryptionUnavailable(format!(
                "topic '{}': protected key has no KeyHolder serialization",
                self.topic
            ))
        })?;
        Ok(Some(hash))
    }

    /// Seal the serialized sample for the wire under this writer's data-plane
    /// key, or pass it through untouched when encryption was never requested.
    ///
    /// Returns `(bytes, was_sealed)`. The flag is load-bearing: the caller
    /// stores the SEALED bytes in the reliable history cache when it is true,
    /// so NACK repair and TRANSIENT_LOCAL replay resend the ciphertext that
    /// went on the wire rather than the plaintext.
    ///
    /// **Fails closed** when encryption was requested and no key exists --
    /// which, since keys are minted at writer build, means the writer was
    /// built without an RTPS endpoint or the mint was bypassed. Never
    /// cleartext.
    #[cfg(feature = "security")]
    fn seal_payload_for_wire(
        &self,
        plaintext: &[u8],
        version: CdrVersion,
    ) -> Result<(Vec<u8>, bool)> {
        let Some(suite) = self.security.as_ref() else {
            return Ok((plaintext.to_vec(), false));
        };

        let attributes = self.endpoint_protection(suite)?;
        if !attributes.is_payload_protected() {
            return Ok((plaintext.to_vec(), false));
        }
        let key = self.rtps_endpoint.and_then(|ctx| {
            suite
                .data_keys
                .material_for_writer(&GUID::new(ctx.guid_prefix, ctx.writer_entity_id))
        });
        let Some((key_id, key)) = key else {
            log::error!(
                "[writer] topic='{}': encryption is enabled but this writer holds no \
                 data-plane key (minting happens at build time and requires an RTPS \
                 endpoint) -- refusing to emit {} bytes in cleartext",
                self.topic,
                plaintext.len()
            );
            return Err(Error::EncryptionUnavailable(format!(
                "topic '{}': this writer holds no data-plane key",
                self.topic
            )));
        };

        let encrypted = key.transformation
            == crate::security::crypto::secure_submessage::Transformation::Aes256Gcm;
        if encrypted != attributes.is_payload_encrypted() {
            return Err(Error::EncryptionUnavailable(format!(
                "topic '{}': writer key transformation differs from its announced attributes",
                self.topic
            )));
        }
        let encap = self
            .rtps_endpoint
            .map_or(0x0007, |ctx| ctx.encapsulation_kind);
        let serialized = crate::protocol::builder::encapsulate_serialized_payload(
            crate::dds::cdr_negotiation::encap_kind_for_version(encap, version),
            plaintext,
            false,
        );
        let sealed = crate::security::crypto::user_data::encode_serialized_payload(
            key_id,
            &key,
            &serialized,
        )
        .map_err(|e| {
            // A cipher failure must abort the write, not degrade it.
            Error::EncryptionUnavailable(format!(
                "topic '{}': sealing the sample failed: {}",
                self.topic, e
            ))
        })?;
        Ok((sealed, true))
    }

    /// Refuse a non-encrypting leg. Thin wrapper over [`refuse_cleartext_leg`],
    /// the shared predicate; runs BEFORE the sample is serialized so the
    /// encode cost is never paid for a write that cannot be delivered.
    #[cfg(feature = "security")]
    fn refuse_unkeyed_local_delivery(&self, leg: &str) -> Result<()> {
        let protection_required = self.security.as_ref().map_or(Ok(false), |suite| {
            self.endpoint_protection(suite)
                .map(|a| suite.cryptographic().is_some() || a.is_payload_protected())
        })?;
        refuse_cleartext_leg(protection_required, &self.topic, leg)
    }

    pub fn write(&self, msg: &T) -> Result<()> {
        let key_hash_opt = msg.instance_key();
        self.write_with_key_hash(msg, key_hash_opt)
    }

    // Opaque relays already know the original wire KeyHash. Carry it through
    // the normal history, local delivery and RTPS emission paths.
    pub(crate) fn write_with_key_hash(
        &self,
        msg: &T,
        key_hash_opt: Option<[u8; 16]>,
    ) -> Result<()> {
        if self.serialized_keys && key_hash_opt.is_none() {
            return Err(Error::InvalidState(
                "serialized keyed writer requires instance metadata".into(),
            ));
        }
        if self.merger.has_local_delivery_control() {
            self.write_in_mode::<ControlledWrite>(msg, key_hash_opt)
        } else {
            self.write_in_mode::<PlainWrite>(msg, key_hash_opt)
        }
    }

    fn write_in_mode<M: LocalWriteMode>(
        &self,
        msg: &T,
        key_hash_opt: Option<[u8; 16]>,
    ) -> Result<()> {
        // A MANUAL_BY_PARTICIPANT or MANUAL_BY_TOPIC writer's write()
        // asserts its liveliness (DDS v1.4 Sec.2.2.3.11); `None` for
        // AUTOMATIC or an infinite lease, so this costs one `Option`
        // check on that path.
        if let Some(ref assert) = self._liveliness_assert {
            assert.assert();
        }

        // The lazy check shares the scheduler's evaluation. With a
        // participant scheduler it only visits the written instance;
        // standalone writers check all instances (DDS v1.4 Sec.2.2.3.7).
        if let Some(deadlines) = self.deadlines.as_ref() {
            deadlines.check_instance(crate::dds::reader::InstanceHandle::new(
                key_hash_opt.unwrap_or_default(),
            ));
        }

        #[cfg(feature = "security")]
        let protected_hash = self.protected_key_hash(msg)?;
        #[cfg(feature = "security")]
        if let Some(wire) = protected_hash {
            self.protected_key_hashes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key_hash_opt.unwrap_or_default(), wire);
        }
        #[cfg(feature = "security")]
        let wire_key_hash_opt = protected_hash.or(key_hash_opt);
        #[cfg(not(feature = "security"))]
        let wire_key_hash_opt = key_hash_opt;

        // Track instance key for auto-unregister on Drop (DDS 2.2.2.4.1.6).
        // The serialized key bytes are captured here so the Drop path can ship
        // a spec-compliant K-payload to cross-vendor subscribers without
        // holding the original `&T` reference. The KeyHash is the one computed
        // above (once per write), and the key bytes are serialized only for
        // an instance this writer has not written yet.
        if let Some(key) = key_hash_opt {
            if let std::collections::hash_map::Entry::Vacant(slot) = self
                .written_instances
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(key)
            {
                let version = self.effective_cdr_version();
                slot.insert((version, msg.encode_key(version)));
            }
            // A fresh write revives the instance; clear any disposed marker so
            // Drop auto-unregisters it on teardown (DDS spec sec. 2.2.2.4.1.6).
            self.disposed_instances
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
        }

        let write_start_ns = current_time_ns();
        // ONE source timestamp for the whole change (RTPS v2.5
        // SS8.3.8.11), read HERE, before any leg below -- the
        // intra-process fast path, the "local readers + remote peers"
        // mixed path, and the wire-only path -- can read it, so a
        // `write_w_timestamp` override reaches every one of them, not
        // not only a leg that calls `stamp_source_ts()` on its own.
        // `write_start_ns` above stays the real write-time clock, read
        // for the latency metric (`add_latency_sample`) that must never
        // see an application-supplied override as if it were when this
        // call actually ran.
        let overridden = self.pending_source_ts.get().is_some();
        let source_ts: (u32, u32) = self.stamp_source_ts_at(write_start_ns);
        // With an application-supplied source timestamp, a co-located
        // reader's ring entry carries that override, and its slab payload
        // the moment this write happened (`IndexEntry::
        // mark_reception_ts_prefix`): a BY_RECEPTION_TIMESTAMP reader
        // merges its writers' rings by the latter, whatever timestamp an
        // application asks for. A plain write needs neither: its source
        // timestamp is its write time.
        let reception_ts = overridden.then_some(write_start_ns);
        // Taken now, journaled below (`HistoryCache::taking`).
        let in_flight = self.taking_change();
        // A GROUP Publisher's writer takes its SN and the Publisher's next
        // GSN as one step (RTPS v2.5 Sec.8.7.5); any other writer
        // pays one `Option` test. A coherent writer's set context is taken
        // here too, not only by the wire branches below: the intra-process
        // fast path, which reaches neither, must know whether the change is
        // a member of an open set (DDS v1.4 Sec.2.2.3.6) -- its stamp says
        // so, and carries its markers. A non-coherent writer pays one bool
        // test, as before.
        // `coherent_stamp`, the change's stamp into its Publisher's open set
        // (`coherent_context_held`), is declared before `guards` so it drops
        // after them: withdrawn, it can deliver the set on this thread, and
        // the readers' listeners that runs may write through this writer. A
        // write that stages its sample takes it out first
        // (`commit_intra_process_entry`). Kept out of `guards`, which every
        // write moves down the fast path.
        // Numbering defers callbacks only until the Publisher lock is gone.
        // Admission owns its own scope and must flush it before a room wait.
        let (seq, group_tag, group_coherent, mut coherent_stamp, orders) =
            match self.publisher.as_ref().filter(|core| core.group_scope) {
                Some(core) => {
                    let _numbers = M::notices(
                        self.qos.presentation.coherent_access
                            || self.qos.presentation.ordered_access,
                    );
                    let (seq, tag, coherent, stamp, orders) = self.take_group_change::<M>(core);
                    (seq, Some(tag), Some(coherent), stamp, orders)
                }
                None if self.qos.presentation.coherent_access => {
                    let _numbers = M::notices(true);
                    let seq = self.next_seq.fetch_add(1, Ordering::AcqRel);
                    let (coherent_sn, group_sn, stamp) = self.coherent_context(seq);
                    (
                        seq,
                        None,
                        Some((coherent_sn, group_sn)),
                        stamp,
                        M::Orders::default(),
                    )
                }
                None => (
                    self.next_seq.fetch_add(1, Ordering::AcqRel),
                    None,
                    None,
                    None,
                    M::Orders::default(),
                ),
            };
        #[cfg(any(test, feature = "test-support"))]
        if M::CONTROLLED && group_tag.is_some() && self.qos.presentation.ordered_access {
            super::run_ordered_write_hook();
        }
        // With no local target there is no Admission to carry the pairing
        // read guard. Keep it through commit so a newly published reader
        // starts after this change. With a target, admission itself holds
        // the guard only while it has room, releasing it before any wait.
        let local_pairing = if M::CONTROLLED {
            self.merger.pairing()
        } else {
            self.merger.pairing_plain()
        };
        let has_local_readers = self.merger.reader_count() > 0;
        let local_pairing = if has_local_readers {
            drop(local_pairing);
            None
        } else {
            local_pairing
        };
        let guards: ChangeGuards<'_, M> = ChangeGuards {
            _in_flight: in_flight,
            _pending_gsn: PendingGsn(group_tag.and_then(|_| self.pending_gsn_slot())),
            _local_pairing: local_pairing,
            _local_notices: M::Notices::default(),
        };

        // Fast path: intra-process only (no remote peers).
        // Skip RTPS framing, UDP send and heartbeats entirely; a durable
        // writer still journals the sample for late joiners (see
        // `commit_intra_process_entry`).
        //
        // DDS-Security: this leg consults the SAME refusal predicate as the
        // wire leg. The earlier justification -- "same address space, nothing
        // to protect it from that could not already read the writer's own
        // memory" -- holds for two endpoints of ONE participant, and that is
        // not what this leg serves: `DomainRegistry::global()` is process-wide
        // and `DomainState` groups endpoints by (topic, type_id) with no
        // notion of which participant owns them, so the reader on the other
        // end can be a different DDS-Security principal that has completed no
        // handshake with us. Delivering plaintext here while the wire leg
        // refuses would make the SAME write() succeed or fail depending on
        // whether a remote peer happens to exist yet.
        let has_remote_peers = self.has_remote_peers();
        if has_local_readers && !has_remote_peers {
            #[cfg(feature = "security")]
            if let Err(e) = self.refuse_unkeyed_local_delivery("intra-process") {
                // Nothing was published: give the sequence number back so it
                // cannot become a hole a future RELIABLE reader NACKs forever
                // -- same discipline as the wire leg's refusal below.
                self.abandon_unpublished_sequence(seq, group_tag);
                return Err(e);
            }
            return self.write_intra_process_fast::<M>(
                msg,
                key_hash_opt,
                seq,
                write_start_ns,
                unix_nanos_from_rtps_timestamp(source_ts),
                reception_ts,
                group_tag,
                orders,
                guards,
                &mut coherent_stamp,
            );
        }

        // No-transport fall-through: with no wire leg, no refusal below can
        // fire, yet the history cache insert further down would still park the
        // PLAINTEXT sample -- and `TopicMerger::add_reader` replays the whole
        // retained TRANSIENT_LOCAL backlog to any reader that binds later,
        // without ever passing through write() again. An encrypting writer
        // with zero readers today must not stockpile cleartext for readers it
        // has not met yet.
        #[cfg(feature = "security")]
        if self.transport.is_none() {
            if let Err(e) = self.refuse_unkeyed_local_delivery("history-cache") {
                self.abandon_unpublished_sequence(seq, group_tag);
                return Err(e);
            }
        }

        // Buffer must fit the ENTIRE serialized payload, not a single DATA
        // submessage. Samples larger than DEFAULT_MAX_UNFRAGMENTED_SIZE are
        // split into DATA_FRAG packets by build_data_frag_packets() later,
        // so the serialized blob can be arbitrarily large. The writer's
        // retained scratch starts at 64 KB and doubles on BufferTooSmall up
        // to a 16 MB cap to support LargeData-style payloads; it is zero at
        // rest, so no byte of an earlier sample can reach the wire.
        // Single encode per write() per DDS-XTypes v1.3 sec. 7.6.3.1.
        let version = self.effective_cdr_version();
        // A sample that cannot be encoded is not published: give its
        // sequence number back, or a RELIABLE reader would NACK the hole
        // forever.
        let encoded =
            match crate::dds::encode_scratch::encode_into(&self.wire_scratch, msg, version) {
                Ok(encoded) => encoded,
                Err(e) => {
                    self.abandon_unpublished_sequence(seq, group_tag);
                    return Err(e);
                }
            };
        let serialized_len = encoded.bytes().len();
        let tmp_buf = encoded.bytes();

        log::debug!(
            "[writer] write() seq={} reader_count={} has_local_readers={}",
            seq,
            self.merger.reader_count(),
            has_local_readers
        );

        // DDS-Security: on the MIXED path (co-located readers AND remote
        // peers) the wire leg is about to carry ciphertext while the slab
        // would carry this same plaintext -- the two legs disagreeing about
        // one sample. Suppress the intra leg instead: co-located readers of
        // OTHER participants still receive the sample as ciphertext over UDP
        // and decrypt it with the distributed key; readers of THIS participant
        // get nothing (the router drops own-prefix datagrams), which is
        // silence, not cleartext -- and both intra routes already refused
        // outright before this point.
        #[cfg(feature = "security")]
        let has_local_readers = has_local_readers && {
            let encrypting = self
                .security
                .as_ref()
                .and_then(|s| s.cryptographic())
                .is_some();
            if encrypting && has_local_readers {
                log::warn!(
                    "[writer] topic='{}': suppressing the intra-process leg (encryption is \
                         enabled; co-located readers receive ciphertext over UDP instead)",
                    self.topic
                );
            }
            !encrypting
        };

        // Reserve intra-process resources only if there are local readers.
        // For remote-only delivery, skip slab allocation entirely.
        // Out of slab memory, a BEST_EFFORT write skips the intra-process
        // leg and still goes on the wire. A RELIABLE one waits for that
        // memory as for room (below), within the same deadline, and times
        // out: going on without the local leg lost the sample for a
        // RELIABLE local reader, unreported.
        //
        // One deadline for the whole write: this wait, the room's and the
        // history's below share it (DDS v1.4 Sec.2.2.3.14, the write blocks
        // at most max_blocking_time). No clock is read unless something
        // waits.
        let deadline = rt::WriteDeadline::new(self.qos.reliability_max_blocking_time);
        // Keep stamped members even before the first local match. A reader
        // joining the open set must receive its earlier members at close.
        let retain_local_set = coherent_stamp.is_some() && {
            #[cfg(feature = "security")]
            {
                self.security
                    .as_ref()
                    .and_then(|s| s.cryptographic())
                    .is_none()
            }
            #[cfg(not(feature = "security"))]
            {
                true
            }
        };
        let intra_process = if has_local_readers {
            match Self::prepare_intra_process_entry(
                &tmp_buf[..serialized_len],
                serialized_len,
                seq,
                unix_nanos_from_rtps_timestamp(source_ts),
                reception_ts,
                version,
                self.waits_for_room().then_some(&deadline),
                &self.counts.drops,
            ) {
                Ok(entry) => Some(entry),
                Err(Error::WouldBlock) => {
                    log::debug!(
                        "[writer] slab pool full seq={}, skipping intra-process",
                        seq
                    );
                    None
                }
                Err(e) => {
                    self.abandon_unpublished_sequence(seq, group_tag);
                    return Err(e);
                }
            }
        } else {
            None
        };

        // Room in every co-located reader's history before the sample is
        // emitted on any leg: a RELIABLE local reader with none makes this
        // write wait (see `TopicMerger::admit`), and its TIMEOUT must leave
        // no trace on the wire or in the history either. Every early return
        // below drops the admission, which gives the room back.
        let local_key = || Some(key_hash_opt.unwrap_or_else(|| msg.compute_key()));
        // A member of an open coherent set takes no admission here: its
        // local delivery is held back by `coherent_stamp` (DDS v1.4
        // Sec.2.2.3.6) until the set closes, exactly as the intra-process-
        // only fast path defers it (`stage_coherent_member`). Reserving
        // room now, for a push that may run much later at the set's close,
        // would hold a reader's ring slot for as long as the set stays
        // open; `IntraCoherentSets::push` takes its own room (with its own
        // fresh deadline) at delivery time instead.
        let local_admission = match intra_process.as_ref() {
            Some((entry, handle)) if coherent_stamp.is_none() => match M::admit(
                &self.merger,
                entry,
                rt::get_slab_pool_ref(),
                &local_key,
                self.waits_for_room().then_some(&deadline),
                self.local_ordering::<M>(group_tag),
            ) {
                Ok(admission) => Some(admission),
                Err(rt::RoomTimeout) => {
                    self.abandon_before_emission(seq, Some(*handle), group_tag);
                    return Err(Error::WriteTimeout);
                }
            },
            _ => None,
        };

        // Coherent-set markers for this sample (PID_COHERENT_SET /
        // PID_GROUP_COHERENT_SET_HDDS), taken from the same
        // `coherent_context(seq)` call used to build the live wire DATA in
        // the small-payload branch below, and journaled with the change
        // whatever the durability: a repair or a replay of a set member
        // carries the set it was written in. Untagged, a member repaired to
        // a live reader ends the set it belongs to there (DDSI-RTPS 2.5
        // 8.7.6: a change with no coherent-set PID is not of the set), and
        // the set's later members start nothing. `(None, None)` for a
        // sample written outside a set: nothing changes for a non-coherent
        // writer. Each branch below (small-DATA, DATA_FRAG, no-transport)
        // computes and journals its own local `(coherent_sn, group_sn)` --
        // there is no single outer variable to thread between them, so
        // there is nothing for a LATER branch to accidentally read a
        // STALE value of.
        // Wire INFO_TS this write() emits, journaled alongside the change
        // so a later NACK repair / TRANSIENT_LOCAL replay can replay the
        // SAME timestamp instead of stamping a fresh one (RTPS v2.5
        // SS8.3.8.11: one source timestamp PER SAMPLE).
        //
        // Stamped at the very top of `write()` (`source_ts`), before ANY
        // leg -- the intra-process fast path (an early return, never
        // reaches here), the mixed local+remote path's
        // `prepare_intra_process_entry` call above, and this wire path
        // below -- so `write_w_timestamp`'s override reaches every one
        // of them from one `stamp_source_ts()` call, including the
        // co-located readers of the mixed path (which must not be handed
        // the raw clock, `write_start_ns`). A second `stamp_source_ts()`
        // call would find the Cell already taken and silently fall back
        // to `now()`, overwriting the override instead of honoring it,
        // which is why every leg below reads this ONE value and none of
        // them re-stamps.
        //
        // `live_source_ts_known` is a SEPARATE bool, not an in-band
        // sentinel on the timestamp itself, because `(0, 0)` (the RTPS
        // epoch) is a legal wire timestamp for a clock that has not yet
        // acquired NTP (see `ChangeMetadata::source_ts_known`); it is
        // unconditionally true here because every write() stamps one.
        let live_source_ts: (u32, u32) = source_ts;
        let live_source_ts_known = true;
        // Fragment size the live DATA_FRAG branch used for this sample, or
        // 0 if the small-DATA branch ran instead (sample not fragmented).
        // Journaled so a repair that must re-fragment a cached change
        // reuses the exact same size (a different size renumbers
        // fragments and corrupts the receiver's reassembly).
        let mut live_frag_size: u16 = 0;

        // Sealed wire bytes, kept alive past the transport block: the history
        // cache below must store what the WIRE carried, so NACK repair and
        // TRANSIENT_LOCAL replay resend ciphertext, not plaintext.
        #[cfg(feature = "security")]
        let mut sealed_wire_payload: Option<Vec<u8>> = None;

        // What the history journals for this change, from what the live
        // emission put on the wire: the INFO_TS, the CDR version the payload
        // was encoded with, the fragment size if it was fragmented, the
        // coherent markers (see the comment on `coherent_markers_for_cache`
        // above). Protection state is journaled with the cached octets;
        // the complete CryptoHeader retains the actual key and session ids.
        let change_metadata = |coherent: (Option<u64>, Option<u64>),
                               source_ts: (u32, u32),
                               source_ts_known: bool,
                               frag_size: u16,
                               sealed: bool| {
            let (coherent_sn, group_sn) = coherent;
            (
                ChangeMetadata {
                    kind: ChangeKind::UserData,
                    coherent_sn,
                    group_sn,
                    key_hash: wire_key_hash_opt,
                    source_ts,
                    source_ts_known,
                    cdr_version: version,
                    frag_size,
                    key_epoch: u16::from(sealed),
                    status_info: None,
                },
                group_tag,
            )
        };

        // Send on UDP
        if let Some(ref transport) = self.transport {
            // DDS Security: seal under this writer's data-plane key, or refuse
            // the sample. There is deliberately no plaintext fallback here
            // (see `seal_payload_for_wire`).
            #[cfg(feature = "security")]
            let plaintext_passthrough: Vec<u8>;
            // Record the protection operation's decision with the cached
            // bytes. Application bytes never determine framing.
            #[cfg(feature = "security")]
            let mut payload_sealed = false;
            #[cfg(feature = "security")]
            let payload_for_network: &[u8] =
                match self.seal_payload_for_wire(&tmp_buf[..serialized_len], version) {
                    Ok((buf, true)) => {
                        payload_sealed = true;
                        sealed_wire_payload.insert(buf).as_slice()
                    }
                    Ok((buf, false)) => {
                        plaintext_passthrough = buf;
                        &plaintext_passthrough
                    }
                    Err(e) => {
                        // Nothing will be published on either path, so give the
                        // reserved intra-process slab entry back before bailing --
                        // same discipline as the fragmentation failure below. A
                        // refused writer refuses EVERY write, so leaking one handle
                        // per attempt would drain the shared slab pool and degrade
                        // unrelated writers to WouldBlock.
                        if let Some((_, handle)) = intra_process {
                            rt::get_slab_pool_ref().release(handle);
                        }
                        // Give the sequence number back too. It was taken at the top
                        // of write() and nothing has advertised it yet (no history
                        // insert, no HEARTBEAT, no intra-process push), so leaving a
                        // hole would make every RELIABLE reader NACK forever for a
                        // sample that will never exist.
                        self.abandon_unpublished_sequence(seq, group_tag);
                        return Err(e);
                    }
                };
            #[cfg(not(feature = "security"))]
            let payload_for_network: &[u8] = &tmp_buf[..serialized_len];
            #[cfg(not(feature = "security"))]
            let payload_sealed = false;

            // Check if payload needs fragmentation (>8KB)
            let use_fragmentation =
                builder::should_fragment(payload_for_network.len()) && self.rtps_endpoint.is_some();

            log::debug!(
                "[writer] fragmentation decision: payload_len={} should_fragment={} rtps_endpoint={} use_fragmentation={}",
                payload_for_network.len(),
                builder::should_fragment(payload_for_network.len()),
                self.rtps_endpoint.is_some(),
                use_fragmentation
            );

            let sent_result = if use_fragmentation {
                // Large payload: send as DATA_FRAG packets
                // `use_fragmentation` is `should_fragment(len) &&
                // self.rtps_endpoint.is_some()`, built ~45 lines above, and
                // nothing assigns `rtps_endpoint`
                // anywhere in this file, so it cannot become None in between.
                // @audit-ok: guarded by `if use_fragmentation`, see just above
                #[allow(clippy::unwrap_used)]
                let ctx = self.rtps_endpoint.unwrap();
                // Resolve the large-payload route BEFORE building so this
                // sample's fragment size matches its destination. Repairs
                // reuse the size journaled below, including the QoS budget.
                self.resolve_frag_route(transport);
                // Build both inline-QoS forms before selecting fragmentSize:
                // every fragment of a sample must use the same size, including
                // repairs and readers with a different GROUP dialect.
                let (coherent_sn, group_sn) = group_coherent.unwrap_or_else(|| {
                    let (coherent_sn, group_sn, _stamp) = self.coherent_context(seq);
                    (coherent_sn, group_sn)
                });
                let legacy_qos = builder::data_frag_inline_qos(
                    &ctx,
                    &self.topic,
                    coherent_sn,
                    group_sn,
                    None,
                    wire_key_hash_opt.as_ref(),
                );
                let spec_qos = group_tag.as_ref().map(|tag| {
                    builder::data_frag_inline_qos(
                        &ctx,
                        &self.topic,
                        coherent_sn,
                        group_sn,
                        Some(tag),
                        wire_key_hash_opt.as_ref(),
                    )
                });
                let inline_qos_len = legacy_qos.len().max(spec_qos.as_ref().map_or(0, Vec::len));
                // GROUP routing can prepend an INFO_DST to isolate native SNs.
                let routing_len = if self.wire_windows.is_group() { 16 } else { 0 };
                live_frag_size = self
                    .frag_route
                    .sample_fragment_size(inline_qos_len, routing_len);
                // One source timestamp, stamped above, for every fragment.
                // A zero budget follows the ordinary build-failure path below.
                let mut frag_packets = if live_frag_size == 0 {
                    Vec::new()
                } else {
                    builder::build_data_frag_packets_ts(
                        &ctx,
                        seq,
                        payload_for_network,
                        usize::from(live_frag_size),
                        version,
                        live_source_ts,
                        payload_sealed,
                    )
                };
                let spec_frag_packets = spec_qos.map(|qos| {
                    let mut spec = frag_packets.clone();
                    if !builder::put_inline_qos_in_first_fragment(&mut spec, &qos) {
                        spec.clear();
                    }
                    spec
                });
                // The plain form (no set PIDs), built lazily from the bare
                // fragments by the first plain reader that selects it.
                let plain_frag_build = || {
                    let plain_qos = builder::data_frag_inline_qos(
                        &ctx,
                        &self.topic,
                        None,
                        None,
                        None,
                        wire_key_hash_opt.as_ref(),
                    );
                    let mut plain = builder::build_data_frag_packets_ts(
                        &ctx,
                        seq,
                        payload_for_network,
                        usize::from(live_frag_size),
                        version,
                        live_source_ts,
                        payload_sealed,
                    );
                    if !plain_qos.is_empty()
                        && !builder::put_inline_qos_in_first_fragment(&mut plain, &plain_qos)
                    {
                        plain.clear();
                    }
                    plain
                };
                let plain_frag_form = group_tag
                    .is_some()
                    .then(|| LazyForm::new(&plain_frag_build));
                if !legacy_qos.is_empty()
                    && !builder::put_inline_qos_in_first_fragment(&mut frag_packets, &legacy_qos)
                {
                    frag_packets.clear();
                }

                if frag_packets.is_empty()
                    || spec_frag_packets
                        .as_ref()
                        .is_some_and(|spec| spec.is_empty())
                {
                    // Fragmentation returned empty (shouldn't happen if should_fragment is true)
                    log::debug!(
                        "[writer] DATA_FRAG build returned empty for seq {} ({} bytes)",
                        seq,
                        payload_for_network.len()
                    );
                    if let Some((_, handle)) = intra_process {
                        rt::get_slab_pool_ref().release(handle);
                    }
                    self.abandon_unpublished_sequence(seq, group_tag);
                    return Err(Error::BufferTooSmall);
                }

                let num_fragments = frag_packets.len();
                log::debug!(
                    "[writer] Sending {} DATA_FRAG packets for seq={} (total {} bytes)",
                    num_fragments,
                    seq,
                    payload_for_network.len()
                );

                // Journal what the wire will carry (sealed bytes under
                // encryption) before any fragment leaves.
                if let Err(e) = self.journal_before_emission::<M>(
                    seq,
                    payload_for_network,
                    change_metadata(
                        (coherent_sn, group_sn),
                        live_source_ts,
                        true,
                        live_frag_size,
                        payload_sealed,
                    ),
                    &deadline,
                ) {
                    self.abandon_before_emission(
                        seq,
                        intra_process.as_ref().map(|(_, h)| *h),
                        group_tag,
                    );
                    return Err(e);
                }

                // Send all fragments
                let result = self.send_packets_to_endpoints(
                    transport,
                    &frag_packets,
                    spec_frag_packets.as_deref(),
                    plain_frag_form.as_ref(),
                );

                // Send multiple HEARTBEAT_FRAGs to improve reliability
                // RTPS v2.5 Sec.8.3.8.7 recommends periodic heartbeats for fragment recovery.
                // We send 3 HBFs with 10ms spacing to handle transient packet loss.
                //
                // Must NOT go through send_packet_to_endpoints_classed(): that helper
                // patches byte 28 of the packet as the reader entity id, but
                // in a HEARTBEAT_FRAG byte 28 falls inside the INFO_DST dest
                // GUID prefix -- patching it corrupts the destination, the
                // receiver drops the submessage, never issues a
                // NACK_FRAG, and fragmented samples past seq 16 are left
                // half-reassembled. Build a per-reader HBF targeting the
                // reader's entity id + participant prefix instead.
                // Large-payload multicast route (frag_route active): skip the
                // HEARTBEAT_FRAG stream entirely. This route is active only
                // when every matched remote reader is of the vendor 0x0103
                // dialect (see `resolve_frag_route`), and for that dialect
                // HDDS emits no HBF: the plain HEARTBEAT stream announces
                // the available SNs and drives NACK_FRAG recovery.
                if result.is_ok() && self.frag_route.multicast_dest().is_none() {
                    // HEARTBEAT_FRAG.lastFragmentNum is a FragmentNumber_t (u32);
                    // a sample with more fragments than that field can name
                    // cannot be advertised by one, so no HBF is sent for it.
                    match u32::try_from(num_fragments) {
                        Err(_) => log::debug!(
                            "[writer] seq={} has {} fragments, more than FragmentNumber_t names; no HEARTBEAT_FRAG",
                            seq,
                            num_fragments
                        ),
                        Ok(num_fragments_u32) => {
                            for i in 0..3 {
                                let hbf_count = HEARTBEAT_FRAG_COUNT.fetch_add(1, Ordering::Relaxed);

                                let mut hbf_delivered = false;
                                if let (Some(ref fsm), Some(ref reg)) =
                                    (&self.discovery_fsm, &self.endpoint_registry)
                                {
                                    let readers = fsm.find_readers_for_topic(&self.topic);
                                    let local_prefix = self.rtps_endpoint.map(|c| c.guid_prefix);
                                    for reader in &readers {
                                        let classic_window = self.wire_windows.is_group()
                                            && fsm.requires_group_window(&reader.endpoint_guid.prefix);
                                        if classic_window && !self.wire_windows.contains(reader.endpoint_guid) {
                                            continue;
                                        }

                                        if let Some(local_pfx) = local_prefix {
                                            if reader.participant_guid.as_bytes()[..12] == local_pfx {
                                                continue;
                                            }
                                        }
                                        let mut dest_prefix = [0u8; 12];
                                        dest_prefix
                                            .copy_from_slice(&reader.participant_guid.as_bytes()[..12]);
                                        let mut pguid_bytes = [0u8; 16];
                                        pguid_bytes[..12].copy_from_slice(&dest_prefix);
                                        pguid_bytes[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
                                        let participant_key = GUID::from_bytes(pguid_bytes);
                                        let dest = reg
                                            .get_reader_locator(&reader.endpoint_guid)
                                            .or_else(|| reg.get(&participant_key));
                                        if let Some(endpoint) = dest {
                                            let hbf_packet = builder::build_heartbeat_frag_packet(
                                                ctx.guid_prefix,
                                                dest_prefix,
                                                reader.endpoint_guid.entity_id,
                                                ctx.writer_entity_id,
                                                seq,
                                                num_fragments_u32,
                                                hbf_count,
                                            );
                                            if self.wire_windows
                                                .send_classed(
                                                    transport,
                                                    &hbf_packet,
                                                    &endpoint,
                                                    reader.endpoint_guid,
                                                    classic_window,
                                                )
                                                .is_ok()
                                            {
                                                hbf_delivered = true;
                                            }
                                        }
                                    }
                                }
                                // Not to a group anyone may listen on, for a
                                // protected topic (`multicast_fallback_closed`).
                                if !hbf_delivered
                                    && !self.wire_windows.is_group()
                                    && !multicast_fallback_closed(
                                        self.discovery_fsm.as_deref(),
                                        &self.topic,
                                    )
                                {
                                    // Fallback: broadcast HBF (ENTITYID_UNKNOWN reader).
                                    let hbf_packet = builder::build_heartbeat_frag_packet(
                                        ctx.guid_prefix,
                                        [0; 12],
                                        [0, 0, 0, 0],
                                        ctx.writer_entity_id,
                                        seq,
                                        num_fragments_u32,
                                        hbf_count,
                                    );
                                    let _ = transport.send_user_data_multicast(&hbf_packet);
                                }
                                log::trace!(
                                    "[writer] Sent HEARTBEAT_FRAG {}/3 for seq={} lastFrag={} count={}",
                                    i + 1,
                                    seq,
                                    num_fragments,
                                    hbf_count
                                );
                            }
                        }
                    }
                }

                result
            } else {
                // Small payload: send as single DATA packet (existing path)
                let (coherent_sn, group_sn) = group_coherent.unwrap_or_else(|| {
                    let (coherent_sn, group_sn, _stamp) = self.coherent_context(seq);
                    (coherent_sn, group_sn)
                });
                let mut spec_packet: Option<Vec<u8>> = None;
                // The plain form (plain), built lazily from the same
                // inputs as the legacy form by the first plain reader that
                // selects it; it stays unbuilt for an audience without one.
                let plain_build = || match self.rtps_endpoint {
                    Some(ctx) => builder::build_data_packet_grouped_ts(
                        &ctx,
                        &self.topic,
                        seq,
                        payload_for_network,
                        version,
                        live_source_ts,
                        None,
                        None,
                        None,
                        wire_key_hash_opt.as_ref(),
                        payload_sealed,
                    ),
                    None => builder::build_data_packet(&self.topic, seq, payload_for_network),
                };
                let plain_form = group_tag.is_some().then(|| LazyForm::new(&plain_build));
                let rtps_packet = if let Some(ctx) = self.rtps_endpoint {
                    // `source_ts`: already stamped once, up front (see
                    // `live_source_ts`'s declaration) -- not here, where a
                    // second `stamp_source_ts()` call would find the Cell
                    // already taken and silently fall back to `now()`,
                    // overwriting write_w_timestamp's override.
                    let source_ts = live_source_ts;
                    // The spec GROUP form, for readers of the spec class;
                    // every other reader keeps today's form below.
                    spec_packet = group_tag.as_ref().map(|tag| {
                        builder::build_data_packet_grouped_ts(
                            &ctx,
                            &self.topic,
                            seq,
                            payload_for_network,
                            version,
                            source_ts,
                            coherent_sn,
                            group_sn,
                            Some(tag),
                            wire_key_hash_opt.as_ref(),
                            payload_sealed,
                        )
                    });
                    builder::build_data_packet_with_context_full_keyed_ts(
                        &ctx,
                        &self.topic,
                        seq,
                        payload_for_network,
                        version,
                        source_ts,
                        coherent_sn,
                        group_sn,
                        wire_key_hash_opt.as_ref(),
                        payload_sealed,
                    )
                } else {
                    builder::build_data_packet(&self.topic, seq, payload_for_network)
                };

                if rtps_packet.is_empty() {
                    if let Some((_, handle)) = intra_process {
                        rt::get_slab_pool_ref().release(handle);
                    }
                    log::debug!(
                        "[writer] Skipping send: failed to build DATA packet for seq {}",
                        seq
                    );
                    return Err(Error::BufferTooSmall);
                }

                if let Err(e) = self.journal_before_emission::<M>(
                    seq,
                    payload_for_network,
                    change_metadata(
                        (coherent_sn, group_sn),
                        live_source_ts,
                        live_source_ts_known,
                        0,
                        payload_sealed,
                    ),
                    &deadline,
                ) {
                    self.abandon_before_emission(
                        seq,
                        intra_process.as_ref().map(|(_, h)| *h),
                        group_tag,
                    );
                    return Err(e);
                }
                self.send_packet_to_endpoints_classed(
                    transport,
                    &rtps_packet,
                    spec_packet.as_deref().filter(|p| !p.is_empty()),
                    plain_form.as_ref(),
                )
            };

            if let Err(e) = sent_result {
                log::debug!("UDP send failed for topic '{}': {}", self.topic, e);
                if let Some(m) = telemetry::get_metrics_opt() {
                    m.increment_transport_errors(1);
                }
            } else {
                log::debug!(
                    "[writer] UDP send succeeded topic='{}' seq={}",
                    self.topic,
                    seq
                );
            }
        }

        // Commit to merger if we have local readers. push() consumes the
        // claim reference on the handle in every outcome (transfer on
        // delivery, free on zero deliveries) -- no caller-side release.
        //
        // Without a transport nothing was journaled above: do it before the
        // intra-process push, which is this change's first emission.
        if self.transport.is_none() {
            // The wire branches above compute their own `(coherent_sn,
            // group_sn)` from `group_coherent` and journal with it
            // locally; a transport-less writer (IntraProcess, or any
            // writer with a dropped/never-bound transport) never runs
            // them, so without this, this journal would record the
            // change as belonging to no set at all -- exactly the defect
            // a late joiner's `HistoryCache::snapshot_for_local_replay`
            // filter relies on NOT seeing. `group_coherent` is already
            // computed (eagerly, at the top of `write()`) for every
            // coherent writer, so this is a plain unwrap, not a second
            // `coherent_context` side-effecting call.
            let coherent_markers_for_cache = group_coherent.unwrap_or_else(|| {
                let (coherent_sn, group_sn, _stamp) = self.coherent_context(seq);
                (coherent_sn, group_sn)
            });
            if let Err(e) = self.journal_before_emission::<M>(
                seq,
                &tmp_buf[..serialized_len],
                change_metadata(
                    coherent_markers_for_cache,
                    live_source_ts,
                    live_source_ts_known,
                    live_frag_size,
                    false,
                ),
                &deadline,
            ) {
                self.abandon_before_emission(
                    seq,
                    intra_process.as_ref().map(|(_, h)| *h),
                    group_tag,
                );
                return Err(e);
            }
        }
        // The serialized sample has been copied everywhere it goes (slab
        // entry, history cache, wire): give the scratch back BEFORE the
        // merger push, which can run co-located readers' listeners, so no
        // lock is held across a user callback.
        let retained_local = (retain_local_set && intra_process.is_none()).then(|| {
            super::intra_coherent::StagedIntraSample::encoded(
                seq,
                &tmp_buf[..serialized_len],
                unix_nanos_from_rtps_timestamp(source_ts),
                reception_ts,
                version,
                key_hash_opt.unwrap_or_else(|| msg.compute_key()),
            )
        });
        drop(encoded);
        self.record_write_commit::<M>(seq, key_hash_opt);
        // Emitted on the wire and journaled: the change is made (a listener
        // the push runs may write again through this writer).
        drop(guards);
        if let Some(stamp) = coherent_stamp.take() {
            // A member of this writer's open coherent set, matched with
            // both co-located AND remote readers: its local delivery must
            // reach co-located readers together with the rest of the set,
            // never ahead of it (DDS v1.4 Sec.2.2.3.6), exactly like the
            // intra-process-only fast path. Staging it here, rather than
            // delivering through the merger at once, withholds it until
            // `IntraCoherentSets` finds the set closed and complete.
            if let Some((entry, _handle)) = intra_process {
                stamp.stage_sample(
                    super::intra_coherent::StagedIntraSample::ready(
                        entry,
                        key_hash_opt.unwrap_or_else(|| msg.compute_key()),
                        None,
                    )
                    .with_pending(M::pending(orders)),
                );
            } else if let Some(sample) = retained_local {
                stamp.stage_sample(sample.with_pending(M::pending(orders)));
            } else {
                // No co-located reader took this change (no local target,
                // or BEST_EFFORT skipped it for lack of memory): nothing to
                // hold back, so withdraw -- the wire leg already carries
                // this member regardless.
                drop(stamp);
            }
        } else if let (Some((entry, _handle)), Some(admission)) = (intra_process, local_admission) {
            // The key hash this write computed, for the ownership gates of
            // EXCLUSIVE readers in this process (asked only if one is bound).
            let merger_success = M::deliver(
                &self.merger,
                admission,
                entry,
                rt::get_slab_pool_ref(),
                &local_key,
                self.local_ordering::<M>(group_tag),
                orders,
            );
            log::debug!(
                "[MERGER] push topic='{}' seq={} success={} reader_count={}",
                self.topic,
                seq,
                merger_success,
                self.merger.reader_count()
            );
        } else {
            log::debug!(
                "[writer] No local readers for topic='{}'; remote-only delivery",
                self.topic
            );
        }

        self.maybe_send_heartbeat(seq);

        if let Some(m) = telemetry::get_metrics_opt() {
            m.increment_sent(1);
            m.increment_bytes_sent(serialized_len as u64);
            m.add_latency_sample(write_start_ns, current_time_ns());
        }
        self.counts.sent(serialized_len);

        // Invoke listener callback if present
        if let Some(listener) = self.listener.get_any() {
            listener.on_sample_written(msg, seq);
        }

        Ok(())
    }

    /// Account for a committed write before any application callback can
    /// dispose or unregister its instance (DDS v1.4 Sec.2.2.3.7 and
    /// Sec.2.2.3.23.3). Those later operations must remain the last update
    /// to the deadline state. Infinite deadlines cost one Option check.
    fn record_write_commit<M: LocalWriteMode>(&self, seq: u64, key_hash: Option<[u8; 16]>) {
        if self.wire_windows.is_group()
            || matches!(
                self.qos.reliability,
                super::super::qos::Reliability::Reliable
            )
        {
            match self.history_cache.as_ref() {
                Some(cache) => cache.record_local_commit(seq),
                None => self.wire_windows.record_unretained(seq),
            }
        }
        if M::CONTROLLED && self.publisher.as_ref().is_some_and(|core| core.group_scope) {
            self.merger.commit_order(seq);
        }
        if let Some(deadlines) = self.deadlines.as_ref() {
            deadlines.on_write(crate::dds::reader::InstanceHandle::new(
                key_hash.unwrap_or_default(),
            ));
        }
    }

    /// Whether a write waits for room in a co-located reader's history: a
    /// RELIABLE writer does, up to `max_blocking_time` (DDS v1.4
    /// Sec.2.2.3.14); a BEST_EFFORT one drops instead.
    #[inline]
    fn waits_for_room(&self) -> bool {
        matches!(
            self.qos.reliability,
            super::super::qos::Reliability::Reliable
        )
    }

    /// Returns true if there are remote peers discovered for this writer.
    #[inline]
    fn has_remote_peers(&self) -> bool {
        if let Some(ref registry) = self.endpoint_registry {
            if registry.endpoint_count() == 0 {
                return false;
            }
            let endpoints = registry.entries();
            if endpoints.is_empty() {
                return false;
            }
            // Check if any endpoint is NOT ourself
            let local_guid = self
                .rtps_endpoint
                .map(|ctx| GUID::new(ctx.guid_prefix, RTPS_ENTITYID_PARTICIPANT));
            endpoints.iter().any(|(guid, _)| Some(*guid) != local_guid)
        } else {
            false
        }
    }

    /// Copy `bytes` into the slab pool for the intra-process leg (a
    /// writer's claim, `rt::Claim::Writer`). Out of memory, a write with a
    /// `deadline` (RELIABLE) waits for it until the deadline, as the
    /// history path does (`HistoryCache::reserve_until`): DDS v1.4
    /// Sec.2.2.3.18 (KEEP_ALL, RELIABLE) blocks the writer until it can
    /// deliver, Sec.2.2.2.4.2.11 bounds the wait by `max_blocking_time`,
    /// then TIMEOUT. The memory comes back as co-located readers take, on
    /// threads that wake nobody here: the wait is sliced. `WouldBlock`
    /// without a deadline (BEST_EFFORT), at once.
    fn reserve_local_leg(
        bytes: &[u8],
        deadline: Option<&rt::WriteDeadline>,
    ) -> Result<rt::SlabHandle> {
        const SLICE: std::time::Duration = std::time::Duration::from_millis(1);
        let slab_pool = rt::get_slab_pool_ref();
        loop {
            if let Some((handle, _metric)) = slab_pool.reserve_and_write(bytes, rt::Claim::Writer) {
                return Ok(handle);
            }
            let Some(deadline) = deadline else {
                if let Some(m) = telemetry::get_metrics_opt() {
                    m.increment_would_block(1);
                }
                return Err(Error::WouldBlock);
            };
            let remaining = deadline.remaining();
            if remaining.is_zero() {
                return Err(Error::WriteTimeout);
            }
            std::thread::sleep(remaining.min(SLICE));
        }
    }

    /// Intra-process write path: bypasses RTPS framing, UDP transport and
    /// heartbeats. A durable (TRANSIENT_LOCAL / TRANSIENT / PERSISTENT)
    /// writer still journals each sample in its history cache, because that
    /// cache is what the merger replays to a late joiner; VOLATILE writers
    /// skip it here as before.
    ///
    /// Hybrid buffer strategy (the follow-up promised by the Tier 2/3
    /// slab-pool activation change):
    ///
    /// 1. **Direct**: reserve a 64 KB-class slot from the primary pool
    ///    and encode straight into it -- single copy, zero interim
    ///    allocation. This is the original fast-path shape; it covers
    ///    every payload that fits the reserved slot while the primary
    ///    64/128 KB classes have capacity.
    /// 2. **Staged**: when the payload outgrows the reserved slot
    ///    (`BufferTooSmall`) or the 64/128 KB classes are exhausted,
    ///    encode into the writer-local reusable scratch (doubling on
    ///    `BufferTooSmall` up to 16 MB, zero-filled only on growth) and
    ///    hand the bytes to `reserve_and_write`, which routes through
    ///    the primary (best-fit), large, and heap fallback tiers in
    ///    turn. Large-payload tier semantics are byte-identical to the
    ///    staged-only shape this replaces.
    #[allow(clippy::too_many_arguments)]
    fn write_intra_process_fast<M: LocalWriteMode>(
        &self,
        msg: &T,
        key_hash: Option<[u8; 16]>,
        seq: u64,
        write_start_ns: u64,
        source_ts_ns: u64,
        reception_ts: Option<u64>,
        group: Option<GroupTag>,
        orders: M::Orders,
        guards: ChangeGuards<'_, M>,
        coherent_stamp: &mut Option<CoherentStamp>,
    ) -> Result<()> {
        let slab_pool = rt::get_slab_pool_ref();
        // One deadline for the whole write: the wait for memory below and
        // the wait for room in a reader's history share it. No clock is
        // read unless something waits.
        let deadline = rt::WriteDeadline::new(self.qos.reliability_max_blocking_time);

        // Single encode per write() per DDS-XTypes v1.3 sec. 7.6.3.1.
        let version = self.effective_cdr_version();

        // Stage 1: direct encode into a primary-pool slot. `reserve`
        // consults the primary tier only; on miss the staged path below
        // still reaches the Large/Heap tiers via `reserve_and_write`.
        const FAST_SLOT_SIZE: usize = 65_536;
        let mut staging_floor = FAST_SLOT_SIZE;
        // A write with a reception-time prefix (`reception_ts`) takes the
        // staged path below, which lays the prefix down: the direct encode
        // stays the plain write's.
        if let Some((handle, slab_buf)) = reception_ts
            .is_none()
            .then(|| slab_pool.reserve(FAST_SLOT_SIZE))
            .flatten()
        {
            // `reserve` may hand back the next class up (128 KB) under
            // 64 KB-class pressure; capture the real slot size so the
            // staged path starts past whatever just failed to fit.
            let slot_len = slab_buf.len();
            match msg.encode(slab_buf, version) {
                Ok(serialized_len) => {
                    return self.commit_intra_process_entry::<M>(
                        msg,
                        key_hash,
                        slab_pool,
                        handle,
                        serialized_len,
                        false,
                        seq,
                        write_start_ns,
                        source_ts_ns,
                        version,
                        group,
                        orders,
                        guards,
                        coherent_stamp,
                        &deadline,
                    );
                }
                Err(Error::BufferTooSmall) => {
                    slab_pool.release(handle);
                    staging_floor = slot_len.saturating_mul(2);
                }
                Err(e) => {
                    slab_pool.release(handle);
                    self.abandon_unpublished_sequence(seq, group);
                    return Err(e);
                }
            }
        }

        // Stage 2: staged encode into the reusable writer-local scratch,
        // then tiered reservation (primary best-fit -> large -> heap).
        const MAX_SERIALIZED_SIZE: usize = 16 * 1024 * 1024;
        let mut scratch = self.intra_scratch.lock().unwrap_or_else(|e| e.into_inner());
        let serialized_len = {
            let mut size = staging_floor.min(MAX_SERIALIZED_SIZE);
            loop {
                if scratch.len() < size {
                    // Grow-once: the zero-fill is paid only when the
                    // scratch actually grows, never per write (the
                    // buffer is retained on the writer).
                    scratch.resize(size, 0);
                }
                match msg.encode(&mut scratch[..size], version) {
                    Ok(len) => break len,
                    Err(Error::BufferTooSmall) if size < MAX_SERIALIZED_SIZE => {
                        size = (size * 2).min(MAX_SERIALIZED_SIZE);
                    }
                    Err(e) => {
                        drop(scratch);
                        self.abandon_unpublished_sequence(seq, group);
                        return Err(e);
                    }
                }
            }
        };

        let prefixed =
            reception_ts.map(|at| Self::with_reception_ts(at, &scratch[..serialized_len]));
        let handle = match Self::reserve_local_leg(
            prefixed.as_deref().unwrap_or(&scratch[..serialized_len]),
            self.waits_for_room().then_some(&deadline),
        ) {
            Ok(handle) => handle,
            Err(e) => {
                drop(scratch);
                self.abandon_unpublished_sequence(seq, group);
                return Err(e);
            }
        };
        drop(scratch);

        self.commit_intra_process_entry::<M>(
            msg,
            key_hash,
            slab_pool,
            handle,
            serialized_len,
            reception_ts.is_some(),
            seq,
            write_start_ns,
            source_ts_ns,
            version,
            group,
            orders,
            guards,
            coherent_stamp,
            &deadline,
        )
    }

    /// The history cache when this writer's durability promises retained
    /// samples to late joiners, i.e. the same predicate the builder uses
    /// to give the merger a replay source; `None` for VOLATILE writers,
    /// whose cache (if any) serves wire repair only.
    #[inline]
    fn durable_history_cache(&self) -> Option<&Arc<HistoryCache>> {
        let durable = matches!(
            self.qos.durability,
            super::super::qos::Durability::TransientLocal
                | super::super::qos::Durability::Transient
                | super::super::qos::Durability::Persistent
        );
        if durable {
            self.history_cache.as_ref()
        } else {
            None
        }
    }

    /// The Publisher identity is stable across every local writer's merger.
    #[inline]
    fn local_ordering<M: LocalWriteMode>(&self, group: Option<GroupTag>) -> Option<(u64, u64)> {
        if M::CONTROLLED && self.qos.presentation.ordered_access {
            let group = group?;
            let publisher = self.publisher.as_ref()?.local_group()?;
            Some((publisher.identity(), group.gsn))
        } else {
            None
        }
    }

    /// Shared tail of both `write_intra_process_fast` stages: journal the
    /// sample for a durable writer, build the COMMITTED `IndexEntry` for a
    /// slab handle that already carries the encoded payload, push it to
    /// the merger, and run the metrics / listener / deadline bookkeeping.
    /// Releases the handle on every failure path.
    #[allow(clippy::too_many_arguments)]
    fn commit_intra_process_entry<M: LocalWriteMode>(
        &self,
        msg: &T,
        key_hash: Option<[u8; 16]>,
        slab_pool: &rt::SlabPool,
        handle: rt::SlabHandle,
        serialized_len: usize,
        reception_prefixed: bool,
        seq: u64,
        write_start_ns: u64,
        source_ts_ns: u64,
        version: crate::dds::CdrVersion,
        group: Option<GroupTag>,
        orders: M::Orders,
        guards: ChangeGuards<'_, M>,
        coherent_stamp: &mut Option<CoherentStamp>,
        deadline: &rt::WriteDeadline,
    ) -> Result<()> {
        let seq_u32 = match u32::try_from(seq) {
            Ok(v) => v,
            Err(_) => {
                slab_pool.release(handle);
                return Err(Error::Unsupported);
            }
        };
        let prefix_len = if reception_prefixed {
            RECEPTION_TS_LEN
        } else {
            0
        };
        let len_u32 = match u32::try_from(prefix_len + serialized_len) {
            Ok(v) => v,
            Err(_) => {
                slab_pool.release(handle);
                return Err(Error::BufferTooSmall);
            }
        };

        let mut entry = rt::IndexEntry {
            seq: seq_u32,
            handle,
            len: len_u32,
            flags: 0x01, // COMMITTED
            // `source_ts_ns`, not `write_start_ns`: the former is
            // `stamp_source_ts()`'s value (the application's
            // `write_w_timestamp` override when one was staged, the
            // write-time clock otherwise), the one a co-located reader's
            // `SampleInfo::source_timestamp_ns` must report -- the wire
            // leg and the journal already read the same value
            // (`live_source_ts`, computed from this same
            // `stamp_source_ts()` call). `write_start_ns` is kept only
            // for this call's OWN latency metric below, which needs the
            // real wall-clock time this write() started, not whatever
            // instant the application asked to pretend it was written at.
            timestamp_ns: source_ts_ns,
            cdr_version: version,
        };
        // A true source timestamp (the write-side clock, or the
        // application's own override): tag it so SampleInfo can report
        // it as such.
        entry.mark_source_ts();
        if reception_prefixed {
            entry.mark_reception_ts_prefix();
        }
        // The sample's key hash, computed only if an EXCLUSIVE reader's
        // ownership gate or a reader's history asks for it.
        let key = || Some(key_hash.unwrap_or_else(|| msg.compute_key()));

        // A durable writer owes this sample to every reader that binds
        // later: the merger replays the history cache to them, so this
        // fast path must journal into that cache too, or a TRANSIENT_LOCAL
        // writer with one live local reader would retain nothing. Journal a
        // copy the way the wire path does (its own slot: merger entries
        // never alias cache retention), before the push below consumes the
        // claim reference that keeps this slot readable. VOLATILE writers
        // never enter here; their cache serves wire repair only.
        //
        // Room in every co-located reader's history comes first, before the
        // sample is journaled or pushed anywhere: a RELIABLE reader with
        // none makes this write wait, and TIMEOUT leaves no trace of it
        // (see `TopicMerger::admit`). Without a journal, admitting and
        // pushing are one call (`push_waiting`), the plain one-reader push.
        if let Some(stamp) = coherent_stamp.take() {
            // A member of an open coherent set: held back from the merger
            // (`stage_coherent_member`), out of line so this, the hot path
            // of every other write, stays untouched.
            self.stage_coherent_member::<M>(
                msg,
                key_hash,
                slab_pool,
                serialized_len,
                seq,
                version,
                group,
                stamp,
                orders,
                guards,
                deadline,
                entry,
            )?;
        } else if self.durable_history_cache().is_some() {
            let metadata = (
                ChangeMetadata {
                    key_hash,
                    cdr_version: version,
                    source_ts: rtps_timestamp_preserving_unix_nanos(entry.timestamp_ns),
                    source_ts_known: true,
                    ..ChangeMetadata::user_data()
                },
                group,
            );
            // The write's one deadline: the memory wait's, the reader-room
            // wait's and the history's.
            let admission = match M::admit(
                &self.merger,
                &entry,
                slab_pool,
                &key,
                self.waits_for_room().then_some(deadline),
                self.local_ordering::<M>(group),
            ) {
                Ok(admission) => admission,
                Err(rt::RoomTimeout) => {
                    self.abandon_before_emission(seq, Some(handle), group);
                    return Err(Error::WriteTimeout);
                }
            };
            // The encoded sample, past a reception-time prefix.
            let at = entry.payload_offset();
            let journaled = match slab_pool.try_borrow(handle) {
                Some(bytes) => self.journal_before_emission::<M>(
                    seq,
                    &bytes[at..at + serialized_len],
                    metadata,
                    deadline,
                ),
                None => self.journal_before_emission::<M>(
                    seq,
                    &slab_pool.get_buffer(handle)[at..at + serialized_len],
                    metadata,
                    deadline,
                ),
            };
            // Refused: nothing is pushed, so the claim reference the push
            // would have consumed goes back here, with the number and the
            // room taken in the readers.
            if let Err(e) = journaled {
                drop(admission);
                self.abandon_before_emission(seq, Some(handle), group);
                return Err(e);
            }
            self.record_write_commit::<M>(seq, key_hash);
            // Journaled: the change is made before the push runs the
            // co-located readers' listeners (`ChangeGuards`).
            drop(guards);
            // deliver() consumes the claim reference on the handle in every
            // outcome (transfer on delivery, free on zero deliveries).
            let _merger_success = M::deliver(
                &self.merger,
                admission,
                entry,
                slab_pool,
                &key,
                self.local_ordering::<M>(group),
                orders,
            );
        } else if self.deadlines.is_some()
            || self.wire_windows.is_group()
            || matches!(
                self.qos.reliability,
                super::super::qos::Reliability::Reliable
            )
        {
            // Commit the reliable/local match watermark, GROUP watermark
            // and any finite deadline after admission succeeds, before
            // delivery can run a callback or release the change guards.
            let admission = match M::admit(
                &self.merger,
                &entry,
                slab_pool,
                &key,
                self.waits_for_room().then_some(deadline),
                self.local_ordering::<M>(group),
            ) {
                Ok(admission) => admission,
                Err(rt::RoomTimeout) => {
                    self.abandon_before_emission(seq, Some(handle), group);
                    return Err(Error::WriteTimeout);
                }
            };
            self.record_write_commit::<M>(seq, key_hash);
            drop(guards);
            M::deliver(
                &self.merger,
                admission,
                entry,
                slab_pool,
                &key,
                self.local_ordering::<M>(group),
                orders,
            );
        } else if let Err(rt::RoomTimeout) = {
            // Nothing to journal here: the change is made before the push
            // runs the co-located readers' listeners (`ChangeGuards`).
            drop(guards);
            M::push_waiting(&self.merger, entry, slab_pool, &key, || {
                self.waits_for_room().then(|| deadline.remaining())
            })
        } {
            // The push consumed the claim reference: only the number goes
            // back.
            self.abandon_unpublished_sequence(seq, group);
            return Err(Error::WriteTimeout);
        }

        if let Some(m) = telemetry::get_metrics_opt() {
            m.increment_sent(1);
            m.increment_bytes_sent(serialized_len as u64);
            m.add_latency_sample(write_start_ns, current_time_ns());
        }
        self.counts.sent(serialized_len);

        if let Some(listener) = self.listener.get_any() {
            listener.on_sample_written(msg, seq);
        }

        Ok(())
    }

    /// `payload` after the 8-byte write-time clock `at` (little endian),
    /// the slab layout of an intra-process write that carries an
    /// application-supplied source timestamp
    /// (`IndexEntry::mark_reception_ts_prefix`). Only such a write pays
    /// for the copy.
    #[cold]
    fn with_reception_ts(at: u64, payload: &[u8]) -> Vec<u8> {
        let mut prefixed = Vec::with_capacity(RECEPTION_TS_LEN + payload.len());
        prefixed.extend_from_slice(&at.to_le_bytes());
        prefixed.extend_from_slice(payload);
        prefixed
    }

    /// `commit_intra_process_entry` for a member of an open coherent set
    /// (DDS v1.4 Sec.2.2.3.6): a co-located coherent-access reader must
    /// never see it ahead of the rest of its set. A durable writer journals
    /// it now -- late joiners are owed the exact history, and
    /// `HistoryCache::snapshot_for_local_replay` withholds it until its set
    /// closes -- and its `stamp` stages it for the merger, which receives
    /// it with the rest of the set once the set is closed and complete
    /// (`intra_coherent`). A refused journal withdraws the stamp: the
    /// change was never part of the set.
    #[cold]
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn stage_coherent_member<M: LocalWriteMode>(
        &self,
        msg: &T,
        key_hash: Option<[u8; 16]>,
        slab_pool: &rt::SlabPool,
        serialized_len: usize,
        seq: u64,
        version: crate::dds::CdrVersion,
        group: Option<GroupTag>,
        stamp: CoherentStamp,
        orders: M::Orders,
        guards: ChangeGuards<'_, M>,
        deadline: &rt::WriteDeadline,
        entry: rt::IndexEntry,
    ) -> Result<()> {
        #[cfg(any(test, feature = "test-support"))]
        super::run_coherent_stage_hook();
        let handle = entry.handle;
        if self.durable_history_cache().is_some() {
            let (coherent_sn, group_sn) = stamp.markers();
            let metadata = (
                ChangeMetadata {
                    key_hash,
                    cdr_version: version,
                    coherent_sn,
                    group_sn,
                    source_ts: rtps_timestamp_preserving_unix_nanos(entry.timestamp_ns),
                    source_ts_known: true,
                    ..ChangeMetadata::user_data()
                },
                group,
            );
            // The encoded sample, past a reception-time prefix.
            let at = entry.payload_offset();
            let journaled = match slab_pool.try_borrow(handle) {
                Some(bytes) => self.journal_before_emission::<M>(
                    seq,
                    &bytes[at..at + serialized_len],
                    metadata,
                    deadline,
                ),
                None => self.journal_before_emission::<M>(
                    seq,
                    &slab_pool.get_buffer(handle)[at..at + serialized_len],
                    metadata,
                    deadline,
                ),
            };
            if let Err(e) = journaled {
                self.abandon_before_emission(seq, Some(handle), group);
                // The other guards first, then the withdrawal (which may
                // deliver the set on this thread).
                drop(guards);
                drop(orders);
                drop(stamp);
                return Err(e);
            }
        }
        self.record_write_commit::<M>(seq, key_hash);
        // The change is made before its set can be delivered, which runs
        // the co-located readers' listeners (`ChangeGuards`), possibly on
        // this thread.
        drop(guards);
        #[cfg(any(test, feature = "test-support"))]
        super::coherent_stage_delay_for_test();
        stamp.stage_sample(
            super::intra_coherent::StagedIntraSample::ready(
                entry,
                key_hash.unwrap_or_else(|| msg.compute_key()),
                None,
            )
            .with_pending(M::pending(orders)),
        );
        Ok(())
    }

    #[allow(clippy::missing_panics_doc)]
    // `drops` is the writer's own `WriterStats::drops`, raised beside the
    // telemetry drop: this is an associated fn (no `self`), and the
    // eighth argument is the price of keeping that door in one place.
    #[allow(clippy::too_many_arguments)]
    fn prepare_intra_process_entry(
        payload: &[u8],
        serialized_len: usize,
        seq: u64,
        source_ts_ns: u64,
        reception_ts: Option<u64>,
        cdr_version: crate::dds::CdrVersion,
        deadline: Option<&rt::WriteDeadline>,
        drops: &core::cell::Cell<u64>,
    ) -> Result<(rt::IndexEntry, rt::SlabHandle)> {
        #[cfg(test)]
        super::run_local_prepare_hook();
        let slab_pool = rt::get_slab_pool_ref();
        let prefixed =
            reception_ts.map(|at| Self::with_reception_ts(at, &payload[..serialized_len]));
        let handle = Self::reserve_local_leg(
            prefixed.as_deref().unwrap_or(&payload[..serialized_len]),
            deadline,
        )?;
        let serialized_len = prefixed.as_ref().map_or(serialized_len, Vec::len);

        let seq_u32 = match u32::try_from(seq) {
            Ok(value) => value,
            Err(_) => {
                slab_pool.release(handle);
                drops.set(drops.get().wrapping_add(1));
                if let Some(m) = telemetry::get_metrics_opt() {
                    m.increment_dropped(1);
                }
                log::debug!(
                    "[writer] Sequence {} exceeds 32-bit limit; dropping intra-process delivery",
                    seq
                );
                return Err(Error::Unsupported);
            }
        };

        let len_u32 = match u32::try_from(serialized_len) {
            Ok(value) => value,
            Err(_) => {
                slab_pool.release(handle);
                drops.set(drops.get().wrapping_add(1));
                if let Some(m) = telemetry::get_metrics_opt() {
                    m.increment_dropped(1);
                }
                log::debug!(
                    "[writer] Serialized payload too large ({} bytes); dropping intra-process delivery",
                    serialized_len
                );
                return Err(Error::BufferTooSmall);
            }
        };

        let mut entry = rt::IndexEntry {
            seq: seq_u32,
            handle,
            len: len_u32,
            flags: 0x01,
            // `stamp_source_ts()`'s value (the application's
            // `write_w_timestamp` override when staged, the write-time
            // clock otherwise) -- the same one the wire leg and journal
            // read for this change, not the raw clock reading, which
            // would ignore an override.
            timestamp_ns: source_ts_ns,
            cdr_version,
        };
        // A true source timestamp: tag it so SampleInfo can report it as
        // such.
        entry.mark_source_ts();
        if reception_ts.is_some() {
            entry.mark_reception_ts_prefix();
        }

        Ok((entry, handle))
    }

    /// Dispose an instance -- marks it as NOT_ALIVE_DISPOSED.
    ///
    /// Sends a DATA submessage with key-only payload (K flag) and
    /// PID_STATUS_INFO = DISPOSED in inline QoS. Remote readers will
    /// transition this instance to NOT_ALIVE_DISPOSED_INSTANCE_STATE.
    ///
    /// DDS spec: Section 2.2.2.4.2.13 -- dispose
    /// RTPS spec: Section 9.6.4.9 -- StatusInfo_t
    pub fn dispose(&self, instance: &T) -> Result<()> {
        self.send_lifecycle_change(instance, crate::protocol::builder::StatusInfoKind::Disposed)
    }

    /// Unregister an instance -- writer no longer claims ownership.
    ///
    /// Sends a DATA submessage with key-only payload (K flag) and
    /// PID_STATUS_INFO in inline QoS. Which bits go on the wire is decided by
    /// WRITER_DATA_LIFECYCLE (DDS v1.4 sec. 2.2.3.21):
    ///
    /// - `autodispose_unregistered_instances = true`, **the DDS default**:
    ///   the writer disposes the instance each time it is unregistered, so
    ///   the wire carries DISPOSED|UNREGISTERED (StatusInfo 0x03) and remote
    ///   readers report NOT_ALIVE_DISPOSED - the standard reports an instance
    ///   that is both as DISPOSED, there being exactly three instance states.
    /// - `false` (`WriterDataLifecycle::manual_dispose()`): UNREGISTERED
    ///   alone (0x02), and readers report NOT_ALIVE_NO_WRITERS once no other
    ///   writer remains.
    ///
    /// An application that wants a plain unregister to read as NO_WRITERS
    /// must therefore ask for it. That is not a quirk of ours: the OMG
    /// reference `shape_main.cxx` sets the flag to FALSE precisely when it is
    /// told to finish by unregistering, which is only necessary because
    /// conformant writers honour the TRUE default. Ours does too;
    /// `examples/shape_main.rs` makes the same call for the same reason.
    ///
    /// The same rule governs the implicit unregister `Drop` performs when the
    /// writer is deleted (DDS v1.4 Sec.2.2.2.4.1.6, Sec.2.2.3.21: the flag
    /// "will determine whether instances are ultimately disposed when the
    /// DataWriter is deleted"). The interop suite's plain-exit run expects
    /// NOT_ALIVE_NO_WRITERS, so `examples/shape_main.rs` turns the policy off
    /// for that run too, rather than the library ignoring it.
    ///
    /// DDS spec: Section 2.2.2.4.2.7 -- unregister_instance
    /// RTPS spec: Section 9.6.4.9 -- StatusInfo_t
    pub fn unregister_instance(&self, instance: &T) -> Result<()> {
        let status_info = crate::protocol::builder::StatusInfoKind::for_unregister(
            self.qos
                .writer_data_lifecycle
                .autodispose_unregistered_instances,
        );
        self.send_lifecycle_change(instance, status_info)
    }

    /// Internal: send a dispose or unregister lifecycle change to every
    /// reader (see `emit_lifecycle_change`) and keep the instance bookkeeping.
    fn send_lifecycle_change(
        &self,
        instance: &T,
        status_info: crate::protocol::builder::StatusInfoKind,
    ) -> Result<()> {
        if self.serialized_keys && instance.instance_key().is_none() {
            return Err(Error::InvalidState(
                "serialized keyed writer requires instance metadata".into(),
            ));
        }
        // dispose()/unregister_instance() assert a MANUAL writer's
        // liveliness exactly like write() (DDS v1.4 Sec.2.2.3.11, RTPS
        // v2.5 Sec.8.4.13.5: "write, dispose or unregister_instance").
        if let Some(ref assert) = self._liveliness_assert {
            assert.assert();
        }
        let instance_key = instance.instance_key();
        let has_instance_key = T::has_key() || instance_key.is_some();
        let key_hash = instance_key.unwrap_or_else(|| instance.compute_key());
        #[cfg(feature = "security")]
        if let Some(wire) = self.protected_key_hash(instance)? {
            self.protected_key_hashes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key_hash, wire);
        }

        // Spec-compliant K-flag DATA payload: serialized @key fields, not the
        // digest, encoded at the version the data path uses, which the
        // packet's encapsulation identifier then announces (not XCDR2
        // whatever the writer negotiated).
        let version = self.effective_cdr_version();
        let serialized_key = instance.encode_key(version);

        // Auto-unregister at Drop covers only instances the app has not yet
        // unregistered (DDS v1.4 sec. 2.2.2.4.1.6 Drop semantics). A bare dispose
        // does NOT terminate the writer-instance association per
        // sec. 2.2.2.4.2.7 (explicit unregister), so we only forget the instance
        // when the application explicitly unregistered it (Unregistered or
        // the combined DisposedUnregistered bitmask).
        //
        // Forgotten BEFORE the change is emitted: a reader of this process
        // asks this table whether the writer still holds the instance when
        // the unregister reaches it, and must not hear "yes" from the very
        // writer that let it go. Put back if the change was not emitted.
        let unregisters = matches!(
            status_info,
            crate::protocol::builder::StatusInfoKind::Unregistered
                | crate::protocol::builder::StatusInfoKind::DisposedUnregistered
        );
        let forgotten = if unregisters {
            self.written_instances
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key_hash)
        } else {
            None
        };
        if let Err(e) = self.emit_lifecycle_change(
            &key_hash,
            &serialized_key,
            version,
            status_info,
            true,
            has_instance_key,
        ) {
            if let Some(key_bytes) = forgotten {
                self.written_instances
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(key_hash, key_bytes);
            }
            return Err(e);
        }

        #[cfg(feature = "security")]
        if unregisters {
            self.protected_key_hashes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key_hash);
        }

        // Both operations stop the timer. Disposal retains registration
        // for idempotent register_instance (DDS v1.4 Sec.2.2.2.4.2.5);
        // unregistration ends the writer association (Sec.2.2.3.23.3).
        if let Some(deadlines) = self.deadlines.as_ref() {
            let handle = crate::dds::reader::InstanceHandle::new(key_hash);
            if unregisters {
                deadlines.remove_instance(handle);
            } else {
                deadlines.dispose_instance(handle);
            }
        }

        if unregisters {
            // Instance fully torn down: no longer needs the disposed guard.
            self.disposed_instances
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key_hash);
        } else if matches!(
            status_info,
            crate::protocol::builder::StatusInfoKind::Disposed
        ) {
            // Bare dispose: mark the instance so Drop skips auto-unregister.
            // A trailing UNREGISTER would flip a subscriber that applies the
            // latest lifecycle change from DISPOSED to NO_WRITERS, losing the
            // disposal the application asked for.
            self.disposed_instances
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key_hash);
        }

        Ok(())
    }

    /// Send a lifecycle change using a pre-computed key hash and the
    /// serialized @key bytes captured at write() time. The K-payload carries
    /// the encoded key per RTPS v2.5 sec. 9.4.5.3.2 so spec-strict subscribers
    /// can deserialize the instance identity and
    /// drive the NOT_ALIVE_* state transition.
    fn send_key_lifecycle_change(
        &self,
        key_hash: &[u8; 16],
        key_bytes: &[u8],
        version: crate::dds::CdrVersion,
        status_info: crate::protocol::builder::StatusInfoKind,
    ) -> Result<()> {
        // Runs from Drop, once per instance: journal without waiting.
        // Every entry captured by write() has an instance key, including
        // opaque adapters whose static DDS type reports has_key() == false.
        self.emit_lifecycle_change(key_hash, key_bytes, version, status_info, false, true)
    }

    /// A cached digest is usable only while the current policy protects keys.
    #[cfg(feature = "security")]
    fn lifecycle_wire_key_hash(
        &self,
        key_hash: &[u8; 16],
        has_instance_key: bool,
    ) -> Result<[u8; 16]> {
        if has_instance_key {
            if let Some(suite) = self.security.as_ref() {
                if self.endpoint_protection(suite)?.is_key_protected() {
                    return self
                        .protected_key_hashes
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(key_hash)
                        .copied()
                        .ok_or_else(|| {
                            Error::EncryptionUnavailable(
                                "protected lifecycle key has no cached digest".into(),
                            )
                        });
                }
            }
        }
        Ok(*key_hash)
    }

    /// Emit one instance lifecycle change (dispose, unregister, or both) to
    /// every reader: remote readers get the key-only DATA, readers in this
    /// process get it through the merger (see `IndexEntry::mark_lifecycle`).
    ///
    /// The one body behind `dispose`, `unregister_instance` and the Drop-time
    /// auto-unregister: one body, so the Drop path cannot drift from the
    /// dispose path (a peek-then-increment of the sequence number, say). It
    /// also reaches a local reader, which must see an instance disposed or
    /// unregistered whatever the transport (intra-process and UDP alike).
    fn emit_lifecycle_change(
        &self,
        key_hash: &[u8; 16],
        key_bytes: &[u8],
        version: crate::dds::CdrVersion,
        status_info: crate::protocol::builder::StatusInfoKind,
        may_block: bool,
        has_instance_key: bool,
    ) -> Result<()> {
        let _local_notices = self
            .qos
            .presentation
            .coherent_access
            .then(crate::dds::LocalDelivery::enter);
        // A lifecycle change is a CacheChange like a sample (RTPS 2.5 8.2.3):
        // it enters the history BEFORE it is emitted, with the payload the
        // key-only DATA carries, so a late joiner receives it and a NACK for
        // its number is repaired with it instead of a GAP.
        // ONE source timestamp for the change, on the wire and in the
        // history, so a repair or a replay reproduces it.
        #[cfg(feature = "security")]
        let wire_key_hash = self.lifecycle_wire_key_hash(key_hash, has_instance_key)?;
        #[cfg(not(feature = "security"))]
        let wire_key_hash = {
            let _ = has_instance_key;
            *key_hash
        };
        let source_ts = self.stamp_source_ts();

        // The cached change keeps the coherent markers it was emitted with,
        // whatever the durability, as a sample does (see the comment on
        // `coherent_markers_for_cache` in write()): a repaired dispose of a
        // set is a member of it.
        let cache_metadata = |coherent_sn: Option<u64>,
                              group_sn: Option<u64>,
                              group: Option<GroupTag>,
                              sealed: bool| {
            (
                ChangeMetadata {
                    key_hash: Some(wire_key_hash),
                    cdr_version: version,
                    source_ts,
                    source_ts_known: true,
                    status_info: Some(status_info),
                    coherent_sn,
                    group_sn,
                    key_epoch: u16::from(sealed),
                    ..ChangeMetadata::user_data()
                },
                group,
            )
        };

        let (Some(transport), Some(ctx)) = (self.transport.as_ref(), self.rtps_endpoint) else {
            // No wire: `fetch_add` takes the number atomically; there is no
            // packet whose build could be refused. Nothing to do at all
            // without a history or a local reader.
            let open_local_set = self.qos.presentation.coherent_access
                && self
                    .publisher
                    .as_ref()
                    .is_some_and(|publisher| publisher.is_coherent());
            if self.history_cache.is_none()
                && !self.lifecycle_reaches_local_readers()
                && !open_local_set
            {
                return Ok(());
            }
            let _in_flight = self.taking_change();
            // A GROUP Publisher's writer takes its SN and the next GSN as
            // one step, as `write()` does (a lifecycle change is a
            // CacheChange, RTPS v2.5 Sec.8.7.5). Its coherent stamp is
            // carried to the local delivery below: a dispose/unregister
            // inside an open set is a member of it (DDS v1.4 Sec.2.2.3.6)
            // and must reach a co-located reader with the rest of the set,
            // never ahead of it.
            let (seq, group_tag, group_coherent, stamp, orders) =
                match self.publisher.as_ref().filter(|core| core.group_scope) {
                    Some(core) => {
                        let (seq, tag, coherent, stamp, orders) =
                            self.take_group_change::<ControlledWrite>(core);
                        (seq, Some(tag), Some(coherent), stamp, orders)
                    }
                    None => {
                        let seq = self.next_seq.fetch_add(1, Ordering::AcqRel);
                        let (coherent_sn, group_sn, stamp) = self.coherent_context(seq);
                        (
                            seq,
                            None,
                            Some((coherent_sn, group_sn)),
                            stamp,
                            rt::merger::PendingOrders::default(),
                        )
                    }
                };
            let _pending_gsn = PendingGsn(group_tag.and_then(|_| self.pending_gsn_slot()));
            // Single producer (plain `fetch_add`, no CAS retry) so this
            // runs exactly once with the SN that is actually committed,
            // same as the sample path's `coherent_context(seq)` call in
            // `write()`.
            let (coherent_sn, group_sn) = group_coherent.unwrap_or_else(|| {
                let (coherent_sn, group_sn, _stamp) = self.coherent_context(seq);
                (coherent_sn, group_sn)
            });
            if let Err(e) = self.journal_change(
                seq,
                key_bytes,
                cache_metadata(coherent_sn, group_sn, group_tag, false),
                may_block
                    .then(|| rt::WriteDeadline::new(self.qos.reliability_max_blocking_time))
                    .as_ref(),
            ) {
                self.abandon_before_emission(seq, None, group_tag);
                // `stamp` drops here (withdraws): the change was never made.
                return Err(e);
            }
            self.last_lifecycle_sn.store(seq, Ordering::Release);
            self.deliver_lifecycle_locally(
                stamp,
                seq,
                key_hash,
                status_info,
                source_ts,
                self.local_ordering::<ControlledWrite>(group_tag),
                orders,
            );
            return Ok(());
        };

        // Wire-bound from here, so the same posture as write(): seal the key
        // bytes under this writer's data-plane key, or refuse. The sealer is
        // a passthrough when encryption was never requested, and fails closed
        // (EncryptionUnavailable, never cleartext) when it was requested and
        // no key exists. Runs BEFORE the SN allocation below so a refused
        // lifecycle change does not burn a sequence number RELIABLE readers
        // would NACK forever. From Drop the caller discards the Result, so a
        // key-less encrypting writer silently seals-or-refuses on teardown,
        // never emits cleartext; Drop retires the data-plane key AFTER its
        // auto-unregister loop for exactly this reason.
        #[cfg(feature = "security")]
        let (sealed_key, sealed) = self.seal_payload_for_wire(key_bytes, version)?;
        #[cfg(feature = "security")]
        let key_bytes: &[u8] = &sealed_key;
        #[cfg(not(feature = "security"))]
        let sealed = false;

        // PEEK the sequence number, build, and only then take it. A refused
        // build must not burn a number: RELIABLE readers would NACK the hole
        // forever and nothing in history could ever repair it - which an
        // allocate-build-refuse order would do whenever
        // `build_dispose_packet_with_context` refuses an oversize inline QoS.
        //
        // The number is TAKEN by compare-exchange, not by a second increment:
        // `DataWriter` is `!Sync`, but it is not this counter's only producer.
        // The publisher closes coherent sets from whatever thread calls
        // `end_coherent_changes` and takes a number for the close marker
        // (`CoherentWriter` is `Send + Sync`). A peek-then-increment let the
        // two carry the SAME number, where RTPS 2.5 8.2.3 has the writer
        // assign it "to uniquely identify the change". If the number moved
        // while the packet was built, build again with the next one.
        //
        // `coherent_context(seq)` runs INSIDE the closure, once per attempt,
        // with that attempt's candidate `seq` -- not once before the loop
        // with a peeked value. `coherent_context` has side effects
        // (`last_sn_in_active_set` and the
        // cold-start `coherent_set_first_sn` store) that must describe the
        // SN actually committed: the loop only exits once a candidate's CAS
        // succeeds, so the LAST closure invocation always corresponds to
        // the final `seq`, and every earlier (failed-CAS, discarded)
        // invocation is superseded by it -- except for the one narrow case
        // where THIS call is the very first change of a brand new coherent
        // set (the cold-start branch) and a concurrent SN producer
        // (`end_coherent_changes`'s close-marker take) forces a retry: the
        // discarded attempt's `coherent_set_first_sn` store is overwritten
        // on the next attempt's cold-start re-check... unless the GSN has
        // not changed, in which case the next attempt re-reads the stale
        // value instead of re-deriving it. That residual race requires a
        // dispose to be the literal opening change of a set AND to race the
        // set's own close on another thread -- the same pre-existing
        // narrow window the shared-counter design already accepts for the
        // close marker; it is not widened by this change and is out of
        // scope for this defect (a writer-authored coherent set opening
        // with a dispose is degenerate usage to begin with).
        let coherent_tags: std::cell::Cell<(Option<u64>, Option<u64>)> =
            std::cell::Cell::new((None, None));
        let spec_packet: std::cell::RefCell<Option<Vec<u8>>> = std::cell::RefCell::new(None);
        // The stamp of the LAST `coherent_context` call `build` makes. Under
        // a CAS retry below, only the final call corresponds to the seq
        // that is actually committed (see the comment above), so only its
        // stamp's set membership matters; replacing it on every call
        // withdraws each discarded attempt's stamp as it is superseded,
        // exactly as if each were dropped on the spot.
        let stamp_slot: std::cell::RefCell<Option<CoherentStamp>> = std::cell::RefCell::new(None);
        let build = |seq: u64,
                     group_tag: Option<&GroupTag>,
                     coherent: Option<(Option<u64>, Option<u64>)>| {
            let (coherent_sn, group_sn) = coherent.unwrap_or_else(|| {
                let (coherent_sn, group_sn, stamp) = self.coherent_context(seq);
                *stamp_slot.borrow_mut() = stamp;
                (coherent_sn, group_sn)
            });
            coherent_tags.set((coherent_sn, group_sn));
            // The spec GROUP form, for readers of the spec class.
            *spec_packet.borrow_mut() = group_tag.map(|tag| {
                builder::build_dispose_packet_with_context_coherent_ts(
                    &ctx,
                    &self.topic,
                    seq,
                    &wire_key_hash,
                    key_bytes,
                    status_info,
                    version,
                    source_ts,
                    coherent_sn,
                    group_sn,
                    Some(tag),
                    sealed,
                )
            });
            builder::build_dispose_packet_with_context_coherent_ts(
                &ctx,
                &self.topic,
                seq,
                &wire_key_hash,
                key_bytes,
                status_info,
                version,
                source_ts,
                coherent_sn,
                group_sn,
                None,
                sealed,
            )
        };
        // A GROUP Publisher's writer takes its SN and the next GSN as one
        // step under the Publisher's lock, which also serializes it with the
        // close markers' numbers; a refused build gives both back.
        let _in_flight = self.taking_change();
        let (seq, packet, group_tag, stamp, orders) =
            match self.publisher.as_ref().filter(|core| core.group_scope) {
                Some(core) => {
                    let (seq, tag, coherent, stamp, orders) =
                        self.take_group_change::<ControlledWrite>(core);
                    let packet = build(seq, Some(&tag), Some(coherent));
                    if packet.is_empty() {
                        let _pending_gsn = PendingGsn(self.pending_gsn_slot());
                        self.give_back_group_change(core, seq, tag.gsn);
                        // The change was never made: withdraw its stamp.
                        drop(stamp);
                        return Err(Error::BufferTooSmall);
                    }
                    (seq, packet, Some(tag), stamp, orders)
                }
                None => {
                    let (seq, packet) =
                        take_sequence_number_for(&self.next_seq, |seq| build(seq, None, None))
                            .ok_or(Error::BufferTooSmall)?;
                    (
                        seq,
                        packet,
                        None,
                        stamp_slot.into_inner(),
                        rt::merger::PendingOrders::default(),
                    )
                }
            };
        let _pending_gsn = PendingGsn(group_tag.and_then(|_| self.pending_gsn_slot()));
        let (coherent_sn, group_sn) = coherent_tags.get();

        if let Err(e) = self.journal_change(
            seq,
            key_bytes,
            cache_metadata(coherent_sn, group_sn, group_tag, sealed),
            may_block
                .then(|| rt::WriteDeadline::new(self.qos.reliability_max_blocking_time))
                .as_ref(),
        ) {
            self.abandon_before_emission(seq, None, group_tag);
            // `stamp` drops here (withdraws): the change was never made.
            return Err(e);
        }
        self.last_lifecycle_sn.store(seq, Ordering::Release);
        self.deliver_lifecycle_locally(
            stamp,
            seq,
            key_hash,
            status_info,
            source_ts,
            self.local_ordering::<ControlledWrite>(group_tag),
            orders,
        );
        let spec_packet = spec_packet.into_inner();
        // The plain form of this change, built by its first plain reader only.
        let plain_build = || {
            builder::build_dispose_packet_with_context_coherent_ts(
                &ctx,
                &self.topic,
                seq,
                &wire_key_hash,
                key_bytes,
                status_info,
                version,
                source_ts,
                None,
                None,
                None,
                sealed,
            )
        };
        let plain_form = group_tag.is_some().then(|| LazyForm::new(&plain_build));
        let sent = self.send_packet_to_endpoints_classed(
            transport,
            &packet,
            spec_packet.as_deref().filter(|p| !p.is_empty()),
            plain_form.as_ref(),
        );
        // The change is in the history from here, sent or not: announce it
        // as write() announces a sample. A HEARTBEAT is how a reliable reader
        // learns the change exists (RTPS 2.5 8.3.8.6, 8.4.2.2); unannounced,
        // a lost dispose or unregister with no later write is never NACKed,
        // so never repaired.
        self.maybe_send_heartbeat(seq);
        sent.map_err(|_| {
            if let Some(m) = telemetry::get_metrics_opt() {
                m.increment_transport_errors(1);
            }
            Error::TransportError
        })?;

        log::debug!(
            "[writer] Sent {:?} for topic='{}' seq={} key_hash={:02x?} coherent_sn={:?} group_sn={:?}",
            status_info,
            self.topic,
            seq,
            &key_hash[..4],
            coherent_sn,
            group_sn
        );
        Ok(())
    }

    /// Whether a lifecycle change has a reader in this process to reach:
    /// one is bound to the merger, and the intra-process leg is not
    /// suppressed by encryption (the same rule `write()` applies to data -
    /// under encryption local readers receive nothing from this leg, so they
    /// hold no instance a change could concern).
    fn lifecycle_reaches_local_readers(&self) -> bool {
        if self.merger.reader_count() == 0 {
            return false;
        }
        self.lifecycle_plaintext_allowed()
    }

    fn lifecycle_plaintext_allowed(&self) -> bool {
        #[cfg(feature = "security")]
        if self
            .security
            .as_ref()
            .and_then(|s| s.cryptographic())
            .is_some()
        {
            return false;
        }
        true
    }

    /// Build the ring entry for a lifecycle change bound for a co-located
    /// reader: flagged as such, carrying the key hash instead of a sample.
    /// `None` for a `seq` past the intra ring's u32 range or an exhausted
    /// slab pool (logged); either way the change has no local target.
    fn build_lifecycle_entry(
        &self,
        seq: u64,
        key_hash: &[u8; 16],
        status_info: crate::protocol::builder::StatusInfoKind,
        source_ts: (u32, u32),
    ) -> Option<rt::IndexEntry> {
        // The same bound `write()` puts on the intra ring's u32 slot.
        let Ok(seq_u32) = u32::try_from(seq) else {
            log::warn!(
                "[writer] topic='{}' seq={} past the intra ring's u32 range: lifecycle change not delivered locally",
                self.topic,
                seq
            );
            return None;
        };
        let slab_pool = rt::get_slab_pool_ref();
        let Some((handle, _metric)) = slab_pool.reserve_and_write(key_hash, rt::Claim::Writer)
        else {
            log::warn!(
                "[writer] topic='{}' seq={}: slab pool exhausted, lifecycle change not delivered locally",
                self.topic,
                seq
            );
            return None;
        };
        let mut entry = rt::IndexEntry {
            seq: seq_u32,
            handle,
            len: 16,
            flags: 0x01, // COMMITTED
            // The change's own source timestamp (`emit_lifecycle_change`'s
            // `stamp_source_ts()`, the application's `_w_timestamp`
            // override or the writer's clock at the time of the call) --
            // never `current_time_ns()` here, which would be THIS
            // function's call time, not the change's, and would answer
            // `dispose_w_timestamp`'s explicit argument with the wrong
            // instant for a co-located reader (DDS v1.4 Sec.2.2.2.5.5).
            timestamp_ns: unix_nanos_from_rtps_timestamp(source_ts),
            cdr_version: crate::CdrVersion::Xcdr2,
        };
        entry.mark_lifecycle(u8::from(status_info));
        Some(entry)
    }

    /// Hand a lifecycle change to the readers in this process now, in the
    /// same order as the samples around it: no open coherent set holds it
    /// back (no stamp, or no local target to stage -- see
    /// [`deliver_lifecycle_locally`](Self::deliver_lifecycle_locally)).
    /// Returns whether the merger actually delivered this lifecycle change
    /// to at least one co-located reader (`false` for no local readers, or
    /// `build_lifecycle_entry` finding no local target, or a merger that
    /// found nothing to deliver to).
    fn push_lifecycle_to_local_readers(
        &self,
        seq: u64,
        key_hash: &[u8; 16],
        status_info: crate::protocol::builder::StatusInfoKind,
        source_ts: (u32, u32),
        ordering: Option<(u64, u64)>,
        orders: rt::merger::PendingOrders,
    ) -> bool {
        let pairing = self.merger.pairing();
        if !self.lifecycle_reaches_local_readers() {
            return false;
        }
        let Some(entry) = self.build_lifecycle_entry(seq, key_hash, status_info, source_ts) else {
            return false;
        };
        drop(pairing);
        // Lifecycle changes take no sample places; delivery consumes the claim.
        let pool = rt::get_slab_pool_ref();
        let key = || Some(*key_hash);
        let Ok(admission) = self.merger.admit(&entry, pool, &key, None) else {
            pool.release(entry.handle);
            return false;
        };
        self.merger
            .deliver(admission, entry, pool, &key, ordering, orders)
    }

    /// A lifecycle change (dispose/unregister) that is a member of an open
    /// coherent set: held back the same way a sample is, so it reaches a
    /// co-located coherent-access reader with the rest of the set and
    /// never ahead of it (DDS v1.4 Sec.2.2.3.6). `stamp` is consumed in
    /// every outcome: staged if there is a local target, withdrawn (the
    /// usual `CoherentStamp::drop`) otherwise. Return value matches
    /// [`push_lifecycle_to_local_readers`](Self::push_lifecycle_to_local_readers)'s:
    /// whether this SN has a local target that will see it (now or once
    /// the set completes), for the same no-reclaim gate.
    #[allow(clippy::too_many_arguments)]
    fn stage_lifecycle_for_local_readers(
        &self,
        stamp: CoherentStamp,
        seq: u64,
        key_hash: &[u8; 16],
        status_info: crate::protocol::builder::StatusInfoKind,
        source_ts: (u32, u32),
        ordering: Option<(u64, u64)>,
        orders: rt::merger::PendingOrders,
    ) -> bool {
        let pairing = self.merger.pairing();
        if !self.lifecycle_plaintext_allowed() {
            drop(pairing);
            drop(stamp);
            return false;
        }
        if self.merger.reader_count() == 0 {
            let sample = super::intra_coherent::StagedIntraSample::lifecycle(
                seq,
                *key_hash,
                u8::from(status_info),
                unix_nanos_from_rtps_timestamp(source_ts),
            );
            drop(pairing);
            stamp.stage_sample(sample.with_pending(orders));
            return true;
        }
        let entry = self.build_lifecycle_entry(seq, key_hash, status_info, source_ts);
        drop(pairing);
        match entry {
            Some(entry) => {
                let _ = ordering;
                stamp.stage_sample(
                    super::intra_coherent::StagedIntraSample::ready(entry, *key_hash, None)
                        .with_pending(orders),
                );
                true
            }
            None => {
                drop(stamp);
                false
            }
        }
    }

    /// Hand a lifecycle change to the readers in this process, staged with
    /// its coherent set if it has a stamp (member of an open set), or
    /// delivered at once otherwise -- the one call both `emit_lifecycle_change`
    /// branches make, so a dispose/unregister is never a special case next
    /// to a sample (DDS v1.4 Sec.2.2.3.6 draws no distinction between a
    /// data change and a lifecycle change inside a coherent set).
    #[allow(clippy::too_many_arguments)]
    fn deliver_lifecycle_locally(
        &self,
        stamp: Option<CoherentStamp>,
        seq: u64,
        key_hash: &[u8; 16],
        status_info: crate::protocol::builder::StatusInfoKind,
        source_ts: (u32, u32),
        ordering: Option<(u64, u64)>,
        orders: rt::merger::PendingOrders,
    ) -> bool {
        match stamp {
            Some(stamp) => self.stage_lifecycle_for_local_readers(
                stamp,
                seq,
                key_hash,
                status_info,
                source_ts,
                ordering,
                orders,
            ),
            None => self.push_lifecycle_to_local_readers(
                seq,
                key_hash,
                status_info,
                source_ts,
                ordering,
                orders,
            ),
        }
    }

    pub fn stats(&self) -> WriterStats {
        // Index order matches `EcsReplayOutcome`'s declaration order (see
        // `WriterReplayState::ecs_replay_counters`'s doc): [BuiltAndSent,
        // UnresolvedVendor, IncompleteMetadata, OrphanClose, SendError].
        let ecs = self
            ._replay_state
            .as_deref()
            .map(WriterReplayState::ecs_replay_counters)
            .unwrap_or_default();
        WriterStats {
            messages_sent: self.counts.messages_sent.get(),
            bytes_sent: self.counts.bytes_sent.get(),
            drops: self.counts.drops.get(),
            replay_ecs_close_sent: ecs[0],
            replay_ecs_close_unresolved_vendor: ecs[1],
            replay_ecs_close_incomplete_metadata: ecs[2],
            replay_ecs_close_orphaned: ecs[3],
            replay_ecs_close_send_error: ecs[4],
            ..WriterStats::default()
        }
    }

    /// Highest sequence number acknowledged by every matched RELIABLE
    /// reader, including local cache admissions (minimum across readers),
    /// or 0 when no reliable reader is matched.
    pub fn acked_through(&self) -> u64 {
        let map = match self.ack_track.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        map.values().copied().min().unwrap_or(0)
    }

    /// True when every sample written so far (including coherent-set close
    /// markers, which consume a sequence number) has been acknowledged by
    /// every matched RELIABLE reader. Trivially true before the first write
    /// or when no reliable reader is matched. Callers that need a reader
    /// to exist should gate on discovery first.
    pub fn fully_acked(&self) -> bool {
        all_acked(&self.next_seq, &self.ack_track)
    }

    /// DDS v1.4 Sec.2.2.2.4.2.15: blocks the calling thread until every
    /// sample written by this DataWriter has been acknowledged by every
    /// matched DataReader with RELIABILITY kind RELIABLE, or `max_wait`
    /// elapses, whichever is first. `Ok(())` on acknowledgment,
    /// `Err(Error::AcknowledgmentTimeout)` on timeout.
    ///
    /// "intended to be used only if the DataWriter has RELIABILITY QoS
    /// kind set to RELIABLE. Otherwise the operation will return
    /// immediately with RETCODE_OK": checked first, so a BEST_EFFORT
    /// writer never waits at all.
    ///
    /// A BEST_EFFORT reader is never counted: `ack_track` gains an entry
    /// only for a reader matched as RELIABLE (a remote proxy or a local
    /// merger binding), the
    /// same map `acked_through` and the DurabilityService cleanup timer
    /// read, so this is the one source of truth, not a second counter.
    /// An intra-process RELIABLE reader is counted identically to a
    /// remote one: local bindings register their own proxy and acknowledge
    /// when the merger admits an entry into the reader's history ring.
    ///
    /// No busy-wait: blocked on the history cache's own condition
    /// variable (`HistoryCache::wait_for_floor_change`), the one
    /// `set_acked_floor` already signals on every ACKNACK that advances
    /// the floor -- the same wake a full RELIABLE history's `write()`
    /// already relies on.
    pub fn wait_for_acknowledgments(&self, max_wait: std::time::Duration) -> Result<()> {
        wait_acked_until(
            matches!(
                self.qos.reliability,
                super::super::qos::Reliability::Reliable
            ),
            &self.next_seq,
            &self.ack_track,
            self.history_cache.as_deref(),
            deadline_after(max_wait),
        )
    }

    /// The source timestamp the NEXT emitted change takes: the one
    /// `write_w_timestamp` / `dispose_w_timestamp` /
    /// `unregister_instance_w_timestamp` staged, taken so it governs
    /// exactly one change and a later plain `write()` or lifecycle call
    /// reads the clock itself, never a stale override.
    pub(super) fn stamp_source_ts(&self) -> (u32, u32) {
        self.pending_source_ts
            .take()
            .unwrap_or_else(builder::now_rtps_timestamp)
    }

    /// [`stamp_source_ts`](Self::stamp_source_ts) for a change whose clock
    /// was already read: `now_ns` (epoch nanoseconds, `current_time_ns`)
    /// stands for the clock when nothing is staged, so a write reads the
    /// clock once rather than once per use.
    fn stamp_source_ts_at(&self, now_ns: u64) -> (u32, u32) {
        self.pending_source_ts
            .take()
            .unwrap_or_else(|| rtps_timestamp_from_unix_nanos(now_ns))
    }

    /// [`write`](Self::write) with an application-supplied source
    /// timestamp (DDS v1.4 Sec.2.2.2.4.2.12) instead of the one `write`
    /// reads from the clock, for DESTINATION_ORDER BY_SOURCE_TIMESTAMP and
    /// `SampleInfo::source_timestamp`. `source_timestamp_ns` is
    /// nanoseconds since the Unix epoch, the same unit
    /// `SampleInfo::source_timestamp_ns` reports back.
    ///
    /// The override is staged for exactly the one change this call
    /// emits: cleared on every exit from `write`, including an error
    /// returned before the clock would have been read, so it can never
    /// leak into a later plain `write()`.
    pub fn write_w_timestamp(&self, msg: &T, source_timestamp_ns: u64) -> Result<()> {
        self.pending_source_ts
            .set(Some(rtps_timestamp_from_unix_nanos(source_timestamp_ns)));
        let _clear = PendingSourceTsGuard(self);
        self.write(msg)
    }

    pub(crate) fn write_with_key_hash_and_timestamp(
        &self,
        msg: &T,
        key_hash: Option<[u8; 16]>,
        source_timestamp_ns: u64,
    ) -> Result<()> {
        self.pending_source_ts
            .set(Some(rtps_timestamp_preserving_unix_nanos(
                source_timestamp_ns,
            )));
        let _clear = PendingSourceTsGuard(self);
        self.write_with_key_hash(msg, key_hash)
    }

    /// [`dispose`](Self::dispose) with an application-supplied source
    /// timestamp (DDS v1.4 Sec.2.2.2.4.2.13). See
    /// [`write_w_timestamp`](Self::write_w_timestamp) for the units and
    /// the staging/clearing contract.
    pub fn dispose_w_timestamp(&self, instance: &T, source_timestamp_ns: u64) -> Result<()> {
        self.pending_source_ts
            .set(Some(rtps_timestamp_from_unix_nanos(source_timestamp_ns)));
        let _clear = PendingSourceTsGuard(self);
        self.dispose(instance)
    }

    /// [`unregister_instance`](Self::unregister_instance) with an
    /// application-supplied source timestamp (DDS v1.4 Sec.2.2.2.4.2.8).
    /// See [`write_w_timestamp`](Self::write_w_timestamp) for the units
    /// and the staging/clearing contract.
    pub fn unregister_instance_w_timestamp(
        &self,
        instance: &T,
        source_timestamp_ns: u64,
    ) -> Result<()> {
        self.pending_source_ts
            .set(Some(rtps_timestamp_from_unix_nanos(source_timestamp_ns)));
        let _clear = PendingSourceTsGuard(self);
        self.unregister_instance(instance)
    }

    /// DDS v1.4 Sec.2.2.2.4.2.5: informs the service that the application
    /// will be modifying `instance`, returning a handle usable in
    /// successive `write` / `dispose` calls. Idempotent: called twice for
    /// the same instance, it returns the same handle both times, since the
    /// handle is exactly the instance's KeyHash (RTPS v2.5 Sec.9.6.4.8),
    /// not an allocation this writer tracks.
    ///
    /// Local registration journals no data and sends nothing on the wire.
    /// A finite DEADLINE starts monitoring before the first write;
    /// repeated registration does not renew that period.
    /// This call never waits for history capacity or returns `WouldBlock`
    /// or `ResourceLimitExceeded`: history and resource limits are
    /// consulted at `write`/`dispose` time.
    /// Its explicit use stays what the spec calls it, optional: every
    /// `DataWriter` method also takes `&T` directly and computes the same
    /// KeyHash itself, exactly the `HANDLE_NIL` path the spec describes
    /// for an application that skips this call.
    pub fn register_instance(&self, instance: &T) -> Result<crate::dds::reader::InstanceHandle> {
        if self.serialized_keys && instance.instance_key().is_none() {
            return Err(Error::InvalidState(
                "serialized keyed writer requires instance metadata".into(),
            ));
        }
        let handle = crate::dds::reader::InstanceHandle::new(
            instance
                .instance_key()
                .unwrap_or_else(|| instance.compute_key()),
        );
        if let Some(deadlines) = self.deadlines.as_ref() {
            deadlines.register_instance(handle);
        }
        Ok(handle)
    }

    /// [`register_instance`](Self::register_instance) with an
    /// application-supplied source timestamp (DDS v1.4
    /// Sec.2.2.2.4.2.6), for "the cases where the application desires to
    /// specify the value for the source_timestamp. The source_timestamp
    /// potentially affects the relative order in which readers observe
    /// events from multiple writers" (DESTINATION_ORDER, Sec.2.2.3.17).
    ///
    /// `register_instance` itself emits nothing a reader ever orders by
    /// time (no wire change, no entry in any time-ordered table): the
    /// timestamp has nothing to govern here, and is accepted only for API
    /// symmetry with `write_w_timestamp` and the other `_w_timestamp`
    /// operations, where it does.
    pub fn register_instance_w_timestamp(
        &self,
        instance: &T,
        _source_timestamp_ns: u64,
    ) -> Result<crate::dds::reader::InstanceHandle> {
        self.register_instance(instance)
    }

    fn maybe_send_heartbeat(&self, last_seq: u64) {
        // Update scheduler state so periodic thread knows the latest seq
        if let Some(ref scheduler) = self._heartbeat_scheduler {
            scheduler.state().update_seq(last_seq);
        }

        let Some(ref transport) = self.transport else {
            return;
        };
        let Some(ref hb_tx) = self.heartbeat_tx else {
            return;
        };

        let mut hb_tx_borrow = hb_tx.borrow_mut();

        if Instant::now() < hb_tx_borrow.next_deadline() {
            return;
        }

        // Compute `firstSN` with the VOLATILE floor from scheduler state.
        // For RELIABLE writers the scheduler is always present (see builder.rs
        // spawn site) and owns the shared `first_eligible_seq`. When absent,
        // we fall back to `cache.oldest_seq()` unchanged.
        let first_seq = if let Some(ref cache) = self.history_cache {
            let cache_oldest =
                super::heartbeat_scheduler::advertised_first_seq(cache.oldest_seq(), last_seq);
            if let Some(ref scheduler) = self._heartbeat_scheduler {
                scheduler.state().heartbeat_first_seq(cache_oldest)
            } else {
                cache_oldest
            }
        } else {
            1
        };

        let mut hb = hb_tx_borrow.build_heartbeat(first_seq, last_seq);
        // Read before `send_with_count` below captures `hb.count` by
        // mutable (disjoint, 2021-edition) reference: used only in the
        // no-scheduler branch, where hb_tx's own internal counter already
        // set it and nothing else needs to read it afterward.
        let no_scheduler_count = hb.count;

        // RTPS demands ONE monotonic HEARTBEAT count per writer, ON THE
        // WIRE, not only in the order counts are allocated; readers drop
        // any HB whose count is not above the last seen. When the periodic
        // scheduler thread is running it emits HBs for this same writer, so
        // both emitters MUST draw from the same sequence -- otherwise
        // whichever stream runs ahead silently disarms the other at every
        // receiver. The scheduler's atomic is the shared source; hb_tx's
        // internal counter only serves the schedulerless configuration.
        // `with_next_count` additionally holds this writer's send-serial
        // lock from allocation through the transmit below, blocking (this
        // runs on the application's own write() thread, never the shared
        // `hdds-hb-sender` worker): without it, a paused/slow periodic tick
        // could allocate N, this call allocate and send N+1, and the
        // periodic tick's N reach the wire afterward -- allocation order
        // alone does not bound emission order.
        let mut send_with_count = |count: u32| {
            hb.count = count;
            // Use context-aware HEARTBEAT if available (for RELIABLE user data).
            // This ensures HEARTBEATs are sent with the correct writer entity ID so
            // readers can properly match and respond with ACKNACKs for retransmission.
            let rtps_packet = if let Some(ctx) = self.rtps_endpoint {
                builder::build_heartbeat_packet_with_context(
                    &ctx,
                    hb.first_seq,
                    hb.last_seq,
                    hb.count,
                )
            } else {
                builder::build_heartbeat_packet(hb.first_seq, hb.last_seq, hb.count)
            };
            // A GROUP Publisher's writer's HEARTBEAT carries its GroupInfo for
            // the readers of the spec class; any other writer pays
            // one `Option` test. This thread made every change it took, so it
            // has no pending GSN to hold back.
            let group_packet = match (
                self.publisher.as_deref().filter(|core| core.group_scope),
                self.rtps_endpoint,
                self.history_cache.as_deref(),
            ) {
                (Some(core), Some(ctx), Some(cache)) => {
                    super::heartbeat_scheduler::group_heartbeat_info_of(
                        core,
                        None,
                        cache,
                        hb.first_seq,
                        hb.last_seq,
                    )
                    .map(|info| {
                        builder::build_heartbeat_packet_group(
                            &ctx,
                            hb.first_seq,
                            hb.last_seq,
                            hb.count,
                            info,
                        )
                    })
                    .filter(|packet| !packet.is_empty())
                }
                _ => None,
            };
            // Send HEARTBEAT to each discovered reader's unicast locator.
            // NOTE: Do NOT use send_packet_to_endpoints_classed() -- it patches readerEntityId
            // at byte offset 28, which in a HEARTBEAT is the writerEntityId, not the
            // readerId. That would corrupt the HEARTBEAT.
            super::heartbeat_scheduler::send_heartbeat_to_readers(
                transport,
                self._heartbeat_scheduler.as_ref().map(|s| &**s.state()),
                self.discovery_fsm.as_deref(),
                self.endpoint_registry.as_ref(),
                &self.topic,
                self.rtps_endpoint.map(|ctx| ctx.guid_prefix),
                &rtps_packet,
                group_packet.as_deref(),
                &self.wire_windows,
                false,
            );
        };

        if let Some(ref scheduler) = self._heartbeat_scheduler {
            scheduler.state().with_next_count(send_with_count);
        } else {
            // No scheduler: hb_tx's own internal counter already set
            // hb.count via build_heartbeat above, and there is no other
            // origin of this writer's HEARTBEAT to race.
            send_with_count(no_scheduler_count);
        }

        if let Some(ref metrics) = self.reliable_metrics {
            metrics.increment_heartbeats_sent(1);
        }
    }

    /// Whether the pairing with `reader_guid` resolved to shared memory.
    ///
    /// Reads the verdict the match registry computed exactly once, at
    /// pairing time; it never recomputes anything, and it is only reached
    /// when `shm_selected` already said at least one reader of this writer
    /// is co-located.
    #[cfg(target_os = "linux")]
    fn reader_is_shm(&self, reader_guid: &GUID) -> bool {
        self.shm_leg.is_some()
            && self._match_token.as_ref().is_some_and(|token| {
                matches!(
                    token.transport_selection(reader_guid),
                    Some(crate::transport::shm::TransportSelection::Shm { .. })
                )
            })
    }

    /// The ring sequence this peer starts reading from, or `None` when it has
    /// not proven it is attached to our ring.
    ///
    /// Also creates the segment on first call, so the peer has something to
    /// attach to. Cold relative to the send loop only in the sense that the
    /// creation happens once; the check itself is a scan of a small table and
    /// runs per reader per packet, like the verdict lookup above it.
    #[cfg(target_os = "linux")]
    fn shm_peer_cursor(&self, participant_guid: &GUID) -> Option<u64> {
        self.shm_leg
            .as_ref()
            .and_then(|leg| leg.participant_cursor(&self.topic, participant_guid.as_bytes()))
    }

    /// Push the framed packet into this writer's shared-memory ring.
    /// Returns false when the caller must fall back to UDP for the readers
    /// whose verdict was SHM.
    ///
    /// A segment that cannot be created retires the leg HERE, once: the
    /// `shm_selected` latch is cleared, so the very next packet takes the
    /// plain UDP path with no per-packet retry and no per-reader verdict
    /// lookup, and the participant stops claiming a transport it cannot
    /// use. The transition is logged at error level by `ShmWriterLeg::push`
    /// and counted in `global_metrics().writer_segment_failures()`.
    #[cfg(target_os = "linux")]
    /// Push the packet into the ring once, returning the sequence it landed
    /// on. `None` means no peer can be served from the ring for this packet.
    fn shm_push_packet(&self, packet: &[u8]) -> Option<u64> {
        let leg = self.shm_leg.as_ref()?;
        match leg.push(&self.topic, packet) {
            ShmPushOutcome::Pushed(msg_seq) => Some(msg_seq),
            ShmPushOutcome::Oversize => None,
            ShmPushOutcome::SegmentUnavailable | ShmPushOutcome::LegDisabled => {
                self.shm_selected.store(false, Ordering::Release);
                None
            }
        }
    }

    /// Send a single RTPS packet to discovered endpoints or multicast fallback.
    ///
    /// When `discovery_fsm` is set, filters destinations by QoS compatibility
    /// (partition, reliability, durability, etc.) so data only flows to
    /// participants that have matching readers for this writer's topic.
    ///
    /// # Shared memory
    ///
    /// A reader whose per-peer verdict is `TransportSelection::Shm` is
    /// served from this writer's shared-memory ring instead of a
    /// `send_user_data_unicast` call. Only this leg (small, unfragmented
    /// DATA) is wired: `send_packets_to_endpoints` (DATA_FRAG), the
    /// HEARTBEAT / ACKNACK control plane and every repair path stay on UDP
    /// unchanged, which costs nothing because SHM is confined to
    /// BEST_EFFORT on both sides.
    /// Whether the participant of `prefix` is a reader of the spec GROUP
    /// class (`GroupDialect::Spec`, decided once at its pairing).
    /// Where this writer records a GSN taken and not yet made, for its
    /// periodic HEARTBEAT origin, scheduler-entry or standalone thread
    /// alike (`HeartbeatSchedulerState::pending_gsn`); `None` without one
    /// (never reliable, or missing a transport/cache/endpoint).
    fn pending_gsn_slot(&self) -> Option<&AtomicU64> {
        self._heartbeat_scheduler
            .as_ref()
            .map(|scheduler| &scheduler.state().pending_gsn)
    }

    fn reader_is_spec(&self, prefix: &[u8; 12]) -> bool {
        self.discovery_fsm
            .as_ref()
            .is_some_and(|fsm| fsm.speaks_spec_group(prefix))
    }

    /// Whether the participant of `reader` takes plain DATA from a GROUP
    /// Publisher (`GroupForm::Plain`): one lock-free load, read per reader.
    fn reader_is_plain(&self, reader: &GUID) -> bool {
        self.discovery_fsm
            .as_ref()
            .is_some_and(|fsm| fsm.speaks_plain_group(&reader.prefix))
    }

    /// Send `packet` to the writer's matched readers. A change of a GROUP
    /// Publisher's writer has up to three forms (plain):
    /// `spec_packet` for readers of the spec class, `plain` (no set
    /// PIDs) for readers taking plain DATA, `packet` (today's form) for every
    /// other reader. A shared leg carries one form only: the shared-memory
    /// ring takes the form of the first reader it serves, a reader of the
    /// other class goes by UDP, and a plain reader never uses the ring; the
    /// participant fallback takes the form of each participant, and the
    /// multicast group, whose audience is not known, takes today's form only
    /// when no spec or plain peer is known (`multicasts`).
    pub(super) fn send_packet_to_endpoints_classed(
        &self,
        transport: &UdpTransport,
        packet: &[u8],
        spec_packet: Option<&[u8]>,
        plain: Option<&LazyForm<'_, Vec<u8>>>,
    ) -> std::result::Result<(), std::io::Error> {
        // The multicast fallback reaches whoever listens on the group: not a
        // protected topic's (`multicast_fallback_closed`). Asked only when a
        // fallback is reached, never on the per-reader path.
        let multicast_closed =
            || multicast_fallback_closed(self.discovery_fsm.as_deref(), &self.topic);
        let registry = match self.endpoint_registry {
            Some(ref r) => r,
            None if multicast_closed() || self.wire_windows.is_group() => return Ok(()),
            None => {
                log::debug!("[writer] No endpoint_registry, falling back to data multicast");
                return send_multicast_unless_group(
                    transport,
                    packet,
                    spec_packet,
                    self.discovery_fsm.as_deref(),
                    &self.topic,
                );
            }
        };

        if registry.is_empty() {
            if multicast_closed() || self.wire_windows.is_group() {
                return Ok(());
            }
            log::debug!("[writer] No endpoints in registry, falling back to data multicast");
            return send_multicast_unless_group(
                transport,
                packet,
                spec_packet,
                self.discovery_fsm.as_deref(),
                &self.topic,
            );
        }

        let local_prefix = self.rtps_endpoint.map(|ctx| ctx.guid_prefix);

        // Per-reader routing: find matched readers via discovery FSM, then send
        // to each reader's SEDP-announced unicast locator. This is the correct
        // RTPS behavior -- remote readers may listen on different ports than the
        // participant's SPDP default_unicast (e.g. a reader on an ephemeral
        // port).
        if let Some(ref fsm) = self.discovery_fsm {
            let readers = fsm.reader_routes_for_topic(&self.topic, self.partition_filter());
            let mut delivered = false;
            // ONE relaxed load per packet is the entire cost of the
            // shared-memory leg for a writer with no co-located reader.
            #[cfg(target_os = "linux")]
            let mut shm_possible = self.shm_selected.load(Ordering::Relaxed);
            // The ring is drained by every peer attached to it: a GROUP
            // change goes into it only when the readers it serves are all of
            // one class. A peer of the other class would drain the
            // wrong form and drop its own UDP copy as a duplicate. One pass
            // over the readers, for GROUP changes only.
            #[cfg(target_os = "linux")]
            if shm_possible && spec_packet.is_some() {
                let mut classes = readers
                    .iter()
                    .filter(|r| {
                        local_prefix != Some(r.endpoint_guid.prefix)
                            && self.reader_is_shm(&r.endpoint_guid)
                            && !self.reader_is_plain(&r.endpoint_guid)
                    })
                    .map(|r| self.reader_is_spec(&r.endpoint_guid.prefix));
                if !shm_audience_is_one_class(&mut classes) {
                    shm_possible = false;
                }
            }
            // Resolved at most once per packet. The OUTER `Option` is the
            // memo (`None` = not attempted yet); the INNER one is the answer:
            // `Some(seq)` = the packet is in the ring at that sequence,
            // `None` = the push was refused and every SHM reader falls through
            // to its UDP copy.
            //
            // The sequence is what makes the per-reader decision correct
            // rather than approximate: one push serves several peers, but only
            // those whose published start cursor is at or before it.
            #[cfg(target_os = "linux")]
            let mut shm_pushed: Option<Option<u64>> = None;
            // The class of the form in the ring, once pushed.
            #[cfg(target_os = "linux")]
            let mut shm_class: Option<bool> = None;

            for reader in &readers {
                let classic_window = self.wire_windows.is_group()
                    && fsm.requires_group_window(&reader.endpoint_guid.prefix);
                if classic_window && !self.wire_windows.contains(reader.endpoint_guid) {
                    continue;
                }

                // Skip local readers (same GUID prefix = same participant)
                if let Some(local_pfx) = local_prefix {
                    if reader.participant_guid.as_bytes()[..12] == local_pfx {
                        continue;
                    }
                }
                // QoS compatibility check (partition, etc.)
                if !reader.compatible {
                    continue;
                }

                // Shared-memory leg. The verdict was resolved once, at
                // pairing, by the match registry; this is an O(1) read of
                // it. The packet goes into the ring ONCE no matter how many
                // readers selected SHM -- they all attach to this writer's
                // single ring and each keeps its own cursor -- so the
                // readerEntityId is deliberately NOT patched here, exactly
                // as on the multicast leg, and the receiving Router demuxes
                // by writer GUID and topic as it always does.
                // The form of a GROUP change for this reader (plain for a
                // reader taking plain DATA; today's forms otherwise).
                let form = super::nack::reader_form(
                    self.discovery_fsm.as_deref(),
                    Some(reader.endpoint_guid.as_bytes()),
                )
                .for_change(spec_packet.is_some() || plain.is_some());
                let plain_reader = form == super::nack::GroupForm::Plain;
                let spec_reader = spec_packet.is_some() && form == super::nack::GroupForm::Spec;
                let packet: &[u8] = if plain_reader {
                    // A plain reader is never sent the legacy form: an empty
                    // form (not built) skips it.
                    match plain.map(|form| form.get()) {
                        Some(bytes) if !bytes.is_empty() => bytes.as_slice(),
                        _ => continue,
                    }
                } else {
                    match spec_packet {
                        Some(spec) if spec_reader => spec,
                        _ => packet,
                    }
                };
                #[cfg(target_os = "linux")]
                if shm_possible
                    && !plain_reader
                    && shm_serves(shm_class, spec_reader)
                    && self.reader_is_shm(&reader.endpoint_guid)
                {
                    // The verdict at pairing says this peer COULD use shared
                    // memory. It is not proof that it does, and the difference
                    // is the whole point: a push into our own ring succeeds
                    // whether or not anyone is draining it, and BEST_EFFORT has
                    // no acknowledgement to reveal the mistake. So the UDP leg
                    // is dropped only for a peer that has claimed an entry in
                    // the segment's presence table, which it can only do by
                    // actually opening the segment.
                    //
                    // An unproven peer falls through to UDP below. That costs
                    // this peer's share of the shared-memory win until it
                    // attaches, and costs nothing at all if it never does --
                    // whereas the reverse mistake costs it every sample,
                    // permanently and silently.
                    if let Some(peer_cursor) = self.shm_peer_cursor(&reader.participant_guid) {
                        let pushed =
                            *shm_pushed.get_or_insert_with(|| self.shm_push_packet(packet));
                        shm_class = Some(spec_reader);
                        // The cursor comparison is the whole handover. The push
                        // is memoised at the FIRST peer we serve, so a peer
                        // evaluated later in this loop may have attached in
                        // between and started reading PAST this packet's slot.
                        // Crediting it then would lose the packet on both legs
                        // at once, with no acknowledgement on BEST_EFFORT to
                        // reveal it; refusing a peer whose cursor is at or
                        // before the packet would duplicate it instead. The
                        // published cursor settles it exactly.
                        if let Some(msg_seq) = pushed {
                            // Two conditions, and the second is the liveness
                            // one. A peer more than a ring behind cannot be
                            // served from the ring at all: the slot its cursor
                            // points at was overwritten long ago. A LIVE reader
                            // never sits there, because it refreshes its cursor
                            // every drain sweep; a claim that stopped moving
                            // belongs to a peer that was killed, whose pid was
                            // recycled into a byte-identical GUID, or that
                            // never existed because something else wrote the
                            // entry. Without this the writer keeps posting into
                            // a ring nobody reads and that peer is blackholed
                            // for the life of the pairing.
                            let lag = msg_seq.saturating_sub(peer_cursor);
                            if peer_cursor <= msg_seq
                                && (lag as usize) < crate::transport::shm::DEFAULT_RING_CAPACITY
                            {
                                delivered = true;
                                continue;
                            }
                            if peer_cursor <= msg_seq {
                                crate::transport::shm::global_metrics().inc_peer_cursor_stale();
                            }
                        }
                        // Either the push was refused (oversized packet, or no
                        // segment), or this peer started reading after this
                        // packet. Both take the ordinary UDP leg below.
                    }
                }

                // Look up reader's SEDP locator, fall back to participant's SPDP locator.
                // EndpointInfo stores participant_guid with entity_id=[0,0,0,0], but
                // the registry keys use RTPS_ENTITYID_PARTICIPANT=[0,0,1,0xC1].
                let mut pguid_bytes = [0u8; 16];
                pguid_bytes[..12].copy_from_slice(&reader.participant_guid.as_bytes()[..12]);
                pguid_bytes[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
                let participant_key = GUID::from_bytes(pguid_bytes);

                let dest = registry
                    .get_reader_locator(&reader.endpoint_guid)
                    .or_else(|| registry.get(&participant_key));

                if let Some(endpoint) = dest {
                    // Apply the per-reader wire transforms (readerEntityId
                    // patch, zzdds encap downgrade, InterCOM HEADER_EXTENSION) --
                    // see `finalize_for_reader` doc. ONE vendor lookup, reused for
                    // both per-vendor branches inside it (on_nack and replay_to
                    // share the same resolve-once-then-apply shape via
                    // `ReaderWireProfile`).
                    let profile = ReaderWireProfile {
                        entity_id: reader.endpoint_guid.entity_id,
                        vendor: fsm.vendor_id_for_participant(&participant_key),
                    };
                    let patched = finalize_for_reader(packet.to_vec(), profile, false);
                    log::debug!(
                        "[writer] Sending unicast USER DATA to {} (reader={}, eid={:02x?})",
                        endpoint,
                        reader.endpoint_guid,
                        reader.endpoint_guid.entity_id
                    );
                    match self.wire_windows.send_classed(
                        transport,
                        &patched,
                        &endpoint,
                        reader.endpoint_guid,
                        classic_window,
                    ) {
                        Ok(_) => {
                            delivered = true;
                        }
                        Err(_e) => {
                            log::debug!("[writer] Failed to send unicast to {}: {}", endpoint, _e);
                        }
                    }
                }
            }

            if delivered || !readers.is_empty() {
                return Ok(());
            }
            // No readers found in FSM -- fall through to participant-level routing
        }

        // Fallback: participant-level routing (no discovery FSM, or no readers yet).
        // Sends to each participant's SPDP default_unicast_locator.
        let local_guid = local_prefix.map(|pfx| GUID::new(pfx, RTPS_ENTITYID_PARTICIPANT));
        let allowed_participants = self.compute_allowed_participants();
        let mut delivered = false;

        for (guid, endpoint) in registry.entries() {
            if Some(guid) == local_guid {
                continue;
            }
            if let Some(ref allowed) = allowed_participants {
                if !allowed.contains(&guid) {
                    continue;
                }
            }
            // The admission the per-reader list applies, for a participant
            // whose readers are not known: a participant the security plugins
            // do not admit on this topic gets nothing (DDS Security v1.1
            // Sec.8.8.7.1, 9.4.3). This fallback must not send to every
            // participant's default locator, unauthenticated ones included.
            if self.wire_windows.is_group()
                && self
                    .discovery_fsm
                    .as_ref()
                    .is_some_and(|fsm| fsm.requires_group_window(&guid.prefix))
            {
                continue;
            }
            if !fallback_admits(self.discovery_fsm.as_deref(), &guid, &self.topic) {
                continue;
            }
            log::debug!(
                "[writer] Sending unicast USER DATA to endpoint={} guid={} (participant fallback)",
                endpoint,
                guid
            );
            // A participant's GROUP class is known even when its readers are
            // not yet: its form (plain included).
            let form: &[u8] = match (plain, spec_packet, self.discovery_fsm.as_deref()) {
                (Some(plain), _, Some(fsm)) if fsm.speaks_plain_group(&guid.prefix) => {
                    let bytes = plain.get();
                    if bytes.is_empty() {
                        continue;
                    }
                    bytes.as_slice()
                }
                (_, Some(spec), Some(fsm)) if fsm.speaks_spec_group(&guid.prefix) => spec,
                _ => packet,
            };
            if self
                .wire_windows
                .send(transport, form, &endpoint, Some(guid))
                .is_ok()
            {
                delivered = true;
            }
        }

        if delivered
            || allowed_participants.is_some()
            || multicast_closed()
            || self.wire_windows.is_group()
        {
            Ok(())
        } else {
            log::debug!("[writer] No remote endpoints (self-only); falling back to data multicast");
            send_multicast_unless_group(
                transport,
                packet,
                spec_packet,
                self.discovery_fsm.as_deref(),
                &self.topic,
            )
        }
    }

    /// The writer QoS a reader's PARTITION is checked against on the send
    /// paths, `None` for the default partition, which matches every reader.
    #[inline]
    fn partition_filter(&self) -> Option<&QoS> {
        (!self.qos.partition.is_default()).then_some(&self.qos)
    }

    /// Compute set of participant GUIDs that have QoS-compatible readers.
    ///
    /// Returns `None` if no filtering is needed (no discovery FSM, or no QoS
    /// policies that require filtering). Returns `Some(set)` when the writer
    /// has partition QoS or other policies that restrict which readers match.
    fn compute_allowed_participants(&self) -> Option<Vec<GUID>> {
        let fsm = self.discovery_fsm.as_ref()?;

        // Only filter if the writer has non-default partition QoS.
        // Default partition (empty) matches everything, so no filtering needed.
        // This keeps the common case (no partitions) zero-cost.
        if self.qos.partition.is_default() {
            return None;
        }

        let readers = fsm.find_readers_for_topic(&self.topic);

        // When the writer has non-default partition and no readers are discovered yet,
        // return empty set (send to nobody). This is correct DDS behavior: a writer
        // with partition QoS only communicates with readers whose partition matches.
        // If no readers are known, there are no matches.
        if readers.is_empty() {
            return Some(Vec::new());
        }

        let mut allowed = Vec::new();
        for reader in &readers {
            if crate::core::discovery::Matcher::is_compatible(&reader.qos, &self.qos) {
                // EndpointInfo stores participant_guid with zeroed entity_id,
                // but endpoint_registry keys use RTPS_ENTITYID_PARTICIPANT.
                // Reconstruct the proper participant GUID for matching.
                let mut pguid_bytes = [0u8; 16];
                pguid_bytes[..12].copy_from_slice(&reader.participant_guid.as_bytes()[..12]);
                pguid_bytes[12..16]
                    .copy_from_slice(&crate::protocol::constants::RTPS_ENTITYID_PARTICIPANT);
                allowed.push(GUID::from_bytes(pguid_bytes));
            }
        }

        Some(allowed)
    }

    /// Resolve the large-payload route from the matched remote readers'
    /// RTPS vendor ids (cold path: registry reads only, once per large
    /// sample, BEFORE the fragments are built).
    ///
    /// The OpenDDS profile (large fragments to the reader's default
    /// user-data multicast group, see `frag_route` module docs) activates
    /// only when EVERY matched remote reader belongs to an OpenDDS
    /// participant -- any other peer mix keeps today's default route, so
    /// self and all other vendor pairings never see it.
    fn resolve_frag_route(&self, transport: &UdpTransport) {
        let Some(ref fsm) = self.discovery_fsm else {
            self.frag_route.reset_default();
            return;
        };
        let local_prefix = self.rtps_endpoint.map(|ctx| ctx.guid_prefix);
        let readers = fsm.find_readers_for_topic(&self.topic);

        let mut remote = 0usize;
        let mut opendds = 0usize;
        for reader in &readers {
            if let Some(local_pfx) = local_prefix {
                if reader.participant_guid.as_bytes()[..12] == local_pfx {
                    continue;
                }
            }
            remote += 1;

            let mut pguid_bytes = [0u8; 16];
            pguid_bytes[..12].copy_from_slice(&reader.participant_guid.as_bytes()[..12]);
            pguid_bytes[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
            if fsm.vendor_id_for_participant(&GUID::from_bytes(pguid_bytes))
                == Some(crate::core::rtps_constants::OPENDDS_VENDOR_ID_U16)
            {
                opendds += 1;
            }
        }

        if remote > 0 && remote == opendds {
            self.frag_route.set_opendds(transport.data_multicast_port());
        } else {
            self.frag_route.reset_default();
        }
    }

    /// Send multiple RTPS packets (DATA_FRAG) to discovered endpoints or multicast fallback.
    pub(super) fn send_packets_to_endpoints(
        &self,
        transport: &UdpTransport,
        packets: &[Vec<u8>],
        spec_packets: Option<&[Vec<u8>]>,
        plain: Option<&LazyForm<'_, Vec<Vec<u8>>>>,
    ) -> std::result::Result<(), std::io::Error> {
        let send_multicast = |pkts: &[Vec<u8>]| -> std::result::Result<(), std::io::Error> {
            if self.wire_windows.is_group() {
                return Ok(());
            }
            for packet in pkts {
                send_multicast_unless_group(
                    transport,
                    packet,
                    spec_packets.map(|_| &[][..]),
                    self.discovery_fsm.as_deref(),
                    &self.topic,
                )?;
            }
            Ok(())
        };

        let multicast_closed =
            || multicast_fallback_closed(self.discovery_fsm.as_deref(), &self.topic);
        let registry = match self.endpoint_registry {
            Some(ref r) => r,
            None if multicast_closed() || self.wire_windows.is_group() => return Ok(()),
            None => {
                log::debug!(
                    "[writer] No endpoint_registry, falling back to multicast for {} fragments",
                    packets.len()
                );
                return send_multicast(packets);
            }
        };

        if registry.is_empty() {
            if multicast_closed() || self.wire_windows.is_group() {
                return Ok(());
            }
            log::debug!(
                "[writer] No endpoints in registry, falling back to multicast for {} fragments",
                packets.len()
            );
            return send_multicast(packets);
        }

        let local_prefix = self.rtps_endpoint.map(|ctx| ctx.guid_prefix);

        // Dialect-gated large-payload route (see frag_route module docs):
        // when active, the whole burst goes ONCE to the peer's default
        // user-data multicast group instead of per-reader unicast. The
        // readerEntityId stays ENTITYID_UNKNOWN (standard for multicast).
        // On send failure fall through to the normal per-reader routing.
        // Not to a group anyone may listen on, for a protected topic.
        if let Some(mdest) = self
            .frag_route
            .multicast_dest()
            .filter(|_| !multicast_closed() && !self.wire_windows.is_group())
        {
            let mut all_sent = true;
            for packet in packets {
                let mut patched = packet.to_vec();
                if patched.len() >= builder::READER_ENTITY_ID_OFFSET + 4 {
                    patched[builder::READER_ENTITY_ID_OFFSET..builder::READER_ENTITY_ID_OFFSET + 4]
                        .copy_from_slice(&[0u8; 4]);
                }
                if transport
                    .send_user_data_multicast_to(&patched, &mdest)
                    .is_err()
                {
                    all_sent = false;
                }
            }
            if all_sent {
                log::debug!(
                    "[writer] Sent {} DATA_FRAG to large-payload multicast {}",
                    packets.len(),
                    mdest
                );
                return Ok(());
            }
        }

        // Per-reader routing (same logic as send_packet_to_endpoints)
        if let Some(ref fsm) = self.discovery_fsm {
            let readers = fsm.reader_routes_for_topic(&self.topic, self.partition_filter());
            let mut delivered = false;

            for reader in &readers {
                let classic_window = self.wire_windows.is_group()
                    && fsm.requires_group_window(&reader.endpoint_guid.prefix);
                if classic_window && !self.wire_windows.contains(reader.endpoint_guid) {
                    continue;
                }

                if let Some(local_pfx) = local_prefix {
                    if reader.participant_guid.as_bytes()[..12] == local_pfx {
                        continue;
                    }
                }
                if !reader.compatible {
                    continue;
                }

                let mut pguid_bytes = [0u8; 16];
                pguid_bytes[..12].copy_from_slice(&reader.participant_guid.as_bytes()[..12]);
                pguid_bytes[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
                let participant_key = GUID::from_bytes(pguid_bytes);

                let dest = registry
                    .get_reader_locator(&reader.endpoint_guid)
                    .or_else(|| registry.get(&participant_key));

                if let Some(endpoint) = dest {
                    log::debug!(
                        "[writer] Sending {} DATA_FRAG unicast to {} (reader={})",
                        packets.len(),
                        endpoint,
                        reader.endpoint_guid
                    );
                    let profile = ReaderWireProfile {
                        entity_id: reader.endpoint_guid.entity_id,
                        vendor: fsm.vendor_id_for_participant(&participant_key),
                    };
                    // A change of a GROUP Publisher's writer has up to three
                    // forms (plain): the plain form for a reader taking
                    // plain DATA, the spec form for a reader of the spec class.
                    let packets: &[Vec<u8>] = match (plain, spec_packets) {
                        (Some(plain), _) if self.reader_is_plain(&reader.endpoint_guid) => {
                            let fragments = plain.get();
                            if fragments.is_empty() {
                                continue;
                            }
                            fragments.as_slice()
                        }
                        (_, Some(spec)) if self.reader_is_spec(&reader.endpoint_guid.prefix) => {
                            spec
                        }
                        _ => packets,
                    };
                    let mut all_sent = true;
                    for (pkt_idx, packet) in packets.iter().enumerate() {
                        // Entity id patch only (see `finalize_for_reader`'s
                        // `fragmented` doc): this is the live DATA_FRAG leg
                        // that the `fragmented = true` boundary was
                        // written to match byte-for-byte.
                        let patched = finalize_for_reader(packet.to_vec(), profile, true);
                        // Pace long fragment bursts (see FRAG_BURST_* docs).
                        // A back-to-back line-rate burst of ~100 datagrams
                        // overflows a default-rcvbuf receiver mid-burst (the
                        // per-skb truesize accounting eats ~2-4x the payload),
                        // punching 30-60-fragment holes into every sample and
                        // shifting the whole exchange onto NACK_FRAG recovery,
                        // which then converges below the publish rate.
                        if pkt_idx > 0
                            && packets.len() > FRAG_BURST_PACING_THRESHOLD
                            && pkt_idx % FRAG_BURST_CHUNK == 0
                        {
                            std::thread::sleep(std::time::Duration::from_micros(
                                FRAG_BURST_PAUSE_US,
                            ));
                        }
                        if self
                            .wire_windows
                            .send_classed(
                                transport,
                                &patched,
                                &endpoint,
                                reader.endpoint_guid,
                                classic_window,
                            )
                            .is_err()
                        {
                            all_sent = false;
                        }
                    }
                    if all_sent {
                        delivered = true;
                    }
                }
            }

            if delivered || !readers.is_empty() {
                return Ok(());
            }
        }

        // Fallback: participant-level routing
        let local_guid = local_prefix.map(|pfx| GUID::new(pfx, RTPS_ENTITYID_PARTICIPANT));
        let allowed_participants = self.compute_allowed_participants();
        let mut delivered = false;

        for (guid, endpoint) in registry.entries() {
            if Some(guid) == local_guid {
                continue;
            }
            if let Some(ref allowed) = allowed_participants {
                if !allowed.contains(&guid) {
                    continue;
                }
            }
            // As on the unfragmented leg (`fallback_admits`).
            if self.wire_windows.is_group()
                && self
                    .discovery_fsm
                    .as_ref()
                    .is_some_and(|fsm| fsm.requires_group_window(&guid.prefix))
            {
                continue;
            }
            if !fallback_admits(self.discovery_fsm.as_deref(), &guid, &self.topic) {
                continue;
            }
            // A participant's GROUP class is known even when its readers are
            // not yet: its form.
            let form: &[Vec<u8>] = match (plain, spec_packets, self.discovery_fsm.as_deref()) {
                (Some(plain), _, Some(fsm)) if fsm.speaks_plain_group(&guid.prefix) => {
                    let fragments = plain.get();
                    if fragments.is_empty() {
                        continue;
                    }
                    fragments.as_slice()
                }
                (_, Some(spec), Some(fsm)) if fsm.speaks_spec_group(&guid.prefix) => spec,
                _ => packets,
            };
            let mut all_sent = true;
            for packet in form {
                if self
                    .wire_windows
                    .send(transport, packet, &endpoint, Some(guid))
                    .is_err()
                {
                    all_sent = false;
                }
            }
            if all_sent {
                delivered = true;
            }
        }

        if delivered
            || allowed_participants.is_some()
            || multicast_closed()
            || self.wire_windows.is_group()
        {
            Ok(())
        } else {
            log::debug!(
                "[writer] No remote endpoints; falling back to multicast for {} fragments",
                packets.len()
            );
            send_multicast(packets)
        }
    }
}

/// How long deleting a RELIABLE DataWriter waits for its readers to
/// acknowledge the lifecycle change the deletion emits (see the `Drop`
/// impl below). Three default heartbeat periods: a change lost on the way
/// is announced by the next periodic HEARTBEAT (RTPS v2.5 Sec.8.4.2.2.3),
/// repaired on the reader's ACKNACK, and acknowledged on the one after
/// that. Bounded like every other reliable wait; the acknowledgement or
/// the reader's own departure ends it early.
pub(super) const DROP_LIFECYCLE_ACK_GRACE: std::time::Duration =
    std::time::Duration::from_millis(3 * super::heartbeat_scheduler::DEFAULT_HEARTBEAT_PERIOD_MS);

/// Auto-unregister all written instances when a DataWriter is dropped, then
/// retire the writer from SEDP.
///
/// DDS v1.4 Sec.2.2.2.4.1.6 (delete_datawriter): when a DataWriter is
/// deleted, all instances it has written are automatically unregistered,
/// and WRITER_DATA_LIFECYCLE (Sec.2.2.3.21) decides whether they are also
/// disposed. Readers, remote and local, see them NOT_ALIVE_DISPOSED with
/// `autodispose_unregistered_instances` TRUE (the default) and
/// NOT_ALIVE_NO_WRITERS with it FALSE. RTPS v2.5 Sec.8.5.4.4: its
/// data-object leaves the history of the SEDP publications writer.
impl<T: DDS> Drop for DataWriter<T> {
    fn drop(&mut self) {
        if let Some(deadlines) = self.deadlines.as_ref() {
            deadlines.close();
        }
        // Taken, not copied: from here the writer holds nothing, which is
        // what a reader of this process must hear when it asks while these
        // unregisters reach it (DDS v1.4 Sec.2.2.3.23.3).
        let instances = std::mem::take(
            &mut *self
                .written_instances
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        );
        if !instances.is_empty() {
            let disposed = self
                .disposed_instances
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            // Deleting a DataWriter unregisters all its instances, and
            // WRITER_DATA_LIFECYCLE decides whether that unregister also
            // disposes them (DDS v1.4 Sec.2.2.2.4.1.6, Sec.2.2.3.21): the
            // same rule, and the same helper, as `unregister_instance`.
            let status_info = crate::protocol::builder::StatusInfoKind::for_unregister(
                self.qos
                    .writer_data_lifecycle
                    .autodispose_unregistered_instances,
            );
            let mut unregistered = 0usize;
            for (key_hash, (version, key_bytes)) in &instances {
                // Skip instances the app explicitly disposed without a
                // subsequent write, whatever the policy. Without autodispose,
                // an UNREGISTER after DISPOSE flips a subscriber that applies
                // the latest lifecycle change from DISPOSED to NO_WRITERS,
                // losing the disposal the application asked for. With it, the
                // combined DISPOSED|UNREGISTERED would dispose the instance a
                // second time: no reader changes state, but a reader that
                // reports every dispose sees a duplicate. The SEDP dispose
                // below still retires the writer from every reader.
                if disposed.contains(key_hash) {
                    continue;
                }
                let _ = self.send_key_lifecycle_change(key_hash, key_bytes, *version, status_info);
                unregistered += 1;
            }
            if unregistered > 0 {
                log::debug!(
                    "[writer] Drop: auto-unregistered {} instance(s) for topic '{}' as {:?}",
                    unregistered,
                    self.topic,
                    status_info
                );
            }
        }

        // RTPS v2.5 Sec.8.4.2.2.3: a RELIABLE writer keeps a change until
        // every matched reader has acknowledged it, and a lifecycle change
        // cannot be repaired once the writer is gone -- its NACK handlers
        // and its HEARTBEATs go away with it. Only the ACKNACK proves the
        // reader APPLIED the change: user data and SEDP travel on different
        // sockets, so a reader can process this writer's SEDP dispose first
        // and then drop the lifecycle change of a writer it no longer
        // knows. Waiting here, before the retirement below, closes that
        // ordering window: the delete does not announce the departure until
        // the reader has the change.
        //
        // The wait is owed once this writer has emitted any lifecycle
        // change, whoever emitted it: an application's `dispose` or
        // `unregister_instance` just before the delete leaves no instance
        // for the loop above to notice, and the loop skips an instance it
        // already disposed, yet that change is exactly as unrecoverable once
        // the departure is announced. A writer that never emitted one owes
        // nothing and returns at once.
        let lifecycle_sn = self.last_lifecycle_sn.load(Ordering::Acquire);
        if lifecycle_sn != 0
            && self
                .wait_for_acknowledgments(DROP_LIFECYCLE_ACK_GRACE)
                .is_err()
        {
            // Not silent: the departure is announced anyway, and a reader
            // that has not applied the change by now is the one case where
            // the instances stay NOT_ALIVE_NO_WRITERS instead of the
            // disposal the application asked for.
            log::debug!(
                "[writer] Drop: no acknowledgement for the final \
                 lifecycle change of topic '{}' within {:?}; \
                 announcing the departure",
                self.topic,
                DROP_LIFECYCLE_ACK_GRACE
            );
        }
        // Vendor zone: a reader that loses an acknowledged change when the
        // writer departs before its application reads it gets a bounded
        // linger here, still announced, heartbeats and repairs running
        // (`protocol::dialect::retirement`). Zero, and no wait, unless such
        // a reader is matched.
        if lifecycle_sn != 0 {
            let linger = self.lifecycle_retirement_linger();
            if !linger.is_zero() {
                std::thread::sleep(linger);
            }
        }

        // Retire this writer's data-plane key: the distribution sweep stops
        // announcing it on its next cycle. Deliberately AFTER the
        // auto-unregister loop and its acknowledgement wait:
        // `send_key_lifecycle_change` seals its K-payload under this key,
        // and retiring the key first would turn every auto-unregister into a
        // silent refusal (Drop discards the Result). Runs whether or not
        // instances were written -- key hygiene does not depend on that.
        #[cfg(feature = "security")]
        if let (Some(suite), Some(ctx)) = (self.security.as_ref(), self.rtps_endpoint) {
            let writer_guid = GUID::new(ctx.guid_prefix, ctx.writer_entity_id);
            suite.data_keys.remove_writer(&writer_guid);
        }

        // The periodic HEARTBEATs end before the dispose, for the same
        // reason: a reader that unmatched the writer on its dispose must not
        // hear from it again. For a standalone writer (`HeartbeatPeriodic::
        // Standalone`), dropping the handle signals its thread and joins it,
        // so none is in flight once this returns. For a writer scheduled on
        // its participant (`HeartbeatPeriodic::Participant`), dropping the
        // watch handle stops any FUTURE fire (no new HEARTBEAT is ever
        // scheduled for it again); one already handed to the scheduler's
        // notice thread before this call can still land on the wire a
        // moment later, same as a LIVELINESS_LOST notice can -- the
        // scheduler thread itself is never blocked waiting for it. Left to
        // the field drops, it ran until after the dispose.
        drop(self._heartbeat_scheduler.take());
        // Its retransmissions end there too: a reader still asking (its
        // ACKNACK crossed the dispose) is answered by nothing, and the
        // registry no longer keeps the handlers, nor the history they hold.
        drop(self.nack_handlers.take());

        // Last, the SEDP dispose of this writer. Deliberately AFTER the
        // auto-unregister loop and its acknowledgement: a reader that learns
        // of the writer's deletion unmatches it, and an unregister arriving
        // after that comes from a writer the reader no longer knows.
        drop(self.sedp_retirement.take());

        // A deleted writer's history keeps no other writer's end of set.
        if let Some(cache) = self.history_cache.as_ref() {
            cache.leave_group_retention();
        }
    }
}

// ---------------------------------------------------------------------------
//  DDS-Security: the fail-closed contract of the write path
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "security"))]
mod security_tests;

// ---------------------------------------------------------------------------
//  Shared-memory leg: nothing about a fallback may be silent
// ---------------------------------------------------------------------------

#[cfg(all(test, target_os = "linux"))]
mod shm_leg_tests {
    use super::ShmPushOutcome;
    use super::ShmWriterLeg;
    use crate::core::discovery::GUID;
    use crate::transport::shm::{global_metrics, SLOT_PAYLOAD_SIZE};

    /// FORCE the oversize path and assert it is COUNTED, not silent.
    ///
    /// The slot is sized so that every packet the unfragmented DATA leg can
    /// produce fits (proved by
    /// `transport::shm::policy::tests::slot_holds_every_unfragmented_data_packet`),
    /// so this branch should be unreachable in normal operation. That is
    /// precisely why it must be observable if it ever runs: an operator
    /// reading `global_metrics().oversize_refused()` learns that the slot
    /// budget has been outgrown, instead of watching shared memory quietly
    /// stop being used. The same call also logs at error level.
    #[test]
    fn an_oversized_packet_is_refused_loudly_and_counted() {
        let leg = ShmWriterLeg::new(
            77,
            GUID::from_bytes([
                0x01, 0x1A, 0x77, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02,
            ]),
        );
        let before = global_metrics().oversize_refused();
        let too_big = vec![0xAB; SLOT_PAYLOAD_SIZE + 1];

        let outcome = leg.push("ShmOversizeProbe", &too_big);

        assert_eq!(
            outcome,
            ShmPushOutcome::Oversize,
            "a packet larger than a slot must be refused, not truncated or pushed"
        );
        assert_eq!(
            global_metrics().oversize_refused(),
            before + 1,
            "the refusal must be counted: a fallback nobody can count is \
             indistinguishable from a feature that works"
        );
        // And the refusal must not have created a segment: the leg is still
        // usable for the next, correctly sized packet.
        let ok = leg.push("ShmOversizeProbe", &[0xAB; 64]);
        assert!(
            matches!(ok, ShmPushOutcome::Pushed(_)),
            "one oversized packet must not disable the leg, got {ok:?}"
        );
    }

    /// A segment that cannot be created RETIRES the leg once, loudly, rather
    /// than being retried on every packet -- the difference between "this
    /// writer told you it moved back to UDP" and "this writer claims shared
    /// memory forever and never uses it".
    ///
    /// Forced with a topic name long enough that the derived notification
    /// segment name blows the POSIX 255-byte limit, which is the one
    /// creation failure reachable without root or a full `/dev/shm`.
    #[test]
    fn a_segment_that_cannot_be_created_retires_the_leg_and_is_counted() {
        let leg = ShmWriterLeg::new(
            78,
            GUID::from_bytes([
                0x01, 0x1A, 0x78, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02,
            ]),
        );
        let unusable_topic = "T".repeat(300);
        let before = global_metrics().writer_segment_failures();

        assert_eq!(
            leg.push(&unusable_topic, &[0xAB; 64]),
            ShmPushOutcome::SegmentUnavailable,
            "a segment that cannot be created must be reported, not papered over"
        );
        assert_eq!(
            global_metrics().writer_segment_failures(),
            before + 1,
            "giving up on shared memory must be counted"
        );

        assert_eq!(
            leg.push(&unusable_topic, &[0xAB; 64]),
            ShmPushOutcome::LegDisabled,
            "the leg must stay retired rather than retrying shm_open per packet"
        );
        assert_eq!(
            global_metrics().writer_segment_failures(),
            before + 1,
            "retirement is counted ONCE per writer, not once per packet"
        );
    }
}

#[cfg(test)]
mod sequence_number_tests {
    use super::take_sequence_number_for;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Another producer (a coherent-set close on the publisher's thread)
    /// takes the number while the change is being built: the change is built
    /// again with the next number instead of going out with a duplicate.
    #[test]
    fn a_number_taken_meanwhile_is_not_reused() {
        let next_seq = AtomicU64::new(7);
        let mut builds = Vec::new();
        let taken = take_sequence_number_for(&next_seq, |seq| {
            builds.push(seq);
            if builds.len() == 1 {
                // The other producer's fetch_add, between our peek and take.
                next_seq.fetch_add(1, Ordering::AcqRel);
            }
            vec![seq as u8]
        });
        assert_eq!(taken, Some((8, vec![8])));
        assert_eq!(builds, vec![7, 8], "rebuilt with the next number");
        assert_eq!(next_seq.load(Ordering::Acquire), 9);
    }

    #[test]
    fn a_refused_build_takes_no_number() {
        let next_seq = AtomicU64::new(7);
        assert_eq!(take_sequence_number_for(&next_seq, |_| Vec::new()), None);
        assert_eq!(next_seq.load(Ordering::Acquire), 7);
    }
}

#[cfg(test)]
mod presentation_commit_cost_tests {
    use super::*;
    use std::time::Duration;

    #[derive(Debug, Clone, crate::DDS)]
    struct Value {
        value: i32,
    }

    #[test]
    fn non_group_coherent_commits_do_not_wait_for_group_order() {
        for scope in [
            crate::dds::qos::PresentationAccessScope::Instance,
            crate::dds::qos::PresentationAccessScope::Topic,
        ] {
            let participant = crate::Participant::builder(&format!("commit-scope-{scope:?}"))
                .domain_id(0)
                .with_transport(crate::TransportMode::IntraProcess)
                .build()
                .unwrap();
            let qos = QoS::reliable()
                .presentation(crate::dds::qos::Presentation::new(scope, true, false));
            let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
            let topic = participant.topic::<Value>("commit-scope-value").unwrap();
            let writer = topic
                .writer()
                .qos(qos)
                .publisher(&publisher)
                .build()
                .unwrap();
            let merger = writer.merger();
            let (sent, received) = std::sync::mpsc::channel();
            let (thread, independent) = merger.with_pending_orders_locked_for_test(|| {
                let thread = std::thread::spawn(move || {
                    writer.record_write_commit::<ControlledWrite>(1, None);
                    let _ = sent.send(());
                });
                (
                    thread,
                    received.recv_timeout(Duration::from_secs(1)).is_ok(),
                )
            });
            // Always release the unrelated registry before joining, including
            // on failure, so a violated cost contract cannot hang the harness.
            thread.join().unwrap();
            assert!(
                independent,
                "{scope:?} commit waited for the GROUP order registry"
            );
        }
    }
}

#[cfg(test)]
mod intra_drop_counter_tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
    struct Probe {
        x: i32,
    }

    /// A sequence number beyond 32 bits cannot be carried by an intra-process
    /// ring entry: the delivery is abandoned and the writer's own drop counter
    /// (`WriterStats::drops`) is raised, beside the telemetry drop.
    #[test]
    fn an_intra_process_sequence_beyond_32_bits_is_a_writer_drop() {
        let drops = core::cell::Cell::new(0u64);
        let payload = [1u8, 2, 3];
        let result = DataWriter::<Probe>::prepare_intra_process_entry(
            &payload,
            payload.len(),
            u32::MAX as u64 + 1,
            0,
            None,
            crate::dds::CdrVersion::Xcdr2,
            None,
            &drops,
        );
        assert!(matches!(result, Err(Error::Unsupported)));
        assert_eq!(drops.get(), 1);
    }
}
