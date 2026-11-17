// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! History cache for writer-side message retransmission
//!
//! Thread-safe ring buffer that stores recently written messages for retransmission.
//! HISTORY and RESOURCE_LIMITS are enforced PER INSTANCE (DDS 1.4 2.2.3.18,
//! 2.2.3.19): KEEP_LAST evicts the oldest change of the same instance, and
//! `max_samples` evicts only from an instance that keeps at least one change;
//! KEEP_ALL refuses once a limit is reached.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

use crate::core::rt::slabpool::{Claim, SlabHandle, SlabPool};
use crate::qos::{History, ResourceLimits};
use crate::telemetry::metrics::current_time_ns;
use crate::Error;

/// Special value meaning "no limit" for DurabilityService limits.
/// Corresponds to DDS LENGTH_UNLIMITED (-1 as i32).
pub const LENGTH_UNLIMITED: usize = usize::MAX;

/// Logical kind of a cached RTPS change.
///
/// Distinguishes ordinary user DATA samples from coherent-set close
/// markers (ECS) so a NACK-triggered repair can rebuild the change with
/// the same logical meaning as the original live emission (RTPS v2.5
/// SS8.7.5).
///
/// `#[repr(u8)]`: pins the discriminant to one byte so `ChangeMetadata`'s
/// layout (and the `size_of` guard below) is not at the mercy of the
/// default enum representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChangeKind {
    /// Ordinary user DATA sample.
    UserData = 0,
    /// Coherent-set close marker (ECS) occupying a writer SN slot.
    EcsClose = 1,
}

/// Typed metadata describing how a cached change was emitted on the wire.
///
/// Carried alongside the payload so a NACK-triggered retransmit can
/// rebuild the logical RTPS change (change kind, coherent-set markers,
/// instance key hash) exactly as the original live send.
///
/// `#[non_exhaustive]`: this struct is reachable from outside the crate
/// (`hdds::reliability::ChangeMetadata`, re-exported by `reliability::mod`),
/// and has already grown a field once (`source_ts_known`). Without this,
/// any future field addition breaks every downstream struct-literal
/// construction; `#[non_exhaustive]` forces external callers through
/// [`ChangeMetadata::user_data`] (then field assignment, since every
/// field stays `pub`) instead. Has NO effect on construction within this
/// crate (Rust only restricts `#[non_exhaustive]` across the crate
/// boundary), so every internal struct-literal site (`nack.rs`,
/// `runtime.rs`, `coherent.rs`, tests) keeps compiling unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChangeMetadata {
    /// Logical kind of the cached change.
    pub kind: ChangeKind,
    /// PID_COHERENT_SET value the live DATA was emitted with (RTPS v2.5
    /// SS8.7.5), or `None` for a non-coherent write. Without this a
    /// retransmitted sample cannot be associated with its coherent set
    /// by the receiver.
    pub coherent_sn: Option<u64>,
    /// PID_GROUP_COHERENT_SET_HDDS value (GROUP-scope coherent access),
    /// or `None` for TOPIC-scope / non-coherent writes. See `coherent_sn`.
    pub group_sn: Option<u64>,
    /// PID_KEY_HASH value (16-byte instance key hash) the live DATA
    /// carried in its inline QoS, or `None` for unkeyed writes.
    pub key_hash: Option<[u8; 16]>,
    /// RTPS `Time_t` (seconds, fraction) the live INFO_TS submessage
    /// carried for this change, captured ONCE at the write() site
    /// (`dds::writer::runtime::DataWriter::write`) so a NACK-triggered
    /// repair or a TRANSIENT_LOCAL replay can reproduce the exact same
    /// wire timestamp instead of stamping a fresh clock read. Meaningful
    /// only when `source_ts_known` is `true`; see that field.
    pub source_ts: (u32, u32),
    /// Whether `source_ts` was actually captured from a live INFO_TS
    /// (`true`), or is unset (`false`: the live emission never captured
    /// one for this change, or the entry was inserted through a legacy
    /// helper that does not fill this field) -- callers MUST treat `false`
    /// as "fall back to `now()`".
    ///
    /// A separate bool, NOT an in-band `(0, 0)` sentinel on `source_ts`:
    /// `(0, 0)` is the RTPS epoch, a LEGAL wire timestamp for a board
    /// whose clock has not yet acquired NTP (esp32 / seL4 boot).
    /// Collapsing "epoch" and "unknown" into the same bit pattern would
    /// silently replace a genuinely-epoch timestamp by `now()` on
    /// repair/replay.
    pub source_ts_known: bool,
    /// CDR encoding version the cached payload bytes were serialized
    /// with (`DDS::encode(buf, version)` at the write() site). A repair
    /// must derive the wire encapsulation header from THIS value, not
    /// from the writer's current `default_version`: the two can diverge
    /// when a QoS/version renegotiation happens between the original
    /// write and a later NACK.
    pub cdr_version: crate::dds::CdrVersion,
    /// Fragment size (bytes) the live DATA_FRAG emission used for this
    /// change, or `0` if the sample was NOT fragmented (sent as a single
    /// small DATA). A repair that re-fragments a cached change must
    /// reuse this size: a different fragment size renumbers fragments
    /// and corrupts the receiver's reassembly.
    ///
    /// `u16`, not `u32`: the wire RTPS DATA_FRAG `fragmentSize` field is
    /// itself `u16` (see `build_single_data_frag_packet`'s
    /// `fragment_size: u16` parameter and the `fragment_size.min(u16::MAX
    /// as usize) as u16` clamp in `build_data_frag_packets`), so a value
    /// that does not fit in `u16` could never have been the live
    /// fragment size in the first place. Also keeps `ChangeMetadata`
    /// within the `<= 64` byte budget below.
    pub frag_size: u16,
    /// Nonzero when the cached payload already contains the complete
    /// protected SerializedPayload replacement. Repairs and replay copy it
    /// without adding a second encapsulation. The actual four-octet key id
    /// and session id are carried by its CryptoHeader.
    pub key_epoch: u16,
    /// `Some` for an instance lifecycle change (dispose, unregister, or
    /// both), `None` for a sample. RTPS 2.5 8.2.3 gives a CacheChange a
    /// `kind` - ALIVE, NOT_ALIVE_DISPOSED, NOT_ALIVE_UNREGISTERED - and a
    /// writer's history holds all three: a late joiner is owed a dispose
    /// like any other change, and a NACK for its number is repaired with
    /// it. The payload is then the serialized @key fields as the live
    /// key-only DATA carried them.
    ///
    /// A field rather than new `ChangeKind` variants: that enum is public
    /// and exhaustive, so growing it would break downstream matches, while
    /// this struct is `#[non_exhaustive]`.
    pub status_info: Option<crate::protocol::builder::StatusInfoKind>,
}

/// `ChangeMetadata` is `Copy` and stored inline in every `CacheEntry`
/// slot; keep it layout-stable and small. Fields that must not silently
/// grow this struct: `kind` (repr(u8)), `coherent_sn`/`group_sn`
/// (`Option<u64>`), `key_hash` (`Option<[u8; 16]>`), `source_ts`
/// (`(u32, u32)`), `source_ts_known` (`bool`), `cdr_version` (repr(Rust)
/// 2-variant enum), `frag_size` / `key_epoch` (`u16` each -- see their
/// doc comments for why not `u32`), `status_info` (`Option` of a `u32`
/// enum, the field that took the budget from 64 to 72 bytes). The group
/// sequence information of a GROUP Publisher's change is kept out of line
/// (`Ring::groups`), so no other writer pays for it. Not a bare `== N`: the exact byte
/// count is compiler-layout-dependent (field reordering, niche packing),
/// only the upper bound matters here. 64-bit target only (`usize`-free
/// struct, so this holds on 32-bit too, but the intent is documented for
/// 64-bit).
const _: () = assert!(core::mem::size_of::<ChangeMetadata>() <= 72);

impl ChangeMetadata {
    /// Metadata for a plain user DATA sample: no markers, no key hash,
    /// no known source timestamp.
    ///
    /// `cdr_version` defaults to `Xcdr2`: a best-effort default for
    /// callers that have no writer version to report (mostly tests and the
    /// legacy `insert_keyed` path below). The real write() path never
    /// relies on it -- it journals the writer's one version
    /// (`effective_cdr_version()`, resolved at creation) via
    /// [`HistoryCache::insert_with_metadata`].
    #[must_use]
    pub const fn user_data() -> Self {
        Self {
            kind: ChangeKind::UserData,
            coherent_sn: None,
            group_sn: None,
            key_hash: None,
            source_ts: (0, 0),
            source_ts_known: false,
            cdr_version: crate::dds::CdrVersion::Xcdr2,
            frag_size: 0,
            key_epoch: 0,
            status_info: None,
        }
    }
}

/// Atomic snapshot of one cached change: payload and metadata copied
/// under a SINGLE ring-lock acquisition (see
/// [`HistoryCache::get_change`]), so a NACK-triggered retransmit can
/// never observe a payload from one cache state and metadata from
/// another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedChange {
    /// RTPS writer sequence number.
    pub seq: u64,
    /// Serialized payload bytes as originally inserted.
    pub payload: Vec<u8>,
    /// Typed emission metadata (kind, coherent markers, key hash).
    pub metadata: ChangeMetadata,
    /// The group sequence number and writerSet the change was written with
    /// by a GROUP Publisher's writer (`PID_GROUP_SEQ_NUM`,
    /// `PID_WRITER_GROUP_INFO`, RTPS v2.5 Sec.8.7.5), `None` for any other
    /// writer: a repair or a replay carries the same.
    pub group: Option<crate::protocol::group::GroupTag>,
}

/// One change of a local late-joiner replay
/// ([`HistoryCache::snapshot_for_local_replay`]).
pub(crate) struct LocalReplayChange {
    /// Invalidated by partial eviction; whole-history departure preserves the
    /// bytes of an already captured complete composite.
    pub coherent_replay_valid: Option<Arc<AtomicBool>>,
    pub coherent_replay_admission: Option<Arc<CoherentReplayAdmission>>,
    pub seq: u64,
    pub coherent_sn: Option<u64>,
    pub group_sn: Option<u64>,
    pub gsn: Option<u64>,
    /// Source instance identity retained alongside the serialized payload.
    pub key_hash: Option<[u8; 16]>,
    /// Carries one slab reference the caller owns.
    pub slab: SlabHandle,
    pub len: usize,
    pub cdr_version: crate::dds::CdrVersion,
    /// Journaled INFO_TS in epoch nanoseconds; `None` means unknown, while
    /// `Some(0)` is a genuine epoch timestamp.
    pub source_timestamp_ns: Option<u64>,
    /// For a lifecycle change: its status and its instance's key hash. The
    /// slab then holds the key-only DATA payload, not a sample.
    pub lifecycle: Option<(crate::protocol::builder::StatusInfoKind, [u8; 16])>,
}

/// Cache entry for a single written message.
#[derive(Debug, Clone, Copy)]
pub struct CacheEntry {
    pub seq: u64,
    pub slab: SlabHandle,
    pub len: usize,
    pub ts_ns: u64,
    /// Instance key hash (0 = unkeyed / default instance).
    pub instance_key: u64,
    /// Typed emission metadata carried alongside the payload so a
    /// NACK-triggered retransmit can rebuild the DATA with the identical
    /// logical RTPS change (kind, inline-QoS coherent markers, key hash)
    /// as the original live send.
    pub metadata: ChangeMetadata,
}

/// The instance a cached change is accounted to.
///
/// HISTORY depth and the RESOURCE_LIMITS per-instance limits are PER
/// INSTANCE (DDS 1.4 2.2.3.18, 2.2.3.19), so the cache must know which
/// instance each change belongs to. The live write path records the full
/// 16-byte PID_KEY_HASH in `ChangeMetadata::key_hash` and passes
/// `instance_key = 0`; reading only `instance_key` made every instance of a
/// keyed topic one instance, so a KEEP_LAST(1) writer retained one sample
/// across all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum InstanceId {
    /// A keyed change, identified by the full key hash it was sent with.
    /// All 16 bytes: a key that fits in 16 bytes IS its key hash, so a
    /// shorter prefix would merge instances that differ past it.
    KeyHash([u8; 16]),
    /// A change inserted with no key hash: the caller's `instance_key`,
    /// which is 0 for an unkeyed topic (its single instance).
    Legacy(u64),
    /// A coherent-set close marker. It occupies a writer SN slot but is a
    /// change of no instance: it never counts against, nor evicts, the data
    /// of any instance, and no HISTORY depth nor RESOURCE_LIMITS bound
    /// applies to it. RTPS v2.5 Sec.8.7.6: an end of set "is not filtered by
    /// time, content, history, lifespan, etc. It can only be removed from
    /// the RTPS Writer cache when all data samples belonging to the coherent
    /// set are removed. It does not count towards resource limits." A close
    /// leaves with the last member of its set (`Ring::orphan_markers`).
    Marker,
}

impl InstanceId {
    fn of(entry: &CacheEntry) -> Self {
        if entry.metadata.kind == ChangeKind::EcsClose {
            Self::Marker
        } else if let Some(hash) = entry.metadata.key_hash {
            Self::KeyHash(hash)
        } else {
            Self::Legacy(entry.instance_key)
        }
    }
}

/// What a GROUP Publisher's writer's history holds of the GSNs of a range
/// of its changes (`HistoryCache::group_window`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GroupWindow {
    /// The GSN of the first change of the range the history holds.
    pub first_gsn: Option<u64>,
    /// The GSN of the last change of the range the history holds.
    pub last_gsn: Option<u64>,
    /// The GSN of the first change the history holds above the range.
    pub unannounced_gsn: Option<u64>,
}

/// The cached changes in insertion order, with a retained-change count per
/// instance kept in step with them.
///
/// Read access goes through `Deref`; the only ways to change the entries are
/// the three methods below, each of which keeps `per_instance` in step. There
/// is deliberately no `DerefMut`: a new removal path that bypassed the count
/// would not compile.
struct Ring {
    /// Changes on each acknowledgment publication, including repeated floors.
    ack_progress: u64,
    /// Threads blocked on `HistoryCache::space`, counted under this lock
    /// (`HistoryCache::wait_for_space`): an acknowledgment publication
    /// wakes only when one is there to wake.
    space_waiters: usize,
    entries: VecDeque<CacheEntry>,
    per_instance: HashMap<InstanceId, usize>,
    /// The group sequence information of the changes of a GROUP
    /// Publisher's writer, by SN: out of line, so the entries of every other
    /// writer pay nothing for it (empty, never looked up).
    groups: std::collections::BTreeMap<u64, crate::protocol::group::GroupTag>,
    /// A GROUP Publisher's writer's changes taken and never made whose
    /// SN and GSN could not be given back: SN -> GSN, the newest
    /// `MAX_GROUP_HOLES` (`HistoryCache::record_group_hole`).
    group_holes: std::collections::BTreeMap<u64, u64>,
    /// A GROUP Publisher's count of the members its writers' histories
    /// retain per set (`GroupRetention`), told of every member this ring
    /// journals and gives up.
    retention: Option<std::sync::Arc<dyn GroupRetention>>,
    /// The last `without_retained` pass (`OrphanMemo`).
    orphan_memo: Option<OrphanMemo>,
    replay_sets: HashMap<u64, LocalReplaySet>,
    replay_empty: std::collections::HashSet<u64>,
    replay_closed_before: u64,
    replay_integrity: Option<Arc<CoherentReplayIntegrity>>,
}

/// What `Ring::without_retained` found, valid while the Publisher's
/// `GroupRetention::generation` stays the same: no set becomes retained or
/// stops being retained, so the ends checked then keep their verdict and
/// only the ends journaled since need asking.
struct OrphanMemo {
    generation: u64,
    /// The SN of the newest end checked.
    checked_through: u64,
    /// The SNs of the ends then found to have no member left anywhere.
    unretained: Vec<u64>,
}

/// The members of each coherent set a GROUP Publisher's writers' histories
/// retain, by the set's first GSN, counted across the writers: an end of set
/// "can only be removed from the RTPS Writer cache when all data samples
/// belonging to the coherent set are removed" (RTPS v2.5 Sec.8.7.6), and
/// under GROUP scope the set's samples are every writer's. Told under the
/// ring's lock; takes no ring lock itself.
pub(crate) trait GroupRetention: Send + Sync {
    /// A member of set `set` is journaled.
    fn retain(&self, set: u64);
    /// A member of set `set` left a history.
    fn release(&self, set: u64);
    /// For each of `sets`, whether some writer's history retains a member
    /// of it (0: no set, never).
    fn retains_each(&self, sets: &[u64]) -> Vec<bool>;
    /// Moves each time a set starts or stops being retained.
    fn generation(&self) -> u64;
    /// Shared GROUP replay integrity, independent of repair retention.
    fn replay_integrity(&self) -> Option<Arc<CoherentReplayIntegrity>> {
        None
    }
}

struct LocalReplaySet {
    resident: usize,
    valid: Arc<AtomicBool>,
}

#[derive(Default)]
struct ReplaySetIntegrity {
    resident: usize,
    members: usize,
    complete: bool,
    admission: Arc<CoherentReplayAdmission>,
    valid: Arc<AtomicBool>,
}

/// Future snapshots need retained history. Captured composites instead own
/// their bytes and may survive departure if they contain every original member.
pub(crate) struct CoherentReplayAdmission {
    eligible: AtomicBool,
    complete: AtomicBool,
    members: AtomicUsize,
}

impl Default for CoherentReplayAdmission {
    fn default() -> Self {
        Self {
            eligible: AtomicBool::new(true),
            complete: AtomicBool::new(false),
            members: AtomicUsize::new(0),
        }
    }
}

impl CoherentReplayAdmission {
    pub(crate) fn permits_captured(&self, members: usize) -> bool {
        self.eligible.load(Ordering::Acquire)
            || (self.complete.load(Ordering::Acquire)
                && members == self.members.load(Ordering::Acquire))
    }
}

/// Suppress retained fragments of a GROUP coherent set during late replay.
/// Ring and coordinator locks may enter this terminal lock; it calls neither.
#[derive(Default)]
pub(crate) struct CoherentReplayIntegrity(Mutex<HashMap<u64, ReplaySetIntegrity>>);

impl CoherentReplayIntegrity {
    fn retain(&self, set: u64) {
        let mut sets = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let state = sets.entry(set).or_insert_with(|| ReplaySetIntegrity {
            valid: Arc::new(AtomicBool::new(true)),
            ..ReplaySetIntegrity::default()
        });
        state.resident += 1;
        state.members += 1;
    }

    fn release(&self, set: u64, invalidate: bool) {
        let mut sets = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = sets.get_mut(&set) {
            state.admission.eligible.store(false, Ordering::Release);
            if invalidate {
                state.valid.store(false, Ordering::Release);
            }
            state.resident -= 1;
            if state.complete && state.resident == 0 {
                sets.remove(&set);
            }
        }
    }

    /// All writers journaled and staged their parts; no member can arrive later.
    pub(crate) fn complete(&self, set: u64) {
        let mut sets = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = sets.get_mut(&set) {
            state.complete = true;
            state
                .admission
                .members
                .store(state.members, Ordering::Relaxed);
            state.admission.complete.store(true, Ordering::Release);
            if state.resident == 0 {
                sets.remove(&set);
            }
        }
    }

    fn ticket(&self, set: u64) -> Option<Arc<AtomicBool>> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&set)
            .map(|state| Arc::clone(&state.valid))
    }

    fn replayable(&self, set: u64) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&set)
            .is_some_and(|state| {
                state.admission.eligible.load(Ordering::Acquire)
                    && state.valid.load(Ordering::Acquire)
            })
    }

    fn admission(&self, set: u64) -> Option<Arc<CoherentReplayAdmission>> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&set)
            .map(|state| Arc::clone(&state.admission))
    }
}

/// The set a change of a GROUP Publisher's writer is a member of: its tag's
/// set, unless it is an end of set.
fn member_of(entry: &CacheEntry, tag: Option<&crate::protocol::group::GroupTag>) -> Option<u64> {
    (entry.metadata.kind != ChangeKind::EcsClose)
        .then(|| tag.and_then(|tag| tag.set_first_gsn))
        .flatten()
}

/// How many holes a GROUP writer's history remembers for its repairs.
const MAX_GROUP_HOLES: usize = 64;

impl Ring {
    /// Retain none of this history's members any more (`GroupRetention`).
    fn leave_retention(&mut self) {
        let Some(retention) = self.retention.take() else {
            return;
        };
        if let Some(integrity) = &self.replay_integrity {
            for entry in &self.entries {
                if entry.metadata.kind != ChangeKind::EcsClose
                    && entry.metadata.coherent_sn.is_some()
                {
                    if let Some(set) = entry.metadata.group_sn {
                        integrity.release(set, false);
                    }
                }
            }
        }
        // Keep the shared eligibility witness: other holders of this cache
        // must not start a replay after its writer has departed.
        for entry in &self.entries {
            if let Some(set) = member_of(entry, self.groups.get(&entry.seq)) {
                retention.release(set);
            }
        }
    }
}

/// A history gone retains none of its members.
impl Drop for Ring {
    fn drop(&mut self) {
        self.leave_retention();
    }
}

impl std::ops::Deref for Ring {
    type Target = VecDeque<CacheEntry>;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl Ring {
    /// Initial capacity only; the limits are enforced at admission. Capped
    /// so a LENGTH_UNLIMITED `max_samples` does not ask for `usize::MAX`
    /// slots up front.
    fn with_capacity(max_samples: usize) -> Self {
        Self {
            ack_progress: 0,
            space_waiters: 0,
            entries: VecDeque::with_capacity(max_samples.min(1024)),
            per_instance: HashMap::new(),
            groups: std::collections::BTreeMap::new(),
            group_holes: std::collections::BTreeMap::new(),
            retention: None,
            orphan_memo: None,
            replay_sets: HashMap::new(),
            replay_empty: std::collections::HashSet::new(),
            replay_closed_before: 0,
            replay_integrity: None,
        }
    }

    /// Journal `entry` in its place by SN. A change is journaled after its
    /// SN is taken, and a later SN can be journaled first (an end of set
    /// another thread took the writer's next SN for): the ring stays in SN
    /// order all the same, which `orphan_markers` reads the members of a set
    /// from.
    fn push_back<const TRACK: bool>(
        &mut self,
        entry: CacheEntry,
        group: Option<crate::protocol::group::GroupTag>,
    ) {
        if TRACK {
            if entry.metadata.kind == ChangeKind::EcsClose {
                self.replay_closed_before = self.replay_closed_before.max(entry.seq);
            } else if let Some(first) = entry.metadata.coherent_sn {
                let state = self
                    .replay_sets
                    .entry(first)
                    .or_insert_with(|| LocalReplaySet {
                        resident: 0,
                        valid: Arc::new(AtomicBool::new(true)),
                    });
                state.resident += 1;
                self.replay_empty.remove(&first);
                if let (Some(set), Some(integrity)) =
                    (entry.metadata.group_sn, &self.replay_integrity)
                {
                    integrity.retain(set);
                }
            }
        }
        *self.per_instance.entry(InstanceId::of(&entry)).or_insert(0) += 1;
        if let Some(tag) = group {
            self.groups.insert(entry.seq, tag);
            if let (Some(set), Some(retention)) =
                (member_of(&entry, Some(&tag)), self.retention.as_ref())
            {
                retention.retain(set);
            }
        }
        let at = self
            .entries
            .iter()
            .rposition(|e| e.seq < entry.seq)
            .map_or(0, |index| index + 1);
        if at == self.entries.len() {
            self.entries.push_back(entry);
        } else {
            self.entries.insert(at, entry);
        }
    }

    fn pop_front(&mut self) -> Option<CacheEntry> {
        self.pop_front_mode::<true>()
    }

    fn pop_front_mode<const TRACK: bool>(&mut self) -> Option<CacheEntry> {
        let entry = self.entries.pop_front()?;
        self.forget::<TRACK>(&entry);
        Some(entry)
    }

    fn remove_mode<const TRACK: bool>(&mut self, index: usize) -> Option<CacheEntry> {
        let entry = self.entries.remove(index)?;
        self.forget::<TRACK>(&entry);
        Some(entry)
    }

    /// Remove every entry whose instance is in `eligible`, in one O(n)
    /// pass over the ring (never `remove(index)` in a loop, which is
    /// O(n) per call over a `VecDeque`), with the SAME per-entry
    /// bookkeeping `remove`/`pop_front` already keep (`forget`:
    /// `per_instance` count, groups, retention). Returns the removed
    /// entries so the caller can release their slabs after this lock
    /// is dropped, not under it.
    fn retain_not_in(
        &mut self,
        eligible: &std::collections::HashSet<InstanceId>,
    ) -> Vec<CacheEntry> {
        if eligible.is_empty() {
            return Vec::new();
        }
        // Drained into a plain Vec first: `forget` needs `&mut self`,
        // which a live `drain(..)` iterator over `self.entries` already
        // borrows (E0499), so the split into "removed" / "kept" and the
        // bookkeeping it drives happen in a second pass, over that Vec.
        let taken: Vec<CacheEntry> = self.entries.drain(..).collect();
        let mut removed = Vec::new();
        let mut kept = VecDeque::with_capacity(taken.len());
        for entry in taken {
            if eligible.contains(&InstanceId::of(&entry)) {
                self.forget::<true>(&entry);
                removed.push(entry);
            } else {
                kept.push_back(entry);
            }
        }
        self.entries = kept;
        removed
    }

    fn forget<const TRACK: bool>(&mut self, entry: &CacheEntry) {
        if TRACK && entry.metadata.kind != ChangeKind::EcsClose {
            if let Some(first) = entry.metadata.coherent_sn {
                if let Some(state) = self.replay_sets.get_mut(&first) {
                    state.valid.store(false, Ordering::Release);
                    state.resident -= 1;
                    if state.resident == 0 {
                        self.replay_empty.insert(first);
                    }
                }
                if let (Some(set), Some(integrity)) =
                    (entry.metadata.group_sn, &self.replay_integrity)
                {
                    integrity.release(set, true);
                }
            }
        }
        if !self.groups.is_empty() {
            let tag = self.groups.remove(&entry.seq);
            if let (Some(set), Some(retention)) =
                (member_of(entry, tag.as_ref()), self.retention.as_ref())
            {
                retention.release(set);
            }
        }
        let id = InstanceId::of(entry);
        if let Some(count) = self.per_instance.get_mut(&id) {
            *count -= 1;
            if *count == 0 {
                self.per_instance.remove(&id);
            }
        }
    }

    /// The group sequence information of change `seq`, if any.
    fn group_of(&self, seq: u64) -> Option<crate::protocol::group::GroupTag> {
        if self.groups.is_empty() {
            return None;
        }
        self.groups.get(&seq).copied()
    }

    fn replay_ticket(&self, entry: &CacheEntry) -> Option<Arc<AtomicBool>> {
        if entry.metadata.kind == ChangeKind::EcsClose {
            return None;
        }
        if let (Some(set), Some(integrity)) = (entry.metadata.group_sn, &self.replay_integrity) {
            return integrity.ticket(set);
        }
        entry.metadata.coherent_sn.and_then(|first| {
            self.replay_sets
                .get(&first)
                .map(|state| Arc::clone(&state.valid))
        })
    }

    fn replayable(&self, entry: &CacheEntry) -> bool {
        if entry.metadata.coherent_sn.is_none() {
            return true;
        }
        if let (Some(set), Some(integrity)) = (entry.metadata.group_sn, &self.replay_integrity) {
            return integrity.replayable(set);
        }
        self.replay_ticket(entry)
            .is_none_or(|valid| valid.load(Ordering::Acquire))
    }

    fn prune_replay_sets(&mut self, earlier_in_flight: bool) {
        if earlier_in_flight {
            return;
        }
        let closed = self.replay_closed_before;
        self.replay_empty.retain(|first| {
            if *first < closed {
                self.replay_sets.remove(first);
                false
            } else {
                true
            }
        });
    }

    fn count(&self, id: InstanceId) -> usize {
        self.per_instance.get(&id).copied().unwrap_or(0)
    }

    /// Changes retained that are data, not close markers: what HISTORY and
    /// RESOURCE_LIMITS count.
    fn data_len(&self) -> usize {
        self.entries.len() - self.count(InstanceId::Marker)
    }

    /// The close markers whose set has no member left, oldest first. The
    /// members of the set a close ends are the changes tagged with a
    /// coherent set (`coherent_sn`) after the previous close and before it.
    fn orphan_markers(&self) -> Vec<usize> {
        let mut orphans = Vec::new();
        if self.count(InstanceId::Marker) == 0 {
            return orphans;
        }
        let mut member = false;
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.metadata.kind == ChangeKind::EcsClose {
                if !member {
                    orphans.push(index);
                }
                member = false;
            } else if entry.metadata.coherent_sn.is_some() {
                member = true;
            }
        }
        orphans
    }

    /// `orphans` (`orphan_markers`) less the ends of a set another writer of
    /// the GROUP Publisher retains a member of (`GroupRetention`): under
    /// GROUP scope a set's members are every writer's.
    fn without_retained(&mut self, mut orphans: Vec<usize>) -> Vec<usize> {
        let Some(retention) = self.retention.as_ref() else {
            return orphans;
        };
        let generation = retention.generation();
        let (checked_through, mut unretained) = match self.orphan_memo.take() {
            Some(memo) if memo.generation == generation => (memo.checked_through, memo.unretained),
            _ => (0, Vec::new()),
        };
        let fresh: Vec<u64> = orphans
            .iter()
            .map(|&index| self.entries[index].seq)
            .filter(|&seq| seq > checked_through)
            .collect();
        let sets: Vec<u64> = fresh
            .iter()
            .map(|seq| {
                self.groups
                    .get(seq)
                    .and_then(|tag| tag.set_first_gsn)
                    .unwrap_or(0)
            })
            .collect();
        let retained = retention.retains_each(&sets);
        unretained.extend(
            fresh
                .iter()
                .zip(retained)
                .filter(|(_, retained)| !retained)
                .map(|(seq, _)| *seq),
        );
        // An end checked then and no orphan then (its writer's members
        // kept it) is one whose set was retained: any member it lost since
        // was released, and had the set none left, the generation moved.
        let newest = fresh
            .last()
            .map_or(checked_through, |&seq| seq.max(checked_through));
        orphans.retain(|&index| unretained.binary_search(&self.entries[index].seq).is_ok());
        unretained = orphans
            .iter()
            .map(|&index| self.entries[index].seq)
            .collect();
        self.orphan_memo = Some(OrphanMemo {
            generation,
            checked_through: newest,
            unretained,
        });
        orphans
    }

    /// Distinct data instances retained; markers are not an instance.
    fn data_instances(&self) -> usize {
        self.per_instance.len() - usize::from(self.per_instance.contains_key(&InstanceId::Marker))
    }

    /// Index of the oldest change of `id`.
    fn oldest_of(&self, id: InstanceId) -> Option<usize> {
        self.entries.iter().position(|e| InstanceId::of(e) == id)
    }

    /// Index of the oldest change that satisfies `pred`.
    fn oldest_where(&self, pred: impl Fn(&CacheEntry) -> bool) -> Option<usize> {
        self.entries.iter().position(pred)
    }

    /// Index of the oldest change whose removal leaves its instance at
    /// least one change, counting the change about to be admitted for
    /// `incoming` (DDS 1.4 2.2.2.4.2.11: when `max_samples` is exhausted
    /// under KEEP_LAST, samples of another instance may be discarded "as
    /// long as at least one sample remains for such an instance").
    fn oldest_spare(&self, incoming: InstanceId) -> Option<usize> {
        self.entries.iter().position(|e| {
            let id = InstanceId::of(e);
            id != InstanceId::Marker && (id == incoming || self.count(id) > 1)
        })
    }
}

/// Who takes a writer's SNs for changes it journals (`HistoryCache::taking`):
/// the writer's own writes, one at a time on the thread that writes (a
/// `DataWriter` is `!Sync`: one producing thread at a time, a compile error
/// otherwise), and the ends of set its Publisher emits for it, one at a time
/// under the Publisher's lock. One slot each is therefore enough.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Producer {
    /// The writer's own changes.
    Writer = 0,
    /// The ends of set the Publisher emits for the writer.
    EndOfSet = 1,
}

/// A change taken and not journaled yet (`HistoryCache::taking`); cleared on
/// drop.
pub(crate) struct InFlight<'a> {
    slot: &'a AtomicU64,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        // Release: a NACK that reads 0 (Acquire) also sees the change
        // journaled, and finds it on its second look-up.
        self.slot.store(0, Ordering::Release);
    }
}

/// History cache for writer-side message retransmission.
pub struct HistoryCache {
    pub(crate) wire_windows: Arc<crate::protocol::dialect::sequence_window::WriterWindows>,
    /// Set boundaries of InterCOM readers whose retirement GAP is deferred
    /// (see `protocol::dialect::close_gap`).
    pub(crate) deferred_close_gaps: crate::protocol::dialect::close_gap::DeferredCloseGaps,
    ring: Mutex<Ring>,
    slabs: Arc<SlabPool>,
    quota_bytes: AtomicUsize,
    max_quota_bytes: usize,
    max_samples: usize,
    history_kind: History,
    /// Maximum number of distinct instances (keyed topics).
    /// LENGTH_UNLIMITED means no limit.
    max_instances: usize,
    /// Maximum samples per instance for keyed topics.
    /// LENGTH_UNLIMITED means no limit.
    max_samples_per_instance: usize,
    /// LIFESPAN QoS: samples older than this are pruned automatically on
    /// every cache read (`get`, `get_all_samples`, `snapshot_payloads`) so
    /// expired samples cannot be retransmitted.  `u64::MAX` means INFINITE
    /// (disabled), which is the default.  Set via `set_lifespan_nanos`.
    lifespan_nanos: std::sync::atomic::AtomicU64,
    /// Woken whenever a change leaves the ring or the acknowledgement
    /// floor moves: the two ways a full history gets room back.
    space: Condvar,
    #[cfg(test)]
    pub(crate) before_floor_wait: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Every change at or below this sequence number has been acknowledged
    /// by every matched reliable reader (RTPS 2.5 8.4.7.4
    /// `is_acked_by_all`); `u64::MAX` when no reliable reader is matched.
    /// Starts at 0, so a cache no writer drives treats nothing as
    /// acknowledged and keeps its behaviour.
    acked_floor: AtomicU64,

    /// The highest sequence number ever inserted, 0 before the first: what
    /// the writer has actually published, unlike its sequence counter, which
    /// also counts a number reserved and not (yet, or ever) written.
    highest_inserted: AtomicU64,
    /// Per producer of changes (`Producer`), a lower bound of the SN of a
    /// change it took and has not journaled yet, 0: none (`taking`).
    in_flight: [AtomicU64; 2],
    /// RELIABLE writer: a full history may only give up changes every
    /// reader has acknowledged. BEST_EFFORT: "the old values will be
    /// discarded" (DDS 1.4 2.2.3.18).
    reliable: AtomicBool,
    /// Keep changes after every reader acknowledged them: true for a
    /// durable writer, which owes them to late joiners; false for a
    /// VOLATILE one, which may remove them (RTPS 2.5 8.4.1 steps 20-22).
    keep_acknowledged: AtomicBool,
    /// Gates `durability_lifecycle` bookkeeping on every `insert`: `false`
    /// for the overwhelming majority of writers (BEST_EFFORT, VOLATILE,
    /// or durable with no `service_cleanup_delay`), which pay for nothing
    /// beyond this one relaxed load. Set once, by
    /// `enable_durability_cleanup`, only by a writer whose durability and
    /// configured delay make `remove_durability_expired` reachable at
    /// all (`WriterBuilder`, before the writer is handed to the caller).
    durability_cleanup_enabled: AtomicBool,
    /// Per-instance DurabilityService lifecycle (DDS v1.4 Sec.2.2.3.5),
    /// maintained incrementally on `insert` rather than rebuilt by
    /// scanning the ring on every cleanup tick: `remove_durability_expired`
    /// reads only this (bounded by the number of distinct instances ever
    /// written, not the ring's size) to decide what to sweep, then visits
    /// the ring once, only for the instances it found eligible. Empty and
    /// never locked while `durability_cleanup_enabled` is false.
    durability_lifecycle: Mutex<HashMap<InstanceId, InstanceLifecycle>>,
}

/// One instance's running DurabilityService state (DDS v1.4 Sec.2.2.3.5),
/// updated on every `insert` of a change of it while
/// `durability_cleanup_enabled` is set.
///
/// `disposed_at` / `unregistered_at` are independent: `dispose()` then a
/// LATER, separate `unregister_instance()` (the `WriterDataLifecycle`
/// `manual_dispose` policy, which keeps the DDS default's two bits from
/// landing in one wire `DisposedUnregistered` change) still sets both,
/// each at its own change's timestamp. A plain write (no lifecycle
/// change) clears both: the instance is alive again, and the rule
/// starts over from there, exactly like a reader that unregisters then
/// writes to the same instance again.
#[derive(Debug, Clone, Copy, Default)]
struct InstanceLifecycle {
    /// The latest sequence number journaled for this instance, so
    /// `remove_durability_expired` can check it is acknowledged without
    /// a second lookup.
    seq: u64,
    /// `Some(ts_ns)` of the latest change disposing this instance since
    /// its last revival (a plain write); `None` if it has not been
    /// disposed since.
    disposed_at: Option<u64>,
    /// `Some(ts_ns)` of the latest change unregistering this instance
    /// since its last revival; `None` if it has not been unregistered
    /// since.
    unregistered_at: Option<u64>,
}

impl HistoryCache {
    /// Create new history cache from QoS `ResourceLimits`.
    pub fn new(slabs: Arc<SlabPool>, limits: &ResourceLimits) -> Self {
        let depth = u32::try_from(limits.max_samples).unwrap_or(u32::MAX);
        let history_kind = History::KeepLast(depth);
        Self::new_with_history(slabs, limits, history_kind)
    }

    /// Create new history cache from QoS `ResourceLimits` and history policy.
    pub fn new_with_history(
        slabs: Arc<SlabPool>,
        limits: &ResourceLimits,
        history_kind: History,
    ) -> Self {
        let max_samples = limits.max_samples;
        let max_quota_bytes = limits.max_quota_bytes;

        Self {
            wire_windows: Arc::default(),
            deferred_close_gaps: Default::default(),
            ring: Mutex::new(Ring::with_capacity(max_samples)),
            slabs,
            quota_bytes: AtomicUsize::new(0),
            max_quota_bytes,
            max_samples,
            history_kind,
            max_instances: limits.max_instances,
            max_samples_per_instance: limits.max_samples_per_instance,
            lifespan_nanos: std::sync::atomic::AtomicU64::new(u64::MAX),
            space: Condvar::new(),
            #[cfg(test)]
            before_floor_wait: Mutex::new(None),
            acked_floor: AtomicU64::new(0),
            highest_inserted: AtomicU64::new(0),
            in_flight: [AtomicU64::new(0), AtomicU64::new(0)],
            reliable: AtomicBool::new(true),
            keep_acknowledged: AtomicBool::new(true),
            durability_cleanup_enabled: AtomicBool::new(false),
            durability_lifecycle: Mutex::new(HashMap::new()),
        }
    }

    /// Create new history cache with explicit limits (legacy API for tests).
    #[doc(hidden)]
    pub fn new_with_limits(
        slabs: Arc<SlabPool>,
        max_samples: usize,
        max_quota_bytes: usize,
        history_kind: History,
    ) -> Self {
        Self {
            wire_windows: Arc::default(),
            deferred_close_gaps: Default::default(),
            ring: Mutex::new(Ring::with_capacity(max_samples)),
            slabs,
            quota_bytes: AtomicUsize::new(0),
            max_quota_bytes,
            max_samples,
            history_kind,
            max_instances: LENGTH_UNLIMITED,
            max_samples_per_instance: LENGTH_UNLIMITED,
            lifespan_nanos: std::sync::atomic::AtomicU64::new(u64::MAX),
            space: Condvar::new(),
            #[cfg(test)]
            before_floor_wait: Mutex::new(None),
            acked_floor: AtomicU64::new(0),
            highest_inserted: AtomicU64::new(0),
            in_flight: [AtomicU64::new(0), AtomicU64::new(0)],
            reliable: AtomicBool::new(true),
            keep_acknowledged: AtomicBool::new(true),
            durability_cleanup_enabled: AtomicBool::new(false),
            durability_lifecycle: Mutex::new(HashMap::new()),
        }
    }

    /// Create new history cache with DurabilityService-style limits.
    ///
    /// Allows specifying max_instances and max_samples_per_instance in addition
    /// to basic max_samples and quota limits.
    pub fn new_with_durability_service_limits(
        slabs: Arc<SlabPool>,
        max_samples: usize,
        max_quota_bytes: usize,
        history_kind: History,
        max_instances: usize,
        max_samples_per_instance: usize,
    ) -> Self {
        Self {
            wire_windows: Arc::default(),
            deferred_close_gaps: Default::default(),
            ring: Mutex::new(Ring::with_capacity(max_samples)),
            slabs,
            quota_bytes: AtomicUsize::new(0),
            max_quota_bytes,
            max_samples,
            history_kind,
            max_instances,
            max_samples_per_instance,
            lifespan_nanos: std::sync::atomic::AtomicU64::new(u64::MAX),
            space: Condvar::new(),
            #[cfg(test)]
            before_floor_wait: Mutex::new(None),
            acked_floor: AtomicU64::new(0),
            highest_inserted: AtomicU64::new(0),
            in_flight: [AtomicU64::new(0), AtomicU64::new(0)],
            reliable: AtomicBool::new(true),
            keep_acknowledged: AtomicBool::new(true),
            durability_cleanup_enabled: AtomicBool::new(false),
            durability_lifecycle: Mutex::new(HashMap::new()),
        }
    }

    /// Set how a full history gets room back, from the owning writer's QoS.
    /// See the `reliable` and `keep_acknowledged` fields.
    pub fn set_release_policy(&self, reliable: bool, keep_acknowledged: bool) {
        self.reliable.store(reliable, Ordering::Relaxed);
        self.keep_acknowledged
            .store(keep_acknowledged, Ordering::Relaxed);
    }

    /// Record that every change up to `floor` is acknowledged by every
    /// matched reliable reader (`u64::MAX`: no reliable reader is matched).
    ///
    /// A cache that does not keep acknowledged changes removes them now.
    /// Either way a writer blocked on a full history is woken: an
    /// acknowledged change is one it may now take the room of.
    pub fn set_acked_floor(&self, floor: u64) {
        // The condition and its notification use the waiter's mutex even
        // when durable history retains acknowledged payloads.
        let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        self.acked_floor.store(floor, Ordering::Release);
        ring.ack_progress = ring.ack_progress.wrapping_add(1);
        if !self.keep_acknowledged.load(Ordering::Relaxed) {
            while let Some(index) = ring.oldest_where(|e| e.seq <= floor) {
                self.discard(&mut ring, index);
            }
        }
        // Everything this publication changed was changed under the lock,
        // and every waiter counts itself under the same lock before it
        // releases it to wait: with none counted, no thread can be waiting
        // for this change, and a later one will see it before it waits.
        // The notification is a system call per acknowledgment otherwise.
        let wake = ring.space_waiters > 0;
        drop(ring);
        if wake {
            self.space.notify_all();
        }
    }

    /// Snapshot progress before checking the wait predicate. The floor can
    /// return to an earlier value after readers join and leave; the revision
    /// records those publications too. This lock is released before the
    /// caller checks its per-reader table, preserving table -> ring order.
    pub(crate) fn ack_progress(&self) -> u64 {
        self.ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ack_progress
    }

    /// Wait only if no acknowledgment publication followed the caller's
    /// progress snapshot. Checking the revision under the notification's
    /// mutex also covers a floor that changed and then changed back.
    pub(crate) fn wait_for_floor_change(&self, observed: u64, deadline: std::time::Instant) {
        #[cfg(test)]
        {
            let hook = self
                .before_floor_wait
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(hook) = hook {
                hook();
            }
        }
        let ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        if ring.ack_progress != observed {
            return;
        }
        let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
            return;
        };
        drop(self.wait_for_space(ring, remaining));
    }

    /// Block on `space` for at most `timeout`, counted in the ring's
    /// `space_waiters` from before the lock is released until it is taken
    /// back, so a notifier that holds the lock sees every thread that
    /// could miss its notification.
    fn wait_for_space<'a>(
        &self,
        mut ring: std::sync::MutexGuard<'a, Ring>,
        timeout: std::time::Duration,
    ) -> std::sync::MutexGuard<'a, Ring> {
        ring.space_waiters += 1;
        let mut ring = match self.space.wait_timeout(ring, timeout) {
            Ok((lock, _)) => lock,
            Err(e) => e.into_inner().0,
        };
        ring.space_waiters -= 1;
        ring
    }

    /// Count this history's members of each coherent set in a GROUP
    /// Publisher's `retention`, and keep its ends of set while any of its
    /// writers' histories retains a member of the set (RTPS v2.5
    /// Sec.8.7.6). Set once, before the first change.
    pub(crate) fn set_group_retention(&self, retention: std::sync::Arc<dyn GroupRetention>) {
        let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        ring.replay_integrity = retention.replay_integrity();
        ring.retention = Some(retention);
    }

    /// The writer is deleted: its history, which other holders may keep a
    /// while, retains none of its members for its Publisher's ends of set
    /// any more (`set_group_retention`).
    pub(crate) fn leave_group_retention(&self) {
        let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        ring.leave_retention();
    }

    /// The acknowledgement floor last set by `set_acked_floor`.
    #[must_use]
    pub fn acked_floor(&self) -> u64 {
        self.acked_floor.load(Ordering::Acquire)
    }

    /// Capture the committed watermark and retained replay debt.
    /// Evicted history and wire-only end-of-set markers are not replay debt.
    pub(crate) fn local_ack_history(&self) -> (u64, std::collections::BTreeSet<u64>) {
        self.prune_by_lifespan();
        let ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        let pending = ring
            .iter()
            .filter(|entry| entry.metadata.kind != ChangeKind::EcsClose)
            .map(|entry| entry.seq)
            .collect();
        (self.highest_inserted(), pending)
    }

    /// The highest sequence number ever inserted, 0 before the first. It
    /// does not move back when changes leave the ring.
    pub(crate) fn highest_inserted(&self) -> u64 {
        self.highest_inserted.load(Ordering::Acquire)
    }

    /// A successful local-only write also commits a writer sequence number,
    /// even when VOLATILE delivery needs no retained payload. Late readers
    /// are owed only changes after this watermark (DDS 1.4 Sec.2.2.3.4).
    pub(crate) fn record_local_commit(&self, seq: u64) {
        self.highest_inserted.fetch_max(seq, Ordering::Release);
    }

    /// `producer` is about to take an SN, at least `from`, for a change it
    /// journals once made: until the returned guard drops (journaled, or
    /// abandoned), a NACK of an SN from `from` up that the history does not
    /// hold is not answered with a GAP (`in_flight_at_or_below`).
    ///
    /// A change is journaled after its SN is taken, and another producer
    /// (an end of set the Publisher takes the writer's next SN for, from
    /// the thread that ends the set) can take and journal a later SN in
    /// between. A HEARTBEAT then announces the later SN, the reader NACKs
    /// the earlier, and a GAP for it told the reader the change it was
    /// about to receive does not exist.
    ///
    /// `from` is read from the producer's SN counter before it takes; only
    /// the producer itself gives an SN back, so the SN it takes is at least
    /// `from`.
    ///
    /// Ordering, no fence: this store comes before the producer's taking RMW
    /// on the SN counter (AcqRel), whose release part publishes it. A later
    /// SN is taken by an RMW later in the counter's modification order, so
    /// acquires it, and is journaled after; the NACK thread acquires that
    /// journal (`highest_inserted`, the ring's lock) before it reads the
    /// slot (Acquire). A NACK that names an SN no later SN was journaled
    /// above is not GAPped anyway (`is_genuinely_evicted`).
    pub(crate) fn taking(&self, producer: Producer, from: u64) -> InFlight<'_> {
        let slot = &self.in_flight[producer as usize];
        debug_assert_eq!(
            slot.load(Ordering::Relaxed),
            0,
            "one change in flight per producer: a DataWriter is !Sync"
        );
        slot.store(from.max(1), Ordering::Release);
        InFlight { slot }
    }

    /// Whether a change a producer took at or below `seq` is not journaled
    /// yet (`taking`).
    pub(crate) fn in_flight_at_or_below(&self, seq: u64) -> bool {
        self.in_flight.iter().any(|slot| {
            let from = slot.load(Ordering::Acquire);
            from != 0 && from <= seq
        })
    }

    /// Configure LIFESPAN QoS for automatic expired-sample pruning.
    ///
    /// `u64::MAX` disables pruning (INFINITE lifespan).
    pub fn set_lifespan_nanos(&self, nanos: u64) {
        self.lifespan_nanos
            .store(nanos, std::sync::atomic::Ordering::Relaxed);
    }

    /// Prune samples older than the configured LIFESPAN. No-op if disabled.
    fn prune_by_lifespan(&self) {
        let nanos = self
            .lifespan_nanos
            .load(std::sync::atomic::Ordering::Relaxed);
        if nanos != u64::MAX {
            self.prune_expired(nanos);
        }
    }

    /// Insert message into cache (unkeyed, instance_key = 0).
    pub fn insert(&self, seq: u64, payload: &[u8]) -> Result<(), Error> {
        self.insert_keyed(seq, payload, 0)
    }

    /// Insert message into cache with an explicit instance key.
    ///
    /// The instance_key is a hash that identifies the data instance for keyed topics.
    /// For unkeyed topics, use 0.
    ///
    /// Stores no coherent-set markers (`coherent_sn = None`, `group_sn = None`);
    /// use [`insert_coherent`](Self::insert_coherent) for samples written
    /// inside a `begin/end_coherent_changes` window.
    pub fn insert_keyed(&self, seq: u64, payload: &[u8], instance_key: u64) -> Result<(), Error> {
        self.insert_with_metadata(seq, payload, instance_key, ChangeMetadata::user_data())
    }

    /// Insert message into cache with an explicit instance key and optional
    /// coherent-set markers (PID_COHERENT_SET / PID_GROUP_COHERENT_SET_HDDS).
    ///
    /// A NACK-triggered retransmit looks these up via
    /// [`coherent_markers`](Self::coherent_markers) or atomically via
    /// [`get_change`](Self::get_change) and rebuilds the DATA
    /// with those coherent inline-QoS values. Pass `None`/`None` for
    /// non-coherent writes, and for coherent durability modes whose
    /// interoperability path intentionally uses markerless historical repair
    /// bytes (equivalent to [`insert_keyed`](Self::insert_keyed)).
    pub fn insert_coherent(
        &self,
        seq: u64,
        payload: &[u8],
        instance_key: u64,
        coherent_sn: Option<u64>,
        group_sn: Option<u64>,
    ) -> Result<(), Error> {
        self.insert_coherent_with_key_hash(seq, payload, instance_key, coherent_sn, group_sn, None)
    }

    /// Insert message into cache with coherent-set markers and an optional
    /// 16-byte PID_KEY_HASH inline-QoS value.
    ///
    /// Superset of [`insert_coherent`](Self::insert_coherent): also stores
    /// the instance key hash the live DATA carried in its inline QoS, so a
    /// NACK-triggered retransmit can rebuild a keyed coherent DATA with
    /// the identical PID_KEY_HASH as the original live send. Pass `None`
    /// for unkeyed writes (behavior identical to `insert_coherent`).
    pub fn insert_coherent_with_key_hash(
        &self,
        seq: u64,
        payload: &[u8],
        instance_key: u64,
        coherent_sn: Option<u64>,
        group_sn: Option<u64>,
        key_hash: Option<[u8; 16]>,
    ) -> Result<(), Error> {
        self.insert_with_metadata(
            seq,
            payload,
            instance_key,
            ChangeMetadata {
                kind: ChangeKind::UserData,
                coherent_sn,
                group_sn,
                key_hash,
                ..ChangeMetadata::user_data()
            },
        )
    }

    /// Insert an End-of-Coherent-Set (ECS) close-slot entry: empty
    /// payload, [`ChangeKind::EcsClose`], carrying the coherent markers
    /// the live ECS emission put on the wire (RTPS v2.5 SS8.7.5).
    ///
    /// An ECS close slot must NEVER be repaired as an ordinary user DATA:
    /// its payload is empty, so the ordinary small-DATA repair would emit
    /// a payload-less user DATA that a classic receiver may
    /// materialize as an extra sample (one more sample than the writer wrote,
    /// in a coherent set repaired under loss). The NACK repair path reads
    /// `metadata.kind` and regenerates the dialect-correct close form
    /// instead (see `dds::writer::nack::build_ecs_repair_packet`).
    pub fn insert_ecs_close(
        &self,
        seq: u64,
        coherent_sn: Option<u64>,
        group_sn: Option<u64>,
    ) -> Result<(), Error> {
        self.insert_with_metadata(
            seq,
            &[],
            0,
            ChangeMetadata {
                kind: ChangeKind::EcsClose,
                coherent_sn,
                group_sn,
                key_hash: None,
                ..ChangeMetadata::user_data()
            },
        )
    }

    /// Insert a change with the full, explicit [`ChangeMetadata`] --
    /// the one entry point that lets a live-path caller journal
    /// everything it knows about how the change was emitted on the wire
    /// (kind, coherent markers, key hash, source timestamp, CDR version,
    /// fragment size, key epoch), instead of going through a narrower
    /// legacy helper that can only fill a subset.
    ///
    /// `insert_keyed` / `insert_coherent` / `insert_coherent_with_key_hash`
    /// / `insert_ecs_close` are thin wrappers over this same
    /// implementation that default the newer fields (`source_ts`,
    /// `cdr_version`, `frag_size`, `key_epoch`) via
    /// [`ChangeMetadata::user_data`] -- existing callers keep compiling
    /// unchanged. The live write() path (`dds::writer::runtime`) and the
    /// ECS close path (`dds::writer::coherent`) call this directly so
    /// their journaled metadata is honest, not defaulted.
    pub fn insert_with_metadata(
        &self,
        seq: u64,
        payload: &[u8],
        instance_key: u64,
        metadata: ChangeMetadata,
    ) -> Result<(), Error> {
        self.insert_with_metadata_until(seq, payload, instance_key, metadata, None)
    }

    /// [`insert_with_metadata`](Self::insert_with_metadata) that, when the
    /// history is full and nothing may be given up yet, waits until
    /// `deadline` for room (an acknowledgement, a removal) instead of
    /// failing at once. DDS 1.4 2.2.2.4.2.11: a RELIABLE write "may block
    /// [...] waiting for space to become available" for `max_blocking_time`.
    ///
    /// Returns `WouldBlock` if the deadline passes (the caller's TIMEOUT)
    /// and `ResourceLimitExceeded` at once when waiting cannot help.
    pub fn insert_with_metadata_until(
        &self,
        seq: u64,
        payload: &[u8],
        instance_key: u64,
        metadata: ChangeMetadata,
        deadline: Option<Instant>,
    ) -> Result<(), Error> {
        self.insert_grouped_until(seq, payload, instance_key, metadata, None, deadline)
    }

    /// [`insert_with_metadata_until`](Self::insert_with_metadata_until) for
    /// a change of a GROUP Publisher's writer, journaling its group sequence
    /// information `group` with it (`CachedChange::group`).
    pub fn insert_grouped_until(
        &self,
        seq: u64,
        payload: &[u8],
        instance_key: u64,
        metadata: ChangeMetadata,
        group: Option<crate::protocol::group::GroupTag>,
        deadline: Option<Instant>,
    ) -> Result<(), Error> {
        self.insert_until::<true>(seq, payload, instance_key, metadata, group, deadline)
    }

    /// A writer with no coherent access needs no replay-integrity bookkeeping.
    /// GROUP sequence metadata is preserved; mixed public cache users use rich insertion.
    pub(crate) fn insert_plain_until(
        &self,
        seq: u64,
        payload: &[u8],
        instance_key: u64,
        metadata: ChangeMetadata,
        group: Option<crate::protocol::group::GroupTag>,
        deadline: Option<Instant>,
    ) -> Result<(), Error> {
        debug_assert!(metadata.coherent_sn.is_none() && metadata.group_sn.is_none());
        self.insert_until::<false>(seq, payload, instance_key, metadata, group, deadline)
    }

    /// The one door of every insert: a refusal, from whichever path made the
    /// insert (a write's journal, a coherent-set close, a replay), is counted
    /// as `cache_insert_errors` here, so no caller can forget it or swallow it.
    fn insert_until<const TRACK: bool>(
        &self,
        seq: u64,
        payload: &[u8],
        instance_key: u64,
        metadata: ChangeMetadata,
        group: Option<crate::protocol::group::GroupTag>,
        deadline: Option<Instant>,
    ) -> Result<(), Error> {
        let inserted = self.insert_until_uncounted::<TRACK>(
            seq,
            payload,
            instance_key,
            metadata,
            group,
            deadline,
        );
        if inserted.is_err() {
            if let Some(m) = crate::telemetry::get_metrics_opt() {
                m.increment_cache_insert_errors(1);
            }
        }
        inserted
    }

    fn insert_until_uncounted<const TRACK: bool>(
        &self,
        seq: u64,
        payload: &[u8],
        instance_key: u64,
        metadata: ChangeMetadata,
        group: Option<crate::protocol::group::GroupTag>,
        deadline: Option<Instant>,
    ) -> Result<(), Error> {
        let len = payload.len();
        let handle = self.reserve_until(payload, deadline).ok_or_else(|| {
            log::warn!(
                "[HistoryCache] insert dropped for seq={} len={}B: slab pool exhausted \
                 (every primary/large/heap tier returned None). The HistoryCache quota \
                 was not consulted yet.",
                seq,
                len,
            );
            Error::WouldBlock
        })?;

        let entry = CacheEntry {
            seq,
            slab: handle,
            len,
            ts_ns: current_time_ns(),
            instance_key,
            metadata,
        };

        let admitted = {
            let mut ring = match self.ring.lock() {
                Ok(lock) => lock,
                Err(e) => {
                    log::debug!("[HistoryCache::insert] Lock poisoned, recovering");
                    e.into_inner()
                }
            };
            let admitted = loop {
                match self.admit::<TRACK>(&mut ring, entry, group) {
                    Err(Error::WouldBlock) => {
                        let Some(remaining) =
                            deadline.and_then(|d| d.checked_duration_since(Instant::now()))
                        else {
                            break Err(Error::WouldBlock);
                        };
                        ring = self.wait_for_space(ring, remaining);
                    }
                    other => break other,
                }
            };
            admitted
        };

        if admitted.is_err() {
            self.slabs.release(handle);
        } else if self.durability_cleanup_enabled.load(Ordering::Relaxed) {
            self.record_durability_lifecycle(&entry);
        }
        admitted
    }

    /// Update `durability_lifecycle` for the instance `entry` belongs to
    /// (DDS v1.4 Sec.2.2.3.5), called once per successful `insert` while
    /// `durability_cleanup_enabled` is set. A marker (a coherent-set
    /// close, which is a change of no instance) is never tracked.
    fn record_durability_lifecycle(&self, entry: &CacheEntry) {
        let id = InstanceId::of(entry);
        if id == InstanceId::Marker {
            return;
        }
        let mut map = match self.durability_lifecycle.lock() {
            Ok(guard) => guard,
            Err(e) => {
                log::debug!(
                    "[HistoryCache::record_durability_lifecycle] Lock poisoned, recovering"
                );
                e.into_inner()
            }
        };
        let life = map.entry(id).or_default();
        life.seq = entry.seq;
        match entry.metadata.status_info {
            // A plain write revives the instance: the rule starts over.
            None => {
                life.disposed_at = None;
                life.unregistered_at = None;
            }
            Some(crate::protocol::builder::StatusInfoKind::Disposed) => {
                life.disposed_at = Some(entry.ts_ns);
            }
            Some(crate::protocol::builder::StatusInfoKind::Unregistered) => {
                life.unregistered_at = Some(entry.ts_ns);
            }
            Some(crate::protocol::builder::StatusInfoKind::DisposedUnregistered) => {
                life.disposed_at = Some(entry.ts_ns);
                life.unregistered_at = Some(entry.ts_ns);
            }
        }
    }

    /// Start tracking `durability_lifecycle` from this call onward (DDS
    /// v1.4 Sec.2.2.3.5): called once, only by a writer whose durability
    /// and configured `service_cleanup_delay` make
    /// `remove_durability_expired` reachable at all (`WriterBuilder`,
    /// before the writer is handed to its caller, so no `insert` can
    /// race it). Every other writer's `insert` pays for one relaxed load
    /// that stays false forever.
    pub(crate) fn enable_durability_cleanup(&self) {
        self.durability_cleanup_enabled
            .store(true, Ordering::Relaxed);
    }

    /// Copy `payload` into the slab pool, waiting until `deadline` for
    /// memory when the pool is exhausted.
    ///
    /// The pool is process-wide and backs every unacknowledged change of
    /// every writer: when it runs out, the room comes back as readers
    /// acknowledge. DDS 1.4 2.2.3.18 (KEEP_ALL, RELIABLE): "the Service
    /// will block the DataWriter until it can deliver the necessary old
    /// values", and 2.2.2.4.2.11 bounds that wait by `max_blocking_time`.
    /// A write that finds the pool empty therefore waits here, as `admit`
    /// does for the same reason, instead of failing at once whatever its
    /// `max_blocking_time`.
    ///
    /// The wait is sliced: a slot freed by ANOTHER cache (another writer,
    /// a reader the application drains) wakes nobody here, and a release
    /// between a failed attempt and the wait would otherwise be missed.
    /// `None` without a deadline, or once it has passed.
    fn reserve_until(&self, payload: &[u8], deadline: Option<Instant>) -> Option<SlabHandle> {
        const SLICE: std::time::Duration = std::time::Duration::from_millis(5);
        loop {
            if let Some((handle, _metric)) = self.slabs.reserve_and_write(payload, Claim::Writer) {
                return Some(handle);
            }
            let remaining = deadline?.checked_duration_since(Instant::now())?;
            let ring = match self.ring.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            drop(self.wait_for_space(ring, remaining.min(SLICE)));
        }
    }

    /// Store `entry` if HISTORY and RESOURCE_LIMITS allow it, evicting what
    /// KEEP_LAST allows to make room. Runs under the ring lock.
    ///
    /// Errors, mapped to what DDS 1.4 2.2.2.4.2.11 lets `write` report:
    /// - `ResourceLimitExceeded`: a new instance beyond `max_instances`.
    ///   Waiting frees nothing (only an unregistration could), which is the
    ///   OUT_OF_RESOURCES case.
    /// - `WouldBlock`: the history is full and nothing may be evicted
    ///   (KEEP_ALL at any limit, or KEEP_LAST with every retained instance
    ///   down to its last sample). The case in which a RELIABLE writer may
    ///   block for `max_blocking_time`.
    fn admit<const TRACK: bool>(
        &self,
        ring: &mut Ring,
        entry: CacheEntry,
        group: Option<crate::protocol::group::GroupTag>,
    ) -> Result<(), Error> {
        if TRACK && !ring.replay_empty.is_empty() {
            ring.prune_replay_sets(self.in_flight_at_or_below(ring.replay_closed_before));
        }
        let id = InstanceId::of(&entry);
        let len = entry.len;

        if id != InstanceId::Marker
            && ring.count(id) == 0
            && self.max_instances != LENGTH_UNLIMITED
            && ring.data_instances() >= self.max_instances
        {
            return Err(Error::ResourceLimitExceeded(format!(
                "max_instances ({}) reached; a new instance cannot be stored",
                self.max_instances
            )));
        }
        // A VOLATILE writer owes nothing every reader already holds: drop
        // it before deciding whether there is room (RTPS 2.5 8.4.1 step
        // 22). With no reliable reader matched the floor is `u64::MAX` and
        // only the change being written stays.
        if !self.keep_acknowledged.load(Ordering::Relaxed) {
            let floor = self.acked_floor.load(Ordering::Acquire);
            while ring.front().is_some_and(|first| first.seq <= floor) {
                self.discard_mode::<TRACK>(ring, 0);
            }
        }
        if len > self.max_quota_bytes {
            return Err(Error::ResourceLimitExceeded(format!(
                "a {len}-byte sample can never fit a {}-byte history quota",
                self.max_quota_bytes
            )));
        }

        match self.history_kind {
            History::KeepAll => {
                let per_instance_full = id != InstanceId::Marker
                    && self.max_samples_per_instance != LENGTH_UNLIMITED
                    && ring.count(id) >= self.max_samples_per_instance;
                if per_instance_full {
                    let Some(index) = self.releasable(ring, Some(id)) else {
                        return Err(Error::WouldBlock);
                    };
                    self.discard_mode::<TRACK>(ring, index);
                }
                while id != InstanceId::Marker
                    && (ring.data_len() >= self.max_samples
                        || self.quota_bytes.load(Ordering::Relaxed).saturating_add(len)
                            > self.max_quota_bytes)
                {
                    let Some(index) = self.releasable(ring, None) else {
                        return Err(Error::WouldBlock);
                    };
                    self.discard_mode::<TRACK>(ring, index);
                }
            }
            History::KeepLast(depth) => {
                // `depth <= max_samples_per_instance` is a creation-time
                // consistency rule (DDS 1.4 2.2.3.18); take the lower of the
                // two so a cache built without that check stays bounded.
                let depth = usize::try_from(depth).unwrap_or(usize::MAX);
                let keep = depth.min(self.max_samples_per_instance).max(1);
                if id != InstanceId::Marker && ring.count(id) >= keep {
                    if let Some(index) = ring.oldest_of(id) {
                        self.discard_mode::<TRACK>(ring, index);
                    }
                }
                while id != InstanceId::Marker
                    && (ring.data_len() >= self.max_samples
                        || self.quota_bytes.load(Ordering::Relaxed).saturating_add(len)
                            > self.max_quota_bytes)
                {
                    // BEST_EFFORT may drop samples outright (DDS 1.4
                    // 2.2.3.19); only a RELIABLE writer blocks here.
                    let spare = ring.oldest_spare(id).or_else(|| {
                        (!self.reliable.load(Ordering::Relaxed) && !ring.is_empty()).then_some(0)
                    });
                    let Some(index) = spare else {
                        return Err(Error::WouldBlock);
                    };
                    self.discard_mode::<TRACK>(ring, index);
                }
            }
        }

        self.quota_bytes.fetch_add(len, Ordering::Relaxed);
        self.highest_inserted.fetch_max(entry.seq, Ordering::AcqRel);
        ring.push_back::<TRACK>(entry, group);
        self.release_orphan_markers(ring);
        Ok(())
    }

    /// Give up the oldest close markers whose set has no member left (RTPS
    /// v2.5 Sec.8.7.6: a close "can only be removed [...] when all data
    /// samples belonging to the coherent set are removed") beyond the depth
    /// a data instance is kept to (KEEP_LAST depth, `max_samples` under
    /// KEEP_ALL): a close of a set with no member left stays repairable as
    /// long as an instance's latest changes do. A close whose set keeps a
    /// member is never given up. RELIABLE KEEP_ALL gives up only an
    /// acknowledged one.
    fn release_orphan_markers(&self, ring: &mut Ring) {
        let orphans = ring.orphan_markers();
        let (bound, any) = match self.history_kind {
            History::KeepLast(depth) => (
                usize::try_from(depth)
                    .unwrap_or(usize::MAX)
                    .min(self.max_samples_per_instance)
                    .max(1),
                true,
            ),
            History::KeepAll => (self.max_samples, !self.reliable.load(Ordering::Relaxed)),
        };
        if orphans.len() <= bound {
            return;
        }
        let orphans = ring.without_retained(orphans);
        let Some(excess) = orphans.len().checked_sub(bound).filter(|&n| n > 0) else {
            return;
        };
        let floor = self.acked_floor.load(Ordering::Acquire);
        for &index in orphans[..excess].iter().rev() {
            if any || ring[index].seq <= floor {
                self.discard(ring, index);
            }
        }
    }

    /// The oldest change a full KEEP_ALL history may give up, optionally
    /// limited to one instance. RELIABLE: only one every matched reader has
    /// acknowledged - "block the DataWriter until it can deliver the
    /// necessary old values to all subscribers" (DDS 1.4 2.2.3.18).
    /// BEST_EFFORT: any, "the old values will be discarded".
    fn releasable(&self, ring: &Ring, of: Option<InstanceId>) -> Option<usize> {
        let floor = self.acked_floor.load(Ordering::Acquire);
        let any = !self.reliable.load(Ordering::Relaxed);
        ring.oldest_where(|e| {
            InstanceId::of(e) != InstanceId::Marker
                && of.is_none_or(|id| InstanceId::of(e) == id)
                && (any || e.seq <= floor)
        })
    }

    /// Remove the change at `index` and give back its slab and quota.
    fn discard(&self, ring: &mut Ring, index: usize) {
        self.discard_mode::<true>(ring, index);
    }

    fn discard_mode<const TRACK: bool>(&self, ring: &mut Ring, index: usize) {
        if let Some(evicted) = ring.remove_mode::<TRACK>(index) {
            self.slabs.release(evicted.slab);
            self.quota_bytes.fetch_sub(evicted.len, Ordering::Relaxed);
        }
    }

    /// Get message by sequence number.
    ///
    /// Thin wrapper over [`get_change`](Self::get_change) returning the
    /// payload only; semantics are byte-identical to the historical `get`.
    pub fn get(&self, seq: u64) -> Option<Vec<u8>> {
        self.get_change(seq).map(|change| change.payload)
    }

    /// Atomically snapshot one cached change (payload + typed metadata).
    ///
    /// Payload bytes and [`ChangeMetadata`] are copied under a SINGLE
    /// ring-lock acquisition, so a caller can never observe a payload
    /// from one cache state and metadata from another (e.g. a concurrent
    /// eviction landing between two separate lookups).
    ///
    /// Returns `None` if `seq` is not in the cache (evicted, expired, or
    /// never written).
    pub fn get_change(&self, seq: u64) -> Option<CachedChange> {
        self.prune_by_lifespan();
        let ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::get_change] Lock poisoned, recovering");
                e.into_inner()
            }
        };
        let entry = ring.iter().find(|e| e.seq == seq)?;
        let buf = self.slabs.get_buffer(entry.slab);
        Some(CachedChange {
            seq: entry.seq,
            payload: buf[..entry.len].to_vec(),
            metadata: entry.metadata,
            group: ring.group_of(entry.seq),
        })
    }

    /// Look up the coherent-set markers stored for `seq` (see
    /// [`insert_coherent`](Self::insert_coherent)), for a NACK-triggered
    /// retransmit to rebuild the DATA with the same PID_COHERENT_SET /
    /// PID_GROUP_COHERENT_SET_HDDS inline QoS as the original live write.
    ///
    /// Returns `None` if `seq` is not in the cache (evicted or never
    /// written). Returns `Some((None, None))` for a cached non-coherent
    /// sample.
    ///
    /// NOTE: this is a separate lookup from [`get`](Self::get); callers
    /// that need payload AND markers consistently should use
    /// [`get_change`](Self::get_change) instead.
    pub fn coherent_markers(&self, seq: u64) -> Option<(Option<u64>, Option<u64>)> {
        let ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::coherent_markers] Lock poisoned, recovering");
                e.into_inner()
            }
        };
        ring.iter()
            .find(|e| e.seq == seq)
            .map(|e| (e.metadata.coherent_sn, e.metadata.group_sn))
    }

    /// Tests only: how many changes hold group sequence information.
    #[cfg(test)]
    pub(crate) fn group_entries_for_test(&self) -> usize {
        self.ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .groups
            .len()
    }

    /// Get number of cached messages.
    pub fn len(&self) -> usize {
        match self.ring.lock() {
            Ok(lock) => lock.len(),
            Err(e) => {
                log::debug!("[HistoryCache::len] Lock poisoned, recovering");
                e.into_inner().len()
            }
        }
    }

    /// Check if cache is empty.
    pub fn is_empty(&self) -> bool {
        match self.ring.lock() {
            Ok(lock) => lock.is_empty(),
            Err(e) => {
                log::debug!("[HistoryCache::is_empty] Lock poisoned, recovering");
                e.into_inner().is_empty()
            }
        }
    }

    /// Get current quota usage in bytes.
    pub fn quota_bytes(&self) -> usize {
        self.quota_bytes.load(Ordering::Relaxed)
    }

    /// Expose configured sample capacity.
    #[must_use]
    pub fn max_samples(&self) -> usize {
        self.max_samples
    }

    /// Expose configured quota limit in bytes.
    #[must_use]
    pub fn max_quota_bytes(&self) -> usize {
        self.max_quota_bytes
    }

    /// Expose configured history policy.
    #[must_use]
    pub fn history_kind(&self) -> History {
        self.history_kind
    }

    /// Snapshot all cached samples for late-joiner delivery.
    pub fn get_all_samples(&self) -> Vec<(u64, SlabHandle, usize)> {
        self.prune_by_lifespan();
        let ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::get_all_samples] Lock poisoned, recovering");
                e.into_inner()
            }
        };
        ring.iter().map(|e| (e.seq, e.slab, e.len)).collect()
    }

    /// Snapshot all cached samples for TRANSIENT_LOCAL late-joiner
    /// replay, taking ONE slab reference per returned handle.
    ///
    /// The increment happens under the ring lock, while the cache's own
    /// persistent reference on each entry is provably still held (every
    /// eviction path also runs under this lock before it releases), so
    /// it can never resurrect a freed slot. The caller owns the returned
    /// references: hand each one to a reader ring push, or release it on
    /// any skip/drop path.
    ///
    /// Each tuple carries the CDR version the payload was encoded with
    /// (journaled at insert time), so the replayed ring entry decodes the
    /// bytes the way the live entry did instead of assuming the default.
    pub fn snapshot_samples_for_replay(
        &self,
    ) -> Vec<(u64, SlabHandle, usize, crate::dds::CdrVersion)> {
        self.snapshot_for_local_replay()
            .into_iter()
            .map(|c| (c.seq, c.slab, c.len, c.cdr_version))
            .collect()
    }

    /// [`snapshot_samples_for_replay`](Self::snapshot_samples_for_replay)
    /// with what a local late joiner needs besides the bytes: whether the
    /// change is an instance lifecycle change, and its instance. The same
    /// reference discipline: one slab reference per returned handle, taken
    /// under the ring lock, owned by the caller.
    pub(crate) fn snapshot_for_local_replay(&self) -> Vec<LocalReplayChange> {
        self.prune_by_lifespan();
        let ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::snapshot_for_local_replay] Lock poisoned, recovering");
                e.into_inner()
            }
        };
        // A coherent-set member (`metadata.coherent_sn.is_some()`) is owed
        // to a late joiner only once its set has actually closed in THIS
        // snapshot (DDS v1.4 SS2.2.2.4.1.10/11, RTPS v2.5 SS8.7.6): an
        // all-or-nothing set delivered in part to a coherent-access reader
        // is worse than one not delivered at all. An `EcsClose` entry
        // takes a fresh writer SN strictly AFTER every member of the set
        // it closes (`WriterCoherentBridge::emit_ecs_data` /
        // `journal_ecs_close`), so the highest
        // retained `EcsClose` SN is the boundary: any member at or above
        // it belongs to a set that never closed, or closed after this
        // snapshot, and must not leak to a late joiner. Sets are
        // sequential and non-overlapping per writer (`PublisherCore`
        // allows exactly one open set at a time), so this single boundary
        // -- not a per-set range match -- identifies the closed range.
        // A stamped write can still be outstanding when an ECS is
        // journaled. GROUP local replay therefore also consults its live
        // collector before publishing this snapshot.
        //
        // `EcsClose` entries themselves carry no payload and are never
        // replayed as a sample either way: unlike the wire leg (whose
        // late joiner decodes PID_COHERENT_SET itself and stages/commits
        // sets the same way it would live), the intra-process merger ring
        // has no such per-entry decoding, so withholding happens HERE,
        // once, rather than at every reader that binds later.
        let closed_before: u64 = ring
            .iter()
            .filter(|e| e.metadata.kind == ChangeKind::EcsClose)
            .map(|e| e.seq)
            .max()
            .unwrap_or(0);
        let mut valid_sets = HashMap::new();
        ring.iter()
            .filter(|e| e.metadata.kind != ChangeKind::EcsClose)
            .filter(|e| e.metadata.coherent_sn.is_none() || e.seq < closed_before)
            .filter(|e| {
                let identity = e
                    .metadata
                    .group_sn
                    .map(|set| (true, set))
                    .or_else(|| e.metadata.coherent_sn.map(|first| (false, first)));
                identity.is_none_or(|identity| {
                    *valid_sets
                        .entry(identity)
                        .or_insert_with(|| ring.replayable(e))
                })
            })
            .map(|e| {
                self.slabs.add_ref(e.slab);
                LocalReplayChange {
                    coherent_replay_valid: ring.replay_ticket(e),
                    coherent_replay_admission: e
                        .metadata
                        .coherent_sn
                        .and(e.metadata.group_sn)
                        .and_then(|set| ring.replay_integrity.as_ref()?.admission(set)),
                    seq: e.seq,
                    coherent_sn: e.metadata.coherent_sn,
                    group_sn: e.metadata.group_sn,
                    gsn: ring.group_of(e.seq).map(|tag| tag.gsn),
                    key_hash: e.metadata.key_hash,
                    slab: e.slab,
                    len: e.len,
                    cdr_version: e.metadata.cdr_version,
                    source_timestamp_ns: e.metadata.source_ts_known.then(|| {
                        let (sec, frac) = e.metadata.source_ts;
                        u64::from(sec) * 1_000_000_000 + ((u64::from(frac) * 1_000_000_000) >> 32)
                    }),
                    lifecycle: e
                        .metadata
                        .status_info
                        .map(|status| (status, e.metadata.key_hash.unwrap_or([0; 16]))),
                }
            })
            .collect()
    }

    /// Snapshot all cached payloads (seq + bytes) for late-joiner replay.
    pub fn snapshot_payloads(&self) -> Vec<(u64, Vec<u8>)> {
        self.prune_by_lifespan();
        let ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::snapshot_payloads] Lock poisoned, recovering");
                e.into_inner()
            }
        };

        ring.iter()
            .map(|entry| {
                let buf = self.slabs.get_buffer(entry.slab);
                (entry.seq, buf[..entry.len].to_vec())
            })
            .collect()
    }

    /// Snapshot all cached changes (payload + typed metadata) for repair
    /// and inspection, including surviving fragments of coherent sets.
    ///
    /// Superset of [`snapshot_payloads`](Self::snapshot_payloads): each
    /// returned [`CachedChange`] carries `kind`, `coherent_sn`, `group_sn`
    /// and `key_hash` alongside the payload, so repair preserves the same
    /// logical RTPS change as the original live send. The late-joiner path
    /// uses `snapshot_changes_for_replay` to enforce whole-set integrity.
    pub fn snapshot_changes(&self) -> Vec<CachedChange> {
        self.prune_by_lifespan();
        let ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::snapshot_changes] Lock poisoned, recovering");
                e.into_inner()
            }
        };

        ring.iter()
            .map(|entry| {
                let buf = self.slabs.get_buffer(entry.slab);
                CachedChange {
                    seq: entry.seq,
                    payload: buf[..entry.len].to_vec(),
                    metadata: entry.metadata,
                    group: ring.group_of(entry.seq),
                }
            })
            .collect()
    }

    /// Typed late-joiner replay omits retained data fragments of damaged
    /// coherent sets. End markers remain available, as RTPS 2.5 8.7.6
    /// requires; repair and inspection use snapshot_changes.
    pub(crate) fn snapshot_changes_for_replay(&self) -> Vec<CachedChange> {
        self.prune_by_lifespan();
        let ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        let mut valid_sets: HashMap<(bool, u64), bool> = HashMap::new();
        ring.iter()
            .filter(|entry| {
                if entry.metadata.kind == ChangeKind::EcsClose {
                    return true;
                }
                let identity = entry
                    .metadata
                    .group_sn
                    .map(|set| (true, set))
                    .or_else(|| entry.metadata.coherent_sn.map(|first| (false, first)));
                identity.is_none_or(|identity| {
                    *valid_sets
                        .entry(identity)
                        .or_insert_with(|| ring.replayable(entry))
                })
            })
            .map(|entry| {
                let buf = self.slabs.get_buffer(entry.slab);
                CachedChange {
                    seq: entry.seq,
                    payload: buf[..entry.len].to_vec(),
                    metadata: entry.metadata,
                    group: ring.group_of(entry.seq),
                }
            })
            .collect()
    }

    /// Snapshot cached payloads for late-joiner replay, limited by DurabilityService constraints.
    ///
    /// Returns only the most recent `max_replay_samples` samples.
    /// If `max_replay_samples` is LENGTH_UNLIMITED, returns all cached samples.
    pub fn snapshot_payloads_limited(&self, max_replay_samples: usize) -> Vec<(u64, Vec<u8>)> {
        self.prune_by_lifespan();
        let ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::snapshot_payloads_limited] Lock poisoned, recovering");
                e.into_inner()
            }
        };

        let total = ring.len();
        let skip = if max_replay_samples >= total || max_replay_samples == LENGTH_UNLIMITED {
            0
        } else {
            total - max_replay_samples
        };

        ring.iter()
            .skip(skip)
            .map(|entry| {
                let buf = self.slabs.get_buffer(entry.slab);
                (entry.seq, buf[..entry.len].to_vec())
            })
            .collect()
    }

    /// Expose configured max_instances limit.
    #[must_use]
    pub fn max_instances(&self) -> usize {
        self.max_instances
    }

    /// Expose configured max_samples_per_instance limit.
    #[must_use]
    pub fn max_samples_per_instance(&self) -> usize {
        self.max_samples_per_instance
    }

    /// Count distinct data instances currently in the cache (coherent-set
    /// close markers belong to no instance and are not counted).
    pub fn instance_count(&self) -> usize {
        let ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::instance_count] Lock poisoned, recovering");
                e.into_inner()
            }
        };
        ring.data_instances()
    }

    /// Count samples inserted with `instance_key` and no key hash (the
    /// [`insert_keyed`](Self::insert_keyed) family). A change that carries a
    /// key hash is accounted to that hash, not to `instance_key`.
    pub fn samples_for_instance(&self, instance_key: u64) -> usize {
        let ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::samples_for_instance] Lock poisoned, recovering");
                e.into_inner()
            }
        };
        ring.count(InstanceId::Legacy(instance_key))
    }

    /// Remove samples whose age (now - insertion time) exceeds `max_age_nanos`.
    ///
    /// Used by DataWriter to enforce LIFESPAN QoS (DDS 2.2.2.4.2.20): expired
    /// samples MUST NOT be retransmitted to readers. Samples are removed from
    /// the front of the FIFO (oldest first) and stop as soon as a non-expired
    /// sample is found, since entries are inserted in monotonic-timestamp order.
    ///
    /// Returns the number of samples removed.
    pub fn prune_expired(&self, max_age_nanos: u64) -> usize {
        if max_age_nanos == u64::MAX {
            return 0;
        }
        let mut removed = 0;
        let now = current_time_ns();
        let cutoff = now.saturating_sub(max_age_nanos);
        let mut ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::prune_expired] Lock poisoned, recovering");
                e.into_inner()
            }
        };

        while let Some(front) = ring.front() {
            if front.ts_ns < cutoff {
                let Some(entry) = ring.pop_front() else {
                    unreachable!("front() returned Some, pop_front must succeed")
                };
                self.slabs.release(entry.slab);
                self.quota_bytes.fetch_sub(entry.len, Ordering::Relaxed);
                removed += 1;
            } else {
                break;
            }
        }

        drop(ring);
        if removed > 0 {
            self.space.notify_all();
        }
        removed
    }

    /// DDS v1.4 Sec.2.2.3.5: remove every cached change of an instance once
    /// all three of the spec's conditions hold:
    ///
    /// 1. the instance has been explicitly disposed;
    /// 2. no live DataWriter is still writing it (for this single-writer
    ///    history, that is this writer itself: it has also unregistered
    ///    the instance, whether in the SAME change as the dispose --
    ///    `StatusInfoKind::DisposedUnregistered`, the DDS default
    ///    autodispose lifecycle -- or a later, separate one, the
    ///    `manual_dispose` policy's explicit `dispose()` then
    ///    `unregister_instance()`);
    /// 3. `delay_nanos` has elapsed since the LATER of the two.
    ///
    /// An instance disposed but not (yet, or ever) unregistered, or
    /// unregistered without ever being disposed, meets only one
    /// condition and is left alone, as is one still short of the delay
    /// since the later event. A write to the instance after either
    /// revives it (`record_durability_lifecycle`): the rule starts over.
    /// Every matched RELIABLE reader must also have acknowledged its
    /// latest change (`acked_seq`): this is DURABILITY_SERVICE cleanup,
    /// not a license to drop what a reader has not caught up to yet.
    ///
    /// Reads only `durability_lifecycle` (bounded by the number of
    /// distinct instances ever written, not the ring's size) to decide
    /// what is eligible, then visits the ring once, only when something
    /// is (`Ring::retain_not_in`, one O(n) pass): no whole-ring scan to
    /// decide, and no per-entry `O(n)` removal in a loop.
    ///
    /// Returns the number of entries removed.
    pub fn remove_durability_expired(
        &self,
        acked_seq: u64,
        delay_nanos: u64,
        now_ns: u64,
    ) -> usize {
        if !self.durability_cleanup_enabled.load(Ordering::Relaxed) {
            return 0;
        }

        let eligible: std::collections::HashSet<InstanceId> = {
            let map = match self.durability_lifecycle.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    log::debug!(
                        "[HistoryCache::remove_durability_expired] Lock poisoned, recovering"
                    );
                    e.into_inner()
                }
            };
            map.iter()
                .filter_map(|(id, life)| {
                    let disposed_at = life.disposed_at?;
                    let unregistered_at = life.unregistered_at?;
                    let since = disposed_at.max(unregistered_at);
                    (life.seq <= acked_seq && now_ns.saturating_sub(since) >= delay_nanos)
                        .then_some(*id)
                })
                .collect()
        };
        if eligible.is_empty() {
            return 0;
        }

        let removed_entries = {
            let mut ring = match self.ring.lock() {
                Ok(lock) => lock,
                Err(e) => {
                    log::debug!(
                        "[HistoryCache::remove_durability_expired] Lock poisoned, recovering"
                    );
                    e.into_inner()
                }
            };
            ring.retain_not_in(&eligible)
        };
        for evicted in &removed_entries {
            self.slabs.release(evicted.slab);
            self.quota_bytes.fetch_sub(evicted.len, Ordering::Relaxed);
        }
        let removed = removed_entries.len();

        if removed > 0 {
            // Gone from the ring entirely: forget their lifecycle too, so
            // the map stays bounded by instances CURRENTLY in the ring,
            // not every instance ever disposed across the writer's life.
            let mut map = match self.durability_lifecycle.lock() {
                Ok(guard) => guard,
                Err(e) => e.into_inner(),
            };
            for id in &eligible {
                map.remove(id);
            }
            drop(map);
            self.space.notify_all();
        }
        removed
    }

    /// Remove all samples acknowledged by all readers (seqs <= acked_seq).
    ///
    /// Returns the number of samples removed.
    pub fn remove_acknowledged(&self, acked_seq: u64) -> usize {
        let mut removed = 0;
        let mut ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::remove_acknowledged] Lock poisoned, recovering");
                e.into_inner()
            }
        };

        while let Some(front) = ring.front() {
            if front.seq <= acked_seq {
                let Some(entry) = ring.pop_front() else {
                    unreachable!("front() returned Some, pop_front must succeed")
                };
                self.slabs.release(entry.slab);
                self.quota_bytes.fetch_sub(entry.len, Ordering::Relaxed);
                removed += 1;
            } else {
                break;
            }
        }

        drop(ring);
        if removed > 0 {
            self.space.notify_all();
        }
        removed
    }

    /// The group sequence numbers a GROUP Publisher's writer announces in a
    /// HEARTBEAT for the changes `first_seq..=last_seq` (RTPS v2.5
    /// Sec.8.3.8.6): the GSN of the first and of the last of them that the
    /// history holds, and the GSN of the first change it holds above
    /// `last_seq` (made, not yet announced). All `None` for any other
    /// writer, whose history holds no group sequence number.
    pub fn group_window(&self, first_seq: u64, last_seq: u64) -> GroupWindow {
        let ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        if ring.groups.is_empty() {
            return GroupWindow::default();
        }
        let mut window = GroupWindow::default();
        if first_seq <= last_seq {
            let mut announced = ring.groups.range(first_seq..=last_seq);
            window.first_gsn = announced.next().map(|(_, tag)| tag.gsn);
            window.last_gsn = announced
                .next_back()
                .map(|(_, tag)| tag.gsn)
                .or(window.first_gsn);
        }
        window.unannounced_gsn = last_seq
            .checked_add(1)
            .and_then(|above| ring.groups.range(above..).next())
            .map(|(_, tag)| tag.gsn);
        window
    }

    /// Remember that change `seq`, of GSN `gsn`, of a GROUP Publisher's
    /// writer was taken and will never be made (D16), so a GAP repairing
    /// that SN for a reader of the spec class names the GSN too (RTPS v2.5
    /// Sec.8.3.8.4 gapStartGSN/gapEndGSN). Only the newest
    /// `MAX_GROUP_HOLES` are kept: holes are rare (an SN and a GSN another
    /// change took past before this one was abandoned), and a GSN no GAP
    /// names is still announced absent by the HEARTBEAT's GroupInfo.
    pub fn record_group_hole(&self, seq: u64, gsn: u64) {
        let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        ring.group_holes.insert(seq, gsn);
        while ring.group_holes.len() > MAX_GROUP_HOLES {
            ring.group_holes.pop_first();
        }
    }

    /// The holes (`record_group_hole`) with SNs in `from..=to`, as (SN,
    /// GSN), in SN order.
    pub fn group_holes_in(&self, from: u64, to: u64) -> Vec<(u64, u64)> {
        let ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        if ring.group_holes.is_empty() || from > to {
            return Vec::new();
        }
        ring.group_holes
            .range(from..=to)
            .map(|(seq, gsn)| (*seq, *gsn))
            .collect()
    }

    /// Get oldest sequence number in cache.
    pub fn oldest_seq(&self) -> Option<u64> {
        self.prune_by_lifespan();
        let ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::oldest_seq] Lock poisoned, recovering");
                e.into_inner()
            }
        };
        ring.front().map(|e| e.seq)
    }

    /// The lowest end-of-set marker (`ChangeKind::EcsClose`) still retained.
    /// A retained marker is unacknowledged by at least one matched reader
    /// until it leaves the history (`set_acked_floor`).
    pub(crate) fn lowest_retained_end_of_set(&self) -> Option<u64> {
        let ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        ring.iter()
            .find(|entry| entry.metadata.kind == ChangeKind::EcsClose)
            .map(|entry| entry.seq)
    }

    /// Get newest sequence number in cache.
    pub fn newest_seq(&self) -> Option<u64> {
        let ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::newest_seq] Lock poisoned, recovering");
                e.into_inner()
            }
        };
        ring.back().map(|e| e.seq)
    }

    /// Evict oldest entry from cache.
    pub fn evict_oldest(&self) -> Option<u64> {
        let entry = {
            let mut ring = match self.ring.lock() {
                Ok(lock) => lock,
                Err(e) => {
                    log::debug!("[HistoryCache::evict_oldest] Lock poisoned, recovering");
                    e.into_inner()
                }
            };
            ring.pop_front()?
        };
        self.slabs.release(entry.slab);
        self.quota_bytes.fetch_sub(entry.len, Ordering::Relaxed);
        self.space.notify_all();
        Some(entry.seq)
    }

    /// Clear all entries from cache.
    pub fn clear(&self) {
        self.clear_mode::<true>();
    }

    fn clear_mode<const TRACK: bool>(&self) {
        let mut ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::clear] Lock poisoned, recovering");
                e.into_inner()
            }
        };
        while let Some(entry) = ring.pop_front_mode::<TRACK>() {
            self.slabs.release(entry.slab);
        }
        self.quota_bytes.store(0, Ordering::Relaxed);
        drop(ring);
        self.space.notify_all();
    }
}

impl Drop for HistoryCache {
    fn drop(&mut self) {
        // Existing snapshots own every captured byte. Whole-cache teardown
        // releases residency without damaging those already complete snapshots.
        self.ring
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .leave_retention();
        self.clear_mode::<false>();
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
#[path = "history_cache_test.rs"]
mod tests;
