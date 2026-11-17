// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Fragment reassembly buffer for RTPS DATA_FRAG submessages.
//!
//
// Large discovery messages (SPDP, SEDP) may arrive as fragmented DATA_FRAG
// packets. Fragments can arrive out-of-order or some may be missing. This module
// implements a production-grade fragment buffer with:
//
// - Out-of-order fragment reassembly
// - Timeout-based eviction for incomplete sequences
// - Fair overflow eviction, by source participant (GUID prefix)
// - Memory-bounded operation, in sequences and in octets
//
// RTPS v2.5 spec Sec.8.3.8.3: DATA_FRAG Submessage

use crate::core::discovery::multicast::control_types::ENTITYID_UNKNOWN;
use crate::core::discovery::multicast::{FragmentGeometry, Origin};
use crate::core::discovery::{EndpointRegistry, GUID};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Fragment reassembly buffer.
///
/// Buffers incoming DATA_FRAG fragments by (writerGUID, seqNum) and reassembles
/// them into complete payloads when all fragments are received.
///
/// # Memory Management
///
/// - `max_pending`: Maximum number of incomplete sequences (default: 256)
/// - `max_bytes`: Maximum number of octets held across every sequence, each
///   charged its whole sample buffer, bitmap and bookkeeping from its first
///   fragment (`with_max_bytes`, default [`DEFAULT_MAX_BUFFERED_BYTES`])
/// - `timeout_ms`: Evict incomplete sequences after this duration (default: 500ms)
///
/// Room is made when a sequence opens (`plan_room`), never later. Sources
/// are of two classes, told apart by the [`KnownSources`] attached
/// (`with_known_sources`; with none, every source is known):
///
/// - Sources not known (a prefix no discovery has seen: anyone may forge
///   one) share ONE pool of a quarter of each bound, and a sequence of
///   theirs may cost at most the pool's octets over its sequences. Among
///   them the sequence idle longest goes. They never evict a known source,
///   and a known source evicts them first.
/// - Among known sources, the sequence furthest from completion goes, each
///   writer offering only its newest; a participant opening its first
///   sequence is never its own victim. A participant's most advanced
///   sequence goes only for one further along, and one past half its
///   sample's octets only for a higher rank (`known_victim`), each for the
///   timeout from its first fragment.
/// - Sequences idle past the timeout go first, in every buffer, whenever
///   room is made (`make_room`), timer or not.
///
/// # Usage
///
/// ```ignore
/// let mut buffer = FragmentBuffer::new(256, 500);
/// // 4 fragments of 1024 octets: the sample is 4096 octets long.
/// let geometry = FragmentGeometry { fragment_size: 1024, sample_size: 4096 };
///
/// // Insert fragment #3
/// let result = buffer.insert_fragment(writer_guid, seq_num, 3, geometry, fragment3_data);
/// assert!(result.is_none()); // Incomplete
///
/// // Insert fragment #1
/// let result = buffer.insert_fragment(writer_guid, seq_num, 1, geometry, fragment1_data);
/// assert!(result.is_none()); // Still incomplete
///
/// // Insert fragment #2 and #4
/// buffer.insert_fragment(writer_guid, seq_num, 2, 4, fragment2_data);
/// let result = buffer.insert_fragment(writer_guid, seq_num, 4, geometry, fragment4_data);
///
/// // Complete! Returns reassembled payload
/// assert!(result.is_some());
/// let complete_payload = result.unwrap();
/// ```
pub struct FragmentBuffer {
    /// Pending incomplete sequences: (writerGUID, seqNum) -> FragmentSet
    pending: HashMap<(GUID, u64), FragmentSet>,

    /// Maximum number of pending sequences (`plan_room` past it)
    max_pending: usize,

    /// Maximum number of octets held across every pending sequence, each
    /// charged what it allocates (`charge_for`) when it opens
    /// (`plan_room` past it). A sequence that would cost more could never
    /// complete and is refused at its first fragment.
    max_bytes: usize,

    /// Octets currently charged, the sum of every `FragmentSet::bytes`.
    buffered_bytes: usize,

    /// Who the known sources are; every source is when `None`.
    known_sources: Option<Arc<dyn KnownSources>>,

    /// Pending sequences of sources not known, and the octets they are
    /// charged: the unknown pool (`unknown_max_pending`, `unknown_max_bytes`).
    unknown_count: usize,
    unknown_bytes: usize,

    /// Advances on every stored fragment; a set records it as its
    /// `progress_tick`. Orders progress strictly, where two `Instant`s may
    /// tie.
    progress_clock: u64,

    /// Timeout in milliseconds for incomplete sequences
    timeout_ms: u64,

    /// Timestamp of the last NACK_FRAG this buffer approved, across EVERY
    /// (writer, seq). Bounds the aggregate outgoing NACK_FRAG rate.
    ///
    /// The per-seq backoff in `try_mark_nacked` only prevents re-NACKing the
    /// SAME sequence too often; it does nothing when many DIFFERENT sequences
    /// are simultaneously incomplete. Once each of them individually clears
    /// its own per-seq cooldown, all can fire in the same 50ms stale-check
    /// tick (and independently, every incoming HEARTBEAT_FRAG can trigger one
    /// more via `handle_heartbeat_frag`), producing a synchronized burst of
    /// up to `max_pending` NACK_FRAGs. When a reader starts behind (cold
    /// start, starved CPU) with many large samples incomplete at once, those
    /// bursts and the DATA_FRAGs answering them grow into a retransmission
    /// storm that saturates the single router thread: throughput collapses
    /// and the reader never catches up.
    last_global_nack: Option<Instant>,
}

/// Minimum spacing between any two NACK_FRAGs this buffer approves, across
/// all sequences combined. Caps the aggregate repair-request rate at
/// `1000 / NACK_FRAG_GLOBAL_MIN_SPACING_MS` per second, i.e. 200/s, regardless
/// of how many distinct sequences are simultaneously stale.
///
/// `NACK_FRAG_BACKOFF_MS` is 200 ms per (writer, seq), so one stuck sequence
/// can emit at most 5 NACK_FRAG/s. 200/s is therefore 40 sequences each
/// running at their per-sequence ceiling, so this cap only binds once about
/// forty sequences are simultaneously stale. Whether 40 is the right knee has
/// not been measured.
const NACK_FRAG_GLOBAL_MIN_SPACING_MS: u64 = 5;

/// Default bound on the octets a [`FragmentBuffer`] holds across every pending
/// sequence, each charged its sample buffer, bitmap and bookkeeping
/// (`FragmentBuffer::with_max_bytes`).
///
/// The sequence count alone is not a bound: each sequence may hold up to its
/// declared `sampleSize` (a `u32` off the wire), so 256 sequences of spoofed
/// writers could pin gigabytes. 256 MiB leaves room for large user samples in
/// flight; the discovery buffer sets its own, smaller one.
pub const DEFAULT_MAX_BUFFERED_BYTES: usize = 256 << 20;

/// The share of each bound (sequences, octets) the sources not known hold
/// together: one quarter.
///
/// Anyone may send a DATA_FRAG from a prefix of its choosing, so a flood
/// from many forged prefixes is told apart from genuine peers only by what
/// discovery knows. The prefixes it does not know share this pool; a flood
/// there competes with itself, and the three quarters left are the known
/// peers' whatever it sends.
///
/// The pool must still let a genuine participant that is not known yet
/// complete a fragmented SPDP (or a handshake message) through a flood. In
/// the pool the sequence idle longest goes, and a genuine sample stays the
/// most recent by making progress, so the flood must open
/// `unknown_max_pending` sequences between two of its fragments to
/// evict it. That holds by COUNT only if octets do not bind first: one
/// sequence of a source not known may be charged at most the pool's octets
/// over its sequences (`unknown_max_charge`). For the discovery buffer
/// (256 sequences, 16 MiB) that is 64 sequences, 4 MiB, 64 KiB per sample;
/// for the user-data buffer (256, 256 MiB): 64, 64 MiB, 1 MiB. A larger
/// sample from a source not known is refused until discovery knows it.
const UNKNOWN_POOL_DIVISOR: usize = 4;

/// Which GUID prefixes a [`FragmentBuffer`] treats as known participants
/// (see [`FragmentBuffer::with_known_sources`]).
///
/// Asked under the buffer's lock, once per sequence opened: an
/// implementation must take no lock that is held while the buffer is locked.
pub trait KnownSources: Send + Sync {
    /// Whether the participant `prefix` is known.
    fn is_known(&self, prefix: &[u8; 12]) -> bool;

    /// Whether the participant `prefix` has proved who it is (DDS Security
    /// authentication) AND the traffic claiming it is authenticated as its
    /// (RTPS protection), which ranks it above a participant merely known:
    /// an SPDP anyone may forge makes a prefix known, only a completed
    /// handshake makes it authenticated, and only a protected message proves
    /// a DATA_FRAG came from it. False for every source by default, and then
    /// every known source ranks the same.
    fn is_authenticated(&self, _prefix: &[u8; 12]) -> bool {
        false
    }
}

/// The participants discovery knows (an SPDP with a usable locator, until
/// it leaves: [`EndpointRegistry`]), this participant never among them.
///
/// A buffer ranks REMOTE traffic: our own fragments are dropped before
/// reassembly (the routers' self-loopback), so a fragment with our prefix
/// that reaches a buffer is someone else's, and anyone may write our prefix
/// into an RTPS header. It therefore never ranks as known, nor as
/// authenticated with DDS Security: one spoofed DATA_FRAG carrying it would
/// otherwise outrank every authenticated peer.
///
/// The registry's maps are leaves: none of its locks is held while another
/// lock is taken.
pub struct DiscoveredParticipants {
    own_prefix: [u8; 12],
    registry: EndpointRegistry,
    /// Who completed authentication, when this participant runs DDS
    /// Security and its governance authenticates the RTPS header
    /// (`with_handshakes`).
    #[cfg(feature = "security")]
    handshakes: Option<Arc<crate::security::handshake::HandshakeMachine>>,
}

impl DiscoveredParticipants {
    /// The participants `registry` holds, `own_prefix` aside.
    pub fn new(own_prefix: [u8; 12], registry: EndpointRegistry) -> Self {
        Self {
            own_prefix,
            registry,
            #[cfg(feature = "security")]
            handshakes: None,
        }
    }

    /// Rank the participants that completed authentication with `machine`
    /// above those discovery merely knows (see
    /// [`KnownSources::is_authenticated`]), when `rtps_protected`: the
    /// governance protects whole RTPS messages (`rtps_protection_kind` other
    /// than NONE, DDS-Security v1.1 9.4.1.2.5.6). Otherwise none ranks
    /// above.
    ///
    /// A buffer reads the prefix it ranks from the RTPS header (or an
    /// INFO_SRC), and only RTPS protection authenticates that header: under
    /// any other governance anyone who saw an authenticated peer's SPDP can
    /// write its prefix into a DATA_FRAG and take its rank. An authenticated participant then ranks as one
    /// discovery knows, like everyone else. This release refuses a
    /// governance asking for RTPS protection (it does not apply it), so the
    /// rank is dormant until it does.
    ///
    /// The machine's session map is a leaf: none of its locks is held while
    /// a fragment buffer is locked.
    #[cfg(feature = "security")]
    #[must_use]
    pub fn with_handshakes(
        mut self,
        machine: Arc<crate::security::handshake::HandshakeMachine>,
        rtps_protected: bool,
    ) -> Self {
        self.handshakes = rtps_protected.then_some(machine);
        self
    }
}

impl KnownSources for DiscoveredParticipants {
    fn is_known(&self, prefix: &[u8; 12]) -> bool {
        *prefix != self.own_prefix
            && self
                .registry
                .get(&GUID::new(
                    *prefix,
                    crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
                ))
                .is_some()
    }

    fn is_authenticated(&self, prefix: &[u8; 12]) -> bool {
        #[cfg(feature = "security")]
        if let Some(machine) = self.handshakes.as_ref() {
            return *prefix != self.own_prefix
                && machine.is_authenticated(&GUID::new(
                    *prefix,
                    crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
                ));
        }
        let _ = prefix;
        false
    }
}

/// A sample buffer of `capacity` octets reserved and none written (see
/// `FragmentSet::data`).
///
/// The reservation is a promise of address space, not of memory: a page is
/// made resident when a fragment is first written to it. With transparent
/// huge pages enabled ("always", the default of several distributions),
/// the first write into a 2 MiB-aligned stretch of a large reservation
/// makes the kernel clear a whole 2 MiB page: one DATA_FRAG carrying one
/// fragment in the middle of a declared 248 MiB sample cost 200 us of
/// router time against 41 us without. A reservation
/// that can hold a huge page is asked not to (`MADV_NOHUGEPAGE`), so that
/// writing a fragment costs its own pages and nothing more. Advice only:
/// the octets and their lifetime are the allocator's, as for any `Vec`.
fn sample_buffer(capacity: usize) -> Vec<u8> {
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut buffer = Vec::with_capacity(capacity);
    #[cfg(target_os = "linux")]
    if capacity >= HUGE_PAGE {
        let start = buffer.as_mut_ptr() as usize;
        let page = 4096;
        let begin = start.div_ceil(page) * page;
        let end = (start + buffer.capacity()) / page * page;
        if end > begin {
            // SAFETY: `begin..end` lies inside the allocation `buffer` owns
            // (page-aligned inward from its start and end), and
            // MADV_NOHUGEPAGE changes no octet and no mapping, only how the
            // kernel backs the pages later faulted in. A failure leaves the
            // pages as they were, which is correct, only slower.
            unsafe {
                libc::madvise(
                    begin as *mut libc::c_void,
                    end - begin,
                    libc::MADV_NOHUGEPAGE,
                );
            }
        }
    }
    buffer
}

/// The transparent huge page size on x86-64 and the arm64 4 KiB granule:
/// no reservation smaller than this can hold one.
#[cfg(target_os = "linux")]
const HUGE_PAGE: usize = 2 << 20;

/// A pending sequence, by key, as the eviction rules walk them.
type Pending<'a> = (&'a (GUID, u64), &'a FragmentSet);

/// Who `FragmentBuffer::known_victim` picked.
enum Victim {
    /// A pending sequence.
    Pending((GUID, u64)),
    /// The sequence opening: it is refused.
    Newcomer,
}

/// How much further along sequence `a` is than `b`: a larger share of its
/// fragments received, then more octets, then the earlier to progress.
fn further_along(a: &FragmentSet, b: &FragmentSet) -> std::cmp::Ordering {
    advance(
        a.received_count,
        a.geometry.total_fragments(),
        a.received_octets,
    )
    .cmp(
        b.received_count,
        b.geometry.total_fragments(),
        b.received_octets,
    )
    .then(b.progress_tick.cmp(&a.progress_tick))
}

/// How far along a sequence is: `received` of `total` fragments, `octets`
/// received. Ordered by share of the fragments (exactly, by cross
/// multiplication), then by octets.
#[derive(Clone, Copy)]
struct Advance {
    received: u32,
    total: u32,
    octets: usize,
}

fn advance(received: u32, total: u32, octets: usize) -> Advance {
    Advance {
        received,
        total,
        octets,
    }
}

impl Advance {
    fn cmp(self, received: u32, total: u32, octets: usize) -> std::cmp::Ordering {
        let ours = u64::from(self.received) * u64::from(total);
        let theirs = u64::from(received) * u64::from(self.total);
        ours.cmp(&theirs).then(self.octets.cmp(&octets))
    }
}

/// A known sequence holding more than `PROTECTED_COMPLETION_NUM /
/// PROTECTED_COMPLETION_DEN` of its sample's octets, and at least
/// `PROTECTED_MIN_OCTETS`, is never evicted to make room for another of its
/// rank, within its participant's share (`FragmentBuffer::known_victim`).
const PROTECTED_COMPLETION_NUM: u64 = 1;
const PROTECTED_COMPLETION_DEN: u64 = 2;

/// Fewest octets a sequence must have received to be protected, whatever
/// its share of the sample.
///
/// Protection is bought in octets, not fragments: RTPS 2.5 sets no minimum
/// fragmentSize, so a threshold of half the FRAGMENTS would let 101 one-octet
/// fragments protect a sequence for 51 octets sent, and one prefix a forged
/// SPDP made known could hold all eight slots of a buffer that way, a
/// fragment per sequence per timeout keeping them alive, while a genuine
/// peer's new sample was refused round after round. The price is half
/// the sample's octets and at least 16 KiB. A sample under 32 KiB is never
/// protected; it is resent whole for less than the protection costs, and
/// its participant's most advanced sequence still keeps its place against a
/// newcomer behind it (`known_victim`). Holding the 256 slots of the
/// discovery buffer protected costs 256 * 16 KiB = 4 MiB sent within each
/// 500 ms timeout (the protection lasts that long from the first fragment),
/// and no one participant may hold more than its share of them.
const PROTECTED_MIN_OCTETS: usize = 16 << 10;

/// Largest fragment count a DATA_FRAG may announce for one sample.
///
/// Every consumer of a wire-supplied `total_fragments` walks
/// `1..=total_fragments` (`get_missing_fragments`, `reassemble_static`) under
/// the buffer mutex, so the count has to be bounded where the set is
/// ADMITTED, in `insert_fragment_with_addr`, the one door every path takes.
/// Bounding it only in the classifier's `scan_all_data_frags` is not enough:
/// when that scan refuses a packet and returns nothing, the router falls back
/// on the classifier's out-param metadata, which would re-admit the very
/// value the scan refused.
///
/// One unauthenticated ~60-byte DATA_FRAG with `sampleSize = 0xFFFFFFFF` and
/// `fragmentSize = 1` announces 4_294_967_295 fragments: a ~16 GiB `Vec<u32>`
/// on the next HEARTBEAT_FRAG or stale tick, an OOM abort or a wedged router.
/// 2^20 fragments is 1 GiB of payload at the 1024-byte fragment size and
/// bounds that sweep at 4 MB. The classifier keeps refusing early with the
/// same constant, as a courtesy; this is the check that counts.
pub const MAX_FRAGMENTS_PER_SAMPLE: u32 = 1 << 20;

/// Most named readers OUTSIDE the local readers a sequence records (see
/// `SampleAudience`).
///
/// Each readerId comes off the wire, one per fragment, so without a bound a
/// sample of `MAX_FRAGMENTS_PER_SAMPLE` fragments could grow the list to a
/// million entries. A local reader is always recorded (the local readers
/// bound those); a reader the sequence did not know when it opened (a late
/// joiner a replay names) counts against this; ENTITYID_UNKNOWN is a flag.
const MAX_READERS_PER_SAMPLE: usize = 64;

/// Fixed allowance charged to every pending sequence on top of its sample
/// and bitmap (`FragmentBuffer::charge_for`): the map slot holding it (the
/// table may be up to half empty, hence twice the slot) and the named-reader
/// list at its bound (`SampleAudience::named`, which may double its capacity
/// as it grows).
const SET_OVERHEAD: usize =
    2 * (std::mem::size_of::<((GUID, u64), FragmentSet)>() + 1) + 2 * 4 * MAX_READERS_PER_SAMPLE;

/// Charged per local reader a sequence records when it opens
/// (`SampleAudience::local`, and the named list that may repeat it).
const PER_LOCAL_READER: usize = 3 * 4;

/// A set of fragments for a specific (writerGUID, seqNum) sequence.
///
/// The sample is ONE buffer of `sampleSize` octets, allocated when the
/// sequence opens, each fragment copied to its place in it; a bitmap records
/// which fragments are there. A fragment costs its octets and nothing else,
/// whatever its size: one allocation per fragment (a `HashMap<u32, Vec<u8>>`)
/// would cost about 98 octets of real memory per octet held at a 1-octet
/// fragmentSize, which RTPS 2.5 allows (it sets no minimum), and would turn a
/// 16 MiB budget into 1.53 GiB of RSS.
struct FragmentSet {
    /// The sample: `geometry.sample_size` octets of capacity reserved at
    /// opening, its length 0 until it completes. Fragment `n` (1-based) is
    /// written into the reserved capacity at `(n - 1) * fragment_size`, in
    /// whatever order it comes; the bitmap says which octets are written,
    /// and the length is set to the sample size only once every fragment is
    /// there (`reassemble_static`), so an octet never written is never read.
    ///
    /// Nothing is written to the buffer but fragments: the cost of a
    /// fragment is its own length, whatever the sampleSize declared.
    /// Zeroing the whole buffer at opening (`vec![0; n]`) would cost a memset of
    /// the sample whenever the allocator reused memory (+39 us on a 1 MB
    /// sample, +1.9 ms on a 10 MB one), and zero-filling only the gap ahead
    /// of a fragment would let ONE DATA_FRAG carrying the last
    /// fragment of a declared sample zero all of it on the router thread:
    /// 130 us for 1 MiB from a source nobody knows, 68 ms for 248 MiB.
    /// Pages of the reservation that no fragment touched are never made
    /// resident.
    data: Vec<u8>,

    /// Bit `n - 1` set when fragment `n` is stored.
    received: Vec<u64>,

    /// Number of bits set in `received`.
    received_count: u32,

    /// Octets of the fragments stored.
    received_octets: usize,

    /// Whether its source was known when it opened (`KnownSources`): which
    /// pool it is charged to, for its whole life.
    known: bool,

    /// Whether its source was authenticated when it opened
    /// (`KnownSources::is_authenticated`): its rank among known sources,
    /// for its whole life.
    authenticated: bool,

    /// The geometry this sequence was admitted with. Pinned at the first
    /// admitted fragment; the fragment count is derived from it, so a
    /// sequence can never hold a count its geometry does not produce.
    geometry: FragmentGeometry,

    /// Timestamp when first fragment was received (kept for stats/logging)
    first_seen: Instant,

    /// Progress clock: refreshed only when a NEW fragment is stored.
    /// Timeout eviction compares against this, so a sequence that keeps
    /// making progress (even slowly, e.g. NACK_FRAG-driven repair at a few
    /// fragments per second) is never evicted mid-reassembly.
    last_updated: Instant,

    /// Timestamp of the last NACK_FRAG sent for this sequence (backoff gate)
    last_nacked: Option<Instant>,

    /// What this sequence holds in memory, counted into
    /// `FragmentBuffer::buffered_bytes`: its sample buffer, bitmap and
    /// bookkeeping from the moment it opens (`FragmentBuffer::charge_for`),
    /// plus its inline QoS once stored.
    bytes: usize,

    /// `FragmentBuffer::progress_clock` when a new fragment was last stored:
    /// the overflow eviction's age, without ties.
    progress_tick: u64,

    /// Where the last fragment of this sequence came from, for NACK_FRAG
    /// responses. RTPS 2.5 8.3.8.10: `Origin::relayed` behind an INFO_SRC
    /// carries no reply locator, so the destination it resolves to must go
    /// through `resolve_nack_frag_dest`, never straight to `origin.from()`.
    source_origin: Option<Origin>,

    /// Who the sample is for, from the readerIds of the DATA_FRAGs admitted
    /// into this sequence (RTPS 2.5 8.3.8.3). See `SampleAudience`.
    audience: SampleAudience,

    /// The inline QoS of the sample, from the first admitted DATA_FRAG
    /// that carried one (its Q flag): the coherent set and GROUP tags of a
    /// fragmented change travel there.
    inline_qos: Option<crate::core::discovery::multicast::FragInlineQos>,

    /// The sample's source timestamp (RTPS v2.5 Sec.8.3.7.9 INFO_TS,
    /// epoch ns): the value in force at the datagram that OPENED this
    /// sequence, i.e. whichever fragment was received first regardless of
    /// its fragment number. `None` when that datagram carried no INFO_TS.
    /// Fixed for the sequence's whole life: a LATER fragment's datagram
    /// may carry a different INFO_TS (a disagreeing peer, or simply none),
    /// and RTPS does not require every fragment of one sample to repeat
    /// the same INFO_TS, but the first one received is the value this
    /// reassembly reports -- the same "first received wins, a later
    /// disagreement is not an update" rule `geometry` and `inline_qos`
    /// already apply to this struct, chosen here because the writer's own
    /// clock reading at the first fragment it actually sent (which is not
    /// necessarily fragment #1) is the closest answer to "when was this
    /// sample written" available without reassembling first.
    source_ts_ns: Option<u64>,
}

impl FragmentSet {
    /// Whether fragment `frag_num` (1-based, inside the total) is stored.
    fn has(&self, frag_num: u32) -> bool {
        let bit = (frag_num - 1) as usize;
        self.received[bit / 64] & (1u64 << (bit % 64)) != 0
    }

    /// Record fragment `frag_num` as stored.
    fn mark(&mut self, frag_num: u32) {
        let bit = (frag_num - 1) as usize;
        self.received[bit / 64] |= 1u64 << (bit % 64);
        self.received_count += 1;
    }

    /// Whether every fragment of the geometry is stored, read off the bitmap
    /// itself rather than the count.
    fn every_fragment_present(&self) -> bool {
        let total = self.geometry.total_fragments() as usize;
        let (full, rest) = (total / 64, total % 64);
        self.received[..full].iter().all(|word| *word == u64::MAX)
            && (rest == 0 || self.received[full] == (1u64 << rest) - 1)
    }
}

/// The readers a reassembled sample is for.
///
/// A DATA_FRAG names the reader it is sent to, or ENTITYID_UNKNOWN for every
/// reader of the receiving participant.
///
/// - A named reader is the writer's choice and is taken as such, whether or
///   not it was here when the sequence opened: a TRANSIENT_LOCAL writer
///   replays its history, written before the match, to exactly the late
///   joiner it names.
/// - "Every reader" means the readers there WHEN THE SEQUENCE OPENED: one
///   created afterwards was not matched when the sample was written, and a
///   VOLATILE one must not receive it (DDS 1.4 2.2.3.4). So the local readers
///   are taken at the first fragment (`local`), and an UNKNOWN fragment
///   stands for them and for subscribers that name no reader.
///
/// A union over the fragments rather than one sequence per reader: fragments
/// of one sample reach a reader under different readerIds (multicast, then a
/// unicast repair naming it), and must complete ONE sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SampleAudience {
    /// The local readers at the first fragment: those of the writer's topic,
    /// or of the whole participant while the writer is not known yet.
    local: Vec<[u8; 4]>,
    /// Named readers the admitted fragments were sent to.
    named: Vec<[u8; 4]>,
    /// An admitted fragment was sent to ENTITYID_UNKNOWN.
    unknown: bool,
    /// Named readers recorded that were not local at the first fragment.
    foreign: usize,
    /// A named reader was left out at `MAX_READERS_PER_SAMPLE`.
    capped: bool,
}

impl SampleAudience {
    /// The audience of a sequence opened with these local readers.
    pub(crate) fn opened_with(local: Vec<[u8; 4]>) -> Self {
        Self {
            local,
            named: Vec::new(),
            unknown: false,
            foreign: 0,
            capped: false,
        }
    }

    /// Count a fragment sent to `reader`.
    fn admit(&mut self, reader: [u8; 4]) {
        if reader == ENTITYID_UNKNOWN {
            self.unknown = true;
        } else if self.named.contains(&reader) {
        } else if self.local.contains(&reader) {
            self.named.push(reader);
        } else if self.foreign < MAX_READERS_PER_SAMPLE {
            self.foreign += 1;
            self.named.push(reader);
        } else if !self.capped {
            self.capped = true;
            log::warn!(
                "[FragBuf] a sequence names more than {} readers that were not here when \
                 it opened; reader {:02x?} and any further one will not receive it",
                MAX_READERS_PER_SAMPLE,
                reader
            );
        }
    }

    /// Whether the named reader `reader` is one this sample is for.
    pub(crate) fn names(&self, reader: [u8; 4]) -> bool {
        self.named.contains(&reader) || (self.unknown && self.local.contains(&reader))
    }

    /// Whether a subscriber that names no reader receives the sample: it
    /// receives what is sent to every reader.
    pub(crate) fn reaches_unnamed(&self) -> bool {
        self.unknown
    }
}

impl FragmentBuffer {
    /// Create a new fragment buffer.
    ///
    /// # Arguments
    ///
    /// - `max_pending`: Maximum number of incomplete sequences (typical: 256)
    /// - `timeout_ms`: Evict incomplete sequences after this duration (typical: 100-500ms)
    ///
    /// # Memory Bound
    ///
    /// [`DEFAULT_MAX_BUFFERED_BYTES`] of sample buffers and their
    /// bookkeeping, whatever the sequence count and the fragment size;
    /// [`with_max_bytes`](Self::with_max_bytes) sets another.
    pub fn new(max_pending: usize, timeout_ms: u64) -> Self {
        Self {
            pending: HashMap::with_capacity(max_pending),
            max_pending,
            max_bytes: DEFAULT_MAX_BUFFERED_BYTES,
            buffered_bytes: 0,
            known_sources: None,
            unknown_count: 0,
            unknown_bytes: 0,
            progress_clock: 0,
            timeout_ms,
            last_global_nack: None,
        }
    }

    /// Bound the octets held across every pending sequence to `max_bytes`
    /// (see [`DEFAULT_MAX_BUFFERED_BYTES`]).
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Tell known participants from the rest by `sources` (see
    /// [`UNKNOWN_POOL_DIVISOR`]). Without it every source is known, and a
    /// flood from forged prefixes competes with genuine peers on completion.
    #[must_use]
    pub fn with_known_sources(mut self, sources: Arc<dyn KnownSources>) -> Self {
        self.known_sources = Some(sources);
        self
    }

    /// Insert a fragment and attempt reassembly.
    ///
    /// # Arguments
    ///
    /// - `writer_guid`: RTPS GUID of the writer that sent this fragment
    /// - `seq_num`: Sequence number (all fragments of same message share this)
    /// - `frag_num`: Fragment number (1-based, from fragmentStartingNum)
    /// - `geometry`: `fragmentSize` and `sampleSize` as the submessage declared
    ///   them; the fragment count and every fragment's expected length are
    ///   derived from it
    /// - `data`: Fragment payload (raw bytes)
    ///
    /// # Returns
    ///
    /// - `Some(Vec<u8>)`: Complete reassembled payload (all fragments received)
    /// - `None`: Still waiting for more fragments
    ///
    /// # Example
    ///
    /// ```ignore
    /// let geometry = FragmentGeometry { fragment_size: 1024, sample_size: 4096 };
    /// let payload = buffer.insert_fragment(guid, 1, 3, geometry, frag3_data);
    /// if let Some(complete) = payload {
    ///     // All fragments received, parse complete message
    ///     parse_spdp(&complete)?;
    /// }
    /// ```
    pub fn insert_fragment(
        &mut self,
        writer_guid: GUID,
        seq_num: u64,
        frag_num: u32,
        geometry: FragmentGeometry,
        data: Vec<u8>,
    ) -> Option<Vec<u8>> {
        self.insert_fragment_with_addr(writer_guid, seq_num, frag_num, geometry, data, None)
    }

    /// Insert a fragment with source tracking for NACK_FRAG responses.
    ///
    /// The fragment counts as sent to every reader (ENTITYID_UNKNOWN); see
    /// `insert_addressed_fragment` for a fragment whose readerId is known.
    pub fn insert_fragment_with_addr(
        &mut self,
        writer_guid: GUID,
        seq_num: u64,
        frag_num: u32,
        geometry: FragmentGeometry,
        data: Vec<u8>,
        source_origin: Option<Origin>,
    ) -> Option<Vec<u8>> {
        self.insert_addressed_fragment(
            writer_guid,
            seq_num,
            frag_num,
            geometry,
            data,
            source_origin,
            ENTITYID_UNKNOWN,
            Vec::new,
        )
        .map(|(payload, _audience)| payload)
    }

    /// Insert a fragment sent to `reader_entity_id` (the readerId of its
    /// DATA_FRAG) and attempt reassembly.
    ///
    /// A completed sample comes back with its audience. `local_readers` is
    /// asked only when this fragment opens a sequence: the ids of the local
    /// readers (see `SampleAudience::local`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn insert_addressed_fragment(
        &mut self,
        writer_guid: GUID,
        seq_num: u64,
        frag_num: u32,
        geometry: FragmentGeometry,
        data: Vec<u8>,
        source_origin: Option<Origin>,
        reader_entity_id: [u8; 4],
        local_readers: impl FnOnce() -> Vec<[u8; 4]>,
    ) -> Option<(Vec<u8>, SampleAudience)> {
        self.insert_addressed_fragment_with_qos(
            writer_guid,
            seq_num,
            frag_num,
            geometry,
            data,
            source_origin,
            reader_entity_id,
            None,
            None,
            local_readers,
        )
        .map(|(payload, audience, _, _)| (payload, audience))
    }

    /// [`insert_addressed_fragment`](Self::insert_addressed_fragment), the
    /// fragment carrying the inline QoS `inline_qos` of its DATA_FRAG and
    /// the source timestamp `source_ts_ns` in force at ITS datagram
    /// (RTPS v2.5 Sec.8.3.7.9 INFO_TS, `None` when that datagram carried
    /// none); the completed sample comes back with the inline QoS of the
    /// first fragment admitted that carried one, and the source timestamp
    /// of the first fragment admitted at all (see `FragmentSet::
    /// source_ts_ns`'s doc for why those two rules differ).
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub(crate) fn insert_addressed_fragment_with_qos(
        &mut self,
        writer_guid: GUID,
        seq_num: u64,
        frag_num: u32,
        geometry: FragmentGeometry,
        mut data: Vec<u8>,
        source_origin: Option<Origin>,
        reader_entity_id: [u8; 4],
        inline_qos: Option<crate::core::discovery::multicast::FragInlineQos>,
        source_ts_ns: Option<u64>,
        local_readers: impl FnOnce() -> Vec<[u8; 4]>,
    ) -> Option<(
        Vec<u8>,
        SampleAudience,
        Option<crate::core::discovery::multicast::FragInlineQos>,
        Option<u64>,
    )> {
        let key = (writer_guid, seq_num);
        let now = Instant::now();
        let total_frags = geometry.total_fragments();

        // Admission, BEFORE any state is created for this sequence. Every
        // value here comes off the wire from a peer nobody has authenticated.
        // - `total_frags` is DERIVED from the geometry, never received, and it
        //   is zero for a geometry that describes no fragment - a fragmentSize
        //   of 0, or a sampleSize of 0. Taking it from `fragmentsInSubmessage`
        //   instead would let one DATA_FRAG declaring
        //   `fragmentSize = 0, fragmentsInSubmessage = 1` become a complete
        //   sample of whatever length its body happened to carry (28 octets
        //   delivered for a declared sampleSize of 64).
        // - `total_frags` bounds every later walk (see MAX_FRAGMENTS_PER_SAMPLE).
        // - `frag_num` is 1-based and must name a slot inside the total: with
        //   no range check, fragments numbered 1, 2 and 99 of a 3-fragment
        //   sample made THREE distinct keys, the count-based completion test
        //   below declared the sample complete, and the application received
        //   fragments 1 and 2 concatenated as the whole sample.
        if total_frags == 0 || total_frags > MAX_FRAGMENTS_PER_SAMPLE {
            log::warn!(
                "[FragBuf] GUID={:?} seqNum={} DATA_FRAG announces total_fragments={} (bound {}); \
                 fragment refused",
                writer_guid,
                seq_num,
                total_frags,
                MAX_FRAGMENTS_PER_SAMPLE
            );
            return None;
        }
        if frag_num == 0 || frag_num > total_frags {
            log::warn!(
                "[FragBuf] GUID={:?} seqNum={} fragment #{} is outside 1..={}; fragment refused",
                writer_guid,
                seq_num,
                frag_num,
                total_frags
            );
            return None;
        }

        // A fragment must carry exactly the octets the geometry says it does:
        // `fragmentSize` for every fragment but the last, the remainder for
        // the last. Completion is a COUNT, so a fragment shorter than that is
        // a hole the count cannot see - the sample completes short and every
        // octet behind the hole is shifted. E.g. `sampleSize` 64,
        // `fragmentSize` 32, a fragment 1 carrying 20 octets: the subscriber
        // would be handed a 52-octet "complete" sample with its second half
        // in the wrong place.
        //
        // Longer is CLIPPED, not refused. What arrives here is a slice of a
        // submessage, and `octetsToNextHeader` counts the alignment padding a
        // peer may add (RTPS v2.5 Sec.8.3.3.3.3), so a conforming writer that
        // pads can hand us 1 to 3 octets more than the fragment holds. HDDS's
        // own emitter adds none - `encode_data_frag` declares `32 +
        // payload.len()` - but the reader must not require that of everyone.
        let Some(expected) = geometry.expected_fragment_len(frag_num) else {
            log::warn!(
                "[FragBuf] GUID={:?} seqNum={} fragment #{} has no length in a \
                 (fragmentSize={}, sampleSize={}) sample; fragment refused",
                writer_guid,
                seq_num,
                frag_num,
                geometry.fragment_size,
                geometry.sample_size
            );
            return None;
        };
        if data.len() < expected {
            log::warn!(
                "[FragBuf] GUID={:?} seqNum={} fragment #{}/{} carries {} octets where the \
                 declared geometry needs {}; fragment refused",
                writer_guid,
                seq_num,
                frag_num,
                total_frags,
                data.len(),
                expected
            );
            return None;
        }
        data.truncate(expected);

        // Open the sequence: its whole sample buffer and bitmap are allocated
        // here, once, and charged in full against the octet budget before a
        // single fragment is stored. What it will hold never grows after
        // this point, whatever the fragmentSize (only an inline QoS, stored
        // once, adds to it).
        if !self.pending.contains_key(&key) {
            let authenticated = self.is_authenticated(&writer_guid.prefix);
            let known = authenticated || self.is_known(&writer_guid.prefix);
            let ceiling = if known {
                self.max_bytes
            } else {
                self.unknown_max_charge()
            };
            let local = local_readers();
            let Some(charge) =
                Self::charge_for(geometry, local.len()).filter(|charge| *charge <= ceiling)
            else {
                log::warn!(
                    "[FragBuf] GUID={:?} seqNum={} DATA_FRAG announces sampleSize={}, over the \
                     {}-octet reassembly budget of a {} source; fragment refused",
                    writer_guid,
                    seq_num,
                    geometry.sample_size,
                    ceiling,
                    if known { "known" } else { "not known" }
                );
                return None;
            };
            // Room is made BEFORE anything is created: a sequence refused
            // here leaves no trace and allocates nothing, and the sequences
            // planned out are evicted only if it is admitted.
            let Some(victims) = self.make_room(
                &key,
                known,
                authenticated,
                Some((total_frags, data.len())),
                charge,
                now,
            ) else {
                log::debug!(
                    "[FragBuf] GUID={:?} seqNum={} no room for a {}-octet sequence of a {} \
                     source; fragment refused",
                    writer_guid,
                    seq_num,
                    charge,
                    if known { "known" } else { "not known" }
                );
                return None;
            };
            self.evict(&victims);
            let words = (total_frags as usize).div_ceil(64);
            self.pending.insert(
                key,
                FragmentSet {
                    data: sample_buffer(geometry.sample_size as usize),
                    received: vec![0u64; words],
                    received_count: 0,
                    received_octets: 0,
                    known,
                    authenticated,
                    geometry,
                    first_seen: now,
                    last_updated: now,
                    last_nacked: None,
                    bytes: charge,
                    progress_tick: 0,
                    source_origin: None,
                    audience: SampleAudience::opened_with(local),
                    inline_qos: None,
                    // This call opened the sequence, so it IS the first
                    // fragment received for it, whatever its frag_num.
                    source_ts_ns,
                },
            );
            self.account_add(known, 1, charge);
        }
        let frag_set = self.pending.get_mut(&key)?;

        // Update source if provided
        if source_origin.is_some() {
            frag_set.source_origin = source_origin;
        }

        // FIRST value wins. Adopting the LATEST total_fragments seen would let
        // any later DATA_FRAG for the same (writer, seq) - the buffer is keyed
        // on GUID and sequence only, so an off-path sender too - lower the
        // expected count to whatever it had already delivered: fragments 1
        // and 2 of a 100-fragment sample, then a header claiming total 2, and
        // the count below would declare the sample complete and hand the
        // application a truncated payload. A disagreeing fragment is a
        // protocol error for that sequence, not an update; it is refused and
        // the set it disagrees with is left as it was.
        if frag_set.geometry != geometry {
            log::warn!(
                "[FragBuf] GUID={:?} seqNum={} DATA_FRAG announces (fragmentSize={}, \
                 sampleSize={}) but this sequence was admitted with (fragmentSize={}, \
                 sampleSize={}); fragment refused, first geometry kept",
                writer_guid,
                seq_num,
                geometry.fragment_size,
                geometry.sample_size,
                frag_set.geometry.fragment_size,
                frag_set.geometry.sample_size
            );
            return None;
        }

        // The first inline QoS a sequence receives is kept, and charged:
        // room for it is made like room for a sequence, the sequence itself
        // never its own victim, and the fragment is refused (before anything
        // of it is stored) when none can be made.
        if frag_set.inline_qos.is_none() {
            if let Some(cost) = inline_qos.as_ref().map(|qos| qos.0.len()) {
                let (known, authenticated) = (frag_set.known, frag_set.authenticated);
                let Some(victims) = self.make_room(&key, known, authenticated, None, cost, now)
                else {
                    log::debug!(
                        "[FragBuf] GUID={:?} seqNum={} no room for a {}-octet inline QoS; \
                         fragment refused",
                        writer_guid,
                        seq_num,
                        cost
                    );
                    return None;
                };
                self.evict(&victims);
                self.account_add(known, 0, cost);
                let frag_set = self.pending.get_mut(&key)?;
                frag_set.bytes += cost;
                frag_set.inline_qos = inline_qos;
            }
        }
        let frag_set = self.pending.get_mut(&key)?;

        // Store a NEW fragment in its place; a duplicate keeps the octets
        // first stored. Refresh the progress clock ONLY for a new fragment:
        // duplicate re-stores are not progress, and a peer stuck re-sending
        // the same fragment forever must still hit timeout eviction.
        if !frag_set.has(frag_num) {
            let offset = (frag_num - 1) as usize * usize::from(geometry.fragment_size);
            // In range by construction: the geometry is the set's own, the
            // capacity reserved is its sampleSize, and `data` was cut to
            // the length it gives this fragment. Written into the reserved
            // capacity (the length stays 0 until completion): no octet but
            // the fragment's own is touched.
            let Some(slot) = frag_set
                .data
                .spare_capacity_mut()
                .get_mut(offset..offset + data.len())
            else {
                log::warn!(
                    "[FragBuf] GUID={:?} seqNum={} fragment #{} falls outside its sample; \
                     fragment refused",
                    writer_guid,
                    seq_num,
                    frag_num
                );
                return None;
            };
            // SAFETY: `slot` is `data.len()` octets (the range above) of the
            // capacity `frag_set.data` owns, borrowed exclusively, and
            // `MaybeUninit<u8>` has the layout of `u8`; `data` is another
            // allocation, so the two do not overlap.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    slot.as_mut_ptr().cast::<u8>(),
                    data.len(),
                );
            }
            frag_set.mark(frag_num);
            frag_set.received_octets += data.len();
            frag_set.last_updated = now;
            self.progress_clock += 1;
            frag_set.progress_tick = self.progress_clock;
        }
        drop(data);
        // Counted only for an ADMITTED fragment: a refused one was never
        // part of this sample, and must not name a reader for it.
        frag_set.audience.admit(reader_entity_id);

        log::debug!(
            "[FragBuf] GUID={:?} seqNum={} frag={}/{} stored ({} fragments buffered)",
            writer_guid,
            seq_num,
            frag_num,
            total_frags,
            frag_set.received_count
        );

        if frag_set.received_count < total_frags {
            return None;
        }
        log::debug!(
            "[FragBuf] [OK] COMPLETE! GUID={:?} seqNum={} ({} fragments)",
            writer_guid,
            seq_num,
            total_frags
        );
        // The count is of bits set, each fragment number inside 1..=total set
        // once; reassembly re-reads the bitmap and REFUSES a hole rather than
        // handing a shorter payload to the application.
        let frag_set = self.take_set(&key)?;
        Self::reassemble_static(frag_set)
    }

    /// What a sequence of `geometry` opened with `local_readers` local
    /// readers is charged against the octet budget: its sample buffer, its
    /// bitmap and its bookkeeping (`SET_OVERHEAD`). `None` past `usize`.
    fn charge_for(geometry: FragmentGeometry, local_readers: usize) -> Option<usize> {
        let sample = usize::try_from(geometry.sample_size).ok()?;
        let bitmap = (geometry.total_fragments() as usize).div_ceil(64) * 8;
        sample
            .checked_add(bitmap)?
            .checked_add(SET_OVERHEAD)?
            .checked_add(local_readers.checked_mul(PER_LOCAL_READER)?)
    }

    /// The audience of the pending sequence `(writer_guid, seq_num)`, if
    /// one is pending: whom a request for its missing fragments speaks for.
    pub(crate) fn pending_audience(
        &self,
        writer_guid: &GUID,
        seq_num: u64,
    ) -> Option<&SampleAudience> {
        self.pending
            .get(&(*writer_guid, seq_num))
            .map(|set| &set.audience)
    }

    /// Hand over a complete sequence: its sample buffer IS the payload, no
    /// copy; with its audience and inline QoS.
    ///
    /// `None` if any fragment in `1..=total_fragments` is absent: a payload
    /// with a hole is not the sample, and "should not happen" is a reason to
    /// refuse, not to log at DEBUG and deliver what is there.
    #[allow(clippy::type_complexity)]
    fn reassemble_static(
        frag_set: FragmentSet,
    ) -> Option<(
        Vec<u8>,
        SampleAudience,
        Option<crate::core::discovery::multicast::FragInlineQos>,
        Option<u64>,
    )> {
        if !frag_set.every_fragment_present() {
            log::warn!(
                "[FragBuf] {} of {} fragments present at reassembly; sample refused",
                frag_set.received_count,
                frag_set.geometry.total_fragments()
            );
            return None;
        }
        let len = frag_set.geometry.sample_size as usize;
        let mut data = frag_set.data;
        if !data.is_empty() || data.capacity() < len {
            log::warn!(
                "[FragBuf] sample buffer of length {} and capacity {} for a {}-octet sample \
                 at reassembly; sample refused",
                data.len(),
                data.capacity(),
                len
            );
            return None;
        }
        // SAFETY: `len` is within the capacity (checked above). Every octet
        // of `0..len` was written: every fragment `1..=total` is present
        // (the bitmap, re-read above), a fragment is marked only after it
        // was written whole at `(n - 1) * fragment_size`, with exactly
        // `expected_fragment_len(n)` octets (`insert_addressed_fragment_with_qos`
        // refuses a shorter one and cuts a longer one), under the set's own
        // geometry (a fragment of another is refused), and those ranges
        // tile `0..sample_size` with no gap (`FragmentGeometry::
        // expected_fragment_len`: `fragment_size` for every fragment but the
        // last, the remainder for the last).
        unsafe { data.set_len(len) };
        log::debug!(
            "[FragBuf] Reassembled {} bytes from {} fragments",
            data.len(),
            frag_set.geometry.total_fragments()
        );
        Some((
            data,
            frag_set.audience,
            frag_set.inline_qos,
            frag_set.source_ts_ns,
        ))
    }

    /// Evict expired incomplete sequences (timeout-based cleanup).
    ///
    /// Call this periodically (e.g., every 100ms) to free memory from
    /// sequences that will never complete.
    ///
    /// The clock is LAST-PROGRESS (`last_updated`), not `first_seen`: a
    /// sequence whose repair trickles in slowly (e.g. NACK_FRAG-driven
    /// retransmission at a few fragments per second) keeps resetting its
    /// idle timer and is never evicted mid-reassembly. Only a sequence with
    /// NO new fragment for `timeout_ms` is dropped. `first_seen` is kept
    /// for the eviction log.
    ///
    /// # Returns
    ///
    /// Number of sequences evicted.
    pub fn evict_expired(&mut self) -> usize {
        let evicted = self.drop_expired(Instant::now(), None);

        // Shrink capacity to avoid memory accumulation over time
        if evicted > 0 {
            self.pending.shrink_to_fit();
        }

        evicted
    }

    /// Drop every sequence idle past the timeout at `now`, `except` one
    /// (a sequence growing as this runs), keeping the totals their sums;
    /// how many went.
    fn drop_expired(&mut self, now: Instant, except: Option<&(GUID, u64)>) -> usize {
        let timeout = Duration::from_millis(self.timeout_ms);
        let mut evicted = 0;
        let mut freed = 0;
        let (mut freed_unknown, mut freed_unknown_bytes) = (0, 0);

        self.pending.retain(|key, frag_set| {
            let (guid, seq_num) = key;
            let idle = now.duration_since(frag_set.last_updated);
            if idle > timeout && Some(key) != except {
                log::debug!(
                    "[FragBuf] [time]  TIMEOUT EVICT: GUID={:?} seqNum={} ({}/{} fragments, idle {:?}, total age {:?})",
                    guid,
                    seq_num,
                    frag_set.received_count,
                    frag_set.geometry.total_fragments(),
                    idle,
                    now.duration_since(frag_set.first_seen)
                );
                evicted += 1;
                freed += frag_set.bytes;
                if !frag_set.known {
                    freed_unknown += 1;
                    freed_unknown_bytes += frag_set.bytes;
                }
                false // Remove from pending
            } else {
                true // Keep
            }
        });

        self.buffered_bytes -= freed;
        self.unknown_count -= freed_unknown;
        self.unknown_bytes -= freed_unknown_bytes;
        evicted
    }

    /// `plan_room`, the sequences idle past the timeout dropped first
    /// whenever room has to be made.
    ///
    /// Only the UDP user router calls `evict_expired` on a timer, so the
    /// discovery buffer and the TCP/QUIC one rely on this sweep. Without it a
    /// sequence that lost a fragment would stay until room was made by
    /// eviction, and one the eviction rules keep (past half its fragments)
    /// would stay for good: four of them would hold a four-sequence buffer and
    /// every new fragmented sample of a known peer would be refused, forever.
    /// Every buffer sweeps here, at the one door a sequence takes to need
    /// room, and only then: a sequence never waits on one that expired, and a
    /// buffer under no pressure pays nothing.
    fn make_room(
        &mut self,
        key: &(GUID, u64),
        known: bool,
        authenticated: bool,
        opening: Option<(u32, usize)>,
        add_bytes: usize,
        now: Instant,
    ) -> Option<Vec<(GUID, u64)>> {
        let plan = self.plan_room(key, known, authenticated, opening, add_bytes, now);
        if plan.as_ref().is_some_and(Vec::is_empty) || self.drop_expired(now, Some(key)) == 0 {
            return plan;
        }
        self.plan_room(key, known, authenticated, opening, add_bytes, now)
    }

    /// Remove the set `key`, keeping `buffered_bytes` and the unknown pool
    /// their sums.
    fn take_set(&mut self, key: &(GUID, u64)) -> Option<FragmentSet> {
        let set = self.pending.remove(key)?;
        self.buffered_bytes -= set.bytes;
        if !set.known {
            self.unknown_count -= 1;
            self.unknown_bytes -= set.bytes;
        }
        Some(set)
    }

    /// Evict the sequences `plan_room` planned out.
    fn evict(&mut self, victims: &[(GUID, u64)]) {
        for victim in victims {
            if let Some(frag_set) = self.take_set(victim) {
                log::debug!(
                    "[FragBuf] [*]  OVERFLOW EVICT: GUID={:?} seqNum={} ({}/{} fragments, {} \
                     octets, {} source, age={:?})",
                    victim.0,
                    victim.1,
                    frag_set.received_count,
                    frag_set.geometry.total_fragments(),
                    frag_set.bytes,
                    if frag_set.known { "known" } else { "not known" },
                    Instant::now().duration_since(frag_set.first_seen)
                );
            }
        }
    }

    /// Whether `prefix` is a participant this buffer knows (see
    /// [`KnownSources`]); every source is, when none is attached.
    fn is_known(&self, prefix: &[u8; 12]) -> bool {
        self.known_sources
            .as_ref()
            .is_none_or(|sources| sources.is_known(prefix))
    }

    /// Whether `prefix` is a participant that proved who it is (see
    /// [`KnownSources::is_authenticated`]); none is, when no sources are
    /// attached.
    fn is_authenticated(&self, prefix: &[u8; 12]) -> bool {
        self.known_sources
            .as_ref()
            .is_some_and(|sources| sources.is_authenticated(prefix))
    }

    /// Most sequences the sources not known may hold together.
    fn unknown_max_pending(&self) -> usize {
        (self.max_pending / UNKNOWN_POOL_DIVISOR).max(1)
    }

    /// Most octets the sources not known may hold together.
    fn unknown_max_bytes(&self) -> usize {
        self.max_bytes / UNKNOWN_POOL_DIVISOR
    }

    /// Most octets one sequence of a source not known may be charged: the
    /// pool's octets over its sequences, so that the count is the bound a
    /// flood meets first (see [`UNKNOWN_POOL_DIVISOR`]).
    fn unknown_max_charge(&self) -> usize {
        self.unknown_max_bytes() / self.unknown_max_pending()
    }

    /// Add `count` sequences and `bytes` octets of a source of class `known`
    /// to the totals.
    fn account_add(&mut self, known: bool, count: usize, bytes: usize) {
        self.buffered_bytes += bytes;
        if !known {
            self.unknown_count += count;
            self.unknown_bytes += bytes;
        }
    }

    /// The sequences to evict, in order, so that `add_bytes` more octets for
    /// `key`, of a source of class `known`, fit every bound; `None` when the
    /// rules below cannot make them fit, and then nothing is evicted at all.
    ///
    /// `opening` is `Some(total fragments)` when `key` opens: it is not
    /// pending yet, it adds a sequence too, and it may itself be the one the
    /// rules pick, in which case it is refused (the buffer then holds what
    /// it held, which was within its bounds). `None` when a pending `key`
    /// grows (by its inline QoS): it is never its own victim.
    ///
    /// 1. A sequence of a source not known goes before any known one, and a
    ///    source not known never evicts a known one: a flood from forged
    ///    prefixes competes with itself, in a pool of its own
    ///    ([`UNKNOWN_POOL_DIVISOR`]). Among them the sequence whose last
    ///    progress is the oldest goes (`progress_tick`); the opening one is
    ///    not pending, so never its own victim there.
    /// 2. Among known sources, `known_victim`: a source merely known goes
    ///    before an authenticated one and never evicts one; within a rank,
    ///    the furthest from completion, and none past half its fragments.
    fn plan_room(
        &self,
        key: &(GUID, u64),
        known: bool,
        authenticated: bool,
        opening: Option<(u32, usize)>,
        add_bytes: usize,
        now: Instant,
    ) -> Option<Vec<(GUID, u64)>> {
        let add_count = usize::from(opening.is_some());
        let mut count = self.pending.len() + add_count;
        let mut bytes = self.buffered_bytes + add_bytes;
        let (mut unknown_count, mut unknown_bytes) = if known {
            (self.unknown_count, self.unknown_bytes)
        } else {
            (
                self.unknown_count + add_count,
                self.unknown_bytes + add_bytes,
            )
        };
        let mut planned: HashSet<(GUID, u64)> = HashSet::new();
        let mut order = Vec::new();
        loop {
            let over_total = count > self.max_pending || bytes > self.max_bytes;
            let over_unknown = !known
                && (unknown_count > self.unknown_max_pending()
                    || unknown_bytes > self.unknown_max_bytes());
            if !over_total && !over_unknown {
                return Some(order);
            }
            let victim = match self.least_recent_unknown(key, &planned) {
                Some(victim) => victim,
                None if known => {
                    match self.known_victim(
                        key,
                        authenticated,
                        opening,
                        bytes > self.max_bytes,
                        add_bytes,
                        &planned,
                        now,
                    )? {
                        Victim::Pending(victim) => victim,
                        Victim::Newcomer => return None,
                    }
                }
                None => return None,
            };
            let set = self.pending.get(&victim)?;
            count -= 1;
            bytes -= set.bytes;
            if !set.known {
                unknown_count -= 1;
                unknown_bytes -= set.bytes;
            }
            planned.insert(victim);
            order.push(victim);
        }
    }

    /// The pending sequence of a source not known whose last progress is
    /// the oldest, `key` and the `planned` ones aside.
    fn least_recent_unknown(
        &self,
        key: &(GUID, u64),
        planned: &HashSet<(GUID, u64)>,
    ) -> Option<(GUID, u64)> {
        self.pending
            .iter()
            .filter(|(k, set)| !set.known && *k != key && !planned.contains(*k))
            .min_by_key(|(_, set)| set.progress_tick)
            .map(|(k, _)| *k)
    }

    /// The known sequence to evict (rule 2 of `plan_room`), `key` and the
    /// `planned` ones aside; `Victim::Newcomer` when the rules pick `key`
    /// itself, opening (`opening`: its total fragments) with `add_bytes`.
    ///
    /// The sequence furthest from completion (fragments received over
    /// fragments total) goes: one that has received more is closer to
    /// freeing its room, and what it received its source paid for. Its size
    /// buys nothing: ranking by size would evict the largest sample first, and
    /// a few hundred one-fragment sequences could evict a genuine sample that
    /// was 89% there. A shape a forged source chooses buys nothing either, since a
    /// source not known is rule 1's.
    ///
    /// Each writer offers only its NEWEST sequence: the oldest incomplete
    /// one is the one a reliable reader's reorder gate is blocked on, the
    /// newest is re-announced by HEARTBEAT_FRAG and rebuilt once room frees
    /// up. Sequence numbers of different writers are never compared (one
    /// lossy writer at seq 1..=256 made every other writer's sample the
    /// maximum, evicted on arrival, forever).
    ///
    /// Ties: the participant holding the most of the bound exceeded
    /// (sequences, or octets when over the octet budget), then the one idle
    /// longest (`progress_tick`, never GUID order), then within it the
    /// writer holding the most, then the one idle longest. The opening
    /// sequence counts as the most recent progress.
    ///
    /// A participant opening its FIRST sequence is never its own victim: at
    /// equal shares a newcomer paying for itself would keep a genuine peer's
    /// new sample from ever completing while others held the buffer. One that
    /// already holds sequences competes with them, so a participant
    /// streaming faster than it completes pays for its own newest.
    ///
    /// Three limits come before that order:
    ///
    /// - Rank. A source merely known (an SPDP, which anyone may forge) goes
    ///   before an authenticated one (`authenticated`: the source of `key`)
    ///   and never evicts one. Without DDS Security every known source ranks
    ///   the same.
    /// - No sequence, opening or growing by its inline QoS, evicts one of
    ///   its own rank `protected`: past half its sample's octets
    ///   (`PROTECTED_COMPLETION_*`) and over `PROTECTED_MIN_OCTETS`, within
    ///   its participant's share; when no other is left, the fragment is
    ///   refused and waits for room.
    ///   Both doors, since a sequence that fits opens and then grows. One
    ///   DATA_FRAG from a prefix a forged SPDP made known, declaring a
    ///   sample the size of the budget, could evict a genuine peer's sample
    ///   800 of 900 fragments there: being its participant's first sequence,
    ///   the newcomer is never its own victim, and the genuine sample is the
    ///   only other one. Holding a slot past that point costs a source half
    ///   the octets of its sample and at least 16 KiB, sent: a sequence
    ///   opened and left to idle is never protected. The protection lasts the
    ///   buffer's timeout from the first fragment and no longer: a sample
    ///   that is coming completes well within it, and one kept alive a
    ///   fragment at a time past it holds its slot only while no one else
    ///   needs it.
    /// - Place. A participant's most advanced sequence goes only for one
    ///   further along (`shielded`), so two samples that cannot be held
    ///   together complete one after the other instead of evicting each
    ///   other forever.
    #[allow(clippy::too_many_arguments)]
    fn known_victim(
        &self,
        key: &(GUID, u64),
        authenticated: bool,
        opening: Option<(u32, usize)>,
        by_bytes: bool,
        add_bytes: usize,
        planned: &HashSet<(GUID, u64)>,
        now: Instant,
    ) -> Option<Victim> {
        /// One known sequence as the rules see it.
        struct Entry {
            key: (GUID, u64),
            authenticated: bool,
            received: u32,
            total: u32,
            load: usize,
            tick: u64,
        }
        let protected = self.protected(key, authenticated, now);
        let shielded = self.shielded(key, authenticated, opening, now);
        let mut entries: Vec<Entry> = self
            .pending
            .iter()
            .filter(|(k, set)| {
                set.known
                    && (authenticated || !set.authenticated)
                    && !protected.contains(*k)
                    && !shielded.contains(*k)
                    && *k != key
                    && !planned.contains(*k)
            })
            .map(|(k, set)| Entry {
                key: *k,
                authenticated: set.authenticated,
                received: set.received_count,
                total: set.geometry.total_fragments(),
                load: if by_bytes { set.bytes } else { 1 },
                tick: set.progress_tick,
            })
            .collect();
        if let Some((total, _)) = opening {
            // Whether its participant holds a sequence, kept or not: one
            // whose sequences are all kept is not opening its first.
            if self.pending.iter().any(|(k, set)| {
                set.known
                    && (authenticated || !set.authenticated)
                    && k.0.prefix == key.0.prefix
                    && !planned.contains(k)
            }) {
                entries.push(Entry {
                    key: *key,
                    authenticated,
                    received: 1,
                    total,
                    load: if by_bytes { add_bytes } else { 1 },
                    tick: self.progress_clock + 1,
                });
            }
        }
        // (load, last progress) per participant; (load, last progress,
        // index of its newest sequence) per writer.
        let mut participants: HashMap<[u8; 12], (usize, u64)> = HashMap::new();
        let mut writers: HashMap<GUID, (usize, u64, usize)> = HashMap::new();
        for (index, entry) in entries.iter().enumerate() {
            let participant = participants.entry(entry.key.0.prefix).or_insert((0, 0));
            participant.0 += entry.load;
            participant.1 = participant.1.max(entry.tick);
            let writer = writers.entry(entry.key.0).or_insert((0, 0, index));
            writer.0 += entry.load;
            writer.1 = writer.1.max(entry.tick);
            let newest = entries.get(writer.2)?;
            if (entry.key.1, entry.tick) > (newest.key.1, newest.tick) {
                writer.2 = index;
            }
        }
        let candidates = writers.values().filter_map(|(w_load, w_tick, index)| {
            let entry = entries.get(*index)?;
            let (p_load, p_tick) = participants.get(&entry.key.0.prefix).copied()?;
            Some((entry, p_load, p_tick, *w_load, *w_tick))
        });
        let chosen = candidates.min_by(|a, b| {
            // a.received / a.total against b.received / b.total, exactly.
            let completion_a = u64::from(a.0.received) * u64::from(b.0.total);
            let completion_b = u64::from(b.0.received) * u64::from(a.0.total);
            a.0.authenticated
                .cmp(&b.0.authenticated)
                .then(completion_a.cmp(&completion_b))
                .then(b.1.cmp(&a.1))
                .then(a.2.cmp(&b.2))
                .then(b.3.cmp(&a.3))
                .then(a.4.cmp(&b.4))
        })?;
        Some(if chosen.0.key == *key {
            Victim::Newcomer
        } else {
            Victim::Pending(chosen.0.key)
        })
    }

    /// The pending sequences of the rank `authenticated` that no sequence
    /// of that rank evicts, `key` making room at `now` (see `known_victim`).
    ///
    /// A sequence qualifies with more than half its sample's octets and at
    /// least `PROTECTED_MIN_OCTETS`, within the buffer's timeout from its
    /// first fragment. Each participant keeps at most its share of the
    /// sequence bound qualified, its most advanced ones (`further_along`):
    /// `max_pending` over the participants of the rank with a sequence in
    /// progress, the source of `key` counted. The shares together leave a
    /// newcomer's participant its own, so that a full buffer is never all
    /// protected, whoever holds it.
    fn protected(
        &self,
        key: &(GUID, u64),
        authenticated: bool,
        now: Instant,
    ) -> HashSet<(GUID, u64)> {
        let timeout = Duration::from_millis(self.timeout_ms);
        let rank = |set: &FragmentSet| set.known && set.authenticated == authenticated;
        let mut participants: HashSet<[u8; 12]> = self
            .pending
            .iter()
            .filter(|(_, set)| rank(set))
            .map(|(k, _)| k.0.prefix)
            .collect();
        participants.insert(key.0.prefix);
        let share = self.max_pending / participants.len();
        let mut qualified: HashMap<[u8; 12], Vec<Pending<'_>>> = HashMap::new();
        for (k, set) in &self.pending {
            let octets = set.received_octets as u64;
            if rank(set)
                && now.duration_since(set.first_seen) <= timeout
                && set.received_octets >= PROTECTED_MIN_OCTETS
                && octets * PROTECTED_COMPLETION_DEN
                    > u64::from(set.geometry.sample_size) * PROTECTED_COMPLETION_NUM
            {
                qualified.entry(k.0.prefix).or_default().push((k, set));
            }
        }
        let mut protected = HashSet::new();
        for mut sets in qualified.into_values() {
            sets.sort_by(|a, b| further_along(b.1, a.1));
            protected.extend(sets.into_iter().take(share).map(|(k, _)| *k));
        }
        protected
    }

    /// The pending sequences of the rank `authenticated` that `key`,
    /// opening (`opening`: its total fragments and the octets of its first)
    /// or growing at `now`, does not evict for being behind them: each
    /// participant's most advanced sequence (`further_along`) when it is at
    /// least as far along as `key`, in share of its fragments then in
    /// octets, within the buffer's timeout from its first fragment, while
    /// the participants of the rank with a sequence in progress, the source
    /// of `key` counted, are no more than `max_pending`.
    ///
    /// Two genuine large samples of two known peers, each fitting the octet
    /// budget alone and not together, must not evict each other forever when
    /// their fragments interleave: each opening sequence is its participant's
    /// first, never its own victim, and the other is the only one to go. The
    /// one further along keeps its place against the one behind, which waits. The
    /// order is total and a sequence only advances, so one that evicted
    /// another is never evicted back by it reopening: the most advanced
    /// sequence of the rank completes, if it can within the timeout.
    ///
    /// The bounds are what keeps a place from being held:
    /// - The share of fragments comes first, so holding octets against a
    ///   sample costs a share of them sent: a sample of the whole budget
    ///   one fragment in is behind any newcomer of fewer fragments.
    /// - A place lasts the timeout from the first fragment, like a
    ///   protection: a sequence kept alive a fragment at a time loses it,
    ///   the newcomer waiting takes it, and keeps it against the trickle
    ///   reopening behind it.
    /// - With no more participants than sequences, a full buffer holds at
    ///   least one sequence that is no participant's place, so a count
    ///   bound never refuses a newcomer for this rule; past that, every
    ///   participant cannot have a place and none does.
    fn shielded(
        &self,
        key: &(GUID, u64),
        authenticated: bool,
        opening: Option<(u32, usize)>,
        now: Instant,
    ) -> HashSet<(GUID, u64)> {
        let incoming = match opening {
            Some((total, octets)) => advance(1, total, octets),
            None => match self.pending.get(key) {
                Some(set) => advance(
                    set.received_count,
                    set.geometry.total_fragments(),
                    set.received_octets,
                ),
                None => return HashSet::new(),
            },
        };
        let timeout = Duration::from_millis(self.timeout_ms);
        let mut leaders: HashMap<[u8; 12], Pending<'_>> = HashMap::new();
        for (k, set) in &self.pending {
            if !set.known || set.authenticated != authenticated || k == key {
                continue;
            }
            let leader = leaders.entry(k.0.prefix).or_insert((k, set));
            if further_along(set, leader.1).is_gt() {
                *leader = (k, set);
            }
        }
        let participants = leaders.len() + usize::from(!leaders.contains_key(&key.0.prefix));
        if participants > self.max_pending {
            return HashSet::new();
        }
        leaders
            .into_values()
            .filter(|(_, set)| {
                now.duration_since(set.first_seen) <= timeout
                    && incoming
                        .cmp(
                            set.received_count,
                            set.geometry.total_fragments(),
                            set.received_octets,
                        )
                        .is_le()
            })
            .map(|(k, _)| *k)
            .collect()
    }

    /// Get current number of pending incomplete sequences (for monitoring).
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Get missing fragment numbers for a specific (writerGUID, seqNum).
    ///
    /// Returns a list of fragment numbers (1-based) that haven't been received yet.
    /// Used to construct NACK_FRAG submessages for reliable fragmented data.
    ///
    /// # Returns
    ///
    /// - `Some((missing, total))`: List of missing fragment numbers and total expected
    /// - `None`: No such sequence in buffer (either complete or never seen)
    pub fn get_missing_fragments(
        &self,
        writer_guid: &GUID,
        seq_num: u64,
    ) -> Option<(Vec<u32>, u32)> {
        let key = (*writer_guid, seq_num);
        let frag_set = self.pending.get(&key)?;

        let mut missing = Vec::new();
        for frag_num in 1..=frag_set.geometry.total_fragments() {
            if !frag_set.has(frag_num) {
                missing.push(frag_num);
            }
        }

        Some((missing, frag_set.geometry.total_fragments()))
    }

    /// Get all incomplete sequences that have been waiting longer than `min_age_ms`.
    ///
    /// Used to decide which sequences need NACK_FRAG retransmission requests.
    ///
    /// # Returns
    ///
    /// List of (writerGUID, seqNum, missing_count, total_fragments, age_ms)
    /// Returns: Vec of (GUID, seq_num, missing_count, total_frags, age_ms, source_origin)
    pub fn get_stale_sequences(
        &self,
        min_age_ms: u64,
    ) -> Vec<(GUID, u64, usize, u32, u64, Option<Origin>)> {
        let now = Instant::now();
        let min_age = Duration::from_millis(min_age_ms);

        self.pending
            .iter()
            .filter_map(|((guid, seq_num), frag_set)| {
                let age = now.duration_since(frag_set.first_seen);
                if age >= min_age {
                    // First-value-wins above makes received_count <= total an
                    // invariant; saturate anyway so a broken invariant reports
                    // zero missing rather than wrapping to 2^64.
                    let missing_count = (frag_set.geometry.total_fragments() as usize)
                        .saturating_sub(frag_set.received_count as usize);
                    Some((
                        *guid,
                        *seq_num,
                        missing_count,
                        frag_set.geometry.total_fragments(),
                        age.as_millis() as u64,
                        frag_set.source_origin,
                    ))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Per-sequence NACK_FRAG backoff gate.
    ///
    /// Returns `true` (and stamps `last_nacked = now`) when no NACK_FRAG has
    /// been recorded for this (writer, seq) within `backoff`; `false` when
    /// the sequence is still inside its backoff window. Sequences not in the
    /// buffer return `true` (nothing to throttle; the caller may be issuing
    /// a request-all for a never-seen sequence).
    ///
    /// Callers gate outgoing NACK_FRAGs on this to avoid retransmit-request
    /// storms against slow-repair peers (observed: ~787 NACK_FRAGs in 16s,
    /// which amplifies load on the very peer we are waiting for).
    pub fn try_mark_nacked(&mut self, writer_guid: &GUID, seq_num: u64, backoff: Duration) -> bool {
        let now = Instant::now();
        let key = (*writer_guid, seq_num);

        // Per-sequence verdict FIRST, with no side effect. Consulting (and
        // STAMPING) the global gate before this check would let a sequence
        // still inside its own backoff burn the 5 ms global window for
        // everyone behind it in the stale sweep, so most ticks would emit no
        // NACK_FRAG at all. A predicate that refuses must leave no trace.
        if let Some(frag_set) = self.pending.get(&key) {
            if let Some(last) = frag_set.last_nacked {
                if now.duration_since(last) < backoff {
                    return false;
                }
            }
        }

        // Global gate LAST: even if this sequence's own backoff has elapsed,
        // do not let it fire alongside every other sequence whose backoff
        // also just elapsed (the thundering-herd case this exists to
        // prevent). It applies whether or not the entry still exists; only a
        // final yes stamps it.
        if !self.allow_global_nack(now) {
            return false;
        }
        if let Some(frag_set) = self.pending.get_mut(&key) {
            frag_set.last_nacked = Some(now);
        }
        true
    }

    /// Global-only NACK_FRAG gate, for callers with no per-seq `FragmentSet`
    /// to stamp a backoff on (the "never seen this sequence" branch of the
    /// HEARTBEAT_FRAG fast path in `handle_heartbeat_frag`, which requests
    /// every fragment and has nowhere to record a per-seq timestamp). Without
    /// this, that branch fires once per incoming HEARTBEAT_FRAG completely
    /// unthrottled, one NACK_FRAG out for every HEARTBEAT_FRAG in, which
    /// makes it the dominant source of NACK_FRAG traffic in a cold-start
    /// stall.
    pub fn try_mark_nacked_global_only(&mut self) -> bool {
        self.allow_global_nack(Instant::now())
    }

    /// Shared spacing check: approves (and stamps) at most once per
    /// `NACK_FRAG_GLOBAL_MIN_SPACING_MS`, independent of which sequence is
    /// asking.
    fn allow_global_nack(&mut self, now: Instant) -> bool {
        if let Some(last) = self.last_global_nack {
            if now.duration_since(last) < Duration::from_millis(NACK_FRAG_GLOBAL_MIN_SPACING_MS) {
                return false;
            }
        }
        self.last_global_nack = Some(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sample cut into `total` fragments of `len` octets each.
    ///
    /// Fixtures declare the geometry they mean rather than a bare count: the
    /// buffer derives the count from `fragmentSize` and `sampleSize` and holds
    /// every fragment to the length that geometry gives it, so a count with no
    /// geometry behind it is not a shape any peer can send.
    fn geo(total: u32, len: u16) -> FragmentGeometry {
        FragmentGeometry {
            fragment_size: len,
            sample_size: u32::from(len) * total,
        }
    }

    /// A reassembled sample is for the readers its admitted fragments were
    /// sent to - a named one even if it came after the sequence opened (a
    /// replay to a late joiner) - and ENTITYID_UNKNOWN stands for the readers
    /// local when the sequence opened, never for one created afterwards.
    #[test]
    fn a_completed_sample_is_for_the_readers_its_fragments_were_sent_to() {
        let mut buffer = FragmentBuffer::new(256, 100);
        let guid = GUID::from_bytes([7u8; 16]);
        let (a, b, late) = ([0, 0, 1, 7], [0, 0, 2, 7], [0, 0, 3, 7]);
        let local = || vec![a, b];
        let mut insert = |seq, frag, total, data: Vec<u8>, reader| {
            buffer.insert_addressed_fragment(
                guid,
                seq,
                frag,
                geo(total, 1),
                data,
                None,
                reader,
                local,
            )
        };

        // Named fragments: those readers only. A refused fragment (shorter
        // than the geometry) names nobody.
        assert!(insert(1, 1, 3, vec![1], a).is_none());
        assert!(insert(1, 2, 3, Vec::new(), b).is_none());
        assert!(insert(1, 2, 3, vec![2], a).is_none());
        let (payload, audience) = insert(1, 3, 3, vec![3], late).expect("complete");
        assert_eq!(payload, vec![1, 2, 3]);
        assert!(audience.names(a));
        assert!(!audience.names(b), "its only fragment was refused");
        assert!(
            audience.names(late),
            "named by the writer: a replay to a late joiner"
        );
        assert!(!audience.reaches_unnamed());

        // An UNKNOWN fragment: every reader local when the sequence opened,
        // and the unnamed ones, but not a reader that came later.
        assert!(insert(2, 1, 2, vec![1], ENTITYID_UNKNOWN).is_none());
        let (_, audience) = insert(2, 2, 2, vec![2], b).expect("complete");
        assert!(audience.names(a) && audience.names(b));
        assert!(!audience.names(late));
        assert!(audience.reaches_unnamed());
    }

    /// Named readerIds come off the wire one per fragment: at most
    /// `MAX_READERS_PER_SAMPLE` are recorded, and ENTITYID_UNKNOWN is never
    /// crowded out.
    #[test]
    fn a_sequence_records_a_bounded_number_of_readers() {
        let mut buffer = FragmentBuffer::new(256, 100);
        let guid = GUID::from_bytes([7u8; 16]);
        let total = u32::try_from(MAX_READERS_PER_SAMPLE + 3).expect("fits");
        let last_named = (total - 1).to_be_bytes();
        let mut completed = None;
        for frag in 1..=total {
            let reader = if frag == total {
                ENTITYID_UNKNOWN
            } else {
                frag.to_be_bytes()
            };
            completed = buffer.insert_addressed_fragment(
                guid,
                1,
                frag,
                geo(total, 1),
                vec![0],
                None,
                reader,
                Vec::new,
            );
        }
        let (_, audience) = completed.expect("complete");
        assert_eq!(audience.named.len(), MAX_READERS_PER_SAMPLE);
        assert!(audience.names(1u32.to_be_bytes()));
        assert!(!audience.names(last_named), "past the bound, and not local");
        assert!(
            audience.reaches_unnamed(),
            "UNKNOWN past the bound still counts"
        );

        // Local readers are never crowded out, however many there are.
        let many: Vec<[u8; 4]> = (1..=total).map(u32::to_be_bytes).collect();
        let mut completed = None;
        for frag in 1..=total {
            completed = buffer.insert_addressed_fragment(
                guid,
                2,
                frag,
                geo(total, 1),
                vec![0],
                None,
                frag.to_be_bytes(),
                || many.clone(),
            );
        }
        let (_, audience) = completed.expect("complete");
        assert!(many.iter().all(|reader| audience.names(*reader)));

        // Past more local readers than the bound, a late joiner a replay
        // names still counts: the bound is on readers that were NOT local.
        let late = [0xFF, 0, 0, 7];
        let total = u32::try_from(many.len() + 1).expect("fits");
        let mut completed = None;
        for frag in 1..=total {
            let reader = many
                .get(usize::try_from(frag - 1).expect("fits"))
                .copied()
                .unwrap_or(late);
            completed = buffer.insert_addressed_fragment(
                guid,
                3,
                frag,
                geo(total, 1),
                vec![0],
                None,
                reader,
                || many.clone(),
            );
        }
        let (_, audience) = completed.expect("complete");
        assert!(audience.names(late));
    }

    /// The pending audience is what a request for missing fragments speaks
    /// for.
    #[test]
    fn a_pending_sequence_reports_its_audience() {
        let mut buffer = FragmentBuffer::new(256, 100);
        let guid = GUID::from_bytes([7u8; 16]);
        let a = [0, 0, 1, 7];
        assert!(buffer
            .insert_addressed_fragment(guid, 1, 1, geo(2, 1), vec![1], None, a, Vec::new)
            .is_none());
        let audience = buffer.pending_audience(&guid, 1).expect("pending");
        assert!(audience.names(a));
        assert!(buffer.pending_audience(&guid, 2).is_none());
    }

    /// A later DATA_FRAG that announces a smaller total must not shrink the
    /// set it disagrees with. Adopting the latest value would be wrong: two
    /// fragments of a 100-fragment sample followed by a header claiming total
    /// 2 would make the set "complete" and hand the application a truncated
    /// payload. The disagreeing fragment is refused, the first value stands,
    /// and the set still reports 98 missing.
    #[test]
    fn a_later_fragment_cannot_shrink_the_expected_total() {
        let mut buffer = FragmentBuffer::new(256, 100);
        let guid = GUID::from_bytes([7u8; 16]);
        assert!(buffer
            .insert_fragment(guid, 1, 1, geo(100, 1), vec![0xAA])
            .is_none());
        assert!(buffer
            .insert_fragment(guid, 1, 2, geo(100, 1), vec![0xBB])
            .is_none());

        // Fragment 3 arrives claiming the sample is only 2 fragments long.
        let refused = buffer.insert_fragment(guid, 1, 3, geo(2, 1), vec![0xCC]);
        assert!(
            refused.is_none(),
            "a fragment that disagrees on the total must not complete the sample"
        );

        let (missing, total) = buffer
            .get_missing_fragments(&guid, 1)
            .expect("the sequence is still pending");
        assert_eq!(total, 100, "the FIRST announced total stands");
        assert_eq!(missing.len(), 98, "fragments 3..=100 are still missing");
        assert!(!missing.contains(&1) && !missing.contains(&2));
    }

    /// The bound is enforced where the set is ADMITTED, not only in the
    /// classifier's scan: an over-bound total creates no state at all.
    #[test]
    fn an_over_bound_total_is_refused_at_admission() {
        let mut buffer = FragmentBuffer::new(256, 1000);
        let guid = GUID::from_bytes([7u8; 16]);
        assert!(buffer
            .insert_fragment(guid, 1, 1, geo(u32::MAX, 1), vec![1])
            .is_none());
        assert!(buffer
            .insert_fragment(guid, 2, 1, geo(MAX_FRAGMENTS_PER_SAMPLE + 1, 1), vec![1])
            .is_none());
        assert!(buffer
            .insert_fragment(guid, 3, 1, geo(0, 1), vec![1])
            .is_none());
        assert_eq!(
            buffer.pending_count(),
            0,
            "a refused total leaves no set behind"
        );
        // Exactly the bound is admitted (inclusive), and stored as incomplete.
        assert!(buffer
            .insert_fragment(guid, 4, 1, geo(MAX_FRAGMENTS_PER_SAMPLE, 1), vec![1])
            .is_none());
        assert_eq!(buffer.pending_count(), 1);
    }

    /// A fragment number outside `1..=total` is refused, so three fragments
    /// numbered 1, 2 and 99 of a 3-fragment sample cannot complete it with a
    /// payload that is missing #3.
    #[test]
    fn a_fragment_number_outside_the_total_is_refused() {
        let mut buffer = FragmentBuffer::new(256, 1000);
        let guid = GUID::from_bytes([8u8; 16]);
        assert!(buffer
            .insert_fragment(guid, 1, 0, geo(3, 1), vec![0])
            .is_none());
        assert!(buffer
            .insert_fragment(guid, 1, 4, geo(3, 1), vec![0])
            .is_none());
        assert_eq!(buffer.pending_count(), 0);

        assert!(buffer
            .insert_fragment(guid, 1, 1, geo(3, 2), vec![1, 1])
            .is_none());
        assert!(buffer
            .insert_fragment(guid, 1, 2, geo(3, 2), vec![2, 2])
            .is_none());
        assert!(
            buffer
                .insert_fragment(guid, 1, 99, geo(3, 2), vec![9, 9])
                .is_none(),
            "#99 of 3 is refused, and must not count as the third fragment"
        );
        let (missing, _) = buffer
            .get_missing_fragments(&guid, 1)
            .expect("still pending");
        assert_eq!(missing, vec![3]);

        let complete = buffer
            .insert_fragment(guid, 1, 3, geo(3, 2), vec![3, 3])
            .expect("the real #3 completes the sample");
        assert_eq!(complete, vec![1, 1, 2, 2, 3, 3]);
    }

    /// A sequence refused by its own backoff must leave the global gate
    /// untouched, so the next sequence in the sweep can still be NACKed.
    #[test]
    fn a_refused_sequence_leaves_the_global_gate_open() {
        let mut buffer = FragmentBuffer::new(256, 1000);
        let a = GUID::from_bytes([1u8; 16]);
        let b = GUID::from_bytes([2u8; 16]);
        let backoff = Duration::from_millis(200);
        buffer.insert_fragment(a, 1, 1, geo(3, 1), vec![0xAA]);
        buffer.insert_fragment(b, 1, 1, geo(3, 1), vec![0xBB]);

        assert!(
            buffer.try_mark_nacked(&a, 1, backoff),
            "first NACK for a is approved"
        );

        // Let the global window (5 ms) pass; the per-seq backoff (200 ms)
        // has not. Waiting longer only makes the assertion easier, so a
        // scheduler stall cannot flip it.
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(NACK_FRAG_GLOBAL_MIN_SPACING_MS + 2) {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            !buffer.try_mark_nacked(&a, 1, backoff),
            "a is inside its own backoff and is refused"
        );
        assert!(
            buffer.try_mark_nacked(&b, 1, backoff),
            "the refusal of a must not have stamped the global gate against b"
        );
    }

    /// Overflow eviction stays within the writer that holds the most sets:
    /// a lossy peer filling the buffer cannot evict another writer's sample
    /// just because that sample carries a larger sequence number.
    #[test]
    fn eviction_stays_within_the_writer_that_holds_the_most_sets() {
        let mut buffer = FragmentBuffer::new(4, 10_000);
        let lossy = GUID::from_bytes([0xAAu8; 16]);
        let other = GUID::from_bytes([0xBBu8; 16]);
        for seq in 1..=4u64 {
            assert!(buffer
                .insert_fragment(lossy, seq, 1, geo(2, 1), vec![1])
                .is_none());
        }
        assert_eq!(buffer.pending_count(), 4);

        // The fifth set, from another writer, at a far larger sequence number.
        assert!(buffer
            .insert_fragment(other, 1000, 1, geo(2, 1), vec![1])
            .is_none());
        assert_eq!(buffer.pending_count(), 4, "one set was evicted");
        assert!(
            buffer.get_missing_fragments(&other, 1000).is_some(),
            "the newcomer from the other writer survives"
        );
        assert!(
            buffer.get_missing_fragments(&lossy, 4).is_none(),
            "the lossy writer's newest set is the victim"
        );
        for seq in 1..=3u64 {
            assert!(buffer.get_missing_fragments(&lossy, seq).is_some());
        }
    }

    /// A writer on the participant `prefix_tail` (the last four prefix
    /// octets), entity of the stateless message writer.
    fn spoofed_writer(prefix_tail: u32) -> GUID {
        let mut prefix = [0u8; 12];
        prefix[8..].copy_from_slice(&prefix_tail.to_be_bytes());
        GUID::new(prefix, [0, 2, 1, 0xC3])
    }

    /// A genuine peer on a bound prefix (first bit 1: the highest GUID
    /// octets of all).
    fn genuine_writer() -> GUID {
        GUID::new([0x80 | 0x7F; 12], [0, 2, 1, 0xC3])
    }

    /// The participants a test declares known.
    struct Known(HashSet<[u8; 12]>);

    impl KnownSources for Known {
        fn is_known(&self, prefix: &[u8; 12]) -> bool {
            self.0.contains(prefix)
        }
    }

    /// A buffer that knows the participants of `writers` and no other.
    fn knowing(buffer: FragmentBuffer, writers: &[GUID]) -> FragmentBuffer {
        buffer.with_known_sources(Arc::new(Known(
            writers.iter().map(|writer| writer.prefix).collect(),
        )))
    }

    /// DATA_FRAG flood on the discovery reassembly buffer: 300 spoofed
    /// writers on prefixes discovery does not know, one pending sequence
    /// each, must not evict the in-progress reassembly of a handshake
    /// message from a known peer. The overflow eviction must not break the
    /// tie between equal writers on the GUID octets (the bound prefix would
    /// always lose); the flood fills a pool of its own.
    #[test]
    fn v2_fragment_flood_from_spoofed_writers_evicts_a_genuine_handshake() {
        let genuine = genuine_writer();
        let mut buf = knowing(FragmentBuffer::new(256, 500), &[genuine]);
        let geo = FragmentGeometry {
            fragment_size: 1024,
            sample_size: 2048,
        };
        assert!(buf
            .insert_fragment(genuine, 1, 1, geo, vec![0xAA; 1024])
            .is_none());
        for n in 0..300u32 {
            let _ = buf.insert_fragment(spoofed_writer(n), 1, 1, geo, vec![0xBB; 1024]);
        }
        assert_eq!(
            buf.unknown_count,
            buf.unknown_max_pending(),
            "a pool of its own"
        );
        assert_eq!(buf.pending_count(), buf.unknown_max_pending() + 1);
        let done = buf.insert_fragment(genuine, 1, 2, geo, vec![0xAA; 1024]);
        assert_eq!(
            done.map(|sample| sample.len()),
            Some(2048),
            "the genuine peer's fragmented handshake message was evicted by spoofed writers"
        );
    }

    /// The same flood arriving FIRST: a later participant still evicts only
    /// from a source holding more than it does, never on GUID order. One
    /// source holding two sequences pays for the newcomer.
    #[test]
    fn overflow_evicts_from_the_source_holding_more_than_the_newcomer() {
        let mut buf = FragmentBuffer::new(4, 10_000);
        let heavy = spoofed_writer(1);
        let light = spoofed_writer(2);
        let newcomer = genuine_writer();
        for seq in 1..=2u64 {
            assert!(buf
                .insert_fragment(heavy, seq, 1, geo(2, 1), vec![1])
                .is_none());
        }
        for seq in 1..=2u64 {
            assert!(buf
                .insert_fragment(light, seq, 1, geo(2, 1), vec![1])
                .is_none());
        }
        // `light` progressed last; `heavy` and `light` tie at two each.
        assert!(buf
            .insert_fragment(newcomer, 1, 1, geo(2, 1), vec![1])
            .is_none());
        assert!(
            buf.get_missing_fragments(&newcomer, 1).is_some(),
            "the newcomer holding less than both survives"
        );
        assert!(
            buf.get_missing_fragments(&heavy, 2).is_none(),
            "the tie went to the source idle longest, its newest sequence"
        );
        assert!(buf.get_missing_fragments(&heavy, 1).is_some());
        assert!(buf.get_missing_fragments(&light, 1).is_some());
        assert!(buf.get_missing_fragments(&light, 2).is_some());
    }

    /// Two writers of ONE participant count as one source: spreading a
    /// flood over writers of the same prefix gains no share.
    #[test]
    fn writers_of_one_participant_share_its_load() {
        let mut buf = FragmentBuffer::new(3, 10_000);
        let a = GUID::new([0x11; 12], [0, 0, 1, 2]);
        let b = GUID::new([0x11; 12], [0, 0, 2, 2]);
        let other = genuine_writer();
        assert!(buf
            .insert_fragment(other, 1, 1, geo(2, 1), vec![1])
            .is_none());
        assert!(buf.insert_fragment(a, 1, 1, geo(2, 1), vec![1]).is_none());
        assert!(buf.insert_fragment(b, 1, 1, geo(2, 1), vec![1]).is_none());
        // Full. A third set from the same participant: it pays itself.
        assert!(buf.insert_fragment(b, 2, 1, geo(2, 1), vec![1]).is_none());
        assert_eq!(buf.pending_count(), 3);
        assert!(buf.get_missing_fragments(&other, 1).is_some());
        assert!(
            buf.get_missing_fragments(&b, 2).is_none(),
            "its own newest went"
        );
    }

    /// What a sequence of `geometry` with no local reader is charged.
    fn charge(geometry: FragmentGeometry) -> usize {
        FragmentBuffer::charge_for(geometry, 0).expect("fits")
    }

    /// The octet bound: one source filling the budget with large sequences
    /// cannot evict a smaller source's sequence; a newcomer that takes the
    /// buffer over the budget evicts from the source holding more octets.
    #[test]
    fn the_octet_budget_is_shared_by_source() {
        let (small_geo, big_geo) = (geo(2, 512), geo(2, 1024));
        let budget = charge(small_geo) + 3 * charge(big_geo);
        let mut buf = FragmentBuffer::new(256, 10_000).with_max_bytes(budget);
        let big = spoofed_writer(1);
        let small = genuine_writer();
        assert!(buf
            .insert_fragment(small, 1, 1, small_geo, vec![0xAA; 512])
            .is_none());
        for seq in 1..=3u64 {
            assert!(buf
                .insert_fragment(big, seq, 1, big_geo, vec![0xBB; 1024])
                .is_none());
        }
        assert_eq!(buf.buffered_bytes, budget);
        // Over the budget: the source holding more octets pays, newest first.
        assert!(buf
            .insert_fragment(small, 2, 1, big_geo, vec![0xAA; 1024])
            .is_none());
        assert!(buf.buffered_bytes <= budget, "{}", buf.buffered_bytes);
        assert!(buf.get_missing_fragments(&big, 3).is_none());
        assert!(buf.get_missing_fragments(&small, 1).is_some());
        assert!(buf.get_missing_fragments(&small, 2).is_some());
        // And the big source taking more evicts only its own.
        assert!(buf
            .insert_fragment(big, 4, 1, big_geo, vec![0xBB; 1024])
            .is_none());
        assert!(buf.buffered_bytes <= budget, "{}", buf.buffered_bytes);
        assert!(buf.get_missing_fragments(&small, 1).is_some());
        assert!(buf.get_missing_fragments(&small, 2).is_some());
        assert_eq!(
            buf.insert_fragment(small, 1, 2, small_geo, vec![0xAA; 512])
                .map(|sample| sample.len()),
            Some(1024)
        );
    }

    /// Among known sources, the sequence furthest from completion goes,
    /// whatever its size: a large sample three quarters there survives a
    /// newcomer from a source holding more, smaller, less complete ones,
    /// which pays with its own newest.
    #[test]
    fn among_known_sources_the_least_complete_goes_not_the_largest() {
        let (small_geo, large_geo, newcomer_geo) = (geo(2, 4096), geo(4, 16384), geo(2, 8192));
        let budget = 3 * charge(small_geo) + charge(large_geo);
        let mut buf = FragmentBuffer::new(256, 10_000).with_max_bytes(budget);
        let many_small = genuine_writer();
        let one_large = spoofed_writer(1);
        for seq in 1..=3u64 {
            assert!(buf
                .insert_fragment(many_small, seq, 1, small_geo, vec![0xAA; 4096])
                .is_none());
        }
        for frag in 1..=3u32 {
            assert!(buf
                .insert_fragment(one_large, 1, frag, large_geo, vec![0xBB; 16384])
                .is_none());
        }
        assert_eq!(buf.buffered_bytes, budget);
        // 1 of 2 against 3 of 4: the newcomer, newest of its writer, pays.
        assert!(buf
            .insert_fragment(many_small, 4, 1, newcomer_geo, vec![0xAA; 8192])
            .is_none());
        assert!(buf.get_missing_fragments(&many_small, 4).is_none());
        assert!(buf.get_missing_fragments(&one_large, 1).is_some());
        assert_eq!(buf.buffered_bytes, budget, "the refused one left no trace");
        // A large sample one fragment in, against small ones half there: it
        // goes, though its source holds the least.
        let mut buf = FragmentBuffer::new(256, 10_000).with_max_bytes(budget);
        assert!(buf
            .insert_fragment(one_large, 1, 1, large_geo, vec![0xBB; 16384])
            .is_none());
        for seq in 1..=4u64 {
            let _ = buf.insert_fragment(many_small, seq, 1, small_geo, vec![0xAA; 4096]);
        }
        assert!(buf.get_missing_fragments(&one_large, 1).is_none());
        for seq in 1..=4u64 {
            assert!(buf.get_missing_fragments(&many_small, seq).is_some());
        }
    }

    /// A sample whose sequence would cost more than the whole octet budget
    /// is refused at its first fragment: it could never complete. One that
    /// costs exactly the budget is admitted.
    #[test]
    fn a_sample_over_the_octet_budget_is_refused() {
        let fits = geo(2, 1024);
        let mut buf = FragmentBuffer::new(16, 10_000).with_max_bytes(charge(fits));
        let w = genuine_writer();
        assert!(buf
            .insert_fragment(w, 1, 1, geo(3, 1024), vec![0; 1024])
            .is_none());
        assert_eq!(buf.pending_count(), 0, "one fragment more than the budget");
        assert_eq!(buf.buffered_bytes, 0);
        assert!(buf.insert_fragment(w, 2, 1, fits, vec![0; 1024]).is_none());
        assert_eq!(buf.pending_count(), 1, "exactly the budget fits");
        assert_eq!(
            buf.insert_fragment(w, 2, 2, fits, vec![0; 1024])
                .map(|sample| sample.len()),
            Some(2048)
        );
    }

    /// A sequence is charged its whole sample, bitmap and bookkeeping when
    /// it opens, whatever arrives later: `buffered_bytes` does not move with
    /// new fragments or duplicates, and completion, expiry and eviction give
    /// back what they remove.
    #[test]
    fn the_octet_count_follows_every_removal() {
        let mut buf = FragmentBuffer::new(1, 0);
        let w = genuine_writer();
        let opened = charge(geo(3, 8));
        assert!(buf
            .insert_fragment(w, 1, 1, geo(3, 8), vec![1; 8])
            .is_none());
        assert_eq!(buf.buffered_bytes, opened, "charged in full at opening");
        assert!(buf
            .insert_fragment(w, 1, 1, geo(3, 8), vec![1; 8])
            .is_none());
        assert!(buf
            .insert_fragment(w, 1, 2, geo(3, 8), vec![1; 8])
            .is_none());
        assert_eq!(buf.buffered_bytes, opened, "nothing more per fragment");
        assert!(buf
            .insert_fragment(w, 1, 3, geo(3, 8), vec![1; 8])
            .is_some());
        assert_eq!(buf.buffered_bytes, 0, "completion gives back");
        assert!(buf
            .insert_fragment(w, 2, 1, geo(2, 8), vec![1; 8])
            .is_none());
        assert!(buf
            .insert_fragment(w, 3, 1, geo(2, 8), vec![1; 8])
            .is_none());
        assert_eq!(buf.pending_count(), 1);
        assert_eq!(buf.buffered_bytes, charge(geo(2, 8)), "eviction gives back");
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(buf.evict_expired(), 1);
        assert_eq!(buf.buffered_bytes, 0, "expiry gives back");
    }

    /// The charge is what the sequence allocates: a 1-octet fragmentSize
    /// costs one bit of bitmap per fragment on top of the sample, never an
    /// allocation per fragment.
    #[test]
    fn a_one_octet_fragment_size_costs_a_bit_per_fragment() {
        let tiny = FragmentGeometry {
            fragment_size: 1,
            sample_size: 1 << 20,
        };
        let whole = FragmentGeometry {
            fragment_size: 1 << 15,
            sample_size: 1 << 20,
        };
        // 2^20 bits against one 64-bit word.
        assert_eq!(charge(tiny) - charge(whole), (1 << 20) / 8 - 8);
        let mut buf = FragmentBuffer::new(4, 10_000);
        let w = genuine_writer();
        for frag in 1..(1u32 << 20) {
            assert!(buf.insert_fragment(w, 1, frag, tiny, vec![5]).is_none());
        }
        assert_eq!(buf.buffered_bytes, charge(tiny));
        let sample = buf
            .insert_fragment(w, 1, 1 << 20, tiny, vec![5])
            .expect("complete");
        assert_eq!(sample.len(), 1 << 20);
        assert!(sample.iter().all(|octet| *octet == 5));
    }

    /// Fragments in any order land in their place: appended in order, a
    /// gap zero-filled ahead of one that comes early and overwritten by the
    /// ones it waits for, the last one short.
    #[test]
    fn fragments_in_any_order_reassemble_the_sample() {
        let shape = FragmentGeometry {
            fragment_size: 7,
            sample_size: 7 * 999 + 3,
        };
        let original: Vec<u8> = (0..shape.sample_size).map(|i| (i % 253) as u8).collect();
        let fragment = |frag: u32| {
            let at = (frag as usize - 1) * 7;
            original[at..at + shape.expected_fragment_len(frag).expect("inside")].to_vec()
        };
        // In order with jumps ahead, then the gaps backwards, then repeats.
        let mut order: Vec<u32> = (1..=1000).filter(|n| n % 3 != 0).collect();
        order.extend((1..=1000).filter(|n| n % 3 == 0).rev());
        let mut buf = FragmentBuffer::new(4, 10_000);
        let w = genuine_writer();
        let mut done = None;
        for (i, frag) in order.iter().enumerate() {
            done = buf.insert_fragment(w, 1, *frag, shape, fragment(*frag));
            if i + 1 < order.len() {
                assert!(done.is_none());
                assert!(buf
                    .insert_fragment(w, 1, *frag, shape, fragment(*frag))
                    .is_none());
            }
        }
        assert_eq!(done.expect("complete"), original);
    }

    #[test]
    fn test_fragment_buffer_in_order() {
        let mut buffer = FragmentBuffer::new(256, 500);
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // Insert fragments in order
        let r1 = buffer.insert_fragment(guid, 1, 1, geo(3, 2), vec![0xAA, 0xBB]);
        assert!(r1.is_none());

        let r2 = buffer.insert_fragment(guid, 1, 2, geo(3, 2), vec![0xCC, 0xDD]);
        assert!(r2.is_none());

        let r3 = buffer.insert_fragment(guid, 1, 3, geo(3, 2), vec![0xEE, 0xFF]);
        assert!(r3.is_some());

        let complete = r3.expect("Should return complete payload after inserting final fragment");
        assert_eq!(complete, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_fragment_buffer_out_of_order() {
        let mut buffer = FragmentBuffer::new(256, 500);
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // Insert fragment #3 first (out-of-order arrival)
        let r3 = buffer.insert_fragment(guid, 1, 3, geo(4, 2), vec![0xEE, 0xFF]);
        assert!(r3.is_none());

        // Insert fragment #1
        let r1 = buffer.insert_fragment(guid, 1, 1, geo(4, 2), vec![0xAA, 0xBB]);
        assert!(r1.is_none());

        // Insert fragment #4
        let r4 = buffer.insert_fragment(guid, 1, 4, geo(4, 2), vec![0x11, 0x22]);
        assert!(r4.is_none());

        // Insert fragment #2 (last one)
        let r2 = buffer.insert_fragment(guid, 1, 2, geo(4, 2), vec![0xCC, 0xDD]);
        assert!(r2.is_some());

        let complete = r2.expect("Should return complete payload after out-of-order reassembly");
        assert_eq!(
            complete,
            vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]
        );
    }

    #[test]
    fn test_timeout_eviction() {
        let mut buffer = FragmentBuffer::new(256, 100); // 100ms timeout
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // Insert partial sequence
        buffer.insert_fragment(guid, 1, 1, geo(3, 1), vec![0xAA]);
        assert_eq!(buffer.pending_count(), 1);

        // Wait for timeout
        std::thread::sleep(std::time::Duration::from_millis(150));

        // Evict expired
        let evicted = buffer.evict_expired();
        assert_eq!(evicted, 1);
        assert_eq!(buffer.pending_count(), 0);
    }

    #[test]
    fn test_overflow_evicts_newest_seq() {
        let mut buffer = FragmentBuffer::new(2, 500); // Max 2 sequences
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // Fill buffer
        buffer.insert_fragment(guid, 1, 1, geo(2, 1), vec![0xAA]);
        buffer.insert_fragment(guid, 2, 1, geo(2, 1), vec![0xBB]);
        assert_eq!(buffer.pending_count(), 2);

        // Insert 3rd sequence -> should evict the NEWEST seq (seqNum=3):
        // the oldest incomplete seq is the reorder-gate blocker and must
        // survive to complete.
        buffer.insert_fragment(guid, 3, 1, geo(2, 1), vec![0xCC]);
        assert_eq!(buffer.pending_count(), 2);

        // Verify seqNum=3 was the victim, oldest sequences survived
        assert!(buffer.pending.contains_key(&(guid, 1)));
        assert!(buffer.pending.contains_key(&(guid, 2)));
        assert!(!buffer.pending.contains_key(&(guid, 3)));
    }

    #[test]
    fn test_slow_progress_survives_eviction() {
        // A sequence receiving a NEW fragment every 300ms with a 1000ms
        // timeout: a first_seen clock would evict it (total age exceeds
        // 1000ms before all fragments arrive, and a sample that slow to
        // arrive would be evicted and requested again forever). The
        // last-progress clock keeps it alive through completion.
        let mut buffer = FragmentBuffer::new(256, 1000);
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        let total = 5u32;
        let mut done = None;
        let mut last_progress = Instant::now();
        for frag in 1..=total {
            if frag > 1 {
                std::thread::sleep(Duration::from_millis(300));
            }
            // Total wall age reaches 1200ms > timeout by the last round,
            // but progress happened 300ms ago: must never evict.
            //
            // The sleep is 300 ms against a 1000 ms timeout, so this asserts a
            // NEGATIVE with a 700 ms margin. A scheduler stall past that margin
            // would fail with a message about a buffer defect that does not
            // exist, so the idle time is MEASURED and the assertion is made
            // only while it is still inside the timeout (as the siblings
            // `test_global_nack_rate_cap*` do).
            let evicted = buffer.evict_expired();
            if last_progress.elapsed() < Duration::from_millis(1000) {
                assert_eq!(
                    evicted, 0,
                    "in-progress sequence must not be evicted (frag {})",
                    frag
                );
            }
            done = buffer.insert_fragment(guid, 61, frag, geo(total, 1), vec![frag as u8]);
            last_progress = Instant::now();
        }
        let complete = done.expect("sequence must complete despite >timeout total age");
        assert_eq!(complete, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_no_progress_evicted_and_duplicates_are_not_progress() {
        let mut buffer = FragmentBuffer::new(256, 200);
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // One fragment, then only a duplicate re-store: no progress.
        buffer.insert_fragment(guid, 1, 1, geo(3, 1), vec![0xAA]);
        std::thread::sleep(Duration::from_millis(120));
        // Duplicate re-store must NOT refresh the progress clock
        buffer.insert_fragment(guid, 1, 1, geo(3, 1), vec![0xAA]);
        std::thread::sleep(Duration::from_millis(120));

        // 240ms since the only NEW fragment > 200ms timeout -> evicted,
        // even though the duplicate arrived 120ms ago.
        assert_eq!(buffer.evict_expired(), 1);
        assert_eq!(buffer.pending_count(), 0);
    }

    #[test]
    fn test_nack_backoff_single_candidate() {
        let mut buffer = FragmentBuffer::new(256, 1000);
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let backoff = Duration::from_millis(200);

        // Incomplete sequence in the buffer
        buffer.insert_fragment(guid, 1, 1, geo(3, 1), vec![0xAA]);

        // Two stale checks 50ms apart -> exactly one NACK candidate.
        //
        // The refusal is asserted only while the clock agrees it is still
        // inside the 200 ms backoff: a scheduler stall past the 150 ms margin
        // would otherwise fail here with a message about a backoff defect that
        // does not exist.
        let first = Instant::now();
        assert!(buffer.try_mark_nacked(&guid, 1, backoff));
        std::thread::sleep(Duration::from_millis(50));
        if first.elapsed() < backoff {
            assert!(!buffer.try_mark_nacked(&guid, 1, backoff));
        }

        // After the backoff window expires, NACK is allowed again. Sleep past
        // the window from the LAST approval, measured, not assumed.
        while first.elapsed() <= backoff {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(buffer.try_mark_nacked(&guid, 1, backoff));

        // Unknown sequence: no per-seq state to throttle on, so once the
        // shared global spacing gate has also cleared, the caller may
        // proceed. (The global gate itself is exercised in
        // `test_global_nack_rate_cap` below.)
        std::thread::sleep(Duration::from_millis(NACK_FRAG_GLOBAL_MIN_SPACING_MS));
        assert!(buffer.try_mark_nacked(&guid, 99, backoff));
    }

    #[test]
    fn test_global_nack_rate_cap() {
        // Many DIFFERENT sequences, each individually past its own per-seq
        // backoff, must NOT all be approved in the same instant: the shared
        // global gate caps the aggregate rate regardless of how many
        // distinct sequences are simultaneously eligible (the cold-start
        // thundering herd of large-sample repairs this gate targets).
        let mut buffer = FragmentBuffer::new(256, 1000);
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let backoff = Duration::from_millis(200);

        for seq in 0..20u64 {
            buffer.insert_fragment(guid, seq, 1, geo(3, 1), vec![0xAA]);
        }

        let mut approved = 0;
        let burst_start = std::time::Instant::now();
        for seq in 0..20u64 {
            if buffer.try_mark_nacked(&guid, seq, backoff) {
                approved += 1;
            }
        }
        // Without a global cap all 20 would be approved (each has a fresh
        // per-seq state); with it, at most one request per spacing window
        // clears the shared gate. Bound the assertion by the wall clock the
        // loop actually consumed: a preempted loop may legitimately cross a
        // window boundary, and this test must not depend on the scheduler.
        let allowed =
            1 + burst_start.elapsed().as_millis() as u64 / NACK_FRAG_GLOBAL_MIN_SPACING_MS;
        assert!(
            approved <= allowed,
            "global gate approved {approved} of 20 same-instant requests (allowed {allowed})"
        );

        // The gate recovers once its spacing window elapses.
        std::thread::sleep(Duration::from_millis(NACK_FRAG_GLOBAL_MIN_SPACING_MS));
        assert!(buffer.try_mark_nacked(&guid, 1, backoff));
    }

    #[test]
    fn test_global_nack_rate_cap_covers_unseen_sequences() {
        // The HEARTBEAT_FRAG "never seen this sequence" branch has no
        // FragmentSet to stamp a per-seq backoff on and relies entirely on
        // `try_mark_nacked_global_only`. A burst of HEARTBEAT_FRAGs for many
        // distinct never-seen sequences must still be capped in aggregate.
        let mut buffer = FragmentBuffer::new(256, 1000);
        let mut approved = 0;
        let burst_start = std::time::Instant::now();
        for _ in 0..10 {
            if buffer.try_mark_nacked_global_only() {
                approved += 1;
            }
        }
        // The gate approves at most one call per spacing window. A tight loop
        // normally spans zero windows, but a preempted one can legitimately
        // cross a few, so bound the assertion by the wall clock the loop
        // actually consumed rather than assuming it ran instantly.
        let allowed =
            1 + burst_start.elapsed().as_millis() as u64 / NACK_FRAG_GLOBAL_MIN_SPACING_MS;
        assert!(
            approved <= allowed,
            "global-only gate approved {approved} of 10 same-instant calls (allowed {allowed})"
        );

        std::thread::sleep(Duration::from_millis(NACK_FRAG_GLOBAL_MIN_SPACING_MS));
        assert!(buffer.try_mark_nacked_global_only());
    }

    #[test]
    fn test_get_missing_fragments() {
        let mut buffer = FragmentBuffer::new(256, 500);
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // Insert fragments 1 and 3 (missing 2 and 4)
        buffer.insert_fragment(guid, 1, 1, geo(4, 1), vec![0xAA]);
        buffer.insert_fragment(guid, 1, 3, geo(4, 1), vec![0xCC]);

        let result = buffer.get_missing_fragments(&guid, 1);
        assert!(result.is_some());

        let (missing, total) = result.unwrap();
        assert_eq!(total, 4);
        assert_eq!(missing, vec![2, 4]); // Missing fragments 2 and 4
    }

    #[test]
    fn test_get_missing_fragments_not_found() {
        let buffer = FragmentBuffer::new(256, 500);
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // No fragments inserted - should return None
        let result = buffer.get_missing_fragments(&guid, 99);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_stale_sequences() {
        let mut buffer = FragmentBuffer::new(256, 500);
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // Insert partial sequence
        buffer.insert_fragment(guid, 1, 1, geo(4, 1), vec![0xAA]);
        buffer.insert_fragment(guid, 1, 2, geo(4, 1), vec![0xBB]);

        // Not stale yet (0ms threshold)
        let stale = buffer.get_stale_sequences(0);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].0, guid); // GUID
        assert_eq!(stale[0].1, 1); // seq_num
        assert_eq!(stale[0].2, 2); // missing_count (fragments 3, 4)
        assert_eq!(stale[0].3, 4); // total_fragments

        // Wait and check again with high threshold - should be empty
        let stale = buffer.get_stale_sequences(10000);
        assert_eq!(stale.len(), 0);
    }

    /// A geometry with no fragment in it names no fragment.
    ///
    /// `fragmentSize == 0` gives `ceil(sampleSize / fragmentSize)` nothing to
    /// divide by. The count must not fall back on `fragmentsInSubmessage`
    /// then: one DATA_FRAG declaring `fragmentSize = 0, fragmentsInSubmessage
    /// = 1` would become a complete sample of whatever length its body
    /// carried (28 octets delivered to a subscriber for a declared sampleSize
    /// of 64). There is no fallback.
    #[test]
    fn a_geometry_with_no_fragment_in_it_admits_nothing() {
        let mut buffer = FragmentBuffer::new(8, 5000);
        let guid = GUID::from_bytes([0x51; 16]);

        for (case, geometry) in [
            (
                "a zero fragment size",
                FragmentGeometry {
                    fragment_size: 0,
                    sample_size: 64,
                },
            ),
            (
                "a zero sample size",
                FragmentGeometry {
                    fragment_size: 8,
                    sample_size: 0,
                },
            ),
        ] {
            assert_eq!(geometry.total_fragments(), 0, "{case}: no fragments");
            assert!(
                buffer
                    .insert_fragment(guid, 1, 1, geometry, vec![0xAA; 28])
                    .is_none(),
                "{case}: nothing completes"
            );
            assert_eq!(
                buffer.pending_count(),
                0,
                "{case}: and nothing is left waiting either"
            );
        }
    }

    /// A fragment shorter than its geometry is refused; the set is untouched.
    ///
    /// Completion is a COUNT, so a short fragment admitted is a sample
    /// completed short with every octet behind the hole in the wrong place:
    /// `sampleSize` 64 cut at 32, a fragment 1 of 20 octets, and the
    /// subscriber would be handed 52 octets called complete. Refusing the fragment
    /// rather than the sequence leaves a retransmission free to repair it -
    /// the same choice the divergent-geometry rule makes.
    #[test]
    fn a_fragment_shorter_than_its_geometry_is_refused() {
        let mut buffer = FragmentBuffer::new(8, 5000);
        let guid = GUID::from_bytes([0x52; 16]);
        let geometry = geo(2, 32);

        assert!(
            buffer
                .insert_fragment(guid, 1, 1, geometry, vec![0xAA; 20])
                .is_none(),
            "a fragment 1 of 20 octets where 32 are declared completes nothing"
        );
        assert_eq!(
            buffer.pending_count(),
            0,
            "and it creates no sequence to wait around it"
        );

        // The repair arrives, and it is admitted: the refusal is of the
        // fragment, not of the (writer, sequence).
        assert!(buffer
            .insert_fragment(guid, 1, 1, geometry, vec![0xAA; 32])
            .is_none());
        let sample = buffer
            .insert_fragment(guid, 1, 2, geometry, vec![0xBB; 32])
            .expect("the repaired sample completes");
        assert_eq!(sample.len(), 64, "and it is the length it declared");
    }

    /// The LAST fragment is short by design, and must stay admitted.
    ///
    /// `build_data_frag_packets` chunks the encapsulated sample and stops, so
    /// every sample whose length is not a multiple of the fragment size ends
    /// with a short fragment. A rule that refused short fragments outright
    /// would refuse our own traffic.
    #[test]
    fn the_last_fragment_carries_the_remainder_and_is_admitted() {
        let mut buffer = FragmentBuffer::new(8, 5000);
        let guid = GUID::from_bytes([0x53; 16]);
        let geometry = FragmentGeometry {
            fragment_size: 32,
            sample_size: 48,
        };
        assert_eq!(geometry.total_fragments(), 2);
        assert_eq!(geometry.expected_fragment_len(1), Some(32));
        assert_eq!(
            geometry.expected_fragment_len(2),
            Some(16),
            "the last fragment carries what the sample has left, not a full one"
        );

        assert!(buffer
            .insert_fragment(guid, 1, 1, geometry, vec![0xAA; 32])
            .is_none());
        let sample = buffer
            .insert_fragment(guid, 1, 2, geometry, vec![0xBB; 16])
            .expect("a conforming short last fragment completes the sample");
        assert_eq!(sample.len(), 48);
        assert_eq!(&sample[..32], &[0xAA; 32]);
        assert_eq!(&sample[32..], &[0xBB; 16]);
    }

    /// A fragment LONGER than its geometry is clipped, never refused.
    ///
    /// What reaches this door is a slice of a submessage, and
    /// `octetsToNextHeader` counts the alignment padding a peer may add
    /// (RTPS v2.5 Sec.8.3.3.3.3) - so a conforming writer that pads hands us
    /// 1 to 3 octets more than the fragment holds. Our own emitter adds none
    /// (`encode_data_frag` declares `32 + payload.len()`), which is exactly
    /// why a strict equality would pass here and yet refuse somebody else's
    /// conforming traffic on the wire.
    #[test]
    fn a_fragment_longer_than_its_geometry_is_clipped() {
        let mut buffer = FragmentBuffer::new(8, 5000);
        let guid = GUID::from_bytes([0x54; 16]);
        let geometry = FragmentGeometry {
            fragment_size: 32,
            sample_size: 48,
        };

        assert!(buffer
            .insert_fragment(guid, 1, 1, geometry, vec![0xAA; 35])
            .is_none());
        let sample = buffer
            .insert_fragment(guid, 1, 2, geometry, vec![0xBB; 19])
            .expect("a padded peer's fragments still complete the sample");
        assert_eq!(
            sample.len(),
            48,
            "the sample is the length it declared, padding and all"
        );
        assert_eq!(&sample[..32], &[0xAA; 32]);
        assert_eq!(&sample[32..], &[0xBB; 16]);
    }

    /// A later fragment that disagrees about the GEOMETRY is refused.
    ///
    /// The widening of this rule from `total_fragments` to the whole
    /// geometry: two fragments can agree on a count and still describe
    /// different samples - 2 fragments of 32 for a 64-octet sample, and 2
    /// fragments of 64 for a 128-octet one. First value wins, the disagreeing
    /// fragment is refused, and the set it disagrees with is left as it was.
    #[test]
    fn a_later_fragment_cannot_change_the_geometry() {
        let mut buffer = FragmentBuffer::new(8, 5000);
        let guid = GUID::from_bytes([0x55; 16]);
        let admitted = geo(2, 32);
        let other = geo(2, 64);
        assert_eq!(
            admitted.total_fragments(),
            other.total_fragments(),
            "fixture: the two geometries agree on the COUNT, which is all the \
             rule used to compare"
        );

        assert!(buffer
            .insert_fragment(guid, 1, 1, admitted, vec![0xAA; 32])
            .is_none());
        assert!(
            buffer
                .insert_fragment(guid, 1, 2, other, vec![0xBB; 64])
                .is_none(),
            "the disagreeing fragment completes nothing"
        );
        let (missing, total) = buffer
            .get_missing_fragments(&guid, 1)
            .expect("the sequence is still there, as it was admitted");
        assert_eq!((missing, total), (vec![2], 2));
    }

    // Adversarial reassembly: a 100 MB sample, spoofed-prefix floods, and the
    // real memory a 1-octet fragmentSize costs.
    fn pfx(n: u32) -> GUID {
        let mut b = [0u8; 16];
        b[..4].copy_from_slice(&n.to_be_bytes());
        b[4] = 0xEE;
        b[15] = 0x02;
        GUID::from_bytes(b)
    }

    fn rss_kib() -> usize {
        let s = std::fs::read_to_string("/proc/self/statm").unwrap();
        let pages: usize = s.split_whitespace().nth(1).unwrap().parse().unwrap();
        pages * 4
    }

    /// A legitimate 100 MB sample, alone, within the 256 MiB default budget.
    #[test]
    fn atk_frag_100mb_sample_reassembles() {
        let mut buf = FragmentBuffer::new(256, 60_000);
        let fsz: u16 = 65000;
        let sample: u32 = 100_000_000;
        let g = FragmentGeometry {
            fragment_size: fsz,
            sample_size: sample,
        };
        let total = g.total_fragments();
        let w = pfx(1);
        let mut done = None;
        for f in 1..=total {
            let len = g.expected_fragment_len(f).unwrap();
            done = buf.insert_fragment(w, 1, f, g, vec![(f % 251) as u8; len]);
            if f < total {
                assert!(done.is_none());
            }
        }
        let p = done.expect("100 MB sample completes");
        assert_eq!(p.len(), sample as usize);
        assert_eq!(buf.buffered_bytes, 0);
    }

    /// A writer on a prefix of `n`, outside the `pfx` range.
    fn source(n: u32) -> GUID {
        let mut prefix = [0x5Au8; 12];
        prefix[..4].copy_from_slice(&n.to_be_bytes());
        GUID::new(prefix, [0, 0, 1, 2])
    }

    /// A legitimate fragmented SPDP from a participant discovery does not
    /// know yet completes through a flood of forged prefixes, while it
    /// keeps itself the most recent of the pool: the flood must open
    /// `unknown_max_pending` sequences between two of its fragments to
    /// evict it. Pinned from both sides of that bound.
    #[test]
    fn a_new_participant_completes_its_fragmented_spdp_through_a_flood() {
        let known_peer = genuine_writer();
        let spdp = |n: u32| {
            let mut prefix = [0x77u8; 12];
            prefix[..4].copy_from_slice(&n.to_be_bytes());
            GUID::new(prefix, [0, 1, 0, 0xC2])
        };
        let shape = FragmentGeometry {
            fragment_size: 1024,
            sample_size: 3000,
        };
        for (between, completes) in [(10, true), (63, true), (64, false), (200, false)] {
            let mut buf =
                knowing(FragmentBuffer::new(256, 60_000), &[known_peer]).with_max_bytes(16 << 20);
            assert_eq!(buf.unknown_max_pending(), 64);
            let mut flood = 0u32;
            let mut flood_once = |buf: &mut FragmentBuffer, count: u32| {
                for _ in 0..count {
                    flood += 1;
                    let _ = buf.insert_fragment(source(flood), 1, 1, geo(1000, 8), vec![3; 8]);
                }
            };
            flood_once(&mut buf, 300);
            let newcomer = spdp(between);
            let mut done = None;
            for frag in 1..=3u32 {
                let len = shape.expected_fragment_len(frag).expect("inside");
                done = buf.insert_fragment(newcomer, 1, frag, shape, vec![0x42; len]);
                if frag < 3 {
                    flood_once(&mut buf, between);
                }
            }
            assert_eq!(
                done.map(|sample| sample.len()),
                completes.then_some(3000),
                "{} flood sequences between two fragments",
                between
            );
            assert!(buf.unknown_count <= 64 && buf.unknown_bytes <= buf.unknown_max_bytes());
        }
    }

    /// A source not known never evicts a known one: when known sources
    /// hold the budget, a sequence of a source not known is refused, and
    /// leaves no trace. A known newcomer evicts the sources not known first.
    #[test]
    fn known_sources_take_precedence_over_sources_not_known() {
        let known = [source(1), source(2)];
        let shape = geo(2, 1024);
        let mut buf = knowing(FragmentBuffer::new(8, 10_000), &known);
        for seq in 1..=4u64 {
            assert!(buf
                .insert_fragment(known[0], seq, 1, shape, vec![1; 1024])
                .is_none());
        }
        for n in 0..2u32 {
            assert!(buf
                .insert_fragment(source(100 + n), 1, 1, shape, vec![2; 1024])
                .is_none());
        }
        assert_eq!((buf.pending_count(), buf.unknown_count), (6, 2));
        // A third source not known: its pool (8 / 4 = 2) is full, its own
        // idle longest goes.
        assert!(buf
            .insert_fragment(source(102), 1, 1, shape, vec![2; 1024])
            .is_none());
        assert!(buf.get_missing_fragments(&source(100), 1).is_none());
        assert_eq!((buf.pending_count(), buf.unknown_count), (6, 2));
        // Known sources fill the rest, then take the pool's room.
        for seq in 1..=4u64 {
            assert!(buf
                .insert_fragment(known[1], seq, 1, shape, vec![1; 1024])
                .is_none());
        }
        assert_eq!((buf.pending_count(), buf.unknown_count), (8, 0));
        // Full of known sources: a source not known is refused outright.
        let before = buf.buffered_bytes;
        assert!(buf
            .insert_fragment(source(103), 1, 1, shape, vec![2; 1024])
            .is_none());
        assert_eq!(
            (buf.pending_count(), buf.unknown_count, buf.buffered_bytes),
            (8, 0, before)
        );
        for writer in known {
            for seq in 1..=4u64 {
                assert!(buf.get_missing_fragments(&writer, seq).is_some());
            }
        }
    }

    /// A participant opening its first sequence is never its own victim,
    /// however far from completion: a sample of many fragments from a new
    /// peer gets in while others hold the buffer, and completes.
    #[test]
    fn a_participant_opening_its_first_sequence_is_never_its_own_victim() {
        let mut buf = FragmentBuffer::new(4, 10_000);
        for n in 1..=4u32 {
            assert!(buf
                .insert_fragment(source(n), 1, 1, geo(2, 8), vec![1; 8])
                .is_none());
        }
        let newcomer = source(9);
        let mut done = None;
        for frag in 1..=100u32 {
            done = buf.insert_fragment(newcomer, 1, frag, geo(100, 8), vec![2; 8]);
        }
        assert_eq!(done.map(|sample| sample.len()), Some(800));
        assert!(
            buf.get_missing_fragments(&source(1), 1).is_none(),
            "the one idle longest paid"
        );
        for n in 2..=4u32 {
            assert!(buf.get_missing_fragments(&source(n), 1).is_some());
        }
    }

    /// One sequence of a source not known may cost at most the pool's
    /// octets over its sequences; a known source may use the whole budget.
    #[test]
    fn a_source_not_known_is_held_to_its_share_of_the_pool() {
        let known = source(1);
        let mut buf = knowing(FragmentBuffer::new(256, 10_000), &[known]).with_max_bytes(16 << 20);
        assert_eq!(buf.unknown_max_charge(), 64 << 10);
        let fits = FragmentGeometry {
            fragment_size: 1024,
            sample_size: 60 << 10,
        };
        let too_big = FragmentGeometry {
            fragment_size: 1024,
            sample_size: 64 << 10,
        };
        assert!(charge(fits) <= 64 << 10 && charge(too_big) > 64 << 10);
        assert!(buf
            .insert_fragment(source(9), 1, 1, too_big, vec![0; 1024])
            .is_none());
        assert_eq!(buf.pending_count(), 0);
        assert!(buf
            .insert_fragment(source(9), 2, 1, fits, vec![0; 1024])
            .is_none());
        assert_eq!(buf.unknown_count, 1);
        let large = FragmentGeometry {
            fragment_size: 60_000,
            sample_size: 8 << 20,
        };
        assert!(buf
            .insert_fragment(known, 1, 1, large, vec![0; 60_000])
            .is_none());
        assert_eq!(buf.pending_count(), 2);
    }

    /// The unknown pool's totals follow every removal: completion, eviction
    /// and expiry.
    #[test]
    fn the_unknown_pool_follows_every_removal() {
        // A timeout long enough that nothing expires before the sleep
        // below: a sequence expired when room is made goes first.
        let mut buf = knowing(FragmentBuffer::new(8, 200), &[]);
        let shape = geo(2, 8);
        assert!(buf
            .insert_fragment(source(1), 1, 1, shape, vec![1; 8])
            .is_none());
        assert_eq!((buf.unknown_count, buf.unknown_bytes), (1, charge(shape)));
        assert!(buf
            .insert_fragment(source(1), 1, 2, shape, vec![1; 8])
            .is_some());
        assert_eq!((buf.unknown_count, buf.unknown_bytes), (0, 0));
        for n in 1..=3u32 {
            assert!(buf
                .insert_fragment(source(n), 1, 1, shape, vec![1; 8])
                .is_none());
        }
        assert_eq!(
            (buf.unknown_count, buf.unknown_bytes),
            (2, 2 * charge(shape)),
            "a pool of 8 / 4 = 2: the third evicted the first"
        );
        assert!(buf.get_missing_fragments(&source(1), 1).is_none());
        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(buf.evict_expired(), 2);
        assert_eq!(
            (buf.unknown_count, buf.unknown_bytes, buf.buffered_bytes),
            (0, 0, 0)
        );
    }

    /// The first inline QoS of a sequence is charged when stored.
    #[test]
    fn an_inline_qos_is_charged() {
        let mut buf = FragmentBuffer::new(8, 10_000);
        let w = source(1);
        let shape = geo(2, 8);
        let qos = (vec![7u8; 100], true);
        let insert = |buf: &mut FragmentBuffer, frag, qos| {
            buf.insert_addressed_fragment_with_qos(
                w,
                1,
                frag,
                shape,
                vec![1; 8],
                None,
                ENTITYID_UNKNOWN,
                qos,
                None,
                Vec::new,
            )
        };
        assert!(insert(&mut buf, 1, Some(qos.clone())).is_none());
        assert_eq!(buf.buffered_bytes, charge(shape) + 100);
        let (_, _, kept, _) = insert(&mut buf, 2, Some((vec![9u8; 50], false))).expect("complete");
        assert_eq!(kept, Some(qos), "the first one is kept");
        assert_eq!(buf.buffered_bytes, 0);
    }

    /// Byte budget, many spoofed prefixes, one small fragment each: does a
    /// genuine large sample in progress survive?
    #[test]
    fn atk_frag_sybil_prefixes_evict_large_genuine_sample() {
        let budget = 1 << 20;
        let mut buf = FragmentBuffer::new(100_000, 60_000).with_max_bytes(budget);
        let genuine = pfx(0xA0);
        let g = FragmentGeometry {
            fragment_size: 1024,
            sample_size: 900 * 1024,
        };
        for f in 1..=800u32 {
            assert!(buf
                .insert_fragment(genuine, 1, f, g, vec![1; 1024])
                .is_none());
        }
        for n in 0..400u32 {
            buf.insert_fragment(pfx(0x1000 + n), 1, 1, geo(2, 1024), vec![2; 1024]);
        }
        assert!(buf.buffered_bytes <= budget);
        let survived = buf.get_missing_fragments(&genuine, 1).is_some();
        // No KnownSources here, so the flood counts as known too: what
        // keeps the genuine sample is its completion (800 of 900 against 1
        // of 2), not its source.
        assert!(
            survived,
            "genuine 800 KiB-in-progress sample evicted by 400 one-KiB spoofed prefixes"
        );
    }

    /// Count bound, slow-loris: max_pending spoofed prefixes, one sequence
    /// each kept alive; can a genuine NEW multi-fragment sample complete?
    #[test]
    fn atk_frag_count_slowloris_blocks_new_genuine_sample() {
        let mut buf = FragmentBuffer::new(256, 60_000);
        for n in 0..256u32 {
            buf.insert_fragment(pfx(0x2000 + n), 1, 1, geo(1000, 8), vec![3; 8]);
        }
        let genuine = pfx(0xB0);
        let mut done = None;
        for f in 1..=3u32 {
            done = buf.insert_fragment(genuine, 1, f, geo(3, 8), vec![4; 8]);
        }
        assert!(done.is_some(), "genuine 3-fragment sample never completes while 256 spoofed prefixes hold one sequence each");
    }

    /// Known and authenticated participants a test declares.
    struct Ranked {
        known: HashSet<[u8; 12]>,
        authenticated: HashSet<[u8; 12]>,
    }

    impl KnownSources for Ranked {
        fn is_known(&self, prefix: &[u8; 12]) -> bool {
            self.known.contains(prefix)
        }
        fn is_authenticated(&self, prefix: &[u8; 12]) -> bool {
            self.authenticated.contains(prefix)
        }
    }

    /// A buffer of `max_pending` sequences that knows `known` and
    /// `authenticated`, the latter authenticated.
    fn ranked(max_pending: usize, known: &[GUID], authenticated: &[GUID]) -> FragmentBuffer {
        FragmentBuffer::new(max_pending, 60_000).with_known_sources(Arc::new(Ranked {
            known: known.iter().map(|writer| writer.prefix).collect(),
            authenticated: authenticated.iter().map(|writer| writer.prefix).collect(),
        }))
    }

    /// Store fragments `1..=received` of a sequence of `total` 8-octet
    /// fragments.
    fn fill(buf: &mut FragmentBuffer, writer: GUID, seq: u64, received: u32, total: u32) {
        for frag in 1..=received {
            assert!(buf
                .insert_fragment(writer, seq, frag, geo(total, 8), vec![7; 8])
                .is_none());
        }
    }

    /// With a handshake machine attached under RTPS protection, the
    /// participants that completed authentication rank authenticated; one
    /// an SPDP alone made known does not, nor this participant's own prefix.
    /// Without RTPS protection, or without a machine, none does.
    #[cfg(feature = "security")]
    #[test]
    fn discovered_participants_rank_the_authenticated_ones() {
        use crate::security::test_pki::bound_test_prefix;
        let (local, peer) = (bound_test_prefix([0x11; 6]), bound_test_prefix([0x21; 6]));
        let stranger = bound_test_prefix([0x31; 6]);
        let registry = EndpointRegistry::new();
        registry.register(
            GUID::new(
                stranger,
                crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
            ),
            "127.0.0.1:7400".parse().expect("address"),
        );
        let plain = DiscoveredParticipants::new(local, registry.clone());
        assert!(!plain.is_authenticated(&local));
        assert!(!plain.is_authenticated(&peer));
        let unprotected = DiscoveredParticipants::new(local, registry.clone()).with_handshakes(
            crate::security::test_pki::local_machine_with_completed_peer(local, peer, None),
            false,
        );
        assert!(
            !unprotected.is_authenticated(&peer),
            "without RTPS protection the header prefix proves nothing"
        );
        let ranked = DiscoveredParticipants::new(local, registry).with_handshakes(
            crate::security::test_pki::local_machine_with_completed_peer(local, peer, None),
            true,
        );
        assert!(
            !ranked.is_authenticated(&local) && !ranked.is_known(&local),
            "our own prefix, which anyone may write into a header, ranks nothing"
        );
        assert!(ranked.is_authenticated(&peer), "its handshake completed");
        assert!(ranked.is_known(&stranger));
        assert!(
            !ranked.is_authenticated(&stranger),
            "known from its SPDP only"
        );
    }

    /// Store fragments `1..=received` of a sequence of `total` fragments of
    /// `len` octets.
    fn fill_sized(
        buf: &mut FragmentBuffer,
        writer: GUID,
        seq: u64,
        received: u32,
        total: u32,
        len: u16,
    ) {
        for frag in 1..=received {
            assert!(buf
                .insert_fragment(
                    writer,
                    seq,
                    frag,
                    geo(total, len),
                    vec![7; usize::from(len)]
                )
                .is_none());
        }
    }

    /// A two-fragment sample of 30 000-octet fragments: its first fragment
    /// alone is further along than any sequence these tests hold, so that
    /// what keeps them is their protection, not their participant's place.
    fn large() -> FragmentGeometry {
        geo(2, 30_000)
    }

    /// A buffer of eight sequences whose octets hold `held` or `large()`,
    /// never both.
    fn one_of(held: FragmentGeometry) -> FragmentBuffer {
        FragmentBuffer::new(8, 60_000).with_max_bytes(charge(held) + charge(large()) - 1)
    }

    /// A DATA_FRAG carrying our own prefix, which anyone may write into an
    /// RTPS header, ranks as a source not known: it never evicts a known
    /// peer's sequence, however far along it claims to be.
    #[test]
    fn our_own_prefix_ranks_as_a_source_not_known() {
        let own = [0x0F; 12];
        let peer = GUID::new([0x21; 12], [0, 0, 0x01, 0xC2]);
        let registry = EndpointRegistry::new();
        registry.register(
            GUID::new(
                peer.prefix,
                crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
            ),
            "127.0.0.1:7400".parse().expect("address"),
        );
        let mut buf = FragmentBuffer::new(1, 60_000)
            .with_known_sources(Arc::new(DiscoveredParticipants::new(own, registry)));
        fill(&mut buf, peer, 1, 4, 10);
        let spoof = GUID::new(own, [0, 0, 0x01, 0xC2]);
        assert!(buf
            .insert_fragment(spoof, 1, 1, geo(2, 8), vec![2; 8])
            .is_none());
        assert!(buf.get_missing_fragments(&spoof, 1).is_none());
        assert!(
            buf.get_missing_fragments(&peer, 1).is_some(),
            "one DATA_FRAG with our own prefix evicted a known peer's sample"
        );
    }

    /// A sequence opening never evicts one of its rank past half its
    /// sample's octets: it is refused. At exactly half the pending one is
    /// not protected and goes as before.
    #[test]
    fn an_opening_sequence_never_evicts_one_past_half_its_sample() {
        let (held, newcomer) = (pfx(0xC0), pfx(0xC1));
        let shape = geo(10, 4096);

        let mut buf = one_of(shape);
        fill_sized(&mut buf, held, 1, 6, 10, 4096);
        assert!(buf
            .insert_fragment(newcomer, 1, 1, large(), vec![1; 30_000])
            .is_none());
        assert!(
            buf.get_missing_fragments(&newcomer, 1).is_none(),
            "the newcomer is refused"
        );
        assert_eq!(
            buf.get_missing_fragments(&held, 1).map(|(m, _)| m.len()),
            Some(4),
            "a sample 6 of 10 fragments there is never evicted by a newcomer"
        );

        let mut buf = one_of(shape);
        fill_sized(&mut buf, held, 1, 5, 10, 4096);
        assert!(buf
            .insert_fragment(newcomer, 1, 1, large(), vec![1; 30_000])
            .is_none());
        assert!(
            buf.get_missing_fragments(&held, 1).is_none(),
            "at exactly half a sample is not protected"
        );
        assert!(buf.get_missing_fragments(&newcomer, 1).is_some());

        // A participant that already holds sequences still pays for its
        // own newest when the others are protected.
        let mut buf =
            FragmentBuffer::new(8, 60_000).with_max_bytes(charge(shape) + 2 * charge(large()) - 1);
        fill_sized(&mut buf, held, 1, 6, 10, 4096);
        assert!(buf
            .insert_fragment(newcomer, 1, 1, large(), vec![1; 30_000])
            .is_none());
        assert!(buf
            .insert_fragment(newcomer, 2, 1, large(), vec![1; 30_000])
            .is_none());
        assert!(buf.get_missing_fragments(&held, 1).is_some());
        assert!(buf.get_missing_fragments(&newcomer, 1).is_some());
        assert!(
            buf.get_missing_fragments(&newcomer, 2).is_none(),
            "the newest of the newcomer's own is the victim"
        );
    }

    /// Protection is bought in octets, not fragments: 101 one-octet
    /// fragments made a sequence past half for 51 octets sent. Under
    /// `PROTECTED_MIN_OCTETS` received, a sequence past half its sample is
    /// not protected.
    #[test]
    fn a_sequence_under_the_octet_floor_is_not_protected() {
        let (held, newcomer) = (pfx(0xC4), pfx(0xC5));
        // 102 fragments, 101 of 160 octets and a last one of 1: past half
        // its octets at 51 fragments, 8160 octets, and half its fragments,
        // no further along than the newcomer.
        let tiny = FragmentGeometry {
            fragment_size: 160,
            sample_size: 160 * 101 + 1,
        };
        let mut buf = one_of(tiny);
        for frag in 1..=51 {
            assert!(buf
                .insert_fragment(held, 1, frag, tiny, vec![7; 160])
                .is_none());
        }
        assert!(buf
            .insert_fragment(newcomer, 1, 1, large(), vec![1; 30_000])
            .is_none());
        assert!(
            buf.get_missing_fragments(&held, 1).is_none(),
            "51 fragments and 8160 octets bought a protected slot"
        );
        assert!(buf.get_missing_fragments(&newcomer, 1).is_some());

        // The same share of a sample whose half is over the floor is.
        let sized = geo(101, 400);
        let mut buf = one_of(sized);
        fill_sized(&mut buf, held, 1, 51, 101, 400);
        assert!(buf
            .insert_fragment(newcomer, 1, 1, large(), vec![1; 30_000])
            .is_none());
        assert!(buf.get_missing_fragments(&held, 1).is_some());
        assert!(buf.get_missing_fragments(&newcomer, 1).is_none());
    }

    /// One participant keeps protected at most its share of the sequence
    /// bound, `max_pending` over the participants with a sequence in
    /// progress: its most advanced ones. Otherwise a prefix a forged SPDP made
    /// known could hold every slot of a buffer with sequences past half, and
    /// a genuine newcomer would be refused for as long as it kept them alive.
    #[test]
    fn a_participant_keeps_protected_only_its_share() {
        let (held, other_writer, newcomer) = (
            pfx(0xC6),
            GUID::new(pfx(0xC6).prefix, [0, 0, 9, 2]),
            pfx(0xC7),
        );
        let shape = geo(10, 4096);
        // Two slots, two participants once the newcomer opens: one each.
        let mut buf = FragmentBuffer::new(2, 60_000);
        fill_sized(&mut buf, held, 1, 7, 10, 4096);
        fill_sized(&mut buf, other_writer, 1, 6, 10, 4096);
        assert!(buf
            .insert_fragment(newcomer, 1, 1, large(), vec![1; 30_000])
            .is_none());
        assert!(
            buf.get_missing_fragments(&newcomer, 1).is_some(),
            "a participant held both slots protected"
        );
        assert!(
            buf.get_missing_fragments(&held, 1).is_some(),
            "its most advanced sequence stays protected"
        );
        assert!(buf.get_missing_fragments(&other_writer, 1).is_none());

        // Within its share, both are.
        let mut buf =
            FragmentBuffer::new(4, 60_000).with_max_bytes(2 * charge(shape) + charge(large()) - 1);
        fill_sized(&mut buf, held, 1, 7, 10, 4096);
        fill_sized(&mut buf, other_writer, 1, 6, 10, 4096);
        assert!(buf
            .insert_fragment(newcomer, 1, 1, large(), vec![1; 30_000])
            .is_none());
        assert!(buf.get_missing_fragments(&newcomer, 1).is_none());
        assert!(buf.get_missing_fragments(&held, 1).is_some());
        assert!(buf.get_missing_fragments(&other_writer, 1).is_some());
    }

    /// The count slow-loris of a prefix a forged SPDP made known: eight
    /// sequences of 101 one-octet fragments, each past half and kept alive
    /// by a fragment every half timeout, against a genuine known peer's
    /// two-fragment sample, four timeouts long.
    #[test]
    fn a_trickle_of_one_octet_fragments_never_blocks_a_genuine_newcomer() {
        let (attacker, genuine) = (pfx(0xA77), pfx(0x600D));
        let timeout = 40;
        let max_pending = 8usize;
        let mut buf = knowing(
            FragmentBuffer::new(max_pending, timeout),
            &[attacker, genuine],
        );
        let trickle = geo(101, 1);
        let mut next = vec![1u32; max_pending];
        for (seq, next) in next.iter_mut().enumerate() {
            for _ in 0..51 {
                assert!(buf
                    .insert_fragment(attacker, seq as u64, *next, trickle, vec![0])
                    .is_none());
                *next += 1;
            }
        }
        let mut refused = 0;
        for _ in 0..4 {
            std::thread::sleep(Duration::from_millis(timeout / 2));
            for (seq, next) in next.iter_mut().enumerate() {
                let _ = buf.insert_fragment(attacker, seq as u64, *next, trickle, vec![0]);
                *next += 1;
            }
            buf.evict_expired();
            let first = buf.insert_fragment(genuine, 7, 1, geo(2, 8), vec![9; 8]);
            let second = buf.insert_fragment(genuine, 7, 2, geo(2, 8), vec![9; 8]);
            if first.is_none() && second.is_none() {
                refused += 1;
            }
        }
        assert_eq!(
            refused, 0,
            "the genuine newcomer was refused in {refused} of 4 rounds"
        );
    }

    /// A sequence that opened within the budget and then grows by an inline
    /// QoS evicts no sample past half its fragments either: its fragment
    /// is refused.
    #[test]
    fn a_growing_sequence_never_evicts_one_past_half_its_sample() {
        let (held, grower) = (pfx(0xC2), pfx(0xC3));
        let shape = geo(10, 4096);
        let mut buf = FragmentBuffer::new(8, 60_000).with_max_bytes(2 * charge(shape) + 50);
        fill_sized(&mut buf, held, 1, 6, 10, 4096);
        fill_sized(&mut buf, grower, 1, 1, 10, 4096);
        assert!(buf
            .insert_addressed_fragment_with_qos(
                grower,
                1,
                2,
                shape,
                vec![1; 4096],
                None,
                ENTITYID_UNKNOWN,
                Some((vec![0; 100], false)),
                None,
                Vec::new,
            )
            .is_none());
        assert_eq!(
            buf.get_missing_fragments(&held, 1).map(|(m, _)| m.len()),
            Some(4),
            "an inline QoS evicted a sample 6 of 10 fragments there"
        );
        assert_eq!(
            buf.get_missing_fragments(&grower, 1).map(|(m, _)| m.len()),
            Some(9),
            "the fragment carrying it is refused"
        );
    }

    /// A source merely known never evicts an authenticated one, however
    /// little that one received; an authenticated one evicts a source
    /// merely known before any of its rank, however much that one received.
    #[test]
    fn a_merely_known_source_never_evicts_an_authenticated_one() {
        let (trusted, other_trusted) = (pfx(0xD0), pfx(0xD1));
        let (discovered, other_discovered) = (pfx(0xD2), pfx(0xD3));
        let known = [trusted, other_trusted, discovered, other_discovered];
        let authenticated = [trusted, other_trusted];

        let mut buf = ranked(1, &known, &authenticated);
        fill(&mut buf, trusted, 1, 1, 10);
        assert!(buf
            .insert_fragment(discovered, 1, 1, geo(2, 8), vec![1; 8])
            .is_none());
        assert!(buf.get_missing_fragments(&discovered, 1).is_none());
        assert!(
            buf.get_missing_fragments(&trusted, 1).is_some(),
            "a forged SPDP outranked an authenticated participant"
        );

        let mut buf = ranked(1, &known, &authenticated);
        fill(&mut buf, discovered, 1, 9, 10);
        assert!(buf
            .insert_fragment(trusted, 1, 1, geo(10, 8), vec![1; 8])
            .is_none());
        assert!(
            buf.get_missing_fragments(&discovered, 1).is_none(),
            "past half its fragments, a source merely known still yields to an authenticated one"
        );
        assert!(buf.get_missing_fragments(&trusted, 1).is_some());

        // Rank before completion: the authenticated sample 1 of 10 there
        // stays, the merely known one 4 of 10 there goes.
        let mut buf = ranked(2, &known, &authenticated);
        fill(&mut buf, other_trusted, 1, 1, 10);
        fill(&mut buf, other_discovered, 1, 4, 10);
        assert!(buf
            .insert_fragment(trusted, 1, 1, geo(10, 8), vec![1; 8])
            .is_none());
        assert!(buf.get_missing_fragments(&other_trusted, 1).is_some());
        assert!(buf.get_missing_fragments(&other_discovered, 1).is_none());
        assert!(buf.get_missing_fragments(&trusted, 1).is_some());
    }

    /// Every buffer sweeps its expired sequences when room has to be made,
    /// not only the one a router sweeps on a timer: four genuine samples
    /// that each lost their last fragment, past half and so kept by the
    /// eviction rules, must not hold a four-sequence buffer nobody sweeps and
    /// get every new fragmented sample of a known peer refused, forever. No
    /// `evict_expired` call here, as in the discovery and TCP/QUIC buffers.
    #[test]
    fn an_expired_sequence_never_holds_room_in_a_buffer_nobody_sweeps() {
        let peers: Vec<GUID> = (0x10..0x14).map(pfx).collect();
        let newcomer = pfx(0x99);
        let mut buf = FragmentBuffer::new(4, 1);
        for peer in &peers {
            fill(&mut buf, *peer, 1, 3, 4);
        }
        assert_eq!(buf.pending_count(), 4);
        std::thread::sleep(Duration::from_millis(20));
        let mut done = None;
        for frag in 1..=4 {
            done = buf.insert_fragment(newcomer, 1, frag, geo(4, 8), vec![2; 8]);
        }
        assert_eq!(
            done.map(|sample| sample.len()),
            Some(32),
            "{} expired sequences held every slot of a buffer nobody sweeps",
            buf.pending_count()
        );
        assert_eq!(buf.pending_count(), 0, "the expired ones went with it");
        assert_eq!(buf.buffered_bytes, 0);
    }

    /// The protection a sequence earns past half its sample lasts the
    /// buffer's timeout from its first fragment and no longer, however
    /// alive a fragment at a time keeps it: before, the newcomer that needs
    /// its octets is refused; after, it evicts it.
    #[test]
    fn protection_lasts_the_timeout_from_the_first_fragment() {
        let (held, newcomer) = (pfx(0xE0), pfx(0xE1));
        let shape = geo(10, 4096);
        let large = FragmentGeometry {
            fragment_size: 60_000,
            sample_size: 120_000,
        };
        let timeout = 300;
        let mut buf =
            FragmentBuffer::new(8, timeout).with_max_bytes(charge(large) + charge(shape) / 2);
        for frag in 1..=6 {
            assert!(buf
                .insert_fragment(held, 1, frag, shape, vec![1; 4096])
                .is_none());
        }
        assert!(buf
            .insert_fragment(newcomer, 1, 1, large, vec![2; 60_000])
            .is_none());
        assert!(
            buf.get_missing_fragments(&held, 1).is_some(),
            "within the timeout the sample past half is kept"
        );
        assert!(buf.get_missing_fragments(&newcomer, 1).is_none());
        std::thread::sleep(Duration::from_millis(timeout + 50));
        assert!(buf
            .insert_fragment(held, 1, 7, shape, vec![1; 4096])
            .is_none());
        assert!(buf
            .insert_fragment(newcomer, 1, 1, large, vec![2; 60_000])
            .is_none());
        assert!(
            buf.get_missing_fragments(&held, 1).is_none(),
            "a sequence kept alive past the timeout kept its protection"
        );
        assert!(buf.get_missing_fragments(&newcomer, 1).is_some());
    }

    /// xorshift, for the interleavings below.
    struct Xorshift(u64);

    impl Xorshift {
        fn below(&mut self, n: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % n.max(1)
        }
    }

    /// How two genuine known peers' large samples interleave on the wire.
    #[derive(Clone, Copy, Debug)]
    enum Interleaving {
        /// One whole sample, then the other.
        Bursts,
        /// One fragment of each in turn.
        Alternating,
        /// Shuffled.
        Random(u64),
    }

    /// Two known peers each send a 60-fragment sample; the octet budget
    /// holds either, never both. Each round every writer resends what the
    /// buffer still misses of its sample (NACK_FRAG repair), in the order
    /// `interleaving` gives. The round each sample completed, if it did
    /// within `rounds`.
    fn two_large_samples(interleaving: Interleaving, rounds: u32) -> [Option<u32>; 2] {
        let peers = [pfx(0xAAAA), pfx(0xBBBB)];
        let shape = geo(60, 1000);
        let mut buf = FragmentBuffer::new(64, 600_000).with_max_bytes(2 * charge(shape) - 1);
        let mut rng = Xorshift(match interleaving {
            Interleaving::Random(seed) => seed,
            _ => 1,
        });
        let mut done = [None, None];
        for round in 1..=rounds {
            let mut queue: Vec<(usize, u32)> = Vec::new();
            for (i, peer) in peers.iter().enumerate() {
                if done[i].is_none() {
                    let missing = buf
                        .get_missing_fragments(peer, 1)
                        .map_or_else(|| (1..=60).collect(), |(missing, _)| missing);
                    queue.extend(missing.into_iter().map(|frag| (i, frag)));
                }
            }
            match interleaving {
                Interleaving::Bursts => queue.sort_by_key(|(i, frag)| (*i, *frag)),
                Interleaving::Alternating => queue.sort_by_key(|(i, frag)| (*frag, *i)),
                Interleaving::Random(_) => {
                    for k in (1..queue.len()).rev() {
                        queue.swap(k, rng.below(k as u64 + 1) as usize);
                    }
                }
            }
            for (i, frag) in queue {
                if done[i].is_none()
                    && buf
                        .insert_fragment(peers[i], 1, frag, shape, vec![i as u8; 1000])
                        .is_some()
                {
                    done[i] = Some(round);
                }
            }
            if done.iter().all(Option::is_some) {
                break;
            }
        }
        done
    }

    /// Two genuine large samples whose fragments interleave under octet
    /// pressure both complete: the one further along keeps its place and
    /// the other waits. They must not evict each other on every fragment,
    /// forever.
    #[test]
    fn two_large_samples_interleaving_under_pressure_both_complete() {
        let mut runs = vec![Interleaving::Bursts, Interleaving::Alternating];
        runs.extend((1..=16).map(|seed| Interleaving::Random(0x9E37_79B9 * seed)));
        for interleaving in runs {
            let done = two_large_samples(interleaving, 40);
            assert!(
                done.iter().all(Option::is_some),
                "{interleaving:?}: a genuine sample never completed in 40 rounds: {done:?}"
            );
            assert!(
                done.iter().all(|round| round.is_some_and(|r| r <= 2)),
                "{interleaving:?}: {done:?}"
            );
        }
    }

    /// A participant's most advanced sequence goes only for one further
    /// along: in share of its fragments, then in octets. Its other
    /// sequences go as before.
    #[test]
    fn a_participant_keeps_its_most_advanced_sequence() {
        let ahead = pfx(0xF0);
        let behind = GUID::new(ahead.prefix, [0, 0, 9, 2]);
        let newcomer = pfx(0xF1);
        // Half of either sample: the one with more octets is the place,
        // and the one idle longest.
        let mut buf = FragmentBuffer::new(2, 60_000);
        fill_sized(&mut buf, ahead, 1, 1, 2, 4000);
        fill_sized(&mut buf, behind, 1, 1, 2, 1000);
        assert!(buf
            .insert_fragment(newcomer, 1, 1, geo(2, 2000), vec![1; 2000])
            .is_none());
        assert!(buf.get_missing_fragments(&newcomer, 1).is_some());
        assert!(
            buf.get_missing_fragments(&ahead, 1).is_some(),
            "the most advanced sequence of a participant is its place"
        );
        assert!(buf.get_missing_fragments(&behind, 1).is_none());

        // A newcomer exactly as far along waits; one octet more and it
        // evicts; so does a larger share with fewer octets.
        let shape = geo(4, 1000);
        let mut buf = FragmentBuffer::new(2, 60_000).with_max_bytes(charge(shape) + 1500);
        fill_sized(&mut buf, ahead, 1, 1, 4, 1000);
        assert!(buf
            .insert_fragment(newcomer, 1, 1, shape, vec![1; 1000])
            .is_none());
        assert!(
            buf.get_missing_fragments(&newcomer, 1).is_none(),
            "a newcomer as far along waits"
        );
        assert!(buf.get_missing_fragments(&ahead, 1).is_some());
        assert!(buf
            .insert_fragment(newcomer, 1, 1, geo(4, 1001), vec![1; 1001])
            .is_none());
        assert!(buf.get_missing_fragments(&newcomer, 1).is_some());
        assert!(buf.get_missing_fragments(&ahead, 1).is_none());

        let mut buf = FragmentBuffer::new(2, 60_000).with_max_bytes(charge(shape) + 1500);
        fill_sized(&mut buf, ahead, 1, 1, 4, 1000);
        assert!(buf
            .insert_fragment(newcomer, 1, 1, geo(5, 900), vec![1; 900])
            .is_none());
        assert!(
            buf.get_missing_fragments(&newcomer, 1).is_none(),
            "a smaller share waits, whatever its size"
        );
        assert!(buf
            .insert_fragment(newcomer, 1, 1, geo(3, 900), vec![1; 900])
            .is_none());
        assert!(
            buf.get_missing_fragments(&newcomer, 1).is_some(),
            "a larger share evicts, whatever its size"
        );
        assert!(buf.get_missing_fragments(&ahead, 1).is_none());
    }

    /// A participant whose sequences all keep their place is not opening
    /// its first: it still pays for its own newest rather than evict
    /// another participant's sequence.
    #[test]
    fn a_participant_with_a_place_still_pays_for_its_own_newest() {
        let (streamer, other) = (pfx(0xF4), pfx(0xF5));
        let mut buf = FragmentBuffer::new(3, 60_000);
        fill(&mut buf, streamer, 1, 1, 2);
        fill(&mut buf, other, 1, 1, 2);
        fill(&mut buf, other, 2, 1, 2);
        assert!(buf
            .insert_fragment(streamer, 2, 1, geo(4, 8), vec![1; 8])
            .is_none());
        assert!(
            buf.get_missing_fragments(&streamer, 2).is_none(),
            "its own newest is the victim"
        );
        assert!(buf.get_missing_fragments(&streamer, 1).is_some());
        assert!(buf.get_missing_fragments(&other, 1).is_some());
        assert!(buf.get_missing_fragments(&other, 2).is_some());
    }

    /// A participant's place lasts the buffer's timeout from its first
    /// fragment, however alive a fragment at a time keeps it.
    #[test]
    fn a_place_lasts_the_timeout_from_the_first_fragment() {
        let (held, newcomer) = (pfx(0xF2), pfx(0xF3));
        let shape = geo(10, 1000);
        let timeout = 300;
        let mut buf =
            FragmentBuffer::new(8, timeout).with_max_bytes(charge(shape) + charge(shape) / 2);
        fill_sized(&mut buf, held, 1, 3, 10, 1000);
        assert!(buf
            .insert_fragment(newcomer, 1, 1, shape, vec![2; 1000])
            .is_none());
        assert!(buf.get_missing_fragments(&newcomer, 1).is_none());
        std::thread::sleep(Duration::from_millis(timeout + 50));
        assert!(buf
            .insert_fragment(held, 1, 4, shape, vec![1; 1000])
            .is_none());
        assert!(buf
            .insert_fragment(newcomer, 1, 1, shape, vec![2; 1000])
            .is_none());
        assert!(
            buf.get_missing_fragments(&held, 1).is_none(),
            "a sequence kept alive past the timeout kept its place"
        );
        assert!(buf.get_missing_fragments(&newcomer, 1).is_some());
    }

    /// Memory bound: what does a 1-octet fragmentSize cost in real memory?
    /// The resident set is the process's, so run it alone
    /// (`--ignored --test-threads=1`); `tests/frag_reassembly_memory.rs`
    /// measures the same in a binary of its own on every run.
    #[test]
    #[ignore = "measures the process RSS: run alone"]
    fn atk_frag_overhead_amplification() {
        let budget = 16 << 20;
        let mut buf = FragmentBuffer::new(256, 600_000).with_max_bytes(budget);
        let before = rss_kib();
        let per_seq = MAX_FRAGMENTS_PER_SAMPLE; // 1 Mi fragments of 1 octet
        let g = FragmentGeometry {
            fragment_size: 1,
            sample_size: per_seq,
        };
        for seq in 0..16u32 {
            let w = pfx(0x3000 + seq);
            for f in 1..per_seq {
                // leave last missing
                buf.insert_fragment(w, 1, f, g, vec![5]);
            }
        }
        let after = rss_kib().max(before);
        let counted = buf.buffered_bytes;
        eprintln!(
            "ATK_OVERHEAD counted_octets={} rss_growth_kib={} ratio={:.1}",
            counted,
            after - before,
            ((after - before) * 1024) as f64 / counted as f64
        );
        assert!(
            ((after - before) * 1024) < 4 * counted,
            "real memory {} KiB for {} counted octets",
            after - before,
            counted
        );
    }
}

// ===== hostile fragment tests =====
#[cfg(test)]
mod verify_frag {
    use super::*;
    use std::collections::HashSet;

    struct Known(HashSet<[u8; 12]>);
    impl KnownSources for Known {
        fn is_known(&self, prefix: &[u8; 12]) -> bool {
            self.0.contains(prefix)
        }
    }
    fn w(n: u32) -> GUID {
        let mut p = [0x33u8; 12];
        p[..4].copy_from_slice(&n.to_be_bytes());
        GUID::new(p, [0, 0, 1, 2])
    }
    fn knowing(b: FragmentBuffer, ws: &[GUID]) -> FragmentBuffer {
        b.with_known_sources(Arc::new(Known(ws.iter().map(|g| g.prefix).collect())))
    }
    /// xorshift
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Property: any geometry, any order, duplicates (with DIFFERENT
    /// content), loss + later repair: the sample completes exactly once,
    /// only when every fragment is in, with the reference bytes; missing
    /// list always equals the reference set of absent fragments.
    #[test]
    fn vf_property_reassembly_matches_reference() {
        let mut rng = Rng(0x9E3779B97F4A7C15);
        for case in 0..3000u32 {
            let fs = 1 + rng.below(700) as u16;
            let sample = 1 + rng.below(20_000) as u32;
            let g = FragmentGeometry {
                fragment_size: fs,
                sample_size: sample,
            };
            let total = g.total_fragments();
            let reference: Vec<u8> = (0..sample).map(|_| rng.next() as u8).collect();
            let mut buf = FragmentBuffer::new(256, 600_000);
            let writer = w(case);
            let mut order: Vec<u32> = (1..=total).collect();
            for i in (1..order.len()).rev() {
                let j = rng.below(i as u64 + 1) as usize;
                order.swap(i, j);
            }
            // drop ~10% first pass; repair later
            let mut lost = Vec::new();
            let mut have: HashSet<u32> = HashSet::new();
            let frag_bytes = |f: u32| {
                let off = (f - 1) as usize * fs as usize;
                let len = g.expected_fragment_len(f).unwrap();
                reference[off..off + len].to_vec()
            };
            let mut completed: Option<Vec<u8>> = None;
            let feed = |rng: &mut Rng,
                        buf: &mut FragmentBuffer,
                        f: u32,
                        have: &mut HashSet<u32>,
                        completed: &mut Option<Vec<u8>>| {
                let mut bytes = frag_bytes(f);
                // occasionally pad (clipped by design)
                if rng.below(5) == 0 {
                    bytes.extend_from_slice(&[0xAB; 3]);
                }
                let r = buf.insert_fragment(writer, 1, f, g, bytes);
                have.insert(f);
                if let Some(p) = r {
                    assert!(completed.is_none(), "case {case}: completed twice");
                    assert_eq!(
                        have.len() as u32,
                        total,
                        "case {case}: completed with a fragment missing"
                    );
                    *completed = Some(p);
                }
                // duplicate with garbage content: must not overwrite
                if completed.is_none() && rng.below(4) == 0 {
                    let len = g.expected_fragment_len(f).unwrap();
                    assert!(buf
                        .insert_fragment(writer, 1, f, g, vec![0xEE; len])
                        .is_none());
                }
            };
            for &f in &order {
                if total > 1 && rng.below(10) == 0 {
                    lost.push(f);
                    continue;
                }
                feed(&mut rng, &mut buf, f, &mut have, &mut completed);
            }
            if completed.is_none() {
                let (missing, t) = buf.get_missing_fragments(&writer, 1).expect("pending");
                assert_eq!(t, total);
                let mut exp: Vec<u32> = (1..=total).filter(|f| !have.contains(f)).collect();
                exp.sort();
                assert_eq!(missing, exp, "case {case}: missing list");
            }
            for f in lost.clone() {
                feed(&mut rng, &mut buf, f, &mut have, &mut completed);
            }
            let p = completed
                .unwrap_or_else(|| panic!("case {case}: never completed fs={fs} sample={sample}"));
            assert_eq!(
                p, reference,
                "case {case}: bytes differ fs={fs} sample={sample}"
            );
            assert_eq!(buf.buffered_bytes, 0);
        }
    }

    /// Inconsistent geometry on the same key: never panics, never a short or
    /// shifted sample.
    #[test]
    fn vf_inconsistent_geometry_never_corrupts() {
        let mut rng = Rng(42);
        for case in 0..20_000u32 {
            let mut buf = FragmentBuffer::new(8, 600_000).with_max_bytes(1 << 20);
            let writer = w(case % 7);
            for _ in 0..30 {
                let fs = rng.below(70) as u16;
                let ss = rng.below(300) as u32;
                let g = FragmentGeometry {
                    fragment_size: fs,
                    sample_size: ss,
                };
                let fnum = rng.below(10) as u32;
                let len = rng.below(80) as usize;
                if let Some(p) = buf.insert_fragment(writer, rng.below(3), fnum, g, vec![1; len]) {
                    // the only fragments ever inserted are all-1, so a sample
                    // must be all-1 of its admitted geometry's length
                    assert!(p.iter().all(|b| *b == 1), "case {case}");
                }
            }
            assert!(buf.buffered_bytes <= 1 << 20);
        }
    }

    fn time_per_packet(
        mut buf: FragmentBuffer,
        g: FragmentGeometry,
        last_only: bool,
        n: u32,
    ) -> f64 {
        let total = g.total_fragments();
        let frag = if last_only { total } else { 1 };
        let len = g.expected_fragment_len(frag).unwrap();
        let start = Instant::now();
        for i in 0..n {
            let _ = buf.insert_fragment(w(1_000_000 + i), 1, frag, g, vec![7; len]);
        }
        start.elapsed().as_nanos() as f64 / f64::from(n)
    }

    /// CPU amplification from a source NOT known (no SPDP needed): one
    /// ~100-octet DATA_FRAG carrying only the LAST fragment of a sample at
    /// the unknown ceiling (1 MiB, user-data buffer) makes the receiver
    /// zero-fill the whole gap. Compared to the same packet carrying the
    /// first fragment.
    #[test]
    fn vf_last_fragment_first_amplification_unknown() {
        let mk = || knowing(FragmentBuffer::new(256, 600_000), &[]);
        // ~1 MiB minus overhead, last fragment 1 octet
        let fs: u16 = 1024;
        let ss: u32 = 1000 * 1024 + 1;
        let g = FragmentGeometry {
            fragment_size: fs,
            sample_size: ss,
        };
        assert!(FragmentBuffer::charge_for(g, 0).unwrap() <= mk().unknown_max_charge());
        let first = time_per_packet(mk(), g, false, 3000);
        let last = time_per_packet(mk(), g, true, 3000);
        eprintln!(
            "VF_AMP_UNKNOWN first_frag={first:.0} ns/pkt last_frag={last:.0} ns/pkt ratio={:.1}",
            last / first
        );
        assert!(
            last < 10.0 * first,
            "last-fragment-first costs {last:.0} ns per packet vs {first:.0}"
        );
    }

    /// Same from a KNOWN source (forged SPDP makes a prefix known): sample at
    /// the full 256 MiB budget.
    #[test]
    fn vf_last_fragment_first_amplification_known() {
        let prefixes: Vec<GUID> = (0..50).map(|i| w(1_000_000 + i)).collect();
        let mk = || knowing(FragmentBuffer::new(256, 600_000), &prefixes);
        let fs: u16 = 65000;
        let ss: u32 = 4000 * 65000 + 1; // ~248 MiB
        let g = FragmentGeometry {
            fragment_size: fs,
            sample_size: ss,
        };
        assert!(FragmentBuffer::charge_for(g, 0).unwrap() <= DEFAULT_MAX_BUFFERED_BYTES);
        let first = time_per_packet(mk(), g, false, 50);
        let last = time_per_packet(mk(), g, true, 50);
        eprintln!(
            "VF_AMP_KNOWN first_frag={first:.0} ns/pkt last_frag={last:.0} ns/pkt ratio={:.1}",
            last / first
        );
        assert!(
            last < 1_000_000.0,
            "one last-fragment packet costs {last:.0} ns of router time"
        );
    }

    /// Discovery buffer shape (16 MiB, known ceiling 16 MiB; unknown 64 KiB).
    #[test]
    fn vf_last_fragment_first_amplification_discovery_buffer() {
        let prefixes: Vec<GUID> = (0..400).map(|i| w(1_000_000 + i)).collect();
        let mk = |ps: &[GUID]| {
            knowing(
                FragmentBuffer::new(256, 600_000).with_max_bytes(16 << 20),
                ps,
            )
        };
        let gk = FragmentGeometry {
            fragment_size: 1024,
            sample_size: 16_000 * 1024 + 1,
        };
        let gu = FragmentGeometry {
            fragment_size: 1024,
            sample_size: 62 * 1024 + 1,
        };
        let k_first = time_per_packet(mk(&prefixes), gk, false, 200);
        let k_last = time_per_packet(mk(&prefixes), gk, true, 200);
        let u_first = time_per_packet(mk(&[]), gu, false, 3000);
        let u_last = time_per_packet(mk(&[]), gu, true, 3000);
        eprintln!("VF_AMP_DISC known first={k_first:.0} last={k_last:.0} ns/pkt; unknown first={u_first:.0} last={u_last:.0} ns/pkt");
        assert!(
            k_last < 10.0 * k_first,
            "known: last {k_last:.0} ns vs first {k_first:.0} ns"
        );
        assert!(
            u_last < 10.0 * u_first,
            "unknown: last {u_last:.0} ns vs first {u_first:.0} ns"
        );
    }

    /// A prefix made known by a forged SPDP: one DATA_FRAG declaring a
    /// budget-sized sample evicts a genuine known peer's sample at 89%.
    #[test]
    fn vf_forged_known_prefix_evicts_genuine_sample_with_one_packet() {
        let genuine = w(1);
        let attacker = w(666);
        let mut buf = knowing(FragmentBuffer::new(256, 600_000), &[genuine, attacker]);
        let g = FragmentGeometry {
            fragment_size: 1024,
            sample_size: 900 * 1024,
        };
        for f in 1..=800u32 {
            assert!(buf
                .insert_fragment(genuine, 1, f, g, vec![1; 1024])
                .is_none());
        }
        let big = FragmentGeometry {
            fragment_size: 65000,
            sample_size: 4125 * 65000,
        };
        assert!(FragmentBuffer::charge_for(big, 0).unwrap() <= DEFAULT_MAX_BUFFERED_BYTES);
        let _ = buf.insert_fragment(attacker, 1, 1, big, vec![0; 65000]);
        assert!(
            buf.get_missing_fragments(&genuine, 1).is_some(),
            "one 65 KB DATA_FRAG from a forged-known prefix evicted a genuine 800/900 sample"
        );
    }

    /// A user-data sample over 1 MiB from a participant not in the
    /// EndpointRegistry is refused at its first fragment, by design
    /// (`UNKNOWN_POOL_DIVISOR`), and completes once discovery knows it.
    #[test]
    fn vf_unknown_peer_large_sample_refused() {
        let peer = w(5);
        let g = FragmentGeometry {
            fragment_size: 65000,
            sample_size: 2 << 20,
        };
        let total = g.total_fragments();
        let send = |buf: &mut FragmentBuffer| {
            let mut done = None;
            for f in 1..=total {
                let len = g.expected_fragment_len(f).unwrap();
                done = buf.insert_fragment(peer, 1, f, g, vec![9; len]);
            }
            done
        };
        let mut buf = knowing(FragmentBuffer::new(256, 600_000), &[]);
        assert!(send(&mut buf).is_none());
        assert_eq!(buf.pending_count(), 0, "refused, nothing held");
        let mut buf = knowing(FragmentBuffer::new(256, 600_000), &[peer]);
        assert_eq!(send(&mut buf).map(|p| p.len()), Some(2 << 20));
    }

    /// Lock churn: EndpointRegistry register/remove on several threads while
    /// another inserts fragments through DiscoveredParticipants. Must finish.
    #[test]
    fn vf_known_sources_concurrent_churn() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Mutex;
        let reg = EndpointRegistry::new();
        let buf = Arc::new(Mutex::new(FragmentBuffer::new(256, 50).with_known_sources(
            Arc::new(DiscoveredParticipants::new([0; 12], reg.clone())),
        )));
        let stop = Arc::new(AtomicBool::new(false));
        let mut hs = Vec::new();
        for t in 0..4u32 {
            let reg = reg.clone();
            let stop = stop.clone();
            hs.push(std::thread::spawn(move || {
                let mut i = 0u32;
                while !stop.load(Ordering::Relaxed) {
                    let g = GUID::new(
                        w(i % 64).prefix,
                        crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
                    );
                    if (i + t).is_multiple_of(2) {
                        reg.register(g, "127.0.0.1:7400".parse().unwrap());
                    } else {
                        reg.remove(&g);
                    }
                    let _ = reg.entries();
                    i = i.wrapping_add(1);
                }
            }));
        }
        for t in 0..3u32 {
            let buf = buf.clone();
            let stop = stop.clone();
            hs.push(std::thread::spawn(move || {
                let mut i = 0u64;
                let g = FragmentGeometry {
                    fragment_size: 8,
                    sample_size: 24,
                };
                while !stop.load(Ordering::Relaxed) {
                    let mut b = buf.lock().unwrap();
                    let _ =
                        b.insert_fragment(w((i % 64) as u32), i, 1 + (i % 3) as u32, g, vec![1; 8]);
                    if i % 1000 == u64::from(t) {
                        b.evict_expired();
                    }
                    drop(b);
                    i += 1;
                }
            }));
        }
        std::thread::sleep(Duration::from_secs(3));
        stop.store(true, Ordering::Relaxed);
        for h in hs {
            h.join().unwrap();
        }
        let b = buf.lock().unwrap();
        assert!(b.buffered_bytes <= b.max_bytes && b.unknown_count <= b.pending.len());
    }

    /// RSS for hostile shapes: last-fragment-only of the largest allowed
    /// unknown sample from many prefixes (forces every byte resident).
    #[test]
    #[ignore = "measures process RSS: run alone"]
    fn vf_rss_last_fragment_flood() {
        let rss = || {
            let s = std::fs::read_to_string("/proc/self/statm").unwrap();
            s.split_whitespace()
                .nth(1)
                .unwrap()
                .parse::<usize>()
                .unwrap()
                * 4096
        };
        let budget = DEFAULT_MAX_BUFFERED_BYTES;
        let known: Vec<GUID> = (0..400).map(|i| w(50_000 + i)).collect();
        let mut buf = knowing(FragmentBuffer::new(256, 600_000), &known);
        let before = rss();
        // unknown flood, last fragment only
        let g = FragmentGeometry {
            fragment_size: 1024,
            sample_size: 1000 * 1024 + 1,
        };
        for i in 0..2000u32 {
            let _ = buf.insert_fragment(w(1_000_000 + i), 1, g.total_fragments(), g, vec![7; 1]);
        }
        let mid = rss();
        // known (forged) prefixes, last fragment only, 4 MiB each
        let g2 = FragmentGeometry {
            fragment_size: 1024,
            sample_size: 4096 * 1024 + 1,
        };
        for k in &known {
            let _ = buf.insert_fragment(*k, 1, g2.total_fragments(), g2, vec![7; 1]);
        }
        let after = rss();
        eprintln!(
            "VF_RSS unknown_flood_growth={} MiB (pool {} MiB) total_growth={} MiB budget={} MiB charged={} MiB pending={}",
            (mid.saturating_sub(before)) >> 20, buf.unknown_max_bytes() >> 20,
            (after.saturating_sub(before)) >> 20, budget >> 20, buf.buffered_bytes >> 20, buf.pending.len()
        );
        assert!(after.saturating_sub(before) < budget + (budget / 4));
    }
}
