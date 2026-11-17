// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Participant-level shared-memory receive leg.
//!
//! # Where this sits
//!
//! One poller thread per participant drains every writer ring this
//! participant has been told to attach to, and pushes what it pops onto the
//! SAME `ArrayQueue<(RxMeta, u8)>` the multicast listeners feed. The Router
//! dequeues without knowing the origin, so decryption, deduplication,
//! fragment reassembly, ownership filters and listener dispatch all run
//! exactly as they do for a UDP datagram. Nothing calls
//! `TopicRegistry::deliver_with_writer` from here.
//!
//! Two consequences of that choice are deliberate:
//!
//! * The poller NEVER blocks the Router thread. `read_blocking` is not used
//!   at all: the Router thread is shared by every topic of the participant,
//!   and a blocking read on one writer's ring would stall the others.
//! * `RxMeta::origin` carries the peer's REAL UDP unicast locator, resolved
//!   by discovery for that peer, never a fabricated address -- unless the
//!   message sits behind an INFO_SRC (RTPS 2.5 8.3.8.10), in which case
//!   `origin.reply()` is `None` and no consumer may derive a destination
//!   from it. Every consumer of `meta.origin` in the Router answers "which
//!   peer sent this, and where does a reply go"; since the control plane
//!   (HEARTBEAT / ACKNACK / NACK_FRAG) stays on UDP, the real locator is the
//!   correct answer when one exists.
//!
//! # Attach is retried, not assumed
//!
//! A reader learns it should attach at pairing time (SEDP), which can be
//! before the remote writer has created its segment -- the writer creates it
//! lazily, on its first SHM-selected send. `shm_open` then fails with
//! ENOENT. Rather than lose the pairing, the request stays on a pending list
//! and is retried on a slow cadence -- but only for `ATTACH_BUDGET`. Past
//! that it is ABANDONED, counted and logged at error level: a retry loop
//! that never gives up would leave the participant claiming a pairing it
//! never made while the remote writer pushes samples into a ring nobody
//! drains, which is silent data loss and the one thing this leg must never
//! do.
//!
//! # Nothing here is silent
//!
//! Every way a packet can fail to reach the Router from this leg -- an
//! unroutable kind, an exhausted `RxPool`, a full rx ring, a packet larger
//! than a pool buffer, a ring the reader fell behind on -- increments a
//! counter on `global_metrics()` and logs at WARN or ERROR. A shared-memory
//! receive leg that quietly drops what a peer sent is indistinguishable
//! from one that works.

use super::notify::TopicNotify;
use super::ring::ShmRingReader;
use super::{segment_name, DEFAULT_RING_CAPACITY};
use crate::core::discovery::multicast::classifier::walk::{
    destined_to, split_by_receiver_state, Destined, Sources,
};
use crate::core::discovery::multicast::{classify_rtps, Origin, PacketKind, RxMeta, RxPool};
use crate::core::discovery::GUID;
use crate::engine::departures::{Departure, DepartureRoute};
use crate::engine::wake::WakeNotifier;
use crossbeam::queue::ArrayQueue;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The poller's sleep after its first sweep that found nothing.
///
/// Same floor as the Router's own idle cadence, so a burst that follows
/// traffic is swept at the same granularity it was before the backoff.
const IDLE_SLEEP_FLOOR: Duration = Duration::from_micros(100);

/// Environment variable that sets the idle sleep cap of the poller, in
/// microseconds. Read once, when the poller thread starts.
const IDLE_CAP_ENV: &str = "HDDS_SHM_IDLE_CAP_US";

/// The largest idle sleep cap `HDDS_SHM_IDLE_CAP_US` can ask for. Larger
/// values are clamped to it.
const IDLE_SLEEP_CAP_MAX: Duration = Duration::from_millis(10);

/// The idle sleep cap a poller uses when `HDDS_SHM_IDLE_CAP_US` is unset.
///
/// Equal to the floor, so an idle poller keeps sweeping at the floor cadence
/// and the first sample after a quiet ring is popped at once. A host where
/// that cadence is too costly opts into a larger cap; the cost of the cap is
/// the latency of a sample that lands in a quiet gap, which is popped at most
/// one cap later. Samples behind it in the same burst are not delayed.
const IDLE_SLEEP_CAP_DEFAULT: Duration = IDLE_SLEEP_FLOOR;

/// How long the poller keeps the floor cadence after a packet.
///
/// A request and its reply leave a gap of one round trip between samples.
/// Inside this window every gap is swept at the floor, so such an exchange
/// keeps its shared-memory latency; only a ring that has been quiet for the
/// whole window is backed off.
const IDLE_HOT_WINDOW: Duration = Duration::from_millis(10);

/// Parses the text of `HDDS_SHM_IDLE_CAP_US`: a whole number of
/// microseconds, clamped to `[IDLE_SLEEP_FLOOR, IDLE_SLEEP_CAP_MAX]`. `None`
/// when the text is not a whole number.
fn parse_idle_cap(text: &str) -> Option<Duration> {
    match text.parse::<u64>() {
        Ok(micros) => {
            Some(Duration::from_micros(micros).clamp(IDLE_SLEEP_FLOOR, IDLE_SLEEP_CAP_MAX))
        }
        Err(err) if *err.kind() == std::num::IntErrorKind::PosOverflow => Some(IDLE_SLEEP_CAP_MAX),
        Err(_) => None,
    }
}

/// The idle sleep cap for the value of `HDDS_SHM_IDLE_CAP_US` (`None` when
/// unset). Unset or empty gives the default; a value that is not a whole
/// number gives the default with one warning.
fn idle_sleep_cap(raw: Option<&str>) -> Duration {
    let text = match raw.map(str::trim) {
        None | Some("") => return IDLE_SLEEP_CAP_DEFAULT,
        Some(text) => text,
    };
    parse_idle_cap(text).unwrap_or_else(|| {
        log::warn!(
            "[SHM-RX] {} = {:?} is not a whole number of microseconds; using {} us",
            IDLE_CAP_ENV,
            text,
            IDLE_SLEEP_CAP_DEFAULT.as_micros()
        );
        IDLE_SLEEP_CAP_DEFAULT
    })
}

/// Sleep schedule of the poller between sweeps.
#[derive(Debug)]
struct IdleBackoff {
    /// The last time a sweep popped a packet, or the schedule started.
    last_packet: Instant,
    /// The sleep the next empty sweep takes once the window has passed.
    next: Duration,
    /// The longest sleep the schedule reaches.
    cap: Duration,
}

impl IdleBackoff {
    fn new(now: Instant, cap: Duration) -> Self {
        Self {
            last_packet: now,
            next: IDLE_SLEEP_FLOOR,
            cap,
        }
    }

    /// A sweep popped at least one packet: the hot window restarts and the
    /// backoff returns to the floor.
    fn active(&mut self, now: Instant) {
        self.last_packet = now;
        self.next = IDLE_SLEEP_FLOOR;
    }

    /// A sweep popped nothing: the duration to sleep now.
    fn idle(&mut self, now: Instant) -> Duration {
        if now.saturating_duration_since(self.last_packet) < IDLE_HOT_WINDOW {
            return IDLE_SLEEP_FLOOR;
        }
        let sleep = self.next;
        self.next = sleep.saturating_mul(2).min(self.cap);
        sleep
    }
}

/// How often a failed attach is retried. Deliberately slow: a retry is an
/// `shm_open` syscall, and the common reason for failure is "the writer has
/// not sent its first SHM sample yet", which resolves on its own.
const ATTACH_RETRY: Duration = Duration::from_millis(20);

/// How long a pending attach may keep retrying before it is ABANDONED,
/// loudly.
///
/// Retrying forever would leave the participant permanently claiming a
/// shared-memory pairing it never established, while the remote writer
/// happily pushes samples into a ring nobody drains -- silent, total data
/// loss for that peer. After this budget the request is dropped with an
/// error log naming the peer, and `global_metrics().attach_abandoned()`
/// counts it, so the condition is observable from outside this module.
const ATTACH_BUDGET: Duration = Duration::from_secs(20);

/// A reader-side request to start draining one remote writer's ring.
struct AttachRequest {
    /// Remote writer endpoint GUID: names the segment (`segment_name`) and
    /// picks the notify bucket.
    writer_guid: GUID,
    /// Topic the local reader matched on, for the topic notification
    /// segment.
    topic: String,
    /// The peer's real UDP unicast locator, stamped into every `RxMeta` this
    /// ring produces. See the module docs.
    peer: SocketAddr,
    /// The owner identity this segment must carry: the remote writer's GUID
    /// and the nonce its participant announced in discovery. `None` when the
    /// peer announced no nonce, which makes the attach refuse rather than
    /// trust an unauthenticated segment.
    expected_owner: Option<([u8; 16], u64)>,
    /// Next instant at which attaching may be retried.
    next_try: Instant,
    /// Instant past which this request is abandoned (see `ATTACH_BUDGET`).
    give_up_at: Instant,
    /// Last failure, so the abandonment log can name the actual reason
    /// rather than "it never worked".
    last_error: Option<String>,
}

/// One successfully attached remote writer ring.
struct AttachedWriter {
    reader: ShmRingReader,
    peer: SocketAddr,
    /// Last value of the ring reader's own overrun counter that was
    /// mirrored into the process-wide metrics, so each overrun is reported
    /// exactly once.
    overruns_seen: u64,
    /// Same, for the number of SAMPLES skipped, which is the figure that
    /// actually answers "how much did we lose".
    samples_skipped_seen: u64,
}

/// Receive leg of one participant's shared-memory transport.
///
/// No thread exists until the first attach request: a participant that
/// never pairs over shared memory (SHM disabled, or no co-located peer)
/// runs no poller at all. The poller thread is started by
/// `attach_writer`, and it lives until this value is dropped, which stops
/// it and joins it.
pub(crate) struct ShmReceiver {
    domain_id: u32,
    local_participant: GUID,
    ring: Arc<ArrayQueue<(RxMeta, u8)>>,
    pool: Arc<RxPool>,
    notifier: Option<Arc<WakeNotifier>>,
    attach_budget: Duration,
    pending: Arc<Mutex<Vec<AttachRequest>>>,
    /// Writer GUIDs already requested, so a replayed SEDP or a second local
    /// reader on the same topic does not attach the same ring twice (which
    /// would deliver every sample twice into the Router ring).
    known: Arc<Mutex<std::collections::HashSet<GUID>>>,
    stop: Arc<AtomicBool>,
    /// The poller thread, once started. Guards the start, and the route
    /// wiring that depends on it, so the two cannot interleave.
    poller: Mutex<Option<JoinHandle<()>>>,
    /// The departures of remote writers posted to the poller: it drains its
    /// rings into the receive ring, then fences them there behind what it
    /// drained (`engine::departures`).
    departures: Arc<Mutex<Vec<Departure>>>,
    route: Arc<std::sync::OnceLock<Arc<DepartureRoute>>>,
    /// Tests only: the poller neither drains nor fences while it is set.
    #[cfg(test)]
    hold: Arc<AtomicBool>,
}

impl ShmReceiver {
    /// The receive leg for one participant. Starts no thread: see the type
    /// docs.
    ///
    /// `ring`, `pool` and `notifier` are the participant's own receive
    /// plumbing, shared verbatim with the multicast listeners.
    pub(crate) fn new(
        domain_id: u32,
        local_participant: GUID,
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        pool: Arc<RxPool>,
        notifier: Option<Arc<WakeNotifier>>,
    ) -> Self {
        Self::with_attach_budget(
            domain_id,
            local_participant,
            ring,
            pool,
            notifier,
            ATTACH_BUDGET,
        )
    }

    /// Same, with an explicit attach budget. Exists so a test can force the
    /// abandonment path in milliseconds instead of waiting out
    /// `ATTACH_BUDGET`; production callers use `new`.
    pub(crate) fn with_attach_budget(
        domain_id: u32,
        local_participant: GUID,
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        pool: Arc<RxPool>,
        notifier: Option<Arc<WakeNotifier>>,
        attach_budget: Duration,
    ) -> Self {
        Self {
            domain_id,
            local_participant,
            ring,
            pool,
            notifier,
            attach_budget,
            pending: Arc::new(Mutex::new(Vec::new())),
            known: Arc::new(Mutex::new(std::collections::HashSet::new())),
            stop: Arc::new(AtomicBool::new(false)),
            poller: Mutex::new(None),
            departures: Arc::new(Mutex::new(Vec::new())),
            route: Arc::new(std::sync::OnceLock::new()),
            #[cfg(test)]
            hold: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the poller thread if it is not running. Called with the
    /// `poller` lock held. Once it runs, the departure route fences through
    /// it.
    fn start_poller(&self, slot: &mut Option<JoinHandle<()>>) {
        if slot.is_some() {
            return;
        }
        let domain_id = self.domain_id;
        let local_participant = self.local_participant;
        let pending = Arc::clone(&self.pending);
        let stop = Arc::clone(&self.stop);
        let ring = Arc::clone(&self.ring);
        let pool = Arc::clone(&self.pool);
        let notifier = self.notifier.clone();
        let departures = Arc::clone(&self.departures);
        let route = Arc::clone(&self.route);
        #[cfg(test)]
        let hold = Arc::clone(&self.hold);
        #[cfg(not(test))]
        let hold = Arc::new(AtomicBool::new(false));
        let spawned = std::thread::Builder::new()
            .name("hdds-shm-rx".to_string())
            .spawn(crate::core::rt::shutdown::owned(move || {
                poller_loop(
                    domain_id,
                    local_participant,
                    &pending,
                    &stop,
                    &ring,
                    &pool,
                    notifier.as_deref(),
                    PollerDepartures {
                        inbox: &departures,
                        route: &route,
                        hold: &hold,
                    },
                );
            }));
        match spawned {
            Ok(handle) => {
                if let Some(route) = self.route.get() {
                    route.attach_shm(Some(Arc::clone(&self.departures)));
                }
                *slot = Some(handle);
            }
            Err(err) => log::error!(
                "[SHM-RX] domain={} could not start the shared-memory poller: {}",
                self.domain_id,
                err
            ),
        }
    }

    /// Route the departures of remote writers through this poller: each is
    /// fenced in the receive ring after the poller drained its rings
    /// (`engine::departures`), so a writer's last samples still in its
    /// shared-memory ring reach the readers before its departure. Until the
    /// poller runs, there is nothing to drain and a departure is fenced at
    /// once.
    pub(crate) fn route_departures(&self, route: Arc<DepartureRoute>) {
        let slot = self.poller.lock().unwrap_or_else(|e| e.into_inner());
        if self.route.set(Arc::clone(&route)).is_ok() && slot.is_some() {
            route.attach_shm(Some(Arc::clone(&self.departures)));
        }
    }

    /// Tests only: hold the poller (it neither drains nor fences) or let it
    /// go.
    #[cfg(test)]
    pub(crate) fn hold_for_test(&self, hold: bool) {
        self.hold.store(hold, Ordering::Release);
    }

    /// Tests only: whether the poller thread has been started.
    #[cfg(test)]
    pub(crate) fn has_poller(&self) -> bool {
        self.poller
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    /// Ask the poller to drain `writer_guid`'s ring, stamping `peer` into
    /// every `RxMeta` it produces.
    ///
    /// Idempotent per writer GUID. Called from the match path (cold: once
    /// per pairing), never from a send or receive hot path.
    pub(crate) fn attach_writer(
        &self,
        writer_guid: GUID,
        topic: &str,
        peer: SocketAddr,
        peer_nonce: Option<u64>,
    ) {
        {
            let mut known = self.known.lock().unwrap_or_else(|e| e.into_inner());
            if !known.insert(writer_guid) {
                return;
            }
        }
        {
            let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            pending.push(AttachRequest {
                writer_guid,
                topic: topic.to_string(),
                peer,
                expected_owner: peer_nonce.map(|n| (writer_guid.as_bytes(), n)),
                next_try: now,
                give_up_at: now + self.attach_budget,
                last_error: None,
            });
        }
        log::debug!(
            "[SHM-RX] domain={} queued attach to writer={} topic='{}' peer={}",
            self.domain_id,
            writer_guid,
            topic,
            peer
        );
        let mut slot = self.poller.lock().unwrap_or_else(|e| e.into_inner());
        self.start_poller(&mut slot);
    }
}

impl Drop for ShmReceiver {
    fn drop(&mut self) {
        // No departure comes here; those posted and not fenced yet
        // are fenced once the poller is gone (nothing left to drain).
        if let Some(route) = self.route.get() {
            route.attach_shm(None);
        }
        self.stop.store(true, Ordering::Relaxed);
        let handle = self
            .poller
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(handle) = handle {
            crate::core::rt::shutdown::join_bounded(handle, "SHM receiver");
        }
        if let Some(route) = self.route.get() {
            let left =
                std::mem::take(&mut *self.departures.lock().unwrap_or_else(|e| e.into_inner()));
            for departure in left {
                route.fence(departure);
            }
        }
    }
}

/// The poller's side of the departure route (`ShmReceiver::route_departures`).
struct PollerDepartures<'a> {
    inbox: &'a Mutex<Vec<Departure>>,
    route: &'a std::sync::OnceLock<Arc<DepartureRoute>>,
    hold: &'a AtomicBool,
}

/// Try to attach one pending request. On failure returns the reason, which
/// the abandonment log quotes verbatim.
fn try_attach(domain_id: u32, request: &AttachRequest) -> Result<ShmRingReader, String> {
    let guid_bytes = request.writer_guid.as_bytes();
    let name = segment_name(domain_id, &guid_bytes);
    let bucket = TopicNotify::bucket_for_guid(&guid_bytes);
    match ShmRingReader::attach(&name, DEFAULT_RING_CAPACITY, bucket, request.expected_owner) {
        Ok(reader) => {
            // No topic notify segment: this poller sweeps its rings on a
            // timer and never waits on the buckets, and holding the segment
            // would take one of its user rows (`NOTIFY_MAX_USERS`) per
            // reader process for nothing.
            log::debug!(
                "[SHM-RX] attached segment {} for topic='{}' peer={}",
                name,
                request.topic,
                request.peer
            );
            Ok(reader)
        }
        Err(err) => Err(format!("{err}")),
    }
}

/// Hand one popped packet to the Router by way of the participant's own
/// receive ring.
///
/// Returns false when the packet could not be handed over. Every such
/// outcome is logged at WARN or ERROR and counted through
/// `global_metrics()`: a receive leg that quietly drops what a peer sent
/// over shared memory is indistinguishable from one that works, which is
/// the failure mode this whole path exists to end. A packet destined
/// entirely to another participant has nothing to hand over, and that is
/// not a failure.
fn forward_to_router(
    received: &[u8],
    ours: &[u8; 12],
    peer: SocketAddr,
    ring: &ArrayQueue<(RxMeta, u8)>,
    pool: &Arc<RxPool>,
    notifier: Option<&WakeNotifier>,
) -> bool {
    // A segment is read by every local participant: only what is destined
    // to this one is routed (RTPS 2.5 8.3.8.8), as on every other leg.
    let part;
    let packet = match destined_to(received, ours) {
        Destined::Whole => received,
        Destined::Part(destined) => {
            part = destined;
            &part[..]
        }
        Destined::Nothing => return true,
    };
    // One message per source (INFO_SRC, RTPS 2.5 8.3.8.10) and reply
    // locator (INFO_REPLY, 8.3.8.9), each forwarded as if it had arrived
    // alone. Every one is attempted. The leading part (if any) is direct:
    // `peer` IS its source. Every part behind an INFO_SRC is relayed: `peer`
    // only forwarded it over shared memory, and 8.3.8.10 leaves it no reply
    // locator. Every part behind an INFO_REPLY replies where it names.
    match split_by_receiver_state(packet) {
        Sources::One(message) => {
            forward_message(message, Origin::direct(peer), ring, pool, notifier)
        }
        Sources::Split(parts) => parts.iter().fold(true, |all, part| {
            forward_message(&part.message, part.origin(peer), ring, pool, notifier) && all
        }),
    }
}

/// Classify one RTPS message and push it into the participant's receive
/// ring; the `false` exits are `forward_to_router`'s.
fn forward_message(
    packet: &[u8],
    origin: Origin,
    ring: &ArrayQueue<(RxMeta, u8)>,
    pool: &Arc<RxPool>,
    notifier: Option<&WakeNotifier>,
) -> bool {
    // Classify with the SAME classifier the UDP listener uses, so a packet
    // that arrived over shared memory is described to the Router in exactly
    // the same terms as one that arrived over a socket.
    let (kind, payload_offset, fragment_metadata, rtps_context) = classify_rtps(packet);
    if !matches!(
        kind,
        PacketKind::Data | PacketKind::DataFrag | PacketKind::Heartbeat | PacketKind::HeartbeatFrag
    ) {
        super::global_metrics().inc_overruns();
        log::error!(
            "[SHM-RX] peer={} pushed a {:?} packet the Router cannot route -- dropped. \
             Only the writer DATA leg is wired to shared memory; anything else means the \
             two sides disagree about what crosses.",
            origin.from(),
            kind
        );
        return false;
    }

    let buffer_id = match pool.acquire_for_listener() {
        Some(id) => id,
        None => {
            super::global_metrics().inc_overruns();
            log::warn!(
                "[SHM-RX] peer={}: RxPool exhausted, dropping a {:?} packet that arrived over \
                 shared memory (BEST_EFFORT, so it is not repaired)",
                origin.from(),
                kind
            );
            return false;
        }
    };

    // Never truncate. A short pool buffer would hand the Router a mangled
    // RTPS packet, which is worse than a counted drop. RxPool buffers are
    // MAX_PACKET_SIZE (64 KB) and a slot holds far less, so this is a
    // guard against a future resizing, not an expected branch.
    let capacity = pool.get_buffer(buffer_id).len();
    if packet.len() > capacity {
        if let Err(err) = pool.release(buffer_id) {
            log::error!("[SHM-RX] failed to release buffer {}: {}", buffer_id, err);
        }
        super::global_metrics().inc_overruns();
        log::error!(
            "[SHM-RX] peer={}: a {} byte shared-memory packet does not fit the {} byte RxPool \
             buffer -- dropped rather than truncated",
            origin.from(),
            packet.len(),
            capacity
        );
        return false;
    }
    let len = packet.len();

    // SAFETY: mirrors the multicast listener's own copy into the pool
    // (`listener.rs`): `buffer_id` was just acquired from the freelist, so no
    // other thread holds it, and it is not published to the ring until the
    // copy below has completed. `len <= capacity` was just checked.
    unsafe {
        let pool_ptr = Arc::as_ptr(pool);
        let buf = (*pool_ptr.cast_mut()).get_buffer_mut(buffer_id);
        buf[..len].copy_from_slice(&packet[..len]);
    }

    let mut meta = match (payload_offset, fragment_metadata) {
        (Some(offset), Some(frag)) => RxMeta::new_with_fragment(origin, len, kind, offset, frag),
        (Some(offset), None) => RxMeta::new_with_offset(origin, len, kind, offset),
        _ => RxMeta::new(origin, len, kind),
    };
    meta.rtps_context = rtps_context;

    if ring.push((meta, buffer_id)).is_err() {
        if let Err(err) = pool.release(buffer_id) {
            log::error!("[SHM-RX] failed to release buffer {}: {}", buffer_id, err);
        }
        super::global_metrics().inc_overruns();
        log::warn!(
            "[SHM-RX] peer={}: the participant rx ring is full, dropping a {:?} packet that \
             arrived over shared memory (BEST_EFFORT, so it is not repaired)",
            origin.from(),
            kind
        );
        return false;
    }
    if let Some(n) = notifier {
        n.notify();
    }
    super::global_metrics().inc_reads();
    true
}

#[allow(clippy::too_many_arguments)]
fn poller_loop(
    domain_id: u32,
    local_participant: GUID,
    pending: &Mutex<Vec<AttachRequest>>,
    stop: &AtomicBool,
    ring: &ArrayQueue<(RxMeta, u8)>,
    pool: &Arc<RxPool>,
    notifier: Option<&WakeNotifier>,
    departures: PollerDepartures<'_>,
) {
    let mut attached: Vec<AttachedWriter> = Vec::new();
    // One scratch buffer, reused: a slot payload is the hard upper bound on
    // what any push could have written.
    let mut scratch = vec![0u8; super::SLOT_PAYLOAD_SIZE];
    let cap = idle_sleep_cap(std::env::var(IDLE_CAP_ENV).ok().as_deref());
    let mut backoff = IdleBackoff::new(Instant::now(), cap);

    while !stop.load(Ordering::Relaxed) {
        // Cold path: promote whatever pending attach is due, and ABANDON --
        // loudly -- whatever has run out of budget. A request retried
        // forever would leave this participant claiming a shared-memory
        // pairing it never made, while the remote writer pushes samples into
        // a ring nobody drains.
        {
            let mut queue = pending.lock().unwrap_or_else(|e| e.into_inner());
            if !queue.is_empty() {
                let now = Instant::now();
                queue.retain_mut(|request| {
                    if request.next_try > now {
                        return true;
                    }
                    match try_attach(domain_id, request) {
                        Ok(reader) => {
                            // Tell the writer we are here, and only now. Until
                            // this claim lands the writer serves this
                            // participant over UDP; after it, over the ring.
                            //
                            // The claim carries the cursor `attach` set from
                            // the ring head. That number does two jobs: it
                            // stops the writer crediting this peer with a
                            // packet it has already gone past, and, as it is
                            // refreshed each drain sweep, it is the proof of
                            // life that lets the writer drop a claim nobody is
                            // behind any more.
                            let start_cursor = reader.sequence();
                            if !reader
                                .presence()
                                .claim(local_participant.as_bytes(), start_cursor)
                            {
                                // Do NOT drain a ring we could not claim. The
                                // writer only stops sending UDP to a peer that
                                // holds an entry, so draining without one means
                                // every sample arrives twice, on both legs, for
                                // the life of the pairing - and each shared-memory
                                // copy costs an RxPool buffer and a slot on the
                                // participant's rx queue, the same ones the UDP
                                // listeners use.
                                super::global_metrics().inc_presence_table_full();
                                log::warn!(
                                    "[SHM-RX] remote writer {} (topic='{}', peer={}): its \
                                     presence table is full, so this participant stays on the \
                                     UDP leg for it. Delivery is unaffected; this costs the \
                                     shared-memory win, not samples.",
                                    request.writer_guid,
                                    request.topic,
                                    request.peer,
                                );
                                return false;
                            }
                            attached.push(AttachedWriter {
                                reader,
                                peer: request.peer,
                                overruns_seen: 0,
                                samples_skipped_seen: 0,
                            });
                            false
                        }
                        Err(err) => {
                            if now >= request.give_up_at {
                                super::global_metrics().inc_attach_abandoned();
                                log::error!(
                                    "[SHM-RX] giving up on remote writer {} (topic='{}', \
                                     peer={}) after the attach budget expired: {}. Every sample \
                                     that writer sends over shared memory is now lost to this \
                                     participant.",
                                    request.writer_guid,
                                    request.topic,
                                    request.peer,
                                    request.last_error.as_deref().unwrap_or(err.as_str())
                                );
                                return false;
                            }
                            request.last_error = Some(err);
                            request.next_try = now + ATTACH_RETRY;
                            true
                        }
                    }
                });
            }
        }

        if departures.hold.load(Ordering::Acquire) {
            std::thread::sleep(backoff.idle(Instant::now()));
            continue;
        }
        // The departures posted before this sweep: fenced after it, behind
        // everything their writers pushed before they left.
        let departed: Vec<Departure> =
            std::mem::take(&mut *departures.inbox.lock().unwrap_or_else(|e| e.into_inner()));
        let mut moved = false;
        for writer in &mut attached {
            let before = writer.reader.sequence();
            while let Some(len) = writer.reader.try_pop(&mut scratch) {
                moved = true;
                forward_to_router(
                    &scratch[..len],
                    &local_participant.prefix,
                    writer.peer,
                    ring,
                    pool,
                    notifier,
                );
            }
            // Publish how far we got, once per sweep rather than per sample.
            // This is what proves to the writer that this participant is still
            // consuming: a claim whose cursor stops moving belongs to a peer
            // that died, was killed, or never existed, and the writer stops
            // crediting it without needing a timer or a reaper.
            let after = writer.reader.sequence();
            if after != before {
                writer
                    .reader
                    .presence()
                    .refresh_cursor(local_participant.as_bytes(), after);
            }
            // Mirror the ring's OWN overrun counter (ring.rs) into the
            // process-wide metrics, so "this reader fell behind and lost
            // samples" is visible outside this module rather than buried in
            // a per-reader struct nobody holds.
            let overruns = writer.reader.metrics.overruns.load(Ordering::Relaxed);
            if overruns > writer.overruns_seen {
                let events = overruns - writer.overruns_seen;
                writer.overruns_seen = overruns;
                // Report SAMPLES, not events. One overrun event can cover many
                // lost messages, and an operator reading "1 overrun" for a
                // ring-sized hole has been told the wrong order of magnitude.
                let skipped = writer
                    .reader
                    .metrics
                    .samples_skipped
                    .load(Ordering::Relaxed);
                let lost = skipped.saturating_sub(writer.samples_skipped_seen);
                writer.samples_skipped_seen = skipped;
                for _ in 0..lost {
                    super::global_metrics().inc_overruns();
                }
                log::warn!(
                    "[SHM-RX] peer={}: {} sample(s) lost across {} shared-memory overrun \
                     event(s); the writer lapped this reader and they are gone (BEST_EFFORT, \
                     not repaired)",
                    writer.peer,
                    lost,
                    events
                );
            }
        }

        if let Some(route) = departures.route.get() {
            for departure in departed {
                route.fence(departure);
            }
        }
        if moved {
            backoff.active(Instant::now());
        } else {
            std::thread::sleep(backoff.idle(Instant::now()));
        }
    }

    // Leaving: drop our claims so the writer stops serving a participant that
    // is no longer draining. A process that dies without reaching this leaves
    // a stale claim, which makes the writer keep using the ring for a peer
    // that is gone -- the same outcome as a peer that dies on the UDP leg, and
    // not a delivery failure for anyone else.
    for writer in &attached {
        writer
            .reader
            .presence()
            .release(local_participant.as_bytes());
    }
}
#[cfg(test)]
mod tests {
    use super::super::test_support::NotifyGoneOnDrop;
    use super::*;
    use crate::transport::shm::ShmWriterTransport;

    /// The topic's notify segment must be gone once the test's writers and
    /// readers are dropped: it is released by its last user.
    fn notify_guard(domain_id: u32, topic: &str) -> NotifyGoneOnDrop {
        NotifyGoneOnDrop::topic(domain_id, topic)
    }

    /// The receive poller never waits on the topic's notify buckets (it
    /// sweeps on a timer), so attaching a ring must not attach the notify
    /// segment: that would spend one of its user rows per reader process
    /// for nothing.
    #[test]
    fn a_receive_attach_takes_no_notify_row() {
        let guid = writer_guid(0x31);
        let mut writer = ShmWriterTransport::new(94, guid, "shm_rx_no_row").expect("writer");
        writer.write(b"x").expect("push");
        let request = AttachRequest {
            writer_guid: guid,
            topic: "shm_rx_no_row".to_string(),
            peer: "127.0.0.1:7494".parse().expect("addr"),
            expected_owner: Some((guid.as_bytes(), crate::transport::shm::local_nonce())),
            next_try: Instant::now(),
            give_up_at: Instant::now() + Duration::from_secs(5),
            last_error: None,
        };
        let reader = try_attach(94, &request).expect("attach");
        assert!(
            !reader.has_notify(),
            "a poller-side reader must not hold a notify row"
        );
        drop(reader);
        drop(writer);
        assert!(!crate::transport::shm::ShmSegment::exists(
            &crate::transport::shm::TopicNotify::segment_name(94, "shm_rx_no_row")
        ));
    }

    /// A segment is read by every local participant: a DATA an INFO_DST
    /// destines to another one is not handed to this one's Router, and that
    /// is not a failure.
    #[test]
    fn only_what_is_destined_here_reaches_the_router() {
        let ring = ArrayQueue::<(RxMeta, u8)>::new(8);
        let pool = Arc::new(RxPool::new(8, 2048).expect("pool"));
        let peer: SocketAddr = "127.0.0.1:7411".parse().expect("addr");
        let ours = [0x0B; 12];
        let data = crate::protocol::builder::build_data_packet("shm_dest", 1, b"payload");
        let destined = |prefix: [u8; 12]| {
            let mut packet = data[..20].to_vec();
            packet.extend_from_slice(&[0x0e, 0x01, 0x0c, 0x00]);
            packet.extend_from_slice(&prefix);
            packet.extend_from_slice(&data[20..]);
            packet
        };

        assert!(forward_to_router(
            &destined([0x0C; 12]),
            &ours,
            peer,
            &ring,
            &pool,
            None
        ));
        assert!(ring.is_empty(), "destined to another participant");

        assert!(forward_to_router(
            &destined(ours),
            &ours,
            peer,
            &ring,
            &pool,
            None
        ));
        let (meta, buffer_id) = ring.pop().expect("destined here");
        assert_eq!(meta.kind, PacketKind::Data);
        pool.release(buffer_id).expect("release");
    }

    /// RTPS 2.5 8.3.8.10: a DATA behind an INFO_SRC comes from the
    /// participant the INFO_SRC names. What reaches the Router is a message
    /// whose header names that source.
    #[test]
    fn a_data_behind_an_info_src_reaches_the_router_under_its_source() {
        let ring = ArrayQueue::<(RxMeta, u8)>::new(8);
        let pool = Arc::new(RxPool::new(8, 2048).expect("pool"));
        let peer: SocketAddr = "127.0.0.1:7411".parse().expect("addr");
        const ORIGIN: [u8; 12] = [0x0D; 12];
        let data = crate::protocol::builder::build_data_packet("shm_src", 1, b"payload");
        assert_ne!(data[8..20], ORIGIN);
        let mut packet = data[..20].to_vec();
        packet.extend_from_slice(&[0x0c, 0x01, 0x14, 0x00, 0, 0, 0, 0, 0x02, 0x05, 0x01, 0x0F]);
        packet.extend_from_slice(&ORIGIN);
        packet.extend_from_slice(&data[20..]);

        assert!(forward_to_router(
            &packet,
            &[0x0B; 12],
            peer,
            &ring,
            &pool,
            None
        ));
        let (meta, buffer_id) = ring.pop().expect("the DATA");
        assert_eq!(meta.kind, PacketKind::Data);
        assert_eq!(pool.get_buffer(buffer_id)[8..20], ORIGIN);
        assert_eq!(
            meta.origin.from(),
            peer,
            "kept for logs, never a destination"
        );
        assert_eq!(
            meta.origin.reply(),
            None,
            "behind an INFO_SRC the SHM peer only forwarded it (RTPS 2.5 8.3.8.10)"
        );
        pool.release(buffer_id).expect("release");
    }

    /// The leading part of a datagram (ahead of any INFO_SRC) is direct: the
    /// SHM peer IS its source, and a reply may still use it.
    #[test]
    fn a_data_ahead_of_an_info_src_keeps_the_peer_as_a_reply_address() {
        let ring = ArrayQueue::<(RxMeta, u8)>::new(8);
        let pool = Arc::new(RxPool::new(8, 2048).expect("pool"));
        let peer: SocketAddr = "127.0.0.1:7411".parse().expect("addr");
        let data = crate::protocol::builder::build_data_packet("shm_direct", 1, b"payload");

        assert!(forward_to_router(
            &data,
            &[0x0B; 12],
            peer,
            &ring,
            &pool,
            None
        ));
        let (meta, buffer_id) = ring.pop().expect("the DATA");
        assert_eq!(meta.origin.reply(), Some(peer), "no INFO_SRC: direct");
        pool.release(buffer_id).expect("release");
    }

    /// RTPS 2.5 8.3.8.9: a DATA behind an INFO_REPLY_IP4 reaches the
    /// Router with the locator it named as its Receiver reply locator; the
    /// address the stateful endpoints fall back to is still the SHM peer.
    #[test]
    fn a_data_behind_an_info_reply_reaches_the_router_with_its_locator() {
        let ring = ArrayQueue::<(RxMeta, u8)>::new(8);
        let pool = Arc::new(RxPool::new(8, 2048).expect("pool"));
        let peer: SocketAddr = "127.0.0.1:7411".parse().expect("addr");
        let data = crate::protocol::builder::build_data_packet("shm_reply", 1, b"payload");
        let mut packet = data[..20].to_vec();
        // INFO_REPLY_IP4, E, 8 octets: 10.1.2.3 port 7999, little-endian.
        packet.extend_from_slice(&[0x0d, 0x01, 0x08, 0x00, 3, 2, 1, 10, 0x3f, 0x1f, 0, 0]);
        packet.extend_from_slice(&data[20..]);

        assert!(forward_to_router(
            &packet,
            &[0x0B; 12],
            peer,
            &ring,
            &pool,
            None
        ));
        let (meta, buffer_id) = ring.pop().expect("the DATA");
        assert_eq!(meta.kind, PacketKind::Data);
        assert_eq!(
            meta.origin.receiver_reply_locator(),
            Some("10.1.2.3:7999".parse().expect("addr"))
        );
        assert_eq!(
            meta.origin.reply(),
            Some(peer),
            "the stateful fallback: the peer"
        );
        pool.release(buffer_id).expect("release");
    }

    fn writer_guid(tag: u8) -> GUID {
        let mut bytes = [0u8; 16];
        bytes[0] = 0xE5;
        bytes[1] = tag;
        bytes[15] = 0x02;
        GUID::from_bytes(bytes)
    }

    /// The poller must survive an attach request for a segment that does not
    /// exist yet, and pick it up once the writer creates it. Without the
    /// retry list, a reader that matched before the writer's first SHM send
    /// would never attach and no sample would ever cross.
    ///
    /// Asserts on the Router-facing side: a real RTPS DATA packet pushed
    /// into the ring must show up on the participant's rx ring, classified
    /// as `Data`, carrying the peer locator the attach request supplied.
    #[test]
    fn attach_is_retried_until_the_writer_segment_exists() {
        let _notify_guard = notify_guard(91, "shm_rx_retry");
        let ring = Arc::new(ArrayQueue::<(RxMeta, u8)>::new(64));
        let pool = Arc::new(RxPool::new(8, 2048).expect("pool"));
        let receiver = ShmReceiver::new(
            91,
            GUID::from_bytes([9u8; 16]),
            Arc::clone(&ring),
            Arc::clone(&pool),
            None,
        );

        let guid = writer_guid(0x11);
        let peer: SocketAddr = "127.0.0.1:7411".parse().expect("addr");
        // Requested BEFORE any segment exists: the first attach attempt fails
        // and the request goes back on the retry list.
        // Same process, so the segment's owner nonce is ours: this exercises
        // the retry path, not the authentication path.
        receiver.attach_writer(
            guid,
            "shm_rx_retry",
            peer,
            Some(crate::transport::shm::local_nonce()),
        );
        std::thread::sleep(Duration::from_millis(30));

        let mut writer = ShmWriterTransport::new(91, guid, "shm_rx_retry").expect("writer");
        let packet = crate::protocol::builder::build_data_packet("shm_rx_retry", 1, b"payload-1");
        assert!(!packet.is_empty(), "builder produced no DATA packet");

        // Write on a loop, not once. `ShmRingReader::attach` starts at the
        // ring's current head, so anything pushed before the poller wins its
        // retry is skipped -- correct BEST_EFFORT behaviour (a late joiner is
        // owed nothing) and exactly why the DDS-level test writes in a loop
        // too.
        let mut got = None;
        for _ in 0..200 {
            writer.write(&packet).expect("push");
            if let Some(item) = ring.pop() {
                got = Some(item);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(receiver);

        let (meta, buffer_id) = got.expect("SHM packet never reached the participant rx ring");

        assert_eq!(meta.kind, PacketKind::Data);
        assert_eq!(
            meta.origin.from(),
            peer,
            "RxMeta must carry the peer's real UDP locator"
        );
        assert_eq!(meta.len as usize, packet.len());
        assert_eq!(&pool.get_buffer(buffer_id)[..packet.len()], &packet[..]);
    }

    /// FORCE the failure the coordinator cares about: a reader told to drain
    /// a writer ring that never appears.
    ///
    /// Retrying forever would leave this participant claiming a pairing it
    /// never made while the remote writer pushes into a ring nobody reads --
    /// total, silent data loss for that peer. After the attach budget the
    /// request must be abandoned, counted in
    /// `global_metrics().attach_abandoned()` and logged at error level.
    /// This asserts the counter, because a counter is what makes the
    /// condition visible from outside the module.
    #[test]
    fn an_attach_that_never_succeeds_is_abandoned_and_counted() {
        let ring = Arc::new(ArrayQueue::<(RxMeta, u8)>::new(8));
        let pool = Arc::new(RxPool::new(4, 2048).expect("pool"));
        let before = super::super::global_metrics().attach_abandoned();

        // Domain 92 with a GUID no writer will ever own: the segment cannot
        // appear, so every retry fails until the budget runs out.
        let receiver = ShmReceiver::with_attach_budget(
            92,
            GUID::from_bytes([8u8; 16]),
            ring,
            pool,
            None,
            Duration::from_millis(120),
        );
        receiver.attach_writer(
            writer_guid(0x7F),
            "shm_rx_never",
            "127.0.0.1:7492".parse().expect("addr"),
            Some(crate::transport::shm::local_nonce()),
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if super::super::global_metrics().attach_abandoned() > before {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let after = super::super::global_metrics().attach_abandoned();
        drop(receiver);

        assert!(
            after > before,
            "an attach that can never succeed was retried past its budget without being \
             counted ({before} before, {after} after): the participant would claim a \
             shared-memory pairing it never made, silently"
        );
    }

    /// A remote writer's departure, posted while its last samples are still
    /// in its shared-memory ring, reaches the receive ring AFTER them: the
    /// poller drains its rings, then fences the departure
    /// (`engine::departures`). Told at once, the readers took the writer for
    /// gone and discarded the sets those samples completed.
    #[test]
    fn a_departure_is_fenced_behind_the_samples_still_in_the_ring() {
        use crate::engine::departures::{Departure, DepartureRoute};
        let _notify_guard = notify_guard(93, "shm_rx_departure");
        let ring = Arc::new(ArrayQueue::<(RxMeta, u8)>::new(64));
        let pool = Arc::new(RxPool::new(32, 2048).expect("pool"));
        let receiver = ShmReceiver::new(
            93,
            GUID::from_bytes([7u8; 16]),
            Arc::clone(&ring),
            Arc::clone(&pool),
            None,
        );
        let route = Arc::new(DepartureRoute::new(Arc::clone(&ring), None));
        receiver.route_departures(Arc::clone(&route));
        let guid = writer_guid(0x21);
        let peer: SocketAddr = "127.0.0.1:7493".parse().expect("addr");
        receiver.attach_writer(
            guid,
            "shm_rx_departure",
            peer,
            Some(crate::transport::shm::local_nonce()),
        );
        let mut writer = ShmWriterTransport::new(93, guid, "shm_rx_departure").expect("writer");
        let packet = crate::protocol::builder::build_data_packet("shm_rx_departure", 1, b"x");
        // Attached once a sample crosses.
        let mut attached = false;
        for _ in 0..400 {
            writer.write(&packet).expect("push");
            if let Some((_, buffer)) = ring.pop() {
                pool.release(buffer).expect("release");
                attached = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(attached, "fixture: the reader attached");
        std::thread::sleep(Duration::from_millis(20));
        while let Some((_, buffer)) = ring.pop() {
            pool.release(buffer).expect("release");
        }
        // The writer's last samples, still in its ring; then it leaves.
        receiver.hold_for_test(true);
        std::thread::sleep(Duration::from_millis(5));
        for _ in 0..5 {
            writer.write(&packet).expect("push");
        }
        let departure = Departure::Participant {
            prefix: [0x21; 12],
            cause: crate::engine::WriterDeparture::Deleted,
        };
        route.post(departure);
        receiver.hold_for_test(false);
        let mut kinds = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !kinds.contains(&PacketKind::Departure) && Instant::now() < deadline {
            match ring.pop() {
                Some((meta, buffer)) => {
                    if meta.kind != PacketKind::Departure {
                        pool.release(buffer).expect("release");
                    }
                    kinds.push(meta.kind);
                }
                None => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        drop(receiver);
        assert_eq!(
            kinds,
            vec![
                PacketKind::Data,
                PacketKind::Data,
                PacketKind::Data,
                PacketKind::Data,
                PacketKind::Data,
                PacketKind::Departure
            ],
            "the writer's last samples, then its departure"
        );
        assert_eq!(route.next(), Some(departure));
    }

    /// A participant that pairs with no co-located peer, or does not use
    /// shared memory at all, runs no shared-memory poller: the thread starts
    /// with the first attach request, not when the participant is built.
    #[test]
    fn no_poller_runs_until_a_peer_asks_for_one() {
        let ring = Arc::new(ArrayQueue::<(RxMeta, u8)>::new(8));
        let pool = Arc::new(RxPool::new(4, 2048).expect("pool"));
        let receiver = ShmReceiver::new(95, GUID::from_bytes([5u8; 16]), ring, pool, None);
        assert!(
            !receiver.has_poller(),
            "a receive leg with nothing to attach must not own a thread"
        );
        receiver.attach_writer(
            writer_guid(0x41),
            "shm_rx_lazy",
            "127.0.0.1:7495".parse().expect("addr"),
            Some(crate::transport::shm::local_nonce()),
        );
        assert!(receiver.has_poller(), "an attach request starts the poller");
    }

    /// The cap an operator asks for with `HDDS_SHM_IDLE_CAP_US=2000`.
    fn two_ms_cap() -> Duration {
        idle_sleep_cap(Some("2000"))
    }

    /// Without the opt-in the cap is the floor, so a quiet poller never
    /// sleeps longer than the floor, however long the ring stays quiet.
    #[test]
    fn an_idle_poller_keeps_the_floor_by_default() {
        let base = Instant::now() + IDLE_HOT_WINDOW;
        let mut backoff = IdleBackoff::new(base - IDLE_HOT_WINDOW, idle_sleep_cap(None));
        for step in 0..64 {
            assert_eq!(
                backoff.idle(base),
                IDLE_SLEEP_FLOOR,
                "step {step}: the default poller backed off"
            );
        }
    }

    /// Inside the hot window a quiet poller keeps the floor cadence, so a
    /// request and its reply, a round trip apart, are swept at the floor.
    #[test]
    fn an_idle_poller_keeps_the_floor_inside_the_hot_window() {
        let base = Instant::now();
        let mut backoff = IdleBackoff::new(base, two_ms_cap());
        let mut at = Duration::ZERO;
        while at < IDLE_HOT_WINDOW {
            assert_eq!(backoff.idle(base + at), IDLE_SLEEP_FLOOR, "at {at:?}");
            at += Duration::from_micros(500);
        }
    }

    /// Past the window the sleep grows, never shrinks, stops at the cap and
    /// stays there.
    #[test]
    fn an_idle_poller_backs_off_to_the_cap_after_the_window() {
        let cap = two_ms_cap();
        assert_eq!(cap, Duration::from_millis(2), "fixture: the opted-in cap");
        let base = Instant::now() + IDLE_HOT_WINDOW;
        let mut backoff = IdleBackoff::new(base - IDLE_HOT_WINDOW, cap);
        let mut previous = Duration::ZERO;
        for _ in 0..64 {
            let sleep = backoff.idle(base);
            assert!(sleep >= previous, "the idle sleep never shrinks while idle");
            assert!(sleep <= cap, "the idle sleep {sleep:?} passed the cap");
            previous = sleep;
        }
        assert_eq!(previous, cap, "an idle poller reaches the cap");
        assert_eq!(
            IdleBackoff::new(base - IDLE_HOT_WINDOW, cap).idle(base),
            IDLE_SLEEP_FLOOR,
            "the first sleep after the window is the floor"
        );
    }

    /// A packet restarts the hot window: a poller backed off to the cap
    /// returns to the floor cadence for the whole window after it.
    #[test]
    fn a_packet_restarts_the_hot_window() {
        let base = Instant::now() + Duration::from_secs(1);
        let mut backoff = IdleBackoff::new(base - IDLE_HOT_WINDOW, two_ms_cap());
        for _ in 0..16 {
            backoff.idle(base);
        }
        backoff.active(base);
        for step in 1..=3u32 {
            assert_eq!(
                backoff.idle(base + Duration::from_millis(u64::from(step))),
                IDLE_SLEEP_FLOOR,
                "step {step} after the packet is inside the window"
            );
        }
    }

    /// A whole number of microseconds sets the cap, exactly.
    #[test]
    fn the_environment_value_sets_the_idle_cap() {
        assert_eq!(idle_sleep_cap(Some("500")), Duration::from_micros(500));
        assert_eq!(idle_sleep_cap(Some(" 500 ")), Duration::from_micros(500));
        assert_eq!(idle_sleep_cap(Some("10000")), Duration::from_millis(10));
    }

    /// Values outside [100, 10000] us are clamped into that range, including
    /// values too large for a u64.
    #[test]
    fn the_idle_cap_is_clamped_to_the_floor_and_the_maximum() {
        assert_eq!(idle_sleep_cap(Some("0")), IDLE_SLEEP_FLOOR);
        assert_eq!(idle_sleep_cap(Some("50")), IDLE_SLEEP_FLOOR);
        assert_eq!(idle_sleep_cap(Some("20000")), Duration::from_millis(10));
        assert_eq!(
            idle_sleep_cap(Some("99999999999999999999999999")),
            Duration::from_millis(10)
        );
    }

    /// Unset, empty and text that is not a whole number of microseconds all
    /// give the default cap. A non-number is never read as a cap of its own.
    #[test]
    fn an_invalid_idle_cap_falls_back_to_the_default() {
        assert_eq!(idle_sleep_cap(None), IDLE_SLEEP_CAP_DEFAULT);
        assert_eq!(idle_sleep_cap(Some("")), IDLE_SLEEP_CAP_DEFAULT);
        assert_eq!(idle_sleep_cap(Some("   ")), IDLE_SLEEP_CAP_DEFAULT);
        for text in ["abc", "-5", "1.5", "2ms", "2_000"] {
            assert_eq!(parse_idle_cap(text), None, "{text:?} is not a cap");
            assert_eq!(
                idle_sleep_cap(Some(text)),
                IDLE_SLEEP_CAP_DEFAULT,
                "{text:?} must fall back to the default"
            );
        }
    }

    /// Delivery rule: a sample written after the poller has been idle for a
    /// long time is still delivered. The poller may sleep between sweeps; it
    /// must never stop them.
    #[test]
    fn a_sample_written_after_a_long_idle_is_delivered() {
        let _notify_guard = notify_guard(96, "shm_rx_idle");
        let ring = Arc::new(ArrayQueue::<(RxMeta, u8)>::new(64));
        let pool = Arc::new(RxPool::new(16, 2048).expect("pool"));
        let receiver = ShmReceiver::new(
            96,
            GUID::from_bytes([6u8; 16]),
            Arc::clone(&ring),
            Arc::clone(&pool),
            None,
        );
        let guid = writer_guid(0x51);
        receiver.attach_writer(
            guid,
            "shm_rx_idle",
            "127.0.0.1:7496".parse().expect("addr"),
            Some(crate::transport::shm::local_nonce()),
        );
        let mut writer = ShmWriterTransport::new(96, guid, "shm_rx_idle").expect("writer");
        let packet = crate::protocol::builder::build_data_packet("shm_rx_idle", 1, b"warm");
        // Attached once a sample crosses; that sample is only the handshake.
        let mut attached = false;
        for _ in 0..400 {
            writer.write(&packet).expect("push");
            if let Some((_, buffer)) = ring.pop() {
                pool.release(buffer).expect("release");
                attached = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(attached, "fixture: the reader attached");
        // Long enough for the sweep to reach its idle cap several times over.
        std::thread::sleep(Duration::from_millis(200));

        writer.write(&packet).expect("push");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut delivered = false;
        while Instant::now() < deadline {
            if let Some((_, buffer)) = ring.pop() {
                pool.release(buffer).expect("release");
                delivered = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(receiver);
        assert!(
            delivered,
            "a sample written after a long idle never reached the rx ring"
        );
    }
}
