// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Per-reader sequence spaces for classic GROUP presentation peers.
//!
//! The journal and all native destinations keep the writer's original SNs.
//! A VOLATILE classic reader starts at the first complete writer part after
//! its match watermark. Historical durable readers keep origin zero.
//! A reader previously served natively also keeps origin zero after classification.

use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::dds::liveliness::{LivelinessClock, MonotonicClock};

use crate::core::discovery::GUID;
use crate::transport::UdpTransport;

#[derive(Clone, Copy, Debug)]
struct Window {
    floor: u64,
    lower: u64,
    generation: u64,
    fixed_origin: bool,
    ready: bool,
    endpoint: Option<SocketAddr>,
}

// UDP has no pairing epoch and no guaranteed maximum packet lifetime. Reusing
// an origin after expiry assumes old controls have ceased for two minutes.
// The bound includes reader timers and replies to delayed HEARTBEATs.
// Each observed delayed control restarts this quiet period. Applications that
// can retain/reinject packets beyond it must use a fresh reader GUID.
const RETIRED_QUIET_NS: u64 = 120_000_000_000;

struct RetiredOrigin {
    origin: u64,
    last_control: u64,
}

/// One control uses one origin and one pairing, including its state update.
#[derive(Clone, Copy)]
pub(crate) struct ControlWindow {
    reader: Option<[u8; 16]>,
    generation: u64,
    pub(crate) offset: u64,
    pub(crate) first: u64,
}

impl ControlWindow {
    pub(crate) fn is_classic(self) -> bool {
        self.generation != 0
    }

    pub(crate) fn valid_base(self, base: u64, highest: u64) -> bool {
        base >= self.first && base <= highest.saturating_add(1)
    }

    pub(crate) fn valid_range(self, range: &std::ops::Range<u64>, highest: u64) -> bool {
        range.start >= self.first
            && range.start < range.end
            && range.end <= highest.saturating_add(1)
    }
}

/// Shared by every producer and reliability consumer of one writer.
#[derive(Default)]
pub(crate) struct WriterWindows {
    present: AtomicBool,
    group: AtomicBool,
    highest_unretained: AtomicU64,
    generation: AtomicU64,
    peers: Mutex<HashMap<[u8; 16], Window>>,
    native_matches: Mutex<HashSet<[u8; 16]>>,
    // Lazily pruned on pairing, departure and delayed controls. Churn retains
    // only departures within the quiet period, never the writer's lifetime.
    retired_origins: Mutex<HashMap<[u8; 16], RetiredOrigin>>,
    retired_present: AtomicBool,
    retirement_clock: OnceLock<Arc<dyn LivelinessClock>>,
    /// Tests only: a one-shot signal fired from every `peers.lock()`
    /// call site that a resolve path can reach (`contains`,
    /// `resolve_inner`), immediately BEFORE attempting the lock, so a
    /// test holding that mutex from another thread
    /// (`hold_peers_for_test`) can confirm some such call actually
    /// reached the contested acquisition, instead of inferring that
    /// from how long some later, unrelated call took.
    #[cfg(test)]
    peers_contention_hook: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}

impl WriterWindows {
    #[cfg(test)]
    pub(crate) fn set_retirement_clock(&self, clock: Arc<dyn LivelinessClock>) {
        assert!(self.retirement_clock.set(clock).is_ok());
    }

    fn retirement_now(&self) -> u64 {
        self.retirement_clock
            .get_or_init(|| Arc::new(MonotonicClock::new()))
            .now()
    }

    fn prune_retired(retired: &mut HashMap<[u8; 16], RetiredOrigin>, now: u64) {
        retired.retain(|_, entry| now.saturating_sub(entry.last_control) < RETIRED_QUIET_NS);
    }

    fn note_retired_control(&self, reader: Option<[u8; 16]>) {
        if !self.retired_present.load(Ordering::Acquire) {
            return;
        }
        let mut retired = self
            .retired_origins
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = self.retirement_now();
        Self::prune_retired(&mut retired, now);
        if let Some(entry) = reader.and_then(|reader| retired.get_mut(&reader)) {
            entry.last_control = now;
        }
        self.retired_present
            .store(!retired.is_empty(), Ordering::Release);
    }

    /// A reader served before classification must never reuse native SNs.
    pub(crate) fn note_native_match(&self, reader: GUID) {
        self.native_matches
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(reader.as_bytes());
    }

    fn isolates_native(&self, endpoint: &SocketAddr) -> bool {
        self.present.load(Ordering::Acquire)
            && self
                .peers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .any(|window| window.endpoint.as_ref() == Some(endpoint))
    }

    pub(crate) fn configure(&self, group: bool) {
        self.group.store(group, Ordering::Release);
    }

    pub(crate) fn record_unretained(&self, seq: u64) {
        if self.is_group() {
            self.highest_unretained.fetch_max(seq, Ordering::Release);
        }
    }

    pub(crate) fn highest_unretained(&self) -> u64 {
        self.highest_unretained.load(Ordering::Acquire)
    }

    pub(crate) fn is_group(&self) -> bool {
        self.group.load(Ordering::Acquire)
    }

    pub(crate) fn pair(
        &self,
        reader: GUID,
        endpoint: Option<SocketAddr>,
        floor: u64,
        coherent: bool,
    ) {
        let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        let key = reader.as_bytes();
        if let Entry::Vacant(vacant) = peers.entry(key) {
            // Generation exhaustion refuses the pairing: nothing is inserted
            // and no retired origin is consumed.
            let next = self.next_generation();
            debug_assert!(next.is_some(), "pairing generations are not exhausted");
            let Some(generation) = next else {
                log::error!("pairing refused: the generation counter is exhausted");
                return;
            };
            let native = self
                .native_matches
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
            let mut retired = self
                .retired_origins
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            Self::prune_retired(&mut retired, self.retirement_now());
            let retired_origin = retired.remove(&key).map(|entry| entry.origin);
            self.retired_present
                .store(!retired.is_empty(), Ordering::Release);
            let origin = if native { Some(0) } else { retired_origin };
            let lower = floor.max(origin.unwrap_or(0));
            vacant.insert(Window {
                floor: origin.unwrap_or(floor),
                lower,
                generation,
                fixed_origin: origin.is_some(),
                ready: !coherent || lower == 0,
                endpoint,
            });
        }
        self.present.store(true, Ordering::Release);
    }

    /// The next pairing generation, or `None` once the counter is exhausted:
    /// it never reuses a value, so it cannot alias an existing pairing or the
    /// native zero sentinel.
    fn next_generation(&self) -> Option<u64> {
        self.generation
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |generation| {
                generation.checked_add(1)
            })
            .ok()
            .map(|previous| previous + 1)
    }

    pub(crate) fn contains(&self, reader: GUID) -> bool {
        // The periodic HEARTBEAT path's first `peers` acquisition for a
        // classic-window reader (`send_heartbeat_best_effort`'s
        // `classic_window && !windows.contains(...)` gate) -- a test
        // holding `peers` elsewhere contends here BEFORE `resolve_inner`
        // ever runs, so the contention signal fires here too.
        #[cfg(test)]
        self.note_peers_lock_attempt();
        self.peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&reader.as_bytes())
    }

    pub(crate) fn unpair(&self, reader: GUID) {
        let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        let native = self
            .native_matches
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&reader.as_bytes());
        if let Some(origin) = peers
            .remove(&reader.as_bytes())
            .map(|window| window.floor)
            .or_else(|| native.then_some(0))
        {
            let mut retired = self
                .retired_origins
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let now = self.retirement_now();
            Self::prune_retired(&mut retired, now);
            retired.insert(
                reader.as_bytes(),
                RetiredOrigin {
                    origin,
                    last_control: now,
                },
            );
            self.retired_present.store(true, Ordering::Release);
        }
        self.present.store(!peers.is_empty(), Ordering::Release);
    }

    /// Resolve one origin for the entire control message, before dispatch.
    /// A required classic window that is not paired yet is never origin zero.
    pub(crate) fn inbound_window(
        &self,
        reader: Option<[u8; 16]>,
        required: bool,
    ) -> Option<ControlWindow> {
        self.note_retired_control(reader);
        let native = ControlWindow {
            reader,
            generation: 0,
            offset: 0,
            first: 1,
        };
        if !self.present.load(Ordering::Acquire) {
            return if required { None } else { Some(native) };
        }
        let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        match reader.and_then(|r| peers.get(&r)) {
            Some(window) => Some(ControlWindow {
                reader,
                generation: window.generation,
                offset: window.floor,
                first: window.lower + 1,
            }),
            None if required => None,
            None => Some(native),
        }
    }

    /// Serialize acknowledgment accounting with pairing removal. A control
    /// decoded before unmatch cannot mutate the next pairing's ReaderProxy.
    pub(crate) fn apply_if_current(&self, snapshot: ControlWindow, apply: impl FnOnce()) -> bool {
        if !snapshot.is_classic() {
            apply();
            return true;
        }
        let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        if !snapshot
            .reader
            .and_then(|reader| peers.get(&reader))
            .is_some_and(|window| {
                window.generation == snapshot.generation
                    && window.floor == snapshot.offset
                    && window.lower + 1 == snapshot.first
            })
        {
            return false;
        }
        apply();
        true
    }

    #[cfg(test)]
    pub(crate) fn inbound_offset(&self, reader: Option<[u8; 16]>, required: bool) -> Option<u64> {
        self.inbound_window(reader, required)
            .map(|window| window.offset)
    }

    #[cfg(test)]
    pub(crate) fn inverse(&self, reader: Option<[u8; 16]>, sn: u64) -> Option<u64> {
        to_original(sn, self.inbound_offset(reader, false)?)
    }

    pub(crate) fn send_profile(
        &self,
        transport: &UdpTransport,
        packet: &[u8],
        endpoint: &SocketAddr,
        reader: Option<GUID>,
        classic: bool,
    ) -> std::io::Result<usize> {
        match reader {
            Some(reader) => self.send_classed(transport, packet, endpoint, reader, classic),
            None => self.send(transport, packet, endpoint, None),
        }
    }

    /// The live route already knows the participant's cached dialect flag.
    /// Native destinations bypass the window table, even in a mixed
    /// audience. The periodic HEARTBEAT path
    /// (`dds::writer::heartbeat_scheduler::send_heartbeat_to_readers`)
    /// does not call this: it calls `resolve_classed` directly, to do
    /// this same resolution work BEFORE taking its send gate, then
    /// transmits best-effort itself (see that function's doc).
    pub(crate) fn send_classed(
        &self,
        transport: &UdpTransport,
        packet: &[u8],
        endpoint: &SocketAddr,
        reader: GUID,
        classic: bool,
    ) -> std::io::Result<usize> {
        transmit_resolved(
            transport,
            self.resolve_classed(packet, endpoint, reader, classic),
        )
    }

    /// Resolve a classic/native destination to its final bytes WITHOUT
    /// sending them: everything `send_classed` does except the actual
    /// transport call (routing, vendor-address translation, the window
    /// table). `None` means RTPS routing says nothing should be sent
    /// here at all, not a failure.
    ///
    /// Used by the periodic HEARTBEAT path
    /// (`dds::writer::heartbeat_scheduler::send_heartbeat_best_effort`)
    /// to do ALL of this work -- including the `peers` mutex acquisition
    /// below -- BEFORE taking `HeartbeatSchedulerState::send_gate`: holding
    /// that gate across this resolution too would let
    /// `revoke_sends()` wait, unboundedly, on whatever (unrelated) thread
    /// happened to be holding `peers` at the time. Every other caller
    /// keeps going through `send_classed`, which calls this and then
    /// transmits in the same breath, unchanged.
    pub(crate) fn resolve_classed<'a>(
        &self,
        packet: &'a [u8],
        endpoint: &SocketAddr,
        reader: GUID,
        classic: bool,
    ) -> Resolved<'a> {
        if classic {
            return self.resolve_inner(packet, endpoint, Some(reader), true);
        }
        self.resolve_native(packet, endpoint, Some(reader))
    }

    /// `pairing` is set by `resolve_classed`'s caller after validating it
    /// is STILL the current one -- see `pairing_unchanged`. Used only by
    /// the periodic HEARTBEAT path, which prepares a batch of these
    /// ahead of time and transmits them later, under its send gate.
    ///
    /// Borrows `packet` (`Cow::Borrowed`) whenever the bytes going out
    /// are exactly the bytes that came in -- the common case for every
    /// DATA/ACKNACK/piggyback-HEARTBEAT send, which never needed a copy
    /// before the periodic path's prepare/transmit split and must not
    /// pay for one now just because that OTHER caller needs owned bytes
    /// to outlive one function call.
    fn resolve_native<'a>(
        &self,
        packet: &'a [u8],
        endpoint: &SocketAddr,
        reader: Option<GUID>,
    ) -> Resolved<'a> {
        if (endpoint.ip().is_multicast() && self.is_group()) || self.isolates_native(endpoint) {
            let reader = reader?;
            // HEARTBEAT_FRAG already carries INFO_DST. Keep its original bytes.
            if packet.get(20) == Some(&0x0e)
                && read_u16(
                    packet,
                    22,
                    packet.get(21).is_some_and(|flags| flags & 1 != 0),
                ) == Some(12)
                && packet.get(24..36) == Some(reader.prefix.as_slice())
            {
                return Some(ResolvedSend {
                    packet: Cow::Borrowed(packet),
                    endpoint: *endpoint,
                    pairing: None,
                });
            }
            return Some(ResolvedSend {
                packet: Cow::Owned(address_native(packet, reader)),
                endpoint: *endpoint,
                pairing: None,
            });
        }
        Some(ResolvedSend {
            packet: Cow::Borrowed(packet),
            endpoint: *endpoint,
            pairing: None,
        })
    }

    /// Encode for one destination, then hand the final bytes to the transport.
    /// With no classic peer this is one flag check, with no table lookup or copy.
    pub(crate) fn send(
        &self,
        transport: &UdpTransport,
        packet: &[u8],
        endpoint: &SocketAddr,
        reader: Option<GUID>,
    ) -> std::io::Result<usize> {
        transmit_resolved(
            transport,
            self.resolve_inner(packet, endpoint, reader, false),
        )
    }

    fn resolve_inner<'a>(
        &self,
        packet: &'a [u8],
        endpoint: &SocketAddr,
        reader: Option<GUID>,
        required: bool,
    ) -> Resolved<'a> {
        if required && endpoint.ip().is_multicast() {
            return None;
        }
        if endpoint.ip().is_multicast() && self.is_group() {
            let reader = reader?;
            let addressed = address_native(packet, reader);
            // A classic peer is unicast only, including its locator fallback.
            if self.contains(reader) {
                return None;
            }
            return Some(ResolvedSend {
                packet: Cow::Owned(addressed),
                endpoint: *endpoint,
                pairing: None,
            });
        }
        if !self.present.load(Ordering::Acquire) {
            return if required {
                None
            } else {
                self.resolve_native(packet, endpoint, reader)
            };
        }
        let transformed = {
            #[cfg(test)]
            self.note_peers_lock_attempt();
            let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
            let key = reader.map(|reader| reader.as_bytes());
            match key.and_then(|key| peers.get_mut(&key).map(|w| (key, w))) {
                Some((key, window)) => {
                    if endpoint.ip().is_multicast() {
                        return None;
                    }
                    window.endpoint = Some(*endpoint);
                    // Captured from the SAME window, under the SAME lock,
                    // translate() is about to run against -- the pairing
                    // this translation is only valid for.
                    let pairing = ClassicPairing {
                        reader: key,
                        generation: window.generation,
                        floor: window.floor,
                    };
                    Some(translate(packet, window, key).map(|packet| (packet, pairing)))
                }
                None if required => return None,
                None => None,
            }
        };
        match transformed {
            Some(Some((packet, pairing))) => Some(ResolvedSend {
                packet: Cow::Owned(packet),
                endpoint: *endpoint,
                pairing: Some(pairing),
            }),
            Some(None) => None,
            None => self.resolve_native(packet, endpoint, reader),
        }
    }

    /// Whether `pairing` (captured by `resolve_inner`/`resolve_classed`
    /// at translation time) still names the CURRENT pairing for that
    /// reader: a `peers` lookup and an integer comparison, no
    /// re-translation. Meant for the periodic HEARTBEAT path to call
    /// immediately before transmitting an already-prepared classic
    /// packet, catching the case where the
    /// reader departs, its retired-origin quiet period
    /// (`RETIRED_QUIET_NS`) expires, and the SAME GUID rematches at a
    /// NEW origin while this packet was sitting prepared -- `pair`
    /// always hands a brand new `generation` to a fresh pairing
    /// (`self.generation.fetch_update`, monotonic), so a mismatch here
    /// means exactly that happened and this packet's translated SNs no
    /// longer mean anything to whoever is on the other end of `reader`
    /// now.
    ///
    /// `try_lock`, never the blocking `lock`: this
    /// call runs under `HeartbeatSchedulerState::send_gate`, where
    /// NOTHING may wait -- `peers` is also held across a callback on the
    /// ACKNACK path (`apply_if_current`, through `set_acked_floor` into
    /// the history ring, with poison-recovery logging on that path too)
    /// and across a discovery-driven unmatch dispatch pass, neither
    /// bounded. On contention this drops THIS reader's packet for this
    /// tick -- legal, the same way a stale-pairing mismatch already is:
    /// the periodic origin retries every period, so a lost tick is not
    /// lost data.
    pub(crate) fn pairing_unchanged(&self, pairing: &ClassicPairing) -> bool {
        let peers = match self.peers.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return false,
        };
        peers.get(&pairing.reader).is_some_and(|window| {
            window.generation == pairing.generation && window.floor == pairing.floor
        })
    }

    /// Test-only: hold `peers`'s mutex until `release`'s flag is set
    /// `true` and its condvar notified -- simulating ANY other holder of
    /// this lock (another HEARTBEAT/ACKNACK/DATA `resolve_inner` call, on
    /// another thread) while a periodic tick is due, to prove the send
    /// gate no longer covers this acquisition (see `resolve_classed`'s
    /// doc and `dds::writer::heartbeat_scheduler::HeartbeatSchedulerState
    /// ::send_gate`). Sends on `entered` only AFTER the lock is actually
    /// held (not merely "this thread has started"), so a test waiting on
    /// it is never racing the lock acquisition itself.
    /// Tests only: arms a one-shot signal on `entering`, fired the next
    /// time `resolve_inner` reaches its `peers.lock()` call site, right
    /// before attempting the lock -- see `peers_contention_hook`'s doc.
    #[cfg(test)]
    pub(crate) fn arm_peers_contention_signal(&self, entering: std::sync::mpsc::Sender<()>) {
        *self
            .peers_contention_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(entering);
    }

    #[cfg(test)]
    fn note_peers_lock_attempt(&self) {
        if let Some(entering) = self
            .peers_contention_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = entering.send(());
        }
    }

    #[cfg(test)]
    pub(crate) fn hold_peers_for_test(
        &self,
        entered: std::sync::mpsc::Sender<()>,
        release: Arc<(Mutex<bool>, std::sync::Condvar)>,
    ) {
        let _guard = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        let _ = entered.send(());
        let (lock, cv) = &*release;
        let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = cv
            .wait_while(guard, |ready| !*ready)
            .unwrap_or_else(|e| e.into_inner());
    }
}

/// A classic peer's window identity at the moment a HEARTBEAT was
/// translated against it (`WriterWindows::resolve_inner`): `reader` is
/// the window's own key, `generation` is bumped to a fresh, monotonic
/// value on every re-pairing (`WriterWindows::pair`), and `floor` is
/// the origin the translation used. `WriterWindows::pairing_unchanged`
/// compares a held one against the CURRENT window.
pub(crate) struct ClassicPairing {
    reader: [u8; 16],
    generation: u64,
    floor: u64,
}

/// What a resolved HEARTBEAT/DATA/control submessage needs to actually
/// reach the wire: final bytes and destination, with all routing and
/// window-table work already done, plus (for a classic/translated send
/// only) the pairing it was translated against -- `None` for a native
/// destination, which carries no window state that can go stale.
///
/// `packet` borrows the original input whenever the bytes are unchanged
/// (the common native/untransformed case -- every DATA/ACKNACK/
/// piggyback-HEARTBEAT send); only a genuinely transformed packet
/// (classic translation, address rewriting) owns a fresh `Vec`. An
/// always-owned version of this type would copy every ordinary packet once
/// more than before the resolve/transmit split existed, on the hot
/// DATA/ACKNACK path, not just the periodic HEARTBEAT path the split is
/// for.
pub(crate) struct ResolvedSend<'a> {
    pub(crate) packet: std::borrow::Cow<'a, [u8]>,
    pub(crate) endpoint: SocketAddr,
    pub(crate) pairing: Option<ClassicPairing>,
}

/// `None` means RTPS routing says nothing should be sent here at all,
/// not a failure.
pub(crate) type Resolved<'a> = Option<ResolvedSend<'a>>;

/// The one place `send`/`send_classed` hand a resolved packet to the
/// transport: always the ordinary blocking unicast send. The periodic
/// HEARTBEAT path never calls this -- it resolves via `resolve_classed`
/// directly and transmits with the best-effort twin itself, under its
/// own send gate (`dds::writer::heartbeat_scheduler::
/// send_heartbeat_best_effort`), after revalidating any `pairing` via
/// `pairing_unchanged`.
fn transmit_resolved(transport: &UdpTransport, resolved: Resolved<'_>) -> std::io::Result<usize> {
    let Some(resolved) = resolved else {
        return Ok(0);
    };
    transport.send_user_data_unicast(&resolved.packet, &resolved.endpoint)
}

pub(crate) fn to_original(sn: u64, offset: u64) -> Option<u64> {
    sn.checked_add(offset).filter(|sn| *sn <= i64::MAX as u64)
}

pub(crate) fn range_to_original(
    range: std::ops::Range<u64>,
    offset: u64,
) -> Option<std::ops::Range<u64>> {
    let start = to_original(range.start, offset)?;
    // The upper bound is exclusive, not a SequenceNumber_t field.
    let end = range
        .end
        .checked_add(offset)
        .filter(|end| *end <= (i64::MAX as u64) + 1)?;
    Some(start..end)
}

fn address_native(packet: &[u8], reader: GUID) -> Vec<u8> {
    let mut addressed = packet.get(..20).unwrap_or(packet).to_vec();
    addressed.extend_from_slice(&[0x0e, 1, 12, 0]);
    addressed.extend_from_slice(&reader.prefix);
    addressed.extend_from_slice(packet.get(20..).unwrap_or_default());
    addressed
}

fn read_u16(bytes: &[u8], at: usize, le: bool) -> Option<u16> {
    let b = bytes.get(at..at.checked_add(2)?)?.try_into().ok()?;
    Some(if le {
        u16::from_le_bytes(b)
    } else {
        u16::from_be_bytes(b)
    })
}

fn read_u32(bytes: &[u8], at: usize, le: bool) -> Option<u32> {
    let b = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    })
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32, le: bool) {
    bytes[at..at + 4].copy_from_slice(&if le {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    });
}

fn sn(bytes: &[u8], at: usize, le: bool) -> Option<u64> {
    let high = read_u32(bytes, at, le)?;
    if high > 0x7fff_ffff {
        return None;
    }
    Some((u64::from(high) << 32) | u64::from(read_u32(bytes, at + 4, le)?))
}

fn put_sn(bytes: &mut [u8], at: usize, value: u64, le: bool) {
    let [hi0, hi1, hi2, hi3, lo0, lo1, lo2, lo3] = value.to_be_bytes();
    put_u32(bytes, at, u32::from_be_bytes([hi0, hi1, hi2, hi3]), le);
    put_u32(bytes, at + 4, u32::from_be_bytes([lo0, lo1, lo2, lo3]), le);
}

/// Locate inline coherent parameters using octetsToInlineQos, for both
/// DATA and DATA_FRAG (RTPS 2.5 Sec.9.4.5.3, Sec.9.4.5.4).
fn coherent_positions(body: &[u8], flags: u8) -> Option<Vec<usize>> {
    if flags & 2 == 0 {
        return Some(Vec::new());
    }
    let le = flags & 1 != 0;
    let mut at = 4 + usize::from(read_u16(body, 2, le)?);
    let mut positions = Vec::new();
    loop {
        let pid = read_u16(body, at, le)?;
        let len = usize::from(read_u16(body, at + 2, le)?);
        at += 4;
        if pid == 1 {
            return Some(positions);
        }
        body.get(at..at.checked_add(len)?)?;
        if pid == 0x0056 {
            if len != 8 {
                return None;
            }
            positions.push(at);
        }
        at += (len + 3) & !3;
    }
}

fn translate(packet: &[u8], window: &mut Window, reader: [u8; 16]) -> Option<Vec<u8>> {
    if packet.get(..4)? != b"RTPS" {
        return None;
    }
    let mut output = packet.get(..20)?.to_vec();
    // Scope even a shared locator to the intended participant.
    output.extend_from_slice(&[0x0e, 1, 12, 0]);
    output.extend_from_slice(&reader[..12]);
    let mut at = 20;
    let mut emitted = false;
    while at < packet.len() {
        let header = packet.get(at..at + 4)?;
        let kind = header[0];
        let flags = header[1];
        let le = flags & 1 != 0;
        let size = usize::from(read_u16(header, 2, le)?);
        let end = if size == 0 {
            packet.len()
        } else {
            at.checked_add(4 + size)?
        };
        let mut body = packet.get(at + 4..end)?.to_vec();
        let mut keep = true;
        match kind {
            0x0c => {
                if body.get(8..20)? != packet.get(8..20)? {
                    return None;
                }
            }
            0x0e => {
                if body.as_slice() != &reader[..12] {
                    return None;
                }
            }
            0x15 | 0x16 => {
                body.get_mut(4..8)?.copy_from_slice(&reader[12..]);
                let raw = sn(&body, 12, le)?;
                let positions = coherent_positions(&body, flags)?;
                if !window.ready {
                    let first = positions.first().and_then(|&p| sn(&body, p, le));
                    if let Some(first) = first.filter(|first| *first > window.lower) {
                        window.lower = first - 1;
                        if !window.fixed_origin {
                            window.floor = window.lower;
                        }
                        window.ready = true;
                    } else if positions.is_empty()
                        && raw > window.lower
                        && ((kind == 0x15 && flags & 0x0c != 0)
                            || (kind == 0x16 && read_u32(&body, 20, le)? == 1))
                    {
                        // An ordinary change outside begin/end is its own
                        // complete part; an untagged bare DATA is a close.
                        // Keep independent post-match changes owed at their original offset.
                        window.ready = true;
                    } else {
                        keep = false;
                    }
                }
                if raw <= window.lower {
                    keep = false;
                }
                if !window.ready {
                    // Empty-window ACKs retire the discarded partial part.
                    // Otherwise a full history could block the first change
                    // of the next complete set before it opens the window.
                    window.lower = window.lower.max(raw);
                    if !window.fixed_origin {
                        window.floor = window.lower;
                    }
                }
                if keep {
                    put_sn(&mut body, 12, raw - window.floor, le);
                    for pos in positions {
                        let raw = sn(&body, pos, le)?;
                        let value = raw.checked_sub(window.floor)?;
                        if value == 0 {
                            return None;
                        }
                        put_sn(&mut body, pos, value, le);
                    }
                }
            }
            0x07 => {
                body.get_mut(..4)?.copy_from_slice(&reader[12..]);
                let first = sn(&body, 8, le)?;
                let last = sn(&body, 16, le)?;
                if !window.ready {
                    let first = window.lower - window.floor + 1;
                    put_sn(&mut body, 8, first, le);
                    put_sn(&mut body, 16, first - 1, le);
                } else {
                    put_sn(
                        &mut body,
                        8,
                        first
                            .max(window.lower + 1)
                            .saturating_sub(window.floor)
                            .max(1),
                        le,
                    );
                    put_sn(&mut body, 16, last.saturating_sub(window.floor), le);
                }
            }
            0x13 => {
                body.get_mut(..4)?.copy_from_slice(&reader[12..]);
                let raw = sn(&body, 8, le)?;
                keep = window.ready && raw > window.lower;
                if keep {
                    put_sn(&mut body, 8, raw - window.floor, le);
                }
            }
            0x08 => {
                body.get_mut(..4)?.copy_from_slice(&reader[12..]);
                keep = window.ready;
                if keep {
                    translate_gap(&mut body, window.floor, le)?;
                }
            }
            _ => (),
        }
        if keep {
            emitted |= matches!(kind, 0x15 | 0x16 | 0x07 | 0x13 | 0x08);
            output.extend_from_slice(&[kind, flags]);
            let len = u16::try_from(body.len()).ok()?;
            output.extend_from_slice(&if le {
                len.to_le_bytes()
            } else {
                len.to_be_bytes()
            });
            output.extend_from_slice(&body);
        }
        at = end;
    }
    emitted.then_some(output)
}

fn translate_gap(body: &mut Vec<u8>, floor: u64, le: bool) -> Option<()> {
    let start = sn(body, 8, le)?;
    let base = sn(body, 16, le)?;
    let bits = read_u32(body, 24, le)?;
    if bits > 256 {
        return None;
    }
    let words = bits.div_ceil(32) as usize;
    body.get(..28 + words * 4)?;
    // The minimum is at most `bits`, so the conversion always succeeds.
    let clamped = floor
        .saturating_add(1)
        .saturating_sub(base)
        .min(u64::from(bits));
    debug_assert!(
        u32::try_from(clamped).is_ok(),
        "the GAP skip is clamped to the bitmap width"
    );
    let skip = u32::try_from(clamped).unwrap_or_else(|_| {
        log::error!("GAP skip saturated to the bitmap width");
        bits
    });
    let new_bits = bits - skip;
    let mut bitmap = vec![0u32; new_bits.div_ceil(32) as usize];
    for bit in skip..bits {
        if read_u32(body, 28 + (bit / 32) as usize * 4, le)? & (1 << (31 - bit % 32)) != 0 {
            let new_bit = bit - skip;
            bitmap[(new_bit / 32) as usize] |= 1 << (31 - new_bit % 32);
        }
    }
    let tail = body[28 + words * 4..].to_vec();
    body.truncate(28);
    put_sn(body, 8, start.saturating_sub(floor).max(1), le);
    put_sn(
        body,
        16,
        base.saturating_add(u64::from(skip))
            .saturating_sub(floor)
            .max(1),
        le,
    );
    put_u32(body, 24, new_bits, le);
    for word in bitmap {
        body.extend_from_slice(&if le {
            word.to_le_bytes()
        } else {
            word.to_be_bytes()
        });
    }
    body.extend_from_slice(&tail);
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixtures follow the RTPS 2.5 wire layouts, independently of HDDS builders.
    fn word(bytes: &mut Vec<u8>, v: u32, le: bool) {
        bytes.extend_from_slice(&if le { v.to_le_bytes() } else { v.to_be_bytes() });
    }
    fn sequence(bytes: &mut Vec<u8>, v: u64, le: bool) {
        word(bytes, (v >> 32) as u32, le);
        word(bytes, v as u32, le);
    }
    fn packet(kind: u8, flags: u8, body: &[u8]) -> Vec<u8> {
        let mut b = b"RTPS\x02\x05\x01\x23".to_vec();
        b.extend_from_slice(&[7; 12]);
        b.extend_from_slice(&[kind, flags]);
        let size = body.len() as u16;
        b.extend_from_slice(&if flags & 1 != 0 {
            size.to_le_bytes()
        } else {
            size.to_be_bytes()
        });
        b.extend_from_slice(body);
        b
    }
    fn data(kind: u8, value: u64, coherent: Option<u64>, le: bool) -> Vec<u8> {
        let mut b = vec![0, 0];
        let offset = if kind == 0x16 { 28u16 } else { 16u16 };
        b.extend_from_slice(&if le {
            offset.to_le_bytes()
        } else {
            offset.to_be_bytes()
        });
        b.extend_from_slice(&[0, 0, 2, 7, 0, 0, 1, 2]);
        sequence(&mut b, value, le);
        if kind == 0x16 {
            word(&mut b, 1, le); // fragmentStartingNum
            b.extend_from_slice(&if le { [1, 0, 0, 4] } else { [0, 1, 4, 0] });
            word(&mut b, 1024, le);
        }
        if let Some(coherent) = coherent {
            b.extend_from_slice(&if le { [0x56, 0, 8, 0] } else { [0, 0x56, 0, 8] });
            sequence(&mut b, coherent, le);
            b.extend_from_slice(&if le {
                [0x30, 0x80, 8, 0]
            } else {
                [0x80, 0x30, 0, 8]
            });
            sequence(&mut b, 57, le); // private Publisher identity stays raw
            b.extend_from_slice(&if le { [1, 0, 0, 0] } else { [0, 1, 0, 0] });
        }
        b.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        packet(
            kind,
            u8::from(le) | if coherent.is_some() { 2 } else { 0 },
            &b,
        )
    }
    fn value(bytes: &[u8], at: usize, le: bool) -> u64 {
        let high: [u8; 4] = bytes[at..at + 4].try_into().unwrap();
        let low: [u8; 4] = bytes[at + 4..at + 8].try_into().unwrap();
        let (high, low) = if le {
            (u32::from_le_bytes(high), u32::from_le_bytes(low))
        } else {
            (u32::from_be_bytes(high), u32::from_be_bytes(low))
        };
        (u64::from(high) << 32) | u64::from(low)
    }
    fn window(floor: u64, ready: bool) -> Window {
        Window {
            floor,
            lower: floor,
            generation: 0,
            fixed_origin: false,
            ready,
            endpoint: None,
        }
    }

    #[test]
    fn data_close_repair_and_fragments_share_the_same_origin() {
        for le in [false, true] {
            let floor = (1u64 << 32) + 17;
            for kind in [0x15, 0x16] {
                let raw = data(kind, floor + 3, Some(floor + 1), le);
                let changed = translate(&raw, &mut window(floor, true), [4; 16]).unwrap();
                assert_eq!(
                    &changed[20..36],
                    &[0x0e, 1, 12, 0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4]
                );
                assert_eq!(value(&changed, 36 + 4 + 12, le), 3);
                let qos = 36 + 4 + if kind == 0x16 { 32 } else { 20 };
                assert_eq!(value(&changed, qos + 4, le), 1);
                assert_eq!(value(&changed, qos + 16, le), 57);
                assert_eq!(&changed[changed.len() - 4..], &[0xaa, 0xbb, 0xcc, 0xdd]);
                // A repair made from the same journaled bytes has the same wire form.
                assert_eq!(
                    translate(&raw, &mut window(floor, true), [4; 16]).unwrap(),
                    changed
                );
            }
            let close = translate(
                &data(0x15, floor + 4, None, le),
                &mut window(floor, true),
                [4; 16],
            )
            .unwrap();
            assert_eq!(value(&close, 52, le), 4);
            assert!(translate(
                &data(0x15, floor, None, le),
                &mut window(floor, true),
                [4; 16]
            )
            .is_none());
        }
    }

    #[test]
    fn heartbeat_ranges_and_fragment_controls_use_writer_sns_only() {
        for le in [false, true] {
            let mut b = vec![0, 0, 2, 7, 0, 0, 1, 2];
            sequence(&mut b, 80, le);
            sequence(&mut b, 104, le);
            word(&mut b, 92, le);
            let p = packet(7, u8::from(le), &b);
            let t = translate(&p, &mut window(100, true), [4; 16]).unwrap();
            assert_eq!(value(&t, 48, le), 1);
            assert_eq!(value(&t, 56, le), 4);
            assert_eq!(&t[64..68], &p[48..52], "count is not an SN");
            let empty = translate(&p, &mut window(100, false), [4; 16]).unwrap();
            assert_eq!(value(&empty, 48, le), 1);
            assert_eq!(value(&empty, 56, le), 0);
            let mut b = vec![0, 0, 2, 7, 0, 0, 1, 2];
            sequence(&mut b, 104, le);
            word(&mut b, 500, le); // lastFragmentNum, not a writer SN
            word(&mut b, 92, le);
            let p = packet(0x13, u8::from(le), &b);
            let t = translate(&p, &mut window(100, true), [4; 16]).unwrap();
            assert_eq!(value(&t, 48, le), 4);
            assert_eq!(&t[56..], &p[40..]);
        }
    }

    #[test]
    fn gap_clips_the_prefix_and_shifts_the_sequence_bitmap() {
        for le in [false, true] {
            let mut b = vec![0, 0, 2, 7, 0, 0, 1, 2];
            sequence(&mut b, 1, le);
            sequence(&mut b, 98, le);
            word(&mut b, 8, le);
            word(&mut b, 0b1010_1010 << 24, le); // 98,100,102,104
            sequence(&mut b, 9, le); // filteredCount is not an SN
            let t = translate(
                &packet(8, u8::from(le) | 4, &b),
                &mut window(100, true),
                [4; 16],
            )
            .unwrap();
            assert_eq!(value(&t, 48, le), 1);
            assert_eq!(value(&t, 56, le), 1);
            assert_eq!(value(&t, 64, le), (5u64 << 32) | (0b01010 << 27));
            assert_eq!(value(&t, 72, le), 9);
        }
    }

    #[test]
    fn a_late_sibling_starts_at_its_next_complete_part_without_resetting_any_peer() {
        let mut first = window(20, false);
        // Match in a writer part whose first sample was 19: no partial set.
        assert!(translate(&data(0x15, 21, Some(19), true), &mut first, [4; 16]).is_none());
        assert!(translate(&data(0x15, 22, None, true), &mut first, [4; 16]).is_none());
        let first_data = translate(&data(0x15, 23, Some(23), true), &mut first, [4; 16]).unwrap();
        assert_eq!(value(&first_data, 52, true), 1);
        let fresh = translate(
            &data(0x15, 23, Some(23), true),
            &mut window(20, false),
            [4; 16],
        )
        .unwrap();
        assert_eq!(
            value(&fresh, 52, true),
            1,
            "unobserved partial prefix is skipped too"
        );
        let mut sibling = window(90, false);
        let sibling_data =
            translate(&data(0x15, 94, Some(94), true), &mut sibling, [4; 16]).unwrap();
        assert_eq!(value(&sibling_data, 52, true), 1);
        assert_eq!(value(&sibling_data, 64, true), 1);
        assert_eq!(
            value(&sibling_data, 76, true),
            57,
            "Publisher identity is not reset"
        );
        let later = translate(&data(0x15, 24, Some(23), true), &mut first, [4; 16]).unwrap();
        assert_eq!(value(&later, 52, true), 2);
        assert_eq!(first.floor, 22);
        assert_eq!(sibling.floor, 93);
    }

    #[test]
    fn acknowledgements_invert_each_readers_window_and_rematch_releases_it() {
        let windows = WriterWindows::default();
        let a = GUID::new([4; 12], [0, 0, 2, 7]);
        let b = GUID::new([5; 12], [0, 0, 2, 7]);
        windows.pair(a, None, 100, false);
        windows.pair(b, None, 400, false);
        // ACKNACK bitmapBase and NACK_FRAG writerSN use this same inverse;
        // fragment numbers and bitmap bits remain unchanged.
        assert_eq!(windows.inverse(Some(a.as_bytes()), 9), Some(109));
        assert_eq!(windows.inverse(Some(b.as_bytes()), 9), Some(409));
        assert_eq!(
            windows.inverse(Some(GUID::new([9; 12], a.entity_id).as_bytes()), 9),
            Some(9)
        );
        assert_eq!(windows.inverse(Some(a.as_bytes()), i64::MAX as u64), None);
        windows.pair(a, None, 999, false);
        assert_eq!(
            windows.inverse(Some(a.as_bytes()), 9),
            Some(109),
            "duplicate pairing is idempotent"
        );
        windows.unpair(a);
        windows.pair(a, None, 800, false);
        assert_eq!(
            windows.inverse(Some(a.as_bytes()), 9),
            Some(109),
            "the same GUID cannot reuse its wire sequence space"
        );
        windows.unpair(a);
        windows.unpair(b);
        assert!(!windows.present.load(Ordering::Acquire));
    }

    #[test]
    fn retired_origins_expire_only_after_a_full_control_quiet_period() {
        use crate::dds::liveliness::ManualClock;
        use std::time::Duration;
        let clock = Arc::new(ManualClock::new(0));
        let windows = WriterWindows::default();
        assert!(windows.retirement_clock.set(clock.clone()).is_ok());
        let reader = GUID::new([4; 12], [0, 0, 2, 7]);
        windows.pair(reader, None, 10, false);
        windows.unpair(reader);
        clock.advance(Duration::from_secs(119));
        // Delayed control from the removed proxy extends the quiet period.
        assert!(windows
            .inbound_window(Some(reader.as_bytes()), true)
            .is_none());
        clock.advance(Duration::from_secs(2));
        windows.pair(reader, None, 50, false);
        assert_eq!(
            windows.inbound_offset(Some(reader.as_bytes()), true),
            Some(10)
        );
        windows.unpair(reader);
        // Distinct-GUID churn cannot retain every departed reader forever.
        for byte in 5..105 {
            let peer = GUID::new([byte; 12], reader.entity_id);
            windows.pair(peer, None, 50, false);
            windows.unpair(peer);
        }
        assert_eq!(windows.retired_origins.lock().unwrap().len(), 101);
        clock.advance(Duration::from_secs(120));
        windows.pair(reader, None, 90, false);
        assert_eq!(
            windows.inbound_offset(Some(reader.as_bytes()), true),
            Some(90)
        );
        assert!(windows.retired_origins.lock().unwrap().is_empty());
        assert!(!windows.retired_present.load(Ordering::Acquire));
    }

    #[test]
    fn pairing_generation_exhaustion_never_becomes_native_zero() {
        let windows = WriterWindows::default();
        windows.generation.store(u64::MAX - 1, Ordering::Relaxed);
        let reader = GUID::new([4; 12], [0, 0, 2, 7]);
        windows.pair(reader, None, 10, false);
        let last = windows
            .inbound_window(Some(reader.as_bytes()), true)
            .unwrap();
        assert!(last.is_classic());
        assert_eq!(last.generation, u64::MAX);
        let other = GUID::new([5; 12], reader.entity_id);
        // Exhausted: debug builds assert the invariant; release builds refuse
        // the pairing. Either way nothing is inserted.
        let asserted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            windows.pair(other, None, 10, false);
        }))
        .is_err();
        assert_eq!(asserted, cfg!(debug_assertions));
        assert!(!windows.contains(other));
        assert!(windows.apply_if_current(last, || {}));
    }

    #[test]
    fn only_the_selected_classic_vendors_require_a_window() {
        use crate::protocol::group::GroupDialect;
        for vendor in [
            None,
            Some(0x0123),
            Some(0x0105),
            Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
        ] {
            assert!(!GroupDialect::needs_sequence_window(vendor));
        }
        for vendor in [0x0101, 0x010a] {
            assert!(GroupDialect::needs_sequence_window(Some(vendor)));
        }
    }

    #[test]
    fn unknown_then_native_discovery_keeps_every_native_packet_byte_identical() {
        use crate::core::discovery::multicast::DiscoveryFsm;
        let domain = crate::test_support::domains::unique_domain();
        let transport = UdpTransport::new(
            domain.id(),
            0,
            crate::transport::PortMapping::calculate(domain.id(), 0).unwrap(),
        )
        .unwrap();
        let socket = crate::test_support::ports::bind_capture_socket();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let endpoint = socket.local_addr().unwrap();
        let fsm = DiscoveryFsm::new(GUID::new([7; 12], [0, 0, 1, 0xc1]), 100_000);
        let windows = WriterWindows::default();
        windows.configure(true);
        let native = GUID::new([6; 12], [0, 0, 2, 7]);
        let raw = data(0x15, 105, Some(101), true);
        let fragment_heartbeat = crate::protocol::builder::build_heartbeat_frag_packet(
            [7; 12],
            native.prefix,
            native.entity_id,
            [0, 0, 1, 3],
            105,
            4,
            1,
        );
        for vendor_id in [None, Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16)] {
            fsm.handle_spdp(crate::protocol::discovery::SpdpData {
                participant_guid: GUID::new(native.prefix, [0, 0, 1, 0xc1]),
                lease_duration_ms: 100_000,
                domain_id: domain.id(),
                metatraffic_unicast_locators: vec![],
                default_unicast_locators: vec![],
                default_multicast_locators: vec![],
                metatraffic_multicast_locators: vec![],
                identity_token: None,
                permissions_token: None,
                participant_security_info: None,
                vendor_id,
                hdds_capabilities: None,
                builtin_endpoint_set: None,
            });
            assert!(!fsm.requires_group_window(&native.prefix));
            for packet in [&raw, &fragment_heartbeat] {
                for classed in [false, true] {
                    if classed {
                        windows
                            .send_classed(
                                &transport,
                                packet,
                                &endpoint,
                                native,
                                fsm.requires_group_window(&native.prefix),
                            )
                            .unwrap();
                    } else {
                        windows
                            .send(&transport, packet, &endpoint, Some(native))
                            .unwrap();
                    }
                    let mut received = [0; 2048];
                    let n = socket.recv(&mut received).unwrap();
                    assert_eq!(&received[..n], packet, "native discovery must add no bytes");
                }
            }
        }
        // A classic reader at another locator or on another writer changes nothing.
        let other = crate::test_support::ports::bind_capture_socket();
        let classic = GUID::new([4; 12], native.entity_id);
        windows.pair(classic, Some(other.local_addr().unwrap()), 100, false);
        windows
            .send_classed(&transport, &raw, &endpoint, native, false)
            .unwrap();
        let mut received = [0; 2048];
        let n = socket.recv(&mut received).unwrap();
        assert_eq!(&received[..n], raw);
        windows.unpair(classic);
        windows.pair(classic, Some(endpoint), 100, false);
        windows
            .send_classed(&transport, &fragment_heartbeat, &endpoint, native, false)
            .unwrap();
        let n = socket.recv(&mut received).unwrap();
        assert_eq!(
            &received[..n],
            fragment_heartbeat,
            "no duplicate INFO_DST in a mixed audience"
        );
        windows.unpair(classic);
        windows
            .send_classed(&transport, &raw, &endpoint, native, false)
            .unwrap();
        let n = socket.recv(&mut received).unwrap();
        assert_eq!(
            &received[..n],
            raw,
            "isolation ends with the shared classic pairing"
        );
    }

    #[test]
    fn native_bytes_are_unchanged_and_shared_locators_do_not_alias_classic_readers() {
        let domain = crate::test_support::domains::unique_domain();
        let mapping = crate::transport::PortMapping::calculate(domain.id(), 0).unwrap();
        let transport = UdpTransport::new(domain.id(), 0, mapping).unwrap();
        let socket = crate::test_support::ports::bind_capture_socket();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let addr = socket.local_addr().unwrap();
        let a = GUID::new([4; 12], [0, 0, 2, 7]);
        let b = GUID::new([5; 12], a.entity_id);
        let native = GUID::new([6; 12], a.entity_id);
        let windows = WriterWindows::default();
        let raw = data(0x15, 205, Some(201), true);
        let mut received = [0u8; 2048];
        windows
            .send_classed(&transport, &raw, &addr, native, false)
            .unwrap();
        let n = socket.recv(&mut received).unwrap();
        assert_eq!(&received[..n], raw, "no classic peers adds no bytes");
        windows.pair(a, Some(addr), 100, false);
        windows.pair(b, Some(addr), 200, false);
        windows.send(&transport, &raw, &addr, Some(native)).unwrap();
        let n = socket.recv(&mut received).unwrap();
        assert_eq!(&received[24..36], &native.prefix);
        assert_eq!(&received[36..n], &raw[20..]);
        for (reader, expected) in [(a, 105), (b, 5)] {
            windows.send(&transport, &raw, &addr, Some(reader)).unwrap();
            let n = socket.recv(&mut received).unwrap();
            assert_eq!(&received[24..36], &reader.prefix);
            assert_eq!(value(&received[..n], 52, true), expected);
            assert_eq!(&received[44..48], &reader.entity_id);
        }
    }

    #[test]
    fn a_plain_change_after_pairing_does_not_wait_for_a_coherent_set() {
        let mut p = data(0x15, 104, None, true);
        p[21] |= 4; // DATA with a serialized payload, outside begin/end.
        let t = translate(&p, &mut window(100, false), [4; 16]).unwrap();
        assert_eq!(value(&t, 52, true), 4);
    }

    #[test]
    fn a_classic_route_is_refused_before_pairing_and_after_departure() {
        let domain = crate::test_support::domains::unique_domain();
        let transport = UdpTransport::new(
            domain.id(),
            0,
            crate::transport::PortMapping::calculate(domain.id(), 0).unwrap(),
        )
        .unwrap();
        let socket = crate::test_support::ports::bind_capture_socket();
        let addr = socket.local_addr().unwrap();
        let reader = GUID::new([4; 12], [0, 0, 2, 7]);
        let windows = WriterWindows::default();
        let p = data(0x15, 104, Some(101), true);
        assert_eq!(
            windows
                .send_classed(&transport, &p, &addr, reader, true)
                .unwrap(),
            0
        );
        windows.pair(reader, Some(addr), 100, false);
        windows.unpair(reader);
        assert_eq!(
            windows
                .send_classed(&transport, &p, &addr, reader, true)
                .unwrap(),
            0
        );
    }

    #[test]
    fn native_multicast_has_a_destination_but_no_sequence_translation() {
        let reader = GUID::new([4; 12], [0, 0, 2, 7]);
        let raw = data(0x15, 104, Some(101), true);
        let scoped = address_native(&raw, reader);
        assert_eq!(&scoped[24..36], &reader.prefix);
        assert_eq!(&scoped[36..], &raw[20..]);
        let domain = crate::test_support::domains::unique_domain();
        let transport = UdpTransport::new(
            domain.id(),
            0,
            crate::transport::PortMapping::calculate(domain.id(), 0).unwrap(),
        )
        .unwrap();
        let windows = WriterWindows::default();
        windows.configure(true);
        windows.pair(reader, None, 100, false);
        let multicast = "239.255.0.1:62651".parse().unwrap();
        assert_eq!(
            windows
                .send_classed(&transport, &raw, &multicast, reader, true)
                .unwrap(),
            0
        );
    }

    #[test]
    fn unretained_changes_keep_a_completed_match_watermark() {
        let windows = WriterWindows::default();
        windows.configure(true);
        windows.record_unretained(8);
        windows.record_unretained(7);
        assert_eq!(windows.highest_unretained(), 8);
    }

    #[test]
    fn an_empty_window_ack_retires_each_skipped_partial_member() {
        let domain = crate::test_support::domains::unique_domain();
        let transport = UdpTransport::new(
            domain.id(),
            0,
            crate::transport::PortMapping::calculate(domain.id(), 0).unwrap(),
        )
        .unwrap();
        let socket = crate::test_support::ports::bind_capture_socket();
        let addr = socket.local_addr().unwrap();
        let reader = GUID::new([4; 12], [0, 0, 2, 7]);
        let windows = WriterWindows::default();
        windows.pair(reader, Some(addr), 20, true);
        let partial = data(0x15, 21, Some(19), true);
        assert_eq!(
            windows
                .send_classed(&transport, &partial, &addr, reader, true)
                .unwrap(),
            0
        );
        assert_eq!(windows.inverse(Some(reader.as_bytes()), 1), Some(22));
        let close = data(0x15, 22, None, true);
        assert_eq!(
            windows
                .send_classed(&transport, &close, &addr, reader, true)
                .unwrap(),
            0
        );
        assert_eq!(windows.inverse(Some(reader.as_bytes()), 1), Some(23));
    }

    #[test]
    fn one_ack_uses_one_origin_and_unpaired_classic_control_is_refused() {
        let domain = crate::test_support::domains::unique_domain();
        let transport = UdpTransport::new(
            domain.id(),
            0,
            crate::transport::PortMapping::calculate(domain.id(), 0).unwrap(),
        )
        .unwrap();
        let socket = crate::test_support::ports::bind_capture_socket();
        let reader = GUID::new([4; 12], [0, 0, 2, 7]);
        let windows = WriterWindows::default();
        assert_eq!(windows.inbound_offset(Some(reader.as_bytes()), true), None);
        windows.pair(reader, None, 20, true);
        let offset = windows
            .inbound_offset(Some(reader.as_bytes()), true)
            .unwrap();
        let partial = data(0x15, 21, Some(19), true);
        windows
            .send_classed(
                &transport,
                &partial,
                &socket.local_addr().unwrap(),
                reader,
                true,
            )
            .unwrap();
        assert_eq!(
            windows.inbound_offset(Some(reader.as_bytes()), true),
            Some(21)
        );
        assert_eq!(to_original(1, offset), Some(21));
        assert_eq!(
            to_original(3, offset),
            Some(23),
            "bitmap ranges use the same snapshot as base"
        );
        windows.unpair(reader);
        assert_eq!(windows.inbound_offset(Some(reader.as_bytes()), true), None);
    }

    #[test]
    fn a_bitmap_can_request_the_largest_valid_sequence_number() {
        let max = i64::MAX as u64;
        assert_eq!(range_to_original(100..101, max - 100), Some(max..max + 1));
        assert_eq!(range_to_original(100..102, max - 100), None);
        assert_eq!(to_original(101, max - 100), None);
    }

    #[test]
    fn a_control_snapshot_cannot_mutate_a_replacement_pairing() {
        let windows = WriterWindows::default();
        let reader = GUID::new([4; 12], [0, 0, 2, 7]);
        windows.pair(reader, None, 100, false);
        let previous = windows
            .inbound_window(Some(reader.as_bytes()), true)
            .unwrap();
        windows.unpair(reader);
        windows.pair(reader, None, 100, false);
        let mut applied = false;
        assert!(!windows.apply_if_current(previous, || applied = true));
        assert!(
            !applied,
            "same origin and bounds do not make the old generation current"
        );
        let current = windows
            .inbound_window(Some(reader.as_bytes()), true)
            .unwrap();
        assert!(windows.apply_if_current(current, || applied = true));
        assert!(applied);
    }

    #[test]
    fn a_rematched_coherent_reader_keeps_its_origin_and_skips_a_partial_part() {
        let domain = crate::test_support::domains::unique_domain();
        let transport = UdpTransport::new(
            domain.id(),
            0,
            crate::transport::PortMapping::calculate(domain.id(), 0).unwrap(),
        )
        .unwrap();
        let socket = crate::test_support::ports::bind_capture_socket();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let endpoint = socket.local_addr().unwrap();
        let reader = GUID::new([4; 12], [0, 0, 2, 7]);
        let windows = WriterWindows::default();
        windows.pair(reader, Some(endpoint), 20, false);
        windows.unpair(reader);
        windows.pair(reader, Some(endpoint), 100, true);
        assert_eq!(
            windows
                .send_classed(
                    &transport,
                    &data(0x15, 101, Some(99), true),
                    &endpoint,
                    reader,
                    true
                )
                .unwrap(),
            0
        );
        windows
            .send_classed(
                &transport,
                &data(0x15, 102, Some(102), true),
                &endpoint,
                reader,
                true,
            )
            .unwrap();
        let mut buf = [0; 2048];
        let n = socket.recv(&mut buf).unwrap();
        assert_eq!(
            value(&buf[..n], 52, true),
            82,
            "wire identity remains original minus 20"
        );
        assert_eq!(windows.inverse(Some(reader.as_bytes()), 82), Some(102));
        assert_eq!(
            windows
                .inbound_window(Some(reader.as_bytes()), true)
                .unwrap()
                .first,
            102
        );
    }

    #[test]
    fn historical_markerless_data_and_fragment_numbers_keep_their_origin() {
        for le in [false, true] {
            let mut p = data(0x15, 40, None, le);
            p[21] |= 4;
            let t = translate(&p, &mut window(0, true), [4; 16]).unwrap();
            assert_eq!(value(&t, 52, le), 40);
            assert_eq!(
                &t[60..],
                &p[44..],
                "historical markerless body remains markerless"
            );
        }
    }

    #[test]
    fn truncated_wire_input_is_refused_without_panicking() {
        let p = data(0x16, 104, Some(101), true);
        for len in 0..p.len() {
            assert!(translate(&p[..len], &mut window(100, true), [4; 16]).is_none());
        }
    }
    #[test]
    fn independent_native_unicast_does_not_enter_a_classic_window_at_a_shared_locator() {
        use crate::core::discovery::multicast::classifier::walk::{destined_to, Destined};
        let domain = crate::test_support::domains::unique_domain();
        let transport = UdpTransport::new(
            domain.id(),
            0,
            crate::transport::PortMapping::calculate(domain.id(), 0).unwrap(),
        )
        .unwrap();
        let socket = crate::test_support::ports::bind_capture_socket();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let endpoint = socket.local_addr().unwrap();
        // EntityIds are only unique inside a participant. A shared relay or
        // receive socket may serve both participants at this same address.
        let classic = GUID::new([4; 12], [0, 0, 2, 7]);
        let native = GUID::new([6; 12], classic.entity_id);
        let windows = WriterWindows::default();
        windows.configure(true);
        windows.pair(classic, Some(endpoint), 100, false);
        let raw = data(0x15, 105, Some(101), true);
        let mut received = [0u8; 2048];
        windows
            .send_classed(&transport, &raw, &endpoint, classic, true)
            .unwrap();
        let n = socket.recv(&mut received).unwrap();
        assert!(matches!(
            destined_to(&received[..n], &native.prefix),
            Destined::Nothing
        ));
        windows
            .send_classed(&transport, &raw, &endpoint, native, false)
            .unwrap();
        let n = socket.recv(&mut received).unwrap();
        assert!(matches!(
            destined_to(&received[..n], &native.prefix),
            Destined::Whole
        ));
        assert!(
            matches!(
                destined_to(&received[..n], &classic.prefix),
                Destined::Nothing
            ),
            "native SN 105 is accepted at the classic participant, whose own wire SN is 5"
        );
        // INFO_DST scopes every submessage in a packet, including reliability
        // controls whose reader EntityIds can collide at the same locator.
        for kind in [0x07, 0x08, 0x13] {
            let mut body = native.entity_id.to_vec();
            body.extend_from_slice(&[0, 0, 1, 2]);
            sequence(&mut body, 105, true);
            if kind == 0x13 {
                word(&mut body, 3, true); // lastFragmentNum
                word(&mut body, 1, true); // count
            } else {
                sequence(&mut body, 106, true); // lastSN or gapList.bitmapBase
                word(&mut body, u32::from(kind == 0x07), true); // count or numBits
            }
            let raw = packet(kind, 1, &body);
            for classed in [true, false] {
                if classed {
                    windows
                        .send_classed(&transport, &raw, &endpoint, native, false)
                        .unwrap();
                } else {
                    windows
                        .send(&transport, &raw, &endpoint, Some(native))
                        .unwrap();
                }
                let n = socket.recv(&mut received).unwrap();
                assert!(matches!(
                    destined_to(&received[..n], &classic.prefix),
                    Destined::Nothing
                ));
                assert!(matches!(
                    destined_to(&received[..n], &native.prefix),
                    Destined::Whole
                ));
                assert_eq!(&received[36..n], &raw[20..], "native SNs stay unchanged");
            }
        }
    }
}
