// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! ARP cache + active-resolution state machine for `Sel4Ring`.
//!
//! Pure-data, `no_std`, no `unsafe`. The cache is a fixed-size linear-scan
//! table of [`ARP_CACHE_CAPACITY`] slots; for a single-peer
//! workload that is plenty and avoids the `heapless` dependency. A full
//! cache returns an "insert rejected" counter to the caller (no LRU
//! eviction - silent LRU could break ongoing flows).
//!
//! Design rules (see also RFC 826):
//! - The cache learns only from `(sha, spa)`. `tha`/`tpa` are never
//!   authoritative.
//! - A reply is emitted ONLY when `tpa == our_ip` (defense against
//!   gratuitous-ARP poisoning of sibling PDs).
//! - The caller sets `pending` to `Some(InFlight)` only after the ARP
//!   request is committed to `tx.active` (not modelled here - that is
//!   the caller's invariant; this module only exposes the state
//!   constructor [`start_resolution`]).
//! - `PendingArp` carries `dest_ip` so colliding callers can tell
//!   "still resolving you" from "resolving someone else".
//! - `Failed` is bounded by [`ARP_FAILED_BACKOFF_TICKS`]; after the
//!   cooldown the slot returns to `None` and the next `enqueue_tx` can
//!   re-issue from scratch.

#![allow(dead_code)]

use super::netstack::{Ipv4Addr, MacAddr, ParsedArp, ARP_OP_REQUEST};

/// Number of distinct IPs the cache holds. Reject-on-full above this.
pub const ARP_CACHE_CAPACITY: usize = 8;

/// Time the caller waits for an ARP reply before retrying. 1 s, RFC 826
/// suggested floor.
pub const ARP_REQUEST_DEADLINE_TICKS: u64 = 16;

/// Maximum retries before falling into `Failed`.
pub const ARP_RETRIES_MAX: u8 = 3;

/// Time spent in `Failed` before allowing a fresh resolution attempt.
pub const ARP_FAILED_BACKOFF_TICKS: u64 = 256;

/// One cache entry - MAC plus the timestamp at which we learned it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpEntry {
    /// Resolved hardware address.
    pub mac: MacAddr,
    /// Microsecond timestamp of the most recent learning event.
    pub learned_at: u64,
}

/// IPv4 -> MAC resolution cache, fixed capacity, linear scan.
#[derive(Debug, Clone)]
pub struct ArpCache {
    slots: [Option<(Ipv4Addr, ArpEntry)>; ARP_CACHE_CAPACITY],
    rejected_inserts: u32,
}

impl Default for ArpCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ArpCache {
    /// Build an empty cache.
    pub const fn new() -> Self {
        Self {
            slots: [None; ARP_CACHE_CAPACITY],
            rejected_inserts: 0,
        }
    }

    /// Resolve `ip`. Returns `None` if not cached.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        for (k, v) in self.slots.iter().flatten() {
            if *k == ip {
                return Some(v.mac);
            }
        }
        None
    }

    /// Insert or refresh a binding.
    ///
    /// Returns `true` if the binding was stored (new or refreshed),
    /// `false` if the cache was full and this was a fresh IP. The
    /// rejection counter is incremented in the failure case.
    pub fn learn(&mut self, ip: Ipv4Addr, mac: MacAddr, now: u64) -> bool {
        // Refresh existing entry.
        for (k, v) in self.slots.iter_mut().flatten() {
            if *k == ip {
                v.mac = mac;
                v.learned_at = now;
                return true;
            }
        }
        // Otherwise insert in the first empty slot.
        for slot in self.slots.iter_mut() {
            if slot.is_none() {
                *slot = Some((
                    ip,
                    ArpEntry {
                        mac,
                        learned_at: now,
                    },
                ));
                return true;
            }
        }
        // Full - reject + counter (no LRU).
        self.rejected_inserts = self.rejected_inserts.saturating_add(1);
        false
    }

    /// Total number of `learn` calls rejected because the cache was full.
    /// Pure observability - never resets.
    pub fn rejected_inserts(&self) -> u32 {
        self.rejected_inserts
    }

    /// Number of occupied slots.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// True if no entries are stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// State of a single in-flight or recently-failed ARP resolution.
///
/// At most one resolution is in flight at a time; `Sel4Ring` holds an
/// `Option<PendingArp>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingArp {
    /// An ARP request for `dest_ip` is on the wire (or about to be
    /// retried). `retries_left` is decremented each time the deadline
    /// elapses and we re-emit.
    InFlight {
        /// IP we are trying to resolve.
        dest_ip: Ipv4Addr,
        /// Remaining retry budget. 0 = the current request is the last.
        retries_left: u8,
        /// Microsecond timestamp at which the current request expires.
        deadline: u64,
    },
    /// All retries exhausted. The caller may attempt fresh resolution
    /// once `cooldown_until` has elapsed (after which `tick_pending`
    /// clears the slot).
    Failed {
        /// IP that failed to resolve.
        dest_ip: Ipv4Addr,
        /// Microsecond timestamp at which the backoff ends.
        cooldown_until: u64,
    },
}

impl PendingArp {
    /// Destination IP of the current state, regardless of variant.
    pub fn dest_ip(&self) -> Ipv4Addr {
        match self {
            PendingArp::InFlight { dest_ip, .. } => *dest_ip,
            PendingArp::Failed { dest_ip, .. } => *dest_ip,
        }
    }
}

/// What the caller should do with an inbound ARP frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpAction {
    /// Frame absorbed: cache updated, pending possibly cleared.
    None,
    /// Build and try to emit an ARP reply targeting `peer_mac`/`peer_ip`
    /// (the original requester). If `tx.free` is empty the caller drops
    /// the reply silently - the peer will retry.
    Reply {
        /// Hardware address of the requester (becomes Ethernet dst).
        peer_mac: MacAddr,
        /// Protocol address of the requester (becomes ARP `tpa` in the
        /// reply).
        peer_ip: Ipv4Addr,
    },
}

/// Process an inbound ARP frame.
///
/// Updates `cache` (learn from `sha`/`spa` only, never from `tha`/`tpa`)
/// and clears `pending` if it pointed to `frame.spa`. Returns the
/// action the caller should take on the wire.
///
/// Anti-loopback: if `frame.spa == our_ip`, we do NOT learn - that
/// would let a looped-back broadcast overwrite our own MAC in the
/// cache. (RFC 5227 conflict-detection territory is out of scope.)
///
/// Anti-sibling-poisoning: a request is only answered when
/// `frame.tpa == our_ip`. Without that gate the Rust PD would answer
/// requests targeting `client0` / `client1` IPs and claim our MAC.
pub fn handle_arp_frame(
    frame: &ParsedArp,
    our_ip: Ipv4Addr,
    cache: &mut ArpCache,
    pending: &mut Option<PendingArp>,
    now: u64,
) -> ArpAction {
    if frame.spa != our_ip {
        cache.learn(frame.spa, frame.sha, now);
        if let Some(p) = pending.as_ref() {
            if p.dest_ip() == frame.spa {
                *pending = None;
            }
        }
    }

    if frame.op == ARP_OP_REQUEST && frame.tpa == our_ip {
        ArpAction::Reply {
            peer_mac: frame.sha,
            peer_ip: frame.spa,
        }
    } else {
        ArpAction::None
    }
}

/// Decision returned by [`tick_pending`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingTick {
    /// `pending` left in a steady state; no wire action.
    Idle,
    /// Caller should re-emit an ARP request for `dest_ip`. The
    /// state in `pending` has already been advanced (retries_left
    /// decremented, deadline reset).
    Retry {
        /// IP to re-issue the request for.
        dest_ip: Ipv4Addr,
    },
}

/// Drive `pending` forward by one tick, using `now` (the caller's tick count).
///
/// Transitions:
/// - `InFlight` with `deadline > now`: no change. Returns `Idle`.
/// - `InFlight` with `deadline <= now` and `retries_left > 0`:
///   decrement retries, push the deadline by `ARP_REQUEST_DEADLINE_TICKS`,
///   return `Retry`. The caller emits the request bytes; the binding
///   stays in `InFlight`.
/// - `InFlight` with `deadline <= now` and `retries_left == 0`:
///   transition to `Failed { cooldown_until = now + ARP_FAILED_BACKOFF_TICKS }`.
///   Returns `Idle`.
/// - `Failed` with `cooldown_until <= now`: clear `pending` (the
///   slot becomes available for a fresh resolution). Returns `Idle`.
/// - `Failed` with `cooldown_until > now`: no change. Returns `Idle`.
pub fn tick_pending(pending: &mut Option<PendingArp>, now: u64) -> PendingTick {
    let Some(p) = pending.as_mut() else {
        return PendingTick::Idle;
    };
    match *p {
        PendingArp::InFlight {
            dest_ip,
            retries_left,
            deadline,
        } => {
            if now < deadline {
                return PendingTick::Idle;
            }
            if retries_left > 0 {
                *p = PendingArp::InFlight {
                    dest_ip,
                    retries_left: retries_left - 1,
                    deadline: now.saturating_add(ARP_REQUEST_DEADLINE_TICKS),
                };
                PendingTick::Retry { dest_ip }
            } else {
                *p = PendingArp::Failed {
                    dest_ip,
                    cooldown_until: now.saturating_add(ARP_FAILED_BACKOFF_TICKS),
                };
                PendingTick::Idle
            }
        }
        PendingArp::Failed {
            cooldown_until, ..
        } => {
            if now >= cooldown_until {
                *pending = None;
            }
            PendingTick::Idle
        }
    }
}

/// Build a fresh `InFlight` state after the caller successfully
/// committed an ARP request to `tx.active`. The caller passes its
/// current tick; the deadline is `now + ARP_REQUEST_DEADLINE_TICKS`.
/// Undo the retry that [`tick_pending`] just counted when the request
/// could not be sent (no free TX buffer). The same retry is due again at
/// the next tick, and the retry budget is unchanged. The caller arranges
/// the wake-up that makes that next tick happen.
pub fn defer_retry(pending: &mut Option<PendingArp>, now: u64) {
    if let Some(PendingArp::InFlight {
        retries_left,
        deadline,
        ..
    }) = pending.as_mut()
    {
        *retries_left = retries_left.saturating_add(1);
        *deadline = now;
    }
}

pub fn start_resolution(dest_ip: Ipv4Addr, now: u64) -> PendingArp {
    PendingArp::InFlight {
        dest_ip,
        retries_left: ARP_RETRIES_MAX,
        deadline: now.saturating_add(ARP_REQUEST_DEADLINE_TICKS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sel4_ring::netstack::{ARP_OP_REPLY, ARP_OP_REQUEST};

    const OUR_MAC: MacAddr = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const OUR_IP: Ipv4Addr = [10, 0, 2, 17];
    const PEER_MAC: MacAddr = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
    const PEER_IP: Ipv4Addr = [10, 0, 2, 2];
    const OTHER_IP: Ipv4Addr = [10, 0, 2, 3];

    fn arp_request_to(target_ip: Ipv4Addr) -> ParsedArp {
        ParsedArp {
            op: ARP_OP_REQUEST,
            sha: PEER_MAC,
            spa: PEER_IP,
            tha: [0; 6],
            tpa: target_ip,
        }
    }

    fn arp_reply_from(peer_mac: MacAddr, peer_ip: Ipv4Addr) -> ParsedArp {
        ParsedArp {
            op: ARP_OP_REPLY,
            sha: peer_mac,
            spa: peer_ip,
            tha: OUR_MAC,
            tpa: OUR_IP,
        }
    }

    #[test]
    fn empty_cache_lookup_returns_none() {
        let cache = ArpCache::new();
        assert_eq!(cache.lookup(PEER_IP), None);
        assert!(cache.is_empty());
    }

    #[test]
    fn learn_then_lookup_round_trip() {
        let mut cache = ArpCache::new();
        assert!(cache.learn(PEER_IP, PEER_MAC, 100));
        assert_eq!(cache.lookup(PEER_IP), Some(PEER_MAC));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn learn_refreshes_existing_entry_without_duplicating() {
        let mut cache = ArpCache::new();
        cache.learn(PEER_IP, PEER_MAC, 100);
        let new_mac: MacAddr = [1, 2, 3, 4, 5, 6];
        cache.learn(PEER_IP, new_mac, 200);
        assert_eq!(cache.lookup(PEER_IP), Some(new_mac));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn full_cache_rejects_new_ip_and_counts() {
        let mut cache = ArpCache::new();
        for i in 0..ARP_CACHE_CAPACITY as u8 {
            assert!(cache.learn([10, 0, 2, i], OUR_MAC, 100));
        }
        assert_eq!(cache.len(), ARP_CACHE_CAPACITY);
        assert!(!cache.learn([10, 0, 2, 99], OUR_MAC, 200));
        assert_eq!(cache.rejected_inserts(), 1);
        // Existing entries still refreshable even when full.
        assert!(cache.learn([10, 0, 2, 0], PEER_MAC, 300));
        assert_eq!(cache.rejected_inserts(), 1);
    }

    #[test]
    fn handle_request_for_us_returns_reply_and_learns_sender() {
        let mut cache = ArpCache::new();
        let mut pending = None;
        let frame = arp_request_to(OUR_IP);
        let action = handle_arp_frame(&frame, OUR_IP, &mut cache, &mut pending, 100);
        assert_eq!(
            action,
            ArpAction::Reply {
                peer_mac: PEER_MAC,
                peer_ip: PEER_IP,
            }
        );
        // Sender pair learned.
        assert_eq!(cache.lookup(PEER_IP), Some(PEER_MAC));
        // Target pair MUST NOT be learned (tpa==our_ip, tha is junk).
        assert_eq!(cache.lookup(OUR_IP), None);
    }

    #[test]
    fn handle_request_for_other_ip_does_not_reply_but_still_learns() {
        let mut cache = ArpCache::new();
        let mut pending = None;
        let frame = arp_request_to(OTHER_IP);
        let action = handle_arp_frame(&frame, OUR_IP, &mut cache, &mut pending, 100);
        assert_eq!(action, ArpAction::None);
        assert_eq!(cache.lookup(PEER_IP), Some(PEER_MAC));
    }

    #[test]
    fn handle_reply_clears_matching_pending() {
        let mut cache = ArpCache::new();
        let mut pending = Some(PendingArp::InFlight {
            dest_ip: PEER_IP,
            retries_left: 2,
            deadline: 1_000_000,
        });
        let frame = arp_reply_from(PEER_MAC, PEER_IP);
        let action = handle_arp_frame(&frame, OUR_IP, &mut cache, &mut pending, 500);
        assert_eq!(action, ArpAction::None);
        assert_eq!(cache.lookup(PEER_IP), Some(PEER_MAC));
        assert_eq!(pending, None);
    }

    #[test]
    fn handle_reply_for_different_ip_leaves_pending_alone() {
        let mut cache = ArpCache::new();
        let mut pending = Some(PendingArp::InFlight {
            dest_ip: OTHER_IP,
            retries_left: 2,
            deadline: 1_000_000,
        });
        let frame = arp_reply_from(PEER_MAC, PEER_IP);
        handle_arp_frame(&frame, OUR_IP, &mut cache, &mut pending, 500);
        assert_eq!(
            pending,
            Some(PendingArp::InFlight {
                dest_ip: OTHER_IP,
                retries_left: 2,
                deadline: 1_000_000,
            })
        );
    }

    #[test]
    fn handle_frame_with_our_spa_does_not_learn() {
        let mut cache = ArpCache::new();
        let mut pending = None;
        // Hostile / looped frame claiming to come from us.
        let hostile = ParsedArp {
            op: ARP_OP_REQUEST,
            sha: PEER_MAC,
            spa: OUR_IP,
            tha: [0; 6],
            tpa: OUR_IP,
        };
        handle_arp_frame(&hostile, OUR_IP, &mut cache, &mut pending, 100);
        // We did NOT overwrite our own IP -> MAC binding.
        assert_eq!(cache.lookup(OUR_IP), None);
    }

    #[test]
    fn handle_frame_ignores_tha_tpa_for_learning() {
        let mut cache = ArpCache::new();
        let mut pending = None;
        // Synthetic: someone sends us a request with tha non-zero
        // and tpa someone else's IP. We must still only learn
        // (sha, spa), never (tha, tpa).
        let frame = ParsedArp {
            op: ARP_OP_REQUEST,
            sha: PEER_MAC,
            spa: PEER_IP,
            tha: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00],
            tpa: OTHER_IP,
        };
        handle_arp_frame(&frame, OUR_IP, &mut cache, &mut pending, 100);
        assert_eq!(cache.lookup(PEER_IP), Some(PEER_MAC));
        // Target pair not learned.
        assert_eq!(cache.lookup(OTHER_IP), None);
    }

    #[test]
    fn tick_pending_idle_within_deadline() {
        let mut pending = Some(PendingArp::InFlight {
            dest_ip: PEER_IP,
            retries_left: 2,
            deadline: 1_000_000,
        });
        let tick = tick_pending(&mut pending, 500_000);
        assert_eq!(tick, PendingTick::Idle);
        assert_eq!(
            pending,
            Some(PendingArp::InFlight {
                dest_ip: PEER_IP,
                retries_left: 2,
                deadline: 1_000_000,
            })
        );
    }

    #[test]
    fn tick_pending_retries_when_deadline_elapses() {
        let mut pending = Some(PendingArp::InFlight {
            dest_ip: PEER_IP,
            retries_left: 2,
            deadline: 1_000_000,
        });
        let tick = tick_pending(&mut pending, 1_500_000);
        assert_eq!(tick, PendingTick::Retry { dest_ip: PEER_IP });
        assert_eq!(
            pending,
            Some(PendingArp::InFlight {
                dest_ip: PEER_IP,
                retries_left: 1,
                deadline: 1_500_000 + ARP_REQUEST_DEADLINE_TICKS,
            })
        );
    }

    #[test]
    fn tick_pending_transitions_to_failed_when_retries_exhausted() {
        let mut pending = Some(PendingArp::InFlight {
            dest_ip: PEER_IP,
            retries_left: 0,
            deadline: 1_000_000,
        });
        let tick = tick_pending(&mut pending, 1_500_000);
        assert_eq!(tick, PendingTick::Idle);
        assert_eq!(
            pending,
            Some(PendingArp::Failed {
                dest_ip: PEER_IP,
                cooldown_until: 1_500_000 + ARP_FAILED_BACKOFF_TICKS,
            })
        );
    }

    #[test]
    fn tick_pending_clears_failed_after_cooldown() {
        let mut pending = Some(PendingArp::Failed {
            dest_ip: PEER_IP,
            cooldown_until: 1_000_000,
        });
        // Before cooldown - unchanged.
        let tick = tick_pending(&mut pending, 500_000);
        assert_eq!(tick, PendingTick::Idle);
        assert!(pending.is_some());
        // After cooldown - cleared.
        let tick = tick_pending(&mut pending, 1_000_001);
        assert_eq!(tick, PendingTick::Idle);
        assert_eq!(pending, None);
    }

    #[test]
    fn tick_pending_idle_on_empty_slot() {
        let mut pending = None;
        let tick = tick_pending(&mut pending, 100);
        assert_eq!(tick, PendingTick::Idle);
        assert_eq!(pending, None);
    }

    #[test]
    fn start_resolution_uses_max_retries() {
        let p = start_resolution(PEER_IP, 1_000);
        assert_eq!(
            p,
            PendingArp::InFlight {
                dest_ip: PEER_IP,
                retries_left: ARP_RETRIES_MAX,
                deadline: 1_000 + ARP_REQUEST_DEADLINE_TICKS,
            }
        );
    }

    #[test]
    fn pending_arp_dest_ip_works_for_both_variants() {
        let p1 = PendingArp::InFlight {
            dest_ip: PEER_IP,
            retries_left: 2,
            deadline: 100,
        };
        let p2 = PendingArp::Failed {
            dest_ip: OTHER_IP,
            cooldown_until: 100,
        };
        assert_eq!(p1.dest_ip(), PEER_IP);
        assert_eq!(p2.dest_ip(), OTHER_IP);
    }
}
