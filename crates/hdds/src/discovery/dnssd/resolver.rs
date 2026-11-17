// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A stub resolver: one question, one UDP datagram, one answer.
//!
//! [`DnsResolver`] asks configured nameservers for `SRV`, `A` and `AAAA`
//! records with [`super::wire`], and turns an `SRV` set plus its address
//! records into the `SocketAddr` list DNS-SD discovery needs.
//!
//! # Address lookup order (DNSSD-1)
//!
//! `A` comes first, everywhere:
//!
//! 1. glue: the `A`/`AAAA` records a server returns in the additional
//!    section of the `SRV` answer, which costs no extra query;
//! 2. the SYSTEM resolver through `std::net::ToSocketAddrs` (default
//!    [`AddressLookup::SystemFirst`]), so `/etc/hosts`, nsswitch and the
//!    host's own caching resolver keep working;
//! 3. an in-tree `A` query, then an in-tree `AAAA` query, to the
//!    configured nameservers.
//!
//! `SRV` has no step 2: `getaddrinfo` cannot ask for a service record, so
//! it always goes through the in-tree codec. [`AddressLookup::NameserversOnly`]
//! drops step 2 for addresses too, which is what a split-horizon zone (and
//! every hermetic test) needs.
//!
//! Step 2 is the one step this resolver does not time out: `getaddrinfo`
//! takes no deadline, so `with_timeout` bounds steps 1 and 3 only. A
//! deployment that needs every lookup bounded must use
//! [`AddressLookup::NameserversOnly`].
//!
//! # UDP only, and what that costs
//!
//! Queries advertise a 4096-byte EDNS0 buffer. A larger answer comes back
//! with the `TC` bit, which this resolver reports as
//! [`DnsError::Truncated`] instead of retrying over TCP: a truncated
//! answer is a PARTIAL peer list, and silently discovering half a fleet is
//! worse than saying so. TCP fallback (RFC 7766) is not implemented; an
//! `_hdds._udp` zone with tens of records stays well inside 4096 bytes.
//!
//! # What this resolver does not do
//!
//! No DNSSEC validation, no DoT/DoH, no cache. Response acceptance is a
//! `connect()`-filtered source address, a matching message ID, exactly one
//! echoed question that matches the one asked (name, type and class), and
//! answer records whose OWNER name is the queried name or a canonical name
//! reached from it through `CNAME`. That raises the bar on off-path
//! spoofing without pretending to close it: an attacker who guesses both
//! the ephemeral source port and the message ID is still believed. A zone
//! that must be trusted end to end belongs behind a validating resolver on
//! the host, or on the DDS-Security path.
//!
//! # Complete answers and partial ones
//!
//! [`DnsResolver::resolve_service`] returns the peer list only when EVERY
//! `SRV` target the zone listed resolved to an address; a target that did
//! not is [`DnsError::IncompleteAnswer`], because a shorter list is
//! indistinguishable from a peer that left. [`ServiceView`] carries the
//! same answer without that judgement, for the discovery loop, which keeps
//! the peers it cannot re-confirm instead of retiring them.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::wire::{
    decode_message, encode_query, normalise_name, Message, RecordData, ResourceRecord, SrvData,
    WireError, CLASS_IN, EDNS_UDP_PAYLOAD, RCODE_NOERROR, RCODE_NXDOMAIN, TYPE_A, TYPE_AAAA,
    TYPE_SRV,
};

/// Default per-question timeout.
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// Default number of passes over the nameserver list.
pub const DEFAULT_ATTEMPTS: u32 = 2;
/// Receive buffer: one byte more than the advertised EDNS0 buffer, so a
/// server that ignores the advertised size is REPORTED as truncated
/// instead of being silently cut by `recv()` and decoded as garbage.
const RECV_BUFFER: usize = EDNS_UDP_PAYLOAD as usize + 1;
/// Longest `CNAME` chain followed inside one answer.
const MAX_CNAME_HOPS: usize = 8;
/// Odd 64-bit constant used to mix the message-ID state.
const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;

/// One xorshift64 step; never returns to zero for a non-zero state.
fn xorshift64(state: u64) -> u64 {
    let mut next = state;
    next ^= next << 13;
    next ^= next >> 7;
    next ^= next << 17;
    next
}

/// Where address records may come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressLookup {
    /// The system resolver first, the configured nameservers only if it
    /// answers with nothing. Keeps `/etc/hosts` and nsswitch working.
    #[default]
    SystemFirst,
    /// The configured nameservers only. Required for a zone the host
    /// resolver cannot see, and the only reproducible mode for a test.
    NameserversOnly,
}

/// Everything a lookup can fail with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// No nameserver is configured and none could be read from
    /// `/etc/resolv.conf`.
    NoNameservers,
    /// No nameserver answered within the timeout, over every attempt.
    Timeout,
    /// A socket operation failed (bind, connect, send, receive).
    Io(String),
    /// The answer did not fit in the advertised UDP buffer (`TC` bit).
    /// UDP-only by design: see the module docs.
    Truncated,
    /// The name does not exist (`NXDOMAIN`).
    NameError,
    /// The server answered with a non-zero `RCODE` other than `NXDOMAIN`.
    Server(u16),
    /// The answer could not be decoded.
    Wire(WireError),
    /// A question was answered, and every target it named failed to
    /// resolve to an address. Reported as an error, never as an empty
    /// result, so a caller cannot mistake it for "the service is gone".
    NoAddresses,
    /// The service or host name is not encodable as a DNS name.
    BadName(String),
    /// The zone answered, but at least one `SRV` target it listed has no
    /// address record. The answer is INCOMPLETE: a caller that treated it
    /// as the full peer set would retire a peer that may well be alive.
    IncompleteAnswer {
        /// Peers that did resolve.
        resolved: usize,
        /// Targets that did not.
        unresolved: Vec<String>,
    },
    /// The caller's cancellation hook fired between two questions.
    Cancelled,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoNameservers => write!(f, "no nameserver configured"),
            Self::Timeout => write!(f, "no nameserver answered in time"),
            Self::Io(reason) => write!(f, "DNS socket error: {}", reason),
            Self::Truncated => write!(
                f,
                "the answer was truncated (TC) and this resolver is UDP-only"
            ),
            Self::NameError => write!(f, "the name does not exist (NXDOMAIN)"),
            Self::Server(rcode) => write!(f, "the nameserver answered RCODE {}", rcode),
            Self::Wire(error) => write!(f, "malformed DNS answer: {}", error),
            Self::NoAddresses => write!(f, "no SRV target resolved to an address"),
            Self::BadName(name) => write!(f, "not a usable DNS name: {}", name),
            Self::IncompleteAnswer {
                resolved,
                unresolved,
            } => write!(
                f,
                "the answer is incomplete: {} peers resolved, but {:?} have no address record",
                resolved, unresolved
            ),
            Self::Cancelled => write!(f, "the lookup was cancelled"),
        }
    }
}

impl std::error::Error for DnsError {}

impl From<WireError> for DnsError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

/// One `SRV` record with whatever glue came with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    /// Lower is preferred (RFC 2782).
    pub priority: u16,
    /// Relative weight among equal priorities.
    pub weight: u16,
    /// Port the service listens on.
    pub port: u16,
    /// Target host name, normalised.
    pub target: String,
    /// Address records the same answer carried for `target`, `A` first.
    pub glue: Vec<IpAddr>,
}

/// A UDP stub resolver over a fixed nameserver list.
#[derive(Debug)]
pub struct DnsResolver {
    nameservers: Vec<SocketAddr>,
    timeout: Duration,
    attempts: u32,
    address_lookup: AddressLookup,
    /// Message-ID generator state (xorshift64*), advanced per query.
    id_state: AtomicU64,
}

impl DnsResolver {
    /// A resolver over an explicit nameserver list.
    pub fn new(nameservers: Vec<SocketAddr>) -> Self {
        Self {
            nameservers,
            timeout: DEFAULT_QUERY_TIMEOUT,
            attempts: DEFAULT_ATTEMPTS,
            address_lookup: AddressLookup::default(),
            id_state: AtomicU64::new(seed()),
        }
    }

    /// A resolver over the host's `/etc/resolv.conf` nameservers.
    pub fn from_system() -> Self {
        Self::new(super::resolv_conf::system_nameservers())
    }

    /// Per-question timeout (default 2 s). Zero is refused: it would make
    /// every receive fail instantly.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        if !timeout.is_zero() {
            self.timeout = timeout;
        }
        self
    }

    /// Passes over the nameserver list before giving up (default 2).
    pub fn with_attempts(mut self, attempts: u32) -> Self {
        self.attempts = attempts.max(1);
        self
    }

    /// Where address records may come from (default
    /// [`AddressLookup::SystemFirst`]).
    pub fn with_address_lookup(mut self, lookup: AddressLookup) -> Self {
        self.address_lookup = lookup;
        self
    }

    /// The nameservers this resolver asks.
    pub fn nameservers(&self) -> &[SocketAddr] {
        &self.nameservers
    }

    /// Next message ID (xorshift64*, never zero-cycling).
    ///
    /// One atomic read-modify-write: `DnsResolver` is `Sync` and may be
    /// shared, and two threads that read the same state would mint the
    /// same ID, which is half of what makes an off-path answer hard to
    /// forge.
    fn next_id(&self) -> u16 {
        let previous = self
            .id_state
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |state| {
                Some(xorshift64(state))
            })
            .unwrap_or(GOLDEN);
        let state = xorshift64(previous);
        // Top 16 bits of the 64-bit state. `to_be_bytes` yields the most
        // significant byte first, so `[hi, lo]` is bits 63..48, i.e. `x >> 48`,
        // and no truncating `as` cast is needed.
        let [hi, lo, ..] = state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_be_bytes();
        u16::from_be_bytes([hi, lo])
    }

    /// Ask every nameserver, `attempts` times, for one question.
    ///
    /// `NXDOMAIN` is authoritative and returns immediately; a transport
    /// failure or a server failure moves on to the next nameserver.
    pub fn query(&self, name: &str, qtype: u16) -> Result<Message, DnsError> {
        self.query_with(name, qtype, &no_cancel)
    }

    /// [`Self::query`], abandoned between two questions when `cancel`
    /// returns true.
    ///
    /// The hook is checked before every datagram, never inside a blocking
    /// receive, so the worst case after a cancellation is one
    /// `query_timeout`. A caller that must bound `Drop` (the DNS-SD thread
    /// does) uses this instead of waiting out
    /// `attempts x nameservers x query_timeout`.
    pub(super) fn query_with(
        &self,
        name: &str,
        qtype: u16,
        cancel: &dyn Fn() -> bool,
    ) -> Result<Message, DnsError> {
        if self.nameservers.is_empty() {
            return Err(DnsError::NoNameservers);
        }
        let question = normalise_name(name);
        let mut last = DnsError::Timeout;
        for _ in 0..self.attempts {
            for server in &self.nameservers {
                if cancel() {
                    return Err(DnsError::Cancelled);
                }
                match self.ask(*server, &question, qtype) {
                    Ok(message) => match message.rcode() {
                        RCODE_NOERROR => {
                            if message.is_truncated() {
                                return Err(DnsError::Truncated);
                            }
                            return Ok(message);
                        }
                        RCODE_NXDOMAIN => return Err(DnsError::NameError),
                        rcode => {
                            log::debug!(
                                "[DNS-SD] {} answered RCODE {} for {} type {}",
                                server,
                                rcode,
                                question,
                                qtype
                            );
                            last = DnsError::Server(rcode);
                        }
                    },
                    Err(error) => {
                        log::debug!(
                            "[DNS-SD] {} did not answer {} type {}: {}",
                            server,
                            question,
                            qtype,
                            error
                        );
                        last = error;
                    }
                }
            }
        }
        Err(last)
    }

    /// One question to one server, with the answer validated against it.
    fn ask(&self, server: SocketAddr, name: &str, qtype: u16) -> Result<Message, DnsError> {
        let id = self.next_id();
        let query = encode_query(id, name, qtype, true)?;
        let bind: SocketAddr = if server.is_ipv6() {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        let socket = UdpSocket::bind(bind).map_err(|e| DnsError::Io(e.to_string()))?;
        // connect() makes the kernel drop datagrams from any other source,
        // which is the cheap half of off-path spoofing resistance.
        socket
            .connect(server)
            .map_err(|e| DnsError::Io(e.to_string()))?;
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| DnsError::Io(e.to_string()))?;
        socket
            .send(&query)
            .map_err(|e| DnsError::Io(e.to_string()))?;

        // A wrong answer must not buy the sender extra time: the deadline
        // is absolute, not per-datagram.
        let deadline = Instant::now() + self.timeout;
        let mut buffer = [0u8; RECV_BUFFER];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(DnsError::Timeout);
            }
            socket
                .set_read_timeout(Some(remaining))
                .map_err(|e| DnsError::Io(e.to_string()))?;
            let len = match socket.recv(&mut buffer) {
                Ok(len) => len,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(DnsError::Timeout)
                }
                Err(error) => return Err(DnsError::Io(error.to_string())),
            };
            if len > EDNS_UDP_PAYLOAD as usize {
                // The server ignored the size we advertised: what arrived
                // is a message this resolver cannot read whole, which is
                // the same situation as a TC answer and is reported the
                // same way (never as a shorter peer list).
                return Err(DnsError::Truncated);
            }
            let message = match decode_message(&buffer[..len]) {
                Ok(message) => message,
                Err(error) => {
                    log::debug!(
                        "[DNS-SD] Discarding a malformed answer from {}: {}",
                        server,
                        error
                    );
                    continue;
                }
            };
            if message.id != id || !message.is_response() {
                continue;
            }
            // The question must come back unchanged, or the answer is
            // about something else. An answer that carries NO question is
            // refused too: no real server omits it, and accepting it would
            // let a forger skip this check entirely by setting QDCOUNT=0.
            let echoed = message.questions.len() == 1
                && message.questions[0].0 == name
                && message.questions[0].1 == qtype
                && message.questions[0].2 == CLASS_IN;
            if !echoed {
                log::debug!(
                    "[DNS-SD] Discarding an answer from {} that does not echo {} type {}: {:?}",
                    server,
                    name,
                    qtype,
                    message.questions
                );
                continue;
            }
            return Ok(message);
        }
    }

    /// Resolve `SRV` records for a service name, glue included.
    ///
    /// The list is sorted by priority, then descending weight, then target
    /// and port, so two polls of an unchanged zone produce an identical
    /// order. Every target is returned: DNS-SD enumerates peers, it does
    /// not pick one server, so RFC 2782's weighted selection does not
    /// apply.
    pub fn resolve_srv(&self, service: &str) -> Result<Vec<SrvRecord>, DnsError> {
        self.resolve_srv_with(service, &no_cancel)
    }

    fn resolve_srv_with(
        &self,
        service: &str,
        cancel: &dyn Fn() -> bool,
    ) -> Result<Vec<SrvRecord>, DnsError> {
        let message = self.query_with(service, TYPE_SRV, cancel)?;
        let owners = accepted_owners(&message, &normalise_name(service));
        let mut records: Vec<SrvRecord> = Vec::new();
        for record in owned_answers(&message, &owners, TYPE_SRV) {
            let RecordData::Srv(SrvData {
                priority,
                weight,
                port,
                target,
            }) = &record.data
            else {
                continue;
            };
            if target.is_empty() {
                // RFC 2782: a root target means "explicitly not available".
                continue;
            }
            records.push(SrvRecord {
                priority: *priority,
                weight: *weight,
                port: *port,
                target: target.clone(),
                glue: glue_for(&message, target),
            });
        }
        records.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then(b.weight.cmp(&a.weight))
                .then(a.target.cmp(&b.target))
                .then(a.port.cmp(&b.port))
        });
        Ok(records)
    }

    /// Resolve a host name to addresses, `A` before `AAAA`.
    ///
    /// See the module docs for the lookup order.
    pub fn resolve_addresses(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        self.resolve_addresses_with(host, &no_cancel)
    }

    fn resolve_addresses_with(
        &self,
        host: &str,
        cancel: &dyn Fn() -> bool,
    ) -> Result<Vec<IpAddr>, DnsError> {
        if cancel() {
            return Err(DnsError::Cancelled);
        }
        if self.address_lookup == AddressLookup::SystemFirst {
            let system = system_addresses(host);
            if !system.is_empty() {
                return Ok(system);
            }
        }
        let mut addresses = Vec::new();
        let mut first_error = None;
        match self.address_records(host, TYPE_A, cancel) {
            Ok(mut found) => addresses.append(&mut found),
            // NXDOMAIN is about the NAME, not the type: asking for AAAA
            // next would only repeat the same answer.
            Err(DnsError::NameError) => return Err(DnsError::NameError),
            Err(DnsError::Cancelled) => return Err(DnsError::Cancelled),
            Err(error) => {
                log::debug!("[DNS-SD] No A record for {}: {}", host, error);
                first_error = Some(error);
            }
        }
        match self.address_records(host, TYPE_AAAA, cancel) {
            Ok(mut found) => addresses.append(&mut found),
            Err(DnsError::Cancelled) => return Err(DnsError::Cancelled),
            Err(error) => {
                log::debug!("[DNS-SD] No AAAA record for {}: {}", host, error);
            }
        }
        if addresses.is_empty() {
            // Report the A failure, which is the one that matters here.
            return Err(first_error.unwrap_or(DnsError::NoAddresses));
        }
        Ok(addresses)
    }

    fn address_records(
        &self,
        host: &str,
        qtype: u16,
        cancel: &dyn Fn() -> bool,
    ) -> Result<Vec<IpAddr>, DnsError> {
        let message = self.query_with(host, qtype, cancel)?;
        let owners = accepted_owners(&message, &normalise_name(host));
        let addresses: Vec<IpAddr> = owned_answers(&message, &owners, qtype)
            .filter_map(|record| match record.data {
                RecordData::A(ip) => Some(IpAddr::V4(ip)),
                RecordData::Aaaa(ip) => Some(IpAddr::V6(ip)),
                _ => None,
            })
            .collect();
        if addresses.is_empty() {
            return Err(DnsError::NoAddresses);
        }
        Ok(addresses)
    }

    /// Resolve a DNS-SD service name to the COMPLETE peer list behind it.
    ///
    /// An empty result means the zone answered and listed nothing (the
    /// service is gone). Every other outcome is an `Err`, so a caller can
    /// distinguish "no peers" from "no answer" and refuse to act on the
    /// second. A target that the zone lists and that has no address record
    /// is [`DnsError::IncompleteAnswer`], NOT a shorter list: the two are
    /// indistinguishable to a caller, and one of them means "this peer
    /// left". [`Self::resolve_service_view`] returns the same answer with
    /// that distinction kept instead of turned into an error.
    pub fn resolve_service(&self, service: &str) -> Result<Vec<SocketAddr>, DnsError> {
        let view = self.resolve_service_view(service)?;
        if !view.unresolved.is_empty() {
            return Err(DnsError::IncompleteAnswer {
                resolved: view.peers.len(),
                unresolved: view.unresolved,
            });
        }
        Ok(view.peers)
    }

    /// Resolve a DNS-SD service name, reporting what did NOT resolve.
    ///
    /// The `SRV` question itself must be answered (any failure there is an
    /// `Err`, and so is an answer whose every target failed: neither says
    /// anything about who is gone). A view whose
    /// [`ServiceView::unresolved`] is non-empty is INCOMPLETE and must not
    /// be treated as the full current membership.
    pub fn resolve_service_view(&self, service: &str) -> Result<ServiceView, DnsError> {
        self.resolve_service_view_with(service, &no_cancel)
    }

    /// [`Self::resolve_service_view`], abandoned between two questions when
    /// `cancel` returns true (see [`Self::query_with`]).
    pub(super) fn resolve_service_view_with(
        &self,
        service: &str,
        cancel: &dyn Fn() -> bool,
    ) -> Result<ServiceView, DnsError> {
        let records = self.resolve_srv_with(service, cancel)?;
        if records.is_empty() {
            return Ok(ServiceView::default());
        }
        let mut view = ServiceView::default();
        for record in &records {
            let addresses = if record.glue.is_empty() {
                match self.resolve_addresses_with(&record.target, cancel) {
                    Ok(addresses) => addresses,
                    Err(DnsError::Cancelled) => return Err(DnsError::Cancelled),
                    Err(error) => {
                        log::debug!(
                            "[DNS-SD] SRV target {} has no usable address: {}",
                            record.target,
                            error
                        );
                        if !view.unresolved.contains(&record.target) {
                            view.unresolved.push(record.target.clone());
                        }
                        continue;
                    }
                }
            } else {
                record.glue.clone()
            };
            for address in addresses {
                let peer = SocketAddr::new(address, record.port);
                if !view.peers.contains(&peer) {
                    view.peers.push(peer);
                }
            }
        }
        if view.peers.is_empty() {
            // Every target failed: this answer carries no information about
            // membership at all, so it is a failure, not an empty zone.
            return Err(DnsError::NoAddresses);
        }
        Ok(view)
    }
}

/// What one answered service lookup found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceView {
    /// Peer addresses that resolved, in `SRV` priority order.
    pub peers: Vec<SocketAddr>,
    /// Targets the zone listed that resolved to no address. Non-empty
    /// means `peers` is INCOMPLETE: a peer missing from it may still be
    /// alive, so its absence must not be read as a departure.
    pub unresolved: Vec<String>,
}

impl ServiceView {
    /// Every listed target resolved.
    pub fn is_complete(&self) -> bool {
        self.unresolved.is_empty()
    }
}

/// The hook a lookup that cannot be cancelled passes.
fn no_cancel() -> bool {
    false
}

/// Owner names an answer record may carry for `queried`.
///
/// The queried name, plus every canonical name reachable from it through
/// `CNAME` records in the SAME message (RFC 1034 section 3.6.2), bounded
/// to [`MAX_CNAME_HOPS`] so a hostile chain cannot spin. Anything else is
/// a record about a name nobody asked about, and is dropped.
fn accepted_owners(message: &Message, queried: &str) -> HashSet<String> {
    let mut owners = HashSet::new();
    owners.insert(queried.to_string());
    for _ in 0..MAX_CNAME_HOPS {
        let mut added = false;
        for record in &message.answers {
            if record.rclass != CLASS_IN || !owners.contains(&record.name) {
                continue;
            }
            if let RecordData::Cname(target) = &record.data {
                added |= owners.insert(target.clone());
            }
        }
        if !added {
            break;
        }
    }
    owners
}

/// Answer records of one type, class IN, owned by a name that was asked
/// about. Everything else in the section is somebody else's answer.
fn owned_answers<'a>(
    message: &'a Message,
    owners: &'a HashSet<String>,
    rtype: u16,
) -> impl Iterator<Item = &'a ResourceRecord> {
    message.answers.iter().filter(move |record| {
        record.rtype == rtype && record.rclass == CLASS_IN && owners.contains(&record.name)
    })
}

/// Glue for `target` from the additional (then answer) sections, `A` first.
fn glue_for(message: &Message, target: &str) -> Vec<IpAddr> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for record in message.additionals.iter().chain(message.answers.iter()) {
        if record.name != target || record.rclass != CLASS_IN {
            continue;
        }
        match record.data {
            RecordData::A(ip) => {
                if !v4.contains(&IpAddr::V4(ip)) {
                    v4.push(IpAddr::V4(ip));
                }
            }
            RecordData::Aaaa(ip) => {
                if !v6.contains(&IpAddr::V6(ip)) {
                    v6.push(IpAddr::V6(ip));
                }
            }
            _ => {}
        }
    }
    v4.extend(v6);
    v4
}

/// The system resolver's view of a host name, IPv4 first (DNSSD-1).
fn system_addresses(host: &str) -> Vec<IpAddr> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    match (host, 0u16).to_socket_addrs() {
        Ok(addrs) => {
            for addr in addrs {
                match addr.ip() {
                    IpAddr::V4(ip) if !v4.contains(&IpAddr::V4(ip)) => v4.push(IpAddr::V4(ip)),
                    IpAddr::V6(ip) if !v6.contains(&IpAddr::V6(ip)) => v6.push(IpAddr::V6(ip)),
                    _ => {}
                }
            }
        }
        Err(error) => {
            log::debug!(
                "[DNS-SD] System resolver has no address for {}: {}",
                host,
                error
            );
        }
    }
    v4.extend(v6);
    v4
}

/// Seed for the message-ID generator: never zero (xorshift64 would stick).
///
/// Time, process id and a process-global counter, so two resolvers built
/// in the same nanosecond do not share an ID stream. Unpredictability here
/// raises the bar on off-path answer spoofing; it is not a security
/// guarantee (see the module docs).
fn seed() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(GOLDEN);
    let pid = u64::from(std::process::id());
    let counted = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mixed = nanos.rotate_left(17) ^ pid.wrapping_mul(GOLDEN) ^ counted.wrapping_mul(GOLDEN);
    if mixed == 0 {
        GOLDEN
    } else {
        mixed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fake_dns::{FakeDnsMode, FakeDnsServer};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};

    /// A nameserver that answers with bytes the test chooses.
    ///
    /// `FakeDnsServer` behaves like a real server, which is exactly why it
    /// cannot express what this resolver must refuse: an answer with no
    /// question section, a record owned by a name nobody asked about, a
    /// wrong class, a wrong ID, a datagram over the advertised buffer.
    struct RawResponder {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl RawResponder {
        /// `reply` receives every query datagram and returns the bytes to
        /// send back, or `None` to stay silent.
        fn start(reply: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static) -> Self {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind responder");
            socket
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("responder timeout");
            let addr = socket.local_addr().expect("responder addr");
            let stop = Arc::new(AtomicBool::new(false));
            let thread_stop = Arc::clone(&stop);
            let thread = thread::Builder::new()
                .name("hdds-raw-dns".to_string())
                .spawn(move || {
                    let mut buffer = [0u8; 4096];
                    while !thread_stop.load(Ordering::SeqCst) {
                        let Ok((len, from)) = socket.recv_from(&mut buffer) else {
                            continue;
                        };
                        if let Some(answer) = reply(&buffer[..len]) {
                            let _ = socket.send_to(&answer, from);
                        }
                    }
                })
                .expect("spawn responder");
            Self {
                addr,
                stop,
                thread: Some(thread),
            }
        }
    }

    impl Drop for RawResponder {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    /// One hand-built response: `question` is echoed when given, and every
    /// answer is written as (owner, type, class, RDATA).
    fn raw_response(
        id: u16,
        question: Option<(&str, u16)>,
        answers: &[(&str, u16, u16, Vec<u8>)],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&(super::super::wire::FLAG_QR | 0x0100u16).to_be_bytes());
        out.extend_from_slice(&u16::from(question.is_some()).to_be_bytes());
        out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        if let Some((name, qtype)) = question {
            out.extend_from_slice(&super::super::wire::encode_name(name).expect("question name"));
            out.extend_from_slice(&qtype.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
        }
        for (name, rtype, rclass, rdata) in answers {
            out.extend_from_slice(&super::super::wire::encode_name(name).expect("owner name"));
            out.extend_from_slice(&rtype.to_be_bytes());
            out.extend_from_slice(&rclass.to_be_bytes());
            out.extend_from_slice(&60u32.to_be_bytes());
            out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(rdata);
        }
        out
    }

    fn query_id(datagram: &[u8]) -> u16 {
        u16::from_be_bytes([datagram[0], datagram[1]])
    }

    fn raw_resolver(responder: &RawResponder) -> DnsResolver {
        DnsResolver::new(vec![responder.addr])
            .with_timeout(Duration::from_millis(250))
            .with_attempts(1)
            .with_address_lookup(AddressLookup::NameserversOnly)
    }

    fn resolver(server: &FakeDnsServer) -> DnsResolver {
        DnsResolver::new(vec![server.addr()])
            .with_timeout(Duration::from_millis(400))
            .with_attempts(1)
            .with_address_lookup(AddressLookup::NameserversOnly)
    }

    fn zone() -> FakeDnsServer {
        let server = FakeDnsServer::start().expect("start fake dns");
        server.add_srv(
            "_hdds._udp.example.test",
            10,
            5,
            7410,
            "node-a.example.test",
        );
        server.add_srv(
            "_hdds._udp.example.test",
            20,
            1,
            7412,
            "node-b.example.test",
        );
        server.add_a("node-a.example.test", Ipv4Addr::new(192, 0, 2, 1));
        server.add_a("node-b.example.test", Ipv4Addr::new(192, 0, 2, 2));
        server
    }

    #[test]
    fn resolves_srv_and_a_records_against_a_fake_nameserver() {
        let server = zone();
        let resolver = resolver(&server);

        let records = resolver
            .resolve_srv("_hdds._udp.EXAMPLE.test.")
            .expect("the zone answers");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].priority, 10);
        assert_eq!(records[0].port, 7410);
        assert_eq!(records[0].target, "node-a.example.test");
        // The fake returns the target's A record as glue, so no second
        // question is needed.
        assert_eq!(
            records[0].glue,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]
        );

        let peers = resolver
            .resolve_service("_hdds._udp.example.test")
            .expect("the service resolves");
        assert_eq!(
            peers,
            vec![
                "192.0.2.1:7410".parse::<SocketAddr>().unwrap(),
                "192.0.2.2:7412".parse::<SocketAddr>().unwrap(),
            ]
        );

        // One SRV question and no address question: glue was used.
        let questions = server.queries();
        assert_eq!(
            questions
                .iter()
                .filter(|q| q.qtype == TYPE_SRV && q.name == "_hdds._udp.example.test")
                .count(),
            2,
            "resolve_srv and resolve_service each asked once: {:?}",
            questions
        );
        assert_eq!(
            questions.iter().filter(|q| q.qtype == TYPE_A).count(),
            0,
            "glue must spare the A questions: {:?}",
            questions
        );
    }

    /// Without glue the resolver asks for `A` first and `AAAA` second.
    #[test]
    fn a_record_is_queried_before_aaaa_when_no_glue_is_offered() {
        let server = FakeDnsServer::start().expect("start fake dns");
        // An SRV whose target has no A record in the same answer: the fake
        // only attaches glue for targets it knows at answer time, so this
        // one is added AFTER the SRV, in a separate name.
        server.add_srv("_hdds._udp.example.test", 0, 0, 7411, "lonely.other.test");
        let resolver = resolver(&server);
        // No address at all: the service resolves to nothing, loudly.
        assert_eq!(
            resolver.resolve_service("_hdds._udp.example.test"),
            Err(DnsError::NoAddresses)
        );
        let types: Vec<u16> = server
            .queries()
            .iter()
            .filter(|q| q.name == "lonely.other.test")
            .map(|q| q.qtype)
            .collect();
        assert_eq!(types, vec![TYPE_A, TYPE_AAAA], "A must be asked first");

        // Give the target an address and the same call now succeeds.
        server.add_a("lonely.other.test", Ipv4Addr::new(198, 51, 100, 7));
        assert_eq!(
            resolver
                .resolve_service("_hdds._udp.example.test")
                .expect("resolves once the target has an A record"),
            vec!["198.51.100.7:7411".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn nxdomain_timeout_and_truncation_yield_no_peers_without_panic() {
        let server = zone();
        let resolver = resolver(&server);

        server.set_mode(FakeDnsMode::NxDomain);
        assert_eq!(
            resolver.resolve_service("_hdds._udp.example.test"),
            Err(DnsError::NameError)
        );

        server.set_mode(FakeDnsMode::Truncated);
        assert_eq!(
            resolver.resolve_service("_hdds._udp.example.test"),
            Err(DnsError::Truncated),
            "a truncated answer is a partial peer list, never a peer list"
        );

        server.set_mode(FakeDnsMode::Silent);
        let started = Instant::now();
        assert_eq!(
            resolver.resolve_service("_hdds._udp.example.test"),
            Err(DnsError::Timeout)
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the timeout was not honoured: {:?}",
            started.elapsed()
        );

        // A zone that answers NOERROR with no record IS authoritative:
        // an empty peer list, not an error.
        server.set_mode(FakeDnsMode::Answer);
        server.clear_records();
        assert_eq!(
            resolver.resolve_service("_hdds._udp.example.test"),
            Ok(Vec::new())
        );
    }

    #[test]
    fn a_resolver_without_a_nameserver_fails_instead_of_querying_nothing() {
        let resolver = DnsResolver::new(Vec::new());
        assert_eq!(
            resolver.resolve_service("_hdds._udp.example.test"),
            Err(DnsError::NoNameservers)
        );
        assert!(resolver.nameservers().is_empty());
    }

    #[test]
    fn an_unencodable_service_name_is_refused_before_any_datagram() {
        let server = zone();
        let resolver = resolver(&server);
        assert!(matches!(
            resolver.resolve_service("_hdds._udp..example.test"),
            Err(DnsError::Wire(_))
        ));
        assert!(
            server.queries().is_empty(),
            "a malformed name must not reach the wire: {:?}",
            server.queries()
        );
    }

    /// The message ID must not be a counter: two questions in a row carry
    /// different IDs, and an answer with the wrong ID is discarded.
    #[test]
    fn message_ids_vary_and_a_mismatched_answer_is_ignored() {
        let server = zone();
        let resolver = resolver(&server);
        for _ in 0..8 {
            let _ = resolver.resolve_srv("_hdds._udp.example.test");
        }
        let ids: Vec<u16> = server.queries().iter().map(|q| q.id).collect();
        assert_eq!(ids.len(), 8);
        let distinct: std::collections::HashSet<u16> = ids.iter().copied().collect();
        assert!(
            distinct.len() >= 7,
            "message IDs repeat too often: {:?}",
            ids
        );

        // The second half of the name: an answer whose ID is not the one
        // asked with is discarded, even though it echoes the question and
        // comes from the nameserver's own address.
        let responder = RawResponder::start(|query| {
            Some(raw_response(
                query_id(query) ^ 1,
                Some(("node-a.example.test", TYPE_A)),
                &[(
                    "node-a.example.test",
                    TYPE_A,
                    CLASS_IN,
                    vec![203, 0, 113, 9],
                )],
            ))
        });
        assert_eq!(
            raw_resolver(&responder).resolve_addresses("node-a.example.test"),
            Err(DnsError::Timeout),
            "an answer with the wrong message ID was accepted"
        );
    }

    /// Everything an off-path forger would try that a real server never
    /// sends: no question at all, a record about another name, a record in
    /// another class.
    #[test]
    fn answers_that_do_not_match_the_question_are_refused() {
        // (a) QDCOUNT = 0: the echoed-question check must not be skippable
        // by simply omitting the question.
        let responder = RawResponder::start(|query| {
            Some(raw_response(
                query_id(query),
                None,
                &[("attacker.invalid", TYPE_A, CLASS_IN, vec![203, 0, 113, 66])],
            ))
        });
        assert_eq!(
            raw_resolver(&responder).resolve_addresses("node-a.example.test"),
            Err(DnsError::Timeout),
            "an answer with no question section was accepted"
        );
        drop(responder);

        // (b) The question is echoed, but the record is owned by another
        // name: it answers something nobody asked.
        let responder = RawResponder::start(|query| {
            Some(raw_response(
                query_id(query),
                Some(("node-a.example.test", TYPE_A)),
                &[("attacker.invalid", TYPE_A, CLASS_IN, vec![203, 0, 113, 66])],
            ))
        });
        assert_eq!(
            raw_resolver(&responder).resolve_addresses("node-a.example.test"),
            Err(DnsError::NoAddresses),
            "a record owned by another name was accepted"
        );
        drop(responder);

        // (c) Right name, wrong class (CH instead of IN).
        let responder = RawResponder::start(|query| {
            Some(raw_response(
                query_id(query),
                Some(("node-a.example.test", TYPE_A)),
                &[("node-a.example.test", TYPE_A, 3, vec![203, 0, 113, 66])],
            ))
        });
        assert_eq!(
            raw_resolver(&responder).resolve_addresses("node-a.example.test"),
            Err(DnsError::NoAddresses),
            "a record in another class was accepted"
        );
    }

    /// An alias is followed, because the owner-name check above would
    /// otherwise break every zone that publishes a host under a `CNAME`.
    #[test]
    fn addresses_follow_a_cname_chain_from_the_queried_name() {
        let responder = RawResponder::start(|query| {
            let canonical =
                super::super::wire::encode_name("canonical.example.test").expect("name");
            Some(raw_response(
                query_id(query),
                Some(("alias.example.test", TYPE_A)),
                &[
                    (
                        "alias.example.test",
                        super::super::wire::TYPE_CNAME,
                        CLASS_IN,
                        canonical,
                    ),
                    (
                        "canonical.example.test",
                        TYPE_A,
                        CLASS_IN,
                        vec![198, 51, 100, 4],
                    ),
                ],
            ))
        });
        assert_eq!(
            raw_resolver(&responder).resolve_addresses("alias.example.test"),
            Ok(vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4))])
        );
    }

    /// A datagram larger than the buffer we advertised is reported as
    /// truncated, never decoded into a shorter peer list.
    #[test]
    fn an_oversized_answer_is_truncated_not_a_shorter_list() {
        let responder = RawResponder::start(|query| {
            let mut answer = raw_response(
                query_id(query),
                Some(("node-a.example.test", TYPE_A)),
                &[(
                    "node-a.example.test",
                    TYPE_A,
                    CLASS_IN,
                    vec![198, 51, 100, 5],
                )],
            );
            answer.resize(super::super::wire::EDNS_UDP_PAYLOAD as usize + 200, 0);
            Some(answer)
        });
        assert_eq!(
            raw_resolver(&responder).resolve_addresses("node-a.example.test"),
            Err(DnsError::Truncated)
        );
    }

    /// A zone that lists a target with no address record has NOT told us
    /// the membership: `resolve_service` refuses to pretend it did, and
    /// the view carries what is missing.
    #[test]
    fn a_target_without_an_address_makes_the_answer_incomplete() {
        let server = FakeDnsServer::start().expect("start fake dns");
        server.add_srv("_hdds._udp.example.test", 0, 0, 7410, "node-a.example.test");
        server.add_srv("_hdds._udp.example.test", 0, 0, 7412, "node-b.example.test");
        server.add_a("node-a.example.test", Ipv4Addr::new(192, 0, 2, 1));
        let resolver = resolver(&server);

        let view = resolver
            .resolve_service_view("_hdds._udp.example.test")
            .expect("the SRV question was answered");
        assert_eq!(
            view.peers,
            vec!["192.0.2.1:7410".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(view.unresolved, vec!["node-b.example.test".to_string()]);
        assert!(!view.is_complete());

        match resolver.resolve_service("_hdds._udp.example.test") {
            Err(DnsError::IncompleteAnswer {
                resolved,
                unresolved,
            }) => {
                assert_eq!(resolved, 1);
                assert_eq!(unresolved, vec!["node-b.example.test".to_string()]);
            }
            other => panic!("a partial answer was reported as a peer list: {:?}", other),
        }

        // With every target resolvable the same call is complete again.
        server.add_a("node-b.example.test", Ipv4Addr::new(192, 0, 2, 2));
        let view = resolver
            .resolve_service_view("_hdds._udp.example.test")
            .expect("the zone answers");
        assert!(view.is_complete(), "{:?}", view);
        assert_eq!(view.peers.len(), 2);
    }

    /// The cancellation hook is honoured between questions, so a caller
    /// that is shutting down does not wait out the retry budget.
    #[test]
    fn a_cancelled_lookup_returns_between_two_questions() {
        let server = zone();
        server.set_mode(FakeDnsMode::Silent);
        let resolver = DnsResolver::new(vec![server.addr(), server.addr(), server.addr()])
            .with_timeout(Duration::from_secs(2))
            .with_attempts(3)
            .with_address_lookup(AddressLookup::NameserversOnly);

        let started = Instant::now();
        assert_eq!(
            resolver.resolve_service_view_with("_hdds._udp.example.test", &|| true),
            Err(DnsError::Cancelled)
        );
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "a cancelled lookup still waited out its budget: {:?}",
            started.elapsed()
        );

        // Without the hook the same resolver spends the whole budget.
        let started = Instant::now();
        assert_eq!(
            resolver.resolve_service("_hdds._udp.example.test"),
            Err(DnsError::Timeout)
        );
        assert!(
            started.elapsed() > Duration::from_secs(2),
            "the uncancelled control did not use its retry budget: {:?}",
            started.elapsed()
        );
    }
}
