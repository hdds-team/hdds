// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DNS-SD peer discovery (RFC 6763 over RFC 2782 `SRV` records).
//!
//! A DNS zone is a COLD-PATH peer source, exactly like a cloud registry:
//! a background thread resolves `_hdds._udp.<zone>` every poll interval,
//! turns the answer into unicast SPDP destinations, and the announcer
//! takes it from there. No RTPS packet is ever parsed, produced or routed
//! here, so nothing in this module is on any hot path.
//!
//! ```text
//!  SRV _hdds._udp.example.test
//!         |
//!         +-- 0 10 7410 node-a.example.test --+
//!         +-- 0 10 7412 node-b.example.test --+--> A / AAAA --> SocketAddr
//!                                                                  |
//!                                     DnsSdPeerSink::on_peers(&[..])+
//! ```
//!
//! # Resolving, not publishing
//!
//! HDDS RESOLVES the zone; it does not write to it. The `SRV` and `A`
//! records are published by whatever owns the zone: AWS Cloud Map,
//! Route 53, CoreDNS, Consul's DNS interface, a hand-written zone file.
//! Dynamic DNS update (RFC 2136) is not implemented and is not planned
//! for 1.5.0.
//!
//! # Failure policy
//!
//! A failed lookup (timeout, `SERVFAIL`, `NXDOMAIN`, a truncated answer)
//! NEVER empties the peer view: a registry that cannot answer has said
//! nothing about who is gone. The peers keep their lease
//! (`3 x poll_interval`) and expire on their own if the zone stays
//! unreachable. Only an answered question that lists nothing removes
//! peers. Consecutive failures are counted and surfaced through
//! [`DnsSdStatus`], and logged loudly every three failures.
//!
//! An answered lookup can also be INCOMPLETE: the zone listed a target
//! whose address record is missing. That is neither a success nor a
//! failure, it is [`Answer::Partial`], and the sink is told so: the peers
//! that did resolve are refreshed, the ones that could not be re-confirmed
//! are kept for a bounded number of polls instead of being retired by an
//! answer that never mentioned them. [`DnsSdStatus::partial_lookups`] and
//! [`DnsSdStatus::unresolved_targets`] surface it.
//!
//! # Example
//!
//! ```no_run
//! use hdds::discovery::dnssd::DnsSdConfig;
//! use hdds::{Participant, TransportMode};
//!
//! let participant = Participant::builder("dns_sd_node")
//!     .with_transport(TransportMode::UdpMulticast)
//!     .with_dns_sd(DnsSdConfig::new("example.test"))
//!     .build()
//!     .unwrap();
//! ```

/// `/etc/resolv.conf` nameserver parsing.
pub mod resolv_conf;
/// UDP stub resolver (`SRV`, `A`, `AAAA`).
pub mod resolver;
/// DNS wire codec (RFC 1035 / 2782 / 6891).
pub mod wire;

pub use resolv_conf::{parse_nameservers, system_nameservers, DNS_PORT};
pub use resolver::{AddressLookup, DnsError, DnsResolver, ServiceView, SrvRecord};
pub use wire::{Message, RecordData, ResourceRecord, SrvData, WireError};

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Service instance HDDS participants are published under by default:
/// the RTPS metatraffic is UDP, so the transport label is `_udp`.
pub const DEFAULT_SERVICE: &str = "_hdds._udp";
/// Default interval between two resolutions of the service name.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Floor on the poll interval: the loop's own wake-up granularity.
///
/// Anything below it means "resolve on every tick": ten questions a
/// second at the nameserver, and a peer lease collapsed onto its
/// one-second floor where a single slow answer starts expiring peers.
/// Refused by [`DnsSdConfig::validate`], not clamped in silence.
pub const MIN_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Loop wake-up granularity, so `stop()` is honoured between polls.
const TICK: Duration = Duration::from_millis(100);
/// How long `stop()` waits for the thread before detaching it, matching
/// the Discovery Server runtime: a lookup already in flight must never
/// hold up `Participant::drop`.
const DROP_JOIN_TIMEOUT: Duration = Duration::from_millis(500);
/// Consecutive failures between two loud log lines.
const LOUD_FAILURE_INTERVAL: u32 = 3;

/// What a DNS-SD lookup found, and how it went.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsSdStatus {
    /// The polling thread is alive.
    pub running: bool,
    /// Lookups that were answered.
    pub successful_lookups: u64,
    /// Lookups that failed since the last answered one.
    pub consecutive_lookup_failures: u32,
    /// Peers the last answered lookup resolved to, BEFORE the participant
    /// wiring drops what its transport cannot send to (IPv6, unspecified,
    /// multicast, port 0, its own locators). This counts what DNS said,
    /// not what became an SPDP destination.
    pub resolved_peers: usize,
    /// Answered lookups that were incomplete (at least one listed `SRV`
    /// target had no address record).
    pub partial_lookups: u64,
    /// Targets the last answered lookup could not resolve.
    pub unresolved_targets: usize,
    /// Most recent failure, if any.
    pub last_error: Option<String>,
}

/// How much of the zone an answered lookup actually resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Every `SRV` target the zone listed resolved to an address. This IS
    /// the current membership: a peer absent from it has left.
    Complete,
    /// At least one listed target had no address record. A peer absent
    /// from this set may still be alive, so its absence must NOT retire
    /// it.
    Partial,
}

/// Consumer of each resolved peer set. Runs on the DNS-SD thread.
pub trait DnsSdPeerSink: Send + 'static {
    /// The peer set an ANSWERED lookup produced, and whether that set is
    /// the complete membership ([`Answer::Complete`]) or an incomplete
    /// view ([`Answer::Partial`]). Never called for a failed lookup.
    fn on_peers(&mut self, peers: &[SocketAddr], answer: Answer);

    /// The thread is stopping; the sink should forget its peers.
    ///
    /// The body is empty because doing nothing IS the correct default, not
    /// because the hook is unfinished. The event is delivered: [`run_loop`]
    /// calls it on its way out, after the loop and after `running` goes
    /// false, and a sink that owns peer state overrides it - `SpdpDnsSdSink`
    /// in `dds/participant/builder/dnssd_runtime.rs` clears the `Cloud`
    /// origin there, which `stopping_clears_only_the_cloud_origin` measures.
    ///
    /// A sink with no state of its own has nothing to forget, and the
    /// blanket impl below - a bare `FnMut(&[SocketAddr])` closure - has no
    /// argument that could carry "stopped" in the first place. The only
    /// shape that would fit, calling it with an empty slice, already means
    /// something else here: an ANSWERED lookup that listed nobody, that is,
    /// every peer has left. Sending that on shutdown would retire peers the
    /// zone never retired, which is exactly what the failure policy in the
    /// module docs forbids.
    ///
    /// `a_stopping_thread_tells_its_sink_before_it_exits` pins the delivery.
    // @audit-ok: deliberate default no-op, reasoned above, not a dropped event
    fn on_stopped(&mut self) {}
}

impl<F> DnsSdPeerSink for F
where
    F: FnMut(&[SocketAddr]) + Send + 'static,
{
    fn on_peers(&mut self, peers: &[SocketAddr], _answer: Answer) {
        self(peers);
    }
}

/// How a participant finds its peers in DNS.
#[derive(Debug, Clone)]
pub struct DnsSdConfig {
    /// Service instance label, `_hdds._udp` by default.
    pub service: String,
    /// The zone the service lives in, for example `example.test` or
    /// `hdds-namespace` for an AWS Cloud Map private namespace.
    pub domain: String,
    /// Nameservers to ask. Empty means `/etc/resolv.conf`, read once at
    /// `build()`; a build with neither is refused.
    pub nameservers: Vec<SocketAddr>,
    /// Interval between two resolutions (default 5 s).
    pub poll_interval: Duration,
    /// Per-question timeout (default 2 s).
    ///
    /// Bounds the questions this crate sends. It does NOT bound the system
    /// resolver step of [`AddressLookup::SystemFirst`] (the default):
    /// `getaddrinfo` takes no deadline. Use
    /// [`AddressLookup::NameserversOnly`] where every lookup must be
    /// bounded.
    pub query_timeout: Duration,
    /// Passes over the nameserver list before a lookup counts as failed.
    pub attempts: u32,
    /// Where `A`/`AAAA` records may come from (default: the system
    /// resolver first).
    pub address_lookup: AddressLookup,
}

impl DnsSdConfig {
    /// Discover `_hdds._udp.<domain>` with every default.
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            service: DEFAULT_SERVICE.to_string(),
            domain: domain.into(),
            nameservers: Vec::new(),
            poll_interval: DEFAULT_POLL_INTERVAL,
            query_timeout: resolver::DEFAULT_QUERY_TIMEOUT,
            attempts: resolver::DEFAULT_ATTEMPTS,
            address_lookup: AddressLookup::default(),
        }
    }

    /// Use another service label (`_hdds._udp` by default). RFC 6763
    /// requires an application label and a transport label, both
    /// underscore-prefixed.
    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.service = service.into();
        self
    }

    /// Ask these nameservers instead of `/etc/resolv.conf`.
    pub fn with_nameservers(mut self, nameservers: Vec<SocketAddr>) -> Self {
        self.nameservers = nameservers;
        self
    }

    /// Interval between two resolutions (default 5 s, floor 100 ms).
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Per-question timeout (default 2 s). See the field: the system
    /// resolver step is bounded by the host, not by this.
    pub fn with_query_timeout(mut self, timeout: Duration) -> Self {
        self.query_timeout = timeout;
        self
    }

    /// Passes over the nameserver list before a lookup counts as failed.
    pub fn with_attempts(mut self, attempts: u32) -> Self {
        self.attempts = attempts;
        self
    }

    /// Where `A`/`AAAA` records may come from.
    pub fn with_address_lookup(mut self, lookup: AddressLookup) -> Self {
        self.address_lookup = lookup;
        self
    }

    /// The fully qualified name that is resolved: `<service>.<domain>`.
    pub fn service_name(&self) -> String {
        format!(
            "{}.{}",
            self.service.trim_end_matches('.'),
            self.domain.trim_end_matches('.')
        )
    }

    /// Nameservers this config will actually query: the explicit list, or
    /// `/etc/resolv.conf` when it is empty.
    pub fn effective_nameservers(&self) -> Vec<SocketAddr> {
        self.effective_nameservers_from(resolv_conf::RESOLV_CONF_PATH)
    }

    /// [`Self::effective_nameservers`] against a specific `resolv.conf`.
    ///
    /// The seam a test needs: on a host whose `/etc/resolv.conf` lists
    /// nameservers, the "no nameserver at all" refusal below can only be
    /// exercised through this.
    pub fn effective_nameservers_from(&self, resolv_conf: impl AsRef<Path>) -> Vec<SocketAddr> {
        if self.nameservers.is_empty() {
            resolv_conf::nameservers_from_file(resolv_conf)
        } else {
            self.nameservers.clone()
        }
    }

    /// Everything that can only fail later, refused now.
    ///
    /// Reads `/etc/resolv.conf` when no nameserver was given, so a
    /// participant is never handed back with a DNS-SD thread that has
    /// nobody to ask.
    pub fn validate(&self) -> Result<Vec<SocketAddr>, String> {
        self.validate_with_resolv_conf(resolv_conf::RESOLV_CONF_PATH)
    }

    /// [`Self::validate`] against a specific `resolv.conf` (the test seam).
    pub fn validate_with_resolv_conf(
        &self,
        resolv_conf_path: impl AsRef<Path>,
    ) -> Result<Vec<SocketAddr>, String> {
        let service = self.service.trim_end_matches('.');
        let mut labels = service.split('.');
        let application = labels.next().unwrap_or("");
        let transport = labels.next().unwrap_or("");
        if !application.starts_with('_') || application.len() < 2 {
            return Err(format!(
                "DNS-SD service {:?} has no underscore-prefixed application label (RFC 6763 section 4.1.2)",
                self.service
            ));
        }
        if transport != "_udp" && transport != "_tcp" {
            return Err(format!(
                "DNS-SD service {:?} has no _udp or _tcp transport label (RFC 6763 section 4.1.2)",
                self.service
            ));
        }
        if labels.next().is_some() {
            return Err(format!(
                "DNS-SD service {:?} must be exactly two labels; put the rest in the domain",
                self.service
            ));
        }
        if self.domain.trim_end_matches('.').is_empty() {
            return Err("DNS-SD domain is empty: there is no zone to resolve".to_string());
        }
        wire::encode_name(&self.service_name()).map_err(|error| {
            format!(
                "DNS-SD name {:?} is not resolvable: {}",
                self.service_name(),
                error
            )
        })?;
        if self.poll_interval < MIN_POLL_INTERVAL {
            return Err(format!(
                "DNS-SD poll interval {:?} is below the {:?} floor: the loop ticks at that granularity, so a shorter interval queries the nameserver on every tick and shrinks the peer lease onto its own floor",
                self.poll_interval, MIN_POLL_INTERVAL
            ));
        }
        if self.query_timeout.is_zero() {
            return Err(
                "DNS-SD query timeout is zero: every question would fail instantly".to_string(),
            );
        }
        let nameservers = self.effective_nameservers_from(resolv_conf_path.as_ref());
        if nameservers.is_empty() {
            return Err(format!(
                "DNS-SD has no nameserver: none was configured and {} lists none",
                resolv_conf_path.as_ref().display()
            ));
        }
        Ok(nameservers)
    }

    /// A resolver for this config, with the nameservers already resolved.
    pub fn resolver(&self) -> Result<DnsResolver, String> {
        let nameservers = self.validate()?;
        Ok(DnsResolver::new(nameservers)
            .with_timeout(self.query_timeout)
            .with_attempts(self.attempts)
            .with_address_lookup(self.address_lookup))
    }
}

/// A running DNS-SD discovery thread.
///
/// Stops on `stop()` or on drop; a lookup still in flight is detached
/// after [`DROP_JOIN_TIMEOUT`] rather than blocking the caller.
pub struct DnsSdDiscovery {
    service_name: String,
    shutdown: Arc<AtomicBool>,
    status: Arc<Mutex<DnsSdStatus>>,
    handle: Option<JoinHandle<()>>,
}

impl DnsSdDiscovery {
    /// Validate `config` and start resolving into `sink`.
    ///
    /// The first lookup happens immediately, then every
    /// [`DnsSdConfig::poll_interval`].
    pub fn spawn(config: DnsSdConfig, sink: impl DnsSdPeerSink) -> Result<Self, String> {
        let resolver = config.resolver()?;
        let service_name = config.service_name();
        let shutdown = Arc::new(AtomicBool::new(false));
        let status = Arc::new(Mutex::new(DnsSdStatus {
            running: true,
            ..DnsSdStatus::default()
        }));

        let thread_shutdown = Arc::clone(&shutdown);
        let thread_status = Arc::clone(&status);
        let thread_name = service_name.clone();
        let poll_interval = config.poll_interval;
        let handle = thread::Builder::new()
            .name("hdds-dnssd".to_string())
            .spawn(crate::core::rt::shutdown::owned(move || {
                run_loop(
                    resolver,
                    thread_name,
                    poll_interval,
                    sink,
                    &thread_shutdown,
                    &thread_status,
                );
            }))
            .map_err(|error| format!("cannot spawn the DNS-SD thread: {}", error))?;

        Ok(Self {
            service_name,
            shutdown,
            status,
            handle: Some(handle),
        })
    }

    /// The name being resolved, `<service>.<domain>`.
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Current lookup state.
    pub fn status(&self) -> DnsSdStatus {
        lock(&self.status).clone()
    }

    /// Stop the thread, detaching it if a lookup is still in flight.
    ///
    /// The loop checks the shutdown flag before every DNS question, so the
    /// worst case is one `query_timeout` (2 s by default) plus, on the
    /// default [`AddressLookup::SystemFirst`], one `getaddrinfo` call that
    /// this crate cannot bound. Past [`DROP_JOIN_TIMEOUT`] the thread is
    /// detached rather than blocking the caller; it holds only its own
    /// `Arc`s and clears the peers it owns when it finally exits.
    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let Some(handle) = self.handle.take() else {
            return;
        };
        let deadline = Instant::now() + DROP_JOIN_TIMEOUT;
        while !handle.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        if handle.is_finished() {
            let _ = handle.join();
        } else {
            log::warn!(
                "[DNS-SD] The {} thread did not stop within {:?}; detaching the pending lookup",
                self.service_name,
                DROP_JOIN_TIMEOUT
            );
        }
        lock(&self.status).running = false;
    }
}

impl Drop for DnsSdDiscovery {
    fn drop(&mut self) {
        self.stop();
    }
}

impl std::fmt::Debug for DnsSdDiscovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsSdDiscovery")
            .field("service_name", &self.service_name)
            .field("running", &self.handle.is_some())
            .finish()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn run_loop(
    resolver: DnsResolver,
    service_name: String,
    poll_interval: Duration,
    mut sink: impl DnsSdPeerSink,
    shutdown: &AtomicBool,
    status: &Mutex<DnsSdStatus>,
) {
    log::info!(
        "[DNS-SD] Resolving {} every {:?} through {:?}",
        service_name,
        poll_interval,
        resolver.nameservers()
    );
    let mut next_poll = Instant::now();
    while !shutdown.load(Ordering::Acquire) {
        if Instant::now() < next_poll {
            thread::sleep(TICK);
            continue;
        }
        next_poll = Instant::now() + poll_interval;

        let cancelled = || shutdown.load(Ordering::Acquire);
        match resolver.resolve_service_view_with(&service_name, &cancelled) {
            Ok(view) => {
                let answer = if view.is_complete() {
                    Answer::Complete
                } else {
                    Answer::Partial
                };
                {
                    let mut state = lock(status);
                    state.successful_lookups += 1;
                    state.consecutive_lookup_failures = 0;
                    state.resolved_peers = view.peers.len();
                    state.unresolved_targets = view.unresolved.len();
                    if answer == Answer::Partial {
                        state.partial_lookups += 1;
                    }
                    state.last_error = None;
                }
                if answer == Answer::Partial {
                    log::warn!(
                        "[DNS-SD] {} answered {} peers but {:?} have no address record: \
                         the view is incomplete, so peers it does not list are kept, not retired",
                        service_name,
                        view.peers.len(),
                        view.unresolved
                    );
                } else {
                    log::debug!(
                        "[DNS-SD] {} resolved to {} peers",
                        service_name,
                        view.peers.len()
                    );
                }
                sink.on_peers(&view.peers, answer);
            }
            // Shutting down: not a lookup failure, and nothing to report.
            Err(DnsError::Cancelled) => break,
            Err(error) => {
                // A lookup that was not answered says NOTHING about who is
                // gone: the peer view is kept and the lease decides.
                let failures = {
                    let mut state = lock(status);
                    state.consecutive_lookup_failures += 1;
                    state.last_error = Some(error.to_string());
                    state.consecutive_lookup_failures
                };
                if failures % LOUD_FAILURE_INTERVAL == 0 {
                    log::error!(
                        "[DNS-SD] {} has failed {} consecutive lookups: {}. Peers keep their lease; \
                         discovery stops when it expires.",
                        service_name,
                        failures,
                        error
                    );
                } else {
                    log::warn!("[DNS-SD] {} lookup failed: {}", service_name, error);
                }
            }
        }
    }
    lock(status).running = false;
    sink.on_stopped();
    log::info!("[DNS-SD] Stopped resolving {}", service_name);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fake_dns::{FakeDnsMode, FakeDnsServer};
    use std::net::Ipv4Addr;
    use std::sync::mpsc;

    fn config(server: &FakeDnsServer) -> DnsSdConfig {
        DnsSdConfig::new("example.test")
            .with_nameservers(vec![server.addr()])
            .with_poll_interval(MIN_POLL_INTERVAL)
            .with_query_timeout(Duration::from_millis(300))
            .with_attempts(1)
            .with_address_lookup(AddressLookup::NameserversOnly)
    }

    fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if condition() {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        condition()
    }

    #[test]
    fn service_name_and_validation_refuse_what_cannot_be_resolved() {
        let ns = vec!["192.0.2.53:53".parse::<SocketAddr>().unwrap()];
        let base = DnsSdConfig::new("example.test").with_nameservers(ns.clone());
        assert_eq!(base.service_name(), "_hdds._udp.example.test");
        assert_eq!(base.validate(), Ok(ns.clone()));

        // A trailing dot on either half is absorbed.
        assert_eq!(
            DnsSdConfig::new("example.test.")
                .with_service("_hdds._udp.")
                .service_name(),
            "_hdds._udp.example.test"
        );

        let cases = [
            (base.clone().with_service("hdds._udp"), "application label"),
            (base.clone().with_service("_hdds._sctp"), "transport label"),
            (base.clone().with_service("_hdds._udp.extra"), "two labels"),
            (base.clone().with_service("_"), "application label"),
            (
                DnsSdConfig::new("").with_nameservers(ns.clone()),
                "domain is empty",
            ),
            (
                base.clone().with_poll_interval(Duration::from_millis(99)),
                "below the",
            ),
            (
                base.clone().with_query_timeout(Duration::ZERO),
                "timeout is zero",
            ),
            (
                DnsSdConfig::new(format!("{}.test", "x".repeat(64))).with_nameservers(ns.clone()),
                "not resolvable",
            ),
        ];
        for (config, expected) in cases {
            let error = config
                .validate()
                .expect_err("this config must not validate");
            assert!(
                error.contains(expected),
                "the refusal of {:?} does not mention {:?}: {}",
                config.service_name(),
                expected,
                error
            );
        }
    }

    /// A zone with no nameserver to ask is refused up front, never started.
    ///
    /// Measured against a `resolv.conf` that lists none, NOT against the
    /// host's: on a box whose `/etc/resolv.conf` is populated (every CI
    /// image) a test that reads the real file proves nothing at all.
    #[test]
    fn a_config_without_any_nameserver_is_refused_before_a_thread_exists() {
        let config = DnsSdConfig::new("example.test").with_nameservers(Vec::new());
        const NO_RESOLV_CONF: &str = "/nonexistent/hdds/dnssd/resolv.conf";
        assert!(
            config.effective_nameservers_from(NO_RESOLV_CONF).is_empty(),
            "the seam must not fall back to the host resolver"
        );
        let error = config
            .validate_with_resolv_conf(NO_RESOLV_CONF)
            .expect_err("no nameserver, no DNS-SD");
        assert!(error.contains("no nameserver"), "{}", error);

        // An explicit list is used whatever the file says.
        assert_eq!(
            DnsSdConfig::new("example.test")
                .with_nameservers(vec!["192.0.2.53:53".parse().unwrap()])
                .validate_with_resolv_conf(NO_RESOLV_CONF),
            Ok(vec!["192.0.2.53:53".parse().unwrap()])
        );
        let (sender, receiver) = mpsc::channel::<Vec<SocketAddr>>();
        let bad = DnsSdConfig::new("example.test")
            .with_nameservers(vec!["192.0.2.53:53".parse().unwrap()])
            .with_service("nope");
        assert!(DnsSdDiscovery::spawn(bad, move |peers: &[SocketAddr]| {
            let _ = sender.send(peers.to_vec());
        })
        .is_err());
        assert!(receiver.try_recv().is_err(), "no lookup can have happened");
    }

    /// A zone that lists a target with no address record is ANSWERED but
    /// incomplete: the sink is told so, and the status counts it.
    #[test]
    fn an_incomplete_zone_is_reported_as_partial_not_as_a_shorter_membership() {
        let server = FakeDnsServer::start().expect("start fake dns");
        server.add_srv("_hdds._udp.example.test", 0, 0, 7410, "node-a.example.test");
        server.add_srv("_hdds._udp.example.test", 0, 0, 7412, "node-b.example.test");
        server.add_a("node-a.example.test", Ipv4Addr::new(192, 0, 2, 1));

        type Seen = Arc<Mutex<Vec<(Vec<SocketAddr>, Answer)>>>;
        struct Recorder(Seen);
        impl DnsSdPeerSink for Recorder {
            fn on_peers(&mut self, peers: &[SocketAddr], answer: Answer) {
                lock(&self.0).push((peers.to_vec(), answer));
            }
        }
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let mut discovery = DnsSdDiscovery::spawn(config(&server), Recorder(Arc::clone(&seen)))
            .expect("the discovery thread starts");

        assert!(
            wait_until(Duration::from_secs(5), || {
                lock(&seen)
                    .iter()
                    .any(|(_, answer)| *answer == Answer::Partial)
            }),
            "an incomplete answer was not reported as partial: {:?}",
            lock(&seen)
        );
        let status = discovery.status();
        assert!(status.partial_lookups >= 1, "{:?}", status);
        assert_eq!(status.unresolved_targets, 1, "{:?}", status);
        assert_eq!(status.consecutive_lookup_failures, 0, "{:?}", status);

        // The missing A record appears: the very next answer is complete.
        server.add_a("node-b.example.test", Ipv4Addr::new(192, 0, 2, 2));
        assert!(
            wait_until(Duration::from_secs(5), || {
                lock(&seen)
                    .last()
                    .is_some_and(|(peers, answer)| *answer == Answer::Complete && peers.len() == 2)
            }),
            "the completed zone was still reported as partial: {:?}",
            lock(&seen)
        );
        assert_eq!(discovery.status().unresolved_targets, 0);
        discovery.stop();
    }

    /// The stop event reaches the sink, exactly once, and not before.
    ///
    /// [`DnsSdPeerSink::on_stopped`] has an empty default body, so the only
    /// thing that separates "a deliberate no-op" from "a hook nobody ever
    /// calls" is a sink that counts the call. This is that sink.
    #[test]
    fn a_stopping_thread_tells_its_sink_before_it_exits() {
        let server = FakeDnsServer::start().expect("start fake dns");
        server.add_srv("_hdds._udp.example.test", 0, 0, 7410, "node-a.example.test");
        server.add_a("node-a.example.test", Ipv4Addr::new(192, 0, 2, 1));

        #[derive(Default)]
        struct Calls {
            peers: usize,
            stopped: usize,
        }
        type Shared = Arc<Mutex<Calls>>;
        struct Recorder(Shared);
        impl DnsSdPeerSink for Recorder {
            fn on_peers(&mut self, _peers: &[SocketAddr], _answer: Answer) {
                lock(&self.0).peers += 1;
            }
            fn on_stopped(&mut self) {
                lock(&self.0).stopped += 1;
            }
        }

        let calls: Shared = Arc::new(Mutex::new(Calls::default()));
        let mut discovery = DnsSdDiscovery::spawn(config(&server), Recorder(Arc::clone(&calls)))
            .expect("the discovery thread starts");
        assert!(
            wait_until(Duration::from_secs(5), || lock(&calls).peers >= 1),
            "no answered lookup ever reached the sink"
        );
        assert_eq!(
            lock(&calls).stopped,
            0,
            "the sink was told to forget while the thread was still running"
        );

        discovery.stop();
        assert!(
            wait_until(Duration::from_secs(5), || lock(&calls).stopped == 1),
            "stop() never reached the sink: {} call(s)",
            lock(&calls).stopped
        );
        // Still exactly one after the thread is long gone.
        thread::sleep(Duration::from_millis(200));
        assert_eq!(lock(&calls).stopped, 1);
    }

    #[test]
    fn discovery_thread_reports_peers_and_survives_a_failing_zone() {
        let server = FakeDnsServer::start().expect("start fake dns");
        server.add_srv("_hdds._udp.example.test", 0, 0, 7410, "node-a.example.test");
        server.add_a("node-a.example.test", Ipv4Addr::new(192, 0, 2, 1));

        let seen: Arc<Mutex<Vec<Vec<SocketAddr>>>> = Arc::new(Mutex::new(Vec::new()));
        let sink_seen = Arc::clone(&seen);
        let mut discovery =
            DnsSdDiscovery::spawn(config(&server), move |peers: &[SocketAddr]| {
                lock(&sink_seen).push(peers.to_vec());
            })
            .expect("the discovery thread starts");
        assert_eq!(discovery.service_name(), "_hdds._udp.example.test");

        assert!(
            wait_until(Duration::from_secs(5), || {
                lock(&seen)
                    .iter()
                    .any(|peers| peers == &["192.0.2.1:7410".parse::<SocketAddr>().unwrap()])
            }),
            "the resolved peer never reached the sink: {:?}",
            lock(&seen)
        );
        let status = discovery.status();
        assert!(status.running);
        assert_eq!(status.resolved_peers, 1);
        assert_eq!(status.consecutive_lookup_failures, 0);

        // A zone that stops answering must NOT hand the sink an empty set.
        server.set_mode(FakeDnsMode::Silent);
        let calls_before = lock(&seen).len();
        assert!(
            wait_until(Duration::from_secs(5), || {
                discovery.status().consecutive_lookup_failures >= 2
            }),
            "the failures were not counted: {:?}",
            discovery.status()
        );
        let after = lock(&seen);
        assert!(
            after.len() >= calls_before && after.iter().all(|peers| !peers.is_empty()),
            "a failed lookup emptied the peer view: {:?}",
            after
        );
        assert!(discovery.status().last_error.is_some());
        drop(after);

        // An ANSWERED lookup that lists nothing does remove the peers.
        server.set_mode(FakeDnsMode::Answer);
        server.clear_records();
        assert!(
            wait_until(Duration::from_secs(5), || {
                lock(&seen).last().is_some_and(Vec::is_empty)
            }),
            "an authoritative empty answer did not reach the sink: {:?}",
            lock(&seen)
        );

        let stopped = Instant::now();
        discovery.stop();
        assert!(!discovery.status().running);
        assert!(
            stopped.elapsed() < Duration::from_secs(2),
            "stop() was not bounded: {:?}",
            stopped.elapsed()
        );
    }
}
