// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Consul Service Discovery
//!
//! Uses HashiCorp Consul for service discovery in Kubernetes, on-prem, and
//! hybrid cloud environments.
//!
//! # What this backend does
//!
//! - **Service registration** -- one Consul service per participant, keyed
//!   by the participant GUID, carrying its metatraffic locators in `Meta`
//!   and its domain in a `domain-<N>` tag.
//!   ([`CloudDiscovery::register_participant`])
//! - **Health checking** -- a TTL check registered with the service and
//!   refreshed by the poller on every tick ([`CloudDiscovery::heartbeat`]).
//!   A crashed participant stops refreshing it, the check goes critical,
//!   and the health query below stops returning it. This is ON by default
//!   ([`ConsulHealthPolicy::Ttl`]): without it a crashed node stays
//!   discoverable until an operator removes it by hand.
//! - **Peer discovery** -- `GET /v1/health/service/<prefix>?tag=domain-<N>
//!   &passing=true`, so only participants whose check is passing (or which
//!   registered no check at all) are returned.
//!   ([`CloudDiscovery::discover_participants`])
//! - **KV registration** -- the same record mirrored under
//!   `hdds/participants/domain-<N>/<guid>` for operators and for tools that
//!   read the KV store; deleted on deregistration.
//! - **ACL** -- an optional token sent as `X-Consul-Token` on every request
//!   ([`ConsulOptions::token`], never rendered by `Debug`).
//! - **Blocking queries** -- opt-in long polling on the Consul index
//!   ([`ConsulOptions::blocking_queries`], OFF by default). The health
//!   query carries `index=<last seen>&wait=<duration>` and Consul holds it
//!   open until the service list actually changes or the wait expires,
//!   instead of answering the whole list on every tick. A fleet then costs
//!   one request per participant per WAIT rather than per poll interval,
//!   and a peer that appears is seen the moment it appears instead of up
//!   to one interval later. The wait is clamped so a query in flight can
//!   never outlive this participant's own TTL check
//!   ([`ConsulDiscovery::blocking_wait`]), and only that one request gets
//!   the longer HTTP bound -- register, heartbeat and deregister keep the
//!   5 s ceiling that stops a black-holed agent from stalling the poller.
//!
//! # Example
//!
//! ```ignore
//! use hdds::discovery::cloud::{ConsulDiscovery, ConsulOptions};
//!
//! let options = ConsulOptions::default().with_token("s3cr3t");
//! let discovery = ConsulDiscovery::new("https://consul.service.consul:8500")?
//!     .with_options(options)
//!     .with_domain_id(39);
//! discovery.register_participant(&info).await?;
//! let peers = discovery.discover_participants().await?;
//! ```

#[cfg(feature = "cloud-discovery")]
use reqwest::{Client, Method, RequestBuilder};
#[cfg(feature = "cloud-discovery")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "cloud-discovery")]
use super::Locator;
use super::{CloudDiscovery, ParticipantInfo};
use crate::dds::Error;
use std::collections::HashMap;
use std::fmt;
#[cfg(feature = "cloud-discovery")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "cloud-discovery")]
use std::sync::Arc;
#[cfg(feature = "cloud-discovery")]
use std::sync::RwLock;
use std::time::Duration;

/// Default Consul service name, and the prefix of every service ID.
pub const DEFAULT_SERVICE_PREFIX: &str = "hdds-participant";

/// Heartbeat periods that must be missed before the TTL check goes
/// critical. Three, like the SPDP cloud peer lease: one late poll must not
/// make a live participant disappear from the catalog.
const TTL_HEARTBEATS: u32 = 3;
/// Floor on the TTL, whatever the poll interval is. A test polls every
/// 200 ms; a 600 ms TTL would expire between two Consul agent
/// anti-entropy passes and flap the service for no reason.
const MIN_TTL: Duration = Duration::from_secs(10);
/// Floor on `DeregisterCriticalServiceAfter`. Consul itself refuses
/// anything below one minute.
const MIN_DEREGISTER_AFTER: Duration = Duration::from_secs(60);

/// Consul's own ceiling on ONE service `Meta` value. Breaking it does not
/// truncate anything: the agent refuses the WHOLE registration with
/// `HTTP 400 Invalid Service Meta`. MEASURED against hashicorp/consul
/// 1.20.2 with the exact JSON this backend writes -- seven locators are
/// 477 characters and register, eight are 545 and come back 400. A host
/// with eight IPv4 addresses is not exotic (the multicast transport
/// enumerates every interface when it finds no primary one), and the
/// failure would be silent: the poller would retry the same refused body
/// with backoff for the life of the process.
const MAX_META_VALUE_LEN: usize = 512;
/// Consul's ceiling on a `Meta` KEY, which must also be `[A-Za-z0-9_-]`.
const MAX_META_KEY_LEN: usize = 128;
/// Consul's ceiling on the number of `Meta` pairs.
const MAX_META_PAIRS: usize = 64;

/// Consul does not return a blocking query at exactly `wait`: it adds a
/// random jitter of up to `wait/16` first, so the real ceiling on the
/// server side is `wait * 17/16`. Numerator and denominator of that
/// factor. A per-request HTTP timeout that does not clear it cuts off
/// answers Consul was about to send, and every one of them reads as a
/// failed poll.
const BLOCKING_JITTER_NUM: u32 = 17;
const BLOCKING_JITTER_DEN: u32 = 16;
/// Round-trip slack added on top of the jittered wait, so the bound on
/// the request is about the SERVER holding the query open and not about
/// how long the body takes to come back.
///
/// Two seconds, and the value is load-bearing rather than taste. The
/// whole budget must stay under the TTL of this participant's own check,
/// because a request that hangs for its full budget is time the poller
/// spends not refreshing that check. With the wait clamped to `ttl/2`
/// (see [`ConsulDiscovery::blocking_wait`]) the budget is
/// `ttl/2 * 17/16 + SLACK`, so staying under `ttl` needs
/// `SLACK < ttl * 15/32`; the smallest TTL this module ever registers is
/// [`MIN_TTL`] = 10 s, which allows 4.6 s. Two seconds keeps the margin
/// wide at every cadence and is still far more than a loopback or
/// same-VPC response body needs. `blocking_budget_stays_under_the_ttl`
/// is the test that holds the invariant.
const BLOCKING_SLACK: Duration = Duration::from_secs(2);
/// Shortest wait worth asking for. Consul parses the wait from a string
/// this module renders with one-second granularity ([`consul_duration`]),
/// so anything below a second would be silently rounded up to one; and a
/// sub-second long poll saves nothing over the plain query it replaces.
/// Below this the feature reports itself as off rather than pretending.
const MIN_BLOCKING_WAIT: Duration = Duration::from_secs(1);

/// The HTTP bound for ONE blocking health query.
///
/// This is the number that must NOT be installed on the client: see
/// [`ConsulDiscovery::discover_participants`], which applies it to that
/// single request builder and leaves every other call on the client-wide
/// [`super::poller_thread::REQUEST_TIMEOUT`].
#[cfg(feature = "cloud-discovery")]
fn blocking_request_timeout(wait: Duration) -> Duration {
    wait * BLOCKING_JITTER_NUM / BLOCKING_JITTER_DEN + BLOCKING_SLACK
}

/// Health-check policy for the participant's own Consul service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ConsulHealthPolicy {
    /// Register a TTL check with the service and refresh it on every poll
    /// tick (`PUT /v1/agent/check/pass/...`). A participant that crashes,
    /// is SIGKILLed or loses the network stops refreshing it: the check
    /// goes critical after the TTL and `discover_participants` (which asks
    /// for passing instances only) stops returning it. This is the
    /// default -- a registry that never forgets a dead node is a registry
    /// that hands every survivor a black hole to unicast into.
    #[default]
    Ttl,
    /// Register no check at all. The service then lives in the catalog
    /// until it is deregistered explicitly; use it only when something
    /// else (a Consul-native sidecar check, an orchestrator) already
    /// removes dead instances.
    Disabled,
}

/// Consul-specific options: everything that is not the endpoint URL.
///
/// `Debug` renders the token as `<redacted>`: the options travel inside
/// `CloudProvider`, which is `Debug` and reaches log lines.
///
/// `#[non_exhaustive]`: this struct is expected to grow (blocking-query
/// settings, agent TLS), and every construction site goes through
/// [`ConsulOptions::default`] plus the `with_*` builders anyway.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConsulOptions {
    /// Consul service name, and the prefix of the per-participant service
    /// ID (default [`DEFAULT_SERVICE_PREFIX`]).
    pub service_prefix: String,
    /// Consul datacenter (`?dc=`), applied to EVERY request including the
    /// health query. `None` uses the agent's own datacenter.
    pub datacenter: Option<String>,
    /// ACL token, sent as `X-Consul-Token` on every request. An
    /// ACL-enabled Consul answers 403 without it.
    pub token: Option<String>,
    /// Health-check policy (default [`ConsulHealthPolicy::Ttl`]).
    pub health: ConsulHealthPolicy,
    /// Mirror the participant record into the KV store under
    /// `hdds/participants/domain-<N>/<guid>` (default `true`).
    ///
    /// When enabled, a KV write that the agent refuses fails the whole
    /// registration: an announced mirror that silently never appears is
    /// worse than a loud retry. Turn it off when the ACL token holds
    /// `service:write` but not `key:write`.
    pub kv_mirror: bool,
    /// Long-poll the peer-discovery query on the Consul index instead of
    /// re-reading the whole service list every poll interval (default
    /// `None`, off).
    ///
    /// `Some(wait)` asks Consul to hold the health query open for up to
    /// `wait` and to answer as soon as the list changes. That trades one
    /// request per poll interval for one request per `wait`, and drops
    /// the time a new peer stays invisible from "up to one interval" to
    /// "as fast as Consul can write the response".
    ///
    /// It is a REQUEST, not a guarantee: the wait really asked for is
    /// clamped to what this participant's own liveness allows (see
    /// [`ConsulDiscovery::blocking_wait`]), and the first query of a
    /// process is always a plain non-blocking read because there is no
    /// index to wait on yet. Leave it off to keep the poller's behaviour
    /// exactly as it is.
    pub blocking_queries: Option<Duration>,
}

impl Default for ConsulOptions {
    fn default() -> Self {
        Self {
            service_prefix: DEFAULT_SERVICE_PREFIX.to_string(),
            datacenter: None,
            token: None,
            health: ConsulHealthPolicy::default(),
            kv_mirror: true,
            blocking_queries: None,
        }
    }
}

impl fmt::Debug for ConsulOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsulOptions")
            .field("service_prefix", &self.service_prefix)
            .field("datacenter", &self.datacenter)
            .field(
                "token",
                &self.token.as_ref().map(|_| "<redacted>").unwrap_or("None"),
            )
            .field("health", &self.health)
            .field("kv_mirror", &self.kv_mirror)
            .field("blocking_queries", &self.blocking_queries)
            .finish()
    }
}

impl ConsulOptions {
    /// Set the Consul service name / service-ID prefix.
    pub fn with_service_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.service_prefix = prefix.into();
        self
    }

    /// Set the Consul datacenter.
    pub fn with_datacenter(mut self, datacenter: impl Into<String>) -> Self {
        self.datacenter = Some(datacenter.into());
        self
    }

    /// Set the ACL token (`X-Consul-Token`).
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Set the health-check policy.
    pub fn with_health(mut self, health: ConsulHealthPolicy) -> Self {
        self.health = health;
        self
    }

    /// Enable or disable the KV mirror.
    pub fn with_kv_mirror(mut self, enabled: bool) -> Self {
        self.kv_mirror = enabled;
        self
    }

    /// Long-poll peer discovery on the Consul index, asking the agent to
    /// hold the health query open for up to `wait`
    /// ([`ConsulOptions::blocking_queries`]). Off unless this is called.
    pub fn with_blocking_queries(mut self, wait: Duration) -> Self {
        self.blocking_queries = Some(wait);
        self
    }

    /// Go back to a plain query per poll interval.
    pub fn without_blocking_queries(mut self) -> Self {
        self.blocking_queries = None;
        self
    }
}

/// Consul Service Discovery backend
///
/// Registers participants with Consul's service catalog and discovers peers
/// via Consul's HTTP API.
#[derive(Debug, Clone)]
pub struct ConsulDiscovery {
    /// Consul HTTP API endpoint
    #[allow(dead_code)] // Used when cloud-discovery feature is enabled
    consul_addr: String,

    /// Everything but the endpoint
    #[allow(dead_code)] // Used when cloud-discovery feature is enabled
    options: ConsulOptions,

    /// Domain ID filter
    #[allow(dead_code)] // Used when cloud-discovery feature is enabled
    domain_id: u32,

    /// How often the owner of this backend calls `heartbeat()`; the TTL is
    /// derived from it.
    #[allow(dead_code)] // Used when cloud-discovery feature is enabled
    heartbeat_interval: Duration,

    /// HTTP client
    #[cfg(feature = "cloud-discovery")]
    client: Client,

    /// Registered service ID (for cleanup)
    #[cfg(feature = "cloud-discovery")]
    registered_id: Arc<RwLock<Option<String>>>,

    /// Last `X-Consul-Index` the health query answered, or 0 when there
    /// is none yet (the state a blocking query waits on).
    ///
    /// An atomic and not a lock, and `Relaxed` throughout, because this
    /// value publishes NOTHING: it is a single `u64` hint read and
    /// written by `discover_participants`, which the poller calls from
    /// one thread at a time, and every other field the answer touches
    /// travels back through the returned `Vec`, not through here. There
    /// is no second location whose visibility has to be ordered against
    /// it, which is the only thing a stronger ordering would buy. A torn
    /// or stale read could at worst cost one redundant query, and the
    /// two guards in `fold_index` already treat any index that does not
    /// make sense as "start again from a plain read".
    #[cfg(feature = "cloud-discovery")]
    last_index: Arc<AtomicU64>,
}

// ============================================================================
// Consul API Types
// ============================================================================

#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Serialize)]
struct ConsulServiceRegistration {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Tags")]
    tags: Vec<String>,
    #[serde(rename = "Address")]
    address: String,
    #[serde(rename = "Port")]
    port: u16,
    #[serde(rename = "Meta")]
    meta: HashMap<String, String>,
    #[serde(rename = "Check", skip_serializing_if = "Option::is_none")]
    check: Option<ConsulTtlCheck>,
}

/// A TTL check: Consul marks the service critical unless
/// `PUT /v1/agent/check/pass/<CheckID>` arrives within `TTL`.
#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Serialize)]
struct ConsulTtlCheck {
    #[serde(rename = "CheckID")]
    check_id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "TTL")]
    ttl: String,
    #[serde(rename = "DeregisterCriticalServiceAfter")]
    deregister_after: String,
    /// Start passing: the participant IS alive at registration time, and a
    /// service that starts critical would be invisible to every peer until
    /// the first heartbeat.
    #[serde(rename = "Status")]
    status: String,
}

/// One entry of `GET /v1/health/service/<name>`.
#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Deserialize)]
struct ConsulHealthEntry {
    #[serde(rename = "Service")]
    service: ConsulAgentService,
}

#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Struct fields used for deserialization from Consul API response
struct ConsulAgentService {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Service")]
    service: String,
    #[serde(rename = "Tags", default)]
    tags: Vec<String>,
    #[serde(rename = "Address", default)]
    address: String,
    #[serde(rename = "Port", default)]
    port: u16,
    #[serde(rename = "Meta", default)]
    meta: HashMap<String, String>,
}

#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Serialize, Deserialize)]
struct ConsulKvParticipant {
    guid: String,
    name: String,
    domain_id: u32,
    locators: Vec<ConsulLocator>,
    metadata: HashMap<String, String>,
}

#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Serialize, Deserialize)]
struct ConsulLocator {
    kind: i32,
    port: u32,
    address: String, // hex-encoded
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Encode bytes to hex string
#[cfg(feature = "cloud-discovery")]
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode hex string to bytes
#[cfg(feature = "cloud-discovery")]
fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Percent-encode one URL component (path segment or query value).
///
/// Service prefixes, datacenters and check IDs are configuration, not
/// literals: a space or a `/` in one of them must not silently re-target
/// the request at another Consul endpoint. Everything outside the RFC 3986
/// unreserved set is escaped.
#[cfg(feature = "cloud-discovery")]
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{:02X}", other)),
        }
    }
    out
}

/// Render a duration the way Consul parses it (`"15s"`).
#[cfg(feature = "cloud-discovery")]
fn consul_duration(duration: Duration) -> String {
    format!("{}s", duration.as_secs().max(1))
}

/// Convert Locator to ConsulLocator
#[cfg(feature = "cloud-discovery")]
fn locator_to_consul(loc: &Locator) -> ConsulLocator {
    ConsulLocator {
        kind: loc.kind,
        port: loc.port,
        address: to_hex(&loc.address),
    }
}

/// Convert ConsulLocator to Locator
#[cfg(feature = "cloud-discovery")]
fn consul_to_locator(cl: &ConsulLocator) -> Option<Locator> {
    let addr_bytes = from_hex(&cl.address)?;
    if addr_bytes.len() != 16 {
        return None;
    }
    let mut address = [0u8; 16];
    address.copy_from_slice(&addr_bytes);
    Some(Locator {
        kind: cl.kind,
        port: cl.port,
        address,
    })
}

/// A `Meta` key Consul accepts: `[A-Za-z0-9_-]`, non-empty, bounded.
#[cfg(feature = "cloud-discovery")]
fn meta_key_is_valid(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_META_KEY_LEN
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The `Meta.locators` value: the participant's locator set as JSON,
/// capped at Consul's 512-character limit on one `Meta` value.
///
/// Usable unicast locators are serialised FIRST, so the one the service
/// `Address`/`Port` pair was taken from is never the one dropped, and the
/// tail is truncated with a warning. Truncating costs a peer some
/// alternative destinations; not truncating costs it the participant
/// altogether, because the agent refuses the whole registration.
#[cfg(feature = "cloud-discovery")]
fn locators_meta(locators: &[Locator]) -> Result<String, Error> {
    let usable = |loc: &&Locator| {
        super::locator_to_socket_addr(loc)
            .is_some_and(|addr| crate::core::discovery::usable_unicast_locator(&addr))
    };
    let mut kept: Vec<ConsulLocator> = locators
        .iter()
        .filter(usable)
        .chain(locators.iter().filter(|loc| !usable(loc)))
        .map(locator_to_consul)
        .collect();
    loop {
        let json = serde_json::to_string(&kept).map_err(|e| {
            Error::Config(format!(
                "Consul locator metadata serialization failed: {}",
                e
            ))
        })?;
        if json.len() <= MAX_META_VALUE_LEN || kept.is_empty() {
            if kept.len() < locators.len() {
                log::warn!(
                    "Consul: only {} of {} locators fit Consul's {}-character Meta limit; \
                     the rest are not published",
                    kept.len(),
                    locators.len(),
                    MAX_META_VALUE_LEN
                );
            }
            return Ok(json);
        }
        kept.pop();
    }
}

/// Everything Consul validates about a `Meta` map, checked BEFORE the
/// request so the offending key is named instead of coming back as an
/// opaque 400 the poller then retries for ever.
#[cfg(feature = "cloud-discovery")]
fn check_meta(meta: &HashMap<String, String>) -> Result<(), Error> {
    if meta.len() > MAX_META_PAIRS {
        return Err(Error::Config(format!(
            "Consul registration refused: {} metadata pairs, Consul accepts {}",
            meta.len(),
            MAX_META_PAIRS
        )));
    }
    for (key, value) in meta {
        if !meta_key_is_valid(key) {
            return Err(Error::Config(format!(
                "Consul registration refused: metadata key {:?} is not one Consul accepts \
                 (non-empty, at most {} characters, only A-Z a-z 0-9 _ -)",
                key, MAX_META_KEY_LEN
            )));
        }
        if value.len() > MAX_META_VALUE_LEN {
            return Err(Error::Config(format!(
                "Consul registration refused: metadata value for {:?} is {} characters, \
                 Consul accepts {}",
                key,
                value.len(),
                MAX_META_VALUE_LEN
            )));
        }
    }
    Ok(())
}

/// The service `Address`/`Port` pair: the FIRST usable unicast IPv4
/// locator, address and port taken from the SAME locator.
///
/// "Usable" is [`crate::core::discovery::usable_unicast_locator`]: UDPv4,
/// a non-zero port, not `0.0.0.0`, not multicast. Loopback COUNTS -- a
/// sidecar-agent deployment and every hermetic test register
/// `127.0.0.1`. `None` when there is none, and then the registration is
/// refused: falling back to a hard-coded `127.0.0.1:7400` would publish an
/// endpoint the participant does not even listen on, which every peer
/// would then unicast SPDP into.
#[cfg(feature = "cloud-discovery")]
fn service_endpoint(locators: &[Locator]) -> Option<(String, u16)> {
    for loc in locators {
        let Some(addr) = super::locator_to_socket_addr(loc) else {
            continue;
        };
        if !crate::core::discovery::usable_unicast_locator(&addr) {
            continue;
        }
        return Some((addr.ip().to_string(), addr.port()));
    }
    None
}

// ============================================================================
// Implementation
// ============================================================================

impl ConsulDiscovery {
    /// Create a new Consul Service Discovery backend
    ///
    /// # Arguments
    ///
    /// - `consul_addr` -- Consul HTTP API endpoint (e.g.
    ///   `https://consul.service.consul:8500`, or `http://127.0.0.1:8500`
    ///   for the local agent)
    ///
    /// # Errors
    ///
    /// Refuses a plaintext `http://` endpoint whose host is not a loopback
    /// literal: the registry traffic carries the participant GUID and its
    /// locators, and there is no flag to re-open that
    /// (see [`super::check_endpoint_transport`]).
    pub fn new(consul_addr: impl Into<String>) -> Result<Self, Error> {
        let consul_addr = consul_addr.into();
        super::check_endpoint_transport(&consul_addr).map_err(Error::Config)?;

        // `.no_proxy()`: a registry endpoint is reached directly. Honouring
        // HTTP_PROXY here would route the participant's registration
        // through whatever the environment points at (and would silently
        // break every loopback test on a box that exports it).
        #[cfg(feature = "cloud-discovery")]
        // ONE bound, one constant: the poller wraps every backend call in
        // `REQUEST_TIMEOUT` already, and a direct user of this type (through
        // `Participant::create_consul_discovery`) gets exactly the same
        // ceiling instead of the client default.
        let client = Client::builder()
            .no_proxy()
            .timeout(super::poller_thread::REQUEST_TIMEOUT)
            .build()
            .map_err(|e| Error::Config(format!("failed to build Consul HTTP client: {}", e)))?;

        Ok(Self {
            consul_addr,
            options: ConsulOptions::default(),
            domain_id: 0,
            heartbeat_interval: super::poller_thread::DEFAULT_POLL_INTERVAL,
            #[cfg(feature = "cloud-discovery")]
            client,
            #[cfg(feature = "cloud-discovery")]
            registered_id: Arc::new(RwLock::new(None)),
            #[cfg(feature = "cloud-discovery")]
            last_index: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Replace every Consul-specific option at once.
    pub fn with_options(mut self, options: ConsulOptions) -> Self {
        self.options = options;
        self
    }

    /// The options in force.
    pub fn options(&self) -> &ConsulOptions {
        &self.options
    }

    /// Set service name prefix (default [`DEFAULT_SERVICE_PREFIX`])
    pub fn with_service_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.options.service_prefix = prefix.into();
        self
    }

    /// Set domain ID filter
    pub fn with_domain_id(mut self, domain_id: u32) -> Self {
        self.domain_id = domain_id;
        self
    }

    /// Set Consul datacenter
    pub fn with_datacenter(mut self, dc: impl Into<String>) -> Self {
        self.options.datacenter = Some(dc.into());
        self
    }

    /// Declare how often [`CloudDiscovery::heartbeat`] will be called; the
    /// TTL of the registered check is three of these intervals (ten
    /// seconds at least).
    pub fn with_heartbeat_interval(mut self, interval: Duration) -> Self {
        self.heartbeat_interval = interval;
        self
    }

    /// TTL of the registered check.
    #[cfg(feature = "cloud-discovery")]
    fn ttl(&self) -> Duration {
        self.heartbeat_interval
            .saturating_mul(TTL_HEARTBEATS)
            .max(MIN_TTL)
    }

    /// The wait this backend may really ask Consul to hold the health
    /// query open for, or `None` when it must not block at all.
    ///
    /// THE CLAMP IS THE WHOLE SAFETY ARGUMENT, so it is worth spelling
    /// out. The poller is ONE sequential loop: while
    /// `discover_participants` sits inside Consul waiting, that same
    /// loop is not calling `heartbeat`, and `heartbeat` is what keeps
    /// this participant's own TTL check passing. A wait longer than the
    /// TTL would therefore make the participant evict ITSELF from the
    /// catalog it is polling -- every peer would stop seeing it, and the
    /// cause would be the efficiency feature. Capping the wait at HALF
    /// the TTL means a heartbeat that has just been delayed by a
    /// full-length blocking query still lands with the other half of the
    /// TTL to spare.
    ///
    /// The consequence is deliberate and is the honest shape of the
    /// feature: how long this participant may long-poll is decided by
    /// how often it has promised to prove it is alive. An operator who
    /// wants minute-long waits raises the poll interval, which raises
    /// the TTL ([`ConsulDiscovery::ttl`]) with it.
    #[cfg(feature = "cloud-discovery")]
    fn blocking_wait(&self) -> Option<Duration> {
        let requested = self.options.blocking_queries?;
        let wait = requested.min(self.ttl() / 2);
        (wait >= MIN_BLOCKING_WAIT).then_some(wait)
    }

    /// Fold one `X-Consul-Index` from a response into the stored value.
    ///
    /// `sent` is the index this query carried (0 when it was a plain
    /// read), `returned` the one the answer came back with.
    #[cfg(feature = "cloud-discovery")]
    fn fold_index(&self, returned: u64, sent: u64) {
        // Consul reserves index 0, and an index below 1 handed back as
        // the "last seen" value of the NEXT query makes that query
        // return immediately -- for ever, at whatever rate the poller
        // runs. Clamp up to 1.
        let returned = returned.max(1);
        // An index that went BACKWARDS means the state it counted was
        // reset underneath us: a restarted agent, a restored snapshot, a
        // different server answering. Consul's documentation is explicit
        // that the client must then drop back to 0, which makes the next
        // query a plain read that seeds a fresh index, instead of
        // waiting on an index that now refers to nothing.
        let next = if returned < sent { 0 } else { returned };
        self.last_index.store(next, Ordering::Relaxed);
    }

    /// How long Consul keeps a critical service before removing it.
    #[cfg(feature = "cloud-discovery")]
    fn deregister_after(&self) -> Duration {
        self.ttl().saturating_mul(4).max(MIN_DEREGISTER_AFTER)
    }

    /// Generate the Consul service ID from the participant GUID.
    ///
    /// The WHOLE GUID, not a prefix of it. A prefix such as `guid[0..8]`
    /// is vendor + host_id + the two HIGH bytes of a big-endian PID, which
    /// are ZERO for any PID below 65536, i.e. IDENTICAL for every
    /// participant on the host: they would all register the same service ID
    /// and silently replace each other in the catalog. Only the whole GUID
    /// is guaranteed unique.
    #[cfg(feature = "cloud-discovery")]
    fn service_id(&self, guid: &[u8; 16]) -> String {
        format!("{}-{}", self.options.service_prefix, to_hex(guid))
    }

    /// The check ID of the service's TTL check. Set explicitly so the
    /// heartbeat URL does not depend on how Consul names implicit checks.
    #[cfg(feature = "cloud-discovery")]
    fn check_id(&self, guid: &[u8; 16]) -> String {
        format!("service:{}", self.service_id(guid))
    }

    /// Build a Consul API URL: `/v1<path>` plus the datacenter (when set)
    /// and the caller's query parameters, all percent-encoded.
    ///
    /// Every request goes through here, the health query included: a
    /// participant registered in datacenter X that is then looked up in the
    /// agent's default datacenter finds nobody.
    #[cfg(feature = "cloud-discovery")]
    fn api_url(&self, path: &str, params: &[(&str, &str)]) -> String {
        let mut url = format!("{}/v1{}", self.consul_addr.trim_end_matches('/'), path);
        let mut separator = '?';
        if let Some(dc) = self.options.datacenter.as_deref() {
            url.push(separator);
            url.push_str("dc=");
            url.push_str(&percent_encode(dc));
            separator = '&';
        }
        for (key, value) in params {
            url.push(separator);
            url.push_str(&percent_encode(key));
            url.push('=');
            url.push_str(&percent_encode(value));
            separator = '&';
        }
        url
    }

    /// One request, with the ACL token when one is configured.
    #[cfg(feature = "cloud-discovery")]
    fn request(&self, method: Method, url: &str) -> RequestBuilder {
        let builder = self.client.request(method, url);
        match self.options.token.as_deref() {
            Some(token) => builder.header("X-Consul-Token", token),
            None => builder,
        }
    }

    /// Undo a service registration whose later steps failed, so a
    /// half-registered participant cannot flap in and out of the catalog
    /// on every retry. Returns the sentence to append to the error.
    #[cfg(feature = "cloud-discovery")]
    async fn rollback_service(&self, service_id: &str) -> String {
        let url = self.api_url(
            &format!("/agent/service/deregister/{}", percent_encode(service_id)),
            &[],
        );
        match self.request(Method::PUT, &url).send().await {
            Ok(response) if response.status().is_success() => {
                "; the service registration was rolled back".to_string()
            }
            Ok(response) => format!(
                "; rolling the service registration back also failed: HTTP {}",
                response.status()
            ),
            Err(e) => format!("; rolling the service registration back also failed: {}", e),
        }
    }

    /// The KV key mirroring one participant of THIS domain.
    #[cfg(feature = "cloud-discovery")]
    fn kv_path(&self, guid: &[u8; 16]) -> String {
        format!(
            "/kv/hdds/participants/domain-{}/{}",
            self.domain_id,
            to_hex(guid)
        )
    }
}

#[cfg(feature = "cloud-discovery")]
impl CloudDiscovery for ConsulDiscovery {
    async fn register_participant(&self, info: &ParticipantInfo) -> Result<(), Error> {
        let service_id = self.service_id(&info.guid);

        // Address/Port of the Consul service: one routable IPv4 locator,
        // address and port from the same one. No fallback -- see
        // `service_endpoint`.
        let (address, port) = service_endpoint(&info.locators).ok_or_else(|| {
            Error::Config(format!(
                "Consul registration refused: participant {} advertises no usable unicast \
                 IPv4 metatraffic locator -- UDPv4, non-zero port, not 0.0.0.0, not \
                 multicast; loopback counts ({} locator(s) offered)",
                info.name,
                info.locators.len()
            ))
        })?;

        // Build metadata
        let mut meta = HashMap::new();
        meta.insert("guid".to_string(), to_hex(&info.guid));
        meta.insert("domain_id".to_string(), info.domain_id.to_string());
        meta.insert("participant_name".to_string(), info.name.clone());

        // Serialize locators to JSON. The Address/Port pair above carries
        // ONE locator; the (bounded) set lives here and is what a peer
        // reads back in `discover_participants`.
        meta.insert("locators".to_string(), locators_meta(&info.locators)?);

        // Add custom metadata
        for (k, v) in &info.metadata {
            meta.insert(format!("user_{}", k), v.clone());
        }

        // Consul validates the whole map or refuses the whole
        // registration; do it here so the answer names the offender.
        check_meta(&meta)?;

        let check = match self.options.health {
            ConsulHealthPolicy::Ttl => Some(ConsulTtlCheck {
                check_id: self.check_id(&info.guid),
                name: "hdds participant liveness".to_string(),
                ttl: consul_duration(self.ttl()),
                deregister_after: consul_duration(self.deregister_after()),
                status: "passing".to_string(),
            }),
            ConsulHealthPolicy::Disabled => None,
        };

        // Build registration payload
        let registration = ConsulServiceRegistration {
            name: self.options.service_prefix.clone(),
            id: service_id.clone(),
            tags: vec![
                format!("domain-{}", info.domain_id),
                "hdds".to_string(),
                "dds".to_string(),
            ],
            address,
            port,
            meta,
            check,
        };

        // Register with Consul
        let url = self.api_url("/agent/service/register", &[]);
        let response = self
            .request(Method::PUT, &url)
            .json(&registration)
            .send()
            .await
            .map_err(|e| Error::Config(format!("Consul register HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            log::error!("Consul registration failed: {} - {}", status, body);
            return Err(Error::Config(format!(
                "Consul service registration failed: HTTP {} - {}",
                status, body
            )));
        }

        // Mirror the record into the KV store. Its failure is NOT ignored:
        // the mirror is an announced feature, so a refused write is a
        // failed registration that the poller retries and reports, not a
        // silent hole. It also ROLLS THE SERVICE BACK, because a half
        // registration flaps: the poller never marks itself registered,
        // so it never heartbeats, and it re-PUTs the service (Status
        // "passing") on every retry -- once the backoff passes the TTL,
        // every peer watches this participant appear and disappear for
        // ever while `status.registered` stays false.
        if self.options.kv_mirror {
            let kv_data = ConsulKvParticipant {
                guid: to_hex(&info.guid),
                name: info.name.clone(),
                domain_id: info.domain_id,
                locators: info.locators.iter().map(locator_to_consul).collect(),
                metadata: info.metadata.clone(),
            };

            let kv_url = self.api_url(&self.kv_path(&info.guid), &[]);
            let kv_response = self
                .request(Method::PUT, &kv_url)
                .json(&kv_data)
                .send()
                .await
                .map_err(|e| e.to_string());
            let kv_response = match kv_response {
                Ok(response) => response,
                Err(e) => {
                    let rollback = self.rollback_service(&service_id).await;
                    return Err(Error::Config(format!(
                        "Consul KV mirror HTTP request failed: {}{}",
                        e, rollback
                    )));
                }
            };
            if !kv_response.status().is_success() {
                let status = kv_response.status();
                let body = kv_response.text().await.unwrap_or_default();
                let rollback = self.rollback_service(&service_id).await;
                return Err(Error::Config(format!(
                    "Consul KV registration failed: HTTP {} - {} (disable it with \
                     ConsulOptions::with_kv_mirror(false) if this token has no key:write){}",
                    status, body, rollback
                )));
            }
        }

        // Store registered ID for cleanup
        if let Ok(mut guard) = self.registered_id.write() {
            *guard = Some(service_id.clone());
        }

        log::info!(
            "Consul: Registered participant '{}' (ID: {}, domain: {})",
            info.name,
            service_id,
            info.domain_id
        );

        Ok(())
    }

    /// `Some(..)` only once blocking queries are configured AND the
    /// clamp leaves a usable wait, so a poller driving this backend with
    /// the option off keeps the request and the cadence it has today.
    fn blocking_discovery_budget(&self) -> Option<Duration> {
        self.blocking_wait().map(blocking_request_timeout)
    }

    async fn discover_participants(&self) -> Result<Vec<ParticipantInfo>, Error> {
        // Health endpoint, not the catalog: `/v1/catalog/service` returns
        // instances whose checks are critical, so a crashed participant
        // would stay a unicast SPDP destination until Consul's
        // deregister-after timer (one minute at the very least) fired.
        // `passing=true` also keeps instances that registered no check at
        // all (nothing is failing), so a peer running with
        // `ConsulHealthPolicy::Disabled` is still discovered.
        let tag = format!("domain-{}", self.domain_id);
        let mut params: Vec<(&str, &str)> = vec![("tag", tag.as_str()), ("passing", "true")];

        // Blocking query, when the option is on AND a previous answer
        // left an index to wait on. The FIRST query of a process has
        // none: `index=0` means "answer now" to Consul, so sending it
        // would be a plain read dressed up as a long poll. It is left
        // off entirely, the answer seeds the index, and every query
        // after it can block.
        let sent_index = self.last_index.load(Ordering::Relaxed);
        let blocking = self
            .blocking_wait()
            .filter(|_| sent_index > 0)
            .map(|wait| (wait, sent_index.to_string(), consul_duration(wait)));
        if let Some((_, index, wait)) = blocking.as_ref() {
            params.push(("index", index.as_str()));
            params.push(("wait", wait.as_str()));
        }

        let url = self.api_url(
            &format!(
                "/health/service/{}",
                percent_encode(&self.options.service_prefix)
            ),
            &params,
        );

        let mut request = self.request(Method::GET, &url);
        if let Some((wait, _, _)) = blocking.as_ref() {
            // PER-REQUEST, and that is the point. The client was built
            // with `.timeout(REQUEST_TIMEOUT)` (5 s) so that a
            // black-holed agent cannot stall the poller's command loop,
            // and that ceiling has to stay exactly where it is for
            // register, heartbeat, deregister and the KV calls -- it is
            // a safety property, not a default. `RequestBuilder::timeout`
            // overrides the client's value for THIS request only
            // (reqwest 0.12 stores it in the request extensions and
            // `RequestConfig::fetch` reads the request's value first,
            // falling back to the client's), so the long poll gets the
            // bound it needs and nothing else moves.
            request = request.timeout(blocking_request_timeout(*wait));
        }

        let response = request
            .send()
            .await
            .map_err(|e| Error::Config(format!("Consul discovery HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            // A non-2xx is a FAILED poll, not an empty catalog: returning
            // Ok(vec![]) here would make the participant forget every peer
            // the moment the registry hiccups. The poller keeps its last
            // view and the peer lease bounds the staleness.
            return Err(Error::Config(format!(
                "Consul discovery query failed: HTTP {}",
                response.status()
            )));
        }

        // The index travels in the RESPONSE HEADER, never in the body --
        // a client that only reads the body never long-polls at all.
        // Read it BEFORE `json()`, which consumes the response.
        //
        // A blocking query whose wait simply expired answers 200 with the
        // SAME index and the full list. That is a normal answer, not an
        // error and not an empty registry: it flows through the ordinary
        // parse below, the index folds to the value it already had, and
        // the poller records a successful poll returning the same peers.
        let returned_index = response
            .headers()
            .get("X-Consul-Index")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok());
        if let Some(returned) = returned_index {
            self.fold_index(returned, sent_index);
        }

        let entries: Vec<ConsulHealthEntry> = response.json().await.map_err(|e| {
            Error::Config(format!("Consul discovery response JSON parse error: {}", e))
        })?;

        let mut participants = Vec::with_capacity(entries.len());

        for entry in entries {
            let svc = entry.service;
            // Parse GUID from metadata
            let guid_hex = match svc.meta.get("guid") {
                Some(g) => g,
                None => continue,
            };
            let guid_bytes = match from_hex(guid_hex) {
                Some(b) if b.len() == 16 => b,
                _ => continue,
            };
            let mut guid = [0u8; 16];
            guid.copy_from_slice(&guid_bytes);

            // Parse locators from metadata (the full set; Address/Port
            // carry only the first one).
            let locators = svc
                .meta
                .get("locators")
                .and_then(|json| serde_json::from_str::<Vec<ConsulLocator>>(json).ok())
                .map(|cls| cls.iter().filter_map(consul_to_locator).collect())
                .unwrap_or_else(|| {
                    // Fallback: construct locator from service address/port
                    let mut addr = [0u8; 16];
                    if let Ok(ip) = svc.address.parse::<std::net::Ipv4Addr>() {
                        let octets = ip.octets();
                        addr[12..16].copy_from_slice(&octets);
                    }
                    vec![Locator {
                        kind: super::LOCATOR_KIND_UDPV4,
                        port: svc.port as u32,
                        address: addr,
                    }]
                });

            // Parse domain_id
            let domain_id = svc
                .meta
                .get("domain_id")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            // Parse name
            let name = svc
                .meta
                .get("participant_name")
                .cloned()
                .unwrap_or_else(|| svc.id.clone());

            // Extract user metadata
            let mut metadata = HashMap::new();
            for (k, v) in &svc.meta {
                if let Some(key) = k.strip_prefix("user_") {
                    metadata.insert(key.to_string(), v.clone());
                }
            }

            participants.push(ParticipantInfo {
                guid,
                name,
                domain_id,
                locators,
                metadata,
            });
        }

        log::debug!(
            "Consul: Discovered {} participants in domain {}",
            participants.len(),
            self.domain_id
        );

        Ok(participants)
    }

    async fn heartbeat(&self, guid: [u8; 16]) -> Result<(), super::HeartbeatError> {
        if self.options.health == ConsulHealthPolicy::Disabled {
            return Ok(());
        }
        let url = self.api_url(
            &format!(
                "/agent/check/pass/{}",
                percent_encode(&self.check_id(&guid))
            ),
            &[],
        );
        let response = match self.request(Method::PUT, &url).send().await {
            Ok(response) => response,
            Err(e) => {
                // The call did not reach a verdict: the check is presumed
                // to still be there. Reporting "gone" here re-registered
                // the whole service on every network hiccup.
                return Err(super::HeartbeatError::Transient(Error::Config(format!(
                    "Consul check-pass HTTP request failed: {}",
                    e
                ))));
            }
        };
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            let error = Error::Config(format!(
                "Consul TTL check refresh failed: HTTP {} - {}",
                status, body
            ));
            // 404 / 410 = the agent does not know this check any more (it
            // was restarted, or an operator removed the service): that is
            // the ONE status that means "register again". Every other
            // status (403 on a rotated token, 429, 5xx) leaves the record
            // where it is and is retried on the next tick.
            return Err(
                if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
                    super::HeartbeatError::RecordGone(error)
                } else {
                    super::HeartbeatError::Transient(error)
                },
            );
        }
        Ok(())
    }

    async fn deregister_participant(&self, guid: [u8; 16]) -> Result<(), Error> {
        let service_id = self.service_id(&guid);
        let mut failure: Option<String> = None;

        // Deregister service (this also removes its TTL check)
        let url = self.api_url(
            &format!("/agent/service/deregister/{}", percent_encode(&service_id)),
            &[],
        );
        match self.request(Method::PUT, &url).send().await {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => {
                failure = Some(format!(
                    "Consul service deregistration failed: HTTP {}",
                    response.status()
                ));
            }
            Err(e) => {
                failure = Some(format!("Consul deregister HTTP request failed: {}", e));
            }
        }

        // Delete exactly ONE KV entry: the one this backend wrote, for the
        // domain it is configured for. Looping over domains 0..10 would
        // miss every domain >= 10 and issue nine pointless DELETEs against
        // keys owned by nobody.
        if self.options.kv_mirror {
            let kv_url = self.api_url(&self.kv_path(&guid), &[]);
            match self.request(Method::DELETE, &kv_url).send().await {
                Ok(response) if response.status().is_success() => {}
                Ok(response) => {
                    let message = format!(
                        "Consul KV cleanup failed: HTTP {} for {}",
                        response.status(),
                        self.kv_path(&guid)
                    );
                    log::warn!("{}", message);
                    failure.get_or_insert(message);
                }
                Err(e) => {
                    let message = format!("Consul KV cleanup HTTP request failed: {}", e);
                    log::warn!("{}", message);
                    failure.get_or_insert(message);
                }
            }
        }

        // Clear registered ID
        if let Ok(mut guard) = self.registered_id.write() {
            *guard = None;
        }

        match failure {
            Some(message) => {
                log::warn!("Consul: {}", message);
                Err(Error::Config(message))
            }
            None => {
                log::info!("Consul: Deregistered service {}", service_id);
                Ok(())
            }
        }
    }

    async fn health_check(&self) -> Result<bool, Error> {
        // Check Consul agent health
        let url = self.api_url("/agent/self", &[]);

        match self.request(Method::GET, &url).send().await {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(_) => Ok(false),
        }
    }
}

// Stub implementation when cloud-discovery feature is disabled
#[cfg(not(feature = "cloud-discovery"))]
impl CloudDiscovery for ConsulDiscovery {
    async fn register_participant(&self, _info: &ParticipantInfo) -> Result<(), Error> {
        Err(Error::Config(
            "Consul discovery requires the 'cloud-discovery' feature".to_string(),
        ))
    }

    async fn discover_participants(&self) -> Result<Vec<ParticipantInfo>, Error> {
        Err(Error::Config(
            "Consul discovery requires the 'cloud-discovery' feature".to_string(),
        ))
    }

    async fn deregister_participant(&self, _guid: [u8; 16]) -> Result<(), Error> {
        Err(Error::Config(
            "Consul discovery requires the 'cloud-discovery' feature".to_string(),
        ))
    }

    /// Explicit, so the trait default (a silent `Ok`) cannot make a build
    /// without the feature look like a refreshed registration.
    async fn heartbeat(&self, _guid: [u8; 16]) -> Result<(), super::HeartbeatError> {
        Err(super::HeartbeatError::Transient(Error::Config(
            "Consul discovery requires the 'cloud-discovery' feature".to_string(),
        )))
    }
}

#[cfg(all(test, feature = "cloud-discovery"))]
mod blocking_query_tests {
    use super::*;

    fn consul(heartbeat: Duration, requested: Option<Duration>) -> ConsulDiscovery {
        // Through the public builder, so these tests exercise the knob a
        // caller actually reaches for.
        let options = match requested {
            Some(wait) => ConsulOptions::default().with_blocking_queries(wait),
            None => ConsulOptions::default().without_blocking_queries(),
        };
        ConsulDiscovery::new("http://127.0.0.1:8500")
            .expect("loopback endpoint")
            .with_heartbeat_interval(heartbeat)
            .with_options(options)
    }

    /// Off unless asked for: a backend built the way every existing
    /// caller builds one never long-polls, and never tells the poller to
    /// change its cadence.
    #[test]
    fn blocking_queries_are_off_by_default() {
        let default = ConsulDiscovery::new("http://127.0.0.1:8500").expect("loopback endpoint");
        assert_eq!(default.options().blocking_queries, None);
        assert_eq!(default.blocking_wait(), None);
        assert_eq!(default.blocking_discovery_budget(), None);
    }

    /// The clamp, which is what keeps the feature from trading a saved
    /// request for a participant that evicts itself.
    #[test]
    fn the_wait_is_clamped_to_half_the_ttl_that_keeps_this_participant_alive() {
        // Default cadence: TTL 15 s, so a five-minute request is cut to
        // 7.5 s whatever the caller asked for.
        let fast = consul(Duration::from_secs(5), Some(Duration::from_secs(300)));
        assert_eq!(fast.ttl(), Duration::from_secs(15));
        assert_eq!(fast.blocking_wait(), Some(Duration::from_millis(7_500)));

        // A slower cadence has a longer TTL and buys a longer wait: how
        // long this participant may block is decided by how often it has
        // promised to prove it is alive.
        let slow = consul(Duration::from_secs(120), Some(Duration::from_secs(300)));
        assert_eq!(slow.ttl(), Duration::from_secs(360));
        assert_eq!(slow.blocking_wait(), Some(Duration::from_secs(180)));

        // Under the clamp the caller's own figure is honoured unchanged.
        let modest = consul(Duration::from_secs(120), Some(Duration::from_secs(30)));
        assert_eq!(modest.blocking_wait(), Some(Duration::from_secs(30)));

        // A wait this module cannot render honestly reports itself as
        // off instead of being silently rounded up to one second.
        let tiny = consul(Duration::from_secs(120), Some(Duration::from_millis(500)));
        assert_eq!(tiny.blocking_wait(), None);
        assert_eq!(tiny.blocking_discovery_budget(), None);
    }

    /// THE invariant. The poller is one sequential loop, so a blocking
    /// query in flight is time not spent refreshing the TTL check. If
    /// the budget could reach the TTL, a single hung request would let
    /// the check go critical and the participant would disappear from
    /// the catalog it is polling. Swept across the cadences a caller can
    /// actually configure.
    #[test]
    fn blocking_budget_stays_under_the_ttl() {
        for heartbeat_secs in [1u64, 2, 3, 5, 10, 30, 60, 120, 600, 3600] {
            let backend = consul(
                Duration::from_secs(heartbeat_secs),
                Some(Duration::from_secs(86_400)),
            );
            let budget = backend
                .blocking_discovery_budget()
                .expect("blocking enabled");
            let ttl = backend.ttl();
            assert!(
                budget < ttl,
                "heartbeat {}s: budget {:?} must stay under the check TTL {:?}",
                heartbeat_secs,
                budget,
                ttl
            );
            // And it must still clear Consul's own wait*17/16 jitter, or
            // the client would cut off answers Consul was about to send.
            let wait = backend.blocking_wait().expect("blocking enabled");
            assert!(
                budget > wait * BLOCKING_JITTER_NUM / BLOCKING_JITTER_DEN,
                "heartbeat {}s: budget {:?} must clear the jittered wait",
                heartbeat_secs,
                budget
            );
        }
    }

    /// The two guards Consul's documentation requires of a client, at
    /// their exact boundaries.
    #[test]
    fn fold_index_applies_consuls_two_guards() {
        let backend = consul(Duration::from_secs(60), Some(Duration::from_secs(30)));
        let stored = || backend.last_index.load(Ordering::Relaxed);

        // Forward progress is stored as it came.
        backend.fold_index(100, 0);
        assert_eq!(stored(), 100);

        // An unchanged index is the wait-expiry answer: nothing moves.
        backend.fold_index(100, 100);
        assert_eq!(stored(), 100);

        // Backwards means the state was reset: drop to 0 so the next
        // query is a plain read that seeds a fresh index.
        backend.fold_index(99, 100);
        assert_eq!(stored(), 0);

        // Below 1 is clamped to 1 rather than stored as 0, which would
        // make every later query return immediately, for ever.
        backend.fold_index(0, 0);
        assert_eq!(stored(), 1);

        // Both guards at once: 0 clamps to 1, and 1 is still behind the
        // index we sent, so it resets.
        backend.fold_index(0, 5);
        assert_eq!(stored(), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consul_discovery_creation() {
        let discovery = ConsulDiscovery::new("http://localhost:8500").unwrap();
        assert_eq!(discovery.consul_addr, "http://localhost:8500");
        assert_eq!(discovery.options.service_prefix, DEFAULT_SERVICE_PREFIX);
        assert_eq!(discovery.options.health, ConsulHealthPolicy::Ttl);
        assert!(discovery.options.kv_mirror);
        assert!(discovery.options.token.is_none());
    }

    #[test]
    fn test_consul_with_options() {
        let discovery = ConsulDiscovery::new("https://consul:8500")
            .unwrap()
            .with_service_prefix("my-hdds")
            .with_domain_id(42)
            .with_datacenter("dc1");

        assert_eq!(discovery.options.service_prefix, "my-hdds");
        assert_eq!(discovery.domain_id, 42);
        assert_eq!(discovery.options.datacenter.as_deref(), Some("dc1"));

        let bundled = ConsulDiscovery::new("https://consul:8500")
            .unwrap()
            .with_options(
                ConsulOptions::default()
                    .with_service_prefix("bundle")
                    .with_datacenter("dc2")
                    .with_token("t")
                    .with_health(ConsulHealthPolicy::Disabled)
                    .with_kv_mirror(false),
            );
        assert_eq!(bundled.options().service_prefix, "bundle");
        assert_eq!(bundled.options().datacenter.as_deref(), Some("dc2"));
        assert_eq!(bundled.options().token.as_deref(), Some("t"));
        assert_eq!(bundled.options().health, ConsulHealthPolicy::Disabled);
        assert!(!bundled.options().kv_mirror);
    }

    /// The ACL token travels inside `CloudProvider`, which is `Debug` and
    /// reaches log lines: it must never be rendered.
    #[test]
    fn consul_options_debug_redacts_the_acl_token() {
        let options = ConsulOptions::default().with_token("s3cr3t-acl-token");
        let rendered = format!("{:?}", options);
        assert!(
            !rendered.contains("s3cr3t-acl-token"),
            "leaked: {}",
            rendered
        );
        assert!(rendered.contains("<redacted>"), "no marker: {}", rendered);
        assert!(format!("{:?}", ConsulOptions::default()).contains("None"));

        let discovery = ConsulDiscovery::new("https://consul:8500")
            .unwrap()
            .with_options(options);
        assert!(!format!("{:?}", discovery).contains("s3cr3t-acl-token"));
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_to_hex() {
        assert_eq!(to_hex(&[0x01, 0x02, 0xab, 0xcd]), "0102abcd");
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_from_hex() {
        assert_eq!(from_hex("0102abcd"), Some(vec![0x01, 0x02, 0xab, 0xcd]));
        assert_eq!(from_hex("invalid"), None);
        assert_eq!(from_hex("0"), None); // odd length
    }

    /// A service ID hex-encoding `guid[0..8]` = vendor(2) + host_id(4) +
    /// the first two PID bytes, which are ZERO for any PID below 65536,
    /// would be shared by every participant on the host, each replacing the
    /// others in the catalog.
    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn service_id_covers_the_whole_guid_so_same_host_participants_do_not_collide() {
        let discovery = ConsulDiscovery::new("http://localhost:8500").unwrap();
        let mut first = [0u8; 16];
        first[..8].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        first[8..12].copy_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        first[12..].copy_from_slice(&[0, 0, 1, 0xc1]);
        let mut second = first;
        second[8..12].copy_from_slice(&[0x00, 0x02, 0x00, 0x00]);

        assert_eq!(
            discovery.service_id(&first),
            "hdds-participant-010203040506070800010000000001c1"
        );
        assert_ne!(discovery.service_id(&first), discovery.service_id(&second));
        assert_eq!(
            discovery.check_id(&first),
            format!("service:{}", discovery.service_id(&first))
        );
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn api_url_carries_the_datacenter_and_encodes_every_component() {
        let plain = ConsulDiscovery::new("http://localhost:8500/").unwrap();
        assert_eq!(
            plain.api_url("/agent/service/register", &[]),
            "http://localhost:8500/v1/agent/service/register"
        );
        assert_eq!(
            plain.api_url(
                "/health/service/x",
                &[("tag", "domain-39"), ("passing", "true")]
            ),
            "http://localhost:8500/v1/health/service/x?tag=domain-39&passing=true"
        );

        let dc = plain.clone().with_datacenter("dc 1/x");
        assert_eq!(
            dc.api_url("/agent/service/register", &[]),
            "http://localhost:8500/v1/agent/service/register?dc=dc%201%2Fx"
        );
        assert_eq!(
            dc.api_url("/health/service/x", &[("tag", "domain-39")]),
            "http://localhost:8500/v1/health/service/x?dc=dc%201%2Fx&tag=domain-39"
        );
        assert_eq!(
            percent_encode("service:hdds-participant-00"),
            "service%3Ahdds-participant-00"
        );
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn ttl_is_three_heartbeats_with_a_floor_and_a_minute_of_grace() {
        let fast = ConsulDiscovery::new("http://localhost:8500")
            .unwrap()
            .with_heartbeat_interval(Duration::from_millis(200));
        assert_eq!(fast.ttl(), MIN_TTL);
        assert_eq!(fast.deregister_after(), MIN_DEREGISTER_AFTER);

        let slow = ConsulDiscovery::new("http://localhost:8500")
            .unwrap()
            .with_heartbeat_interval(Duration::from_secs(30));
        assert_eq!(slow.ttl(), Duration::from_secs(90));
        assert_eq!(slow.deregister_after(), Duration::from_secs(360));
        assert_eq!(consul_duration(slow.ttl()), "90s");
        assert_eq!(consul_duration(Duration::from_millis(1)), "1s");
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn kv_path_is_the_configured_domain_only() {
        let discovery = ConsulDiscovery::new("http://localhost:8500")
            .unwrap()
            .with_domain_id(39);
        assert_eq!(
            discovery.kv_path(&[0xab; 16]),
            "/kv/hdds/participants/domain-39/abababababababababababababababab"
        );
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn service_endpoint_takes_address_and_port_from_one_routable_locator() {
        let unroutable = Locator {
            kind: super::super::LOCATOR_KIND_UDPV4,
            port: 7400,
            address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let routable = Locator {
            kind: super::super::LOCATOR_KIND_UDPV4,
            port: 7410,
            address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 100],
        };
        assert_eq!(
            service_endpoint(&[unroutable, routable]),
            Some(("192.168.1.100".to_string(), 7410))
        );
        assert_eq!(service_endpoint(&[unroutable]), None);
        assert_eq!(service_endpoint(&[]), None);
    }

    /// Consul refuses a whole registration whose Meta value passes 512
    /// characters; the cap keeps the usable unicast locators (the ones a
    /// peer can send to, and the one Address/Port was taken from) and
    /// drops the tail.
    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn locators_meta_stays_under_the_consul_512_character_cap() {
        let usable = |last: u8, port: u32| Locator {
            kind: super::super::LOCATOR_KIND_UDPV4,
            port,
            address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, last],
        };
        let unusable = Locator {
            kind: super::super::LOCATOR_KIND_UDPV4,
            port: 7400,
            address: [0; 16],
        };

        let seven: Vec<Locator> = (1..=7).map(|i| usable(i, 7400 + i as u32)).collect();
        let json = locators_meta(&seven).unwrap();
        assert!(json.len() <= MAX_META_VALUE_LEN, "{}", json.len());
        assert_eq!(
            serde_json::from_str::<Vec<ConsulLocator>>(&json)
                .unwrap()
                .len(),
            7,
            "seven locators fit and must all be published"
        );

        let twenty: Vec<Locator> = (1..=20).map(|i| usable(i, 7400 + i as u32)).collect();
        let json = locators_meta(&twenty).unwrap();
        assert!(
            json.len() <= MAX_META_VALUE_LEN,
            "{} characters would be refused by the agent",
            json.len()
        );
        let kept: Vec<ConsulLocator> = serde_json::from_str(&json).unwrap();
        assert!(!kept.is_empty() && kept.len() < 20);
        assert_eq!(kept[0].port, 7401, "the first usable locator is kept");

        // The usable ones are serialised first, so an unusable locator in
        // front of the list cannot push the real one out.
        let mut mixed = vec![unusable; 10];
        mixed.push(usable(9, 7499));
        let kept: Vec<ConsulLocator> =
            serde_json::from_str(&locators_meta(&mixed).unwrap()).unwrap();
        assert_eq!(kept[0].port, 7499);
    }

    /// A key Consul refuses fails the whole registration; catching it
    /// here names the offender instead of leaving an opaque 400 the
    /// poller retries for ever.
    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn check_meta_mirrors_consul_key_and_value_limits() {
        let ok = HashMap::from([("guid".to_string(), "ab".repeat(16))]);
        assert!(check_meta(&ok).is_ok());
        assert!(meta_key_is_valid("user_region-1"));
        assert!(!meta_key_is_valid("user_my.key"));
        assert!(!meta_key_is_valid(""));
        assert!(!meta_key_is_valid(&"k".repeat(MAX_META_KEY_LEN + 1)));

        let bad_key = HashMap::from([("user_my.key".to_string(), "v".to_string())]);
        assert!(format!("{}", check_meta(&bad_key).unwrap_err()).contains("user_my.key"));
        let bad_value = HashMap::from([("blob".to_string(), "x".repeat(MAX_META_VALUE_LEN + 1))]);
        assert!(format!("{}", check_meta(&bad_value).unwrap_err()).contains("blob"));
        let ceiling = HashMap::from([("blob".to_string(), "x".repeat(MAX_META_VALUE_LEN))]);
        assert!(check_meta(&ceiling).is_ok());
        let too_many: HashMap<String, String> = (0..MAX_META_PAIRS + 1)
            .map(|i| (format!("k{}", i), "v".to_string()))
            .collect();
        assert!(check_meta(&too_many).is_err());
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_locator_roundtrip() {
        let locator = Locator {
            kind: 1,
            port: 7400,
            address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 1, 50],
        };

        let consul_loc = locator_to_consul(&locator);
        let back = consul_to_locator(&consul_loc).unwrap();

        assert_eq!(locator.kind, back.kind);
        assert_eq!(locator.port, back.port);
        assert_eq!(locator.address, back.address);
    }
}
