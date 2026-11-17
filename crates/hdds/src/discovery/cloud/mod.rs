// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Cloud Discovery for DDS
//!
//! Provides discovery mechanisms for cloud environments where UDP multicast
//! is not available (AWS, Azure, GCP, Kubernetes, etc.).
//!
//! # Supported Backends
//!
//! - **AWS Cloud Map** -- Service discovery for AWS ECS/EKS
//! - **Azure Table Storage** -- participant registry for VM/VMSS/AKS
//! - **Consul** -- HashiCorp Consul service mesh
//!
//! # Architecture
//!
//! ```text
//! CloudDiscovery Trait
//! +-- AwsCloudMap      (AWS Cloud Map + ECS metadata)
//! +-- AzureDiscovery   (Azure Table Storage + Managed Identity)
//! +-- ConsulDiscovery  (Consul KV + Health checks)
//! ```
//!
//! # Example
//!
//! ```ignore
//! use hdds::discovery::cloud::{CloudDiscovery, ConsulDiscovery};
//!
//! let discovery = ConsulDiscovery::new("https://consul.service.consul:8500")?;
//! discovery.register_participant(participant_guid, &locators).await?;
//!
//! let peers = discovery.discover_participants().await?;
//! ```

pub mod aws;
/// AWS Cloud Map JSON 1.1 client (control and data planes).
pub(crate) mod aws_client;
/// AWS credential chain (env, IRSA web identity, ECS container, IMDSv2).
pub(crate) mod aws_credentials;
/// AWS Signature Version 4 request signing.
pub(crate) mod aws_sigv4;
pub mod azure;
/// Credential acquisition for the Azure backend (Managed Identity, AKS
/// Workload Identity, SAS).
#[cfg(feature = "cloud-discovery")]
pub(crate) mod azure_auth;
/// Configuration of the Azure Table Storage backend.
#[cfg(feature = "cloud-discovery")]
pub mod azure_config;
pub mod consul;
#[cfg(all(test, feature = "cloud-discovery"))]
mod consul_tests;
pub mod poller_thread;
pub(crate) mod sha256;

pub use aws::{AwsCloudMap, AwsCloudMapConfig, AwsHealthStatus};
pub use aws_credentials::AwsCredentialSource;
pub use azure::AzureDiscovery;
#[cfg(feature = "cloud-discovery")]
pub use azure_config::{AzureAuth, AzureDiscoveryConfig};
pub use consul::{ConsulDiscovery, ConsulHealthPolicy, ConsulOptions, DEFAULT_SERVICE_PREFIX};
pub(crate) use poller_thread::{
    backend_is_available, provider_label, CloudPeerSink, CloudPollerWiring,
};
pub use poller_thread::{
    CloudCommand, CloudDiscoveryPoller, CloudDiscoveryPollerHandle, CloudDiscoveryStatus,
    CloudEvent, CloudPollerConfig, CloudProvider,
};

use crate::dds::Error;
use std::net::SocketAddr;

/// Locator structure (simplified for cloud discovery)
///
/// Represents a DDS RTPS locator (address + port).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Locator {
    /// Locator kind (1 = UDP, 2 = TCP, etc.)
    pub kind: i32,
    /// Port number
    pub port: u32,
    /// IPv4 or IPv6 address (16 bytes)
    pub address: [u8; 16],
}

/// Participant metadata for cloud discovery
#[derive(Debug, Clone)]
pub struct ParticipantInfo {
    /// Participant GUID
    pub guid: [u8; 16],

    /// Participant name
    pub name: String,

    /// Domain ID
    pub domain_id: u32,

    /// Unicast locators
    pub locators: Vec<Locator>,

    /// Custom metadata (key-value pairs)
    pub metadata: std::collections::HashMap<String, String>,
}

/// Cloud discovery trait
///
/// Backend-agnostic interface for service discovery in cloud environments.
pub trait CloudDiscovery: Send + Sync {
    /// One-shot cold-path warm-up, run by the poller before its first
    /// registration and outside the per-call budget that bounds every
    /// other method.
    ///
    /// A backend resolves here whatever it would otherwise resolve inside
    /// its first `register_participant`: credentials, a service identity,
    /// an instance metadata address. Without that separation the poller's
    /// `REQUEST_TIMEOUT` bounds a CHAIN of calls while the backend's own
    /// retry budget is sized for one, and a degraded metadata service
    /// makes registration structurally unable to finish - every attempt
    /// cancelled mid-chain, nothing cached, for ever.
    ///
    /// Failing here is not fatal: the poller logs it and registers
    /// anyway, resolving lazily as before. The default is a no-op, which
    /// is right for a backend whose registration is already one call.
    fn prepare(&self) -> impl std::future::Future<Output = Result<(), Error>> + Send {
        async { Ok(()) }
    }

    /// Register this participant with the cloud discovery service
    ///
    /// # Arguments
    ///
    /// - `info` -- Participant metadata (GUID, name, locators, etc.)
    fn register_participant(
        &self,
        info: &ParticipantInfo,
    ) -> impl std::future::Future<Output = Result<(), Error>> + Send;

    /// Discover other participants in the same domain
    ///
    /// # Returns
    ///
    /// List of discovered participant metadata
    fn discover_participants(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<ParticipantInfo>, Error>> + Send;

    /// Deregister this participant (cleanup on shutdown)
    fn deregister_participant(
        &self,
        guid: [u8; 16],
    ) -> impl std::future::Future<Output = Result<(), Error>> + Send;

    /// Refresh the liveness of this participant's own registration.
    ///
    /// Called by the poller once per poll interval while the participant
    /// is registered. A backend whose registry expires a record unless it
    /// is refreshed (Consul's TTL check) implements it; a backend whose
    /// records are removed only on request does nothing.
    ///
    /// The two failure kinds are NOT the same event and must not be
    /// reported as one: [`HeartbeatError::RecordGone`] means the registry
    /// no longer holds the record (the caller registers again at once),
    /// while [`HeartbeatError::Transient`] means the call itself failed
    /// (a timeout, a 5xx, a reset) and says nothing about the record. A
    /// backend that reported every failure as "gone" made a participant
    /// re-register once per poll interval against a briefly overloaded
    /// registry it had never left.
    fn heartbeat(
        &self,
        _guid: [u8; 16],
    ) -> impl std::future::Future<Output = Result<(), HeartbeatError>> + Send {
        async { Ok(()) }
    }

    /// Health check (optional, for service mesh integrations)
    fn health_check(&self) -> impl std::future::Future<Output = Result<bool, Error>> + Send {
        async { Ok(true) }
    }

    /// Upper bound on one [`CloudDiscovery::discover_participants`] call
    /// when that call LONG POLLS, and the signal to the poller that it
    /// does.
    ///
    /// `None`, the default, is the plain shape: the call returns as soon
    /// as the registry answers, the poller bounds it with
    /// `poller_thread::REQUEST_TIMEOUT` and then waits a whole
    /// `poll_interval` before asking again.
    ///
    /// `Some(budget)` says the call holds the query open until the
    /// registry has something new to say. Two things follow, and a
    /// poller that does only one of them is worse than not having the
    /// feature: the call must be bounded by `budget` instead of
    /// `REQUEST_TIMEOUT` (which is far shorter than any useful wait, so
    /// every long poll would be cut off), and a SUCCESSFUL call must be
    /// re-issued at once instead of after `poll_interval` (the waiting
    /// now happens inside the call, so sleeping on top of it would ADD
    /// latency to the very thing meant to remove it).
    ///
    /// It is read fresh on every poll, so a backend may answer `None`
    /// while it has no state to block on yet.
    fn blocking_discovery_budget(&self) -> Option<std::time::Duration> {
        None
    }
}

/// Why a liveness heartbeat did not go through.
///
/// The distinction is the whole point: one of the two is a reason to
/// register again, the other is a reason to wait.
#[derive(Debug)]
pub enum HeartbeatError {
    /// The registry does not hold this participant's record any more:
    /// the agent was restarted, an operator removed the service, or the
    /// record was reaped. The caller registers again immediately.
    RecordGone(Error),
    /// The call failed (timeout, 5xx, connection reset, refused token).
    /// The record is presumed to still be there; the caller keeps its
    /// registration and retries on the next tick.
    Transient(Error),
}

impl HeartbeatError {
    /// Does this failure mean the registry lost the record?
    pub fn is_record_gone(&self) -> bool {
        matches!(self, HeartbeatError::RecordGone(_))
    }

    /// The underlying error.
    pub fn error(&self) -> &Error {
        match self {
            HeartbeatError::RecordGone(e) | HeartbeatError::Transient(e) => e,
        }
    }
}

impl std::fmt::Display for HeartbeatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeartbeatError::RecordGone(e) => write!(f, "registration is gone: {}", e),
            HeartbeatError::Transient(e) => write!(f, "{}", e),
        }
    }
}

/// RTPS locator kind for UDPv4 (the only kind the UDP transport sends to).
pub const LOCATOR_KIND_UDPV4: i32 = 1;

/// Helper: Convert a UDPv4 Locator to a SocketAddr.
///
/// Returns `None` for any locator the transport could not send to: a
/// non-UDPv4 kind, a port outside the u16 range, or an address that is
/// not IPv4-mapped. Silently truncating a port or "converting" a UDPv6
/// locator would hand the announcer an address that fails on every send.
pub(crate) fn locator_to_socket_addr(locator: &Locator) -> Option<SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr};

    if locator.kind != LOCATOR_KIND_UDPV4 {
        return None;
    }
    let port = u16::try_from(locator.port).ok()?;
    match locator.address {
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, a, b, c, d] => {
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port))
        }
        _ => None,
    }
}

/// Transport policy for a registry endpoint: TLS everywhere except a
/// loopback host.
///
/// A cloud registry endpoint carries the participant's GUID, its
/// metatraffic locators and, for the managed backends, a bearer token.
/// Plaintext HTTP to a remote host puts all three on the wire in the
/// clear, so it is refused BY CONSTRUCTION: there is no flag, no
/// environment variable and no config field that re-opens it. `http://`
/// stays legal only when the host is a loopback literal (`127.0.0.0/8`,
/// `::1`, `localhost`), which is the sidecar-agent case (a Consul agent
/// on the same host or pod) and the case every hermetic test uses.
///
/// Instance-metadata endpoints (IMDS, `169.254.169.254`) are http by
/// design and never pass through here: they are not registry endpoints.
///
/// Returns the reason as `Err` so each caller can wrap it in its own
/// error type.
pub(crate) fn check_endpoint_transport(endpoint: &str) -> Result<(), String> {
    // Parse with the SAME parser the HTTP client will use (`reqwest::Url`
    // is a re-export of the `url` crate's WHATWG parser). A hand-rolled
    // split on "://" and '/' disagrees with it on the authority
    // terminators the standard defines for special schemes -- notably
    // '\\', so `http://evil.example.com\\@127.0.0.1:8500` reads as host
    // "127.0.0.1" to a naive splitter and as host "evil.example.com" to
    // the client that actually sends the request. One parser, one verdict.
    let url = reqwest::Url::parse(endpoint).map_err(|error| {
        format!(
            "cloud registry endpoint {:?} is not a URL ({}): expected https://host[:port] \
             (http:// only for a loopback host)",
            endpoint, error
        )
    })?;
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            // `host_str()` is the parser's canonical host: an IPv4
            // literal is normalised, a domain is lowercased ASCII, an
            // IPv6 literal keeps its brackets.
            let host = url.host_str().ok_or_else(|| {
                format!(
                    "cloud registry endpoint {:?} has no host: expected https://host[:port] \
                     (http:// only for a loopback host)",
                    endpoint
                )
            })?;
            if host_is_loopback(host) {
                Ok(())
            } else {
                Err(format!(
                    "cloud registry endpoint {:?} is plaintext http to non-loopback host {}: \
                     use https:// (plaintext is accepted only for 127.0.0.0/8, ::1 or localhost)",
                    endpoint, host
                ))
            }
        }
        other => Err(format!(
            "cloud registry endpoint {:?} uses unsupported scheme {:?}: expected https or http \
             (a bare host with no scheme is not an endpoint)",
            endpoint, other
        )),
    }
}

/// Is this canonical host a loopback literal? Only literals count: a
/// name that merely resolves to 127.0.0.1 today can resolve elsewhere
/// tomorrow, so `localhost` is the single accepted name.
fn host_is_loopback(host: &str) -> bool {
    use std::net::{Ipv4Addr, Ipv6Addr};

    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return inner
            .parse::<Ipv6Addr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    }
    host.parse::<Ipv4Addr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Transport policy for an INSTANCE-METADATA endpoint (IMDS, the ECS
/// container credentials endpoint, the ECS task metadata endpoint).
///
/// These are not registry endpoints: they are plaintext `http` by design
/// and they answer with a credential. The rule that protects them is not
/// TLS, it is the ADDRESS: only a link-local host (`169.254.0.0/16`,
/// `fe80::/10`) or a loopback host is accepted. Without it, a config
/// field pointing the credential chain at an arbitrary host turns a
/// misconfiguration - or an SSRF - into credential exfiltration: the
/// chain would happily send the container authorization token, and later
/// the IMDS session token, to whatever answered.
///
/// Returns the reason as `Err` so each caller can wrap it in its own
/// error type.
pub(crate) fn check_metadata_endpoint(endpoint: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(endpoint).map_err(|error| {
        format!(
            "metadata endpoint {:?} is not a URL ({}): expected http://<link-local or loopback host>",
            endpoint, error
        )
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "metadata endpoint {:?} uses unsupported scheme {:?}: expected http or https",
            endpoint,
            url.scheme()
        ));
    }
    let host = url.host_str().ok_or_else(|| {
        format!(
            "metadata endpoint {:?} has no host: expected http://<link-local or loopback host>",
            endpoint
        )
    })?;
    if host_is_loopback(host) || host_is_link_local(host) {
        Ok(())
    } else {
        Err(format!(
            "metadata endpoint {:?} points at {}, which is neither link-local nor loopback: \
             a credential endpoint is accepted only on 169.254.0.0/16, fe80::/10, 127.0.0.0/8 or ::1",
            endpoint, host
        ))
    }
}

/// Is this canonical host a link-local literal (`169.254.0.0/16`,
/// `fe80::/10`)? Only literals count, for the same reason `localhost` is
/// the single accepted loopback name.
fn host_is_link_local(host: &str) -> bool {
    use std::net::{Ipv4Addr, Ipv6Addr};

    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return inner
            .parse::<Ipv6Addr>()
            .map(|ip| (ip.segments()[0] & 0xffc0) == 0xfe80)
            .unwrap_or(false);
    }
    host.parse::<Ipv4Addr>()
        .map(|ip| ip.is_link_local())
        .unwrap_or(false)
}

/// Helper: Convert an IPv4 SocketAddr to a UDPv4 Locator (`None` for IPv6).
pub(crate) fn socket_addr_to_locator(addr: &SocketAddr) -> Option<Locator> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut address = [0u8; 16];
            address[12..].copy_from_slice(&v4.ip().octets());
            Some(Locator {
                kind: LOCATOR_KIND_UDPV4,
                port: u32::from(v4.port()),
                address,
            })
        }
        SocketAddr::V6(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_endpoints_are_accepted_anywhere() {
        for endpoint in [
            "https://consul.service.consul:8500",
            "HTTPS://consul.prod:8500/v1",
            "https://user:pass@consul.prod",
            "https://[2001:db8::1]:8500",
        ] {
            assert!(
                check_endpoint_transport(endpoint).is_ok(),
                "https endpoint refused: {}",
                endpoint
            );
        }
    }

    #[test]
    fn plaintext_endpoint_is_loopback_only_and_has_no_override() {
        for endpoint in [
            "http://127.0.0.1:8500",
            "http://127.9.9.9:8500/v1/agent",
            "http://localhost:8500",
            "http://LocalHost",
            "http://[::1]:8500",
            // The parser canonicalises a short-form IPv4 literal, so the
            // loopback verdict does not depend on how it was written.
            "http://127.1:8500",
        ] {
            assert!(
                check_endpoint_transport(endpoint).is_ok(),
                "loopback plaintext endpoint refused: {}",
                endpoint
            );
        }
        for endpoint in [
            "http://consul.prod:8500",
            "http://10.0.0.5:8500",
            "http://169.254.169.254/metadata",
            "http://localhost.evil.example:8500",
            "http://user@consul.prod:8500",
            "http://[2001:db8::1]:8500",
            // Authority-terminator confusion: a naive split on "://" and
            // '/' reads the host as 127.0.0.1 here, but '\\' ends the
            // authority for a special scheme, so the request really goes
            // to evil.example.com. The guard must agree with the client.
            "http://evil.example.com\\@127.0.0.1:8500",
            // The loopback literal is userinfo, not the host.
            "http://127.0.0.1@evil.example.com:8500",
            // Tab and newline are stripped by the URL parser before the
            // host is read: what is sent is one remote domain.
            "http://127.0.0.1\n.evil.example.com:8500",
            "http://127.0.0.1\t.evil.example.com:8500",
        ] {
            let error = check_endpoint_transport(endpoint)
                .expect_err("plaintext to a non-loopback host must be refused");
            assert!(
                error.contains("plaintext http"),
                "unexpected error for {}: {}",
                endpoint,
                error
            );
        }
    }

    #[test]
    fn endpoint_without_scheme_or_with_a_foreign_scheme_is_refused() {
        // "consul.prod:8500" parses as the foreign scheme "consul.prod":
        // either way it is not an http(s) registry endpoint.
        assert!(check_endpoint_transport("consul.prod:8500")
            .expect_err("a bare host is not an endpoint")
            .contains("unsupported scheme"));
        assert!(check_endpoint_transport("ftp://consul.prod")
            .expect_err("only http(s) is spoken here")
            .contains("unsupported scheme"));
        assert!(check_endpoint_transport("127.0.0.1:8500")
            .expect_err("a bare address is not an endpoint")
            .contains("is not a URL"));
        assert!(check_endpoint_transport("")
            .expect_err("an empty endpoint is not an endpoint")
            .contains("is not a URL"));
    }

    #[test]
    fn test_locator_to_socket_addr_ipv4() {
        let locator = Locator {
            kind: 1,
            port: 7400,
            address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 100],
        };

        let addr = locator_to_socket_addr(&locator).unwrap();
        assert_eq!(addr.to_string(), "192.168.1.100:7400");
        assert_eq!(socket_addr_to_locator(&addr), Some(locator));
    }

    #[test]
    fn locator_to_socket_addr_rejects_non_udpv4_kinds_ports_and_addresses() {
        let good = Locator {
            kind: LOCATOR_KIND_UDPV4,
            port: 7400,
            address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1],
        };
        assert!(locator_to_socket_addr(&good).is_some());
        assert!(locator_to_socket_addr(&Locator { kind: 2, ..good }).is_none());
        assert!(locator_to_socket_addr(&Locator {
            port: 70_000,
            ..good
        })
        .is_none());
        let mut v6 = good;
        v6.address[0] = 0x20;
        assert!(locator_to_socket_addr(&v6).is_none());
        assert!(socket_addr_to_locator(&"[::1]:7410".parse().unwrap()).is_none());
    }

    #[test]
    fn test_participant_info_creation() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("region".to_string(), "us-east-1".to_string());

        let info = ParticipantInfo {
            guid: [0x42; 16],
            name: "test-participant".to_string(),
            domain_id: 0,
            locators: vec![],
            metadata,
        };

        assert_eq!(info.name, "test-participant");
        assert_eq!(info.metadata.get("region").unwrap(), "us-east-1");
    }
}
