// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! AWS Cloud Map discovery backend.
//!
//! Registers this participant as a Cloud Map instance and discovers its
//! peers with real Cloud Map API calls:
//!
//! | operation | plane | AWS call |
//! |---|---|---|
//! | register | control | `RegisterInstance` |
//! | discover | data | `DiscoverInstances` |
//! | deregister | control | `DeregisterInstance` |
//! | health check | data | `DiscoverInstances` (`MaxResults` 1) |
//! | service lookup | control | `GetService` (id -> NAME) or `ListNamespaces` + `ListServices` (NAME -> id) |
//!
//! A Cloud Map service has TWO identities and they are not
//! interchangeable: `RegisterInstance` and `DeregisterInstance` take the
//! `srv-...` ID, `DiscoverInstances` takes the service NAME. Whichever
//! one is configured, the other is resolved ONCE on the cold path (in
//! `prepare`) and cached. Configuring both - the id plus
//! [`AwsCloudMapConfig::with_service_name`] - is the only form that needs
//! no lookup at all, and therefore the only one whose IAM policy is just
//! the three instance actions.
//!
//! Every call is SigV4-signed (`aws_sigv4`) with credentials from the
//! standard chain (`aws_credentials`: environment, EKS IRSA web identity,
//! ECS container role, IMDSv2). Nothing here touches the RTPS data path:
//! registration and polling are cold-path, and the peers they produce are
//! fed into the SPDP unicast destinations exactly like Discovery Server
//! peers.
//!
//! # Attributes written on an instance
//!
//! | attribute | meaning |
//! |---|---|
//! | `AWS_INSTANCE_IPV4` / `AWS_INSTANCE_PORT` | first metatraffic locator, so a Cloud Map A/SRV service also resolves |
//! | `GUID` | 32 lower-case hex characters, the participant GUID |
//! | `DOMAIN_ID` | DDS domain, also the `DiscoverInstances` query filter |
//! | `PARTICIPANT_NAME` | participant name |
//! | `LOCATORS` | compact `ip:port,ip:port` list of every metatraffic unicast locator |
//! | `USER_<KEY>` | participant metadata |
//!
//! `LOCATORS` is a compact list on purpose: Cloud Map caps an instance at
//! 30 custom attributes and 5000 characters of keys plus values, and a
//! hex-encoded 16-byte address per locator burns that budget on a
//! multi-homed host. Over-budget registrations are REFUSED, never
//! truncated: a truncated locator list is a participant that half exists.
//!
//! # Validation status
//!
//! Proven against an in-process fake Cloud Map endpoint
//! (`test_support::fake_aws`) that verifies the SigV4 signature of every
//! request it receives. NOT validated against a live AWS account.
//!
//! # Example
//!
//! ```ignore
//! use hdds::discovery::cloud::{AwsCloudMap, AwsCloudMapConfig};
//!
//! let discovery = AwsCloudMap::with_config(
//!     AwsCloudMapConfig::new("hdds-namespace", "srv-0123456789abcdef", "eu-west-3")
//!         .with_domain_id(39),
//! )?;
//! discovery.register_participant(&info).await?;
//! let peers = discovery.discover_participants().await?;
//! ```

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::RwLock;

use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::aws_client::{
    CloudMapClient, DeregisterInstanceRequest, DiscoverInstancesRequest, DiscoverInstancesResponse,
    DiscoveredInstance, OperationResponse, Plane, RegisterInstanceRequest, ServiceIdentity,
};
use super::aws_credentials::{AwsCredentialProvider, AwsCredentialSource};
use super::{locator_to_socket_addr, socket_addr_to_locator, CloudDiscovery, Locator};
use super::{ParticipantInfo, LOCATOR_KIND_UDPV4};
use crate::dds::Error;

/// Maximum number of custom (non `AWS_`) attributes on a Cloud Map instance.
pub const MAX_CUSTOM_ATTRIBUTES: usize = 30;
/// Maximum total length of an instance's attribute keys plus values.
pub const MAX_ATTRIBUTE_CHARS: usize = 5000;
/// Maximum length of ONE attribute value (AWS `RegisterInstance`).
pub const MAX_ATTRIBUTE_VALUE_CHARS: usize = 1024;
/// Maximum length of ONE attribute key (AWS `RegisterInstance`).
pub const MAX_ATTRIBUTE_KEY_CHARS: usize = 255;
/// `DiscoverInstances` page size requested (AWS caps it at 1000).
const DISCOVER_MAX_RESULTS: u32 = 1000;
/// Whole-client HTTP timeout; individual calls are shorter still.
const CLIENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Which instances `DiscoverInstances` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AwsHealthStatus {
    /// Every registered instance, healthy or not.
    ///
    /// The default, and the fail-SAFE choice: Cloud Map only knows an
    /// instance is healthy when the service carries a health check, which
    /// is infrastructure the user owns. Filtering on health without one
    /// returns nothing and the participant discovers no peers at all.
    #[default]
    All,
    /// Healthy instances only.
    Healthy,
    /// Healthy instances, or every instance when none is healthy.
    ///
    /// Requires a health check configured on the Cloud Map service.
    HealthyOrElseAll,
}

impl AwsHealthStatus {
    /// The wire value Cloud Map expects.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "ALL",
            Self::Healthy => "HEALTHY",
            Self::HealthyOrElseAll => "HEALTHY_OR_ELSE_ALL",
        }
    }
}

/// Full configuration of the AWS Cloud Map backend.
///
/// `Debug` is derived from the fields' own `Debug`; the only field that
/// could carry a secret is `credentials`, whose `Debug` redacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsCloudMapConfig {
    /// Cloud Map namespace. `DiscoverInstances` matches the namespace HTTP
    /// name, which equals the name it was created with UNLESS the name was
    /// reused, in which case AWS appends a generated hash: pass the HTTP
    /// name from the console when the two differ.
    pub namespace: String,
    /// Cloud Map service: a `srv-...` id, a service ARN, or a service NAME.
    ///
    /// The control plane (`RegisterInstance`, `DeregisterInstance`) takes
    /// the ID and `DiscoverInstances` takes the NAME, so BOTH are always
    /// needed. Configuring the id plus [`Self::service_name`] is the
    /// minimal-IAM form: it needs only `RegisterInstance`,
    /// `DeregisterInstance` and `DiscoverInstances`. An id alone costs one
    /// `GetService` at startup; a NAME alone costs one `ListNamespaces`
    /// plus `ListServices` walk at startup.
    pub service: String,
    /// Service NAME, when [`Self::service`] carries an id or an ARN.
    ///
    /// `DiscoverInstances` takes the name Cloud Map's service was created
    /// with, never its `srv-...` id. Setting this field is what makes the
    /// id form work with no extra IAM action at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    /// AWS region, e.g. `eu-west-3`.
    pub region: String,
    /// DDS domain id written on the instance and used as the
    /// `DiscoverInstances` filter.
    #[serde(default)]
    pub domain_id: u32,
    /// Which instances discovery returns.
    #[serde(default)]
    pub health_status: AwsHealthStatus,
    /// Where credentials come from.
    #[serde(default)]
    pub credentials: AwsCredentialSource,
    /// Replaces both plane endpoints (a VPC endpoint, or a hermetic fake).
    /// Plaintext `http://` is accepted only for a loopback host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_override: Option<String>,
    /// ECS task metadata endpoint (`ECS_CONTAINER_METADATA_URI_V4`).
    ///
    /// Read at construction, never at call time, so a poll cannot pick up
    /// an environment that changed under it. `from_json` fills it from the
    /// same variable `new` does, so the three-argument builder API behaves
    /// like the typed one on ECS.
    #[serde(
        default = "ecs_metadata_uri_from_env",
        skip_serializing_if = "Option::is_none"
    )]
    pub ecs_metadata_uri: Option<String>,
}

impl AwsCloudMapConfig {
    /// A configuration with the default credential chain and health filter.
    pub fn new(
        namespace: impl Into<String>,
        service: impl Into<String>,
        region: impl Into<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            service: service.into(),
            service_name: None,
            region: region.into(),
            domain_id: 0,
            health_status: AwsHealthStatus::default(),
            credentials: AwsCredentialSource::default(),
            endpoint_override: None,
            ecs_metadata_uri: ecs_metadata_uri_from_env(),
        }
    }

    /// Set the service NAME to use on the data plane when
    /// [`Self::service`] carries a `srv-...` id or an ARN.
    pub fn with_service_name(mut self, name: impl Into<String>) -> Self {
        self.service_name = Some(name.into());
        self
    }

    /// The NAME `DiscoverInstances` must be given, when it is already
    /// known without a call: the explicit field, or `service` itself when
    /// that is a name rather than an id or an ARN.
    pub fn known_service_name(&self) -> Option<&str> {
        if let Some(name) = self.service_name.as_deref() {
            return Some(name);
        }
        if self.service.starts_with("srv-") || self.service.starts_with("arn:") {
            return None;
        }
        Some(self.service.as_str())
    }

    /// Set the DDS domain id filter.
    pub fn with_domain_id(mut self, domain_id: u32) -> Self {
        self.domain_id = domain_id;
        self
    }

    /// Set which instances discovery returns.
    pub fn with_health_status(mut self, health_status: AwsHealthStatus) -> Self {
        self.health_status = health_status;
        self
    }

    /// Set where credentials come from.
    pub fn with_credentials(mut self, credentials: AwsCredentialSource) -> Self {
        self.credentials = credentials;
        self
    }

    /// Override both plane endpoints.
    pub fn with_endpoint_override(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint_override = Some(endpoint.into());
        self
    }

    /// Parse a configuration from JSON.
    ///
    /// Accepts the three-field form `with_aws_cloud_map` writes
    /// (`{"namespace":...,"service":...,"region":...}`) and fills every
    /// other field with its default, which is what "the existing
    /// three-argument API maps to env-derived defaults" means.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let config: Self = serde_json::from_str(json).map_err(|e| {
            Error::Config(format!("aws cloud discovery config JSON is invalid: {}", e))
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Render as JSON. Never call this on a config whose credentials are
    /// `Static`: use [`Self::redacted_json`] for anything a user can read.
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|e| {
            Error::Config(format!(
                "aws cloud discovery config could not be serialised: {}",
                e
            ))
        })
    }

    /// The identity of this configuration with no credential material:
    /// what a public accessor or a log line may carry.
    ///
    /// The credential source appears only as a redacted SUMMARY, under a
    /// key `credentials_source` that [`Self::from_json`] ignores, so
    /// re-parsing this form yields the default credential chain rather
    /// than a config that pretends to carry credentials it does not.
    pub fn redacted_json(&self) -> String {
        format!(
            r#"{{"namespace":{},"service":{},"service_name":{},"region":{},"domain_id":{},"health_status":"{}","credentials_source":"{}"}}"#,
            json_string(&self.namespace),
            json_string(&self.service),
            match self.service_name.as_deref() {
                Some(name) => json_string(name),
                None => "null".to_string(),
            },
            json_string(&self.region),
            self.domain_id,
            self.health_status.as_str(),
            self.credentials.redacted_summary()
        )
    }

    /// Reject a configuration that cannot produce a working backend.
    pub fn validate(&self) -> Result<(), Error> {
        for (name, value) in [
            ("namespace", &self.namespace),
            ("service", &self.service),
            ("region", &self.region),
        ] {
            if value.trim().is_empty() {
                return Err(Error::Config(format!(
                    "aws cloud discovery config field {:?} is empty",
                    name
                )));
            }
        }
        if let Some(endpoint) = self.endpoint_override.as_deref() {
            super::check_endpoint_transport(endpoint).map_err(Error::Config)?;
        }
        if let Some(name) = self.service_name.as_deref() {
            if name.trim().is_empty() {
                return Err(Error::Config(
                    "aws cloud discovery config field \"service_name\" is empty".to_string(),
                ));
            }
            let service_is_a_name =
                !self.service.starts_with("srv-") && !self.service.starts_with("arn:");
            if service_is_a_name && name != self.service {
                return Err(Error::Config(format!(
                    "aws cloud discovery config sets service {:?} and service_name {:?}: \
                     when `service` is a NAME rather than a srv- id or an ARN the two must \
                     agree, otherwise registration and discovery would target two services",
                    self.service, name
                )));
            }
        }
        if let Some(uri) = self.ecs_metadata_uri.as_deref() {
            super::check_metadata_endpoint(uri).map_err(|e| {
                Error::Config(format!("aws cloud discovery ECS metadata endpoint: {}", e))
            })?;
        }
        Ok(())
    }
}

/// `ECS_CONTAINER_METADATA_URI_V4`, the ECS / Fargate task metadata
/// endpoint. One function, used by BOTH `new` and serde's `default`, so
/// the typed API and the three-argument API cannot disagree about it.
fn ecs_metadata_uri_from_env() -> Option<String> {
    std::env::var("ECS_CONTAINER_METADATA_URI_V4").ok()
}

/// Minimal JSON string escaping for [`AwsCloudMapConfig::redacted_json`].
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// AWS Cloud Map discovery backend.
#[derive(Debug)]
pub struct AwsCloudMap {
    config: AwsCloudMapConfig,
    client: CloudMapClient,
    http: Client,
    /// Instance id registered by this backend, cleared on deregistration.
    registered_instance: RwLock<Option<String>>,
    /// ECS task IP, fetched once.
    ecs_ip: RwLock<Option<Option<String>>>,
}

impl AwsCloudMap {
    /// Build a backend from namespace, service and region, with the
    /// default credential chain and health filter.
    pub fn new(
        namespace: impl Into<String>,
        service: impl Into<String>,
        region: impl Into<String>,
    ) -> Result<Self, Error> {
        Self::with_config(AwsCloudMapConfig::new(namespace, service, region))
    }

    /// Build a backend from a full configuration.
    pub fn with_config(config: AwsCloudMapConfig) -> Result<Self, Error> {
        config.validate()?;
        // `.no_proxy()`: a registry endpoint is reached directly, never
        // through whatever HTTP_PROXY happens to name (same rule as the
        // Consul client; it also keeps loopback fakes hermetic).
        let http = Client::builder()
            .no_proxy()
            .timeout(CLIENT_TIMEOUT)
            .build()
            .map_err(|e| Error::Config(format!("failed to build AWS HTTP client: {}", e)))?;
        let credentials =
            AwsCredentialProvider::new(config.credentials.clone(), config.region.clone());
        let client = CloudMapClient::new(
            http.clone(),
            config.region.clone(),
            config.endpoint_override.as_deref(),
            credentials,
        )?;
        Ok(Self {
            config,
            client,
            http,
            registered_instance: RwLock::new(None),
            ecs_ip: RwLock::new(None),
        })
    }

    /// Set the DDS domain id filter.
    pub fn with_domain_id(mut self, domain_id: u32) -> Self {
        self.config.domain_id = domain_id;
        self
    }

    /// The configuration in use.
    pub fn config(&self) -> &AwsCloudMapConfig {
        &self.config
    }

    /// The instance id currently registered, if any.
    pub fn registered_instance_id(&self) -> Option<String> {
        self.registered_instance
            .read()
            .ok()
            .and_then(|guard| guard.clone())
    }

    /// The service id AND name, resolved once and cached.
    ///
    /// The two are not interchangeable: `RegisterInstance` takes the id,
    /// `DiscoverInstances` takes the name. Sending an id where AWS wants
    /// the name is a registration that succeeds followed by a discovery
    /// that returns nothing, for ever.
    async fn service_identity(&self) -> Result<ServiceIdentity, Error> {
        self.client
            .resolve_service(
                &self.config.namespace,
                &self.config.service,
                self.config.known_service_name(),
            )
            .await
    }

    /// Instance id derived from a GUID.
    ///
    /// The FULL 12-byte prefix plus the 4-byte entity id is hex-encoded:
    /// two participants on the same host in the same second share the
    /// first 8 bytes of their GUID, so a shorter id silently collides and
    /// one participant deregisters the other.
    fn instance_id(&self, guid: &[u8; 16]) -> String {
        format!("hdds-{}", hex(guid))
    }

    /// ECS task IPv4, fetched once from the task metadata endpoint.
    async fn ecs_task_ip(&self) -> Option<String> {
        if let Ok(guard) = self.ecs_ip.read() {
            if let Some(cached) = guard.as_ref() {
                return cached.clone();
            }
        }
        let fetched = self.fetch_ecs_task_ip().await;
        if let Ok(mut guard) = self.ecs_ip.write() {
            *guard = Some(fetched.clone());
        }
        fetched
    }

    async fn fetch_ecs_task_ip(&self) -> Option<String> {
        #[derive(Deserialize)]
        struct TaskMetadata {
            #[serde(rename = "Networks")]
            networks: Option<Vec<Network>>,
        }
        #[derive(Deserialize)]
        struct Network {
            #[serde(rename = "IPv4Addresses")]
            ipv4_addresses: Option<Vec<String>>,
        }

        let base = self.config.ecs_metadata_uri.as_deref()?;
        let url = format!("{}/task", base.trim_end_matches('/'));
        let response = self
            .http
            .get(&url)
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            log::warn!(
                "[CLOUD-DISCOVERY] ECS task metadata {} returned {}",
                url,
                response.status()
            );
            return None;
        }
        let metadata: TaskMetadata = response.json().await.ok()?;
        metadata
            .networks?
            .first()?
            .ipv4_addresses
            .as_ref()?
            .first()
            .cloned()
    }

    /// Build the attribute map for one participant, enforcing the Cloud
    /// Map limits BEFORE anything is sent.
    async fn attributes(&self, info: &ParticipantInfo) -> Result<HashMap<String, String>, Error> {
        // `SocketAddrV4`, not `SocketAddr`: `locator_to_socket_addr` only
        // ever yields UDPv4, and narrowing the type here means the IPv4
        // address below is a value, not a match arm with an unreachable
        // branch to defend.
        let routable: Vec<SocketAddrV4> = info
            .locators
            .iter()
            .filter_map(locator_to_socket_addr)
            .filter_map(|addr| match addr {
                SocketAddr::V4(v4) => Some(v4),
                SocketAddr::V6(_) => None,
            })
            .collect();
        let Some(&primary) = routable.first() else {
            return Err(Error::Config(
                "AWS Cloud Map registration has no routable UDPv4 metatraffic locator: \
                 registering an instance a peer cannot reach is worse than not registering"
                    .to_string(),
            ));
        };

        // The address a peer should contact. An ECS task advertises its
        // task ENI address when the metadata endpoint offers one AND that
        // address is one of the locators we actually bound; otherwise the
        // first routable locator wins. The instance's own metadata IP is
        // never advertised blind.
        let ecs_ip = self
            .ecs_task_ip()
            .await
            .and_then(|ip| ip.parse::<Ipv4Addr>().ok());
        let advertised = match ecs_ip {
            Some(ip) => match routable.iter().find(|addr| *addr.ip() == ip) {
                Some(addr) => *addr,
                None => {
                    log::warn!(
                        "[CLOUD-DISCOVERY] ECS task IP {} is not among this participant's \
                         metatraffic locators; advertising {} instead",
                        ip,
                        primary
                    );
                    primary
                }
            },
            None => primary,
        };

        let mut attributes = HashMap::new();
        attributes.insert("AWS_INSTANCE_IPV4".to_string(), advertised.ip().to_string());
        attributes.insert(
            "AWS_INSTANCE_PORT".to_string(),
            advertised.port().to_string(),
        );
        attributes.insert("GUID".to_string(), hex(&info.guid));
        attributes.insert("DOMAIN_ID".to_string(), info.domain_id.to_string());
        attributes.insert("PARTICIPANT_NAME".to_string(), info.name.clone());
        attributes.insert("LOCATORS".to_string(), encode_locators(&routable));
        for (key, value) in &info.metadata {
            attributes.insert(format!("USER_{}", key.to_uppercase()), value.clone());
        }

        check_attribute_limits(&attributes)?;
        Ok(attributes)
    }
}

/// Lower-case hex of a byte slice.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Compact `ip:port,ip:port` rendering of the metatraffic locators.
fn encode_locators(locators: &[SocketAddrV4]) -> String {
    locators
        .iter()
        .map(|addr| addr.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Parse the compact locator list back. Unparseable entries are dropped
/// (a peer with one bad locator is still reachable on the others).
fn decode_locators(value: &str) -> Vec<Locator> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| entry.parse::<SocketAddr>().ok())
        .filter_map(|addr| socket_addr_to_locator(&addr))
        .collect()
}

/// Is this a legal Cloud Map attribute KEY (`^[a-zA-Z0-9!-~]+$`)?
fn key_is_legal(key: &str) -> bool {
    !key.is_empty() && key.chars().all(|c| ('!'..='~').contains(&c))
}

/// Is this a legal Cloud Map attribute VALUE? Printable ASCII, spaces and
/// tabs allowed inside but never at either end, empty allowed.
fn value_is_legal(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    if !value
        .chars()
        .all(|c| ('!'..='~').contains(&c) || c == ' ' || c == '\t')
    {
        return false;
    }
    let first = value.chars().next();
    let last = value.chars().next_back();
    !matches!(first, Some(' ') | Some('\t')) && !matches!(last, Some(' ') | Some('\t'))
}

/// Refuse an attribute map Cloud Map would reject or silently truncate.
fn check_attribute_limits(attributes: &HashMap<String, String>) -> Result<(), Error> {
    // Per-attribute rules first: they name ONE offending key, which is
    // what an operator can act on. AWS answers `InvalidInput` for each of
    // them, and answering it locally keeps the promise that an
    // out-of-budget registration is refused here rather than half applied
    // on the other side.
    for (key, value) in attributes {
        if key.chars().count() > MAX_ATTRIBUTE_KEY_CHARS || !key_is_legal(key) {
            return Err(Error::Config(format!(
                "AWS Cloud Map attribute key {:?} is not registrable: a key is 1 to {} \
                 printable ASCII characters with no space (AWS pattern [a-zA-Z0-9!-~]+): \
                 rename the participant metadata entry",
                key, MAX_ATTRIBUTE_KEY_CHARS
            )));
        }
        if value.chars().count() > MAX_ATTRIBUTE_VALUE_CHARS {
            return Err(Error::Config(format!(
                "AWS Cloud Map attribute {:?} is {} characters, the per-value limit is {}: \
                 a multi-homed host should restrict its metatraffic locators \
                 (HDDS_INTERFACE_ALLOW) rather than register a truncated value",
                key,
                value.chars().count(),
                MAX_ATTRIBUTE_VALUE_CHARS
            )));
        }
        if !value_is_legal(value) {
            return Err(Error::Config(format!(
                "AWS Cloud Map attribute {:?} has a value AWS refuses: printable ASCII, \
                 with spaces and tabs allowed inside but not at either end \
                 (no control character, no leading or trailing blank)",
                key
            )));
        }
    }
    let custom = attributes
        .keys()
        .filter(|key| !key.starts_with("AWS_"))
        .count();
    if custom > MAX_CUSTOM_ATTRIBUTES {
        return Err(Error::Config(format!(
            "AWS Cloud Map instance would carry {} custom attributes, the limit is {}: \
             reduce the participant metadata",
            custom, MAX_CUSTOM_ATTRIBUTES
        )));
    }
    let chars: usize = attributes
        .iter()
        .map(|(key, value)| key.chars().count() + value.chars().count())
        .sum();
    if chars > MAX_ATTRIBUTE_CHARS {
        return Err(Error::Config(format!(
            "AWS Cloud Map instance attributes total {} characters, the limit is {}: \
             a multi-homed host should restrict its metatraffic locators \
             (HDDS_INTERFACE_ALLOW) rather than register a truncated locator list",
            chars, MAX_ATTRIBUTE_CHARS
        )));
    }
    Ok(())
}

/// Build a `ParticipantInfo` from one discovered instance.
///
/// Returns `None` for an instance that is not an HDDS participant of this
/// domain, or whose GUID is unusable: a half-parsed peer is worse than no
/// peer, because the announcer would unicast SPDP at an address nothing
/// answers on.
pub(crate) fn parse_instance(
    instance: &DiscoveredInstance,
    domain_id: u32,
) -> Option<ParticipantInfo> {
    let attributes = &instance.attributes;
    let guid_hex = attributes.get("GUID")?;
    let guid = parse_guid(guid_hex)?;

    let instance_domain: u32 = attributes.get("DOMAIN_ID")?.trim().parse().ok()?;
    if instance_domain != domain_id {
        return None;
    }

    let mut locators = attributes
        .get("LOCATORS")
        .map(|value| decode_locators(value))
        .unwrap_or_default();
    if locators.is_empty() {
        locators = fallback_locator(attributes).into_iter().collect();
    }
    if locators.is_empty() {
        log::debug!(
            "[CLOUD-DISCOVERY] Cloud Map instance {} has no usable locator; ignored",
            instance.instance_id
        );
        return None;
    }

    let metadata = attributes
        .iter()
        .filter_map(|(key, value)| {
            key.strip_prefix("USER_")
                .map(|stripped| (stripped.to_lowercase(), value.clone()))
        })
        .collect();

    Some(ParticipantInfo {
        guid,
        name: attributes
            .get("PARTICIPANT_NAME")
            .cloned()
            .unwrap_or_else(|| instance.instance_id.clone()),
        domain_id: instance_domain,
        locators,
        metadata,
    })
}

/// 32 lower- or upper-case hex characters -> a GUID.
fn parse_guid(value: &str) -> Option<[u8; 16]> {
    let value = value.trim();
    if value.len() != 32 {
        return None;
    }
    let mut guid = [0u8; 16];
    for (index, byte) in guid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(value.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(guid)
}

/// `AWS_INSTANCE_IPV4` + `AWS_INSTANCE_PORT` when no `LOCATORS` attribute
/// was written (an instance registered by something other than HDDS, or an
/// older HDDS).
fn fallback_locator(attributes: &HashMap<String, String>) -> Option<Locator> {
    let ip: Ipv4Addr = attributes.get("AWS_INSTANCE_IPV4")?.trim().parse().ok()?;
    let port: u16 = attributes.get("AWS_INSTANCE_PORT")?.trim().parse().ok()?;
    let mut address = [0u8; 16];
    address[12..].copy_from_slice(&ip.octets());
    Some(Locator {
        kind: LOCATOR_KIND_UDPV4,
        port: u32::from(port),
        address,
    })
}

impl CloudDiscovery for AwsCloudMap {
    /// Cold-path warm-up, run once by the poller OUTSIDE its per-call
    /// budget: resolve the credentials, the service identity and the ECS
    /// task IP, so that a later `register_participant` is ONE Cloud Map
    /// operation and fits in the poller's `REQUEST_TIMEOUT` the way the
    /// retry budget assumes. Without it, a degraded metadata service or a
    /// slow `ListServices` makes registration structurally unable to
    /// finish: every attempt is cancelled mid-chain and nothing is cached.
    async fn prepare(&self) -> Result<(), Error> {
        self.client.warm_credentials().await?;
        let identity = self.service_identity().await?;
        // Not fatal, and not on the registration path: an instance that
        // cannot read its task metadata advertises its first bound
        // locator instead.
        let _ = self.ecs_task_ip().await;
        log::debug!(
            "[CLOUD-DISCOVERY] AWS Cloud Map ready: service {} (id {}) in namespace {}",
            identity.name,
            identity.id,
            self.config.namespace
        );
        Ok(())
    }

    async fn register_participant(&self, info: &ParticipantInfo) -> Result<(), Error> {
        let instance_id = self.instance_id(&info.guid);
        let attributes = self.attributes(info).await?;
        let service_id = self.service_identity().await?.id;

        let response: OperationResponse = self
            .client
            .call(
                Plane::Control,
                "RegisterInstance",
                &RegisterInstanceRequest {
                    service_id: service_id.clone(),
                    instance_id: instance_id.clone(),
                    // Idempotency token: re-registering the same
                    // participant with the same attributes is a no-op, so
                    // the poller's retry loop cannot create duplicates.
                    creator_request_id: instance_id.clone(),
                    attributes,
                },
            )
            .await?;

        if let Ok(mut guard) = self.registered_instance.write() {
            *guard = Some(instance_id.clone());
        }
        log::info!(
            "[CLOUD-DISCOVERY] AWS Cloud Map: registered instance {} in {}/{} (operation {})",
            instance_id,
            self.config.namespace,
            service_id,
            response.operation_id.as_deref().unwrap_or("-")
        );
        Ok(())
    }

    async fn discover_participants(&self) -> Result<Vec<ParticipantInfo>, Error> {
        let service_name = self.service_identity().await?.name;
        let mut query_parameters = HashMap::new();
        query_parameters.insert("DOMAIN_ID".to_string(), self.config.domain_id.to_string());
        let response: DiscoverInstancesResponse = self
            .client
            .call(
                Plane::Data,
                "DiscoverInstances",
                &DiscoverInstancesRequest {
                    namespace_name: self.config.namespace.clone(),
                    service_name,
                    query_parameters,
                    health_status: self.config.health_status.as_str().to_string(),
                    max_results: DISCOVER_MAX_RESULTS,
                },
            )
            .await?;

        let participants: Vec<ParticipantInfo> = response
            .instances
            .iter()
            .filter_map(|instance| parse_instance(instance, self.config.domain_id))
            .collect();
        log::debug!(
            "[CLOUD-DISCOVERY] AWS Cloud Map: {} of {} instances are domain-{} participants",
            participants.len(),
            response.instances.len(),
            self.config.domain_id
        );
        // `DiscoverInstances` has no continuation token: 1000 is the whole
        // answer AWS will ever give. A domain that reaches it loses peers
        // silently, which reads as intermittent discovery failure, so it
        // is reported once per poll that hits the cap.
        let at_cap = u32::try_from(response.instances.len())
            .map_or(true, |count| count >= DISCOVER_MAX_RESULTS);
        if at_cap {
            log::warn!(
                "[CLOUD-DISCOVERY] AWS Cloud Map returned {} instances, the DiscoverInstances \
                 cap ({}): peers beyond it are invisible to this participant. Split the domain \
                 across services or namespaces.",
                response.instances.len(),
                DISCOVER_MAX_RESULTS
            );
        }
        Ok(participants)
    }

    async fn deregister_participant(&self, guid: [u8; 16]) -> Result<(), Error> {
        let instance_id = self.instance_id(&guid);
        let service_id = self.service_identity().await?.id;
        let result: Result<OperationResponse, Error> = self
            .client
            .call(
                Plane::Control,
                "DeregisterInstance",
                &DeregisterInstanceRequest {
                    service_id,
                    instance_id: instance_id.clone(),
                },
            )
            .await;

        // The local state is cleared whatever AWS answered: keeping a
        // deregistered id would make a later shutdown retry an instance
        // this participant no longer owns.
        if let Ok(mut guard) = self.registered_instance.write() {
            *guard = None;
        }
        result.map(|_| ()).map_err(|e| {
            log::warn!(
                "[CLOUD-DISCOVERY] AWS Cloud Map: deregistering {} failed: {}",
                instance_id,
                e
            );
            e
        })?;
        log::info!(
            "[CLOUD-DISCOVERY] AWS Cloud Map: deregistered instance {}",
            instance_id
        );
        Ok(())
    }

    /// Health check = one signed `DiscoverInstances` with `MaxResults` 1.
    ///
    /// It proves what actually matters: credentials resolve, the clock is
    /// inside the SigV4 window, the endpoint answers, and the IAM policy
    /// grants the operation the poller runs. It is deliberately NOT
    /// `ListNamespaces`, which would demand an IAM action a minimal policy
    /// does not grant and would report "unhealthy" for a perfectly working
    /// deployment.
    async fn health_check(&self) -> Result<bool, Error> {
        let service_name = match self.service_identity().await {
            Ok(identity) => identity.name,
            Err(e) => {
                log::warn!(
                    "[CLOUD-DISCOVERY] AWS Cloud Map health check could not resolve the \
                     service: {}",
                    e
                );
                return Ok(false);
            }
        };
        let response: Result<DiscoverInstancesResponse, Error> = self
            .client
            .call(
                Plane::Data,
                "DiscoverInstances",
                &DiscoverInstancesRequest {
                    namespace_name: self.config.namespace.clone(),
                    service_name,
                    query_parameters: HashMap::new(),
                    health_status: self.config.health_status.as_str().to_string(),
                    max_results: 1,
                },
            )
            .await;
        match response {
            Ok(_) => Ok(true),
            Err(e) => {
                log::warn!("[CLOUD-DISCOVERY] AWS Cloud Map health check failed: {}", e);
                Ok(false)
            }
        }
    }
}

/// `AwsCloudMap` holds only `Send + Sync` state; the trait requires it.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AwsCloudMap>();
};

#[cfg(test)]
#[path = "aws_tests.rs"]
mod tests;
