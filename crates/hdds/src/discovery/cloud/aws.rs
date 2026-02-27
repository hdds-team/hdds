// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! AWS Cloud Map Discovery
//!
//! Uses AWS Cloud Map for service discovery in ECS/EKS environments.
//!
//! # ⚠️ IMPORTANT: STUB IMPLEMENTATION ⚠️
//!
//! **The `register_participant()` and `discover_participants()` functions are
//! currently stubs that do NOT make actual AWS API calls.**
//!
//! - `register_participant()` logs the attempt but does not register with AWS
//! - `discover_participants()` always returns an empty list
//! - `deregister_participant()` only clears local state
//!
//! To make this module functional, you need to:
//! 1. Add `aws-sdk-servicediscovery` crate as a dependency
//! 2. Implement proper AWS credential loading via `aws-config`
//! 3. Replace the stub implementations with actual AWS SDK calls
//!
//! See the individual function documentation for implementation examples.
//!
//! # Features
//!
//! - **ECS Task Metadata** -- Auto-detect task IP from ECS metadata endpoint
//! - **Cloud Map Registration** -- Register service instances with attributes
//! - **DNS Discovery** -- Resolve peer participants via DNS SRV records
//! - **HTTP Discovery** -- Alternative via Cloud Map DiscoverInstances API
//!
//! # Example
//!
//! ```ignore
//! use hdds::discovery::cloud::AwsCloudMap;
//!
//! let discovery = AwsCloudMap::new("hdds-namespace", "hdds-participants", "us-east-1")?;
//! discovery.register_participant(&info).await?;
//! let peers = discovery.discover_participants().await?;
//! ```

#[cfg(feature = "cloud-discovery")]
use reqwest::Client;
#[cfg(feature = "cloud-discovery")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "cloud-discovery")]
use super::Locator;
use super::{CloudDiscovery, ParticipantInfo};
use crate::dds::Error;
#[cfg(feature = "cloud-discovery")]
use std::collections::HashMap;
#[cfg(feature = "cloud-discovery")]
use std::sync::Arc;
#[cfg(feature = "cloud-discovery")]
use std::sync::RwLock;

/// AWS Cloud Map discovery backend
///
/// Registers participants with AWS Cloud Map and discovers peers via
/// the DiscoverInstances API or DNS-based service discovery.
#[derive(Debug)]
pub struct AwsCloudMap {
    /// Cloud Map namespace name or ID
    #[allow(dead_code)] // Used for API calls when cloud-discovery feature is enabled
    namespace: String,

    /// Cloud Map service name
    #[allow(dead_code)] // Used for API calls when cloud-discovery feature is enabled
    service_name: String,

    /// AWS region
    #[allow(dead_code)] // Used for API calls when cloud-discovery feature is enabled
    region: String,

    /// Domain ID filter
    #[allow(dead_code)] // Used for filtering when cloud-discovery feature is enabled
    domain_id: u32,

    /// HTTP client for Cloud Map API
    #[cfg(feature = "cloud-discovery")]
    client: Client,

    /// Registered instance ID (for deregistration)
    #[cfg(feature = "cloud-discovery")]
    registered_instance: Arc<RwLock<Option<String>>>,

    /// Cached ECS task IP
    #[cfg(feature = "cloud-discovery")]
    ecs_ip: Arc<RwLock<Option<String>>>,
}

// ============================================================================
// AWS API Types (simplified - real impl would use aws-sdk-servicediscovery)
// ============================================================================

#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Serialize)]
#[allow(dead_code)] // API struct for AWS Cloud Map registration
struct CloudMapRegisterRequest {
    #[serde(rename = "ServiceId")]
    service_id: String,
    #[serde(rename = "InstanceId")]
    instance_id: String,
    #[serde(rename = "Attributes")]
    attributes: HashMap<String, String>,
}

#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // API struct for AWS Cloud Map discovery response
struct CloudMapDiscoverResponse {
    #[serde(rename = "Instances")]
    instances: Vec<CloudMapInstance>,
}

#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // API struct for AWS Cloud Map instance
struct CloudMapInstance {
    #[serde(rename = "InstanceId")]
    instance_id: String,
    #[serde(rename = "Attributes")]
    attributes: HashMap<String, String>,
}

#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Deserialize)]
struct EcsTaskMetadata {
    #[serde(rename = "Networks")]
    networks: Option<Vec<EcsNetwork>>,
}

#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Deserialize)]
struct EcsNetwork {
    #[serde(rename = "IPv4Addresses")]
    ipv4_addresses: Option<Vec<String>>,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Encode bytes to hex string
#[cfg(any(feature = "cloud-discovery", test))]
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode hex string to bytes
#[cfg(feature = "cloud-discovery")]
#[allow(dead_code)] // Used by parse_locators for cloud discovery
fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Parse locators from JSON string
#[cfg(feature = "cloud-discovery")]
#[allow(dead_code)] // Used for parsing locators from cloud discovery response
fn parse_locators(json: &str) -> Vec<Locator> {
    #[derive(Deserialize)]
    struct LocatorJson {
        kind: i32,
        port: u32,
        address: String,
    }

    serde_json::from_str::<Vec<LocatorJson>>(json)
        .ok()
        .map(|locs| {
            locs.iter()
                .filter_map(|l| {
                    let bytes = from_hex(&l.address)?;
                    if bytes.len() != 16 {
                        return None;
                    }
                    let mut address = [0u8; 16];
                    address.copy_from_slice(&bytes);
                    Some(Locator {
                        kind: l.kind,
                        port: l.port,
                        address,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Serialize locators to JSON
#[cfg(feature = "cloud-discovery")]
fn serialize_locators(locators: &[Locator]) -> String {
    #[derive(Serialize)]
    struct LocatorJson {
        kind: i32,
        port: u32,
        address: String,
    }

    let locs: Vec<LocatorJson> = locators
        .iter()
        .map(|l| LocatorJson {
            kind: l.kind,
            port: l.port,
            address: to_hex(&l.address),
        })
        .collect();

    serde_json::to_string(&locs).unwrap_or_default()
}

// ============================================================================
// Implementation
// ============================================================================

impl AwsCloudMap {
    /// Create a new AWS Cloud Map discovery backend
    ///
    /// # Arguments
    ///
    /// - `namespace` -- Cloud Map namespace name (e.g., "hdds-namespace")
    /// - `service_name` -- Cloud Map service name (e.g., "hdds-participants")
    /// - `region` -- AWS region (e.g., "us-east-1")
    pub fn new(
        namespace: impl Into<String>,
        service_name: impl Into<String>,
        region: impl Into<String>,
    ) -> Result<Self, Error> {
        #[cfg(feature = "cloud-discovery")]
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|_| Error::Config)?;

        Ok(Self {
            namespace: namespace.into(),
            service_name: service_name.into(),
            region: region.into(),
            domain_id: 0,
            #[cfg(feature = "cloud-discovery")]
            client,
            #[cfg(feature = "cloud-discovery")]
            registered_instance: Arc::new(RwLock::new(None)),
            #[cfg(feature = "cloud-discovery")]
            ecs_ip: Arc::new(RwLock::new(None)),
        })
    }

    /// Set domain ID filter
    pub fn with_domain_id(mut self, domain_id: u32) -> Self {
        self.domain_id = domain_id;
        self
    }

    /// Generate instance ID from GUID
    #[cfg(any(feature = "cloud-discovery", test))]
    fn instance_id(&self, guid: &[u8; 16]) -> String {
        format!("hdds-{}", to_hex(&guid[0..8]))
    }

    /// Get ECS task IP from metadata endpoint
    #[cfg(feature = "cloud-discovery")]
    async fn get_ecs_task_ip(&self) -> Option<String> {
        // Check cache first
        if let Ok(guard) = self.ecs_ip.read() {
            if let Some(ref ip) = *guard {
                return Some(ip.clone());
            }
        }

        // ECS_CONTAINER_METADATA_URI_V4 is set by ECS agent
        let metadata_uri = std::env::var("ECS_CONTAINER_METADATA_URI_V4").ok()?;
        let task_url = format!("{}/task", metadata_uri);

        let response = self.client.get(&task_url).send().await.ok()?;
        let metadata: EcsTaskMetadata = response.json().await.ok()?;

        let ip = metadata
            .networks?
            .first()?
            .ipv4_addresses
            .as_ref()?
            .first()?
            .clone();

        // Cache the result
        if let Ok(mut guard) = self.ecs_ip.write() {
            *guard = Some(ip.clone());
        }

        Some(ip)
    }

    /// Get Cloud Map API endpoint
    #[cfg(feature = "cloud-discovery")]
    fn api_endpoint(&self) -> String {
        format!("https://servicediscovery.{}.amazonaws.com", self.region)
    }
}

#[cfg(feature = "cloud-discovery")]
impl CloudDiscovery for AwsCloudMap {
    /// Register this participant with AWS Cloud Map.
    ///
    /// # ⚠️ WARNING: STUB IMPLEMENTATION ⚠️
    ///
    /// **This function does NOT actually register anything with AWS Cloud Map.**
    ///
    /// Current behavior:
    /// - Logs the registration attempt
    /// - Stores the instance ID locally
    /// - Returns `Ok(())` without making any AWS API calls
    ///
    /// ## What's Missing
    ///
    /// To make this functional, you need to:
    /// 1. Add `aws-sdk-servicediscovery` to dependencies
    /// 2. Implement AWS SigV4 request signing
    /// 3. Call `RegisterInstance` API with proper credentials
    ///
    /// ## Example of Required Implementation
    ///
    /// ```ignore
    /// let config = aws_config::from_env().region(&self.region).load().await;
    /// let client = aws_sdk_servicediscovery::Client::new(&config);
    /// client.register_instance()
    ///     .service_id(&self.service_id)
    ///     .instance_id(&instance_id)
    ///     .set_attributes(Some(attributes))
    ///     .send()
    ///     .await?;
    /// ```
    async fn register_participant(&self, info: &ParticipantInfo) -> Result<(), Error> {
        let instance_id = self.instance_id(&info.guid);

        // Get IP address - try ECS metadata first, then use first locator
        let ip_address = self
            .get_ecs_task_ip()
            .await
            .or_else(|| {
                info.locators.first().and_then(|loc| {
                    if loc.address[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] {
                        Some(format!(
                            "{}.{}.{}.{}",
                            loc.address[12], loc.address[13], loc.address[14], loc.address[15]
                        ))
                    } else {
                        None
                    }
                })
            })
            .unwrap_or_else(|| "127.0.0.1".to_string());

        let port = info.locators.first().map(|l| l.port).unwrap_or(7400);

        // Build attributes for Cloud Map
        let mut attributes = HashMap::new();
        attributes.insert("AWS_INSTANCE_IPV4".to_string(), ip_address.clone());
        attributes.insert("AWS_INSTANCE_PORT".to_string(), port.to_string());
        attributes.insert("GUID".to_string(), to_hex(&info.guid));
        attributes.insert("DOMAIN_ID".to_string(), info.domain_id.to_string());
        attributes.insert("PARTICIPANT_NAME".to_string(), info.name.clone());
        attributes.insert("LOCATORS".to_string(), serialize_locators(&info.locators));

        // Add custom metadata
        for (k, v) in &info.metadata {
            attributes.insert(format!("USER_{}", k.to_uppercase()), v.clone());
        }

        // Note: In production, you would use aws-sdk-servicediscovery crate
        // This is a simplified implementation using direct HTTP calls
        // The actual AWS API requires SigV4 signing which is complex to implement manually

        log::info!(
            "AWS Cloud Map: Registering instance {} (IP: {}, port: {}) in {}/{}",
            instance_id,
            ip_address,
            port,
            self.namespace,
            self.service_name
        );

        // For real implementation, uncomment and use AWS SDK:
        // let config = aws_config::from_env().region(self.region.clone()).load().await;
        // let client = aws_sdk_servicediscovery::Client::new(&config);
        // client.register_instance()
        //     .service_id(&self.service_id)
        //     .instance_id(&instance_id)
        //     .set_attributes(Some(attributes))
        //     .send()
        //     .await?;

        // Store registered instance ID
        if let Ok(mut guard) = self.registered_instance.write() {
            *guard = Some(instance_id.clone());
        }

        // For now, we'll use a DNS-based fallback approach
        // Register via Route 53 (if integrated) or log for manual setup
        log::info!(
            "AWS Cloud Map: Instance {} registered (namespace: {}, service: {})",
            instance_id,
            self.namespace,
            self.service_name
        );

        Ok(())
    }

    /// Discover other participants registered in AWS Cloud Map.
    ///
    /// # ⚠️ WARNING: STUB IMPLEMENTATION ⚠️
    ///
    /// **This function does NOT actually discover anything. It always returns an empty list.**
    ///
    /// Current behavior:
    /// - Logs a debug message
    /// - Returns `Ok(vec![])` (empty vector)
    /// - No AWS API calls are made
    ///
    /// ## What's Missing
    ///
    /// To make this functional, you need to:
    /// 1. Add `aws-sdk-servicediscovery` to dependencies
    /// 2. Implement AWS SigV4 request signing
    /// 3. Call `DiscoverInstances` API with proper credentials
    /// 4. Parse the response and build `ParticipantInfo` structs
    ///
    /// ## Example of Required Implementation
    ///
    /// ```ignore
    /// let config = aws_config::from_env().region(&self.region).load().await;
    /// let client = aws_sdk_servicediscovery::Client::new(&config);
    /// let response = client.discover_instances()
    ///     .namespace_name(&self.namespace)
    ///     .service_name(&self.service_name)
    ///     .query_parameters("DOMAIN_ID", &self.domain_id.to_string())
    ///     .send()
    ///     .await?;
    ///
    /// for instance in response.instances() {
    ///     // Parse attributes and build ParticipantInfo
    /// }
    /// ```
    async fn discover_participants(&self) -> Result<Vec<ParticipantInfo>, Error> {
        // Note: Full implementation requires AWS SDK with SigV4 signing
        // This shows the structure of what the discovery would look like

        log::debug!(
            "AWS Cloud Map: Discovering instances in {}/{}",
            self.namespace,
            self.service_name
        );

        // DNS-based discovery fallback (works without AWS SDK)
        // Query: <service>.<namespace>.local or configured DNS name
        let _dns_name = format!("{}.{}", self.service_name, self.namespace);

        // For DNS-SD, you would resolve SRV records:
        // dig SRV _hdds._tcp.<_dns_name>

        // For HTTP API (requires AWS SDK):
        // let response = client.discover_instances()
        //     .namespace_name(&self.namespace)
        //     .service_name(&self.service_name)
        //     .query_parameters("DOMAIN_ID", &self.domain_id.to_string())
        //     .send()
        //     .await?;

        let participants = Vec::new();

        // Parse discovered instances (placeholder - would come from API response)
        // for instance in response.instances() {
        //     let attrs = instance.attributes();
        //     let guid_hex = attrs.get("GUID")?;
        //     let guid_bytes = from_hex(guid_hex)?;
        //     ... build ParticipantInfo ...
        // }

        log::debug!(
            "AWS Cloud Map: Discovered {} participants",
            participants.len()
        );

        Ok(participants)
    }

    /// Deregister this participant from AWS Cloud Map.
    ///
    /// # ⚠️ WARNING: STUB IMPLEMENTATION ⚠️
    ///
    /// **This function does NOT actually deregister anything from AWS.**
    /// It only clears the locally stored instance ID.
    ///
    /// ## What's Missing
    ///
    /// Requires `aws-sdk-servicediscovery` and `DeregisterInstance` API call.
    async fn deregister_participant(&self, guid: [u8; 16]) -> Result<(), Error> {
        let instance_id = self.instance_id(&guid);

        log::info!(
            "AWS Cloud Map: Deregistering instance {} from {}/{}",
            instance_id,
            self.namespace,
            self.service_name
        );

        // For real implementation with AWS SDK:
        // client.deregister_instance()
        //     .service_id(&self.service_id)
        //     .instance_id(&instance_id)
        //     .send()
        //     .await?;

        // Clear registered instance
        if let Ok(mut guard) = self.registered_instance.write() {
            *guard = None;
        }

        Ok(())
    }

    async fn health_check(&self) -> Result<bool, Error> {
        // Check if we can reach the Cloud Map API endpoint
        let url = format!("{}/", self.api_endpoint());

        match self.client.get(&url).send().await {
            Ok(resp) => {
                // AWS returns 403 for unauthenticated but reachable endpoints
                Ok(resp.status().is_success() || resp.status().as_u16() == 403)
            }
            Err(_) => Ok(false),
        }
    }
}

// Stub implementation when cloud-discovery feature is disabled
#[cfg(not(feature = "cloud-discovery"))]
impl CloudDiscovery for AwsCloudMap {
    /// Register this participant with AWS Cloud Map.
    ///
    /// # ⚠️ WARNING: STUB - FEATURE DISABLED ⚠️
    ///
    /// **This is a no-op.** The `cloud-discovery` feature is not enabled.
    /// Enable it in Cargo.toml: `hdds = { features = ["cloud-discovery"] }`
    async fn register_participant(&self, _info: &ParticipantInfo) -> Result<(), Error> {
        log::warn!("AWS Cloud Map requires 'cloud-discovery' feature");
        Ok(())
    }

    /// Discover other participants registered in AWS Cloud Map.
    ///
    /// # ⚠️ WARNING: STUB - FEATURE DISABLED ⚠️
    ///
    /// **Always returns an empty list.** The `cloud-discovery` feature is not enabled.
    /// Enable it in Cargo.toml: `hdds = { features = ["cloud-discovery"] }`
    async fn discover_participants(&self) -> Result<Vec<ParticipantInfo>, Error> {
        log::warn!("AWS Cloud Map requires 'cloud-discovery' feature");
        Ok(vec![])
    }

    /// Deregister this participant from AWS Cloud Map.
    ///
    /// # ⚠️ WARNING: STUB - FEATURE DISABLED ⚠️
    ///
    /// **This is a no-op.** The `cloud-discovery` feature is not enabled.
    async fn deregister_participant(&self, _guid: [u8; 16]) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_cloud_map_creation() {
        let discovery = AwsCloudMap::new("hdds-ns", "hdds-svc", "us-east-1").unwrap();
        assert_eq!(discovery.namespace, "hdds-ns");
        assert_eq!(discovery.service_name, "hdds-svc");
        assert_eq!(discovery.region, "us-east-1");
    }

    #[test]
    fn test_aws_with_domain() {
        let discovery = AwsCloudMap::new("ns", "svc", "eu-west-1")
            .unwrap()
            .with_domain_id(42);
        assert_eq!(discovery.domain_id, 42);
    }

    #[test]
    fn test_instance_id_generation() {
        let discovery = AwsCloudMap::new("ns", "svc", "us-east-1").unwrap();
        let guid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(discovery.instance_id(&guid), "hdds-0102030405060708");
    }

    #[test]
    fn test_to_hex() {
        assert_eq!(to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_locator_serialization() {
        let locators = vec![Locator {
            kind: 1,
            port: 7400,
            address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 1, 50],
        }];

        let json = serialize_locators(&locators);
        let parsed = parse_locators(&json);

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, 1);
        assert_eq!(parsed[0].port, 7400);
    }
}
