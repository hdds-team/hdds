// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Consul Service Discovery
//!
//! Uses HashiCorp Consul for service discovery in Kubernetes, on-prem, and
//! hybrid cloud environments.
//!
//! # Features
//!
//! - **Service Registration** -- Register participant as Consul service
//! - **Health Checks** -- HTTP/TCP health check endpoints
//! - **KV Store** -- Store participant metadata (GUID, domain, locators)
//! - **Blocking Queries** -- Efficient long-poll for real-time discovery
//!
//! # Example
//!
//! ```ignore
//! use hdds::discovery::cloud::ConsulDiscovery;
//!
//! let discovery = ConsulDiscovery::new("http://consul.service.consul:8500")?;
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

/// Consul Service Discovery backend
///
/// Registers participants with Consul's service catalog and discovers peers
/// via Consul's HTTP API.
#[derive(Debug, Clone)]
pub struct ConsulDiscovery {
    /// Consul HTTP API endpoint
    #[allow(dead_code)] // Used when cloud-discovery feature is enabled
    consul_addr: String,

    /// Consul service name prefix
    #[allow(dead_code)] // Used when cloud-discovery feature is enabled
    service_prefix: String,

    /// Domain ID filter
    #[allow(dead_code)] // Used when cloud-discovery feature is enabled
    domain_id: u32,

    /// Consul datacenter (optional)
    #[allow(dead_code)] // Used when cloud-discovery feature is enabled
    datacenter: Option<String>,

    /// Health check port (optional)
    #[allow(dead_code)] // Used when cloud-discovery feature is enabled
    health_check_port: Option<u16>,

    /// HTTP client
    #[cfg(feature = "cloud-discovery")]
    client: Client,

    /// Registered service ID (for cleanup)
    #[cfg(feature = "cloud-discovery")]
    registered_id: Arc<RwLock<Option<String>>>,
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
    check: Option<ConsulHealthCheck>,
}

#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Serialize)]
struct ConsulHealthCheck {
    #[serde(rename = "HTTP", skip_serializing_if = "Option::is_none")]
    http: Option<String>,
    #[serde(rename = "TCP", skip_serializing_if = "Option::is_none")]
    tcp: Option<String>,
    #[serde(rename = "Interval")]
    interval: String,
    #[serde(rename = "Timeout")]
    timeout: String,
    #[serde(rename = "DeregisterCriticalServiceAfter")]
    deregister_after: String,
}

#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Struct fields used for deserialization from Consul API response
struct ConsulCatalogService {
    #[serde(rename = "ServiceID")]
    service_id: String,
    #[serde(rename = "ServiceName")]
    service_name: String,
    #[serde(rename = "ServiceAddress")]
    service_address: String,
    #[serde(rename = "ServicePort")]
    service_port: u16,
    #[serde(rename = "ServiceTags")]
    service_tags: Vec<String>,
    #[serde(rename = "ServiceMeta")]
    service_meta: HashMap<String, String>,
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

/// Extract IPv4 address from locator (first unicast locator)
#[cfg(feature = "cloud-discovery")]
fn extract_ipv4(locators: &[Locator]) -> Option<String> {
    for loc in locators {
        // Check for IPv4-mapped IPv6 address: ::ffff:a.b.c.d or 0:0:0:0:0:0:0:0:0:0:0:0:a:b:c:d
        if loc.address[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] {
            let ip = format!(
                "{}.{}.{}.{}",
                loc.address[12], loc.address[13], loc.address[14], loc.address[15]
            );
            if ip != "0.0.0.0" {
                return Some(ip);
            }
        }
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
    /// - `consul_addr` -- Consul HTTP API endpoint (e.g., "http://localhost:8500")
    pub fn new(consul_addr: impl Into<String>) -> Result<Self, Error> {
        #[cfg(feature = "cloud-discovery")]
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|_e| Error::Config)?;

        Ok(Self {
            consul_addr: consul_addr.into(),
            service_prefix: "hdds-participant".to_string(),
            domain_id: 0,
            datacenter: None,
            health_check_port: None,
            #[cfg(feature = "cloud-discovery")]
            client,
            #[cfg(feature = "cloud-discovery")]
            registered_id: Arc::new(RwLock::new(None)),
        })
    }

    /// Set service name prefix (default: "hdds-participant")
    pub fn with_service_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.service_prefix = prefix.into();
        self
    }

    /// Set domain ID filter
    pub fn with_domain_id(mut self, domain_id: u32) -> Self {
        self.domain_id = domain_id;
        self
    }

    /// Set Consul datacenter
    pub fn with_datacenter(mut self, dc: impl Into<String>) -> Self {
        self.datacenter = Some(dc.into());
        self
    }

    /// Enable HTTP health check on specified port
    pub fn with_health_check(mut self, port: u16) -> Self {
        self.health_check_port = Some(port);
        self
    }

    /// Generate service ID from GUID
    #[cfg(feature = "cloud-discovery")]
    fn service_id(&self, guid: &[u8; 16]) -> String {
        format!("{}-{}", self.service_prefix, to_hex(&guid[0..8]))
    }

    /// Build Consul API URL with optional datacenter
    #[cfg(feature = "cloud-discovery")]
    fn api_url(&self, path: &str) -> String {
        let base = format!("{}/v1{}", self.consul_addr.trim_end_matches('/'), path);
        if let Some(ref dc) = self.datacenter {
            format!("{}?dc={}", base, dc)
        } else {
            base
        }
    }
}

#[cfg(feature = "cloud-discovery")]
impl CloudDiscovery for ConsulDiscovery {
    async fn register_participant(&self, info: &ParticipantInfo) -> Result<(), Error> {
        let service_id = self.service_id(&info.guid);

        // Extract IP and port from locators
        let address = extract_ipv4(&info.locators).unwrap_or_else(|| "127.0.0.1".to_string());
        let port = info.locators.first().map(|l| l.port as u16).unwrap_or(7400);

        // Build metadata
        let mut meta = HashMap::new();
        meta.insert("guid".to_string(), to_hex(&info.guid));
        meta.insert("domain_id".to_string(), info.domain_id.to_string());
        meta.insert("participant_name".to_string(), info.name.clone());

        // Serialize locators to JSON
        let locators_json: Vec<ConsulLocator> =
            info.locators.iter().map(locator_to_consul).collect();
        if let Ok(json) = serde_json::to_string(&locators_json) {
            meta.insert("locators".to_string(), json);
        }

        // Add custom metadata
        for (k, v) in &info.metadata {
            meta.insert(format!("user_{}", k), v.clone());
        }

        // Build health check if configured
        let check = self.health_check_port.map(|hc_port| ConsulHealthCheck {
            http: Some(format!("http://{}:{}/health", address, hc_port)),
            tcp: None,
            interval: "10s".to_string(),
            timeout: "5s".to_string(),
            deregister_after: "30s".to_string(),
        });

        // Build registration payload
        let registration = ConsulServiceRegistration {
            name: self.service_prefix.clone(),
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
        let url = self.api_url("/agent/service/register");
        let response = self
            .client
            .put(&url)
            .json(&registration)
            .send()
            .await
            .map_err(|_| Error::Config)?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            log::error!("Consul registration failed: {} - {}", status, body);
            return Err(Error::Config);
        }

        // Store participant metadata in KV store for richer queries
        let kv_data = ConsulKvParticipant {
            guid: to_hex(&info.guid),
            name: info.name.clone(),
            domain_id: info.domain_id,
            locators: info.locators.iter().map(locator_to_consul).collect(),
            metadata: info.metadata.clone(),
        };

        let kv_url = self.api_url(&format!(
            "/kv/hdds/participants/domain-{}/{}",
            info.domain_id,
            to_hex(&info.guid)
        ));
        let _ = self.client.put(&kv_url).json(&kv_data).send().await;

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

    async fn discover_participants(&self) -> Result<Vec<ParticipantInfo>, Error> {
        // Query Consul catalog for services with our prefix and domain tag
        let tag = format!("domain-{}", self.domain_id);
        let url = format!(
            "{}/v1/catalog/service/{}?tag={}",
            self.consul_addr.trim_end_matches('/'),
            self.service_prefix,
            tag
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|_| Error::Config)?;

        if !response.status().is_success() {
            log::warn!("Consul discovery query failed: {}", response.status());
            return Ok(vec![]);
        }

        let services: Vec<ConsulCatalogService> =
            response.json().await.map_err(|_| Error::Config)?;

        let mut participants = Vec::with_capacity(services.len());

        for svc in services {
            // Parse GUID from metadata
            let guid_hex = match svc.service_meta.get("guid") {
                Some(g) => g,
                None => continue,
            };
            let guid_bytes = match from_hex(guid_hex) {
                Some(b) if b.len() == 16 => b,
                _ => continue,
            };
            let mut guid = [0u8; 16];
            guid.copy_from_slice(&guid_bytes);

            // Parse locators from metadata
            let locators = svc
                .service_meta
                .get("locators")
                .and_then(|json| serde_json::from_str::<Vec<ConsulLocator>>(json).ok())
                .map(|cls| cls.iter().filter_map(consul_to_locator).collect())
                .unwrap_or_else(|| {
                    // Fallback: construct locator from service address/port
                    let mut addr = [0u8; 16];
                    if let Ok(ip) = svc.service_address.parse::<std::net::Ipv4Addr>() {
                        let octets = ip.octets();
                        addr[12..16].copy_from_slice(&octets);
                    }
                    vec![Locator {
                        kind: 1, // UDP
                        port: svc.service_port as u32,
                        address: addr,
                    }]
                });

            // Parse domain_id
            let domain_id = svc
                .service_meta
                .get("domain_id")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            // Parse name
            let name = svc
                .service_meta
                .get("participant_name")
                .cloned()
                .unwrap_or_else(|| svc.service_id.clone());

            // Extract user metadata
            let mut metadata = HashMap::new();
            for (k, v) in &svc.service_meta {
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

    async fn deregister_participant(&self, guid: [u8; 16]) -> Result<(), Error> {
        let service_id = self.service_id(&guid);

        // Deregister service
        let url = self.api_url(&format!("/agent/service/deregister/{}", service_id));
        let response = self
            .client
            .put(&url)
            .send()
            .await
            .map_err(|_| Error::Config)?;

        if !response.status().is_success() {
            log::warn!(
                "Consul deregistration failed for {}: {}",
                service_id,
                response.status()
            );
        }

        // Delete KV entry (try all domains since we may not know the exact one)
        for domain in 0..10 {
            let kv_url = self.api_url(&format!(
                "/kv/hdds/participants/domain-{}/{}",
                domain,
                to_hex(&guid)
            ));
            let _ = self.client.delete(&kv_url).send().await;
        }

        // Clear registered ID
        if let Ok(mut guard) = self.registered_id.write() {
            *guard = None;
        }

        log::info!("Consul: Deregistered service {}", service_id);

        Ok(())
    }

    async fn health_check(&self) -> Result<bool, Error> {
        // Check Consul agent health
        let url = format!("{}/v1/agent/self", self.consul_addr.trim_end_matches('/'));

        match self.client.get(&url).send().await {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(_) => Ok(false),
        }
    }
}

// Stub implementation when cloud-discovery feature is disabled
#[cfg(not(feature = "cloud-discovery"))]
impl CloudDiscovery for ConsulDiscovery {
    async fn register_participant(&self, _info: &ParticipantInfo) -> Result<(), Error> {
        log::warn!("Consul discovery requires 'cloud-discovery' feature");
        Ok(())
    }

    async fn discover_participants(&self) -> Result<Vec<ParticipantInfo>, Error> {
        log::warn!("Consul discovery requires 'cloud-discovery' feature");
        Ok(vec![])
    }

    async fn deregister_participant(&self, _guid: [u8; 16]) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consul_discovery_creation() {
        let discovery = ConsulDiscovery::new("http://localhost:8500").unwrap();
        assert_eq!(discovery.consul_addr, "http://localhost:8500");
        assert_eq!(discovery.service_prefix, "hdds-participant");
    }

    #[test]
    fn test_consul_with_options() {
        let discovery = ConsulDiscovery::new("http://consul:8500")
            .unwrap()
            .with_service_prefix("my-hdds")
            .with_domain_id(42)
            .with_datacenter("dc1")
            .with_health_check(8080);

        assert_eq!(discovery.service_prefix, "my-hdds");
        assert_eq!(discovery.domain_id, 42);
        assert_eq!(discovery.datacenter.unwrap(), "dc1");
        assert_eq!(discovery.health_check_port.unwrap(), 8080);
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

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_service_id() {
        let discovery = ConsulDiscovery::new("http://localhost:8500").unwrap();
        let guid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(
            discovery.service_id(&guid),
            "hdds-participant-0102030405060708"
        );
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_extract_ipv4() {
        let locators = vec![Locator {
            kind: 1,
            port: 7400,
            address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 100],
        }];
        assert_eq!(extract_ipv4(&locators), Some("192.168.1.100".to_string()));

        let empty: Vec<Locator> = vec![];
        assert_eq!(extract_ipv4(&empty), None);
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
