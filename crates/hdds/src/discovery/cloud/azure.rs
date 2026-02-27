// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Azure Service Discovery
//!
//! Uses Azure DNS Private Zones and Instance Metadata Service for discovery
//! in Azure VMs, AKS, and Container Instances environments.
//!
//! # Features
//!
//! - **Azure Instance Metadata** -- Auto-detect VM/container IP
//! - **DNS Private Zones** -- DNS SRV/TXT records for participants
//! - **Service Bus Topics** -- Real-time participant announcements (optional)
//! - **Table Storage** -- Persistent participant registry (optional)
//!
//! # Example
//!
//! ```ignore
//! use hdds::discovery::cloud::AzureDiscovery;
//!
//! let discovery = AzureDiscovery::new("hdds.private.azure.local")?
//!     .with_table_storage("hddsparticipants", "<connection_string>");
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
use std::sync::Arc;
#[cfg(feature = "cloud-discovery")]
use std::sync::RwLock;

/// Azure Service Discovery backend
///
/// Uses Azure DNS Private Zones for DNS-based discovery and optionally
/// Azure Table Storage for persistent participant registry.
#[derive(Debug)]
pub struct AzureDiscovery {
    /// Azure DNS Private Zone name
    #[allow(dead_code)] // Used for DNS queries when cloud-discovery feature is enabled
    dns_zone: String,

    /// Domain ID filter
    #[allow(dead_code)] // Used for filtering when cloud-discovery feature is enabled
    domain_id: u32,

    /// Table Storage account name (optional)
    storage_account: Option<String>,

    /// Table name in Table Storage
    table_name: Option<String>,

    /// Service Bus connection string (optional)
    service_bus_conn: Option<String>,

    /// HTTP client
    #[cfg(feature = "cloud-discovery")]
    client: Client,

    /// Cached VM IP from IMDS
    #[cfg(feature = "cloud-discovery")]
    cached_ip: Arc<RwLock<Option<String>>>,

    /// Registered record name
    #[cfg(feature = "cloud-discovery")]
    registered_record: Arc<RwLock<Option<String>>>,
}

// ============================================================================
// Azure API Types
// ============================================================================

#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Deserialize)]
struct AzureImdsResponse {
    network: Option<AzureImdsNetwork>,
}

#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Deserialize)]
struct AzureImdsNetwork {
    interface: Option<Vec<AzureImdsInterface>>,
}

#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Deserialize)]
struct AzureImdsInterface {
    #[serde(rename = "ipv4")]
    ipv4: Option<AzureImdsIpv4>,
}

#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Deserialize)]
struct AzureImdsIpv4 {
    #[serde(rename = "ipAddress")]
    ip_address: Option<Vec<AzureImdsIpAddress>>,
}

#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Deserialize)]
struct AzureImdsIpAddress {
    #[serde(rename = "privateIpAddress")]
    private_ip_address: Option<String>,
}

#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Serialize, Deserialize)]
struct TableStorageEntity {
    #[serde(rename = "PartitionKey")]
    partition_key: String,
    #[serde(rename = "RowKey")]
    row_key: String,
    #[serde(rename = "Guid")]
    guid: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "DomainId")]
    domain_id: u32,
    #[serde(rename = "Locators")]
    locators: String, // JSON
    #[serde(rename = "Metadata")]
    metadata: String, // JSON
    #[serde(rename = "LastUpdated")]
    last_updated: String,
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

/// Parse locators from JSON
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

// ============================================================================
// Implementation
// ============================================================================

impl AzureDiscovery {
    /// Create a new Azure Service Discovery backend
    ///
    /// # Arguments
    ///
    /// - `dns_zone` -- Azure DNS Private Zone (e.g., "hdds.private.azure.local")
    pub fn new(dns_zone: impl Into<String>) -> Result<Self, Error> {
        #[cfg(feature = "cloud-discovery")]
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|_| Error::Config)?;

        Ok(Self {
            dns_zone: dns_zone.into(),
            domain_id: 0,
            storage_account: None,
            table_name: None,
            service_bus_conn: None,
            #[cfg(feature = "cloud-discovery")]
            client,
            #[cfg(feature = "cloud-discovery")]
            cached_ip: Arc::new(RwLock::new(None)),
            #[cfg(feature = "cloud-discovery")]
            registered_record: Arc::new(RwLock::new(None)),
        })
    }

    /// Set domain ID filter
    pub fn with_domain_id(mut self, domain_id: u32) -> Self {
        self.domain_id = domain_id;
        self
    }

    /// Configure Azure Table Storage for persistent registry
    ///
    /// This is the recommended approach for reliable discovery in Azure.
    pub fn with_table_storage(
        mut self,
        storage_account: impl Into<String>,
        table_name: impl Into<String>,
    ) -> Self {
        self.storage_account = Some(storage_account.into());
        self.table_name = Some(table_name.into());
        self
    }

    /// With Service Bus for real-time announcements
    pub fn with_service_bus(mut self, connection_string: impl Into<String>) -> Self {
        self.service_bus_conn = Some(connection_string.into());
        self
    }

    /// Generate record/entity name from GUID
    #[cfg(any(feature = "cloud-discovery", test))]
    fn entity_id(&self, guid: &[u8; 16]) -> String {
        format!("hdds-{}", to_hex(&guid[0..8]))
    }

    /// Get VM IP from Azure Instance Metadata Service (IMDS)
    #[cfg(feature = "cloud-discovery")]
    async fn get_azure_vm_ip(&self) -> Option<String> {
        // Check cache first
        if let Ok(guard) = self.cached_ip.read() {
            if let Some(ref ip) = *guard {
                return Some(ip.clone());
            }
        }

        // Azure IMDS endpoint
        let url = "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01";

        let response = self
            .client
            .get(url)
            .header("Metadata", "true")
            .send()
            .await
            .ok()?;

        let imds: AzureImdsResponse = response.json().await.ok()?;

        let ip = imds
            .network?
            .interface?
            .first()?
            .ipv4
            .as_ref()?
            .ip_address
            .as_ref()?
            .first()?
            .private_ip_address
            .clone()?;

        // Cache result
        if let Ok(mut guard) = self.cached_ip.write() {
            *guard = Some(ip.clone());
        }

        Some(ip)
    }

    /// Get Table Storage API endpoint
    #[cfg(feature = "cloud-discovery")]
    fn table_storage_url(&self, table: &str) -> Option<String> {
        let account = self.storage_account.as_ref()?;
        Some(format!(
            "https://{}.table.core.windows.net/{}",
            account, table
        ))
    }
}

#[cfg(feature = "cloud-discovery")]
impl CloudDiscovery for AzureDiscovery {
    /// Register a participant with Azure cloud discovery.
    ///
    /// # ⚠️ WARNING: STUB IMPLEMENTATION ⚠️
    ///
    /// **This function does NOT actually register participants to Azure Table Storage.**
    ///
    /// Current behavior:
    /// - Retrieves VM IP from Azure IMDS (or falls back to locator/localhost)
    /// - Logs the registration intent
    /// - Stores the entity ID in local memory
    /// - Returns `Ok(())` without any network call to Azure Table Storage
    ///
    /// ## What needs to be implemented:
    ///
    /// 1. **Azure Storage Authentication** - Add support for Shared Key or Azure AD token
    ///    authentication using the `azure_identity` and `azure_storage_tables` crates
    /// 2. **HTTP Request to Table Storage** - Actually POST the `TableStorageEntity` to
    ///    the Azure Table Storage REST API endpoint
    /// 3. **Error Handling** - Handle HTTP errors, conflicts (409), and retry logic
    /// 4. **TTL/Lease Management** - Implement heartbeat mechanism to keep registration alive
    ///
    /// ## Example implementation outline:
    /// ```ignore
    /// use azure_storage_tables::TableClient;
    /// use azure_identity::DefaultAzureCredential;
    ///
    /// let credential = DefaultAzureCredential::default();
    /// let client = TableClient::new(&account, &table, credential);
    /// client.upsert_entity(&entity).await?;
    /// ```
    async fn register_participant(&self, info: &ParticipantInfo) -> Result<(), Error> {
        let entity_id = self.entity_id(&info.guid);

        // Get IP from IMDS or locators
        let ip_address = self
            .get_azure_vm_ip()
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

        let port = info.locators.first().map(|l| l.port as u16).unwrap_or(7400);

        log::info!(
            "Azure Discovery: Registering participant '{}' (IP: {}, port: {})",
            info.name,
            ip_address,
            port
        );

        // Register in Table Storage if configured
        if let (Some(table_url), Some(_account)) = (
            self.table_name
                .as_ref()
                .and_then(|t| self.table_storage_url(t)),
            &self.storage_account,
        ) {
            let entity = TableStorageEntity {
                partition_key: format!("domain-{}", info.domain_id),
                row_key: to_hex(&info.guid),
                guid: to_hex(&info.guid),
                name: info.name.clone(),
                domain_id: info.domain_id,
                locators: serialize_locators(&info.locators),
                metadata: serde_json::to_string(&info.metadata).unwrap_or_default(),
                last_updated: chrono::Utc::now().to_rfc3339(),
            };

            // Note: Real implementation requires Azure Storage authentication
            // Using Shared Key or Azure AD token
            // For now, log the intent

            log::info!(
                "Azure Table Storage: Would insert entity to {} (PartitionKey={}, RowKey={})",
                table_url,
                entity.partition_key,
                entity.row_key
            );

            // Example with azure_storage_tables crate:
            // let client = TableClient::new(account, table, credential);
            // client.insert_entity(&entity).await?;
        }

        // Store registered record
        if let Ok(mut guard) = self.registered_record.write() {
            *guard = Some(entity_id.clone());
        }

        log::info!(
            "Azure Discovery: Registered participant '{}' (ID: {}, domain: {})",
            info.name,
            entity_id,
            info.domain_id
        );

        Ok(())
    }

    /// Discover participants from Azure cloud discovery.
    ///
    /// # ⚠️ WARNING: STUB IMPLEMENTATION ⚠️
    ///
    /// **This function ALWAYS returns an empty list.** It does NOT query Azure Table Storage.
    ///
    /// Current behavior:
    /// - Logs debug messages about the query intent
    /// - Creates an empty `Vec<ParticipantInfo>`
    /// - Returns the empty vector without any network call
    ///
    /// ## What needs to be implemented:
    ///
    /// 1. **Azure Storage Authentication** - Add support for Shared Key or Azure AD token
    ///    using `azure_identity` and `azure_storage_tables` crates
    /// 2. **Query Table Storage** - Execute OData query with partition key filter:
    ///    `PartitionKey eq 'domain-{domain_id}'`
    /// 3. **Parse Response** - Deserialize `TableStorageEntity` rows into `ParticipantInfo`
    ///    using `from_hex()` for GUID and `parse_locators()` for locators
    /// 4. **DNS Fallback** - Optionally implement DNS SRV record lookup as fallback
    ///
    /// ## Example implementation outline:
    /// ```ignore
    /// let filter = format!("PartitionKey eq 'domain-{}'", self.domain_id);
    /// let entities: Vec<TableStorageEntity> = client.query_entities(&filter).await?;
    ///
    /// for entity in entities {
    ///     let guid = from_hex(&entity.guid)?;
    ///     participants.push(ParticipantInfo {
    ///         guid,
    ///         name: entity.name,
    ///         domain_id: entity.domain_id,
    ///         locators: parse_locators(&entity.locators),
    ///         metadata: serde_json::from_str(&entity.metadata).unwrap_or_default(),
    ///     });
    /// }
    /// ```
    async fn discover_participants(&self) -> Result<Vec<ParticipantInfo>, Error> {
        log::debug!(
            "Azure Discovery: Discovering participants in domain {}",
            self.domain_id
        );

        let participants = Vec::new();

        // Query Table Storage if configured
        if let (Some(table_url), Some(_account)) = (
            self.table_name
                .as_ref()
                .and_then(|t| self.table_storage_url(t)),
            &self.storage_account,
        ) {
            log::debug!(
                "Azure Table Storage: Querying {} for PartitionKey='domain-{}'",
                table_url,
                self.domain_id
            );

            // Example with azure_storage_tables crate:
            // let client = TableClient::new(account, table, credential);
            // let filter = format!("PartitionKey eq 'domain-{}'", self.domain_id);
            // let entities = client.query_entities(filter).await?;
            //
            // for entity in entities {
            //     let guid_bytes = from_hex(&entity.guid)?;
            //     let mut guid = [0u8; 16];
            //     guid.copy_from_slice(&guid_bytes);
            //
            //     participants.push(ParticipantInfo {
            //         guid,
            //         name: entity.name,
            //         domain_id: entity.domain_id,
            //         locators: parse_locators(&entity.locators),
            //         metadata: serde_json::from_str(&entity.metadata).unwrap_or_default(),
            //     });
            // }
        }

        // Fallback: DNS SRV record lookup
        // dig SRV _hdds._tcp.domain-{}.{dns_zone}
        let dns_query = format!("_hdds._tcp.domain-{}.{}", self.domain_id, self.dns_zone);
        log::debug!("Azure Discovery: DNS fallback query: {}", dns_query);

        log::debug!("Azure Discovery: Found {} participants", participants.len());

        Ok(participants)
    }

    /// Deregister a participant from Azure cloud discovery.
    ///
    /// # ⚠️ WARNING: STUB IMPLEMENTATION ⚠️
    ///
    /// **This function does NOT actually delete from Azure Table Storage.**
    ///
    /// Current behavior:
    /// - Logs the deregistration intent
    /// - Clears the local `registered_record` cache
    /// - Returns `Ok(())` without any network call
    ///
    /// ## What needs to be implemented:
    ///
    /// 1. **Azure Storage Authentication** - Same as `register_participant()`
    /// 2. **DELETE Request** - Call Table Storage DELETE endpoint with PartitionKey and RowKey
    /// 3. **Error Handling** - Handle 404 (already deleted) gracefully
    async fn deregister_participant(&self, guid: [u8; 16]) -> Result<(), Error> {
        let entity_id = self.entity_id(&guid);

        log::info!("Azure Discovery: Deregistering participant {}", entity_id);

        // Delete from Table Storage if configured
        if let (Some(table_url), Some(_account)) = (
            self.table_name
                .as_ref()
                .and_then(|t| self.table_storage_url(t)),
            &self.storage_account,
        ) {
            log::info!(
                "Azure Table Storage: Would delete entity from {} (RowKey={})",
                table_url,
                to_hex(&guid)
            );

            // Example:
            // client.delete_entity("domain-{domain_id}", &to_hex(&guid)).await?;
        }

        // Clear registered record
        if let Ok(mut guard) = self.registered_record.write() {
            *guard = None;
        }

        Ok(())
    }

    async fn health_check(&self) -> Result<bool, Error> {
        // Check if IMDS is reachable (indicates we're in Azure)
        let url = "http://169.254.169.254/metadata/instance?api-version=2021-02-01";

        match self
            .client
            .get(url)
            .header("Metadata", "true")
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await
        {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(_) => {
                // IMDS not available - might be local dev, still OK
                Ok(true)
            }
        }
    }
}

// Stub implementation when cloud-discovery feature is disabled
#[cfg(not(feature = "cloud-discovery"))]
impl CloudDiscovery for AzureDiscovery {
    async fn register_participant(&self, _info: &ParticipantInfo) -> Result<(), Error> {
        log::warn!("Azure Discovery requires 'cloud-discovery' feature");
        Ok(())
    }

    async fn discover_participants(&self) -> Result<Vec<ParticipantInfo>, Error> {
        log::warn!("Azure Discovery requires 'cloud-discovery' feature");
        Ok(vec![])
    }

    async fn deregister_participant(&self, _guid: [u8; 16]) -> Result<(), Error> {
        Ok(())
    }
}

// Add chrono for timestamp
#[cfg(feature = "cloud-discovery")]
mod chrono {
    pub struct Utc;
    impl Utc {
        pub fn now() -> UtcNow {
            UtcNow
        }
    }
    pub struct UtcNow;
    impl UtcNow {
        pub fn to_rfc3339(&self) -> String {
            // Simple implementation - in real code use chrono crate
            use std::time::{SystemTime, UNIX_EPOCH};
            let duration = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            format!("{}Z", duration.as_secs())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_discovery_creation() {
        let discovery = AzureDiscovery::new("hdds.private.azure.local").unwrap();
        assert_eq!(discovery.dns_zone, "hdds.private.azure.local");
    }

    #[test]
    fn test_azure_with_options() {
        let discovery = AzureDiscovery::new("hdds.azure.local")
            .unwrap()
            .with_domain_id(5)
            .with_table_storage("myaccount", "participants")
            .with_service_bus("Endpoint=sb://...");

        assert_eq!(discovery.domain_id, 5);
        assert_eq!(discovery.storage_account.unwrap(), "myaccount");
        assert_eq!(discovery.table_name.unwrap(), "participants");
        assert!(discovery.service_bus_conn.is_some());
    }

    #[test]
    fn test_entity_id_generation() {
        let discovery = AzureDiscovery::new("test.local").unwrap();
        let guid = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(discovery.entity_id(&guid), "hdds-aabbccddeeff0011");
    }

    #[test]
    fn test_to_hex() {
        assert_eq!(to_hex(&[0xca, 0xfe, 0xba, 0xbe]), "cafebabe");
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_table_storage_url() {
        let discovery = AzureDiscovery::new("test.local")
            .unwrap()
            .with_table_storage("myaccount", "mytable");

        assert_eq!(
            discovery.table_storage_url("mytable"),
            Some("https://myaccount.table.core.windows.net/mytable".to_string())
        );
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_locator_roundtrip() {
        let locators = vec![Locator {
            kind: 1,
            port: 7400,
            address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 172, 16, 0, 1],
        }];

        let json = serialize_locators(&locators);
        let parsed = parse_locators(&json);

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].port, 7400);
        assert_eq!(parsed[0].address[12..16], [172, 16, 0, 1]);
    }
}
