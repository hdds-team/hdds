// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Azure participant registry over Table Storage (ADR 0002).
//!
//! One participant record per row in an Azure Storage table:
//! `PartitionKey` is the DDS domain (optionally prefixed by a
//! namespace), `RowKey` is the participant GUID in hex, and the row
//! carries the metatraffic locators SPDP itself advertises. Discovery is
//! one OData query per poll, filtered on the partition, so a participant
//! joins a domain in cloud networks that never route multicast.
//!
//! # What this backend does
//!
//! - `register_participant` -- creates the table if it is missing, then
//!   inserts-or-replaces this participant's row (idempotent, so the same
//!   call refreshes the lease);
//! - `discover_participants` -- queries the domain's partition, follows
//!   the continuation headers, and drops rows whose lease has expired (a
//!   crashed participant; never deleted, it is not ours to delete);
//! - `deregister_participant` -- deletes the row (`404` tolerated);
//! - `health_check` -- one bounded query; unreachable or unauthorised
//!   answers `false` (fail closed).
//!
//! # Authentication
//!
//! Managed Identity (VM, VMSS, AKS node), AKS Workload Identity (pod) or
//! a scoped SAS -- see [`super::azure_auth`]. The identity needs the
//! `Storage Table Data Contributor` role on the account. Shared Key
//! (account key) is refused by construction.
//!
//! # Builds without `cloud-discovery`
//!
//! There are none: `discovery::cloud` is gated on the feature as a whole
//! (`discovery/mod.rs`), so a binary built without it does not have this
//! type at all. No code path can report a successful registration with no
//! backend behind it.
//!
//! # Not built
//!
//! DNS Private Zones and Service Bus announcements are NOT implemented:
//! a private zone carries no participant GUID and its records are written
//! through the ARM control plane, and Service Bus is a message bus, not a
//! registry, so late joiners would still need a store. ADR 0002 records
//! both rejections.
//!
//! # Example
//!
//! ```ignore
//! use hdds::discovery::cloud::{AzureDiscovery, AzureDiscoveryConfig};
//!
//! let config = AzureDiscoveryConfig::from_json(
//!     r#"{"account":"hddsacct","auth":{"kind":"managed_identity"}}"#,
//! )?;
//! let discovery = AzureDiscovery::from_config(config)?.with_domain_id(39);
//! discovery.register_participant(&info).await?;
//! let peers = discovery.discover_participants().await?;
//! ```

#[cfg(feature = "cloud-discovery")]
use reqwest::{Client, RequestBuilder};
#[cfg(feature = "cloud-discovery")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "cloud-discovery")]
use super::azure_auth::{Credential, TokenProvider};
#[cfg(feature = "cloud-discovery")]
use super::azure_config::{AzureAuth, AzureDiscoveryConfig};
#[cfg(feature = "cloud-discovery")]
use super::Locator;
use super::{CloudDiscovery, ParticipantInfo};
use crate::dds::Error;
#[cfg(feature = "cloud-discovery")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "cloud-discovery")]
use std::sync::Arc;
#[cfg(feature = "cloud-discovery")]
use std::time::{SystemTime, UNIX_EPOCH};

/// Table service REST API version this client speaks.
#[cfg(feature = "cloud-discovery")]
const TABLE_API_VERSION: &str = "2019-02-02";
/// Upper bound on continuation pages followed by one query: a registry
/// that keeps handing out a continuation token must not spin the poller.
#[cfg(feature = "cloud-discovery")]
const MAX_QUERY_PAGES: usize = 32;
/// How many of OUR lease periods a row may claim for itself before the
/// claim is capped.
#[cfg(feature = "cloud-discovery")]
const MAX_LEASE_FACTOR: u64 = 4;

/// Azure Table Storage participant registry.
///
/// Construct it from a validated [`AzureDiscoveryConfig`]
/// ([`Self::from_config`]), or from a namespace plus
/// [`Self::with_table_storage`] for the default Managed Identity setup.
pub struct AzureDiscovery {
    /// PartitionKey prefix (the argument of [`Self::new`]).
    namespace: Option<String>,

    /// Domain ID filter.
    domain_id: u32,

    /// Storage account name.
    storage_account: Option<String>,

    /// Table holding the participant records.
    table_name: Option<String>,

    /// Service Bus connection string, recorded and unused (see the
    /// module docs and ADR 0002).
    service_bus_conn: Option<String>,

    /// Table service base URL, without a trailing slash.
    #[cfg(feature = "cloud-discovery")]
    endpoint: Option<String>,

    /// Record lease in seconds.
    #[cfg(feature = "cloud-discovery")]
    lease_seconds: u32,

    /// HTTP client (5 s ceiling, no environment proxy).
    #[cfg(feature = "cloud-discovery")]
    client: Client,

    /// Credential minting and caching.
    #[cfg(feature = "cloud-discovery")]
    tokens: Arc<TokenProvider>,

    /// Whether the table was created (or found) in this process.
    #[cfg(feature = "cloud-discovery")]
    table_ready: Arc<AtomicBool>,
}

/// `{:?}` of a backend must not print a secret: the Service Bus
/// connection string carries a `SharedAccessKey`, and the credential
/// itself is redacted one level down (`TokenProvider`).
impl std::fmt::Debug for AzureDiscovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = f.debug_struct("AzureDiscovery");
        out.field("namespace", &self.namespace)
            .field("domain_id", &self.domain_id)
            .field("storage_account", &self.storage_account)
            .field("table_name", &self.table_name);
        #[cfg(feature = "cloud-discovery")]
        out.field("endpoint", &self.endpoint)
            .field("lease_seconds", &self.lease_seconds)
            .field("tokens", &self.tokens);
        out.field(
            "service_bus_conn",
            &self.service_bus_conn.as_ref().map(|_| "<redacted>"),
        )
        .finish_non_exhaustive()
    }
}

// ============================================================================
// Wire types
// ============================================================================

/// One participant row.
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
    /// JSON array of locators.
    #[serde(rename = "Locators")]
    locators: String,
    /// JSON object of user metadata.
    #[serde(rename = "Metadata")]
    metadata: String,
    /// Unix seconds, as a string (Table Storage numbers are Edm.Int32).
    #[serde(rename = "LastUpdated")]
    last_updated: String,
    #[serde(rename = "LeaseSeconds")]
    lease_seconds: u32,
}

#[cfg(feature = "cloud-discovery")]
#[derive(Debug, Deserialize)]
struct ODataQueryResponse {
    #[serde(default)]
    value: Vec<serde_json::Value>,
}

// ============================================================================
// Helper functions
// ============================================================================

/// Encode bytes to a hex string.
#[cfg(any(feature = "cloud-discovery", test))]
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode a hex string to bytes, or `None` for anything else.
///
/// Registry rows are foreign bytes: the string must not be sliced by
/// BYTE index, or a `Guid` or locator `address` column carrying one
/// multi-byte character would panic the poller thread (and a panic there
/// would freeze the status at `running: true` for the life of the process).
#[cfg(feature = "cloud-discovery")]
fn from_hex(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(text, 16).ok()
        })
        .collect()
}

/// Serialize locators to JSON.
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

/// Parse locators from JSON.
#[cfg(feature = "cloud-discovery")]
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

/// Percent-encode one query-string value (RFC 3986 unreserved set kept).
#[cfg(feature = "cloud-discovery")]
fn encode_query_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{:02X}", other)),
        }
    }
    out
}

/// Unix seconds now.
#[cfg(feature = "cloud-discovery")]
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Append a SAS signature to a URL that may already carry a query.
#[cfg(feature = "cloud-discovery")]
fn with_credential(url: String, credential: &Credential) -> String {
    match credential {
        // The signature is used EXACTLY as configured: it is already
        // percent-encoded, and re-encoding it would invalidate it.
        Credential::Sas(signature) => {
            let separator = if url.contains('?') { '&' } else { '?' };
            format!("{}{}{}", url, separator, signature)
        }
        Credential::Bearer(_) => url,
    }
}

/// Attach the bearer token, if that is the credential form.
#[cfg(feature = "cloud-discovery")]
fn authorize(request: RequestBuilder, credential: &Credential) -> RequestBuilder {
    match credential {
        Credential::Bearer(token) => request.header("Authorization", format!("Bearer {}", token)),
        Credential::Sas(_) => request,
    }
}

/// One transport-level failure, WITHOUT the request URL.
///
/// The URL of every Table request carries the SAS signature when that is
/// the credential, and this message reaches `last_error` (public through
/// `Participant::cloud_discovery_status()`) and the log. `reqwest`'s own
/// `Display` appends `for url (..)`, so the URL is stripped here.
#[cfg(feature = "cloud-discovery")]
fn transport_error(what: &str, error: reqwest::Error) -> Error {
    Error::Config(format!("azure {} failed: {}", what, error.without_url()))
}

/// Headers every Table service request carries.
#[cfg(feature = "cloud-discovery")]
fn table_headers(request: RequestBuilder) -> RequestBuilder {
    request
        .header("x-ms-version", TABLE_API_VERSION)
        .header("Accept", "application/json;odata=nometadata")
        .header("DataServiceVersion", "3.0;NetFx")
        .header("MaxDataServiceVersion", "3.0;NetFx")
}

// ============================================================================
// Implementation
// ============================================================================

impl AzureDiscovery {
    /// Create a backend for one namespace (the PartitionKey prefix).
    ///
    /// The storage account is not known yet: call
    /// [`Self::with_table_storage`], or use [`Self::from_config`] for the
    /// full configuration. An empty namespace means "no prefix".
    ///
    /// # Errors
    ///
    /// When the namespace is not a legal PartitionKey prefix, or the HTTP
    /// client cannot be built.
    pub fn new(namespace: impl Into<String>) -> Result<Self, Error> {
        let namespace = namespace.into();
        // The SAME rule `AzureDiscoveryConfig` enforces: the namespace
        // becomes a PartitionKey, which is both an OData string literal
        // and a URL path segment.
        #[cfg(feature = "cloud-discovery")]
        if !namespace.is_empty() {
            super::azure_config::check_namespace(&namespace)?;
        }
        #[cfg(feature = "cloud-discovery")]
        // `.no_proxy()`: the registry is reached directly, never through
        // whatever HTTP_PROXY happens to name. ONE bound, the poller's:
        // a black-holed endpoint cannot outlive the command loop's own
        // ceiling.
        let client = Client::builder()
            .no_proxy()
            .timeout(super::poller_thread::REQUEST_TIMEOUT)
            .build()
            .map_err(|e| Error::Config(format!("failed to build Azure HTTP client: {}", e)))?;

        Ok(Self {
            namespace: Some(namespace).filter(|value| !value.is_empty()),
            domain_id: 0,
            storage_account: None,
            table_name: None,
            service_bus_conn: None,
            #[cfg(feature = "cloud-discovery")]
            endpoint: None,
            #[cfg(feature = "cloud-discovery")]
            lease_seconds: super::azure_config::DEFAULT_LEASE_SECONDS,
            #[cfg(feature = "cloud-discovery")]
            tokens: Arc::new(TokenProvider::new(
                client.clone(),
                // Default identity: the instance's own, from IMDS.
                AzureDiscoveryConfig {
                    account: String::new(),
                    table: String::new(),
                    auth: AzureAuth::ManagedIdentity { client_id: None },
                    endpoint: None,
                    imds_endpoint: None,
                    authority_endpoint: None,
                    namespace: None,
                    lease_seconds: super::azure_config::DEFAULT_LEASE_SECONDS,
                }
                .credential_source()?,
            )),
            #[cfg(feature = "cloud-discovery")]
            client,
            #[cfg(feature = "cloud-discovery")]
            table_ready: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Build a backend from a validated configuration.
    ///
    /// # Errors
    ///
    /// When the configuration is invalid (see
    /// [`AzureDiscoveryConfig::validate`]) or the HTTP client cannot be
    /// built.
    #[cfg(feature = "cloud-discovery")]
    pub fn from_config(config: AzureDiscoveryConfig) -> Result<Self, Error> {
        config.validate()?;
        let source = config.credential_source()?;
        let client = Client::builder()
            .no_proxy()
            .timeout(super::poller_thread::REQUEST_TIMEOUT)
            .build()
            .map_err(|e| Error::Config(format!("failed to build Azure HTTP client: {}", e)))?;
        Ok(Self {
            namespace: config.namespace.clone(),
            domain_id: 0,
            storage_account: Some(config.account.clone()),
            table_name: Some(config.table.clone()),
            service_bus_conn: None,
            endpoint: Some(config.table_endpoint()),
            lease_seconds: config.lease_seconds,
            tokens: Arc::new(TokenProvider::new(client.clone(), source)),
            client,
            table_ready: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Set the domain ID filter.
    pub fn with_domain_id(mut self, domain_id: u32) -> Self {
        self.domain_id = domain_id;
        self
    }

    /// Point the backend at a storage account and table, authenticated by
    /// the instance's Managed Identity.
    pub fn with_table_storage(
        mut self,
        storage_account: impl Into<String>,
        table_name: impl Into<String>,
    ) -> Self {
        let storage_account = storage_account.into();
        #[cfg(feature = "cloud-discovery")]
        {
            self.endpoint = Some(format!(
                "https://{}.table.core.windows.net",
                storage_account
            ));
        }
        self.storage_account = Some(storage_account);
        self.table_name = Some(table_name.into());
        self
    }

    /// Record a Service Bus connection string.
    ///
    /// Nothing reads it: the Service Bus announcer is not implemented,
    /// and Table Storage is the registry of record (ADR 0002). Kept so
    /// existing calls still compile.
    #[deprecated(
        since = "1.5.0",
        note = "Service Bus announcements are not implemented; Table Storage is the registry (ADR 0002)"
    )]
    pub fn with_service_bus(mut self, connection_string: impl Into<String>) -> Self {
        self.service_bus_conn = Some(connection_string.into());
        self
    }

    /// Record name for a GUID (short form, used in logs).
    #[cfg(any(feature = "cloud-discovery", test))]
    fn entity_id(&self, guid: &[u8; 16]) -> String {
        format!("hdds-{}", to_hex(&guid[0..8]))
    }

    /// PartitionKey of this backend's domain.
    #[cfg(feature = "cloud-discovery")]
    fn partition_key(&self) -> String {
        match self.namespace.as_deref() {
            Some(namespace) => format!("{}-domain-{}", namespace, self.domain_id),
            None => format!("domain-{}", self.domain_id),
        }
    }

    /// Table service base URL for the configured account and table.
    #[cfg(feature = "cloud-discovery")]
    fn table_storage_url(&self, table: &str) -> Option<String> {
        let endpoint = self.endpoint.clone().or_else(|| {
            self.storage_account
                .as_ref()
                .map(|account| format!("https://{}.table.core.windows.net", account))
        })?;
        Some(format!("{}/{}", endpoint.trim_end_matches('/'), table))
    }

    /// The configured table, or the error that says nothing is configured.
    #[cfg(feature = "cloud-discovery")]
    fn require_table(&self) -> Result<(&str, String), Error> {
        let table = self.table_name.as_deref().ok_or_else(|| {
            Error::Config(
                "azure discovery has no table configured: call with_table_storage() or \
                 from_config()"
                    .to_string(),
            )
        })?;
        let base = self.table_storage_url(table).ok_or_else(|| {
            Error::Config(
                "azure discovery has no storage account configured: call with_table_storage() \
                 or from_config()"
                    .to_string(),
            )
        })?;
        Ok((table, base))
    }

    /// Entity URL for one (PartitionKey, RowKey) pair.
    #[cfg(feature = "cloud-discovery")]
    fn entity_url(&self, base: &str, partition_key: &str, row_key: &str) -> String {
        format!(
            "{}(PartitionKey='{}',RowKey='{}')",
            base, partition_key, row_key
        )
    }

    /// Create the table once per backend instance, BEST EFFORT.
    ///
    /// `409` means it already exists, and `403` means this credential may
    /// not create tables at all -- which is what a SAS scoped to one
    /// table answers, and what a Managed Identity without table-creation
    /// rights answers. Neither is a reason to refuse to register: the
    /// entity upsert is the authority, and it reports `TableNotFound`
    /// itself if the table really is missing.
    #[cfg(feature = "cloud-discovery")]
    async fn ensure_table(&self, credential: &Credential) -> Result<(), Error> {
        if self.table_ready.load(Ordering::Relaxed) {
            return Ok(());
        }
        let (table, base) = self.require_table()?;
        let endpoint = base
            .rsplit_once('/')
            .map(|(head, _)| head.to_string())
            .unwrap_or_else(|| base.clone());
        let url = with_credential(format!("{}/Tables", endpoint), credential);
        let response = table_headers(authorize(self.client.post(&url), credential))
            .header("Content-Type", "application/json")
            .body(format!(r#"{{"TableName":"{}"}}"#, table))
            .send()
            .await
            .map_err(|error| transport_error("table creation request", error))?;
        let status = response.status();
        if status.is_success() || status.as_u16() == 409 {
            self.table_ready.store(true, Ordering::Relaxed);
            return Ok(());
        }
        if status.as_u16() == 403 {
            log::debug!(
                "[AZURE] This credential may not create tables (HTTP 403); assuming {} exists",
                table
            );
            self.table_ready.store(true, Ordering::Relaxed);
            return Ok(());
        }
        Err(self.http_error("table creation", response).await)
    }

    /// One error carrying the status and the head of the body, never a
    /// credential.
    #[cfg(feature = "cloud-discovery")]
    async fn http_error(&self, what: &str, response: reqwest::Response) -> Error {
        let status = response.status();
        if status.as_u16() == 401 || status.as_u16() == 403 {
            // The peer rejected our credential: drop the cached token so
            // the next attempt mints a fresh one.
            self.tokens.invalidate();
        }
        if status.as_u16() == 404 {
            // The table is gone (an operator, a lifecycle policy, a
            // rebuilt account). Without this the one-way `table_ready`
            // latch would keep the process from ever creating it again.
            self.table_ready.store(false, Ordering::Relaxed);
        }
        let body = response.text().await.unwrap_or_default();
        let head: String = body.chars().take(256).collect();
        Error::Config(format!("azure {} failed: HTTP {} - {}", what, status, head))
    }

    /// Turn one queried row into a participant record, or `None` when the
    /// row is malformed or its lease has expired.
    #[cfg(feature = "cloud-discovery")]
    fn row_to_participant(&self, row: &serde_json::Value, now: u64) -> Option<ParticipantInfo> {
        let entity: TableStorageEntity = serde_json::from_value(row.clone()).ok()?;
        // The row's identity is its RowKey. A row whose `Guid` column
        // disagrees with the key it is stored under is not a participant
        // we are willing to speak to.
        if !entity.guid.eq_ignore_ascii_case(&entity.row_key) {
            log::debug!(
                "[AZURE] Ignoring row {} whose Guid column is not its RowKey",
                entity.row_key
            );
            return None;
        }
        let bytes = from_hex(&entity.guid)?;
        if bytes.len() != 16 {
            return None;
        }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&bytes);

        let last_updated: u64 = entity.last_updated.parse().ok()?;
        // A row must not be able to declare itself immortal: the honoured
        // lease is capped at a few of OUR lease periods, so a bogus
        // `LeaseSeconds` cannot pin a dead participant in the peer set.
        let cap = u64::from(self.lease_seconds).saturating_mul(MAX_LEASE_FACTOR);
        let lease = u64::from(if entity.lease_seconds == 0 {
            self.lease_seconds
        } else {
            entity.lease_seconds
        })
        .min(cap);
        if last_updated.saturating_add(lease) < now {
            log::debug!(
                "[AZURE] Ignoring expired record {} (last updated {}s ago, lease {}s)",
                entity.row_key,
                now.saturating_sub(last_updated),
                lease
            );
            return None;
        }

        Some(ParticipantInfo {
            guid,
            name: entity.name,
            domain_id: entity.domain_id,
            locators: parse_locators(&entity.locators),
            metadata: serde_json::from_str(&entity.metadata).unwrap_or_default(),
        })
    }
}

#[cfg(feature = "cloud-discovery")]
impl CloudDiscovery for AzureDiscovery {
    /// Insert-or-replace this participant's row, creating the table if it
    /// is missing.
    ///
    /// The row carries the locators the CALLER advertises (the
    /// participant's own filtered metatraffic locators), never an
    /// address read from instance metadata: on AKS the instance address
    /// is the node's, not the pod's, and it bypasses the interface
    /// allowlist SPDP itself honours.
    ///
    /// The call is idempotent, so the poller reuses it as the lease
    /// heartbeat.
    async fn register_participant(&self, info: &ParticipantInfo) -> Result<(), Error> {
        let (_, base) = self.require_table()?;
        // Fail closed: no credential, no request. Nothing is advertised
        // and the poller reports the error.
        let credential = self.tokens.credential().await?;
        self.ensure_table(&credential).await?;

        let partition_key = self.partition_key();
        let row_key = to_hex(&info.guid);
        let entity = TableStorageEntity {
            partition_key: partition_key.clone(),
            row_key: row_key.clone(),
            guid: row_key.clone(),
            name: info.name.clone(),
            domain_id: info.domain_id,
            locators: serialize_locators(&info.locators),
            metadata: serde_json::to_string(&info.metadata).unwrap_or_else(|_| "{}".to_string()),
            last_updated: now_secs().to_string(),
            lease_seconds: self.lease_seconds,
        };
        let body = serde_json::to_string(&entity).map_err(|error| {
            Error::Config(format!("azure entity serialisation failed: {}", error))
        })?;

        let url = with_credential(
            self.entity_url(&base, &partition_key, &row_key),
            &credential,
        );
        let response = table_headers(authorize(self.client.put(&url), &credential))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|error| transport_error("entity upsert request", error))?;
        if !response.status().is_success() {
            return Err(self.http_error("entity upsert", response).await);
        }

        log::info!(
            "[AZURE] Registered participant '{}' ({}, partition {})",
            info.name,
            self.entity_id(&info.guid),
            partition_key
        );
        Ok(())
    }

    /// Query this domain's partition, following continuation pages.
    ///
    /// A non-2xx answer or an unparsable page is an ERROR, never an empty
    /// registry: returning `Ok(vec![])` on a hiccup would make every peer
    /// look lost at once.
    async fn discover_participants(&self) -> Result<Vec<ParticipantInfo>, Error> {
        let (_, base) = self.require_table()?;
        let credential = self.tokens.credential().await?;

        let partition_key = self.partition_key();
        let filter = format!("PartitionKey eq '{}'", partition_key);
        let now = now_secs();
        let mut participants = Vec::new();
        let mut seen: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
        let mut continuation: Option<(String, String)> = None;

        for _page in 0..MAX_QUERY_PAGES {
            let mut url = format!("{}()?$filter={}", base, encode_query_value(&filter));
            if let Some((next_partition, next_row)) = &continuation {
                url.push_str(&format!(
                    "&NextPartitionKey={}&NextRowKey={}",
                    encode_query_value(next_partition),
                    encode_query_value(next_row)
                ));
            }
            let response = table_headers(authorize(
                self.client.get(with_credential(url, &credential)),
                &credential,
            ))
            .send()
            .await
            .map_err(|error| transport_error("query request", error))?;
            if !response.status().is_success() {
                return Err(self.http_error("entity query", response).await);
            }

            let next_partition = header_value(&response, "x-ms-continuation-NextPartitionKey");
            let next_row = header_value(&response, "x-ms-continuation-NextRowKey");
            let page: ODataQueryResponse = response
                .json()
                .await
                .map_err(|error| transport_error("query response parse", error))?;
            for row in &page.value {
                if let Some(info) = self.row_to_participant(row, now) {
                    // A row replayed across pages is one peer, not two:
                    // `status.registry_peers` counts what is returned.
                    if seen.insert(info.guid) {
                        participants.push(info);
                    }
                }
            }

            continuation = match (next_partition, next_row) {
                (Some(partition), Some(row)) => Some((partition, row)),
                // A partition token without a row token still identifies
                // the next page for a partition-scoped query.
                (Some(partition), None) => Some((partition, String::new())),
                _ => None,
            };
            if continuation.is_none() {
                log::debug!(
                    "[AZURE] Query returned {} live participants in partition {}",
                    participants.len(),
                    partition_key
                );
                return Ok(participants);
            }
        }

        // DEGRADE, never stop: returning `Err` here would discard the
        // peers already collected, so a partition that outgrows the cap
        // (a churning AKS deployment) would kill discovery outright.
        log::warn!(
            "[AZURE] Partition {} did not terminate after {} continuation pages; \
             reporting the {} participants read so far",
            partition_key,
            MAX_QUERY_PAGES,
            participants.len()
        );
        Ok(participants)
    }

    /// Delete this participant's row. A `404` is success: the row is gone.
    async fn deregister_participant(&self, guid: [u8; 16]) -> Result<(), Error> {
        let (_, base) = self.require_table()?;
        let credential = self.tokens.credential().await?;
        let partition_key = self.partition_key();
        let row_key = to_hex(&guid);
        let url = with_credential(
            self.entity_url(&base, &partition_key, &row_key),
            &credential,
        );
        let response = table_headers(authorize(self.client.delete(&url), &credential))
            // Unconditional delete: we own this row.
            .header("If-Match", "*")
            .send()
            .await
            .map_err(|error| transport_error("entity delete request", error))?;
        let status = response.status();
        if status.is_success() || status.as_u16() == 404 {
            log::info!("[AZURE] Deregistered participant {}", self.entity_id(&guid));
            return Ok(());
        }
        Err(self.http_error("entity delete", response).await)
    }

    /// One bounded query. Unreachable, unauthorised or refused answers
    /// `false`: the previous implementation reported healthy whenever the
    /// endpoint could not be reached at all.
    async fn health_check(&self) -> Result<bool, Error> {
        match self.discover_participants().await {
            Ok(_) => Ok(true),
            Err(error) => {
                log::warn!("[AZURE] Health check failed: {}", error);
                Ok(false)
            }
        }
    }
}

/// One response header as a `String`.
#[cfg(feature = "cloud-discovery")]
fn header_value(response: &reqwest::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .filter(|value| !value.is_empty())
}

// The historical `azure_tests.rs` (a tracked file that no `mod`
// declaration ever pulled in, written against an API that existed in no
// commit) is finally compiled -- with tests that exercise the backend
// that is actually here.
#[cfg(test)]
#[path = "azure_tests.rs"]
mod tests;
