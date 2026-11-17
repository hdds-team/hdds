// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Configuration of the Azure Table Storage discovery backend (ADR 0002).
//!
//! One type parses the JSON the builder carries
//! ([`crate::dds::ParticipantBuilder::with_azure_discovery`]) and the
//! poller thread reconstructs the backend from the SAME text, so the
//! participant and its poller can never disagree about what was
//! configured.
//!
//! Everything here FAILS CLOSED:
//!
//! * unknown fields are refused, so a typo is an error and not a silent
//!   default;
//! * Shared Key (storage account key) authentication is refused by name:
//!   it is a long-lived shared secret with full data-plane rights, which
//!   a cert-ready product does not carry (decision AZ-3);
//! * the table endpoint follows the crate-wide registry transport rule
//!   ([`super::check_endpoint_transport`]): `https://` anywhere,
//!   plaintext only to a loopback literal (the Azurite / hermetic-fake
//!   case). There is no flag that re-opens plaintext to a remote host;
//! * the instance-metadata endpoint may only be the well-known
//!   link-local IMDS address, an `https://` host, or a loopback literal;
//! * a credential that cannot be resolved is an error at
//!   `Participant::build()`, not a surprise on the first poll: the
//!   Workload Identity token FILE is read (it must exist and be
//!   non-empty), the SAS is resolved from its environment variable and
//!   checked for characters that cannot survive a URL, and an
//!   unresolvable Managed Identity endpoint is refused.

use crate::dds::Error;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// The well-known Azure Instance Metadata Service address.
pub const DEFAULT_IMDS_ENDPOINT: &str = "http://169.254.169.254";
/// Default Entra ID (Azure AD) authority for the Workload Identity flow.
pub const DEFAULT_AUTHORITY_ENDPOINT: &str = "https://login.microsoftonline.com";
/// Default table name.
pub const DEFAULT_TABLE: &str = "hddsparticipants";
/// Default record lease: a participant that stops refreshing its record
/// is treated as gone after this many seconds.
pub const DEFAULT_LEASE_SECONDS: u32 = 60;
/// Floor on the record-refresh interval derived from the lease.
const MIN_HEARTBEAT: Duration = Duration::from_secs(1);

/// Environment variables the AKS Workload Identity webhook projects into
/// every pod that opts in.
const ENV_TENANT_ID: &str = "AZURE_TENANT_ID";
const ENV_CLIENT_ID: &str = "AZURE_CLIENT_ID";
const ENV_FEDERATED_TOKEN_FILE: &str = "AZURE_FEDERATED_TOKEN_FILE";
const ENV_AUTHORITY_HOST: &str = "AZURE_AUTHORITY_HOST";

/// How the backend proves its identity to the Table service.
///
/// Serialised as `{"kind":"managed_identity", ...}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AzureAuth {
    /// Azure Managed Identity: a bearer token minted by IMDS on the VM,
    /// VMSS instance or AKS node. `client_id` selects a user-assigned
    /// identity; absent means the system-assigned one.
    ManagedIdentity {
        /// Client id of a user-assigned identity, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_id: Option<String>,
    },
    /// AKS Workload Identity: the pod holds a projected federated token,
    /// exchanged at the Entra ID authority for a storage bearer token.
    /// IMDS does not serve this flow, so a pod-scoped identity needs it
    /// (decision AZ-2); every field defaults to the environment variable
    /// the AKS webhook projects.
    WorkloadIdentity {
        /// Directory (tenant) id; defaults to `AZURE_TENANT_ID`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tenant_id: Option<String>,
        /// Application (client) id; defaults to `AZURE_CLIENT_ID`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_id: Option<String>,
        /// Projected token path; defaults to `AZURE_FEDERATED_TOKEN_FILE`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token_file: Option<String>,
    },
    /// A Shared Access Signature appended to every request.
    ///
    /// Prefer `token_env`: it names the environment variable holding the
    /// signature, so the participant configuration itself carries no
    /// secret (`Participant::cloud_discovery_config()` returns that
    /// string verbatim).
    Sas {
        /// The signature, literally, and ALREADY url-encoded: it is
        /// appended to the request URL exactly as it is written here
        /// (re-encoding it would invalidate it), so a '#', a space or a
        /// control character is refused at build time. Test and Azurite
        /// use; prefer `token_env`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
        /// Name of the environment variable holding the signature.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token_env: Option<String>,
    },
}

/// Everything the Azure backend needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AzureDiscoveryConfig {
    /// Storage account name (3-24 lowercase alphanumerics).
    pub account: String,
    /// Table holding the participant records.
    #[serde(default = "default_table")]
    pub table: String,
    /// How to authenticate to the Table service.
    pub auth: AzureAuth,
    /// Table service base URL. Defaults to
    /// `https://{account}.table.core.windows.net`; override it for
    /// Azurite (`http://127.0.0.1:10002/devstoreaccount1`) or a test.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Instance Metadata Service base URL (Managed Identity only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imds_endpoint: Option<String>,
    /// Entra ID authority base URL (Workload Identity only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_endpoint: Option<String>,
    /// Optional PartitionKey prefix, so several logical deployments can
    /// share one table. This is what `AzureDiscovery::new(..)` sets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Record lease in seconds: a record older than this is a crashed
    /// participant and is ignored (never deleted: it is not ours).
    #[serde(default = "default_lease_seconds")]
    pub lease_seconds: u32,
}

fn default_table() -> String {
    DEFAULT_TABLE.to_string()
}

fn default_lease_seconds() -> u32 {
    DEFAULT_LEASE_SECONDS
}

/// A credential source with every value resolved: nothing left to read
/// from the environment, nothing left to default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CredentialSource {
    /// IMDS bearer token.
    Imds {
        endpoint: String,
        client_id: Option<String>,
    },
    /// Federated-token exchange at the Entra ID authority.
    Workload {
        authority: String,
        tenant_id: String,
        client_id: String,
        token_file: String,
    },
    /// Shared Access Signature query string.
    Sas { signature: String },
}

impl AzureDiscoveryConfig {
    /// Parse the builder's JSON.
    ///
    /// Refuses Shared Key authentication by name before serde ever sees
    /// it, so the error explains the posture instead of reading as an
    /// unknown-variant complaint.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let value: serde_json::Value = serde_json::from_str(json).map_err(|error| {
            Error::Config(format!(
                "azure cloud discovery config JSON parse error: {}",
                error
            ))
        })?;
        if let Some(kind) = value
            .get("auth")
            .and_then(|auth| auth.get("kind"))
            .and_then(serde_json::Value::as_str)
        {
            if matches!(kind, "shared_key" | "account_key" | "connection_string") {
                return Err(Error::Config(format!(
                    "azure auth kind {:?} is refused: Shared Key / account key / connection string \
                     is a long-lived shared secret with full data-plane rights over the storage \
                     account. Use \"managed_identity\" (VM, VMSS, AKS node), \"workload_identity\" \
                     (AKS pod) or a scoped \"sas\" signature (decision AZ-3, ADR 0002)",
                    kind
                )));
            }
        }
        let config: Self = serde_json::from_value(value).map_err(|error| {
            Error::Config(format!(
                "azure cloud discovery config is not a valid configuration: {}",
                error
            ))
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Table service base URL, without a trailing slash.
    pub fn table_endpoint(&self) -> String {
        self.endpoint
            .clone()
            .unwrap_or_else(|| format!("https://{}.table.core.windows.net", self.account))
            .trim_end_matches('/')
            .to_string()
    }

    /// PartitionKey holding the records of one domain.
    pub fn partition_key(&self, domain_id: u32) -> String {
        match self.namespace.as_deref().filter(|ns| !ns.is_empty()) {
            Some(namespace) => format!("{}-domain-{}", namespace, domain_id),
            None => format!("domain-{}", domain_id),
        }
    }

    /// How often the participant refreshes its own record so its lease
    /// never expires while it is alive: a third of the lease, one second
    /// at least.
    pub fn heartbeat_interval(&self) -> Duration {
        Duration::from_secs(u64::from(self.lease_seconds.max(1)) / 3).max(MIN_HEARTBEAT)
    }

    /// Check every field, and resolve the credential source (which reads
    /// the environment for the Workload Identity and SAS-by-env forms).
    ///
    /// Called at `Participant::build()` AND when the poller thread builds
    /// the backend, so a misconfiguration is a build error rather than a
    /// participant with no peer source.
    pub fn validate(&self) -> Result<(), Error> {
        check_account_name(&self.account)?;
        check_table_name(&self.table)?;
        if let Some(namespace) = self.namespace.as_deref() {
            check_namespace(namespace)?;
        }
        if self.lease_seconds == 0 {
            return Err(Error::Config(
                "azure lease_seconds is 0: every record would be stale the moment it is written"
                    .to_string(),
            ));
        }
        super::check_endpoint_transport(&self.table_endpoint()).map_err(Error::Config)?;
        self.credential_source().map(|_| ())
    }

    /// The resolved credential source.
    pub(super) fn credential_source(&self) -> Result<CredentialSource, Error> {
        match &self.auth {
            AzureAuth::ManagedIdentity { client_id } => {
                let endpoint = self
                    .imds_endpoint
                    .clone()
                    .unwrap_or_else(|| DEFAULT_IMDS_ENDPOINT.to_string());
                check_metadata_endpoint(&endpoint)?;
                Ok(CredentialSource::Imds {
                    endpoint: endpoint.trim_end_matches('/').to_string(),
                    client_id: client_id.clone().filter(|id| !id.is_empty()),
                })
            }
            AzureAuth::WorkloadIdentity {
                tenant_id,
                client_id,
                token_file,
            } => {
                let authority = self
                    .authority_endpoint
                    .clone()
                    .or_else(|| non_empty_env(ENV_AUTHORITY_HOST))
                    .unwrap_or_else(|| DEFAULT_AUTHORITY_ENDPOINT.to_string());
                super::check_endpoint_transport(&authority).map_err(Error::Config)?;
                Ok(CredentialSource::Workload {
                    authority: authority.trim_end_matches('/').to_string(),
                    tenant_id: resolve(tenant_id, ENV_TENANT_ID, "tenant_id")?,
                    client_id: resolve(client_id, ENV_CLIENT_ID, "client_id")?,
                    token_file: {
                        let path = resolve(token_file, ENV_FEDERATED_TOKEN_FILE, "token_file")?;
                        check_federated_token_file(&path)?;
                        path
                    },
                })
            }
            AzureAuth::Sas { token, token_env } => {
                let signature = match (
                    token.as_deref().filter(|value| !value.is_empty()),
                    token_env.as_deref().filter(|name| !name.is_empty()),
                ) {
                    (Some(_), Some(_)) => {
                        return Err(Error::Config(
                            "azure sas auth carries both \"token\" and \"token_env\": pick one"
                                .to_string(),
                        ))
                    }
                    (Some(literal), None) => literal.to_string(),
                    (None, Some(name)) => non_empty_env(name).ok_or_else(|| {
                        Error::Config(format!(
                            "azure sas auth reads the signature from ${}, which is unset or empty",
                            name
                        ))
                    })?,
                    (None, None) => {
                        return Err(Error::Config(
                            "azure sas auth carries neither \"token\" nor \"token_env\""
                                .to_string(),
                        ))
                    }
                };
                let signature = signature.trim_start_matches('?').to_string();
                check_sas_signature(&signature)?;
                Ok(CredentialSource::Sas { signature })
            }
        }
    }
}

fn resolve(configured: &Option<String>, env: &str, field: &str) -> Result<String, Error> {
    configured
        .clone()
        .filter(|value| !value.is_empty())
        .or_else(|| non_empty_env(env))
        .ok_or_else(|| {
            Error::Config(format!(
                "azure workload_identity auth has no {}: set it in the config or let the AKS \
                 webhook project ${} (decision AZ-2)",
                field, env
            ))
        })
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// Azure storage account naming rule: 3-24 lowercase letters and digits.
fn check_account_name(account: &str) -> Result<(), Error> {
    if (3..=24).contains(&account.len())
        && account
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return Ok(());
    }
    Err(Error::Config(format!(
        "azure storage account name {:?} is invalid: 3 to 24 lowercase letters and digits",
        account
    )))
}

/// Azure table naming rule: 3-63 alphanumerics, starting with a letter.
fn check_table_name(table: &str) -> Result<(), Error> {
    if (3..=63).contains(&table.len())
        && table.starts_with(|c: char| c.is_ascii_alphabetic())
        && table.chars().all(|c| c.is_ascii_alphanumeric())
    {
        return Ok(());
    }
    Err(Error::Config(format!(
        "azure table name {:?} is invalid: 3 to 63 alphanumerics starting with a letter",
        table
    )))
}

/// A namespace ends up inside a PartitionKey, which is also a URL path
/// segment and an OData string literal. Only the characters that need no
/// escaping in either place are accepted; anything else is refused
/// rather than encoded, so the key on the wire is always the key that
/// was configured.
pub(super) fn check_namespace(namespace: &str) -> Result<(), Error> {
    if (1..=64).contains(&namespace.len())
        && namespace
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Ok(());
    }
    Err(Error::Config(format!(
        "azure namespace {:?} is invalid: 1 to 64 characters, letters, digits, '-', '_' or '.' \
         (it becomes a PartitionKey prefix, which is both a URL path segment and an OData \
         string literal)",
        namespace
    )))
}

/// A SAS signature is appended to the request URL EXACTLY as configured
/// (re-encoding it would invalidate it), so it must already be
/// URL-encoded. A '#' would truncate the URL and the request would then
/// carry no credential at all; a raw space or control character is
/// refused by the service.
fn check_sas_signature(signature: &str) -> Result<(), Error> {
    if let Some(bad) = signature
        .chars()
        .find(|c| *c == '#' || c.is_whitespace() || c.is_control() || !c.is_ascii())
    {
        return Err(Error::Config(format!(
            "azure sas signature carries {:?}: the signature is sent exactly as configured, so \
             it must already be url encoded ('#' truncates the request URL, and the request \
             would then carry no credential at all)",
            bad
        )));
    }
    Ok(())
}

/// The projected federated token is read HERE too, not only at mint
/// time: a pod whose Workload Identity webhook did not project the file
/// must fail `Participant::build()` rather than build, lower the
/// multicast default and then have no peer source at all.
fn check_federated_token_file(path: &str) -> Result<(), Error> {
    let content = std::fs::read_to_string(path).map_err(|error| {
        Error::Config(format!(
            "azure workload_identity federated token file {:?} is unreadable: {} (the AKS \
             webhook projects it and names it in ${})",
            path, error, ENV_FEDERATED_TOKEN_FILE
        ))
    })?;
    if content.trim().is_empty() {
        return Err(Error::Config(format!(
            "azure workload_identity federated token file {:?} is empty",
            path
        )));
    }
    Ok(())
}

/// The instance-metadata endpoint is not a registry endpoint: the real
/// one is plaintext link-local by design. Accept exactly that address,
/// any `https://` host, or a loopback literal (tests and Azurite).
fn check_metadata_endpoint(endpoint: &str) -> Result<(), Error> {
    if endpoint.trim_end_matches('/') == DEFAULT_IMDS_ENDPOINT {
        return Ok(());
    }
    super::check_endpoint_transport(endpoint).map_err(|reason| {
        Error::Config(format!(
            "azure imds_endpoint is neither the well-known {} nor an acceptable URL: {}",
            DEFAULT_IMDS_ENDPOINT, reason
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn managed(json_extra: &str) -> String {
        format!(
            r#"{{"account":"hddsacct","auth":{{"kind":"managed_identity"}}{}}}"#,
            json_extra
        )
    }

    #[test]
    fn from_json_defaults_table_lease_and_endpoint() {
        let config = AzureDiscoveryConfig::from_json(&managed("")).expect("valid config");
        assert_eq!(config.table, DEFAULT_TABLE);
        assert_eq!(config.lease_seconds, DEFAULT_LEASE_SECONDS);
        assert_eq!(
            config.table_endpoint(),
            "https://hddsacct.table.core.windows.net"
        );
        assert_eq!(config.partition_key(39), "domain-39");
        assert_eq!(config.heartbeat_interval(), Duration::from_secs(20));
        assert_eq!(
            config.credential_source().expect("resolvable"),
            CredentialSource::Imds {
                endpoint: DEFAULT_IMDS_ENDPOINT.to_string(),
                client_id: None,
            }
        );
    }

    #[test]
    fn from_json_refuses_shared_key_by_name() {
        for kind in ["shared_key", "account_key", "connection_string"] {
            let json = format!(
                r#"{{"account":"hddsacct","auth":{{"kind":"{}","key":"c2VjcmV0"}}}}"#,
                kind
            );
            let Err(Error::Config(message)) = AzureDiscoveryConfig::from_json(&json) else {
                panic!("{} was accepted", kind);
            };
            assert!(
                message.contains("is refused") && message.contains(kind),
                "unexpected message for {}: {}",
                kind,
                message
            );
        }
    }

    #[test]
    fn from_json_refuses_unknown_fields_and_bad_names() {
        assert!(AzureDiscoveryConfig::from_json(&managed(r#","tabel":"typo""#)).is_err());
        assert!(AzureDiscoveryConfig::from_json(
            r#"{"account":"HddsAcct","auth":{"kind":"managed_identity"}}"#
        )
        .is_err());
        assert!(AzureDiscoveryConfig::from_json(
            r#"{"account":"hddsacct","table":"1table","auth":{"kind":"managed_identity"}}"#
        )
        .is_err());
        assert!(AzureDiscoveryConfig::from_json(&managed(r#","lease_seconds":0"#)).is_err());
        assert!(AzureDiscoveryConfig::from_json(&managed(r#","namespace":"a/b""#)).is_err());
        assert!(AzureDiscoveryConfig::from_json(r#"{"auth":{"kind":"sas"}}"#).is_err());
    }

    #[test]
    fn table_endpoint_is_https_unless_the_host_is_loopback() {
        assert!(AzureDiscoveryConfig::from_json(&managed(
            r#","endpoint":"http://hddsacct.table.core.windows.net""#
        ))
        .is_err());
        assert!(AzureDiscoveryConfig::from_json(&managed(
            r#","endpoint":"http://127.0.0.1:10002/devstoreaccount1""#
        ))
        .is_ok());
        assert!(AzureDiscoveryConfig::from_json(&managed(
            r#","endpoint":"https://private.table.example.net""#
        ))
        .is_ok());
    }

    #[test]
    fn imds_endpoint_accepts_the_link_local_address_and_loopback_only() {
        assert!(AzureDiscoveryConfig::from_json(&managed(
            r#","imds_endpoint":"http://169.254.169.254""#
        ))
        .is_ok());
        assert!(AzureDiscoveryConfig::from_json(&managed(
            r#","imds_endpoint":"http://127.0.0.1:9""#
        ))
        .is_ok());
        assert!(AzureDiscoveryConfig::from_json(&managed(
            r#","imds_endpoint":"http://metadata.evil.example""#
        ))
        .is_err());
    }

    #[test]
    fn namespace_becomes_a_partition_key_prefix() {
        let config = AzureDiscoveryConfig::from_json(&managed(r#","namespace":"fleet-a""#))
            .expect("valid config");
        assert_eq!(config.partition_key(39), "fleet-a-domain-39");
    }

    #[test]
    fn sas_reads_its_signature_from_the_environment_when_asked() {
        let literal = AzureDiscoveryConfig::from_json(
            r#"{"account":"hddsacct","auth":{"kind":"sas","token":"?sv=2024&sig=ABC"}}"#,
        )
        .expect("literal sas");
        assert_eq!(
            literal.credential_source().expect("resolvable"),
            CredentialSource::Sas {
                signature: "sv=2024&sig=ABC".to_string()
            }
        );

        // Unset variable: refused, not silently unauthenticated.
        let by_env = AzureDiscoveryConfig::from_json(
            r#"{"account":"hddsacct","auth":{"kind":"sas","token_env":"HDDS_TEST_AZURE_SAS_UNSET"}}"#,
        );
        assert!(by_env.is_err());

        assert!(AzureDiscoveryConfig::from_json(
            r#"{"account":"hddsacct","auth":{"kind":"sas","token":"a","token_env":"B"}}"#
        )
        .is_err());
    }

    #[test]
    fn workload_identity_needs_a_tenant_client_id_and_token_file() {
        let directory = tempfile::tempdir().expect("temp dir");
        let token_file = directory.path().join("federated-token");
        std::fs::write(&token_file, "PROJECTED.JWT.VALUE\n").expect("write token file");
        let complete = AzureDiscoveryConfig::from_json(&format!(
            concat!(
                r#"{{"account":"hddsacct","auth":{{"kind":"workload_identity","#,
                r#""tenant_id":"t","client_id":"c","token_file":"{}"}},"#,
                r#""authority_endpoint":"https://login.microsoftonline.com"}}"#
            ),
            token_file.display()
        ))
        .expect("complete workload identity config");
        assert_eq!(
            complete.credential_source().expect("resolvable"),
            CredentialSource::Workload {
                authority: DEFAULT_AUTHORITY_ENDPOINT.to_string(),
                tenant_id: "t".to_string(),
                client_id: "c".to_string(),
                token_file: token_file.display().to_string(),
            }
        );

        // Nothing in the config and (in this process) nothing in the
        // environment: a build error, never an unauthenticated request.
        let incomplete = AzureDiscoveryConfig::from_json(
            r#"{"account":"hddsacct","auth":{"kind":"workload_identity","tenant_id":"t"}}"#,
        );
        if std::env::var(ENV_CLIENT_ID).is_err() {
            let Err(Error::Config(message)) = incomplete else {
                panic!("an unresolvable workload identity was accepted");
            };
            assert!(
                message.contains("client_id") && message.contains(ENV_CLIENT_ID),
                "unexpected message: {}",
                message
            );
        }
    }

    /// The rustdoc promises that a credential which cannot be resolved is
    /// an error at `Participant::build()`. For Workload Identity that
    /// means the projected token file itself, not just its path string:
    /// a pod whose webhook is misconfigured must not build, lower the
    /// multicast default and then have no peer source at all.
    #[test]
    fn workload_identity_reads_its_token_file_at_build_time() {
        let directory = tempfile::tempdir().expect("temp dir");
        let token_file = directory.path().join("federated-token");
        let config = |path: &std::path::Path| {
            AzureDiscoveryConfig::from_json(&format!(
                concat!(
                    r#"{{"account":"hddsacct","auth":{{"kind":"workload_identity","#,
                    r#""tenant_id":"t","client_id":"c","token_file":"{}"}}}}"#
                ),
                path.display()
            ))
        };

        let Err(Error::Config(missing)) = config(&token_file) else {
            panic!("a missing federated token file was accepted at build time");
        };
        assert!(
            missing.contains("unreadable") && missing.contains("token"),
            "{}",
            missing
        );

        std::fs::write(&token_file, "   \n").expect("write empty token file");
        let Err(Error::Config(empty)) = config(&token_file) else {
            panic!("an empty federated token file was accepted at build time");
        };
        assert!(empty.contains("empty"), "{}", empty);

        std::fs::write(&token_file, "PROJECTED.JWT.VALUE\n").expect("write token file");
        assert!(config(&token_file).is_ok());
    }

    /// A SAS signature travels in the query string EXACTLY as configured,
    /// so it must already be URL-encoded: a '#' truncates the URL (the
    /// request then carries no credential at all) and a raw space or a
    /// control character is refused by the service.
    #[test]
    fn a_sas_signature_must_already_be_url_encoded() {
        for bad in [
            "sv=2024&sig=ABC#def",
            "sv=2024&sig=ABC def",
            "sv=2024&sig=ABC\tdef",
            "sv=2024&sig=ABC\ndef",
        ] {
            let json = format!(
                r#"{{"account":"hddsacct","auth":{{"kind":"sas","token":"{}"}}}}"#,
                bad.escape_default()
            );
            let Err(Error::Config(message)) = AzureDiscoveryConfig::from_json(&json) else {
                panic!(
                    "a signature that cannot survive a URL was accepted: {:?}",
                    bad
                );
            };
            assert!(
                message.contains("sas") && message.contains("encoded"),
                "unexpected message for {:?}: {}",
                bad,
                message
            );
        }

        assert!(AzureDiscoveryConfig::from_json(
            r#"{"account":"hddsacct","auth":{"kind":"sas","token":"?sv=2024&sig=ABC%2Fdef"}}"#
        )
        .is_ok());
    }

    #[test]
    fn round_trips_through_serde_without_inventing_fields() {
        let config = AzureDiscoveryConfig::from_json(&managed(
            r#","namespace":"fleet-a","lease_seconds":90,"endpoint":"https://x.example""#,
        ))
        .expect("valid config");
        let json = serde_json::to_string(&config).expect("serialise");
        let parsed = AzureDiscoveryConfig::from_json(&json).expect("re-parse");
        assert_eq!(parsed, config);
    }
}
