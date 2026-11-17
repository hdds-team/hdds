// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Credential acquisition for the Azure Table Storage backend (ADR 0002).
//!
//! Three sources, all resolved once at configuration time
//! ([`super::azure_config::CredentialSource`]):
//!
//! * **Managed Identity** -- `GET {imds}/metadata/identity/oauth2/token`
//!   with the anti-SSRF header `Metadata: true`. Works on a VM, a VMSS
//!   instance and an AKS node.
//! * **AKS Workload Identity** -- the projected federated token is
//!   exchanged at the Entra ID authority for a storage token
//!   (`client_credentials` + `client_assertion`). IMDS does not serve
//!   this flow, so a POD-scoped identity has no other way in (AZ-2).
//! * **SAS** -- a signature appended to the query string; no token
//!   endpoint is involved.
//!
//! Bearer tokens are cached and refreshed [`REFRESH_MARGIN`] before they
//! expire. A token is NEVER logged, never rendered by `Debug` and never
//! put in an error message: failures carry the HTTP status and a
//! truncated error body only.

use super::azure_config::CredentialSource;
use crate::dds::Error;
use reqwest::Client;
use serde::Deserialize;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Scope/resource the token is minted for.
const STORAGE_RESOURCE: &str = "https://storage.azure.com/";
/// Scope form used by the OAuth2 v2.0 endpoint.
const STORAGE_SCOPE: &str = "https://storage.azure.com/.default";
/// IMDS API version that returns `expires_in`.
const IMDS_API_VERSION: &str = "2018-02-01";
/// Refresh this long before expiry, so a token never expires in flight.
pub(super) const REFRESH_MARGIN: Duration = Duration::from_secs(300);
/// Lower bound on a cached token's life, in case the issuer reports a
/// lifetime shorter than the refresh margin.
const MIN_CACHE: Duration = Duration::from_secs(1);
/// How much of an error body is quoted back.
const ERROR_BODY_HEAD: usize = 256;
/// Ceiling on a lifetime reported by a token endpoint. Azure tokens live
/// for about an hour; anything past a day is nonsense, and an unclamped
/// `expires_in` reaches `Instant + Duration`, which PANICS on overflow
/// (on the poller thread).
const MAX_TOKEN_LIFETIME: Duration = Duration::from_secs(86_400);

/// What one request must carry to be accepted by the Table service.
#[derive(Clone, PartialEq, Eq)]
pub(super) enum Credential {
    /// `Authorization: Bearer <token>`.
    Bearer(String),
    /// Query-string signature appended to the request URL.
    Sas(String),
}

/// Neither form is ever rendered: both ARE the secret.
impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Credential::Bearer(_) => f.write_str("Bearer(<redacted>)"),
            Credential::Sas(_) => f.write_str("Sas(<redacted>)"),
        }
    }
}

struct CachedToken {
    token: String,
    /// When the cached token stops being handed out.
    valid_until: Instant,
}

/// Mints and caches the credential of one backend instance.
pub(super) struct TokenProvider {
    client: Client,
    source: CredentialSource,
    cache: Mutex<Option<CachedToken>>,
}

/// `{:?}` of a backend must not print a token or a signature.
impl fmt::Debug for TokenProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.source {
            CredentialSource::Imds { .. } => "managed_identity",
            CredentialSource::Workload { .. } => "workload_identity",
            CredentialSource::Sas { .. } => "sas",
        };
        f.debug_struct("TokenProvider")
            .field("auth", &kind)
            .finish()
    }
}

impl TokenProvider {
    pub(super) fn new(client: Client, source: CredentialSource) -> Self {
        Self {
            client,
            source,
            cache: Mutex::new(None),
        }
    }

    /// The credential for one request, minting or refreshing as needed.
    ///
    /// Fails closed: without a credential the caller must not send the
    /// request at all.
    pub(super) async fn credential(&self) -> Result<Credential, Error> {
        if let CredentialSource::Sas { signature } = &self.source {
            return Ok(Credential::Sas(signature.clone()));
        }
        if let Some(token) = self.cached() {
            return Ok(Credential::Bearer(token));
        }
        let (token, lifetime) = match &self.source {
            CredentialSource::Imds {
                endpoint,
                client_id,
            } => self.imds_token(endpoint, client_id.as_deref()).await?,
            CredentialSource::Workload {
                authority,
                tenant_id,
                client_id,
                token_file,
            } => {
                self.workload_token(authority, tenant_id, client_id, token_file)
                    .await?
            }
            CredentialSource::Sas { .. } => unreachable!("handled above"),
        };
        self.store(&token, lifetime);
        Ok(Credential::Bearer(token))
    }

    /// Drop the cached token (a `401` means the peer disagrees with us).
    pub(super) fn invalidate(&self) {
        *lock(&self.cache) = None;
    }

    fn cached(&self) -> Option<String> {
        let guard = lock(&self.cache);
        guard
            .as_ref()
            .filter(|cached| Instant::now() < cached.valid_until)
            .map(|cached| cached.token.clone())
    }

    fn store(&self, token: &str, lifetime: Duration) {
        let now = Instant::now();
        let life = lifetime
            .min(MAX_TOKEN_LIFETIME)
            .saturating_sub(REFRESH_MARGIN)
            .max(MIN_CACHE);
        // Belt and braces: the clamp above already bounds `life`, and a
        // deadline that still cannot be represented falls back to the
        // floor rather than panicking.
        let valid_until = now.checked_add(life).unwrap_or(now + MIN_CACHE);
        *lock(&self.cache) = Some(CachedToken {
            token: token.to_string(),
            valid_until,
        });
    }

    async fn imds_token(
        &self,
        endpoint: &str,
        client_id: Option<&str>,
    ) -> Result<(String, Duration), Error> {
        let url = format!("{}/metadata/identity/oauth2/token", endpoint);
        let mut query: Vec<(&str, &str)> = vec![
            ("api-version", IMDS_API_VERSION),
            ("resource", STORAGE_RESOURCE),
        ];
        if let Some(client_id) = client_id {
            query.push(("client_id", client_id));
        }
        let response = self
            .client
            // The anti-SSRF header IMDS requires; without it the service
            // answers 400 and no token exists.
            .get(&url)
            .header("Metadata", "true")
            .query(&query)
            .send()
            .await
            .map_err(|error| {
                Error::Config(format!(
                    "azure managed identity token request to IMDS failed: {}",
                    error.without_url()
                ))
            })?;
        parse_token_response(response, "managed identity").await
    }

    async fn workload_token(
        &self,
        authority: &str,
        tenant_id: &str,
        client_id: &str,
        token_file: &str,
    ) -> Result<(String, Duration), Error> {
        // The projected token is short-lived and rotated in place, so it
        // is read on EVERY exchange, never cached.
        let assertion = std::fs::read_to_string(token_file).map_err(|error| {
            Error::Config(format!(
                "azure workload identity federated token file {:?} is unreadable: {}",
                token_file, error
            ))
        })?;
        let assertion = assertion.trim().to_string();
        if assertion.is_empty() {
            return Err(Error::Config(format!(
                "azure workload identity federated token file {:?} is empty",
                token_file
            )));
        }
        let url = format!("{}/{}/oauth2/v2.0/token", authority, tenant_id);
        let form = [
            ("client_id", client_id),
            ("scope", STORAGE_SCOPE),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", assertion.as_str()),
            ("grant_type", "client_credentials"),
        ];
        let response = self
            .client
            .post(&url)
            .form(&form)
            .send()
            .await
            .map_err(|error| {
                Error::Config(format!(
                    "azure workload identity token exchange failed: {}",
                    error.without_url()
                ))
            })?;
        parse_token_response(response, "workload identity").await
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    /// IMDS sends this as a string, the OAuth2 endpoint as a number.
    #[serde(default)]
    expires_in: Option<serde_json::Value>,
}

async fn parse_token_response(
    response: reqwest::Response,
    what: &str,
) -> Result<(String, Duration), Error> {
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(Error::Config(format!(
            "azure {} token endpoint answered HTTP {}: {}",
            what,
            status,
            head_of(&body)
        )));
    }
    let parsed: TokenResponse = response.json().await.map_err(|error| {
        Error::Config(format!(
            "azure {} token response could not be parsed: {}",
            what, error
        ))
    })?;
    if parsed.access_token.is_empty() {
        return Err(Error::Config(format!(
            "azure {} token endpoint returned an empty access_token",
            what
        )));
    }
    let lifetime = parsed
        .expires_in
        .as_ref()
        .and_then(expires_in_seconds)
        .map(Duration::from_secs)
        .map(|lifetime| lifetime.min(MAX_TOKEN_LIFETIME))
        // No lifetime reported: keep it only until the next refresh
        // margin elapses rather than assuming an hour.
        .unwrap_or(REFRESH_MARGIN + MIN_CACHE);
    Ok((parsed.access_token, lifetime))
}

fn expires_in_seconds(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

fn head_of(body: &str) -> String {
    let head: String = body.chars().take(ERROR_BODY_HEAD).collect();
    if head.len() < body.len() {
        format!("{}...", head)
    } else {
        head
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> Client {
        Client::builder()
            .no_proxy()
            .build()
            .expect("build test client")
    }

    #[test]
    fn a_sas_source_needs_no_token_endpoint() {
        let provider = TokenProvider::new(
            client(),
            CredentialSource::Sas {
                signature: "sv=2024&sig=ABC".to_string(),
            },
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let credential = runtime
            .block_on(provider.credential())
            .expect("a sas needs no network");
        assert_eq!(credential, Credential::Sas("sv=2024&sig=ABC".to_string()));
    }

    #[test]
    fn neither_a_token_nor_a_signature_is_ever_rendered() {
        assert_eq!(
            format!("{:?}", Credential::Bearer("SECRET-TOKEN".to_string())),
            "Bearer(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", Credential::Sas("sig=SECRET".to_string())),
            "Sas(<redacted>)"
        );
        let provider = TokenProvider::new(
            client(),
            CredentialSource::Sas {
                signature: "sig=SECRET".to_string(),
            },
        );
        let rendered = format!("{:?}", provider);
        assert!(!rendered.contains("SECRET"), "leaked: {}", rendered);
        assert!(rendered.contains("sas"));
    }

    #[test]
    fn a_cached_token_is_handed_out_until_the_refresh_margin() {
        let provider = TokenProvider::new(
            client(),
            CredentialSource::Imds {
                endpoint: "http://127.0.0.1:1".to_string(),
                client_id: None,
            },
        );
        // One hour of life, minus the five-minute margin: still valid.
        provider.store("token-a", Duration::from_secs(3600));
        assert_eq!(provider.cached().as_deref(), Some("token-a"));

        // A lifetime inside the margin is not cached beyond its floor.
        provider.store("token-b", REFRESH_MARGIN);
        let cached = lock(&provider.cache);
        let remaining = cached
            .as_ref()
            .expect("cached")
            .valid_until
            .saturating_duration_since(Instant::now());
        assert!(
            remaining <= MIN_CACHE,
            "a token expiring inside the refresh margin was cached for {:?}",
            remaining
        );
        drop(cached);

        provider.invalidate();
        assert_eq!(provider.cached(), None);
    }

    /// A token endpoint reporting an absurd lifetime must not overflow
    /// the cache deadline: `Instant + Duration` panics on overflow, and
    /// that panic would happen on the poller thread.
    #[test]
    fn an_absurd_lifetime_never_overflows_the_cache_deadline() {
        let provider = TokenProvider::new(
            client(),
            CredentialSource::Imds {
                endpoint: "http://127.0.0.1:1".to_string(),
                client_id: None,
            },
        );
        provider.store("token-huge", Duration::from_secs(u64::MAX));
        assert_eq!(provider.cached().as_deref(), Some("token-huge"));
        assert_eq!(
            expires_in_seconds(&serde_json::json!(u64::MAX)),
            Some(u64::MAX),
            "the wire value is read as it is; the clamp happens later"
        );
    }

    #[test]
    fn expires_in_is_read_from_a_number_or_a_string() {
        assert_eq!(
            expires_in_seconds(&serde_json::json!(3599)),
            Some(3599),
            "OAuth2 sends a number"
        );
        assert_eq!(
            expires_in_seconds(&serde_json::json!("3599")),
            Some(3599),
            "IMDS sends a string"
        );
        assert_eq!(expires_in_seconds(&serde_json::json!("soon")), None);
        assert_eq!(expires_in_seconds(&serde_json::json!(null)), None);
    }
}
