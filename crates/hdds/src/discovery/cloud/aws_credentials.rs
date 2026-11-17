// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! AWS credential resolution for the Cloud Map backend.
//!
//! The standard AWS credential chain, in the order the AWS SDKs use it:
//!
//! 1. **Static** - credentials given in the config (tests, and deployments
//!    that inject their own).
//! 2. **Environment** - `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
//!    (+ optional `AWS_SESSION_TOKEN`).
//! 3. **Web identity (IRSA)** - `AWS_WEB_IDENTITY_TOKEN_FILE` +
//!    `AWS_ROLE_ARN`, exchanged at STS for temporary credentials. This is
//!    how a pod gets credentials on EKS; without it the backend cannot run
//!    on the platform its own documentation names.
//! 4. **Container** - `AWS_CONTAINER_CREDENTIALS_FULL_URI` or
//!    `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` (ECS / Fargate task role).
//! 5. **IMDSv2** - instance metadata on `169.254.169.254`, token-first
//!    (`PUT /latest/api/token`, then the role name, then the credentials).
//!
//! Everything is FAIL CLOSED: when no source resolves, `resolve()` returns
//! `Error::Config` naming every source it tried and why each failed, and
//! the caller sends nothing. An unsigned or anonymously-signed request is
//! never produced.
//!
//! Every base URL is a field, never a hardcoded constant read at call
//! time, so a test points the chain at an in-process fake without setting
//! or mutating a single environment variable.

// `refresh_count` is a test observable of the caching policy; nothing in
// a normal build reads it. Stated rather than hidden behind `#[cfg(test)]`,
// which would let the counter itself drift out of the production path.
// Narrow on purpose (same idiom as `sha256.rs`): a test build still
// reports anything genuinely dead here.
#![cfg_attr(not(test), allow(dead_code))]

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::aws_sigv4::AwsCredentials;
use crate::dds::Error;

/// Default IMDS endpoint (link-local, plaintext by design: it is not a
/// registry endpoint and carries no user payload on the request side).
pub const DEFAULT_IMDS_ENDPOINT: &str = "http://169.254.169.254";
/// Default ECS container-credentials host for the RELATIVE_URI form.
pub const DEFAULT_CONTAINER_ENDPOINT: &str = "http://169.254.170.2";
/// IMDSv2 token lifetime requested (seconds).
const IMDS_TOKEN_TTL_SECONDS: u32 = 21_600;
/// Refresh temporary credentials this long before they expire.
const REFRESH_MARGIN: Duration = Duration::from_secs(300);
/// Per-request timeout for a metadata / STS call.
///
/// Deliberately short: the default chain walks up to four sources, and
/// the whole resolution has to fit inside the poller's warm-up budget
/// (`poller_thread::PREPARE_TIMEOUT`, 15 s) with room for the service
/// lookup that follows it. A metadata service that needs more than two
/// seconds per request is down, not slow.
const METADATA_TIMEOUT: Duration = Duration::from_secs(2);

/// Where credentials come from.
///
/// `Serialize`/`Deserialize` exist so a participant builder can carry the
/// choice; `Static` is deliberately part of the enum because a hermetic
/// test needs credentials the fake knows, but see
/// [`AwsCredentialSource::redacted_summary`] for what is allowed to be
/// rendered anywhere.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum AwsCredentialSource {
    /// The default chain: environment, web identity, container, IMDSv2.
    #[default]
    DefaultChain,
    /// Fixed credentials.
    Static {
        /// Access key id.
        access_key_id: String,
        /// Secret access key.
        secret_access_key: String,
        /// Optional STS session token.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_token: Option<String>,
    },
    /// `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`.
    Environment,
    /// EKS IRSA: a projected service-account token exchanged at STS.
    WebIdentity {
        /// Path of the projected OIDC token.
        token_file: String,
        /// Role to assume.
        role_arn: String,
        /// Session name reported to STS.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_name: Option<String>,
        /// STS endpoint; defaults to the regional endpoint.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sts_endpoint: Option<String>,
    },
    /// ECS / Fargate task role over the container credentials endpoint.
    Container {
        /// Full URI to GET.
        uri: String,
        /// Value of the `Authorization` header, when the platform sets one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authorization: Option<String>,
    },
    /// EC2 instance metadata, IMDSv2 (token-first).
    Imds {
        /// Base URL of the metadata service.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        endpoint: Option<String>,
    },
    /// Try each source in order, first success wins.
    ///
    /// A STRUCT variant, not a newtype one: this enum is internally
    /// tagged (`#[serde(tag = "kind")]`), and serde cannot represent a
    /// newtype variant holding a sequence in that form - `to_json` on a
    /// chain would fail at runtime on a public method.
    Chain {
        /// Sources to try, in order.
        sources: Vec<AwsCredentialSource>,
    },
}

impl AwsCredentialSource {
    /// A one-word name of the source, safe to log.
    pub fn label(&self) -> &'static str {
        match self {
            Self::DefaultChain => "default-chain",
            Self::Static { .. } => "static",
            Self::Environment => "environment",
            Self::WebIdentity { .. } => "web-identity",
            Self::Container { .. } => "container",
            Self::Imds { .. } => "imds",
            Self::Chain { .. } => "chain",
        }
    }

    /// What may be rendered in a log line or a public accessor: the source
    /// kind and its non-secret locations, never a key, token or password.
    pub fn redacted_summary(&self) -> String {
        match self {
            Self::Static { access_key_id, .. } => {
                format!("static({})", access_key_id)
            }
            Self::WebIdentity {
                role_arn,
                token_file,
                ..
            } => format!("web-identity({}, {})", role_arn, token_file),
            Self::Container { uri, .. } => format!("container({})", uri),
            Self::Imds { endpoint } => format!(
                "imds({})",
                endpoint.as_deref().unwrap_or(DEFAULT_IMDS_ENDPOINT)
            ),
            Self::Chain { sources } => {
                let inner: Vec<String> = sources.iter().map(Self::redacted_summary).collect();
                format!("chain[{}]", inner.join(", "))
            }
            other => other.label().to_string(),
        }
    }
}

impl std::fmt::Debug for AwsCredentialSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.redacted_summary())
    }
}

/// STS / container / IMDS credential documents all carry the same four
/// fields under slightly different names.
#[derive(Debug, Deserialize)]
struct CredentialResponse {
    #[serde(alias = "AccessKeyId")]
    access_key_id: String,
    #[serde(alias = "SecretAccessKey")]
    secret_access_key: String,
    // ECS returns "Token", IMDS returns "Token" too, STS returns
    // "SessionToken"; accept both spellings.
    #[serde(default, alias = "Token", alias = "SessionToken")]
    token: Option<String>,
    #[serde(default, alias = "Expiration")]
    expiration: Option<String>,
}

impl CredentialResponse {
    fn into_resolved(self) -> Resolved {
        let expires_at = self
            .expiration
            .as_deref()
            .and_then(parse_rfc3339_utc)
            .map(|secs| UNIX_EPOCH + Duration::from_secs(secs));
        Resolved {
            credentials: AwsCredentials {
                access_key_id: self.access_key_id,
                secret_access_key: self.secret_access_key,
                session_token: self.token,
            },
            expires_at,
        }
    }
}

/// Parse the `YYYY-MM-DDTHH:MM:SSZ` form AWS returns into a Unix second.
///
/// Anything else (a different offset, a malformed value) yields `None`,
/// which makes the credentials look non-expiring: the next 403 refreshes
/// them, which is strictly better than treating a parse failure as
/// "expired now" and hammering the metadata service.
fn parse_rfc3339_utc(value: &str) -> Option<u64> {
    let value = value.trim();
    let (date, rest) = value.split_once('T')?;
    let time = rest
        .strip_suffix('Z')
        .or_else(|| rest.strip_suffix("+00:00"))?;
    let time = time.split('.').next()?;
    let mut date_parts = date.split('-');
    let year: u64 = date_parts.next()?.parse().ok()?;
    let month: u64 = date_parts.next()?.parse().ok()?;
    let day: u64 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let mut time_parts = time.split(':');
    let hour: u64 = time_parts.next()?.parse().ok()?;
    let minute: u64 = time_parts.next()?.parse().ok()?;
    let second: u64 = time_parts.next()?.parse().ok()?;
    if time_parts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    // Days from the civil date (proleptic Gregorian), Howard Hinnant's
    // days_from_civil, shifted back to the Unix epoch.
    let year_adjusted = if month <= 2 {
        // Year 0 with a January or February month underflows: the value
        // comes straight off the wire (a metadata document, or the STS
        // XML), and the contract above says a malformed value yields
        // `None`, never a panic in a debug build.
        year.checked_sub(1)?
    } else {
        year
    };
    let era = year_adjusted / 400;
    let year_of_era = year_adjusted - era * 400;
    let month_shifted = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era;
    // 719468 = days from 0000-03-01 to 1970-01-01.
    let days = days.checked_sub(719_468)?;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// STS `AssumeRoleWithWebIdentityResponse`, parsed from XML.
///
/// `roxmltree` is already an optional dependency of this crate (the QoS
/// XML loaders use it); the `cloud-discovery` feature turns it on so this
/// module adds no crate to the tree.
fn parse_sts_credentials(xml: &str) -> Result<Resolved, String> {
    let document =
        roxmltree::Document::parse(xml).map_err(|e| format!("STS response is not XML: {}", e))?;
    let credentials = document
        .descendants()
        .find(|node| node.has_tag_name("Credentials"))
        .ok_or_else(|| "STS response has no Credentials element".to_string())?;
    let field = |name: &str| -> Option<String> {
        credentials
            .children()
            .find(|node| node.has_tag_name(name))
            .and_then(|node| node.text())
            .map(str::to_string)
    };
    let access_key_id =
        field("AccessKeyId").ok_or_else(|| "STS credentials have no AccessKeyId".to_string())?;
    let secret_access_key = field("SecretAccessKey")
        .ok_or_else(|| "STS credentials have no SecretAccessKey".to_string())?;
    let session_token =
        field("SessionToken").ok_or_else(|| "STS credentials have no SessionToken".to_string())?;
    let expires_at = field("Expiration")
        .as_deref()
        .and_then(parse_rfc3339_utc)
        .map(|secs| UNIX_EPOCH + Duration::from_secs(secs));
    Ok(Resolved {
        credentials: AwsCredentials {
            access_key_id,
            secret_access_key,
            session_token: Some(session_token),
        },
        expires_at,
    })
}

/// Credentials plus the instant they stop being usable.
#[derive(Clone, Debug)]
struct Resolved {
    credentials: AwsCredentials,
    expires_at: Option<SystemTime>,
}

impl Resolved {
    fn is_fresh(&self, now: SystemTime) -> bool {
        match self.expires_at {
            None => true,
            Some(expiry) => expiry
                .checked_sub(REFRESH_MARGIN)
                .map(|deadline| now < deadline)
                .unwrap_or(false),
        }
    }
}

/// Resolves and caches credentials for one Cloud Map client.
pub struct AwsCredentialProvider {
    source: AwsCredentialSource,
    region: String,
    cached: Mutex<Option<Resolved>>,
    /// Test seam: what "now" is. Production uses `SystemTime::now`.
    clock: Arc<dyn Fn() -> SystemTime + Send + Sync>,
    /// Counts every resolution that actually hit a source (not the cache).
    refreshes: std::sync::atomic::AtomicU32,
}

impl std::fmt::Debug for AwsCredentialProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsCredentialProvider")
            .field("source", &self.source.redacted_summary())
            .field("region", &self.region)
            .finish()
    }
}

impl AwsCredentialProvider {
    /// A provider over `source` for `region`.
    pub fn new(source: AwsCredentialSource, region: impl Into<String>) -> Self {
        Self {
            source,
            region: region.into(),
            cached: Mutex::new(None),
            clock: Arc::new(SystemTime::now),
            refreshes: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Replace the clock (tests only).
    #[cfg(test)]
    fn with_clock(mut self, clock: Arc<dyn Fn() -> SystemTime + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// How many times a source was really contacted.
    pub fn refresh_count(&self) -> u32 {
        self.refreshes.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The source, redacted, for logs and public accessors.
    pub fn source_summary(&self) -> String {
        self.source.redacted_summary()
    }

    /// Resolve credentials, using the cache while they are fresh.
    pub async fn resolve(&self, http: &Client) -> Result<AwsCredentials, Error> {
        let now = (self.clock)();
        if let Some(cached) = self.cached_fresh(now) {
            return Ok(cached);
        }
        let resolved = resolve_source(&self.source, http, &self.region)
            .await
            .map_err(|reasons| {
                Error::Config(format!(
                    "AWS credentials could not be resolved for region {}: {}",
                    self.region, reasons
                ))
            })?;
        self.refreshes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let credentials = resolved.credentials.clone();
        if let Ok(mut guard) = self.cached.lock() {
            *guard = Some(resolved);
        }
        Ok(credentials)
    }

    /// Drop the cache: called when AWS answers that the signature or the
    /// token is no longer valid.
    pub fn invalidate(&self) {
        if let Ok(mut guard) = self.cached.lock() {
            *guard = None;
        }
    }

    fn cached_fresh(&self, now: SystemTime) -> Option<AwsCredentials> {
        let guard = self.cached.lock().ok()?;
        let cached = guard.as_ref()?;
        cached.is_fresh(now).then(|| cached.credentials.clone())
    }
}

/// The chain the SDKs walk when nothing is configured, built from the
/// environment. Every entry keeps its own base URL so nothing re-reads the
/// environment later.
fn default_chain() -> AwsCredentialSource {
    let mut sources = vec![AwsCredentialSource::Environment];

    if let (Ok(token_file), Ok(role_arn)) = (
        std::env::var("AWS_WEB_IDENTITY_TOKEN_FILE"),
        std::env::var("AWS_ROLE_ARN"),
    ) {
        sources.push(AwsCredentialSource::WebIdentity {
            token_file,
            role_arn,
            session_name: std::env::var("AWS_ROLE_SESSION_NAME").ok(),
            sts_endpoint: std::env::var("AWS_STS_ENDPOINT").ok(),
        });
    }

    if let Ok(uri) = std::env::var("AWS_CONTAINER_CREDENTIALS_FULL_URI") {
        sources.push(AwsCredentialSource::Container {
            uri,
            authorization: container_authorization(),
        });
    } else if let Ok(relative) = std::env::var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
        sources.push(AwsCredentialSource::Container {
            uri: format!("{}{}", DEFAULT_CONTAINER_ENDPOINT, relative),
            authorization: container_authorization(),
        });
    }

    sources.push(AwsCredentialSource::Imds {
        endpoint: std::env::var("AWS_EC2_METADATA_SERVICE_ENDPOINT").ok(),
    });
    AwsCredentialSource::Chain { sources }
}

/// The container credentials `Authorization` header, from the token file
/// when the platform provides one, else from the inline variable.
fn container_authorization() -> Option<String> {
    if let Ok(path) = std::env::var("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") {
        if let Ok(token) = std::fs::read_to_string(&path) {
            return Some(token.trim().to_string());
        }
    }
    std::env::var("AWS_CONTAINER_AUTHORIZATION_TOKEN").ok()
}

/// Resolve one source, or return a human-readable list of what failed.
fn resolve_source<'a>(
    source: &'a AwsCredentialSource,
    http: &'a Client,
    region: &'a str,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Resolved, String>> + Send + 'a>> {
    Box::pin(async move {
        match source {
            AwsCredentialSource::DefaultChain => {
                resolve_source(&default_chain(), http, region).await
            }
            AwsCredentialSource::Static {
                access_key_id,
                secret_access_key,
                session_token,
            } => {
                if access_key_id.is_empty() || secret_access_key.is_empty() {
                    return Err("static: access key id or secret is empty".to_string());
                }
                Ok(Resolved {
                    credentials: AwsCredentials {
                        access_key_id: access_key_id.clone(),
                        secret_access_key: secret_access_key.clone(),
                        session_token: session_token.clone(),
                    },
                    expires_at: None,
                })
            }
            AwsCredentialSource::Environment => {
                let access_key_id = std::env::var("AWS_ACCESS_KEY_ID")
                    .map_err(|_| "environment: AWS_ACCESS_KEY_ID is not set".to_string())?;
                let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY")
                    .map_err(|_| "environment: AWS_SECRET_ACCESS_KEY is not set".to_string())?;
                if access_key_id.is_empty() || secret_access_key.is_empty() {
                    return Err(
                        "environment: AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY is empty"
                            .to_string(),
                    );
                }
                Ok(Resolved {
                    credentials: AwsCredentials {
                        access_key_id,
                        secret_access_key,
                        session_token: std::env::var("AWS_SESSION_TOKEN").ok(),
                    },
                    expires_at: None,
                })
            }
            AwsCredentialSource::WebIdentity {
                token_file,
                role_arn,
                session_name,
                sts_endpoint,
            } => {
                resolve_web_identity(
                    http,
                    region,
                    token_file,
                    role_arn,
                    session_name.as_deref(),
                    sts_endpoint.as_deref(),
                )
                .await
            }
            AwsCredentialSource::Container { uri, authorization } => {
                resolve_container(http, uri, authorization.as_deref()).await
            }
            AwsCredentialSource::Imds { endpoint } => {
                resolve_imds(http, endpoint.as_deref().unwrap_or(DEFAULT_IMDS_ENDPOINT)).await
            }
            AwsCredentialSource::Chain { sources } => {
                if sources.is_empty() {
                    return Err("chain: no source configured".to_string());
                }
                let mut reasons = Vec::with_capacity(sources.len());
                for inner in sources {
                    match resolve_source(inner, http, region).await {
                        Ok(resolved) => return Ok(resolved),
                        Err(reason) => reasons.push(reason),
                    }
                }
                Err(reasons.join("; "))
            }
        }
    })
}

async fn resolve_container(
    http: &Client,
    uri: &str,
    authorization: Option<&str>,
) -> Result<Resolved, String> {
    super::check_metadata_endpoint(uri).map_err(|e| format!("container: {}", e))?;
    let mut request = http.get(uri).timeout(METADATA_TIMEOUT);
    if let Some(token) = authorization {
        request = request.header("Authorization", token);
    }
    let response = request
        .send()
        .await
        .map_err(|e| format!("container: GET {} failed: {}", uri, e))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("container: GET {} returned {}", uri, status));
    }
    let body = response
        .text()
        .await
        .map_err(|e| format!("container: body of {} unreadable: {}", uri, e))?;
    let parsed: CredentialResponse = serde_json::from_str(&body)
        .map_err(|e| format!("container: {} did not return credentials JSON: {}", uri, e))?;
    Ok(parsed.into_resolved())
}

async fn resolve_imds(http: &Client, endpoint: &str) -> Result<Resolved, String> {
    super::check_metadata_endpoint(endpoint).map_err(|e| format!("imds: {}", e))?;
    let endpoint = endpoint.trim_end_matches('/');

    // IMDSv2 is token-first BY CONSTRUCTION: there is no v1 fallback here.
    // A v1 GET is exactly the request an SSRF turns into a credential
    // leak, and every instance that can answer v2 answers v2.
    let token = http
        .put(format!("{}/latest/api/token", endpoint))
        .header(
            "x-aws-ec2-metadata-token-ttl-seconds",
            IMDS_TOKEN_TTL_SECONDS.to_string(),
        )
        .timeout(METADATA_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("imds: token request failed: {}", e))?;
    if !token.status().is_success() {
        return Err(format!(
            "imds: token request returned {} (IMDSv1 is not used)",
            token.status()
        ));
    }
    let token = token
        .text()
        .await
        .map_err(|e| format!("imds: token body unreadable: {}", e))?;
    let token = token.trim().to_string();

    let role = http
        .get(format!(
            "{}/latest/meta-data/iam/security-credentials/",
            endpoint
        ))
        .header("x-aws-ec2-metadata-token", &token)
        .timeout(METADATA_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("imds: role listing failed: {}", e))?;
    if !role.status().is_success() {
        return Err(format!(
            "imds: role listing returned {} (no instance profile?)",
            role.status()
        ));
    }
    let role = role
        .text()
        .await
        .map_err(|e| format!("imds: role listing unreadable: {}", e))?;
    let role = role
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| "imds: instance has no role attached".to_string())?;

    // The role name is a path SEGMENT: percent-encode it with the same
    // unreserved set SigV4 canonicalisation uses. A role containing a
    // space, '#' or '?' would otherwise build a malformed request whose
    // failure reads as an opaque 404.
    let response = http
        .get(format!(
            "{}/latest/meta-data/iam/security-credentials/{}",
            endpoint,
            super::aws_sigv4::uri_encode(role, true)
        ))
        .header("x-aws-ec2-metadata-token", &token)
        .timeout(METADATA_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("imds: credential request failed: {}", e))?;
    if !response.status().is_success() {
        return Err(format!(
            "imds: credential request returned {}",
            response.status()
        ));
    }
    let body = response
        .text()
        .await
        .map_err(|e| format!("imds: credential body unreadable: {}", e))?;
    let parsed: CredentialResponse = serde_json::from_str(&body)
        .map_err(|e| format!("imds: credential body is not JSON: {}", e))?;
    Ok(parsed.into_resolved())
}

async fn resolve_web_identity(
    http: &Client,
    region: &str,
    token_file: &str,
    role_arn: &str,
    session_name: Option<&str>,
    sts_endpoint: Option<&str>,
) -> Result<Resolved, String> {
    let token = std::fs::read_to_string(token_file).map_err(|e| {
        format!(
            "web-identity: token file {} is unreadable: {}",
            token_file, e
        )
    })?;
    let token = token.trim();
    if token.is_empty() {
        return Err(format!("web-identity: token file {} is empty", token_file));
    }

    let endpoint = match sts_endpoint {
        Some(endpoint) => endpoint.trim_end_matches('/').to_string(),
        None => format!("https://sts.{}.amazonaws.com", region),
    };
    // The STS endpoint carries the OIDC assertion and receives a secret
    // back: same transport rule as a registry endpoint.
    super::check_endpoint_transport(&endpoint).map_err(|e| format!("web-identity: {}", e))?;

    let session_name = session_name.unwrap_or("hdds-cloud-discovery");
    let form = [
        ("Action", "AssumeRoleWithWebIdentity"),
        ("Version", "2011-06-15"),
        ("RoleArn", role_arn),
        ("RoleSessionName", session_name),
        ("WebIdentityToken", token),
    ];
    let response = http
        .post(&endpoint)
        .form(&form)
        .timeout(METADATA_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("web-identity: STS call to {} failed: {}", endpoint, e))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| format!("web-identity: STS body unreadable: {}", e))?;
    if !status.is_success() {
        return Err(format!(
            "web-identity: STS returned {} for role {}: {}",
            status,
            role_arn,
            first_line(&body)
        ));
    }
    parse_sts_credentials(&body).map_err(|e| format!("web-identity: {}", e))
}

/// First line of a body, bounded, for an error message.
fn first_line(body: &str) -> String {
    let line = body.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    line.chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fake_http::{FakeHttpServer, FakeResponse};

    fn client() -> Client {
        Client::builder()
            .no_proxy()
            .build()
            .expect("test HTTP client")
    }

    fn provider(source: AwsCredentialSource) -> AwsCredentialProvider {
        AwsCredentialProvider::new(source, "eu-west-3")
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(future)
    }

    #[test]
    fn static_source_is_returned_verbatim_and_cached() {
        let provider = provider(AwsCredentialSource::Static {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "secret".into(),
            session_token: Some("token".into()),
        });
        let http = client();
        let creds = block_on(provider.resolve(&http)).expect("static credentials resolve");
        assert_eq!(creds.access_key_id, "AKIDEXAMPLE");
        assert_eq!(creds.secret_access_key, "secret");
        assert_eq!(creds.session_token.as_deref(), Some("token"));
        block_on(provider.resolve(&http)).expect("second resolve");
        assert_eq!(provider.refresh_count(), 1, "second resolve must be cached");
    }

    /// Nothing resolves -> a Config error naming every source tried. The
    /// caller must never fall back to an unsigned request.
    #[test]
    fn empty_and_failing_chains_fail_closed_with_every_reason() {
        let http = client();
        let empty = provider(AwsCredentialSource::Chain { sources: vec![] });
        let error = block_on(empty.resolve(&http)).expect_err("an empty chain must fail");
        assert!(
            matches!(&error, Error::Config(m) if m.contains("no source configured")),
            "unexpected error: {:?}",
            error
        );

        // A container source pointed at a closed loopback port and a
        // static source with an empty secret: both must be named.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = closed.local_addr().expect("addr").port();
        drop(closed);
        let failing = provider(AwsCredentialSource::Chain {
            sources: vec![
                AwsCredentialSource::Static {
                    access_key_id: "AKID".into(),
                    secret_access_key: String::new(),
                    session_token: None,
                },
                AwsCredentialSource::Container {
                    uri: format!("http://127.0.0.1:{}/creds", port),
                    authorization: None,
                },
            ],
        });
        let error = block_on(failing.resolve(&http)).expect_err("a failing chain must fail");
        let Error::Config(message) = &error else {
            panic!("unexpected error kind: {:?}", error);
        };
        assert!(
            message.contains("static:"),
            "missing static reason: {}",
            message
        );
        assert!(
            message.contains("container:"),
            "missing container reason: {}",
            message
        );
    }

    #[test]
    fn container_source_fetches_json_and_honours_the_authorization_header() {
        let server = FakeHttpServer::start(|request| {
            if request.path() != "/creds" {
                return FakeResponse::status(404);
            }
            if request.header("authorization") != Some("Bearer opaque") {
                return FakeResponse::status(401);
            }
            FakeResponse::json(
                200,
                r#"{"AccessKeyId":"ASIAECS","SecretAccessKey":"ecs-secret",
                    "Token":"ecs-token","Expiration":"2099-01-01T00:00:00Z"}"#,
            )
        })
        .expect("fake credentials endpoint");

        let http = client();
        let unauthorized = provider(AwsCredentialSource::Container {
            uri: format!("{}/creds", server.base_url()),
            authorization: None,
        });
        let error = block_on(unauthorized.resolve(&http)).expect_err("401 must fail closed");
        assert!(matches!(&error, Error::Config(m) if m.contains("401")));

        let authorized = provider(AwsCredentialSource::Container {
            uri: format!("{}/creds", server.base_url()),
            authorization: Some("Bearer opaque".into()),
        });
        let creds = block_on(authorized.resolve(&http)).expect("container credentials");
        assert_eq!(creds.access_key_id, "ASIAECS");
        assert_eq!(creds.session_token.as_deref(), Some("ecs-token"));
    }

    /// IMDSv2 only: the PUT that mints the session token must come first,
    /// carry the TTL header, and every later GET must present the token.
    /// A v1 GET is never attempted.
    #[test]
    fn imds_v2_puts_a_token_before_every_get_and_never_falls_back_to_v1() {
        let server =
            FakeHttpServer::start(|request| match (request.method.as_str(), request.path()) {
                ("PUT", "/latest/api/token") => {
                    if request
                        .header("x-aws-ec2-metadata-token-ttl-seconds")
                        .is_none()
                    {
                        return FakeResponse::status(400);
                    }
                    FakeResponse::text(200, "IMDS-TOKEN")
                }
                ("GET", path) if path.starts_with("/latest/meta-data/iam/security-credentials") => {
                    if request.header("x-aws-ec2-metadata-token") != Some("IMDS-TOKEN") {
                        return FakeResponse::status(401);
                    }
                    if path.ends_with('/') {
                        FakeResponse::text(200, "hdds-node-role\n")
                    } else if path.ends_with("hdds-node-role") {
                        FakeResponse::json(
                            200,
                            r#"{"AccessKeyId":"ASIAIMDS","SecretAccessKey":"imds-secret",
                            "Token":"imds-token","Expiration":"2099-01-01T00:00:00Z"}"#,
                        )
                    } else {
                        FakeResponse::status(404)
                    }
                }
                _ => FakeResponse::status(404),
            })
            .expect("fake IMDS");

        let http = client();
        let provider = provider(AwsCredentialSource::Imds {
            endpoint: Some(server.base_url()),
        });
        let creds = block_on(provider.resolve(&http)).expect("IMDSv2 credentials");
        assert_eq!(creds.access_key_id, "ASIAIMDS");
        assert_eq!(creds.session_token.as_deref(), Some("imds-token"));

        let requests = server.requests();
        assert_eq!(requests[0].method, "PUT");
        assert_eq!(requests[0].path(), "/latest/api/token");
        assert!(
            requests[1..]
                .iter()
                .all(|r| r.method == "GET"
                    && r.header("x-aws-ec2-metadata-token") == Some("IMDS-TOKEN")),
            "an unauthenticated (IMDSv1) GET was attempted: {:?}",
            requests
        );
    }

    /// EKS IRSA: the projected token is POSTed to STS as
    /// AssumeRoleWithWebIdentity and the XML answer is parsed.
    #[test]
    fn web_identity_exchanges_the_projected_token_at_sts() {
        let token_file = std::env::temp_dir().join(format!(
            "hdds-irsa-token-{}-{}",
            std::process::id(),
            fastrand::u32(..)
        ));
        std::fs::write(&token_file, "eyJhbGciOiJSUzI1NiJ9.projected.token\n")
            .expect("write token file");

        let server = FakeHttpServer::start(|request| {
            let body = request.body_text();
            if request.method != "POST" || !body.contains("Action=AssumeRoleWithWebIdentity") {
                return FakeResponse::status(400);
            }
            if !body.contains("WebIdentityToken=eyJhbGciOiJSUzI1NiJ9.projected.token") {
                return FakeResponse::text(400, "token not forwarded");
            }
            if !body.contains("RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fhdds") {
                return FakeResponse::text(400, "role not forwarded");
            }
            FakeResponse::text(
                200,
                r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIAIRSA</AccessKeyId>
      <SecretAccessKey>irsa-secret</SecretAccessKey>
      <SessionToken>irsa-token</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>"#,
            )
        })
        .expect("fake STS");

        let http = client();
        let provider = provider(AwsCredentialSource::WebIdentity {
            token_file: token_file.to_string_lossy().into_owned(),
            role_arn: "arn:aws:iam::123456789012:role/hdds".into(),
            session_name: Some("hdds-test".into()),
            sts_endpoint: Some(server.base_url()),
        });
        let creds = block_on(provider.resolve(&http)).expect("IRSA credentials");
        assert_eq!(creds.access_key_id, "ASIAIRSA");
        assert_eq!(creds.secret_access_key, "irsa-secret");
        assert_eq!(creds.session_token.as_deref(), Some("irsa-token"));

        let _ = std::fs::remove_file(&token_file);
    }

    /// A missing token file is a fail-closed error, not a silent skip to
    /// an anonymous request.
    #[test]
    fn web_identity_without_a_token_file_fails_closed() {
        let http = client();
        let provider = provider(AwsCredentialSource::WebIdentity {
            token_file: "/nonexistent/hdds/irsa/token".into(),
            role_arn: "arn:aws:iam::123456789012:role/hdds".into(),
            session_name: None,
            sts_endpoint: None,
        });
        let error = block_on(provider.resolve(&http)).expect_err("no token file, no credentials");
        assert!(
            matches!(&error, Error::Config(m) if m.contains("token file") && m.contains("unreadable")),
            "unexpected error: {:?}",
            error
        );
    }

    /// Temporary credentials are re-fetched once their expiry comes within
    /// the refresh margin, and only then.
    #[test]
    fn expiring_credentials_are_refreshed_once_the_margin_is_reached() {
        let issued = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let server_issued = Arc::clone(&issued);
        let server = FakeHttpServer::start(move |_request| {
            let nth = server_issued.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            FakeResponse::json(
                200,
                &format!(
                    r#"{{"AccessKeyId":"ASIA{}","SecretAccessKey":"s","Token":"t",
                         "Expiration":"1970-01-01T01:00:00Z"}}"#,
                    nth
                ),
            )
        })
        .expect("fake credentials endpoint");

        let now = Arc::new(Mutex::new(UNIX_EPOCH));
        let clock_now = Arc::clone(&now);
        let provider = AwsCredentialProvider::new(
            AwsCredentialSource::Container {
                uri: format!("{}/creds", server.base_url()),
                authorization: None,
            },
            "eu-west-3",
        )
        .with_clock(Arc::new(move || *clock_now.lock().expect("clock lock")));

        let http = client();
        // Expiry is at t+3600; the margin is 300 s.
        assert_eq!(
            block_on(provider.resolve(&http))
                .expect("first")
                .access_key_id,
            "ASIA0"
        );
        *now.lock().expect("clock") = UNIX_EPOCH + Duration::from_secs(3_000);
        assert_eq!(
            block_on(provider.resolve(&http))
                .expect("still fresh")
                .access_key_id,
            "ASIA0"
        );
        assert_eq!(provider.refresh_count(), 1);
        *now.lock().expect("clock") = UNIX_EPOCH + Duration::from_secs(3_400);
        assert_eq!(
            block_on(provider.resolve(&http))
                .expect("refreshed")
                .access_key_id,
            "ASIA1"
        );
        assert_eq!(provider.refresh_count(), 2);
    }

    #[test]
    fn expiration_timestamps_parse_to_unix_seconds() {
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_utc("2015-08-30T12:36:00Z"),
            Some(1_440_938_160)
        );
        assert_eq!(
            parse_rfc3339_utc("2023-11-14T22:13:20Z"),
            Some(1_700_000_000)
        );
        assert_eq!(
            parse_rfc3339_utc("2024-02-29T12:00:00Z"),
            Some(1_709_208_000)
        );
        assert_eq!(
            parse_rfc3339_utc("2024-02-29T12:00:00.123Z"),
            Some(1_709_208_000)
        );
        assert_eq!(parse_rfc3339_utc("2024-02-29T12:00:00+02:00"), None);
        assert_eq!(parse_rfc3339_utc("not-a-date"), None);
        assert_eq!(parse_rfc3339_utc("2024-13-01T00:00:00Z"), None);
        // Year zero: the civil-date arithmetic shifts January and
        // February back a year, which would underflow and PANIC in a
        // debug build on a value that arrives straight off the wire.
        assert_eq!(parse_rfc3339_utc("0000-01-01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_utc("0000-02-29T00:00:00Z"), None);
        // March of year zero does not shift, so it is merely before the
        // epoch and still yields None rather than a wrapped number.
        assert_eq!(parse_rfc3339_utc("0000-03-01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_utc("0001-01-01T00:00:00Z"), None);
    }

    /// Every variant of the source must survive `to_json` -> `from_json`.
    /// `Chain` is the one that could not: serde's internally tagged
    /// representation cannot serialise a newtype variant holding a
    /// sequence, so a chain config failed at runtime on a public method.
    #[test]
    fn every_credential_source_variant_round_trips_through_json() {
        let sources = [
            AwsCredentialSource::DefaultChain,
            AwsCredentialSource::Environment,
            AwsCredentialSource::Static {
                access_key_id: "AKIDEXAMPLE".into(),
                secret_access_key: "s".into(),
                session_token: None,
            },
            AwsCredentialSource::WebIdentity {
                token_file: "/var/run/token".into(),
                role_arn: "arn:aws:iam::123456789012:role/hdds".into(),
                session_name: None,
                sts_endpoint: None,
            },
            AwsCredentialSource::Container {
                uri: "http://169.254.170.2/creds".into(),
                authorization: None,
            },
            AwsCredentialSource::Imds { endpoint: None },
            AwsCredentialSource::Chain {
                sources: vec![
                    AwsCredentialSource::Environment,
                    AwsCredentialSource::Imds { endpoint: None },
                ],
            },
        ];
        for source in sources {
            let json = serde_json::to_string(&source)
                .unwrap_or_else(|e| panic!("{} does not serialise: {}", source.label(), e));
            let parsed: AwsCredentialSource = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("{} does not parse back: {}", source.label(), e));
            assert_eq!(parsed.label(), source.label());
            assert_eq!(parsed.redacted_summary(), source.redacted_summary());
        }
    }

    /// The IMDS role name is a path segment: a name with a space must be
    /// percent-encoded, not sent raw into the URL.
    #[test]
    fn an_imds_role_name_with_a_space_is_percent_encoded() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        let server = FakeHttpServer::start(move |request| {
            seen.lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(request.target.clone());
            if request.method == "PUT" {
                return FakeResponse::text(200, "token");
            }
            if request.target.ends_with("/security-credentials/") {
                return FakeResponse::text(200, "hdds role");
            }
            FakeResponse::json(
                200,
                r#"{"AccessKeyId":"ASIA","SecretAccessKey":"s","Token":"t"}"#,
            )
        })
        .expect("fake IMDS");
        let http = client();
        let credentials =
            block_on(resolve_imds(&http, &server.base_url())).expect("the encoded role resolves");
        assert_eq!(credentials.credentials.access_key_id, "ASIA");
        let targets = requests.lock().unwrap_or_else(|p| p.into_inner()).clone();
        assert!(
            targets
                .iter()
                .any(|target| target.ends_with("/security-credentials/hdds%20role")),
            "the role segment was not percent-encoded: {:?}",
            targets
        );
    }

    /// Nothing that renders a source may carry a secret.
    #[test]
    fn credential_source_debug_and_summary_never_render_a_secret() {
        let source = AwsCredentialSource::Chain {
            sources: vec![
                AwsCredentialSource::Static {
                    access_key_id: "AKIDEXAMPLE".into(),
                    secret_access_key: "top-secret-value".into(),
                    session_token: Some("session-secret-value".into()),
                },
                AwsCredentialSource::Container {
                    uri: "http://127.0.0.1:9/creds".into(),
                    authorization: Some("Bearer header-secret-value".into()),
                },
            ],
        };
        for rendered in [format!("{:?}", source), source.redacted_summary()] {
            assert!(rendered.contains("AKIDEXAMPLE"));
            assert!(!rendered.contains("top-secret-value"), "{}", rendered);
            assert!(!rendered.contains("session-secret-value"), "{}", rendered);
            assert!(!rendered.contains("header-secret-value"), "{}", rendered);
        }
        let provider = provider(source);
        let rendered = format!("{:?}", provider);
        assert!(!rendered.contains("top-secret-value"), "{}", rendered);
    }

    /// A metadata endpoint must stay link-local or loopback: a config that
    /// points the credential chain at an arbitrary remote host is how an
    /// SSRF becomes a credential exfiltration.
    #[test]
    fn metadata_endpoints_outside_the_link_local_range_are_refused() {
        let http = client();
        for uri in [
            "http://evil.example.com/creds",
            "http://10.0.0.5/creds",
            "https://evil.example.com/creds",
        ] {
            let error = block_on(
                provider(AwsCredentialSource::Container {
                    uri: uri.to_string(),
                    authorization: None,
                })
                .resolve(&http),
            )
            .expect_err("a remote metadata endpoint must be refused");
            assert!(
                matches!(&error, Error::Config(m) if m.contains("container:")),
                "unexpected error for {}: {:?}",
                uri,
                error
            );
        }
    }
}
