// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! AWS Cloud Map (Route 53 Auto Naming) JSON 1.1 client.
//!
//! Cloud Map speaks the AWS JSON 1.1 protocol: every operation is a
//! `POST /` with an `X-Amz-Target` header naming
//! `Route53AutoNaming_v20170314.<Operation>`, an
//! `application/x-amz-json-1.1` body, and a SigV4 `Authorization` header.
//! Two endpoints are involved:
//!
//! * the CONTROL plane, `servicediscovery.<region>.amazonaws.com`, for
//!   `RegisterInstance`, `DeregisterInstance`, `ListNamespaces` and
//!   `ListServices`;
//! * the DATA plane, `data-servicediscovery.<region>.amazonaws.com`, for
//!   `DiscoverInstances`.
//!
//! Sending a data-plane operation to the control host (or the reverse) is
//! an error AWS answers with `UnknownOperationException`, so the plane is
//! part of every call's type rather than a convention.

// `request_count` and the response fields the backend does not consume
// (`NamespaceName`, `ServiceName`, `HealthStatus`) are read by tests only.
// The three response fields are kept because they are what Cloud Map
// returns: dropping them from the type would make a future consumer
// re-derive the wire shape from scratch.
// Narrow on purpose (same idiom as `sha256.rs`): a test build still
// reports anything genuinely dead here.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::aws_credentials::AwsCredentialProvider;
use super::aws_sigv4;
use crate::dds::Error;

/// `X-Amz-Target` prefix of every Cloud Map operation.
const TARGET_PREFIX: &str = "Route53AutoNaming_v20170314";
/// SigV4 signing service name for Cloud Map (both planes).
const SIGNING_SERVICE: &str = "servicediscovery";
/// Per-request timeout. The poller bounds the whole call at 5 s, so a
/// single attempt must leave room for its retries.
const REQUEST_TIMEOUT: Duration = Duration::from_millis(1_500);
/// Total attempts for one operation (1 try + 2 retries).
const MAX_ATTEMPTS: u32 = 3;
/// Backoff before retry n (n starting at 1).
const RETRY_BACKOFF: Duration = Duration::from_millis(120);
/// Page size of `ListNamespaces` / `ListServices` (both are paginated:
/// the caller walks `NextToken` to the end).
const LIST_PAGE_SIZE: u32 = 100;

/// Which Cloud Map endpoint an operation belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plane {
    /// `servicediscovery.<region>.amazonaws.com`.
    Control,
    /// `data-servicediscovery.<region>.amazonaws.com`.
    Data,
}

/// Default endpoint of a plane in a region.
pub fn default_endpoint(plane: Plane, region: &str) -> String {
    match plane {
        Plane::Control => format!("https://servicediscovery.{}.amazonaws.com", region),
        Plane::Data => format!("https://data-servicediscovery.{}.amazonaws.com", region),
    }
}

// ============================================================================
// Wire types
// ============================================================================

/// `RegisterInstance` request.
#[derive(Debug, Serialize)]
pub struct RegisterInstanceRequest {
    /// `srv-...` service id.
    #[serde(rename = "ServiceId")]
    pub service_id: String,
    /// Instance id, unique inside the service.
    #[serde(rename = "InstanceId")]
    pub instance_id: String,
    /// Idempotency token: a repeated call with the same token and the same
    /// attributes is a no-op instead of a duplicate registration.
    #[serde(rename = "CreatorRequestId")]
    pub creator_request_id: String,
    /// Instance attributes (`AWS_INSTANCE_IPV4`, `AWS_INSTANCE_PORT`, ...).
    #[serde(rename = "Attributes")]
    pub attributes: HashMap<String, String>,
}

/// `DeregisterInstance` request.
#[derive(Debug, Serialize)]
pub struct DeregisterInstanceRequest {
    /// `srv-...` service id.
    #[serde(rename = "ServiceId")]
    pub service_id: String,
    /// Instance id to remove.
    #[serde(rename = "InstanceId")]
    pub instance_id: String,
}

/// Both control-plane instance operations answer with an operation id: the
/// change is applied asynchronously.
#[derive(Debug, Deserialize)]
pub struct OperationResponse {
    /// Id of the asynchronous operation, when AWS returned one.
    #[serde(rename = "OperationId", default)]
    pub operation_id: Option<String>,
}

/// `DiscoverInstances` request (data plane).
#[derive(Debug, Serialize)]
pub struct DiscoverInstancesRequest {
    /// Namespace HTTP name.
    #[serde(rename = "NamespaceName")]
    pub namespace_name: String,
    /// Service name.
    #[serde(rename = "ServiceName")]
    pub service_name: String,
    /// Attribute filter applied by Cloud Map, e.g. `DOMAIN_ID`.
    #[serde(rename = "QueryParameters", skip_serializing_if = "HashMap::is_empty")]
    pub query_parameters: HashMap<String, String>,
    /// `ALL`, `HEALTHY`, `UNHEALTHY` or `HEALTHY_OR_ELSE_ALL`.
    #[serde(rename = "HealthStatus")]
    pub health_status: String,
    /// Upper bound on returned instances (AWS caps it at 1000).
    #[serde(rename = "MaxResults")]
    pub max_results: u32,
}

/// One instance as `DiscoverInstances` returns it.
// `namespace_name`, `service_name` and `health_status` are what Cloud Map
// really sends; the backend keys off the attributes alone. They are kept
// so a future consumer does not re-derive the wire shape, and the
// allowance is on THIS type rather than the whole module.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveredInstance {
    /// Instance id.
    #[serde(rename = "InstanceId", default)]
    pub instance_id: String,
    /// Namespace the instance was found in.
    #[serde(rename = "NamespaceName", default)]
    pub namespace_name: Option<String>,
    /// Service the instance belongs to.
    #[serde(rename = "ServiceName", default)]
    pub service_name: Option<String>,
    /// Health status Cloud Map reports.
    #[serde(rename = "HealthStatus", default)]
    pub health_status: Option<String>,
    /// The attributes that were registered.
    #[serde(rename = "Attributes", default)]
    pub attributes: HashMap<String, String>,
}

/// `DiscoverInstances` response.
#[derive(Debug, Deserialize)]
pub struct DiscoverInstancesResponse {
    /// Instances matching the query.
    #[serde(rename = "Instances", default)]
    pub instances: Vec<DiscoveredInstance>,
}

/// A `ListNamespaces` / `ListServices` filter.
#[derive(Debug, Serialize)]
pub struct ListFilter {
    /// Filter name (`NAME`, `NAMESPACE_ID`).
    #[serde(rename = "Name")]
    pub name: String,
    /// Values the filter matches.
    #[serde(rename = "Values")]
    pub values: Vec<String>,
    /// Match condition (`EQ`).
    #[serde(rename = "Condition")]
    pub condition: String,
}

/// `ListNamespaces` / `ListServices` request.
#[derive(Debug, Serialize)]
pub struct ListRequest {
    /// Filters applied server-side.
    #[serde(rename = "Filters")]
    pub filters: Vec<ListFilter>,
    /// Page size.
    #[serde(rename = "MaxResults")]
    pub max_results: u32,
    /// Continuation token of the previous page, when there was one.
    #[serde(rename = "NextToken", skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
}

/// A namespace summary.
#[derive(Debug, Deserialize)]
pub struct NamespaceSummary {
    /// Namespace id (`ns-...`).
    #[serde(rename = "Id", default)]
    pub id: String,
    /// Namespace name as created.
    #[serde(rename = "Name", default)]
    pub name: String,
}

/// `ListNamespaces` response.
#[derive(Debug, Deserialize)]
pub struct ListNamespacesResponse {
    /// Namespaces matching the filters.
    #[serde(rename = "Namespaces", default)]
    pub namespaces: Vec<NamespaceSummary>,
    /// Continuation token: another page exists when this is `Some`.
    #[serde(rename = "NextToken", default)]
    pub next_token: Option<String>,
}

/// A service summary.
#[derive(Debug, Deserialize)]
pub struct ServiceSummary {
    /// Service id (`srv-...`).
    #[serde(rename = "Id", default)]
    pub id: String,
    /// Service name.
    #[serde(rename = "Name", default)]
    pub name: String,
}

/// `ListServices` response.
#[derive(Debug, Deserialize)]
pub struct ListServicesResponse {
    /// Services matching the filters.
    #[serde(rename = "Services", default)]
    pub services: Vec<ServiceSummary>,
    /// Continuation token: another page exists when this is `Some`.
    #[serde(rename = "NextToken", default)]
    pub next_token: Option<String>,
}

/// `GetService` request: the one call that turns a `srv-...` id into the
/// NAME `DiscoverInstances` needs.
#[derive(Debug, Serialize)]
pub struct GetServiceRequest {
    /// `srv-...` service id.
    #[serde(rename = "Id")]
    pub id: String,
}

/// `GetService` response.
#[derive(Debug, Deserialize)]
pub struct GetServiceResponse {
    /// The service, when AWS returned one.
    #[serde(rename = "Service", default)]
    pub service: Option<ServiceSummary>,
}

/// The two identities of one Cloud Map service.
///
/// They are NOT interchangeable and this is the whole reason the type
/// exists: `RegisterInstance` and `DeregisterInstance` take the `srv-...`
/// ID, while `DiscoverInstances` takes the service NAME (AWS rejects an
/// id there - it does not even match the `ServiceName` pattern once it is
/// an ARN). Sending one where the other belongs registers a participant
/// that then discovers nobody, forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceIdentity {
    /// `srv-...` id, for the control plane.
    pub id: String,
    /// Service name, for `DiscoverInstances`.
    pub name: String,
}

/// The AWS JSON 1.1 error shape.
#[derive(Debug, Deserialize, Default)]
struct ErrorBody {
    #[serde(rename = "__type", default)]
    error_type: Option<String>,
    #[serde(rename = "message", alias = "Message", default)]
    message: Option<String>,
}

/// The `__type` value with its `com.amazonaws...#` prefix stripped.
fn short_error_type(raw: &str) -> &str {
    raw.rsplit('#').next().unwrap_or(raw)
}

/// Errors AWS answers to a request that was fine but arrived too fast.
fn is_throttling(error_type: &str) -> bool {
    matches!(
        error_type,
        "RequestLimitExceeded"
            | "ThrottlingException"
            | "Throttling"
            | "TooManyRequestsException"
            | "ServiceUnavailable"
    )
}

/// Errors that mean the credentials in hand are no longer usable.
fn is_credential_error(error_type: &str) -> bool {
    matches!(
        error_type,
        "InvalidSignatureException"
            | "ExpiredTokenException"
            | "ExpiredToken"
            | "UnrecognizedClientException"
            | "InvalidClientTokenId"
            | "IncompleteSignature"
    )
}

// ============================================================================
// Client
// ============================================================================

/// A signed Cloud Map client over one region.
pub struct CloudMapClient {
    http: Client,
    region: String,
    control_endpoint: String,
    data_endpoint: String,
    credentials: AwsCredentialProvider,
    /// Resolved service identity (id AND name), cached after the first
    /// cold-path lookup.
    service: RwLock<Option<ServiceIdentity>>,
    /// Number of requests actually put on the wire (retries included).
    requests: std::sync::atomic::AtomicU32,
}

impl std::fmt::Debug for CloudMapClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudMapClient")
            .field("region", &self.region)
            .field("control_endpoint", &self.control_endpoint)
            .field("data_endpoint", &self.data_endpoint)
            .field("credentials", &self.credentials)
            .finish()
    }
}

impl CloudMapClient {
    /// Build a client for `region`.
    ///
    /// `endpoint_override` replaces BOTH plane endpoints (that is what a
    /// hermetic fake and a VPC endpoint both need). Plaintext `http://` is
    /// accepted only for a loopback host, by construction: see
    /// [`super::check_endpoint_transport`].
    pub fn new(
        http: Client,
        region: impl Into<String>,
        endpoint_override: Option<&str>,
        credentials: AwsCredentialProvider,
    ) -> Result<Self, Error> {
        let region = region.into();
        if region.is_empty() {
            return Err(Error::Config(
                "AWS Cloud Map region is empty: an endpoint and a SigV4 scope cannot be derived"
                    .to_string(),
            ));
        }
        let (control_endpoint, data_endpoint) = match endpoint_override {
            Some(endpoint) => {
                super::check_endpoint_transport(endpoint).map_err(Error::Config)?;
                let endpoint = endpoint.trim_end_matches('/').to_string();
                (endpoint.clone(), endpoint)
            }
            None => (
                default_endpoint(Plane::Control, &region),
                default_endpoint(Plane::Data, &region),
            ),
        };
        Ok(Self {
            http,
            region,
            control_endpoint,
            data_endpoint,
            credentials,
            service: RwLock::new(None),
            requests: std::sync::atomic::AtomicU32::new(0),
        })
    }

    /// Endpoint of a plane.
    pub fn endpoint(&self, plane: Plane) -> &str {
        match plane {
            Plane::Control => &self.control_endpoint,
            Plane::Data => &self.data_endpoint,
        }
    }

    /// Requests put on the wire so far, retries included.
    pub fn request_count(&self) -> u32 {
        self.requests.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Resolve credentials into the provider's cache without sending a
    /// Cloud Map request. Called from the backend's cold-path warm-up, so
    /// that the first real operation is one HTTP call rather than a whole
    /// credential chain plus one HTTP call.
    pub async fn warm_credentials(&self) -> Result<(), Error> {
        self.credentials.resolve(&self.http).await.map(|_| ())
    }

    /// Perform one operation, retrying throttling and 5xx answers.
    pub async fn call<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        plane: Plane,
        operation: &str,
        request: &Req,
    ) -> Result<Resp, Error> {
        let body = serde_json::to_vec(request).map_err(|e| {
            Error::Config(format!(
                "AWS Cloud Map {} request could not be serialised: {}",
                operation, e
            ))
        })?;
        let text = self.call_raw(plane, operation, &body).await?;
        // An empty 200 body is legal for operations with no output.
        if text.trim().is_empty() {
            return serde_json::from_str("{}").map_err(|e| {
                Error::Config(format!(
                    "AWS Cloud Map {} returned an empty body: {}",
                    operation, e
                ))
            });
        }
        serde_json::from_str(&text).map_err(|e| {
            Error::Config(format!(
                "AWS Cloud Map {} response could not be parsed: {}",
                operation, e
            ))
        })
    }

    async fn call_raw(&self, plane: Plane, operation: &str, body: &[u8]) -> Result<String, Error> {
        let endpoint = self.endpoint(plane);
        let url = reqwest::Url::parse(endpoint).map_err(|e| {
            Error::Config(format!(
                "AWS Cloud Map endpoint {:?} is not a URL: {}",
                endpoint, e
            ))
        })?;
        // The Host header hyper will really send: authority without the
        // scheme's default port. Signing anything else yields a signature
        // AWS computes over a different canonical request.
        let host = match (url.host_str(), url.port()) {
            (Some(host), Some(port)) => format!("{}:{}", host, port),
            (Some(host), None) => host.to_string(),
            (None, _) => {
                return Err(Error::Config(format!(
                    "AWS Cloud Map endpoint {:?} has no host",
                    endpoint
                )))
            }
        };
        let target = format!("{}.{}", TARGET_PREFIX, operation);

        let mut last_error = None;
        for attempt in 1..=MAX_ATTEMPTS {
            let credentials = self.credentials.resolve(&self.http).await?;
            let (datetime, date) = aws_sigv4::utc_now();
            let signed = aws_sigv4::sign_json_post(
                &credentials,
                &aws_sigv4::JsonPost {
                    host: &host,
                    target: &target,
                    body,
                    region: &self.region,
                    service: SIGNING_SERVICE,
                    datetime: &datetime,
                    date: &date,
                },
            );

            let mut request = self
                .http
                .post(url.clone())
                .timeout(REQUEST_TIMEOUT)
                .body(body.to_vec());
            for (name, value) in &signed.headers {
                // `host` is set by the HTTP stack from the URL; sending it
                // twice is what makes a signature mismatch impossible to
                // debug.
                if name != "host" {
                    request = request.header(name.as_str(), value.as_str());
                }
            }

            self.requests
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let response = match request.send().await {
                Ok(response) => response,
                Err(e) => {
                    last_error = Some(Error::Config(format!(
                        "AWS Cloud Map {} to {} failed: {}",
                        operation, endpoint, e
                    )));
                    if attempt < MAX_ATTEMPTS {
                        tokio::time::sleep(RETRY_BACKOFF * attempt).await;
                        continue;
                    }
                    break;
                }
            };

            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            if status.is_success() {
                return Ok(text);
            }

            let parsed: ErrorBody = serde_json::from_str(&text).unwrap_or_default();
            let error_type = parsed
                .error_type
                .as_deref()
                .map(short_error_type)
                .unwrap_or("")
                .to_string();
            let message = parsed
                .message
                .clone()
                .unwrap_or_else(|| text.chars().take(200).collect());

            if is_credential_error(&error_type) {
                // Either the credentials rotated under us or this host's
                // clock is outside the 15-minute SigV4 window: name the
                // x-amz-date we sent so the second case is legible.
                self.credentials.invalidate();
                last_error = Some(Error::Config(format!(
                    "AWS Cloud Map {} rejected the signature ({}): {} \
                     [x-amz-date sent: {}, region {}, credentials {}]",
                    operation,
                    error_type,
                    message,
                    datetime,
                    self.region,
                    self.credentials.source_summary()
                )));
                if attempt < MAX_ATTEMPTS {
                    tokio::time::sleep(RETRY_BACKOFF * attempt).await;
                    continue;
                }
                break;
            }

            let retryable = is_throttling(&error_type) || status.is_server_error();
            last_error = Some(Error::Config(format!(
                "AWS Cloud Map {} failed with HTTP {} {}: {}",
                operation,
                status.as_u16(),
                if error_type.is_empty() {
                    "(no __type)"
                } else {
                    error_type.as_str()
                },
                message
            )));
            if retryable && attempt < MAX_ATTEMPTS {
                tokio::time::sleep(RETRY_BACKOFF * attempt).await;
                continue;
            }
            break;
        }

        Err(last_error.unwrap_or_else(|| {
            Error::Config(format!("AWS Cloud Map {} failed with no answer", operation))
        }))
    }

    /// Resolve the configured service to BOTH identities it is used
    /// under: the `srv-...` id the control plane takes and the NAME
    /// `DiscoverInstances` takes.
    ///
    /// * a `srv-...` value, or an ARN whose last path segment is one,
    ///   gives the id for free; its NAME comes from `explicit_name` when
    ///   the caller configured one, else from ONE `GetService` call;
    /// * a plain NAME gives the name for free; its id comes from
    ///   `ListNamespaces` + `ListServices`, both paginated.
    ///
    /// The result is cached for the life of the client, so this is a
    /// cold-path lookup: `AwsCloudMap::prepare` runs it once, outside the
    /// poller's per-call budget.
    pub async fn resolve_service(
        &self,
        namespace: &str,
        service: &str,
        explicit_name: Option<&str>,
    ) -> Result<ServiceIdentity, Error> {
        if let Ok(guard) = self.service.read() {
            if let Some(identity) = guard.as_ref() {
                return Ok(identity.clone());
            }
        }

        let identity = match service_id_from_literal(service) {
            Some(id) => {
                let name = match explicit_name {
                    Some(name) => name.to_string(),
                    None => self.service_name_of(&id).await?,
                };
                ServiceIdentity { id, name }
            }
            None => ServiceIdentity {
                id: self.service_id_of(namespace, service).await?,
                name: service.to_string(),
            },
        };

        if let Ok(mut guard) = self.service.write() {
            *guard = Some(identity.clone());
        }
        Ok(identity)
    }

    /// NAME of a `srv-...` id, through one `GetService`.
    async fn service_name_of(&self, id: &str) -> Result<String, Error> {
        let response: GetServiceResponse = self
            .call(
                Plane::Control,
                "GetService",
                &GetServiceRequest { id: id.to_string() },
            )
            .await
            .map_err(|e| {
                Error::Config(format!(
                    "{}: resolving the NAME of service {} failed. DiscoverInstances takes the \
                     service NAME, never its id, so the name is required even when the id is \
                     configured: either grant servicediscovery:GetService, or set the \
                     `service_name` configuration field to the name the service was created with",
                    e, id
                ))
            })?;
        let name = response
            .service
            .map(|service| service.name)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                Error::Config(format!(
                    "AWS Cloud Map GetService {} returned no service name: set the \
                     `service_name` configuration field",
                    id
                ))
            })?;
        Ok(name)
    }

    /// `srv-...` id of a service NAME, through the two paginated list
    /// operations.
    async fn service_id_of(&self, namespace: &str, service: &str) -> Result<String, Error> {
        let mut next_token = None;
        let mut namespace_id = None;
        let mut namespaces_seen = 0usize;
        loop {
            let page: ListNamespacesResponse = self
                .call(
                    Plane::Control,
                    "ListNamespaces",
                    &ListRequest {
                        filters: vec![ListFilter {
                            name: "NAME".to_string(),
                            values: vec![namespace.to_string()],
                            condition: "EQ".to_string(),
                        }],
                        max_results: LIST_PAGE_SIZE,
                        next_token: next_token.clone(),
                    },
                )
                .await?;
            namespaces_seen += page.namespaces.len();
            if let Some(found) = page
                .namespaces
                .iter()
                .find(|candidate| candidate.name == namespace)
            {
                namespace_id = Some(found.id.clone());
                break;
            }
            next_token = page.next_token;
            if next_token.is_none() {
                break;
            }
        }
        let namespace_id = namespace_id.ok_or_else(|| {
            Error::Config(format!(
                "AWS Cloud Map namespace {:?} was not found in region {} \
                 (ListNamespaces returned {} namespaces)",
                namespace, self.region, namespaces_seen
            ))
        })?;

        // Pagination is not cosmetic here: ListServices filters by
        // NAMESPACE_ID only, so a namespace holding more services than one
        // page would otherwise report a service that exists as missing.
        let mut next_token = None;
        let mut services_seen = 0usize;
        loop {
            let page: ListServicesResponse = self
                .call(
                    Plane::Control,
                    "ListServices",
                    &ListRequest {
                        filters: vec![ListFilter {
                            name: "NAMESPACE_ID".to_string(),
                            values: vec![namespace_id.clone()],
                            condition: "EQ".to_string(),
                        }],
                        max_results: LIST_PAGE_SIZE,
                        next_token: next_token.clone(),
                    },
                )
                .await?;
            services_seen += page.services.len();
            if let Some(found) = page
                .services
                .iter()
                .find(|candidate| candidate.name == service)
            {
                return Ok(found.id.clone());
            }
            next_token = page.next_token;
            if next_token.is_none() {
                break;
            }
        }
        Err(Error::Config(format!(
            "AWS Cloud Map service {:?} was not found in namespace {:?} ({}), \
             across {} services on every page: check the name, or configure the \
             `srv-...` id directly",
            service, namespace, namespace_id, services_seen
        )))
    }
}

/// `srv-...`, or an ARN ending in one, used without any lookup.
fn service_id_from_literal(service: &str) -> Option<String> {
    if service.starts_with("srv-") {
        return Some(service.to_string());
    }
    if service.starts_with("arn:") {
        let last = service.rsplit('/').next().unwrap_or("");
        if last.starts_with("srv-") {
            return Some(last.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::cloud::aws_credentials::AwsCredentialSource;
    use crate::test_support::fake_http::{FakeHttpServer, FakeResponse};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(future)
    }

    fn client_for(endpoint: &str) -> CloudMapClient {
        let http = Client::builder().no_proxy().build().expect("http client");
        let credentials = AwsCredentialProvider::new(
            AwsCredentialSource::Static {
                access_key_id: "AKIDEXAMPLE".into(),
                secret_access_key: "secret".into(),
                session_token: None,
            },
            "eu-west-3",
        );
        CloudMapClient::new(http, "eu-west-3", Some(endpoint), credentials).expect("client")
    }

    #[test]
    fn default_endpoints_split_the_control_and_data_planes() {
        assert_eq!(
            default_endpoint(Plane::Control, "eu-west-3"),
            "https://servicediscovery.eu-west-3.amazonaws.com"
        );
        assert_eq!(
            default_endpoint(Plane::Data, "eu-west-3"),
            "https://data-servicediscovery.eu-west-3.amazonaws.com"
        );
    }

    /// Every call must carry the operation in `X-Amz-Target`, the JSON 1.1
    /// content type, and a SigV4 Authorization header scoped to the
    /// `servicediscovery` service.
    #[test]
    fn a_call_is_a_signed_json_1_1_post_naming_its_operation() {
        let server = FakeHttpServer::start(|_request| FakeResponse::json(200, r#"{}"#))
            .expect("fake Cloud Map");
        let client = client_for(&server.base_url());
        let _: OperationResponse = block_on(client.call(
            Plane::Control,
            "DeregisterInstance",
            &DeregisterInstanceRequest {
                service_id: "srv-1".into(),
                instance_id: "hdds-1".into(),
            },
        ))
        .expect("call succeeds");

        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.path(), "/");
        assert_eq!(
            request.header("x-amz-target"),
            Some("Route53AutoNaming_v20170314.DeregisterInstance")
        );
        assert_eq!(
            request.header("content-type"),
            Some(aws_sigv4::JSON_CONTENT_TYPE)
        );
        let authorization = request.header("authorization").expect("signed");
        assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"));
        assert!(
            authorization.contains("/eu-west-3/servicediscovery/aws4_request"),
            "wrong SigV4 scope: {}",
            authorization
        );
        assert!(request.header("x-amz-date").is_some());
        assert!(request.body_text().contains("\"ServiceId\":\"srv-1\""));
    }

    /// A plaintext endpoint is refused unless the host is loopback; there
    /// is no flag that re-opens it.
    #[test]
    fn plaintext_endpoint_is_refused_unless_loopback() {
        let http = Client::builder().no_proxy().build().expect("http client");
        let source = || {
            AwsCredentialProvider::new(
                AwsCredentialSource::Static {
                    access_key_id: "AKID".into(),
                    secret_access_key: "s".into(),
                    session_token: None,
                },
                "eu-west-3",
            )
        };
        for endpoint in ["http://cloudmap.example.com", "http://10.0.0.5:8080"] {
            let error = CloudMapClient::new(http.clone(), "eu-west-3", Some(endpoint), source())
                .expect_err("plaintext to a remote host must be refused");
            assert!(matches!(&error, Error::Config(m) if m.contains("plaintext http")));
        }
        for endpoint in ["http://127.0.0.1:8080", "https://cloudmap.example.com"] {
            assert!(
                CloudMapClient::new(http.clone(), "eu-west-3", Some(endpoint), source()).is_ok(),
                "legal endpoint refused: {}",
                endpoint
            );
        }
        assert!(CloudMapClient::new(http, "", None, source()).is_err());
    }

    /// The AWS `__type` and message reach the caller instead of a bare
    /// status code.
    #[test]
    fn aws_error_body_maps_to_a_config_error_naming_the_type() {
        let server = FakeHttpServer::start(|_request| {
            FakeResponse::json(
                400,
                r#"{"__type":"com.amazonaws.servicediscovery#ServiceNotFound",
                    "message":"srv-nope does not exist"}"#,
            )
        })
        .expect("fake Cloud Map");
        let client = client_for(&server.base_url());
        let error: Error = block_on(client.call::<_, OperationResponse>(
            Plane::Control,
            "RegisterInstance",
            &DeregisterInstanceRequest {
                service_id: "srv-nope".into(),
                instance_id: "hdds-1".into(),
            },
        ))
        .expect_err("a 400 must surface");
        let Error::Config(message) = &error else {
            panic!("unexpected error kind: {:?}", error);
        };
        assert!(message.contains("ServiceNotFound"), "{}", message);
        assert!(message.contains("srv-nope does not exist"), "{}", message);
        assert!(!message.contains("com.amazonaws"), "{}", message);
        // A client error is not retried.
        assert_eq!(server.request_count(), 1);
    }

    /// Throttling is retried up to the bound, then reported.
    #[test]
    fn request_limit_exceeded_is_retried_then_reported() {
        let server = FakeHttpServer::start(|_request| {
            FakeResponse::json(
                400,
                r#"{"__type":"RequestLimitExceeded","message":"slow down"}"#,
            )
        })
        .expect("fake Cloud Map");
        let client = client_for(&server.base_url());
        let error = block_on(client.call::<_, OperationResponse>(
            Plane::Control,
            "RegisterInstance",
            &DeregisterInstanceRequest {
                service_id: "srv-1".into(),
                instance_id: "hdds-1".into(),
            },
        ))
        .expect_err("exhausted retries must surface");
        assert!(matches!(&error, Error::Config(m) if m.contains("RequestLimitExceeded")));
        assert_eq!(server.request_count(), MAX_ATTEMPTS as usize);
        assert_eq!(client.request_count(), MAX_ATTEMPTS);
    }

    /// A signature rejection drops the cached credentials so the next
    /// attempt re-resolves them, and the error names the date we sent.
    #[test]
    fn a_signature_rejection_names_the_date_sent_and_invalidates_the_cache() {
        let server = FakeHttpServer::start(|_request| {
            FakeResponse::json(
                403,
                r#"{"__type":"InvalidSignatureException","message":"Signature expired"}"#,
            )
        })
        .expect("fake Cloud Map");
        let client = client_for(&server.base_url());
        let error = block_on(client.call::<_, OperationResponse>(
            Plane::Data,
            "DiscoverInstances",
            &DeregisterInstanceRequest {
                service_id: "srv-1".into(),
                instance_id: "x".into(),
            },
        ))
        .expect_err("403 must surface");
        let Error::Config(message) = &error else {
            panic!("unexpected error kind: {:?}", error);
        };
        assert!(message.contains("InvalidSignatureException"), "{}", message);
        assert!(message.contains("x-amz-date sent:"), "{}", message);
        assert!(message.contains("static(AKIDEXAMPLE)"), "{}", message);
        assert!(!message.contains("secret"), "{}", message);
    }

    /// A `srv-...` id or an ARN with an explicitly configured NAME is
    /// used verbatim: no ListNamespaces, no ListServices, no GetService,
    /// so a minimal IAM policy is enough.
    #[test]
    fn a_literal_service_id_or_arn_with_a_configured_name_needs_no_lookup() {
        let calls = Arc::new(AtomicU32::new(0));
        let server_calls = Arc::clone(&calls);
        let server = FakeHttpServer::start(move |_request| {
            server_calls.fetch_add(1, Ordering::SeqCst);
            FakeResponse::json(200, "{}")
        })
        .expect("fake Cloud Map");

        for service in [
            "srv-abcdef",
            "arn:aws:servicediscovery:eu-west-3:123456789012:service/srv-abcdef",
        ] {
            let client = client_for(&server.base_url());
            let identity = block_on(client.resolve_service("ns", service, Some("hdds-svc")))
                .expect("literal identity");
            assert_eq!(identity.id, "srv-abcdef");
            assert_eq!(identity.name, "hdds-svc");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    /// A `srv-...` id with NO configured name still needs the NAME, since
    /// that is what `DiscoverInstances` takes: exactly one `GetService`,
    /// then the cache.
    #[test]
    fn a_literal_service_id_without_a_name_resolves_it_once_through_get_service() {
        let calls = Arc::new(AtomicU32::new(0));
        let server_calls = Arc::clone(&calls);
        let server = FakeHttpServer::start(move |request| {
            server_calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                request.header("x-amz-target"),
                Some("Route53AutoNaming_v20170314.GetService")
            );
            assert!(request.body_text().contains("\"Id\":\"srv-abcdef\""));
            FakeResponse::json(200, r#"{"Service":{"Id":"srv-abcdef","Name":"hdds-svc"}}"#)
        })
        .expect("fake Cloud Map");
        let client = client_for(&server.base_url());

        let identity =
            block_on(client.resolve_service("ns", "srv-abcdef", None)).expect("GetService");
        assert_eq!(identity.id, "srv-abcdef");
        assert_eq!(identity.name, "hdds-svc");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let again = block_on(client.resolve_service("ns", "srv-abcdef", None)).expect("cached");
        assert_eq!(again, identity);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the second resolution must come from the cache"
        );
    }

    /// A denied `GetService` names the two ways out instead of surfacing
    /// as a bare access-denied.
    #[test]
    fn a_denied_get_service_names_the_service_name_field_and_the_iam_action() {
        let server = FakeHttpServer::start(|_request| {
            FakeResponse::json(
                400,
                r#"{"__type":"AccessDeniedException","message":"not authorized"}"#,
            )
        })
        .expect("fake Cloud Map");
        let client = client_for(&server.base_url());
        let error = block_on(client.resolve_service("ns", "srv-abcdef", None)).expect_err("denied");
        let Error::Config(message) = &error else {
            panic!("unexpected error kind: {:?}", error);
        };
        assert!(message.contains("AccessDeniedException"), "{}", message);
        assert!(
            message.contains("servicediscovery:GetService"),
            "{}",
            message
        );
        assert!(message.contains("service_name"), "{}", message);
    }

    /// A service NAME is resolved once through ListNamespaces +
    /// ListServices and cached.
    #[test]
    fn a_service_name_is_resolved_once_then_cached() {
        let list_calls = Arc::new(AtomicU32::new(0));
        let server_calls = Arc::clone(&list_calls);
        let server = FakeHttpServer::start(move |request| {
            let target = request.header("x-amz-target").unwrap_or("").to_string();
            server_calls.fetch_add(1, Ordering::SeqCst);
            if target.ends_with("ListNamespaces") {
                assert!(request.body_text().contains("\"Name\":\"NAME\""));
                FakeResponse::json(
                    200,
                    r#"{"Namespaces":[{"Id":"ns-1","Name":"other"},{"Id":"ns-2","Name":"hdds-ns"}]}"#,
                )
            } else if target.ends_with("ListServices") {
                assert!(request.body_text().contains("\"Values\":[\"ns-2\"]"));
                FakeResponse::json(
                    200,
                    r#"{"Services":[{"Id":"srv-999","Name":"hdds-svc"}]}"#,
                )
            } else {
                FakeResponse::status(404)
            }
        })
        .expect("fake Cloud Map");
        let client = client_for(&server.base_url());

        let identity =
            block_on(client.resolve_service("hdds-ns", "hdds-svc", None)).expect("resolved");
        assert_eq!(identity.id, "srv-999");
        assert_eq!(identity.name, "hdds-svc");
        assert_eq!(list_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            block_on(client.resolve_service("hdds-ns", "hdds-svc", None))
                .expect("cached")
                .id,
            "srv-999"
        );
        assert_eq!(
            list_calls.load(Ordering::SeqCst),
            2,
            "the second resolution must come from the cache"
        );
    }

    /// A namespace or service that does not exist is a loud error, not an
    /// empty peer list.
    #[test]
    fn an_unknown_namespace_or_service_fails_closed() {
        let server = FakeHttpServer::start(|request| {
            let target = request.header("x-amz-target").unwrap_or("").to_string();
            if target.ends_with("ListNamespaces") {
                FakeResponse::json(200, r#"{"Namespaces":[]}"#)
            } else {
                FakeResponse::json(200, r#"{"Services":[]}"#)
            }
        })
        .expect("fake Cloud Map");
        let client = client_for(&server.base_url());
        let error = block_on(client.resolve_service("hdds-ns", "hdds-svc", None))
            .expect_err("no namespace");
        assert!(
            matches!(&error, Error::Config(m) if m.contains("namespace \"hdds-ns\" was not found"))
        );
    }

    /// A service on the SECOND page must be found: both list operations
    /// walk `NextToken` instead of reporting page one as the whole world.
    #[test]
    fn a_service_beyond_the_first_page_is_still_found() {
        let server = FakeHttpServer::start(move |request| {
            let target = request.header("x-amz-target").unwrap_or("").to_string();
            let body = request.body_text();
            let paging = body.contains("\"NextToken\":\"page-2\"");
            if target.ends_with("ListNamespaces") {
                if paging {
                    FakeResponse::json(200, r#"{"Namespaces":[{"Id":"ns-2","Name":"hdds-ns"}]}"#)
                } else {
                    FakeResponse::json(
                        200,
                        r#"{"Namespaces":[{"Id":"ns-1","Name":"other"}],"NextToken":"page-2"}"#,
                    )
                }
            } else if target.ends_with("ListServices") {
                if paging {
                    FakeResponse::json(200, r#"{"Services":[{"Id":"srv-999","Name":"hdds-svc"}]}"#)
                } else {
                    FakeResponse::json(
                        200,
                        r#"{"Services":[{"Id":"srv-1","Name":"other"}],"NextToken":"page-2"}"#,
                    )
                }
            } else {
                FakeResponse::status(404)
            }
        })
        .expect("fake Cloud Map");
        let client = client_for(&server.base_url());
        let identity = block_on(client.resolve_service("hdds-ns", "hdds-svc", None))
            .expect("the second page is walked");
        assert_eq!(identity.id, "srv-999");
        assert_eq!(identity.name, "hdds-svc");
    }

    #[test]
    fn error_type_shortening_strips_the_java_package() {
        assert_eq!(
            short_error_type("com.amazonaws.servicediscovery#ServiceNotFound"),
            "ServiceNotFound"
        );
        assert_eq!(
            short_error_type("RequestLimitExceeded"),
            "RequestLimitExceeded"
        );
        assert!(is_throttling("ThrottlingException"));
        assert!(!is_throttling("ServiceNotFound"));
        assert!(is_credential_error("ExpiredTokenException"));
        assert!(!is_credential_error("ServiceNotFound"));
    }
}
