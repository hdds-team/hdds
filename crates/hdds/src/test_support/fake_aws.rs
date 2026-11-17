// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! In-process fake AWS Cloud Map endpoint for hermetic tests.
//!
//! Serves, on one loopback port and with no network, no TLS and no AWS
//! account:
//!
//! * `POST /` - the Cloud Map JSON 1.1 API, routed on `X-Amz-Target`:
//!   `RegisterInstance`, `DeregisterInstance`, `DiscoverInstances`,
//!   `ListNamespaces`, `ListServices`;
//! * `GET /creds` - a container-credentials document, so a test drives the
//!   real credential chain without setting one environment variable;
//! * `GET /task` - an ECS task metadata document.
//!
//! EVERY request to `/` has its SigV4 signature RECOMPUTED from what
//! arrived on the wire and compared with the `Authorization` header; a
//! mismatch is answered `403 InvalidSignatureException`, exactly as AWS
//! does. So a canonicalisation bug fails a test instead of passing
//! silently.
//!
//! Limitation, stated where it matters: the verifier calls the same
//! `aws_sigv4` code the client does, so a SYMMETRIC canonicalisation bug
//! would satisfy both sides. The independent oracle for that is
//! `discovery::cloud::aws_sigv4::tests::sigv4_matches_the_official_aws_test_suite_vectors`,
//! which compares against signatures AWS publishes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use crate::discovery::cloud::aws_sigv4::{self, AwsCredentials, SigningRequest};

use super::fake_http::{FakeHttpServer, FakeRequest, FakeResponse};

/// Access key id the fake accepts.
pub const FAKE_ACCESS_KEY_ID: &str = "AKIDEXAMPLE";
/// Secret the fake verifies signatures with.
// @audit-ok: fixed test value for an in-process fake, not a credential.
pub const FAKE_SECRET_ACCESS_KEY: &str = "hdds-fake-cloud-map-secret";
/// Session token the fake's credential document hands out.
pub const FAKE_SESSION_TOKEN: &str = "hdds-fake-session-token";
/// Namespace id the fake's `ListNamespaces` returns.
pub const FAKE_NAMESPACE_ID: &str = "ns-hddsfake";
/// Service id the fake's `ListServices` returns.
pub const FAKE_SERVICE_ID: &str = "srv-hddsfake";
/// Service NAME of that id. `DiscoverInstances` is answered ONLY for this
/// value, exactly as AWS does: the service id is not a service name there
/// and never matches. That asymmetry is the reason the fake enforces it
/// instead of echoing whatever arrived.
pub const FAKE_SERVICE_NAME: &str = "hdds-service";
/// Namespace HTTP name the fake answers `DiscoverInstances` for.
pub const FAKE_NAMESPACE_NAME: &str = "hdds-namespace";

/// One instance as the fake stored it.
#[derive(Debug, Clone)]
pub struct FakeInstance {
    /// Instance id given to `RegisterInstance`.
    pub instance_id: String,
    /// Service id the instance was registered under.
    pub service_id: String,
    /// Attributes as received.
    pub attributes: HashMap<String, String>,
}

/// Everything the fake remembers.
#[derive(Debug, Default)]
struct FakeState {
    instances: Vec<FakeInstance>,
    registered_ids: Vec<String>,
    deregistered_ids: Vec<String>,
    targets: Vec<String>,
    signature_failures: Vec<String>,
}

/// A fake Cloud Map endpoint on `127.0.0.1:0`.
pub struct FakeCloudMap {
    server: FakeHttpServer,
    state: Arc<Mutex<FakeState>>,
    /// While set, `DiscoverInstances` answers with an empty instance list.
    discover_gate: Arc<AtomicBool>,
    /// Number of `DiscoverInstances` calls served.
    discover_calls: Arc<AtomicU32>,
    /// While set, every Cloud Map call answers `RequestLimitExceeded`.
    throttle: Arc<AtomicBool>,
}

impl FakeCloudMap {
    /// Start a fake endpoint.
    pub fn start() -> std::io::Result<Self> {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let discover_gate = Arc::new(AtomicBool::new(false));
        let discover_calls = Arc::new(AtomicU32::new(0));
        let throttle = Arc::new(AtomicBool::new(false));

        let handler_state = Arc::clone(&state);
        let handler_gate = Arc::clone(&discover_gate);
        let handler_calls = Arc::clone(&discover_calls);
        let handler_throttle = Arc::clone(&throttle);
        let server = FakeHttpServer::start(move |request| {
            handle(
                request,
                &handler_state,
                &handler_gate,
                &handler_calls,
                &handler_throttle,
            )
        })?;

        Ok(Self {
            server,
            state,
            discover_gate,
            discover_calls,
            throttle,
        })
    }

    /// `http://127.0.0.1:<port>`: pass this as `endpoint_override`.
    pub fn base_url(&self) -> String {
        self.server.base_url()
    }

    /// URL of the container-credentials document.
    pub fn credentials_url(&self) -> String {
        format!("{}/creds", self.server.base_url())
    }

    /// URL of the ECS task metadata endpoint (its `/task` child is served).
    pub fn ecs_metadata_url(&self) -> String {
        self.server.base_url()
    }

    /// Hold back every `DiscoverInstances` answer (an empty list) until
    /// released. Lets a test pin causality: nothing but Cloud Map could
    /// have taught a participant about its peer.
    pub fn gate_discovery(&self, gated: bool) {
        self.discover_gate.store(gated, Ordering::SeqCst);
    }

    /// Answer `RequestLimitExceeded` to every Cloud Map call.
    pub fn throttle(&self, throttled: bool) {
        self.throttle.store(throttled, Ordering::SeqCst);
    }

    /// Instances currently registered.
    pub fn instances(&self) -> Vec<FakeInstance> {
        lock(&self.state).instances.clone()
    }

    /// Instance ids that were registered, in order (duplicates included).
    pub fn registered_ids(&self) -> Vec<String> {
        lock(&self.state).registered_ids.clone()
    }

    /// Instance ids that were deregistered, in order.
    pub fn deregistered_ids(&self) -> Vec<String> {
        lock(&self.state).deregistered_ids.clone()
    }

    /// `X-Amz-Target` operation names served, in order.
    pub fn targets(&self) -> Vec<String> {
        lock(&self.state).targets.clone()
    }

    /// Requests whose signature did not verify (empty on a healthy run).
    pub fn signature_failures(&self) -> Vec<String> {
        lock(&self.state).signature_failures.clone()
    }

    /// How many `DiscoverInstances` calls were served.
    pub fn discover_call_count(&self) -> u32 {
        self.discover_calls.load(Ordering::SeqCst)
    }

    /// Every HTTP request the fake saw.
    pub fn requests(&self) -> Vec<FakeRequest> {
        self.server.requests()
    }

    /// Register an instance directly, as if a peer had done it.
    pub fn seed_instance(&self, instance: FakeInstance) {
        let mut state = lock(&self.state);
        state.instances.retain(|existing| {
            existing.instance_id != instance.instance_id
                || existing.service_id != instance.service_id
        });
        state.instances.push(instance);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn error_response(status: u16, error_type: &str, message: &str) -> FakeResponse {
    FakeResponse::json(
        status,
        &format!(
            r#"{{"__type":"com.amazonaws.servicediscovery#{}","message":"{}"}}"#,
            error_type, message
        ),
    )
}

fn handle(
    request: &FakeRequest,
    state: &Arc<Mutex<FakeState>>,
    discover_gate: &Arc<AtomicBool>,
    discover_calls: &Arc<AtomicU32>,
    throttle: &Arc<AtomicBool>,
) -> FakeResponse {
    match (request.method.as_str(), request.path()) {
        ("GET", "/creds") => FakeResponse::json(
            200,
            &format!(
                r#"{{"AccessKeyId":"{}","SecretAccessKey":"{}","Token":"{}",
                     "Expiration":"2099-01-01T00:00:00Z"}}"#,
                FAKE_ACCESS_KEY_ID, FAKE_SECRET_ACCESS_KEY, FAKE_SESSION_TOKEN
            ),
        ),
        ("GET", "/task") => {
            FakeResponse::json(200, r#"{"Networks":[{"IPv4Addresses":["127.0.0.1"]}]}"#)
        }
        ("POST", "/") => cloud_map(request, state, discover_gate, discover_calls, throttle),
        _ => FakeResponse::status(404),
    }
}

fn cloud_map(
    request: &FakeRequest,
    state: &Arc<Mutex<FakeState>>,
    discover_gate: &Arc<AtomicBool>,
    discover_calls: &Arc<AtomicU32>,
    throttle: &Arc<AtomicBool>,
) -> FakeResponse {
    let target = request.header("x-amz-target").unwrap_or("").to_string();
    let operation = target.rsplit('.').next().unwrap_or("").to_string();
    lock(state).targets.push(operation.clone());

    if let Err(reason) = verify_signature(request) {
        lock(state)
            .signature_failures
            .push(format!("{}: {}", operation, reason));
        return error_response(403, "InvalidSignatureException", &reason);
    }

    if throttle.load(Ordering::SeqCst) {
        return error_response(400, "RequestLimitExceeded", "fake is throttling");
    }

    let body: serde_json::Value = match serde_json::from_slice(&request.body) {
        Ok(body) => body,
        Err(e) => {
            return error_response(400, "SerializationException", &format!("bad body: {}", e))
        }
    };
    let field = |name: &str| -> String {
        body.get(name)
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string()
    };

    match operation.as_str() {
        "RegisterInstance" => {
            let instance_id = field("InstanceId");
            let service_id = field("ServiceId");
            if instance_id.is_empty() || service_id.is_empty() {
                return error_response(
                    400,
                    "InvalidInput",
                    "ServiceId and InstanceId are required",
                );
            }
            let attributes: HashMap<String, String> = body
                .get("Attributes")
                .and_then(|value| value.as_object())
                .map(|map| {
                    map.iter()
                        .map(|(key, value)| (key.clone(), value.as_str().unwrap_or("").to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let mut state = lock(state);
            state.registered_ids.push(instance_id.clone());
            state
                .instances
                .retain(|existing| existing.instance_id != instance_id);
            state.instances.push(FakeInstance {
                instance_id,
                service_id,
                attributes,
            });
            FakeResponse::json(200, r#"{"OperationId":"op-fake"}"#)
        }
        "DeregisterInstance" => {
            let instance_id = field("InstanceId");
            let mut state = lock(state);
            state.deregistered_ids.push(instance_id.clone());
            state
                .instances
                .retain(|existing| existing.instance_id != instance_id);
            FakeResponse::json(200, r#"{"OperationId":"op-fake"}"#)
        }
        "DiscoverInstances" => {
            discover_calls.fetch_add(1, Ordering::SeqCst);
            if discover_gate.load(Ordering::SeqCst) {
                return FakeResponse::json(200, r#"{"Instances":[]}"#);
            }
            let namespace = field("NamespaceName");
            let service = field("ServiceName");
            // AWS answers `ServiceNotFound` for a ServiceName that is not
            // a NAME of an existing service - a `srv-...` id included. The
            // fake enforces it so the id/name asymmetry cannot silently
            // come back: a client that sends the id fails here.
            if service != FAKE_SERVICE_NAME {
                return error_response(
                    400,
                    "ServiceNotFound",
                    &format!(
                        "DiscoverInstances takes the service NAME ({}), not {:?}",
                        FAKE_SERVICE_NAME, service
                    ),
                );
            }
            if namespace != FAKE_NAMESPACE_NAME {
                return error_response(
                    400,
                    "NamespaceNotFound",
                    &format!(
                        "no namespace named {:?} (this fake serves {})",
                        namespace, FAKE_NAMESPACE_NAME
                    ),
                );
            }
            let filters: HashMap<String, String> = body
                .get("QueryParameters")
                .and_then(|value| value.as_object())
                .map(|map| {
                    map.iter()
                        .map(|(key, value)| (key.clone(), value.as_str().unwrap_or("").to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let state = lock(state);
            let instances: Vec<String> = state
                .instances
                .iter()
                .filter(|instance| {
                    filters.iter().all(|(key, wanted)| {
                        instance.attributes.get(key).map(String::as_str) == Some(wanted.as_str())
                    })
                })
                .map(|instance| {
                    let attributes: Vec<String> = instance
                        .attributes
                        .iter()
                        .map(|(key, value)| {
                            format!("{}:{}", json_str(key), json_str(value))
                        })
                        .collect();
                    format!(
                        r#"{{"InstanceId":{},"NamespaceName":{},"ServiceName":{},"HealthStatus":"HEALTHY","Attributes":{{{}}}}}"#,
                        json_str(&instance.instance_id),
                        json_str(&namespace),
                        json_str(&service),
                        attributes.join(",")
                    )
                })
                .collect();
            FakeResponse::json(
                200,
                &format!(r#"{{"Instances":[{}]}}"#, instances.join(",")),
            )
        }
        "ListNamespaces" => FakeResponse::json(
            200,
            &format!(
                r#"{{"Namespaces":[{{"Id":"{}","Name":{}}}]}}"#,
                FAKE_NAMESPACE_ID,
                json_str(&first_filter_value(&body))
            ),
        ),
        "ListServices" => FakeResponse::json(
            200,
            &format!(
                r#"{{"Services":[{{"Id":"{}","Name":"{}"}}]}}"#,
                FAKE_SERVICE_ID, FAKE_SERVICE_NAME
            ),
        ),
        "GetService" => {
            let id = field("Id");
            if id == FAKE_SERVICE_ID {
                FakeResponse::json(
                    200,
                    &format!(
                        r#"{{"Service":{{"Id":"{}","Name":"{}"}}}}"#,
                        FAKE_SERVICE_ID, FAKE_SERVICE_NAME
                    ),
                )
            } else {
                error_response(
                    400,
                    "ServiceNotFound",
                    &format!("no service {:?} (this fake serves {})", id, FAKE_SERVICE_ID),
                )
            }
        }
        other => error_response(
            400,
            "UnknownOperationException",
            &format!("fake does not implement {}", other),
        ),
    }
}

fn first_filter_value(body: &serde_json::Value) -> String {
    body.get("Filters")
        .and_then(|value| value.as_array())
        .and_then(|filters| filters.first())
        .and_then(|filter| filter.get("Values"))
        .and_then(|values| values.as_array())
        .and_then(|values| values.first())
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string()
}

fn json_str(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

/// Recompute the SigV4 signature of a received request and compare it
/// with the `Authorization` header the client sent.
fn verify_signature(request: &FakeRequest) -> Result<(), String> {
    let authorization = request
        .header("authorization")
        .ok_or_else(|| "request carries no Authorization header".to_string())?;
    let rest = authorization
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .ok_or_else(|| format!("unexpected authorization scheme: {}", authorization))?;

    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for part in rest.split(',') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("Credential=") {
            credential = Some(value.to_string());
        } else if let Some(value) = part.strip_prefix("SignedHeaders=") {
            signed_headers = Some(value.to_string());
        } else if let Some(value) = part.strip_prefix("Signature=") {
            signature = Some(value.to_string());
        }
    }
    let credential = credential.ok_or_else(|| "authorization has no Credential".to_string())?;
    let signed_headers =
        signed_headers.ok_or_else(|| "authorization has no SignedHeaders".to_string())?;
    let signature = signature.ok_or_else(|| "authorization has no Signature".to_string())?;

    let scope: Vec<&str> = credential.split('/').collect();
    if scope.len() != 5 || scope[4] != "aws4_request" {
        return Err(format!("malformed credential scope: {}", credential));
    }
    let (access_key_id, date, region, service) = (scope[0], scope[1], scope[2], scope[3]);
    if access_key_id != FAKE_ACCESS_KEY_ID {
        return Err(format!("unknown access key id {}", access_key_id));
    }
    let datetime = request
        .header("x-amz-date")
        .ok_or_else(|| "request carries no x-amz-date".to_string())?;
    if !datetime.starts_with(date) {
        return Err(format!(
            "x-amz-date {} does not match the credential scope date {}",
            datetime, date
        ));
    }

    // Rebuild exactly the header set the client said it signed, in the
    // order the headers arrived (that is what the canonicalisation joins
    // repeats in).
    let wanted: Vec<&str> = signed_headers.split(';').collect();
    let mut headers = Vec::with_capacity(wanted.len());
    for (name, value) in &request.headers {
        if wanted.contains(&name.as_str()) {
            headers.push((name.clone(), value.clone()));
        }
    }
    let missing: Vec<&&str> = wanted
        .iter()
        .filter(|name| !headers.iter().any(|(present, _)| present == **name))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "signed headers absent from the request: {:?}",
            missing
        ));
    }

    let (path, query) = match request.target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (request.target.as_str(), ""),
    };
    let recomputed = aws_sigv4::sign(
        &AwsCredentials::new(FAKE_ACCESS_KEY_ID, FAKE_SECRET_ACCESS_KEY),
        &SigningRequest {
            method: &request.method,
            path,
            query,
            headers,
            body: &request.body,
            region,
            service,
            datetime,
            date,
        },
    );
    if recomputed.signature != signature {
        return Err(format!(
            "signature mismatch: client sent {}, endpoint computed {} over canonical request {:?}",
            signature, recomputed.signature, recomputed.canonical_request
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("test client")
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(future)
    }

    /// A correctly signed request is accepted and routed.
    #[test]
    fn a_correctly_signed_call_is_accepted() {
        let fake = FakeCloudMap::start().expect("fake");
        let body = br#"{"ServiceId":"srv-hddsfake","InstanceId":"hdds-1","Attributes":{}}"#;
        let status = block_on(post_signed(
            &fake,
            "RegisterInstance",
            body,
            FAKE_SECRET_ACCESS_KEY,
        ));
        assert_eq!(status, 200);
        assert_eq!(fake.registered_ids(), vec!["hdds-1".to_string()]);
        assert!(fake.signature_failures().is_empty());
    }

    /// A request signed with the wrong secret is rejected with the same
    /// error shape AWS uses. This is what makes the end-to-end proof
    /// meaningful: an unsigned or wrongly-signed client cannot pass.
    #[test]
    fn a_call_signed_with_the_wrong_secret_is_rejected_403() {
        let fake = FakeCloudMap::start().expect("fake");
        let status = block_on(post_signed(
            &fake,
            "RegisterInstance",
            br#"{"ServiceId":"srv-hddsfake","InstanceId":"hdds-1"}"#,
            "not-the-secret",
        ));
        assert_eq!(status, 403);
        assert!(fake.registered_ids().is_empty());
        assert_eq!(fake.signature_failures().len(), 1);
        assert!(fake.signature_failures()[0].contains("signature mismatch"));
    }

    /// A tampered body invalidates the signature even though every header
    /// is untouched: the payload hash is part of the canonical request.
    #[test]
    fn a_tampered_body_invalidates_the_signature() {
        let fake = FakeCloudMap::start().expect("fake");
        let signed = aws_sigv4::sign_json_post(
            &AwsCredentials::new(FAKE_ACCESS_KEY_ID, FAKE_SECRET_ACCESS_KEY),
            &aws_sigv4::JsonPost {
                host: &host_of(&fake),
                target: "Route53AutoNaming_v20170314.RegisterInstance",
                body: br#"{"ServiceId":"srv-hddsfake","InstanceId":"hdds-1"}"#,
                region: "eu-west-3",
                service: "servicediscovery",
                datetime: "20150830T123600Z",
                date: "20150830",
            },
        );
        let status = block_on(async {
            let mut request = client()
                .post(fake.base_url())
                .body(br#"{"ServiceId":"srv-hddsfake","InstanceId":"hdds-EVIL"}"#.to_vec());
            for (name, value) in &signed.headers {
                if name != "host" {
                    request = request.header(name.as_str(), value.as_str());
                }
            }
            request.send().await.expect("send").status().as_u16()
        });
        assert_eq!(status, 403);
        assert!(fake.registered_ids().is_empty());
    }

    /// An unsigned request never reaches the routing.
    #[test]
    fn an_unsigned_call_is_rejected() {
        let fake = FakeCloudMap::start().expect("fake");
        let status = block_on(async {
            client()
                .post(fake.base_url())
                .header(
                    "x-amz-target",
                    "Route53AutoNaming_v20170314.RegisterInstance",
                )
                .body(br#"{"ServiceId":"srv-hddsfake","InstanceId":"hdds-1"}"#.to_vec())
                .send()
                .await
                .expect("send")
                .status()
                .as_u16()
        });
        assert_eq!(status, 403);
        assert!(fake.registered_ids().is_empty());
    }

    /// The fake is proven to REFUSE the id where AWS wants the name
    /// before any test is allowed to trust it to accept.
    #[test]
    fn discover_instances_refuses_the_service_id_where_the_name_belongs() {
        let fake = FakeCloudMap::start().expect("fake");
        let with_service = |service: &str| {
            format!(
                r#"{{"NamespaceName":"{}","ServiceName":"{}","HealthStatus":"ALL","MaxResults":10}}"#,
                FAKE_NAMESPACE_NAME, service
            )
        };
        let refused = block_on(post_signed(
            &fake,
            "DiscoverInstances",
            with_service(FAKE_SERVICE_ID).as_bytes(),
            FAKE_SECRET_ACCESS_KEY,
        ));
        assert_eq!(refused, 400, "the service id must not pass as a name");
        let accepted = block_on(post_signed(
            &fake,
            "DiscoverInstances",
            with_service(FAKE_SERVICE_NAME).as_bytes(),
            FAKE_SECRET_ACCESS_KEY,
        ));
        assert_eq!(accepted, 200);
        assert!(fake.signature_failures().is_empty());
    }

    /// `GetService` is what turns the id into that name.
    #[test]
    fn get_service_answers_the_name_of_the_configured_id() {
        let fake = FakeCloudMap::start().expect("fake");
        let status = block_on(post_signed(
            &fake,
            "GetService",
            format!(r#"{{"Id":"{}"}}"#, FAKE_SERVICE_ID).as_bytes(),
            FAKE_SECRET_ACCESS_KEY,
        ));
        assert_eq!(status, 200);
        let unknown = block_on(post_signed(
            &fake,
            "GetService",
            br#"{"Id":"srv-nope"}"#,
            FAKE_SECRET_ACCESS_KEY,
        ));
        assert_eq!(unknown, 400);
    }

    /// The credential and ECS metadata routes answer without a signature.
    #[test]
    fn the_credential_and_ecs_routes_answer_unsigned() {
        let fake = FakeCloudMap::start().expect("fake");
        let (creds, task) = block_on(async {
            let creds = client()
                .get(fake.credentials_url())
                .send()
                .await
                .expect("creds")
                .text()
                .await
                .expect("creds body");
            let task = client()
                .get(format!("{}/task", fake.ecs_metadata_url()))
                .send()
                .await
                .expect("task")
                .text()
                .await
                .expect("task body");
            (creds, task)
        });
        assert!(creds.contains(FAKE_ACCESS_KEY_ID));
        assert!(creds.contains(FAKE_SESSION_TOKEN));
        assert!(task.contains("127.0.0.1"));
    }

    fn host_of(fake: &FakeCloudMap) -> String {
        fake.base_url()
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string()
    }

    async fn post_signed(fake: &FakeCloudMap, operation: &str, body: &[u8], secret: &str) -> u16 {
        let signed = aws_sigv4::sign_json_post(
            &AwsCredentials::new(FAKE_ACCESS_KEY_ID, secret),
            &aws_sigv4::JsonPost {
                host: &host_of(fake),
                target: &format!("Route53AutoNaming_v20170314.{}", operation),
                body,
                region: "eu-west-3",
                service: "servicediscovery",
                datetime: "20150830T123600Z",
                date: "20150830",
            },
        );
        let mut request = client().post(fake.base_url()).body(body.to_vec());
        for (name, value) in &signed.headers {
            if name != "host" {
                request = request.header(name.as_str(), value.as_str());
            }
        }
        request.send().await.expect("send").status().as_u16()
    }
}
