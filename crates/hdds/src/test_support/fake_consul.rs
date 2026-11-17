// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! In-process Consul agent standing in for `hashicorp/consul` in tests.
//!
//! It models the seven endpoints [`crate::discovery::cloud::ConsulDiscovery`]
//! speaks, on top of the shared [`super::fake_http`] server (no second HTTP
//! implementation, no container, no credential):
//!
//! | route | modelled behaviour |
//! |---|---|
//! | `PUT /v1/agent/service/register` | stores the service BY ID (a second register with the same ID REPLACES the first, like the real agent), creates its TTL check, and answers `400 Invalid Service Meta` on a `Meta` map the real agent would refuse (key charset, 128-character keys, 512-character values, 64 pairs) |
//! | `PUT /v1/agent/service/deregister/<id>` | removes the service and its check |
//! | `PUT /v1/agent/check/pass/<check-id>` | marks the check passing and counts the refresh; `404` for an unknown check, exactly as the agent answers once it has forgotten a service |
//! | `GET /v1/health/service/<name>` | filters by `?tag=`, and with `?passing=true` hides services whose check is critical (a service with no check is passing); answers `X-Consul-Index` when [`FakeConsulAgent::set_health_index`] has set one |
//! | `PUT` / `DELETE /v1/kv/<key>` | key-value store, with the delete log a test can assert on |
//! | `GET /v1/agent/self` | agent liveness |
//!
//! On top of that it can be told to fail: [`FakeConsulAgent::require_token`]
//! answers `403` to any request without the right `X-Consul-Token`,
//! [`FakeConsulAgent::fail_all`] and [`FakeConsulAgent::fail_route`] inject a
//! status code, and [`FakeConsulAgent::expire_check`] simulates a TTL that
//! ran out without waiting for one.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use super::fake_http::{FakeHttpServer, FakeRequest, FakeResponse};

/// A service as the agent holds it.
#[derive(Debug, Clone, Default)]
pub struct FakeService {
    /// Service ID (the key: a register with an existing ID replaces it).
    pub id: String,
    /// Service name.
    pub name: String,
    /// Tags, e.g. `domain-39`.
    pub tags: Vec<String>,
    /// Advertised address.
    pub address: String,
    /// Advertised port.
    pub port: u16,
    /// `Meta` map.
    pub meta: HashMap<String, String>,
    /// `CheckID` of the TTL check registered with the service, if any.
    pub check_id: Option<String>,
    /// `TTL` string of that check, if any.
    pub check_ttl: Option<String>,
    /// `DeregisterCriticalServiceAfter` of that check, if any.
    pub check_deregister_after: Option<String>,
}

/// State of one TTL check.
#[derive(Debug, Clone)]
struct FakeCheck {
    status: String,
    passes: u32,
}

#[derive(Debug, Default)]
struct AgentState {
    services: HashMap<String, FakeService>,
    checks: HashMap<String, FakeCheck>,
    kv: HashMap<String, Vec<u8>>,
    kv_deletes: Vec<String>,
}

/// An in-process Consul agent on `127.0.0.1:0`.
pub struct FakeConsulAgent {
    server: FakeHttpServer,
    state: Arc<Mutex<AgentState>>,
    failures: Arc<Failures>,
    health_index: Arc<Mutex<Option<u64>>>,
}

/// Injected failures, shared with the request handler.
#[derive(Default)]
struct Failures {
    /// Status answered for every route (0 = healthy).
    all: AtomicU16,
    /// Status answered for requests whose path starts with the prefix.
    routes: Mutex<Vec<(String, u16)>>,
    /// Token every request must carry, if any.
    token: Mutex<Option<String>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl FakeConsulAgent {
    /// Start an agent on a loopback port.
    ///
    /// # Panics
    ///
    /// If the loopback listener cannot be bound.
    #[allow(clippy::expect_used)]
    pub fn start() -> Self {
        let state = Arc::new(Mutex::new(AgentState::default()));
        let failures = Arc::new(Failures::default());
        let health_index = Arc::new(Mutex::new(None));
        let handler_state = Arc::clone(&state);
        let handler_failures = Arc::clone(&failures);
        let handler_index = Arc::clone(&health_index);
        let server = FakeHttpServer::start(move |request: &FakeRequest| {
            handle(request, &handler_state, &handler_failures, &handler_index)
        })
        .expect("start fake consul agent");
        Self {
            server,
            state,
            failures,
            health_index,
        }
    }

    /// `http://127.0.0.1:<port>` -- pass this to `with_consul`.
    pub fn url(&self) -> String {
        self.server.base_url()
    }

    /// Every HTTP request the agent has served, in order.
    pub fn requests(&self) -> Vec<FakeRequest> {
        self.server.requests()
    }

    /// Forget the recorded requests (not the agent's state).
    pub fn clear_requests(&self) {
        self.server.clear_requests();
    }

    /// Requests matching a method and a path prefix.
    pub fn requests_to(&self, method: &str, path_prefix: &str) -> Vec<FakeRequest> {
        self.server
            .requests()
            .into_iter()
            .filter(|r| r.method == method && r.path().starts_with(path_prefix))
            .collect()
    }

    /// Every registered service, sorted by ID.
    pub fn services(&self) -> Vec<FakeService> {
        let state = lock(&self.state);
        let mut services: Vec<_> = state.services.values().cloned().collect();
        services.sort_by(|a, b| a.id.cmp(&b.id));
        services
    }

    /// One registered service.
    pub fn service(&self, id: &str) -> Option<FakeService> {
        lock(&self.state).services.get(id).cloned()
    }

    /// Register a service directly, as if another node had done it.
    pub fn inject_service(&self, service: FakeService) {
        let mut state = lock(&self.state);
        if let Some(check_id) = service.check_id.clone() {
            state.checks.insert(
                check_id,
                FakeCheck {
                    status: "passing".to_string(),
                    passes: 0,
                },
            );
        }
        state.services.insert(service.id.clone(), service);
    }

    /// How many `check/pass` refreshes this check has received.
    pub fn check_passes(&self, check_id: &str) -> u32 {
        lock(&self.state)
            .checks
            .get(check_id)
            .map(|c| c.passes)
            .unwrap_or(0)
    }

    /// Current status of a check (`passing`, `critical`), if it exists.
    pub fn check_status(&self, check_id: &str) -> Option<String> {
        lock(&self.state)
            .checks
            .get(check_id)
            .map(|c| c.status.clone())
    }

    /// Mark a check critical: the TTL ran out. A test does not have to
    /// wait for the real TTL to observe what the peers then see.
    pub fn expire_check(&self, check_id: &str) {
        if let Some(check) = lock(&self.state).checks.get_mut(check_id) {
            check.status = "critical".to_string();
        }
    }

    /// KV keys currently stored, sorted.
    pub fn kv_keys(&self) -> Vec<String> {
        let mut keys: Vec<_> = lock(&self.state).kv.keys().cloned().collect();
        keys.sort();
        keys
    }

    /// Value stored under a KV key.
    pub fn kv_value(&self, key: &str) -> Option<Vec<u8>> {
        lock(&self.state).kv.get(key).cloned()
    }

    /// Every KV key that was deleted, in order (duplicates included).
    pub fn kv_deletes(&self) -> Vec<String> {
        lock(&self.state).kv_deletes.clone()
    }

    /// Answer this value in the `X-Consul-Index` RESPONSE HEADER of the
    /// health query (`None`, the default, sends no header at all).
    ///
    /// Consul carries the index of a blocking query in the header and
    /// never in the body, so this is the only way a test can drive the
    /// client's index bookkeeping -- including the two guards, by
    /// handing back an index that went backwards or one below 1.
    pub fn set_health_index(&self, index: Option<u64>) {
        *lock(&self.health_index) = index;
    }

    /// Require this ACL token on every request; anything else gets 403.
    pub fn require_token(&self, token: &str) {
        *lock(&self.failures.token) = Some(token.to_string());
    }

    /// Answer this status on every route (`None` restores the agent).
    pub fn fail_all(&self, status: Option<u16>) {
        self.failures
            .all
            .store(status.unwrap_or(0), Ordering::SeqCst);
    }

    /// Answer this status for every request whose path starts with
    /// `path_prefix` (`None` clears the override).
    pub fn fail_route(&self, path_prefix: &str, status: Option<u16>) {
        let mut routes = lock(&self.failures.routes);
        routes.retain(|(prefix, _)| prefix != path_prefix);
        if let Some(status) = status {
            routes.push((path_prefix.to_string(), status));
        }
    }
}

fn handle(
    request: &FakeRequest,
    state: &Mutex<AgentState>,
    failures: &Failures,
    health_index: &Mutex<Option<u64>>,
) -> FakeResponse {
    if let Some(expected) = lock(&failures.token).as_deref() {
        if request.header("x-consul-token") != Some(expected) {
            return FakeResponse::text(403, "Permission denied: ACL token missing or wrong");
        }
    }
    let all = failures.all.load(Ordering::SeqCst);
    if all != 0 {
        return FakeResponse::text(all, "injected failure");
    }
    for (prefix, status) in lock(&failures.routes).iter() {
        if request.path().starts_with(prefix.as_str()) {
            return FakeResponse::text(*status, "injected route failure");
        }
    }

    match (request.method.as_str(), request.path()) {
        ("PUT", "/v1/agent/service/register") => register(request, state),
        ("PUT", path) if path.starts_with("/v1/agent/service/deregister/") => {
            let id = decode(&path["/v1/agent/service/deregister/".len()..]);
            let mut state = lock(state);
            if let Some(service) = state.services.remove(&id) {
                if let Some(check_id) = service.check_id {
                    state.checks.remove(&check_id);
                }
            }
            FakeResponse::status(200)
        }
        ("PUT", path) if path.starts_with("/v1/agent/check/pass/") => {
            let check_id = decode(&path["/v1/agent/check/pass/".len()..]);
            let mut state = lock(state);
            match state.checks.get_mut(&check_id) {
                Some(check) => {
                    check.status = "passing".to_string();
                    check.passes = check.passes.saturating_add(1);
                    FakeResponse::status(200)
                }
                None => FakeResponse::text(
                    404,
                    &format!("CheckID {:?} does not have associated TTL", check_id),
                ),
            }
        }
        ("GET", path) if path.starts_with("/v1/health/service/") => health_service(
            &decode(&path["/v1/health/service/".len()..]),
            request,
            state,
            *lock(health_index),
        ),
        ("PUT", path) if path.starts_with("/v1/kv/") => {
            lock(state)
                .kv
                .insert(path["/v1/kv/".len()..].to_string(), request.body.clone());
            FakeResponse::json(200, "true")
        }
        ("DELETE", path) if path.starts_with("/v1/kv/") => {
            let key = path["/v1/kv/".len()..].to_string();
            let mut state = lock(state);
            state.kv.remove(&key);
            state.kv_deletes.push(key);
            FakeResponse::json(200, "true")
        }
        ("GET", "/v1/agent/self") => {
            FakeResponse::json(200, r#"{"Config":{"Datacenter":"dc1","NodeName":"fake"}}"#)
        }
        _ => FakeResponse::text(404, "no route"),
    }
}

fn register(request: &FakeRequest, state: &Mutex<AgentState>) -> FakeResponse {
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&request.body) else {
        return FakeResponse::text(400, "register body is not JSON");
    };
    let string = |key: &str| -> String {
        body.get(key)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    };
    let id = string("ID");
    if id.is_empty() {
        return FakeResponse::text(400, "register body has no ID");
    }
    let tags = body
        .get("Tags")
        .and_then(|v| v.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let meta: HashMap<String, String> = body
        .get("Meta")
        .and_then(|v| v.as_object())
        .map(|map| {
            map.iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                .collect()
        })
        .unwrap_or_default();
    if let Err(message) = check_meta(&meta) {
        return FakeResponse::text(400, &message);
    }
    let check = body.get("Check");
    let check_id = check
        .and_then(|c| c.get("CheckID"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let service = FakeService {
        id: id.clone(),
        name: string("Name"),
        tags,
        address: string("Address"),
        // A port outside u16 is treated like a missing one (0), not wrapped.
        port: body
            .get("Port")
            .and_then(serde_json::Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(0),
        meta,
        check_id: check_id.clone(),
        check_ttl: check
            .and_then(|c| c.get("TTL"))
            .and_then(|v| v.as_str())
            .map(str::to_string),
        check_deregister_after: check
            .and_then(|c| c.get("DeregisterCriticalServiceAfter"))
            .and_then(|v| v.as_str())
            .map(str::to_string),
    };
    let mut state = lock(state);
    if let Some(check_id) = check_id {
        let status = check
            .and_then(|c| c.get("Status"))
            .and_then(|v| v.as_str())
            .unwrap_or("critical")
            .to_string();
        let passes = state.checks.get(&check_id).map(|c| c.passes).unwrap_or(0);
        state.checks.insert(check_id, FakeCheck { status, passes });
    }
    // A register with an existing ID REPLACES the previous definition;
    // that is what makes a colliding service ID silently lose a peer.
    state.services.insert(id, service);
    FakeResponse::status(200)
}

/// Consul's own `Meta` validation, modelled because breaking it does not
/// truncate anything: the agent refuses the WHOLE registration with
/// `HTTP 400 Invalid Service Meta`. Without this, a test could pass with
/// a body the real agent rejects. Limits MEASURED against
/// hashicorp/consul 1.20.2 (a 545-character value = 400, a key with a
/// `.` = 400).
fn check_meta(meta: &HashMap<String, String>) -> Result<(), String> {
    if meta.len() > 64 {
        return Err(format!(
            "Invalid Service Meta: {} pairs exceeds the 64 pair limit",
            meta.len()
        ));
    }
    for (key, value) in meta {
        let key_ok = !key.is_empty()
            && key.len() <= 128
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !key_ok {
            return Err(format!(
                "Invalid Service Meta: Couldn't load metadata pair ('{}', '{}'): \
                 Key contains invalid characters",
                key, value
            ));
        }
        if value.len() > 512 {
            return Err(format!(
                "Invalid Service Meta: Couldn't load metadata pair ('{}', '...'): \
                 Value exceeds the 512 character limit ({} characters)",
                key,
                value.len()
            ));
        }
    }
    Ok(())
}

fn health_service(
    name: &str,
    request: &FakeRequest,
    state: &Mutex<AgentState>,
    health_index: Option<u64>,
) -> FakeResponse {
    let mut wanted_tag = None;
    let mut passing_only = false;
    for pair in request.query().unwrap_or("").split('&') {
        match pair.split_once('=') {
            Some(("tag", value)) => wanted_tag = Some(decode(value)),
            Some(("passing", value)) => passing_only = decode(value) == "true",
            _ => {}
        }
    }

    let state = lock(state);
    let mut entries: Vec<String> = Vec::new();
    let mut services: Vec<_> = state.services.values().collect();
    services.sort_by(|a, b| a.id.cmp(&b.id));
    for service in services {
        if service.name != name {
            continue;
        }
        if let Some(tag) = wanted_tag.as_deref() {
            if !service.tags.iter().any(|t| t == tag) {
                continue;
            }
        }
        if passing_only {
            // No check at all = nothing is failing = passing, which is
            // what Consul itself answers.
            let critical = service
                .check_id
                .as_ref()
                .and_then(|id| state.checks.get(id))
                .map(|check| check.status != "passing")
                .unwrap_or(false);
            if critical {
                continue;
            }
        }
        let meta = serde_json::Value::Object(
            service
                .meta
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect(),
        );
        let entry = serde_json::json!({
            "Node": { "Node": "fake", "Address": service.address },
            "Service": {
                "ID": service.id,
                "Service": service.name,
                "Tags": service.tags,
                "Address": service.address,
                "Port": service.port,
                "Meta": meta,
            },
        });
        entries.push(entry.to_string());
    }
    let response = FakeResponse::json(200, &format!("[{}]", entries.join(",")));
    match health_index {
        Some(index) => response.with_header("X-Consul-Index", &index.to_string()),
        None => response,
    }
}

/// Decode the percent-escapes the client writes into path segments and
/// query values. Anything malformed is kept verbatim: this is a test
/// double, it must not hide a bad URL by "repairing" it.
fn decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(id: &str, tag: &str) -> FakeService {
        FakeService {
            id: id.to_string(),
            name: "hdds-participant".to_string(),
            tags: vec![tag.to_string()],
            address: "192.0.2.1".to_string(),
            port: 7410,
            meta: HashMap::from([("guid".to_string(), "ab".repeat(16))]),
            check_id: Some(format!("service:{}", id)),
            check_ttl: Some("10s".to_string()),
            check_deregister_after: Some("60s".to_string()),
        }
    }

    #[test]
    fn health_query_filters_by_tag_and_hides_a_critical_check() {
        let agent = FakeConsulAgent::start();
        agent.inject_service(service("a", "domain-39"));
        agent.inject_service(service("b", "domain-40"));

        let body = get(
            &agent,
            "/v1/health/service/hdds-participant?tag=domain-39&passing=true",
        );
        assert!(body.contains(r#""ID":"a""#), "{}", body);
        assert!(!body.contains(r#""ID":"b""#), "{}", body);

        agent.expire_check("service:a");
        let body = get(
            &agent,
            "/v1/health/service/hdds-participant?tag=domain-39&passing=true",
        );
        assert_eq!(body, "[]");
        // Without passing=true the critical instance is still listed:
        // that is exactly why the client asks for passing instances.
        let body = get(&agent, "/v1/health/service/hdds-participant?tag=domain-39");
        assert!(body.contains(r#""ID":"a""#), "{}", body);
    }

    #[test]
    fn unknown_check_refresh_is_404_and_a_known_one_is_counted() {
        let agent = FakeConsulAgent::start();
        agent.inject_service(service("a", "domain-39"));
        assert_eq!(put(&agent, "/v1/agent/check/pass/service%3Aa").0, 200);
        assert_eq!(agent.check_passes("service:a"), 1);
        assert_eq!(put(&agent, "/v1/agent/check/pass/service%3Aghost").0, 404);
    }

    #[test]
    fn token_and_failure_injection_apply_to_every_route() {
        let agent = FakeConsulAgent::start();
        agent.require_token("s3cr3t");
        assert_eq!(get_status(&agent, "/v1/agent/self", None), 403);
        assert_eq!(get_status(&agent, "/v1/agent/self", Some("wrong")), 403);
        assert_eq!(get_status(&agent, "/v1/agent/self", Some("s3cr3t")), 200);

        agent.fail_route("/v1/kv/", Some(500));
        assert_eq!(get_status(&agent, "/v1/agent/self", Some("s3cr3t")), 200);
        assert_eq!(get_status(&agent, "/v1/kv/x", Some("s3cr3t")), 500);
        agent.fail_route("/v1/kv/", None);
        assert_eq!(get_status(&agent, "/v1/kv/x", Some("s3cr3t")), 404);

        agent.fail_all(Some(503));
        assert_eq!(get_status(&agent, "/v1/agent/self", Some("s3cr3t")), 503);
        agent.fail_all(None);
        assert_eq!(get_status(&agent, "/v1/agent/self", Some("s3cr3t")), 200);
    }

    /// The fake must refuse what the real agent refuses, or a hermetic
    /// test could pass with a body hashicorp/consul answers 400 to.
    #[test]
    fn meta_validation_answers_400_like_the_real_agent() {
        let agent = FakeConsulAgent::start();
        let register = |meta: &str| -> (u16, String) {
            let body = format!(
                r#"{{"ID":"a","Name":"hdds-participant","Address":"127.0.0.1","Port":7410,"Meta":{}}}"#,
                meta
            );
            raw(
                &agent,
                &format!(
                    "PUT /v1/agent/service/register HTTP/1.1\r\nHost: fake\r\n\
                     Content-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                ),
            )
        };

        assert_eq!(register(r#"{"guid":"ab"}"#).0, 200);
        let (status, body) = register(&format!(r#"{{"locators":"{}"}}"#, "x".repeat(513)));
        assert_eq!(status, 400, "{}", body);
        assert!(body.contains("Invalid Service Meta"), "{}", body);
        let (status, body) = register(r#"{"user_my.key":"v"}"#);
        assert_eq!(status, 400, "{}", body);
        assert!(body.contains("Key contains invalid characters"), "{}", body);
        // The 512-character value itself is accepted: the limit is a
        // ceiling, not an off-by-one.
        assert_eq!(
            register(&format!(r#"{{"k":"{}"}}"#, "x".repeat(512))).0,
            200
        );
    }

    // ------------------------------------------------------------------
    // Raw HTTP/1.1 helpers (no HTTP client crate in the always-on tests)
    // ------------------------------------------------------------------

    fn raw(agent: &FakeConsulAgent, request: &str) -> (u16, String) {
        use std::io::{Read, Write};
        let addr = agent.server.addr();
        let mut stream = std::net::TcpStream::connect(addr).expect("connect");
        stream.write_all(request.as_bytes()).expect("write");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read");
        let (head, body) = response.split_once("\r\n\r\n").expect("response head");
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .expect("status code");
        (status, body.to_string())
    }

    fn get(agent: &FakeConsulAgent, target: &str) -> String {
        raw(
            agent,
            &format!("GET {} HTTP/1.1\r\nHost: fake\r\n\r\n", target),
        )
        .1
    }

    fn get_status(agent: &FakeConsulAgent, target: &str, token: Option<&str>) -> u16 {
        let header = token
            .map(|t| format!("X-Consul-Token: {}\r\n", t))
            .unwrap_or_default();
        raw(
            agent,
            &format!("GET {} HTTP/1.1\r\nHost: fake\r\n{}\r\n", target, header),
        )
        .0
    }

    fn put(agent: &FakeConsulAgent, target: &str) -> (u16, String) {
        raw(
            agent,
            &format!(
                "PUT {} HTTP/1.1\r\nHost: fake\r\nContent-Length: 0\r\n\r\n",
                target
            ),
        )
    }
}
