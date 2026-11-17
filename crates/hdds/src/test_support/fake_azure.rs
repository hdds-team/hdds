// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! In-process stand-in for the two Azure endpoints the discovery backend
//! talks to: the token issuers (IMDS Managed Identity, and the AKS
//! Workload Identity federated flow against the AAD authority) and the
//! Table Storage data-plane REST API.
//!
//! Everything runs on ONE [`FakeHttpServer`] bound to `127.0.0.1:0`, so a
//! test injects the same base URL as `endpoint`, `imds_endpoint` and
//! `authority_endpoint`; the routes are disjoint. No network, no
//! container, no Azure credential, no DNS.
//!
//! The fake ENFORCES authentication: every Table route answers `401`
//! unless the request carries `Authorization: Bearer <token this fake
//! issued>` or the SAS signature it was configured with, and it counts
//! the unauthenticated attempts. A regression that drops the credential
//! turns the proof red instead of passing quietly.
//!
//! Entities are stored as the raw JSON body the client sent, keyed by
//! `(PartitionKey, RowKey)`, and echoed back inside `{"value":[...]}`;
//! the fake never needs a JSON parser, which keeps it usable in builds
//! without the `cloud-discovery` feature.

use super::fake_http::{FakeHttpServer, FakeRequest, FakeResponse};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};

/// Resource the Managed Identity / Workload Identity tokens are minted for.
pub const STORAGE_RESOURCE: &str = "https://storage.azure.com/";

/// How the fake answers the next token request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenScript {
    /// Mint a fresh token valid for `expires_in` seconds.
    Ok { expires_in: u64 },
    /// Answer with this HTTP status and no token (IMDS returns 500 when
    /// no identity is assigned to the instance).
    Status(u16),
}

impl Default for TokenScript {
    fn default() -> Self {
        TokenScript::Ok { expires_in: 3600 }
    }
}

#[derive(Debug)]
struct State {
    tables: BTreeSet<String>,
    entities: BTreeMap<(String, String), String>,
    issued_tokens: BTreeSet<String>,
    token_serial: u64,
    token_script: TokenScript,
    token_requests: u64,
    table_status: u16,
    table_create_status: u16,
    page_size: usize,
    duplicate_rows: bool,
    unauthenticated_attempts: u64,
    sas_signature: Option<String>,
    federated_assertion: Option<String>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            tables: BTreeSet::new(),
            entities: BTreeMap::new(),
            issued_tokens: BTreeSet::new(),
            token_serial: 0,
            token_script: TokenScript::default(),
            token_requests: 0,
            table_status: 200,
            table_create_status: 201,
            page_size: 0,
            duplicate_rows: false,
            unauthenticated_attempts: 0,
            sas_signature: None,
            federated_assertion: None,
        }
    }
}

/// An Azure token issuer plus a Table Storage account, on loopback.
pub struct FakeAzure {
    server: FakeHttpServer,
    state: Arc<Mutex<State>>,
}

impl FakeAzure {
    /// Bind a loopback port and start serving.
    pub fn start() -> io::Result<Self> {
        let state = Arc::new(Mutex::new(State::default()));
        let handler_state = Arc::clone(&state);
        let server = FakeHttpServer::start(move |request: &FakeRequest| {
            let mut state = lock(&handler_state);
            route(&mut state, request)
        })?;
        Ok(Self { server, state })
    }

    /// Base URL: valid as `endpoint`, `imds_endpoint` and
    /// `authority_endpoint` at once.
    pub fn url(&self) -> String {
        self.server.base_url()
    }

    /// The underlying HTTP server (recorded requests, handler swap).
    pub fn server(&self) -> &FakeHttpServer {
        &self.server
    }

    /// How the next token request is answered.
    pub fn set_token_script(&self, script: TokenScript) {
        lock(&self.state).token_script = script;
    }

    /// Status returned by every Table route (200 = serve normally).
    pub fn set_table_status(&self, status: u16) {
        lock(&self.state).table_status = status;
    }

    /// Status returned by `POST /Tables` (201 = create normally).
    ///
    /// A credential scoped to one table cannot create tables: the real
    /// service answers `403` there while the entity routes keep working.
    pub fn set_table_create_status(&self, status: u16) {
        lock(&self.state).table_create_status = status;
    }

    /// Entities per query page (0 = one page, no continuation).
    pub fn set_page_size(&self, page_size: usize) {
        lock(&self.state).page_size = page_size;
    }

    /// List every matching entity TWICE in each query page, as a service
    /// replaying a continuation page would.
    pub fn set_duplicate_rows(&self, duplicate: bool) {
        lock(&self.state).duplicate_rows = duplicate;
    }

    /// Delete a table behind the client's back (an operator, a lifecycle
    /// policy, a rebuilt account).
    pub fn drop_table(&self, name: &str) {
        let mut state = lock(&self.state);
        state.tables.remove(name);
        state.entities.clear();
    }

    /// Accept this decoded `sig=` query VALUE as a SAS credential
    /// (`"ABC/def"` matches a request carrying `sig=ABC%2Fdef`).
    pub fn set_sas_signature(&self, signature: &str) {
        lock(&self.state).sas_signature = Some(signature.to_string());
    }

    /// Accept this exact `client_assertion` on the Workload Identity flow.
    pub fn set_federated_assertion(&self, assertion: &str) {
        lock(&self.state).federated_assertion = Some(assertion.to_string());
    }

    /// Pre-create a table, as `POST /Tables` would have.
    pub fn create_table(&self, name: &str) {
        lock(&self.state).tables.insert(name.to_string());
    }

    /// Pre-seed one entity, as the client would have written it.
    pub fn put_entity(&self, partition_key: &str, row_key: &str, json_body: &str) {
        lock(&self.state).entities.insert(
            (partition_key.to_string(), row_key.to_string()),
            json_body.to_string(),
        );
    }

    /// Remove one entity behind the client's back.
    pub fn remove_entity(&self, partition_key: &str, row_key: &str) {
        lock(&self.state)
            .entities
            .remove(&(partition_key.to_string(), row_key.to_string()));
    }

    /// Every stored entity as `(PartitionKey, RowKey, raw JSON body)`.
    pub fn entities(&self) -> Vec<(String, String, String)> {
        lock(&self.state)
            .entities
            .iter()
            .map(|((pk, rk), body)| (pk.clone(), rk.clone(), body.clone()))
            .collect()
    }

    /// Table requests that carried no credential the fake accepted.
    pub fn unauthenticated_attempts(&self) -> u64 {
        lock(&self.state).unauthenticated_attempts
    }

    /// Token requests served (any outcome).
    pub fn token_requests(&self) -> u64 {
        lock(&self.state).token_requests
    }

    /// Tables created through `POST /Tables`.
    pub fn tables(&self) -> Vec<String> {
        lock(&self.state).tables.iter().cloned().collect()
    }

    /// Requests whose method and path prefix match.
    pub fn requests_matching(&self, method: &str, path_prefix: &str) -> Vec<FakeRequest> {
        self.server
            .requests()
            .into_iter()
            .filter(|request| request.method == method && request.path().starts_with(path_prefix))
            .collect()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn route(state: &mut State, request: &FakeRequest) -> FakeResponse {
    let path = request.path().to_string();
    if path.starts_with("/metadata/identity/oauth2/token") {
        return imds_token(state, request);
    }
    if path.ends_with("/oauth2/v2.0/token") {
        return federated_token(state, request);
    }
    table_route(state, request, &path)
}

// ---------------------------------------------------------------------------
// Token issuers
// ---------------------------------------------------------------------------

fn imds_token(state: &mut State, request: &FakeRequest) -> FakeResponse {
    state.token_requests = state.token_requests.saturating_add(1);
    // IMDS refuses any request without the anti-SSRF header.
    if request.header("metadata") != Some("true") {
        return FakeResponse::json(
            400,
            r#"{"error":"invalid_request","error_description":"Metadata header required"}"#,
        );
    }
    let query = request.query().unwrap_or_default();
    if !query.contains("api-version=") {
        return FakeResponse::json(
            400,
            r#"{"error":"invalid_request","error_description":"api-version required"}"#,
        );
    }
    match state.token_script {
        TokenScript::Status(status) => FakeResponse::json(
            status,
            r#"{"error":"no_identity","error_description":"no managed identity on this instance"}"#,
        ),
        TokenScript::Ok { expires_in } => {
            let token = mint(state);
            FakeResponse::json(
                200,
                &format!(
                    r#"{{"access_token":"{}","expires_in":"{}","token_type":"Bearer","resource":"{}"}}"#,
                    token, expires_in, STORAGE_RESOURCE
                ),
            )
        }
    }
}

fn federated_token(state: &mut State, request: &FakeRequest) -> FakeResponse {
    state.token_requests = state.token_requests.saturating_add(1);
    if request.method != "POST" {
        return FakeResponse::json(405, r#"{"error":"invalid_request"}"#);
    }
    let body = request.body_text();
    let form: BTreeMap<String, String> = body
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (percent_decode(key), percent_decode(value)))
        .collect();
    let expected_assertion = state.federated_assertion.clone();
    if let Some(expected) = expected_assertion {
        if form.get("client_assertion").map(String::as_str) != Some(expected.as_str()) {
            return FakeResponse::json(
                401,
                r#"{"error":"invalid_client","error_description":"federated assertion mismatch"}"#,
            );
        }
    }
    if form.get("grant_type").map(String::as_str) != Some("client_credentials") {
        return FakeResponse::json(400, r#"{"error":"unsupported_grant_type"}"#);
    }
    if !form.contains_key("client_id") {
        return FakeResponse::json(400, r#"{"error":"invalid_request"}"#);
    }
    match state.token_script {
        TokenScript::Status(status) => FakeResponse::json(status, r#"{"error":"invalid_client"}"#),
        TokenScript::Ok { expires_in } => {
            let token = mint(state);
            FakeResponse::json(
                200,
                &format!(
                    r#"{{"token_type":"Bearer","expires_in":{},"access_token":"{}"}}"#,
                    expires_in, token
                ),
            )
        }
    }
}

fn mint(state: &mut State) -> String {
    state.token_serial = state.token_serial.saturating_add(1);
    let token = format!("fake-azure-token-{}", state.token_serial);
    state.issued_tokens.insert(token.clone());
    token
}

// ---------------------------------------------------------------------------
// Table Storage data plane
// ---------------------------------------------------------------------------

fn table_route(state: &mut State, request: &FakeRequest, path: &str) -> FakeResponse {
    if !authorized(state, request) {
        state.unauthenticated_attempts = state.unauthenticated_attempts.saturating_add(1);
        return FakeResponse::json(
            401,
            r#"{"odata.error":{"code":"AuthenticationFailed","message":{"value":"no accepted credential"}}}"#,
        );
    }
    if state.table_status != 200 {
        return FakeResponse::json(
            state.table_status,
            r#"{"odata.error":{"code":"ServerBusy","message":{"value":"scripted failure"}}}"#,
        );
    }

    if request.method == "POST" && path == "/Tables" {
        if state.table_create_status != 201 {
            return FakeResponse::json(
                state.table_create_status,
                r#"{"odata.error":{"code":"AuthorizationPermissionMismatch","message":{"value":"this credential may not create tables"}}}"#,
            );
        }
        let name = extract_json_string(&request.body_text(), "TableName").unwrap_or_default();
        if name.is_empty() {
            return FakeResponse::json(400, r#"{"odata.error":{"code":"InvalidInput"}}"#);
        }
        if !state.tables.insert(name.clone()) {
            return FakeResponse::json(
                409,
                r#"{"odata.error":{"code":"TableAlreadyExists","message":{"value":"exists"}}}"#,
            );
        }
        return FakeResponse::json(201, &format!(r#"{{"TableName":"{}"}}"#, name));
    }

    // /{table}(PartitionKey='..',RowKey='..')  or  /{table}()
    let Some((table, keys)) = split_entity_path(path) else {
        return FakeResponse::status(404);
    };
    if !state.tables.contains(&table) {
        return FakeResponse::json(
            404,
            r#"{"odata.error":{"code":"TableNotFound","message":{"value":"table not found"}}}"#,
        );
    }

    match (request.method.as_str(), keys) {
        ("PUT" | "MERGE", Some((pk, rk))) => {
            state.entities.insert((pk, rk), request.body_text());
            FakeResponse::status(204)
        }
        ("DELETE", Some((pk, rk))) => {
            if state.entities.remove(&(pk, rk)).is_some() {
                FakeResponse::status(204)
            } else {
                FakeResponse::json(
                    404,
                    r#"{"odata.error":{"code":"ResourceNotFound","message":{"value":"gone"}}}"#,
                )
            }
        }
        ("GET", None) => query_entities(state, request),
        _ => FakeResponse::status(404),
    }
}

fn authorized(state: &State, request: &FakeRequest) -> bool {
    if let Some(header) = request.header("authorization") {
        return header
            .strip_prefix("Bearer ")
            .is_some_and(|token| state.issued_tokens.contains(token));
    }
    let Some(expected) = state.sas_signature.as_deref() else {
        return false;
    };
    request
        .query()
        .unwrap_or_default()
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .any(|(key, value)| key == "sig" && percent_decode(value) == expected)
}

fn query_entities(state: &State, request: &FakeRequest) -> FakeResponse {
    let query: Vec<(String, String)> = request
        .query()
        .unwrap_or_default()
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (percent_decode(key), percent_decode(value)))
        .collect();
    let get = |name: &str| -> Option<String> {
        query
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };

    // Only the one filter shape the backend sends is understood.
    let partition = get("$filter").and_then(|filter| {
        filter
            .strip_prefix("PartitionKey eq '")
            .and_then(|rest| rest.strip_suffix('\''))
            .map(str::to_string)
    });

    let start = get("NextPartitionKey").map(|pk| (pk, get("NextRowKey").unwrap_or_default()));

    let mut matching: Vec<(&(String, String), &String)> = state
        .entities
        .iter()
        .filter(|((pk, _), _)| partition.as_ref().is_none_or(|wanted| pk == wanted))
        .filter(|((pk, rk), _)| match &start {
            Some((spk, srk)) => (pk.as_str(), rk.as_str()) >= (spk.as_str(), srk.as_str()),
            None => true,
        })
        .collect();
    matching.sort_by(|a, b| a.0.cmp(b.0));

    let page_size = if state.page_size == 0 {
        matching.len()
    } else {
        state.page_size
    };
    let mut page: Vec<&String> = matching
        .iter()
        .take(page_size)
        .map(|(_, body)| *body)
        .collect();
    if state.duplicate_rows {
        page = page.iter().flat_map(|body| [*body, *body]).collect();
    }
    let next = matching
        .get(page_size)
        .map(|(keys, _)| (keys.0.clone(), keys.1.clone()));

    let body = format!(
        r#"{{"value":[{}]}}"#,
        page.iter()
            .map(|entity| entity.as_str())
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut response = FakeResponse::json(200, &body);
    if let Some((pk, rk)) = next {
        response = response
            .with_header("x-ms-continuation-NextPartitionKey", &pk)
            .with_header("x-ms-continuation-NextRowKey", &rk);
    }
    response
}

/// `/mytable(PartitionKey='a',RowKey='b')` -> `("mytable", Some(("a","b")))`,
/// `/mytable()` -> `("mytable", None)`.
fn split_entity_path(path: &str) -> Option<(String, Option<(String, String)>)> {
    let path = path.strip_prefix('/')?;
    let (table, rest) = path.split_once('(')?;
    let keys = rest.strip_suffix(')')?;
    if table.is_empty() {
        return None;
    }
    if keys.is_empty() {
        return Some((table.to_string(), None));
    }
    let mut partition_key = None;
    let mut row_key = None;
    for part in keys.split(',') {
        let (name, value) = part.split_once('=')?;
        let value = percent_decode(value.trim());
        let value = value.strip_prefix('\'')?.strip_suffix('\'')?.to_string();
        match name.trim() {
            "PartitionKey" => partition_key = Some(value),
            "RowKey" => row_key = Some(value),
            _ => return None,
        }
    }
    Some((table.to_string(), Some((partition_key?, row_key?))))
}

fn extract_json_string(body: &str, field: &str) -> Option<String> {
    let needle = format!("\"{}\"", field);
    let start = body.find(&needle)? + needle.len();
    let rest = body.get(start..)?.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    fn raw(server: &FakeHttpServer, request: &str) -> (u16, String, String) {
        let mut stream = TcpStream::connect(server.addr()).expect("connect");
        stream.write_all(request.as_bytes()).expect("write");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read");
        let text = String::from_utf8_lossy(&response).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
        let status: u16 = head
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .expect("status code");
        (status, head.to_string(), body.to_string())
    }

    #[test]
    fn fake_issues_a_token_only_with_the_metadata_header() {
        let azure = FakeAzure::start().expect("start fake azure");
        let (status, _, _) = raw(
            azure.server(),
            "GET /metadata/identity/oauth2/token?api-version=2018-02-01 HTTP/1.1\r\nHost: x\r\n\r\n",
        );
        assert_eq!(
            status, 400,
            "IMDS must refuse a request without Metadata:true"
        );

        let (status, _, body) = raw(
            azure.server(),
            "GET /metadata/identity/oauth2/token?api-version=2018-02-01 HTTP/1.1\r\nHost: x\r\nMetadata: true\r\n\r\n",
        );
        assert_eq!(status, 200);
        assert!(body.contains("fake-azure-token-1"), "body: {}", body);
        assert_eq!(azure.token_requests(), 2);
    }

    #[test]
    fn fake_refuses_every_table_request_without_an_accepted_credential() {
        let azure = FakeAzure::start().expect("start fake azure");
        let (status, _, _) = raw(
            azure.server(),
            "POST /Tables HTTP/1.1\r\nHost: x\r\nContent-Length: 26\r\n\r\n{\"TableName\":\"hddspeers\"}\r\n",
        );
        assert_eq!(status, 401);
        assert_eq!(azure.unauthenticated_attempts(), 1);

        let (status, _, _) = raw(
            azure.server(),
            "POST /Tables HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer forged\r\nContent-Length: 24\r\n\r\n{\"TableName\":\"hddspeers\"}",
        );
        assert_eq!(
            status, 401,
            "a token this fake never issued is not a credential"
        );
        assert_eq!(azure.unauthenticated_attempts(), 2);
        assert!(azure.tables().is_empty());
    }

    #[test]
    fn fake_pages_a_query_with_a_continuation_header() {
        let azure = FakeAzure::start().expect("start fake azure");
        azure.set_sas_signature("SIGNATURE");
        let (status, _, _) = raw(
            azure.server(),
            "POST /Tables?sv=2024&sig=SIGNATURE HTTP/1.1\r\nHost: x\r\nContent-Length: 24\r\n\r\n{\"TableName\":\"hddspeers\"}",
        );
        assert_eq!(status, 201);
        for row in ["a", "b", "c"] {
            azure.put_entity("domain-39", row, &format!(r#"{{"RowKey":"{}"}}"#, row));
        }
        azure.set_page_size(2);

        let (status, head, body) = raw(
            azure.server(),
            "GET /hddspeers()?%24filter=PartitionKey%20eq%20%27domain-39%27&sv=2024&sig=SIGNATURE HTTP/1.1\r\nHost: x\r\n\r\n",
        );
        assert_eq!(status, 200);
        assert!(
            body.contains(r#""RowKey":"a""#) && body.contains(r#""RowKey":"b""#),
            "{}",
            body
        );
        assert!(
            !body.contains(r#""RowKey":"c""#),
            "page must stop at 2: {}",
            body
        );
        assert!(
            head.contains("x-ms-continuation-NextRowKey: c"),
            "head: {}",
            head
        );

        let (status, head, body) = raw(
            azure.server(),
            "GET /hddspeers()?%24filter=PartitionKey%20eq%20%27domain-39%27&NextPartitionKey=domain-39&NextRowKey=c&sv=2024&sig=SIGNATURE HTTP/1.1\r\nHost: x\r\n\r\n",
        );
        assert_eq!(status, 200);
        assert!(body.contains(r#""RowKey":"c""#), "{}", body);
        assert!(
            !head.contains("x-ms-continuation"),
            "last page carries no continuation: {}",
            head
        );
    }
}
