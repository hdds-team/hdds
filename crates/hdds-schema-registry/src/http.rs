// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HTTP surface of the registry (feature `server`).
//!
//! The routes are exactly the mapping [`SchemaRegistryApi`] documents, with
//! one deliberate difference: the compatibility check takes the candidate
//! schema in a request BODY, so it is a POST, not a GET.
//!
//! | method | path                              | meaning                     |
//! |--------|-----------------------------------|-----------------------------|
//! | GET    | /schemas                          | list schema names           |
//! | POST   | /schemas                          | register a version          |
//! | GET    | /schemas/{name}                   | latest version              |
//! | GET    | /schemas/{name}/versions          | version numbers             |
//! | GET    | /schemas/{name}/versions/{n}      | one version                 |
//! | POST   | /schemas/{name}/compatibility     | check a candidate           |
//! | GET    | /health                           | liveness                    |
//!
//! Registration persists through [`FilePersistence`] when the server was
//! given a data directory, and a persistence failure is a 500 with the
//! version NOT reported as registered: a registry that cannot durably record
//! a schema must not claim it did.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::compatibility::Compatibility;
use crate::persistence::FilePersistence;
use crate::registry::{RegistryError, SchemaEntry, SchemaFormat};
use crate::server::SchemaRegistryApi;

/// Shared state behind the routes.
pub struct ServerState {
    pub api: SchemaRegistryApi,
    /// Where registrations are written. `None` = in-memory only.
    pub persistence: Option<FilePersistence>,
    /// Announce every registration on the DDS distribution topic.
    #[cfg(feature = "dds")]
    pub announcer: Option<std::sync::Mutex<crate::distribution::SchemaAnnouncer>>,
}

impl ServerState {
    /// In-memory state, nothing written to disk.
    pub fn in_memory(api: SchemaRegistryApi) -> Self {
        Self {
            api,
            persistence: None,
            #[cfg(feature = "dds")]
            announcer: None,
        }
    }

    /// State that persists every registration under `persistence`.
    pub fn with_persistence(api: SchemaRegistryApi, persistence: FilePersistence) -> Self {
        Self {
            api,
            persistence: Some(persistence),
            #[cfg(feature = "dds")]
            announcer: None,
        }
    }
}

/// Body of `POST /schemas`.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub name: String,
    pub content: String,
    #[serde(default = "default_format")]
    pub format: SchemaFormat,
}

fn default_format() -> SchemaFormat {
    SchemaFormat::Idl4
}

/// Body of `POST /schemas/{name}/compatibility`.
#[derive(Debug, Deserialize)]
pub struct CompatibilityRequest {
    pub content: String,
}

/// Answer of `POST /schemas`.
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub name: String,
    pub version: u32,
}

/// Answer of the compatibility check.
#[derive(Debug, Serialize)]
pub struct CompatibilityResponse {
    pub compatibility: String,
    pub compatible: bool,
    pub details: Vec<String>,
}

/// JSON error body.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// One schema version, JSON-shaped.
#[derive(Debug, Serialize)]
pub struct SchemaResponse {
    pub name: String,
    pub version: u32,
    pub format: SchemaFormat,
    pub content: String,
    pub hash: String,
}

impl From<SchemaEntry> for SchemaResponse {
    fn from(e: SchemaEntry) -> Self {
        Self {
            name: e.name,
            version: e.version,
            format: e.format,
            content: e.content,
            hash: format!("{:016x}", e.hash),
        }
    }
}

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: message.into(),
        }),
    )
        .into_response()
}

/// Build the router over shared state.
pub fn router(state: Arc<ServerState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/schemas", get(list_schemas).post(register_schema))
        .route("/schemas/:name", get(get_schema))
        .route("/schemas/:name/versions", get(list_versions))
        .route("/schemas/:name/versions/:version", get(get_version))
        .route("/schemas/:name/compatibility", post(check_compatibility))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

async fn list_schemas(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    Json(state.api.list_schemas())
}

async fn get_schema(State(state): State<Arc<ServerState>>, Path(name): Path<String>) -> Response {
    match state.api.get_schema(&name) {
        Some(entry) => Json(SchemaResponse::from(entry)).into_response(),
        None => error(StatusCode::NOT_FOUND, format!("schema not found: {}", name)),
    }
}

async fn list_versions(
    State(state): State<Arc<ServerState>>,
    Path(name): Path<String>,
) -> Response {
    let versions = state.api.list_versions(&name);
    if versions.is_empty() {
        return error(StatusCode::NOT_FOUND, format!("schema not found: {}", name));
    }
    Json(versions).into_response()
}

async fn get_version(
    State(state): State<Arc<ServerState>>,
    Path((name, version)): Path<(String, u32)>,
) -> Response {
    match state.api.get_version(&name, version) {
        Some(entry) => Json(SchemaResponse::from(entry)).into_response(),
        None => error(
            StatusCode::NOT_FOUND,
            format!("schema not found: {} v{}", name, version),
        ),
    }
}

async fn register_schema(
    State(state): State<Arc<ServerState>>,
    Json(body): Json<RegisterRequest>,
) -> Response {
    // Durability before acknowledgement, and it has to be ONE step: a
    // persistence failure must leave nothing behind for the read routes to
    // serve.
    let version = match state.api.register_schema_durable(
        &body.name,
        &body.content,
        body.format.clone(),
        state.persistence.as_ref(),
    ) {
        Ok(v) => v,
        Err(RegistryError::EmptyContent) => {
            return error(StatusCode::BAD_REQUEST, "schema content is empty")
        }
        Err(RegistryError::DuplicateContent) => {
            return error(
                StatusCode::CONFLICT,
                "identical schema content already registered",
            )
        }
        Err(e) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("schema not registered: {}", e),
            )
        }
    };

    #[cfg(feature = "dds")]
    if let Some(announcer) = &state.announcer {
        if let Some(entry) = state.api.get_version(&body.name, version) {
            // The announcement is best effort (below), so one failure inside
            // it must not poison the mutex and break every later POST.
            match announcer.lock() {
                Ok(mut announcer) => {
                    if let Err(e) = announcer.announce(&entry) {
                        log::warn!("schema {} v{} not announced: {}", body.name, version, e);
                    }
                }
                Err(poisoned) => {
                    log::warn!(
                        "the schema announcer panicked earlier; {} v{} is registered but not announced",
                        body.name,
                        version
                    );
                    // Take the guard anyway: the announcer's own state is a
                    // DDS writer that a panic in announce() does not corrupt.
                    let mut announcer = poisoned.into_inner();
                    if let Err(e) = announcer.announce(&entry) {
                        log::warn!("schema {} v{} not announced: {}", body.name, version, e);
                    }
                }
            }
        }
    }

    (
        StatusCode::CREATED,
        Json(RegisterResponse {
            name: body.name,
            version,
        }),
    )
        .into_response()
}

async fn check_compatibility(
    State(state): State<Arc<ServerState>>,
    Path(name): Path<String>,
    Json(body): Json<CompatibilityRequest>,
) -> Response {
    let result = state.api.check_compatibility(&name, &body.content);
    let compatible = !matches!(result.compatibility, Compatibility::Breaking);
    Json(CompatibilityResponse {
        compatibility: format!("{:?}", result.compatibility).to_uppercase(),
        compatible,
        details: result.details,
    })
    .into_response()
}
