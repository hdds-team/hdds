// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HTTP request handlers for REST API.

use crate::AppState;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::sync::Arc;

/// API error response
#[derive(Serialize)]
pub struct ApiError {
    pub error: String,
    pub code: u16,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self)).into_response()
    }
}

impl From<std::io::Error> for ApiError {
    fn from(err: std::io::Error) -> Self {
        Self {
            error: err.to_string(),
            code: match err.kind() {
                std::io::ErrorKind::ConnectionRefused => 503,
                std::io::ErrorKind::TimedOut => 504,
                _ => 500,
            },
        }
    }
}

/// GET /api/v1/health
pub async fn health(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let client = state.get_client().await?;
    let json = client.get_health()?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
        .into_response())
}

/// GET /api/v1/mesh
pub async fn mesh(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let client = state.get_client().await?;
    let json = client.get_mesh()?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
        .into_response())
}

/// GET /api/v1/topics
pub async fn topics(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let client = state.get_client().await?;
    let json = client.get_topics()?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
        .into_response())
}

/// GET /api/v1/metrics
pub async fn metrics(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let client = state.get_client().await?;
    let json = client.get_metrics()?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
        .into_response())
}

/// GET /api/v1/writers - `DataWriters`
pub async fn writers(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let client = state.get_client().await?;
    let json = client.get_writers()?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
        .into_response())
}

/// GET /api/v1/readers - `DataReaders`
pub async fn readers(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let client = state.get_client().await?;
    let json = client.get_readers()?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
        .into_response())
}

/// GET /api/v1/info - Gateway info
pub async fn info() -> Response {
    let info = serde_json::json!({
        "name": "hdds-gateway",
        "version": env!("CARGO_PKG_VERSION"),
        "api_version": "v1",
        "endpoints": [
            "/api/v1/health",
            "/api/v1/mesh",
            "/api/v1/topics",
            "/api/v1/metrics",
            "/api/v1/writers",
            "/api/v1/readers",
            "/api/v1/info"
        ]
    });

    (StatusCode::OK, Json(info)).into_response()
}
