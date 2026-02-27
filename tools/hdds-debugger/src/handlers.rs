// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use crate::client::AdminClient;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::{Arc, Mutex};

pub type SharedClient = Arc<Mutex<AdminClient>>;

/// GET /mesh
pub async fn handler_mesh(State(client): State<SharedClient>) -> Result<Response, AppError> {
    let json = {
        let mut client = client
            .lock()
            .map_err(|_| std::io::Error::other("Mutex lock poisoned"))?;
        client.get_mesh()?
    };
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
        .into_response())
}

/// GET /topics
pub async fn handler_topics(State(client): State<SharedClient>) -> Result<Response, AppError> {
    let json = {
        let mut client = client
            .lock()
            .map_err(|_| std::io::Error::other("Mutex lock poisoned"))?;
        client.get_topics()?
    };
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
        .into_response())
}

/// GET /metrics
pub async fn handler_metrics(State(client): State<SharedClient>) -> Result<Response, AppError> {
    let json = {
        let mut client = client
            .lock()
            .map_err(|_| std::io::Error::other("Mutex lock poisoned"))?;
        client.get_metrics()?
    };
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
        .into_response())
}

/// GET /health
pub async fn handler_health(State(client): State<SharedClient>) -> Result<Response, AppError> {
    let json = {
        let mut client = client
            .lock()
            .map_err(|_| std::io::Error::other("Mutex lock poisoned"))?;
        client.get_health()?
    };
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
        .into_response())
}

/// Error wrapper for handler errors
pub struct AppError(std::io::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Admin API error: {}", self.0),
        )
            .into_response()
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        Self(err)
    }
}
