// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Route definitions for REST API and Web UI.

use crate::handlers;
use crate::AppState;
use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use rust_embed::RustEmbed;
use std::sync::Arc;

#[derive(RustEmbed)]
#[folder = "static/"]
struct Assets;

/// API v1 routes
pub fn api_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/health", get(handlers::health))
        .route("/api/v1/mesh", get(handlers::mesh))
        .route("/api/v1/topics", get(handlers::topics))
        .route("/api/v1/metrics", get(handlers::metrics))
        .route("/api/v1/writers", get(handlers::writers))
        .route("/api/v1/readers", get(handlers::readers))
        .route("/api/v1/info", get(handlers::info))
        // Legacy routes (compatibility with hdds-debugger)
        .route("/health", get(handlers::health))
        .route("/mesh", get(handlers::mesh))
        .route("/topics", get(handlers::topics))
        .route("/metrics", get(handlers::metrics))
}

/// Web UI routes
pub fn ui_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(serve_index))
        .route("/index.html", get(serve_index))
        .route("/style.css", get(serve_style))
        .route("/app.js", get(serve_app_js))
        .route("/favicon.ico", get(serve_favicon))
}

async fn serve_index() -> Response {
    serve_asset("index.html")
}

async fn serve_style() -> Response {
    serve_asset("style.css")
}

async fn serve_app_js() -> Response {
    serve_asset("app.js")
}

async fn serve_favicon() -> Response {
    // Return empty 204 if no favicon
    StatusCode::NO_CONTENT.into_response()
}

fn serve_asset(path: &str) -> Response {
    match Assets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, mime.as_ref())],
                content.data,
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "404 Not Found").into_response(),
    }
}
