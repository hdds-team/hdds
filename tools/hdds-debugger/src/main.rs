// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

mod client;
mod handlers;

use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use rust_embed::RustEmbed;
use std::sync::{Arc, Mutex};
use tower_http::cors::{Any, CorsLayer};

#[derive(RustEmbed)]
#[folder = "static/"]
struct Assets;

async fn handler_index() -> impl IntoResponse {
    serve_asset("index.html")
}

async fn handler_style() -> impl IntoResponse {
    serve_asset("style.css")
}

async fn handler_app_js() -> impl IntoResponse {
    serve_asset("app.js")
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

#[tokio::main]
async fn main() {
    if let Err(e) = try_main().await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn try_main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to Admin API
    let admin_addr =
        std::env::var("HDDS_ADMIN_ADDR").unwrap_or_else(|_| "127.0.0.1:4243".to_string());

    let client = client::AdminClient::connect(&admin_addr)?;

    let shared_client = Arc::new(Mutex::new(client));

    // Build Axum app
    let app = Router::new()
        // Frontend assets
        .route("/", get(handler_index))
        .route("/style.css", get(handler_style))
        .route("/app.js", get(handler_app_js))
        // API endpoints
        .route("/mesh", get(handlers::handler_mesh))
        .route("/topics", get(handlers::handler_topics))
        .route("/metrics", get(handlers::handler_metrics))
        .route("/health", get(handlers::handler_health))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(shared_client);

    // Run server
    let port = std::env::var("HDDS_DEBUGGER_PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{port}");

    println!("[START] HDDS Debugger running on http://{addr}");
    println!("[CONN] Connected to Admin API: {admin_addr}");

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    axum::serve(listener, app).await?;

    Ok(())
}
