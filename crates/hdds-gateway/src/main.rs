// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS Gateway - REST API Gateway with Web UI
//!
//! Provides HTTP REST endpoints for HDDS administration and monitoring.
//! Connects to the Admin API (TCP binary protocol) and exposes JSON endpoints.
//!
//! # Usage
//!
//! ```bash
//! # Start gateway on default port 8080
//! hdds-gateway
//!
//! # Custom port and admin address
//! hdds-gateway --port 9000 --admin-addr 192.168.1.100:4243
//! ```
//!
//! # Endpoints
//!
//! - `GET /` - Web UI dashboard
//! - `GET /api/v1/health` - Health check
//! - `GET /api/v1/mesh` - Discovered participants
//! - `GET /api/v1/topics` - Active topics
//! - `GET /api/v1/metrics` - Runtime metrics
//! - `GET /api/v1/writers` - `DataWriters`
//! - `GET /api/v1/readers` - `DataReaders`

mod client;
mod handlers;
mod routes;

use axum::Router;
use clap::Parser;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

/// HDDS REST API Gateway
#[derive(Parser, Debug)]
#[command(name = "hdds-gateway")]
#[command(about = "HDDS REST API Gateway with Web UI")]
#[command(version)]
struct Args {
    /// HTTP server port
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// Bind address
    #[arg(short, long, default_value = "0.0.0.0")]
    bind: String,

    /// Admin API address (TCP binary protocol)
    #[arg(short, long, default_value = "127.0.0.1:4243")]
    admin_addr: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Disable Web UI (API only)
    #[arg(long)]
    api_only: bool,
}

/// Shared application state
pub struct AppState {
    client: RwLock<Option<client::AdminClient>>,
    admin_addr: String,
}

impl AppState {
    fn new(admin_addr: String) -> Self {
        Self {
            client: RwLock::new(None),
            admin_addr,
        }
    }

    /// Get or create admin client connection
    async fn get_client(&self) -> Result<client::AdminClient, std::io::Error> {
        // Try to reuse existing connection
        {
            let guard = self.client.read().await;
            if let Some(ref client) = *guard {
                if client.is_connected() {
                    return Ok(client.clone());
                }
            }
        }

        // Create new connection
        let new_client = client::AdminClient::connect(&self.admin_addr)?;

        // Store for reuse
        {
            let mut guard = self.client.write().await;
            *guard = Some(new_client.clone());
        }

        Ok(new_client)
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Setup logging
    let filter = args.log_level.parse().unwrap_or(tracing::Level::INFO);
    tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_target(false)
        .init();

    // Create shared state
    let state = Arc::new(AppState::new(args.admin_addr.clone()));

    // Build router
    let app = build_router(state, args.api_only);

    // Start server
    let addr = format!("{}:{}", args.bind, args.port);
    info!("HDDS Gateway v{}", env!("CARGO_PKG_VERSION"));
    info!("HTTP server: http://{}", addr);
    info!("Admin API: {}", args.admin_addr);

    if !args.api_only {
        info!("Web UI: http://{}/", addr);
    }

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind");

    axum::serve(listener, app).await.expect("Server error");
}

fn build_router(state: Arc<AppState>, api_only: bool) -> Router {
    let mut router = Router::new();

    // API routes (v1)
    router = router.merge(routes::api_routes());

    // Web UI routes (unless api_only)
    if !api_only {
        router = router.merge(routes::ui_routes());
    }

    router
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
