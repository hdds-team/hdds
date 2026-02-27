// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS WebSocket Bridge - Connect browsers to DDS topics in real-time.
//!
//! This server exposes a WebSocket endpoint that allows web clients to:
//! - Subscribe to DDS topics and receive live data
//! - Publish messages to DDS topics
//! - Monitor topic activity
//!
//! # Usage
//!
//! ```bash
//! # Start WebSocket bridge on default port 9090
//! hdds-ws
//!
//! # Custom port and domain
//! hdds-ws --port 8080 --domain 42
//! ```
//!
//! # Protocol
//!
//! Messages are JSON-encoded:
//!
//! ```json
//! // Subscribe to a topic
//! {"type": "subscribe", "topic": "temperature"}
//!
//! // Publish to a topic
//! {"type": "publish", "topic": "commands", "data": {"action": "start"}}
//!
//! // Receive data
//! {"type": "data", "topic": "temperature", "sample": {...}, "seq": 42}
//! ```

mod bridge;
mod protocol;
mod session;

use axum::{
    extract::{ws::WebSocket, State, WebSocketUpgrade},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use clap::Parser;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

use bridge::DdsBridge;
use session::ClientSession;

/// HDDS WebSocket Bridge
#[derive(Parser, Debug, Clone)]
#[command(name = "hdds-ws")]
#[command(about = "HDDS WebSocket Bridge - Connect browsers to DDS")]
#[command(version)]
struct Args {
    /// WebSocket server port
    #[arg(short, long, default_value = "9090")]
    port: u16,

    /// Bind address
    #[arg(short, long, default_value = "0.0.0.0")]
    bind: String,

    /// DDS Domain ID
    #[arg(short, long, default_value = "0")]
    domain: u32,

    /// Participant name
    #[arg(long, default_value = "hdds-ws-bridge")]
    name: String,

    /// Transport mode: udp (multicast) or intra (in-process)
    #[arg(short, long, default_value = "udp")]
    transport: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Maximum concurrent WebSocket connections
    #[arg(long, default_value = "100")]
    max_clients: usize,
}

/// Shared application state
pub struct AppState {
    bridge: Arc<DdsBridge>,
    config: Args,
    client_count: RwLock<usize>,
}

impl AppState {
    async fn new(config: Args) -> Result<Self, Box<dyn std::error::Error>> {
        let bridge = DdsBridge::new(config.domain, &config.name, &config.transport).await?;

        Ok(Self {
            bridge: Arc::new(bridge),
            config,
            client_count: RwLock::new(0),
        })
    }

    async fn can_accept_client(&self) -> bool {
        let count = *self.client_count.read().await;
        count < self.config.max_clients
    }

    async fn add_client(&self) {
        let mut count = self.client_count.write().await;
        *count += 1;
        info!("Client connected. Total: {}", *count);
    }

    async fn remove_client(&self) {
        let mut count = self.client_count.write().await;
        *count = count.saturating_sub(1);
        info!("Client disconnected. Total: {}", *count);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Setup logging
    let filter = args.log_level.parse().unwrap_or(tracing::Level::INFO);
    tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_target(false)
        .init();

    info!("HDDS WebSocket Bridge v{}", env!("CARGO_PKG_VERSION"));
    info!("Domain ID: {}", args.domain);

    let addr = format!("{}:{}", args.bind, args.port);

    // Create DDS bridge
    let state = Arc::new(AppState::new(args).await?);

    // Build router
    let app = Router::new()
        .route("/", get(serve_demo_page))
        .route("/ws", get(ws_handler))
        .route("/health", get(health_handler))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    info!("WebSocket endpoint: ws://{}/ws", addr);
    info!("Demo page: http://{}/", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// WebSocket upgrade handler
async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if !state.can_accept_client().await {
        warn!("Connection rejected: max clients reached");
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "Too many connections",
        )
            .into_response();
    }

    ws.on_upgrade(move |socket| handle_socket(socket, state))
        .into_response()
}

/// Handle WebSocket connection
async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    state.add_client().await;

    let session = ClientSession::new(state.bridge.clone());

    if let Err(e) = session.run(socket).await {
        error!("Session error: {}", e);
    }

    state.remove_client().await;
}

/// Health check endpoint
async fn health_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let count = *state.client_count.read().await;

    axum::Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "domain": state.config.domain,
        "clients": count,
        "max_clients": state.config.max_clients,
    }))
}

/// Serve embedded demo page
async fn serve_demo_page() -> Html<&'static str> {
    Html(include_str!("demo.html"))
}
