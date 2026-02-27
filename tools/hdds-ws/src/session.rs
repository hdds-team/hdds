// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! WebSocket client session management.
//!
//! Each connected WebSocket client gets a Session that handles:
//! - Message parsing and routing
//! - Subscription management
//! - Data forwarding from DDS to WebSocket

use crate::bridge::DdsBridge;
use crate::protocol::{ClientMessage, ErrorCode, ServerMessage};
use axum::extract::ws::{Message, WebSocket};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// A WebSocket client session
pub struct ClientSession {
    bridge: Arc<DdsBridge>,
    /// Active subscriptions: subscription_id -> topic_name
    subscriptions: DashMap<String, String>,
    /// Session ID for logging
    session_id: String,
}

impl ClientSession {
    /// Create a new client session
    pub fn new(bridge: Arc<DdsBridge>) -> Self {
        let session_id = Uuid::new_v4().to_string()[..8].to_string();
        info!("[{}] New session created", session_id);

        Self {
            bridge,
            subscriptions: DashMap::new(),
            session_id,
        }
    }

    /// Run the session, handling messages until disconnect
    pub async fn run(
        self,
        socket: WebSocket,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut ws_tx, mut ws_rx) = socket.split();

        // Send welcome message
        let welcome = ServerMessage::welcome(self.bridge.domain_id());
        let welcome_json = serde_json::to_string(&welcome)?;
        ws_tx.send(Message::Text(welcome_json)).await?;

        // Channel for sending messages to WebSocket
        let (tx, mut rx) = tokio::sync::mpsc::channel::<ServerMessage>(256);

        // Spawn task to forward messages to WebSocket
        let session_id = self.session_id.clone();
        let ws_forward = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match serde_json::to_string(&msg) {
                    Ok(json) => {
                        if ws_tx.send(Message::Text(json)).await.is_err() {
                            debug!("[{}] WebSocket send failed, closing", session_id);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("[{}] Failed to serialize message: {}", session_id, e);
                    }
                }
            }
        });

        // Handle incoming messages
        while let Some(msg) = ws_rx.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    if let Err(e) = self.handle_message(&text, tx.clone()).await {
                        warn!("[{}] Error handling message: {}", self.session_id, e);
                        let error_msg =
                            ServerMessage::error(ErrorCode::InternalError, e.to_string());
                        let _ = tx.send(error_msg).await;
                    }
                }
                Ok(Message::Close(_)) => {
                    info!("[{}] Client closed connection", self.session_id);
                    break;
                }
                Ok(Message::Ping(_)) => {
                    // Axum handles pong automatically
                }
                Ok(Message::Pong(_)) => {
                    debug!("[{}] Pong received", self.session_id);
                }
                Ok(Message::Binary(_)) => {
                    warn!("[{}] Binary messages not supported", self.session_id);
                }
                Err(e) => {
                    error!("[{}] WebSocket error: {}", self.session_id, e);
                    break;
                }
            }
        }

        // Cleanup
        ws_forward.abort();
        info!("[{}] Session ended", self.session_id);

        Ok(())
    }

    /// Handle a single client message
    // @audit-ok: Sequential handler (cyclo 14, cogni 2) - message type dispatch with error handling
    async fn handle_message(
        &self,
        text: &str,
        tx: tokio::sync::mpsc::Sender<ServerMessage>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let msg: ClientMessage = match serde_json::from_str(text) {
            Ok(m) => m,
            Err(e) => {
                let error =
                    ServerMessage::error(ErrorCode::InvalidMessage, format!("Invalid JSON: {}", e));
                tx.send(error).await?;
                return Ok(());
            }
        };

        debug!("[{}] Received: {:?}", self.session_id, msg);

        match msg {
            ClientMessage::Subscribe { topic, _qos: _ } => {
                self.handle_subscribe(&topic, tx).await?;
            }
            ClientMessage::Unsubscribe { topic } => {
                self.handle_unsubscribe(&topic, tx).await?;
            }
            ClientMessage::Publish { topic, data } => {
                self.handle_publish(&topic, data, tx).await?;
            }
            ClientMessage::ListTopics => {
                self.handle_list_topics(tx).await?;
            }
            ClientMessage::Ping { id } => {
                tx.send(ServerMessage::Pong { id }).await?;
            }
        }

        Ok(())
    }

    /// Handle subscribe request
    async fn handle_subscribe(
        &self,
        topic: &str,
        tx: tokio::sync::mpsc::Sender<ServerMessage>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Check if already subscribed
        for entry in self.subscriptions.iter() {
            if entry.value() == topic {
                let error = ServerMessage::topic_error(
                    ErrorCode::AlreadySubscribed,
                    "Already subscribed to this topic",
                    topic,
                );
                tx.send(error).await?;
                return Ok(());
            }
        }

        // Subscribe via bridge
        let mut receiver = self.bridge.subscribe(topic).await?;

        // Generate subscription ID
        let sub_id = format!("sub_{}", &Uuid::new_v4().to_string()[..8]);
        self.subscriptions.insert(sub_id.clone(), topic.to_string());

        // Send confirmation
        let confirm = ServerMessage::Subscribed {
            topic: topic.to_string(),
            subscription_id: sub_id.clone(),
        };
        tx.send(confirm).await?;

        info!(
            "[{}] Subscribed to '{}' ({})",
            self.session_id, topic, sub_id
        );

        // Spawn task to forward samples
        let session_id = self.session_id.clone();
        let topic_name = topic.to_string();
        let sub_id_clone = sub_id.clone();

        tokio::spawn(async move {
            loop {
                match receiver.recv().await {
                    Ok(sample) => {
                        let msg = ServerMessage::Data {
                            topic: sample.topic,
                            subscription_id: sub_id_clone.clone(),
                            sample: sample.data,
                            info: sample.info,
                        };
                        if tx.send(msg).await.is_err() {
                            debug!(
                                "[{}] Client disconnected, stopping subscription",
                                session_id
                            );
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("[{}] Lagged {} messages on '{}'", session_id, n, topic_name);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        debug!("[{}] Subscription '{}' closed", session_id, topic_name);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Handle unsubscribe request
    async fn handle_unsubscribe(
        &self,
        topic: &str,
        tx: tokio::sync::mpsc::Sender<ServerMessage>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Find and remove subscription
        let mut found = false;
        self.subscriptions.retain(|_k, v| {
            if v == topic {
                found = true;
                false // Remove this entry
            } else {
                true
            }
        });

        if found {
            let confirm = ServerMessage::Unsubscribed {
                topic: topic.to_string(),
            };
            tx.send(confirm).await?;
            info!("[{}] Unsubscribed from '{}'", self.session_id, topic);
        } else {
            let error = ServerMessage::topic_error(
                ErrorCode::NotSubscribed,
                "Not subscribed to this topic",
                topic,
            );
            tx.send(error).await?;
        }

        Ok(())
    }

    /// Handle publish request
    async fn handle_publish(
        &self,
        topic: &str,
        data: serde_json::Value,
        tx: tokio::sync::mpsc::Sender<ServerMessage>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match self.bridge.publish(topic, data).await {
            Ok(seq) => {
                let confirm = ServerMessage::Published {
                    topic: topic.to_string(),
                    sequence: seq,
                };
                tx.send(confirm).await?;
                debug!(
                    "[{}] Published to '{}' (seq={})",
                    self.session_id, topic, seq
                );
            }
            Err(e) => {
                let error = ServerMessage::topic_error(
                    ErrorCode::PublishFailed,
                    format!("Publish failed: {}", e),
                    topic,
                );
                tx.send(error).await?;
            }
        }

        Ok(())
    }

    /// Handle list topics request
    async fn handle_list_topics(
        &self,
        tx: tokio::sync::mpsc::Sender<ServerMessage>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let topics = self.bridge.list_topics();

        let msg = ServerMessage::Topics { topics };
        tx.send(msg).await?;

        debug!("[{}] Listed topics", self.session_id);
        Ok(())
    }
}
