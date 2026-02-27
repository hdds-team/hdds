// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// HDDS WASM SDK - Relay protocol handler (server-side, native only)

use crate::error::WasmError;
use crate::protocol::{self, RelayMessage};
use std::collections::{HashMap, HashSet};

/// Information about a topic registered by a client.
#[derive(Debug, Clone)]
pub struct TopicInfo {
    /// Human-readable topic name.
    pub topic_name: String,
    /// Type name (e.g. "sensor_msgs::Temperature").
    pub type_name: String,
}

/// Relay-side state for one connected WASM client.
#[derive(Debug)]
pub struct RelayClient {
    /// Participant ID assigned to this client.
    pub participant_id: u32,
    /// DDS domain ID requested by the client.
    pub domain_id: u16,
    /// Topics created by this client: topic_id -> info.
    pub topics: HashMap<u16, TopicInfo>,
    /// Topic IDs this client is subscribed to.
    pub subscriptions: HashSet<u16>,
}

impl RelayClient {
    fn new(participant_id: u32, domain_id: u16) -> Self {
        Self {
            participant_id,
            domain_id,
            topics: HashMap::new(),
            subscriptions: HashSet::new(),
        }
    }
}

/// Relay message processor.
///
/// Manages connected WASM clients, processes their protocol messages,
/// and routes data between them. Does NOT perform actual DDS operations --
/// that is the responsibility of the relay server that embeds this handler.
pub struct RelayHandler {
    /// Connected clients keyed by participant_id.
    clients: HashMap<u32, RelayClient>,
    /// Next participant ID to assign.
    next_participant_id: u32,
    /// Global topic registry: topic_name -> topic_id.
    /// Shared across clients so they can subscribe to each other's topics.
    global_topics: HashMap<String, u16>,
    /// Reverse lookup: topic_id -> topic_name.
    topic_names: HashMap<u16, String>,
    /// Global next topic ID.
    next_global_topic_id: u16,
}

impl RelayHandler {
    /// Create a new relay handler.
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
            next_participant_id: 1,
            global_topics: HashMap::new(),
            topic_names: HashMap::new(),
            next_global_topic_id: 1,
        }
    }

    /// Accept a new client connection.
    /// Returns (client_id, connect_ack_bytes).
    pub fn accept_client(&mut self) -> (u32, Vec<u8>) {
        let id = self.next_participant_id;
        self.next_participant_id = self.next_participant_id.wrapping_add(1);
        // Client is not fully registered until we receive CONNECT with domain_id
        let ack = protocol::build_connect_ack(id, 0);
        (id, ack)
    }

    /// Remove a disconnected client and clean up its state.
    pub fn remove_client(&mut self, client_id: u32) {
        self.clients.remove(&client_id);
    }

    /// Process an incoming message from a WASM client.
    /// Returns response messages to send back to that client.
    pub fn process_client_message(
        &mut self,
        client_id: u32,
        data: &[u8],
    ) -> Result<Vec<Vec<u8>>, WasmError> {
        let msg = protocol::parse_message(data)?;
        let mut responses = Vec::new();

        match msg {
            RelayMessage::Connect { domain_id } => {
                // Register client with domain_id
                let client = RelayClient::new(client_id, domain_id);
                self.clients.insert(client_id, client);
                let ack = protocol::build_connect_ack(client_id, 0);
                responses.push(ack);
            }
            RelayMessage::CreateTopic {
                topic_name,
                type_name,
            } => {
                let client = self
                    .clients
                    .get_mut(&client_id)
                    .ok_or(WasmError::UnknownClient(client_id))?;

                // Use global topic ID if topic already exists, otherwise allocate new
                let topic_id = if let Some(&existing_id) = self.global_topics.get(&topic_name) {
                    existing_id
                } else {
                    let new_id = self.next_global_topic_id;
                    self.next_global_topic_id = self.next_global_topic_id.wrapping_add(1);
                    self.global_topics.insert(topic_name.clone(), new_id);
                    self.topic_names.insert(new_id, topic_name.clone());
                    new_id
                };

                client.topics.insert(
                    topic_id,
                    TopicInfo {
                        topic_name: topic_name.clone(),
                        type_name,
                    },
                );

                let ack = protocol::build_topic_ack(topic_id, &topic_name, 0);
                responses.push(ack);
            }
            RelayMessage::Subscribe { topic_id } => {
                let client = self
                    .clients
                    .get_mut(&client_id)
                    .ok_or(WasmError::UnknownClient(client_id))?;
                client.subscriptions.insert(topic_id);
            }
            RelayMessage::Unsubscribe { topic_id } => {
                let client = self
                    .clients
                    .get_mut(&client_id)
                    .ok_or(WasmError::UnknownClient(client_id))?;
                client.subscriptions.remove(&topic_id);
            }
            RelayMessage::Publish {
                topic_id: _,
                sequence_nr: _,
                payload: _,
            } => {
                // Relay would forward to DDS and/or other clients.
                // The actual routing is done via route_publication().
                // No immediate response needed.
                let _client = self
                    .clients
                    .get(&client_id)
                    .ok_or(WasmError::UnknownClient(client_id))?;
            }
            RelayMessage::Ping { sequence_nr } => {
                let pong = protocol::build_pong(sequence_nr);
                responses.push(pong);
            }
            RelayMessage::Disconnected => {
                self.remove_client(client_id);
            }
            _ => {
                // Unexpected message types (e.g. server-to-client messages)
                let err_msg = protocol::build_error("unexpected message type", 0);
                responses.push(err_msg);
            }
        }

        Ok(responses)
    }

    /// Route a publication from one WASM client to other subscribed WASM clients.
    /// Returns (client_id, data_message) pairs for each subscriber.
    pub fn route_publication(
        &self,
        topic_id: u16,
        cdr_data: &[u8],
        source_client: u32,
    ) -> Vec<(u32, Vec<u8>)> {
        let mut results = Vec::new();
        for (cid, client) in &self.clients {
            if *cid == source_client {
                continue; // don't echo back to sender
            }
            if client.subscriptions.contains(&topic_id) {
                let data_msg = protocol::build_data(topic_id, 0, cdr_data);
                results.push((*cid, data_msg));
            }
        }
        results
    }

    /// Route DDS data (from native DDS side) to subscribed WASM clients.
    /// Returns (client_id, data_message) pairs.
    pub fn route_dds_data(
        &self,
        topic_name: &str,
        cdr_data: &[u8],
    ) -> Vec<(u32, Vec<u8>)> {
        let topic_id = match self.global_topics.get(topic_name) {
            Some(&id) => id,
            None => return Vec::new(),
        };
        let mut results = Vec::new();
        for (cid, client) in &self.clients {
            if client.subscriptions.contains(&topic_id) {
                let data_msg = protocol::build_data(topic_id, 0, cdr_data);
                results.push((*cid, data_msg));
            }
        }
        results
    }

    /// Get the number of connected clients.
    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    /// Check if a client is registered.
    pub fn has_client(&self, client_id: u32) -> bool {
        self.clients.contains_key(&client_id)
    }

    /// Get the global topic ID for a topic name, if it exists.
    pub fn get_topic_id(&self, topic_name: &str) -> Option<u16> {
        self.global_topics.get(topic_name).copied()
    }
}

impl Default for RelayHandler {
    fn default() -> Self {
        Self::new()
    }
}
