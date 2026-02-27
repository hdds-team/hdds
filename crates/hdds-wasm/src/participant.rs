// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// HDDS WASM SDK - WasmParticipant (browser-side DDS participant)

use crate::error::WasmError;
use crate::protocol::{self, RelayMessage};
use crate::reader::WasmReader;
use crate::writer::WasmWriter;
use std::collections::HashMap;

/// Browser-side DDS participant that communicates with a relay server.
///
/// The participant builds protocol messages to send over WebSocket
/// and processes incoming messages from the relay.
/// Actual WebSocket I/O is handled externally (by JS glue code).
pub struct WasmParticipant {
    /// Participant ID assigned by the relay (0 until connected).
    pub participant_id: u32,
    /// DDS domain ID.
    pub domain_id: u16,
    /// Mapping from topic name to relay-assigned topic ID.
    pub topics: HashMap<String, u16>,
    /// Writers keyed by topic ID.
    pub writers: HashMap<u16, WasmWriter>,
    /// Readers keyed by topic ID.
    pub readers: HashMap<u16, WasmReader>,
    /// Monotonically increasing sequence number.
    sequence_nr: u32,
    /// Whether we have received a CONNECT_ACK.
    pub connected: bool,
}

impl WasmParticipant {
    /// Create a new participant for the given domain.
    pub fn new(domain_id: u16) -> Self {
        Self {
            participant_id: 0,
            domain_id,
            topics: HashMap::new(),
            writers: HashMap::new(),
            readers: HashMap::new(),
            sequence_nr: 0,
            connected: false,
        }
    }

    /// Get and increment the sequence number.
    fn next_seq(&mut self) -> u32 {
        let seq = self.sequence_nr;
        self.sequence_nr = self.sequence_nr.wrapping_add(1);
        seq
    }

    /// Build a CONNECT message to send to the relay.
    pub fn build_connect(&mut self) -> Vec<u8> {
        let seq = self.next_seq();
        protocol::build_connect(self.domain_id, seq)
    }

    /// Process a CONNECT_ACK from the relay.
    pub fn handle_connect_ack(&mut self, data: &[u8]) -> Result<(), WasmError> {
        let msg = protocol::parse_message(data)?;
        match msg {
            RelayMessage::ConnectAck { participant_id } => {
                self.participant_id = participant_id;
                self.connected = true;
                Ok(())
            }
            _ => Err(WasmError::ProtocolError(
                "expected CONNECT_ACK".to_string(),
            )),
        }
    }

    /// Build a CREATE_TOPIC message.
    pub fn build_create_topic(&mut self, name: &str, type_name: &str) -> Vec<u8> {
        let seq = self.next_seq();
        protocol::build_create_topic(name, type_name, seq)
    }

    /// Process a TOPIC_ACK from the relay. Returns the assigned topic ID.
    pub fn handle_topic_ack(&mut self, data: &[u8]) -> Result<u16, WasmError> {
        let msg = protocol::parse_message(data)?;
        match msg {
            RelayMessage::TopicAck {
                topic_id,
                topic_name,
            } => {
                self.topics.insert(topic_name, topic_id);
                Ok(topic_id)
            }
            _ => Err(WasmError::ProtocolError("expected TOPIC_ACK".to_string())),
        }
    }

    /// Create a writer for the given topic.
    pub fn create_writer(&mut self, topic_id: u16) -> Result<&WasmWriter, WasmError> {
        if !self.topics.values().any(|&id| id == topic_id) {
            return Err(WasmError::UnknownTopic(topic_id));
        }
        if self.writers.contains_key(&topic_id) {
            return Err(WasmError::WriterAlreadyExists(topic_id));
        }
        let writer = WasmWriter::new(topic_id);
        self.writers.insert(topic_id, writer);
        Ok(self.writers.get(&topic_id).unwrap())
    }

    /// Create a reader for the given topic.
    pub fn create_reader(&mut self, topic_id: u16) -> Result<&WasmReader, WasmError> {
        if !self.topics.values().any(|&id| id == topic_id) {
            return Err(WasmError::UnknownTopic(topic_id));
        }
        if self.readers.contains_key(&topic_id) {
            return Err(WasmError::ReaderAlreadyExists(topic_id));
        }
        let reader = WasmReader::new(topic_id);
        self.readers.insert(topic_id, reader);
        Ok(self.readers.get(&topic_id).unwrap())
    }

    /// Build a PUBLISH message with CDR payload.
    pub fn build_publish(
        &mut self,
        topic_id: u16,
        cdr_data: &[u8],
    ) -> Result<Vec<u8>, WasmError> {
        if !self.connected {
            return Err(WasmError::NotConnected);
        }
        if let Some(writer) = self.writers.get_mut(&topic_id) {
            writer.record_write();
        } else {
            return Err(WasmError::UnknownTopic(topic_id));
        }
        let seq = self.next_seq();
        Ok(protocol::build_publish(topic_id, seq, cdr_data))
    }

    /// Build a SUBSCRIBE message for the given topic.
    pub fn build_subscribe(&mut self, topic_id: u16) -> Vec<u8> {
        if let Some(reader) = self.readers.get_mut(&topic_id) {
            reader.set_subscribed(true);
        }
        let seq = self.next_seq();
        protocol::build_subscribe(topic_id, seq)
    }

    /// Process an incoming DATA message from the relay.
    /// Returns (topic_id, cdr_payload).
    pub fn handle_data(&mut self, data: &[u8]) -> Result<(u16, Vec<u8>), WasmError> {
        let msg = protocol::parse_message(data)?;
        match msg {
            RelayMessage::Data {
                topic_id,
                sequence_nr: _,
                payload,
            } => {
                if let Some(reader) = self.readers.get_mut(&topic_id) {
                    reader.record_receive();
                }
                Ok((topic_id, payload))
            }
            _ => Err(WasmError::ProtocolError("expected DATA".to_string())),
        }
    }

    /// Build a PING message.
    pub fn build_ping(&self) -> Vec<u8> {
        protocol::build_ping(self.sequence_nr)
    }

    /// Build a DISCONNECT message.
    pub fn build_disconnect(&self) -> Vec<u8> {
        protocol::build_disconnect(self.sequence_nr)
    }

    /// Process any incoming message from the relay.
    pub fn process_message(&mut self, data: &[u8]) -> Result<RelayMessage, WasmError> {
        let msg = protocol::parse_message(data)?;
        match &msg {
            RelayMessage::ConnectAck { participant_id } => {
                self.participant_id = *participant_id;
                self.connected = true;
            }
            RelayMessage::TopicAck {
                topic_id,
                topic_name,
            } => {
                self.topics.insert(topic_name.clone(), *topic_id);
            }
            RelayMessage::Data {
                topic_id,
                sequence_nr: _,
                payload: _,
            } => {
                if let Some(reader) = self.readers.get_mut(topic_id) {
                    reader.record_receive();
                }
            }
            RelayMessage::Disconnected => {
                self.connected = false;
            }
            RelayMessage::Error { reason: _ } => {
                // Application can inspect the error from the returned message
            }
            RelayMessage::Pong { .. } => {
                // Keepalive response, no state change
            }
            _ => {
                // Other message types are client-to-relay, not expected here
            }
        }
        Ok(msg)
    }
}
