// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// HDDS WASM SDK - WasmReader (receives data from WebSocket)

use crate::qos::WasmQos;

/// A WASM-side DDS data reader.
///
/// Represents one reader endpoint subscribed to a specific topic.
/// Incoming DATA messages are dispatched to readers by the participant.
#[derive(Debug, Clone)]
pub struct WasmReader {
    /// Topic ID assigned by the relay.
    pub topic_id: u16,
    /// QoS settings for this reader.
    pub qos: WasmQos,
    /// Number of samples received.
    pub samples_received: u64,
    /// Whether the reader is actively subscribed.
    pub subscribed: bool,
}

impl WasmReader {
    /// Create a new reader for the given topic ID.
    pub fn new(topic_id: u16) -> Self {
        Self {
            topic_id,
            qos: WasmQos::default(),
            samples_received: 0,
            subscribed: false,
        }
    }

    /// Create a new reader with specific QoS.
    pub fn with_qos(topic_id: u16, qos: WasmQos) -> Self {
        Self {
            topic_id,
            qos,
            samples_received: 0,
            subscribed: false,
        }
    }

    /// Mark this reader as subscribed.
    pub fn set_subscribed(&mut self, subscribed: bool) {
        self.subscribed = subscribed;
    }

    /// Record a received sample and return the new count.
    pub fn record_receive(&mut self) -> u64 {
        self.samples_received += 1;
        self.samples_received
    }
}
