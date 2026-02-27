// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// HDDS WASM SDK - WasmWriter (sends data through WebSocket)

use crate::qos::WasmQos;

/// A WASM-side DDS data writer.
///
/// Represents one writer endpoint bound to a specific topic.
/// The actual WebSocket send is handled externally (by JS glue or relay);
/// the writer just tracks state and prepares messages.
#[derive(Debug, Clone)]
pub struct WasmWriter {
    /// Topic ID assigned by the relay.
    pub topic_id: u16,
    /// QoS settings for this writer.
    pub qos: WasmQos,
    /// Number of samples written.
    pub samples_written: u64,
}

impl WasmWriter {
    /// Create a new writer for the given topic ID.
    pub fn new(topic_id: u16) -> Self {
        Self {
            topic_id,
            qos: WasmQos::default(),
            samples_written: 0,
        }
    }

    /// Create a new writer with specific QoS.
    pub fn with_qos(topic_id: u16, qos: WasmQos) -> Self {
        Self {
            topic_id,
            qos,
            samples_written: 0,
        }
    }

    /// Increment the sample counter and return the new count.
    pub fn record_write(&mut self) -> u64 {
        self.samples_written += 1;
        self.samples_written
    }
}
