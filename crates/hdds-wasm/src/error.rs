// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// HDDS WASM SDK - Error types

use core::fmt;

/// Errors that can occur in the WASM DDS SDK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasmError {
    /// Not connected to relay.
    NotConnected,
    /// Already connected to relay.
    AlreadyConnected,
    /// Unknown topic ID.
    UnknownTopic(u16),
    /// Topic already exists.
    TopicAlreadyExists(String),
    /// Writer already exists for this topic.
    WriterAlreadyExists(u16),
    /// Reader already exists for this topic.
    ReaderAlreadyExists(u16),
    /// Unknown message type received.
    UnknownMessageType(u8),
    /// Message too short (truncated).
    MessageTooShort {
        expected: usize,
        actual: usize,
    },
    /// CDR encoding error.
    CdrEncodeError(String),
    /// CDR decoding error.
    CdrDecodeError(String),
    /// Protocol error from relay.
    ProtocolError(String),
    /// Unknown client ID on relay side.
    UnknownClient(u32),
    /// Buffer underflow during decode.
    BufferUnderflow,
}

impl fmt::Display for WasmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WasmError::NotConnected => write!(f, "not connected to relay"),
            WasmError::AlreadyConnected => write!(f, "already connected to relay"),
            WasmError::UnknownTopic(id) => write!(f, "unknown topic id: {}", id),
            WasmError::TopicAlreadyExists(name) => {
                write!(f, "topic already exists: {}", name)
            }
            WasmError::WriterAlreadyExists(id) => {
                write!(f, "writer already exists for topic: {}", id)
            }
            WasmError::ReaderAlreadyExists(id) => {
                write!(f, "reader already exists for topic: {}", id)
            }
            WasmError::UnknownMessageType(t) => {
                write!(f, "unknown message type: 0x{:02X}", t)
            }
            WasmError::MessageTooShort { expected, actual } => {
                write!(
                    f,
                    "message too short: expected {} bytes, got {}",
                    expected, actual
                )
            }
            WasmError::CdrEncodeError(msg) => write!(f, "CDR encode error: {}", msg),
            WasmError::CdrDecodeError(msg) => write!(f, "CDR decode error: {}", msg),
            WasmError::ProtocolError(msg) => write!(f, "protocol error: {}", msg),
            WasmError::UnknownClient(id) => write!(f, "unknown client id: {}", id),
            WasmError::BufferUnderflow => write!(f, "buffer underflow"),
        }
    }
}

impl std::error::Error for WasmError {}
