// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS WASM SDK -- DDS in the browser via WebAssembly.
//!
//! This crate provides a WASM-compatible DDS client that communicates with
//! a relay server over WebSocket. The relay bridges WASM clients to full
//! DDS participants on the native side.
//!
//! # Architecture
//!
//! ```text
//! Browser (wasm32) <--WebSocket--> Relay (native) <--DDS/RTPS--> Network
//! ```
//!
//! ## WASM side (this crate, `wasm32` target)
//! - CDR serialization/deserialization
//! - QoS management
//! - Protocol message construction and parsing
//!
//! ## Relay side (this crate, native target)
//! - Client connection management via WebSocket
//! - Topic registration and routing
//! - Bridging to native DDS participants
//!
//! # Design Decisions
//!
//! - **No `wasm-bindgen` dependency** -- pure Rust that compiles to both native and wasm32
//! - Relay module is `#[cfg(not(target_arch = "wasm32"))]` gated
//! - CDR encoder/decoder is shared between both targets

pub mod cdr;
pub mod error;
pub mod participant;
pub mod protocol;
pub mod qos;
pub mod reader;
pub mod writer;

// Relay module is only available on native targets (not wasm32)
#[cfg(not(target_arch = "wasm32"))]
pub mod relay;

// Re-export main types for convenience
pub use cdr::{CdrDecoder, CdrEncoder};
pub use error::WasmError;
pub use participant::WasmParticipant;
pub use protocol::{MessageHeader, RelayMessage};
pub use qos::{WasmDurability, WasmQos, WasmReliability};
pub use reader::WasmReader;
pub use writer::WasmWriter;

#[cfg(not(target_arch = "wasm32"))]
pub use relay::{RelayClient, RelayHandler, TopicInfo};

#[cfg(test)]
mod tests;
