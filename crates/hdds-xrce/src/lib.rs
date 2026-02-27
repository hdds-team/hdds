// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS-XRCE v1.0 agent/client bridge.
//!
//! Implements the OMG DDS-XRCE (eXtremely Resource Constrained Environments)
//! protocol for bridging resource-constrained devices (MCUs, sensors, embedded
//! Linux) into a full DDS network.
//!
//! # Architecture
//!
//! ```text
//! XRCE Client (MCU)                XRCE Agent (this crate)         DDS Network
//!   ESP32 / STM32                    Linux / Windows
//!        |                                |                            |
//!        |--- CREATE_CLIENT ------------>|                            |
//!        |--- CREATE(topic) ------------>|--- create DDS reader ----->|
//!        |--- WRITE_DATA(payload) ------>|--- DDS write ------------->|
//!        |<-- DATA(payload) -------------|<-- DDS sample ------------|
//!        |--- DELETE ------------------->|--- cleanup --------------->|
//! ```
//!
//! # Key Features
//!
//! - **Transport-agnostic**: Supports UDP, Serial (UART), and TCP transports
//! - **DDS-agnostic**: Any DDS implementation can be plugged in via [`ProxyBridge`]
//! - **Fragmentation**: Large payloads are fragmented and reassembled transparently
//! - **Session management**: Reliable delivery with sequence numbers and heartbeats
//!
//! # Transports
//!
//! | Transport | Use Case | MTU |
//! |-----------|----------|-----|
//! | [`UdpTransport`] | WiFi / Ethernet MCUs | 1500 |
//! | [`SerialTransport`] | UART / RS-485 / HC-12 | 64-256 |
//! | [`TcpTransport`] | Cloud / NAT traversal | 65535 |

pub mod agent;
pub mod config;
pub mod protocol;
pub mod proxy;
pub mod session;
pub mod transport;

// Re-exports for convenience.
pub use agent::XrceAgent;
pub use config::XrceAgentConfig;
pub use protocol::{
    // Error
    XrceError,
    // Message types
    MessageHeader, SubmessageHeader, Submessage, XrceMessage,
    // Payload types
    CreateClientPayload, CreatePayload, DeletePayload,
    WriteDataPayload, ReadDataPayload, DataPayload,
    StatusPayload, HeartbeatPayload, AcknackPayload,
    // Enums
    ObjectKind, StatusCode,
    // Fragmentation
    FragmentHeader, ReassemblyBuffer,
    // Functions
    parse_message, parse_submessage,
    serialize_message, serialize_submessage,
    fragment_payload,
    encode_string, decode_string,
};
pub use proxy::{ProxyBridge, NullBridge};
pub use session::{ClientSession, SessionTable, StreamState, StreamKind, XrceObject};
pub use transport::{TransportAddr, XrceTransport, UdpTransport, SerialTransport, TcpTransport};

#[cfg(test)]
mod tests;
