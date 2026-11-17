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
//! # Admission, stated exactly
//!
//! The ClientKey list decides who may OPEN a session, and the session is then
//! bound to the address that opened it: a later submessage from anywhere else
//! (or carrying a different ClientKey on a keyed session id) is dropped and
//! counted in [`agent::XrceAgent::denied_submessages`]. A client whose source
//! address changes must open a new session.
//!
//! # What inbound reliability does and does not do
//!
//! Outbound reliability is complete: sequence numbers per stream, retained
//! frames, ACKNACK-driven retransmission and periodic HEARTBEAT. On the
//! INBOUND side the agent deduplicates - a sequence number a reliable stream
//! has already passed is dropped, so a replayed CREATE, DELETE, WRITE_DATA or
//! READ_DATA is never executed twice - but it does NOT buffer or reorder: a
//! frame that arrives out of order is executed on arrival, and the gap is not
//! requested back. Ordered inbound delivery is not implemented.
//!
//! # Transports
//!
//! | Transport | Use Case | MTU |
//! |-----------|----------|-----|
//! | [`UdpTransport`] | WiFi / Ethernet MCUs | 1500 |
//! | [`SerialTransport`] | UART / RS-485 / HC-12 | 64-256 |
//! | [`TcpTransport`] | Cloud / NAT traversal | 65535 |

pub mod agent;
#[cfg(feature = "hdds")]
pub mod bridge_hdds;
pub mod config;
pub mod protocol;
pub mod proxy;
pub mod session;
pub mod transport;

// Re-exports for convenience.
pub use agent::XrceAgent;
pub use config::XrceAgentConfig;
pub use protocol::{
    decode_string,
    encode_string,
    fragment_message,
    fragment_payload,
    // Functions
    parse_message,
    parse_submessage,
    serialize_message,
    serialize_submessage,
    AcknackPayload,
    // Payload types
    CreateClientPayload,
    CreatePayload,
    DataPayload,
    DeletePayload,
    // Fragmentation
    FragmentHeader,
    FragmentPayload,
    HeartbeatPayload,
    // Message types
    MessageHeader,
    // Enums
    ObjectKind,
    ReadDataPayload,
    ReassemblyBuffer,
    StatusCode,
    StatusPayload,
    Submessage,
    SubmessageHeader,
    WriteDataPayload,
    // Error
    XrceError,
    XrceMessage,
};
pub use proxy::{NullBridge, ProxyBridge};

#[cfg(feature = "hdds")]
pub use bridge_hdds::HddsBridge;
pub use session::{ClientSession, SessionTable, StreamKind, StreamState, XrceObject};
pub use transport::{
    tcp_frame, SerialTransport, TcpTransport, TransportAddr, UdpTransport, XrceTransport,
    TCP_LENGTH_PREFIX_SIZE,
};

#[cfg(test)]
mod tests;
