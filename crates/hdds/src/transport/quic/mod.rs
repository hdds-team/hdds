// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! QUIC Transport for RTPS communication.
//!
//! Provides QUIC-based transport for DDS/RTPS with modern features:
//!
//! - **NAT Traversal**: UDP-based protocol works better through NAT/firewalls
//! - **0-RTT**: Near-instant connection establishment for known peers
//! - **Connection Migration**: Seamless handoff when IP changes (mobile robots, WiFi roaming)
//! - **Built-in TLS 1.3**: Encrypted by default, no separate TLS layer needed
//! - **Multiplexing**: Multiple streams without head-of-line blocking
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      QuicTransport                          │
//! │  ┌───────────────────────────────────────────────────────┐  │
//! │  │                    quinn::Endpoint                     │  │
//! │  │  ┌─────────────────┐  ┌─────────────────────────────┐ │  │
//! │  │  │    Listener     │  │     Connection Pool         │ │  │
//! │  │  │   (incoming)    │  │   HashMap<SocketAddr, Conn> │ │  │
//! │  │  └─────────────────┘  └─────────────────────────────┘ │  │
//! │  └───────────────────────────────────────────────────────┘  │
//! │                              │                               │
//! │  ┌───────────────────────────▼───────────────────────────┐  │
//! │  │                  quinn::Connection                     │  │
//! │  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐  │  │
//! │  │  │   Stream 0  │ │   Stream 1  │ │    Stream N     │  │  │
//! │  │  │  (control)  │ │  (topic A)  │ │   (topic N)     │  │  │
//! │  │  └─────────────┘ └─────────────┘ └─────────────────┘  │  │
//! │  └───────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Wire Format
//!
//! QUIC provides reliable, ordered streams. Each RTPS message is sent on
//! a unidirectional stream with a 4-byte length prefix (same as TCP):
//!
//! ```text
//! Stream N:
//! ┌────────────────┬───────────────────┐
//! │ Length (4B BE) │ RTPS Message      │
//! └────────────────┴───────────────────┘
//! ```
//!
//! # Interoperability
//!
//! **Note**: DDS over QUIC is **not standardized** by OMG. This transport
//! is for **HDDS <-> HDDS** communication only. For cross-vendor interop,
//! use UDP transport.
//!
//! # Example
//!
//! ```ignore
//! use hdds::transport::quic::{QuicConfig, QuicTransport};
//!
//! // Create QUIC transport config
//! let config = QuicConfig::builder()
//!     .bind_addr("0.0.0.0:0".parse().unwrap())
//!     .build();
//!
//! // Connect to remote endpoint
//! let transport = QuicTransport::new(config).await?;
//! transport.connect("192.168.1.100:7400".parse().unwrap()).await?;
//!
//! // Send RTPS message
//! transport.send(b"RTPS...", &remote_addr).await?;
//! ```
//!
//! # Feature Flag
//!
//! This module requires the `quic` feature:
//!
//! ```toml
//! [dependencies]
//! hdds = { version = "0.8", features = ["quic"] }
//! ```

mod config;
mod connection;
mod io_thread;
mod transport;

// Re-exports
pub use config::{QuicConfig, QuicConfigBuilder};
pub use connection::{QuicConnection, QuicConnectionState, MAX_QUIC_MESSAGE_SIZE};
pub use io_thread::{QuicCommand, QuicEvent, QuicIoThread, QuicIoThreadHandle};
pub use transport::{QuicTransport, QuicTransportHandle};

/// QUIC transport error types.
#[derive(Debug)]
pub enum QuicError {
    /// Failed to bind to local address.
    BindFailed(String),
    /// Connection to remote peer failed.
    ConnectionFailed(String),
    /// Failed to open stream.
    StreamFailed(String),
    /// Send operation failed.
    SendFailed(String),
    /// Receive operation failed.
    RecvFailed(String),
    /// TLS/crypto error.
    TlsError(String),
    /// Connection closed by peer.
    ConnectionClosed,
    /// Operation timed out.
    Timeout,
    /// Invalid configuration.
    InvalidConfig(String),
}

impl std::fmt::Display for QuicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuicError::BindFailed(msg) => write!(f, "QUIC bind failed: {}", msg),
            QuicError::ConnectionFailed(msg) => write!(f, "QUIC connection failed: {}", msg),
            QuicError::StreamFailed(msg) => write!(f, "QUIC stream failed: {}", msg),
            QuicError::SendFailed(msg) => write!(f, "QUIC send failed: {}", msg),
            QuicError::RecvFailed(msg) => write!(f, "QUIC recv failed: {}", msg),
            QuicError::TlsError(msg) => write!(f, "QUIC TLS error: {}", msg),
            QuicError::ConnectionClosed => write!(f, "QUIC connection closed"),
            QuicError::Timeout => write!(f, "QUIC operation timed out"),
            QuicError::InvalidConfig(msg) => write!(f, "QUIC invalid config: {}", msg),
        }
    }
}

impl std::error::Error for QuicError {}

/// Result type for QUIC operations.
pub type QuicResult<T> = Result<T, QuicError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = QuicError::BindFailed("address in use".to_string());
        assert!(err.to_string().contains("bind failed"));

        let err = QuicError::ConnectionClosed;
        assert!(err.to_string().contains("closed"));
    }
}
