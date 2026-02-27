// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TCP Transport for RTPS communication.
//!
//! Provides TCP-based transport for DDS/RTPS in environments where UDP
//! is blocked, unreliable, or unavailable:
//!
//! - Corporate firewalls with TCP-only policies
//! - Cloud/Kubernetes environments without multicast
//! - NAT traversal scenarios where UDP hole punching fails
//! - WAN connections with high packet loss
//!
//! # Architecture
//!
//! ```text
//! +-------------------------------------------------------------+
//! |                      TcpTransport                            |
//! |  +-------------------------------------------------------+  |
//! |  |                 ConnectionManager                      |  |
//! |  |  +-----------------+  +-----------------------------+ |  |
//! |  |  |    Listener     |  |      ConnectionPool         | |  |
//! |  |  |  (TcpListener)  |  |  HashMap<GuidPrefix, Conn>  | |  |
//! |  |  +-----------------+  +-----------------------------+ |  |
//! |  +-------------------------------------------------------+  |
//! |                              |                               |
//! |  +---------------------------v---------------------------+  |
//! |  |                    TcpConnection                       |  |
//! |  |  +-------------+ +-------------+ +-----------------+  |  |
//! |  |  | ByteStream  | | FrameCodec  | | ConnectionState |  |  |
//! |  |  +-------------+ +-------------+ +-----------------+  |  |
//! |  +-------------------------------------------------------+  |
//! |                              |                               |
//! |  +---------------------------v---------------------------+  |
//! |  |                     IoThread                           |  |
//! |  |  - mio::Poll event loop                               |  |
//! |  |  - Handle accept, connect, read, write                |  |
//! |  +-------------------------------------------------------+  |
//! +-------------------------------------------------------------+
//! ```
//!
//! # Wire Format
//!
//! TCP requires framing since it's a stream protocol. Each RTPS message
//! is prefixed with a 4-byte big-endian length:
//!
//! ```text
//! +----------------+-------------------+
//! | Length (4B BE) | RTPS Message      |
//! +----------------+-------------------+
//! ```
//!
//! # Interoperability
//!
//! **Important**: RTPS over TCP is not standardized and is **not interoperable**
//! across DDS vendors. Each vendor (RTI, FastDDS, CycloneDDS) uses different
//! framing and connection protocols.
//!
//! This TCP transport is for **HDDS <-> HDDS** communication only.
//! For cross-vendor interop, use UDP transport or a gateway.
//!
//! # Example
//!
//! ```ignore
//! use hdds::transport::tcp::{TcpConfig, TcpTransport, TransportPreference};
//!
//! // Enable TCP with hybrid mode (UDP discovery + TCP data)
//! let config = TcpConfig {
//!     enabled: true,
//!     listen_port: 7410,
//!     ..Default::default()
//! };
//!
//! // Create participant with TCP transport
//! let participant = ParticipantBuilder::new(0)
//!     .tcp_config(config)
//!     .transport_preference(TransportPreference::UdpDiscoveryTcpData)
//!     .build()?;
//! ```
//!
//! # Modules
//!
//! - `config` - Configuration types (`TcpConfig`, `TcpRole`, `TransportPreference`)
//! - `frame_codec` - Length-prefix framing codec
//! - `byte_stream` - Stream abstraction for TCP/TLS
//! - `locator` - TCP locator handling
//! - `connection` - TCP connection state machine (Phase 2)
//! - `connection_manager` - Connection pool management (Phase 2)
//! - `io_thread` - Non-blocking I/O event loop (Phase 3)
//! - `transport` - High-level transport interface (Phase 4)
//! - `metrics` - Transport metrics (Phase 5)
//! - `tls` - TLS encryption support (Phase 6, requires `tcp-tls` feature)

// Phase 1: Foundations
pub mod byte_stream;
pub mod config;
pub mod frame_codec;
pub mod locator;

// Phase 2: Connection
pub mod connection;

// Phase 3: I/O
pub mod io_thread;

// Phase 4: Transport
pub mod connection_manager;
pub mod metrics;
pub mod transport;

// Phase 6: TLS
pub mod tls;

// ============================================================================
// Re-exports
// ============================================================================

// Config types
pub use config::{TcpConfig, TcpRole, TransportPreference};

// Frame codec
pub use frame_codec::{
    extract_frame, peek_frame_header, FrameCodec, ParseResult, DEFAULT_MAX_MESSAGE_SIZE,
    FRAME_HEADER_SIZE, MIN_RTPS_MESSAGE_SIZE,
};

// Byte stream
pub use byte_stream::{BoxedByteStream, ByteStream};

// Locator types
pub use locator::{
    filter_tcp_locators, is_tcp_locator_kind, is_udp_locator_kind, tcp_to_udp_kind,
    udp_to_tcp_kind, TcpLocator, LOCATOR_ADDRESS_LEN, LOCATOR_KIND_INVALID, LOCATOR_KIND_RESERVED,
    LOCATOR_KIND_SHM, LOCATOR_KIND_TCPV4, LOCATOR_KIND_TCPV6, LOCATOR_KIND_UDPV4,
    LOCATOR_KIND_UDPV6, LOCATOR_PORT_INVALID, LOCATOR_SIZE,
};

// Connection types (Phase 2)
pub use connection::{ConnectionState, FlushResult, TcpConnection, TcpConnectionStats};

// I/O thread (Phase 3)
pub use io_thread::{IoCommand, IoThread, IoThreadHandle, TcpEvent};

// Connection manager (Phase 4)
pub use connection_manager::{ConnectionManager, ConnectionManagerConfig, PendingConnection};

// Transport (Phase 4)
pub use transport::{TcpTransport, TcpTransportEvent};

// Metrics (Phase 5)
pub use metrics::{TcpConnectionMetrics, TcpTransportMetrics};

// TLS (Phase 6)
#[cfg(feature = "tcp-tls")]
pub use tls::{TlsAcceptor, TlsConnector, TlsStream};
pub use tls::{TlsConfig, TlsConfigBuilder, TlsError, TlsVersion};

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify key types are accessible
        let _ = TcpConfig::default();
        let _ = TcpRole::Auto;
        let _ = TransportPreference::UdpOnly;
        let _ = FrameCodec::new(1024);
        let _ = TcpLocator::invalid();
    }

    #[test]
    fn test_constants() {
        assert_eq!(FRAME_HEADER_SIZE, 4);
        assert_eq!(LOCATOR_SIZE, 24);
        assert_eq!(LOCATOR_KIND_TCPV4, 4);
        assert_eq!(LOCATOR_KIND_TCPV6, 8);
    }
}
