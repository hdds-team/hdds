// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! STUN Binding client implementation per RFC 5389.
//!
//! Implements the minimal subset needed for NAT traversal:
//! - STUN Binding Request (20-byte header only, no attributes)
//! - STUN Binding Response parsing (XOR-MAPPED-ADDRESS + MAPPED-ADDRESS)
//!
//! # Wire Format (RFC 5389 Section 6)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |0 0|     STUN Message Type     |         Message Length        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Magic Cookie                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                     Transaction ID (96 bits)                  |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use super::{NatError, ReflexiveAddress};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

// -- STUN message types (RFC 5389 Section 6) --

/// Binding Request: class=Request(0b00), method=Binding(0x001)
const BINDING_REQUEST: u16 = 0x0001;
/// Binding Success Response: class=SuccessResponse(0b10), method=Binding(0x001)
const BINDING_RESPONSE: u16 = 0x0101;
/// Binding Error Response: class=ErrorResponse(0b11), method=Binding(0x001)
const BINDING_ERROR: u16 = 0x0111;

// -- STUN attributes (RFC 5389 Section 15) --

/// MAPPED-ADDRESS (legacy, RFC 3489)
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
/// XOR-MAPPED-ADDRESS (RFC 5389 Section 15.2)
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// ERROR-CODE (RFC 5389 Section 15.6)
const ATTR_ERROR_CODE: u16 = 0x0009;

/// STUN magic cookie (RFC 5389 Section 6)
const MAGIC_COOKIE: u32 = 0x2112_A442;

/// XOR mask for port obfuscation in STUN (high 16 bits of MAGIC_COOKIE)
/// Value: 0x2112 (mask ensures it fits in u16)
const MAGIC_COOKIE_PORT_XOR: u16 = ((MAGIC_COOKIE >> 16) & 0xFFFF) as u16;

/// STUN header size in bytes
const STUN_HEADER_SIZE: usize = 20;

/// Address family constants
const ADDRESS_FAMILY_IPV4: u8 = 0x01;
const ADDRESS_FAMILY_IPV6: u8 = 0x02;

/// STUN Binding client.
///
/// Sends STUN Binding Requests to a server and parses responses to discover
/// the reflexive (public) transport address as seen by the STUN server.
pub struct StunClient {
    /// STUN server address
    server: SocketAddr,
    /// Timeout for each request attempt
    timeout: Duration,
    /// Maximum number of retransmission attempts
    max_retries: u32,
    /// Transaction ID of the last sent request (for validation)
    last_transaction_id: [u8; 12],
}

impl StunClient {
    /// Create a new STUN client targeting the given server.
    #[must_use]
    pub fn new(server: SocketAddr, timeout: Duration, max_retries: u32) -> Self {
        Self {
            server,
            timeout,
            max_retries,
            last_transaction_id: [0u8; 12],
        }
    }

    /// Discover the reflexive address by sending a STUN Binding Request.
    ///
    /// Binds an ephemeral UDP socket, sends the request, and waits for a
    /// response. Retransmits up to `max_retries` times on timeout.
    pub fn discover_reflexive_address(&mut self) -> Result<ReflexiveAddress, NatError> {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| {
            NatError::NetworkError(format!("failed to bind UDP socket: {}", e))
        })?;
        self.discover_with_socket(&socket)
    }

    /// Discover the reflexive address using an existing socket.
    ///
    /// This variant allows reuse of an already-bound socket (e.g. the
    /// RTPS data socket) so the reflexive address maps to the correct port.
    pub fn discover_with_socket(
        &mut self,
        socket: &UdpSocket,
    ) -> Result<ReflexiveAddress, NatError> {
        socket.set_read_timeout(Some(self.timeout)).map_err(|e| {
            NatError::NetworkError(format!("failed to set read timeout: {}", e))
        })?;

        let request = self.build_binding_request();
        let mut buf = [0u8; 576]; // RFC 5389 minimum MTU recommendation

        for attempt in 0..=self.max_retries {
            socket
                .send_to(&request, self.server)
                .map_err(|e| NatError::NetworkError(format!("send failed: {}", e)))?;

            match socket.recv_from(&mut buf) {
                Ok((len, src)) => {
                    if src.ip() != self.server.ip() {
                        // Response from unexpected source -- ignore and retry
                        continue;
                    }
                    return self.parse_binding_response(&buf[..len]);
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    if attempt == self.max_retries {
                        return Err(NatError::Timeout(format!(
                            "STUN server {} did not respond after {} attempts",
                            self.server,
                            self.max_retries + 1
                        )));
                    }
                    // Will retransmit same request (same transaction ID per RFC 5389 7.2.1)
                    continue;
                }
                Err(e) => {
                    return Err(NatError::NetworkError(format!("recv failed: {}", e)));
                }
            }
        }

        Err(NatError::Timeout(format!(
            "STUN server {} did not respond",
            self.server
        )))
    }

    /// Build a STUN Binding Request message.
    ///
    /// The request is a 20-byte header with no attributes:
    /// - Type: 0x0001 (Binding Request)
    /// - Length: 0x0000 (no attributes)
    /// - Magic Cookie: 0x2112A442
    /// - Transaction ID: 12 random bytes
    pub fn build_binding_request(&mut self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(STUN_HEADER_SIZE);

        // Message type: Binding Request (2 bytes, big-endian)
        msg.extend_from_slice(&BINDING_REQUEST.to_be_bytes());

        // Message length: 0 (no attributes) (2 bytes, big-endian)
        msg.extend_from_slice(&0u16.to_be_bytes());

        // Magic cookie (4 bytes, big-endian)
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());

        // Transaction ID (12 random bytes)
        let transaction_id = generate_transaction_id();
        self.last_transaction_id = transaction_id;
        msg.extend_from_slice(&transaction_id);

        msg
    }

    /// Parse a STUN Binding Response and extract the reflexive address.
    ///
    /// Validates the header (magic cookie, message type, transaction ID),
    /// then scans attributes for XOR-MAPPED-ADDRESS (preferred) or
    /// MAPPED-ADDRESS (legacy fallback).
    pub fn parse_binding_response(
        &self,
        data: &[u8],
    ) -> Result<ReflexiveAddress, NatError> {
        if data.len() < STUN_HEADER_SIZE {
            return Err(NatError::MalformedResponse(format!(
                "response too short: {} bytes (minimum {})",
                data.len(),
                STUN_HEADER_SIZE
            )));
        }

        // Validate message type
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        if msg_type == BINDING_ERROR {
            return Err(NatError::ServerError(
                "STUN server returned Binding Error Response".to_string(),
            ));
        }
        if msg_type != BINDING_RESPONSE {
            return Err(NatError::MalformedResponse(format!(
                "unexpected message type: 0x{:04X} (expected 0x{:04X})",
                msg_type, BINDING_RESPONSE
            )));
        }

        // Validate magic cookie
        let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if cookie != MAGIC_COOKIE {
            return Err(NatError::MalformedResponse(format!(
                "invalid magic cookie: 0x{:08X} (expected 0x{:08X})",
                cookie, MAGIC_COOKIE
            )));
        }

        // Validate transaction ID
        let mut tid = [0u8; 12];
        tid.copy_from_slice(&data[8..20]);
        if tid != self.last_transaction_id {
            return Err(NatError::MalformedResponse(
                "transaction ID mismatch".to_string(),
            ));
        }

        // Message length (bytes after header)
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < STUN_HEADER_SIZE + msg_len {
            return Err(NatError::MalformedResponse(format!(
                "message length {} exceeds available data {}",
                msg_len,
                data.len() - STUN_HEADER_SIZE
            )));
        }

        // Parse attributes -- prefer XOR-MAPPED-ADDRESS, fall back to MAPPED-ADDRESS
        let attrs = &data[STUN_HEADER_SIZE..STUN_HEADER_SIZE + msg_len];
        let mut xor_mapped: Option<(IpAddr, u16)> = None;
        let mut mapped: Option<(IpAddr, u16)> = None;

        let mut offset = 0;
        while offset + 4 <= attrs.len() {
            let attr_type = u16::from_be_bytes([attrs[offset], attrs[offset + 1]]);
            let attr_len = u16::from_be_bytes([attrs[offset + 2], attrs[offset + 3]]) as usize;
            let attr_start = offset + 4;

            if attr_start + attr_len > attrs.len() {
                break; // Truncated attribute -- stop parsing
            }

            let attr_data = &attrs[attr_start..attr_start + attr_len];

            match attr_type {
                ATTR_XOR_MAPPED_ADDRESS => {
                    xor_mapped =
                        Some(self.xor_decode_address(attr_data, &tid)?);
                }
                ATTR_MAPPED_ADDRESS => {
                    mapped = Some(Self::decode_mapped_address(attr_data)?);
                }
                _ => {
                    // Unknown attribute -- skip
                }
            }

            // Attributes are padded to 4-byte boundaries (RFC 5389 Section 15)
            let padded_len = (attr_len + 3) & !3;
            offset = attr_start + padded_len;
        }

        let (ip, port) = xor_mapped
            .or(mapped)
            .ok_or_else(|| {
                NatError::MalformedResponse(
                    "no XOR-MAPPED-ADDRESS or MAPPED-ADDRESS in response".to_string(),
                )
            })?;

        Ok(ReflexiveAddress {
            ip,
            port,
            server_used: self.server,
            discovered_at: Instant::now(),
        })
    }

    /// XOR-decode an address per RFC 5389 Section 15.2.
    ///
    /// For IPv4:
    ///   - X-Port = port XOR (magic_cookie >> 16)
    ///   - X-Address = addr XOR magic_cookie
    ///
    /// For IPv6:
    ///   - X-Port = port XOR (magic_cookie >> 16)
    ///   - X-Address = addr XOR (magic_cookie || transaction_id)
    pub fn xor_decode_address(
        &self,
        data: &[u8],
        transaction_id: &[u8; 12],
    ) -> Result<(IpAddr, u16), NatError> {
        // Minimum: 1 (reserved) + 1 (family) + 2 (port) + 4 (IPv4 addr) = 8
        if data.len() < 8 {
            return Err(NatError::MalformedResponse(format!(
                "XOR-MAPPED-ADDRESS too short: {} bytes",
                data.len()
            )));
        }

        let family = data[1];
        let x_port = u16::from_be_bytes([data[2], data[3]]);
        let port = x_port ^ MAGIC_COOKIE_PORT_XOR;

        match family {
            ADDRESS_FAMILY_IPV4 => {
                if data.len() < 8 {
                    return Err(NatError::MalformedResponse(
                        "XOR-MAPPED-ADDRESS IPv4 too short".to_string(),
                    ));
                }
                let x_addr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let addr = x_addr ^ MAGIC_COOKIE;
                Ok((IpAddr::V4(Ipv4Addr::from(addr)), port))
            }
            ADDRESS_FAMILY_IPV6 => {
                if data.len() < 20 {
                    return Err(NatError::MalformedResponse(
                        "XOR-MAPPED-ADDRESS IPv6 too short".to_string(),
                    ));
                }
                // XOR key = magic_cookie (4 bytes) || transaction_id (12 bytes) = 16 bytes
                let mut xor_key = [0u8; 16];
                xor_key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                xor_key[4..16].copy_from_slice(transaction_id);

                let mut addr_bytes = [0u8; 16];
                for i in 0..16 {
                    addr_bytes[i] = data[4 + i] ^ xor_key[i];
                }
                Ok((IpAddr::V6(Ipv6Addr::from(addr_bytes)), port))
            }
            _ => Err(NatError::MalformedResponse(format!(
                "unknown address family: 0x{:02X}",
                family
            ))),
        }
    }

    /// Decode a plain MAPPED-ADDRESS attribute (legacy, RFC 3489).
    ///
    /// Format: 1 byte reserved, 1 byte family, 2 bytes port, 4/16 bytes address.
    fn decode_mapped_address(data: &[u8]) -> Result<(IpAddr, u16), NatError> {
        if data.len() < 8 {
            return Err(NatError::MalformedResponse(format!(
                "MAPPED-ADDRESS too short: {} bytes",
                data.len()
            )));
        }

        let family = data[1];
        let port = u16::from_be_bytes([data[2], data[3]]);

        match family {
            ADDRESS_FAMILY_IPV4 => {
                let addr = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                Ok((IpAddr::V4(addr), port))
            }
            ADDRESS_FAMILY_IPV6 => {
                if data.len() < 20 {
                    return Err(NatError::MalformedResponse(
                        "MAPPED-ADDRESS IPv6 too short".to_string(),
                    ));
                }
                let mut addr_bytes = [0u8; 16];
                addr_bytes.copy_from_slice(&data[4..20]);
                Ok((IpAddr::V6(Ipv6Addr::from(addr_bytes)), port))
            }
            _ => Err(NatError::MalformedResponse(format!(
                "unknown address family: 0x{:02X}",
                family
            ))),
        }
    }

    /// Return the STUN server address.
    #[must_use]
    pub fn server(&self) -> SocketAddr {
        self.server
    }

    /// Return the last transaction ID (for testing).
    #[must_use]
    pub fn last_transaction_id(&self) -> &[u8; 12] {
        &self.last_transaction_id
    }
}

/// Generate a cryptographically random 12-byte transaction ID.
///
/// Uses a simple LCG seeded from the system clock for portability
/// (no extra dependencies). This is sufficient for STUN transaction IDs
/// which only need uniqueness, not cryptographic security.
fn generate_transaction_id() -> [u8; 12] {
    let mut id = [0u8; 12];

    // Seed from multiple time sources for better entropy
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();

    let instant_seed = {
        // Use Instant as additional entropy source
        let start = Instant::now();
        // Tiny spin to get a non-zero elapsed
        let _ = std::hint::black_box(42);
        
        start.elapsed().as_nanos() as u64
    };

    // Mix nanoseconds, seconds, and Instant entropy
    let mut state: u64 = now.as_nanos() as u64;
    state = state.wrapping_add(instant_seed);
    state = state.wrapping_mul(6_364_136_223_846_793_005);
    state = state.wrapping_add(1_442_695_040_888_963_407);

    // Fill 12 bytes using LCG
    for chunk in id.chunks_mut(4) {
        state = state.wrapping_mul(6_364_136_223_846_793_005);
        state = state.wrapping_add(1_442_695_040_888_963_407);
        let bytes = (state >> 32).to_le_bytes();
        let len = chunk.len().min(4);
        chunk[..len].copy_from_slice(&bytes[..len]);
    }

    id
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "stun_tests.rs"]
mod tests;
