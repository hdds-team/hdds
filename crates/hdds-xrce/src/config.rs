// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// Agent configuration with validation.

use std::net::{IpAddr, Ipv4Addr};

use crate::protocol::XrceError;

/// Configuration for the XRCE agent.
#[derive(Debug, Clone)]
pub struct XrceAgentConfig {
    /// Address the UDP and TCP listeners bind to.
    ///
    /// Defaults to loopback: an XRCE agent is an unauthenticated write path
    /// into a DDS domain, so it never listens on every interface unless the
    /// operator asks for it by name (`--bind`).
    pub bind_address: IpAddr,
    /// UDP listen port (default: 2019, the XRCE standard port).
    pub udp_port: u16,
    /// Optional serial device path (e.g. "/dev/ttyUSB0").
    pub serial_device: Option<String>,
    /// Serial baud rate (default: 115200).
    pub serial_baud: u32,
    /// Optional TCP listen port. If set, TCP transport is enabled.
    pub tcp_port: Option<u16>,
    /// Maximum concurrent clients (default: 128).
    pub max_clients: usize,
    /// Session timeout in milliseconds (default: 30000).
    pub session_timeout_ms: u64,
    /// Heartbeat period in milliseconds for reliable streams (default: 200).
    pub heartbeat_period_ms: u64,
    /// Maximum message size in bytes (default: 512, typical MCU limit).
    pub max_message_size: usize,
    /// Largest message the agent will reassemble from FRAGMENT submessages.
    pub max_reassembled_size: usize,
    /// ClientKeys allowed to open a session.
    ///
    /// DDS-XRCE 1.0 treats the ClientKey as a shared secret configured on both
    /// sides, so admission is a list, not a formality. An empty list with
    /// `open_admission == false` is a configuration error, not "allow all".
    pub accepted_client_keys: Vec<[u8; 4]>,
    /// Accept any ClientKey. Must be set explicitly (the `--open` flag on the
    /// binary); it is never the default.
    pub open_admission: bool,
}

impl Default for XrceAgentConfig {
    fn default() -> Self {
        Self {
            bind_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            udp_port: 2019,
            serial_device: None,
            serial_baud: 115200,
            tcp_port: None,
            max_clients: 128,
            session_timeout_ms: 30_000,
            heartbeat_period_ms: 200,
            max_message_size: 512,
            max_reassembled_size: 64 * 1024,
            accepted_client_keys: Vec::new(),
            open_admission: false,
        }
    }
}

impl XrceAgentConfig {
    /// True when `key` may open a session on this agent.
    pub fn accepts_client_key(&self, key: &[u8; 4]) -> bool {
        self.open_admission || self.accepted_client_keys.iter().any(|k| k == key)
    }

    /// Validate configuration. Returns Ok(()) if valid.
    pub fn validate(&self) -> Result<(), XrceError> {
        if self.max_clients == 0 {
            return Err(XrceError::ConfigError("max_clients must be > 0".into()));
        }
        // Session ids live in 0x80..=0xFF (the DDS-XRCE range that carries no
        // per-message ClientKey), so 128 slots exist.
        if self.max_clients > 128 {
            return Err(XrceError::ConfigError(
                "max_clients must be <= 128 (session ids use the 0x80..=0xFF range)".into(),
            ));
        }
        if self.session_timeout_ms == 0 {
            return Err(XrceError::ConfigError(
                "session_timeout_ms must be > 0".into(),
            ));
        }
        if self.heartbeat_period_ms == 0 {
            return Err(XrceError::ConfigError(
                "heartbeat_period_ms must be > 0".into(),
            ));
        }
        // Minimum message size must fit a message header + submessage header + minimal payload
        if self.max_message_size < 16 {
            return Err(XrceError::ConfigError(
                "max_message_size must be >= 16".into(),
            ));
        }
        if self.serial_baud == 0 {
            return Err(XrceError::ConfigError("serial_baud must be > 0".into()));
        }
        if self.max_reassembled_size < self.max_message_size {
            return Err(XrceError::ConfigError(
                "max_reassembled_size must be >= max_message_size".into(),
            ));
        }
        if self.accepted_client_keys.is_empty() && !self.open_admission {
            return Err(XrceError::ConfigError(
                "no accepted client keys configured; pass an explicit open admission flag to accept any client".into(),
            ));
        }
        Ok(())
    }
}
