// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// Agent configuration with validation.

use crate::protocol::XrceError;

/// Configuration for the XRCE agent.
#[derive(Debug, Clone)]
pub struct XrceAgentConfig {
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
}

impl Default for XrceAgentConfig {
    fn default() -> Self {
        Self {
            udp_port: 2019,
            serial_device: None,
            serial_baud: 115200,
            tcp_port: None,
            max_clients: 128,
            session_timeout_ms: 30_000,
            heartbeat_period_ms: 200,
            max_message_size: 512,
        }
    }
}

impl XrceAgentConfig {
    /// Validate configuration. Returns Ok(()) if valid.
    pub fn validate(&self) -> Result<(), XrceError> {
        if self.max_clients == 0 {
            return Err(XrceError::ConfigError(
                "max_clients must be > 0".into(),
            ));
        }
        // session_id is u8 so max 255 clients
        if self.max_clients > 255 {
            return Err(XrceError::ConfigError(
                "max_clients must be <= 255 (session_id is u8)".into(),
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
            return Err(XrceError::ConfigError(
                "serial_baud must be > 0".into(),
            ));
        }
        Ok(())
    }
}
