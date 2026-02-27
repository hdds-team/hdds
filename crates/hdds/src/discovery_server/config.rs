// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Discovery Server client configuration.

use std::net::SocketAddr;
use std::time::Duration;

/// Configuration for connecting to a Discovery Server.
#[derive(Debug, Clone)]
pub struct DiscoveryServerConfig {
    /// Discovery server address (host:port).
    pub server_address: SocketAddr,

    /// Connection timeout.
    pub connect_timeout: Duration,

    /// Reconnect delay after disconnection.
    pub reconnect_delay: Duration,

    /// Maximum reconnection attempts (0 = infinite).
    pub max_reconnect_attempts: u32,

    /// Heartbeat interval (to keep lease alive).
    pub heartbeat_interval: Duration,

    /// Enable automatic reconnection on disconnect.
    pub auto_reconnect: bool,

    /// Maximum message size.
    pub max_message_size: usize,

    /// Disable multicast discovery when using server.
    pub disable_multicast: bool,
}

impl Default for DiscoveryServerConfig {
    fn default() -> Self {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        Self {
            server_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 7400),
            connect_timeout: Duration::from_secs(5),
            reconnect_delay: Duration::from_secs(1),
            max_reconnect_attempts: 10,
            heartbeat_interval: Duration::from_secs(10),
            auto_reconnect: true,
            max_message_size: 16 * 1024 * 1024,
            disable_multicast: true,
        }
    }
}

impl DiscoveryServerConfig {
    /// Create a new configuration with the given server address.
    pub fn new(server_address: SocketAddr) -> Self {
        Self {
            server_address,
            ..Default::default()
        }
    }

    /// Builder: set connection timeout.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Builder: set reconnect delay.
    pub fn with_reconnect_delay(mut self, delay: Duration) -> Self {
        self.reconnect_delay = delay;
        self
    }

    /// Builder: set max reconnect attempts.
    pub fn with_max_reconnect_attempts(mut self, attempts: u32) -> Self {
        self.max_reconnect_attempts = attempts;
        self
    }

    /// Builder: set heartbeat interval.
    pub fn with_heartbeat_interval(mut self, interval: Duration) -> Self {
        self.heartbeat_interval = interval;
        self
    }

    /// Builder: disable auto reconnect.
    pub fn without_auto_reconnect(mut self) -> Self {
        self.auto_reconnect = false;
        self
    }

    /// Builder: keep multicast enabled (hybrid mode).
    pub fn with_multicast_enabled(mut self) -> Self {
        self.disable_multicast = false;
        self
    }

    /// Validate configuration.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.connect_timeout.is_zero() {
            return Err("connect_timeout must be > 0");
        }
        if self.heartbeat_interval.is_zero() {
            return Err("heartbeat_interval must be > 0");
        }
        if self.max_message_size == 0 {
            return Err("max_message_size must be > 0");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DiscoveryServerConfig::default();
        assert_eq!(config.server_address.port(), 7400);
        assert!(config.auto_reconnect);
        assert!(config.disable_multicast);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_new_with_address() {
        let addr: SocketAddr = "192.168.1.100:7410".parse().unwrap();
        let config = DiscoveryServerConfig::new(addr);
        assert_eq!(config.server_address, addr);
    }

    #[test]
    fn test_builder_methods() {
        let config = DiscoveryServerConfig::default()
            .with_connect_timeout(Duration::from_secs(10))
            .with_heartbeat_interval(Duration::from_secs(5))
            .with_max_reconnect_attempts(20)
            .without_auto_reconnect()
            .with_multicast_enabled();

        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.heartbeat_interval, Duration::from_secs(5));
        assert_eq!(config.max_reconnect_attempts, 20);
        assert!(!config.auto_reconnect);
        assert!(!config.disable_multicast);
    }

    #[test]
    fn test_validation_errors() {
        let mut config = DiscoveryServerConfig {
            connect_timeout: Duration::ZERO,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        config.connect_timeout = Duration::from_secs(5);
        config.heartbeat_interval = Duration::ZERO;
        assert!(config.validate().is_err());

        config.heartbeat_interval = Duration::from_secs(10);
        config.max_message_size = 0;
        assert!(config.validate().is_err());
    }
}
