// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! QUIC transport configuration.

use std::net::SocketAddr;
use std::time::Duration;

/// QUIC transport configuration.
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// Local address to bind to (default: 0.0.0.0:0 for auto-assign).
    pub bind_addr: SocketAddr,

    /// Server name for TLS SNI (default: "hdds.local").
    pub server_name: String,

    /// Enable 0-RTT for faster reconnection (default: true).
    ///
    /// **Security note**: 0-RTT data can be replayed. Only enable if your
    /// application can handle duplicate messages.
    pub enable_0rtt: bool,

    /// Keep-alive interval to maintain NAT bindings (default: 15s).
    pub keep_alive_interval: Duration,

    /// Connection idle timeout (default: 30s).
    pub idle_timeout: Duration,

    /// Maximum concurrent streams per connection (default: 100).
    pub max_concurrent_streams: u32,

    /// Maximum receive window size (default: 1MB).
    pub max_recv_window: u64,

    /// Enable connection migration (default: true).
    ///
    /// Allows connections to survive IP address changes (WiFi roaming,
    /// mobile networks, etc.).
    pub enable_migration: bool,

    /// Custom certificate for server identity (PEM format).
    ///
    /// If None, a self-signed certificate is generated.
    pub certificate_pem: Option<String>,

    /// Custom private key (PEM format).
    pub private_key_pem: Option<String>,

    /// Skip certificate verification (for testing only).
    ///
    /// **WARNING**: Never use in production!
    pub dangerous_skip_verify: bool,

    // -------------------------------------------------------------------------
    // Reconnection settings (v234-sprint5)
    // -------------------------------------------------------------------------
    /// Enable automatic reconnection when connections drop (default: true).
    ///
    /// v234-sprint5: When enabled, dropped connections are automatically
    /// re-established with exponential backoff.
    pub reconnect_enabled: bool,

    /// Maximum reconnection attempts before giving up.
    ///
    /// - `None` = infinite retry (default)
    /// - `Some(n)` = give up after n failed attempts
    pub reconnect_max_attempts: Option<u32>,

    /// Base delay for reconnection backoff (default: 1 second).
    ///
    /// The actual delay doubles after each failed attempt.
    pub reconnect_base_delay: Duration,

    /// Maximum delay cap for reconnection backoff (default: 60 seconds).
    ///
    /// Backoff will never exceed this value.
    pub reconnect_max_delay: Duration,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            #[allow(clippy::unwrap_used)] // constant valid socket address literal
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            server_name: "hdds.local".to_string(),
            enable_0rtt: true,
            keep_alive_interval: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(30),
            max_concurrent_streams: 100,
            max_recv_window: 1024 * 1024, // 1MB
            enable_migration: true,
            certificate_pem: None,
            private_key_pem: None,
            dangerous_skip_verify: false,
            // v234-sprint5 reconnection defaults
            reconnect_enabled: true,
            reconnect_max_attempts: None, // infinite retry
            reconnect_base_delay: Duration::from_secs(1),
            reconnect_max_delay: Duration::from_secs(60),
        }
    }
}

impl QuicConfig {
    /// Create a new configuration builder.
    pub fn builder() -> QuicConfigBuilder {
        QuicConfigBuilder::default()
    }
}

/// Builder for QUIC configuration.
#[derive(Debug, Default)]
pub struct QuicConfigBuilder {
    config: QuicConfig,
}

impl QuicConfigBuilder {
    /// Set the local bind address.
    pub fn bind_addr(mut self, addr: SocketAddr) -> Self {
        self.config.bind_addr = addr;
        self
    }

    /// Set the server name for TLS SNI.
    pub fn server_name(mut self, name: impl Into<String>) -> Self {
        self.config.server_name = name.into();
        self
    }

    /// Enable or disable 0-RTT.
    pub fn enable_0rtt(mut self, enable: bool) -> Self {
        self.config.enable_0rtt = enable;
        self
    }

    /// Set keep-alive interval.
    pub fn keep_alive_interval(mut self, interval: Duration) -> Self {
        self.config.keep_alive_interval = interval;
        self
    }

    /// Set idle timeout.
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.config.idle_timeout = timeout;
        self
    }

    /// Set maximum concurrent streams.
    pub fn max_concurrent_streams(mut self, max: u32) -> Self {
        self.config.max_concurrent_streams = max;
        self
    }

    /// Enable or disable connection migration.
    pub fn enable_migration(mut self, enable: bool) -> Self {
        self.config.enable_migration = enable;
        self
    }

    /// Set custom TLS certificate (PEM format).
    pub fn certificate(mut self, cert_pem: impl Into<String>) -> Self {
        self.config.certificate_pem = Some(cert_pem.into());
        self
    }

    /// Set custom private key (PEM format).
    pub fn private_key(mut self, key_pem: impl Into<String>) -> Self {
        self.config.private_key_pem = Some(key_pem.into());
        self
    }

    /// Skip certificate verification (testing only).
    ///
    /// # Warning
    ///
    /// This completely disables TLS security. Only use for local testing.
    pub fn dangerous_skip_verify(mut self) -> Self {
        self.config.dangerous_skip_verify = true;
        self
    }

    // -------------------------------------------------------------------------
    // Reconnection settings (v234-sprint5)
    // -------------------------------------------------------------------------

    /// Enable or disable automatic reconnection (default: enabled).
    ///
    /// v234-sprint5: When disabled, dropped connections stay dropped.
    pub fn reconnect_enabled(mut self, enable: bool) -> Self {
        self.config.reconnect_enabled = enable;
        self
    }

    /// Set maximum reconnection attempts.
    ///
    /// - `None` = infinite retry (default)
    /// - `Some(n)` = give up after n failed attempts
    pub fn reconnect_max_attempts(mut self, max: Option<u32>) -> Self {
        self.config.reconnect_max_attempts = max;
        self
    }

    /// Set base delay for exponential backoff (default: 1 second).
    pub fn reconnect_base_delay(mut self, delay: Duration) -> Self {
        self.config.reconnect_base_delay = delay;
        self
    }

    /// Set maximum delay cap for backoff (default: 60 seconds).
    pub fn reconnect_max_delay(mut self, delay: Duration) -> Self {
        self.config.reconnect_max_delay = delay;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> QuicConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = QuicConfig::default();
        assert_eq!(config.server_name, "hdds.local");
        assert!(config.enable_0rtt);
        assert!(config.enable_migration);
        assert!(!config.dangerous_skip_verify);
    }

    #[test]
    fn test_builder() {
        let config = QuicConfig::builder()
            .bind_addr("127.0.0.1:7400".parse().unwrap())
            .server_name("test.local")
            .enable_0rtt(false)
            .idle_timeout(Duration::from_secs(60))
            .build();

        assert_eq!(config.bind_addr.port(), 7400);
        assert_eq!(config.server_name, "test.local");
        assert!(!config.enable_0rtt);
        assert_eq!(config.idle_timeout, Duration::from_secs(60));
    }

    // v234-sprint5 tests
    #[test]
    fn test_reconnect_defaults() {
        let config = QuicConfig::default();
        assert!(config.reconnect_enabled);
        assert!(config.reconnect_max_attempts.is_none());
        assert_eq!(config.reconnect_base_delay, Duration::from_secs(1));
        assert_eq!(config.reconnect_max_delay, Duration::from_secs(60));
    }

    #[test]
    fn test_reconnect_builder() {
        let config = QuicConfig::builder()
            .reconnect_enabled(false)
            .reconnect_max_attempts(Some(5))
            .reconnect_base_delay(Duration::from_millis(500))
            .reconnect_max_delay(Duration::from_secs(30))
            .build();

        assert!(!config.reconnect_enabled);
        assert_eq!(config.reconnect_max_attempts, Some(5));
        assert_eq!(config.reconnect_base_delay, Duration::from_millis(500));
        assert_eq!(config.reconnect_max_delay, Duration::from_secs(30));
    }
}
