// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TX socket pool for TSN traffic classes.
//!
//! Different TSN configurations (priority, clock, txtime policy) require
//! separate sockets because SO_PRIORITY is per-socket, not per-packet.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, RwLock};

use super::backend::TsnBackend;
use super::config::{SocketProfile, TsnConfig};
use super::error_queue::ErrorQueueDrainer;
use super::metrics::TsnMetrics;

/// TX socket pool keyed by SocketProfile.
///
/// Creates sockets lazily on first use for each profile.
/// Sockets are configured with appropriate SO_PRIORITY and SO_TXTIME.
pub struct TxSocketPool {
    /// The bind address for new sockets.
    bind_addr: SocketAddr,
    /// Pool of sockets by profile.
    sockets: RwLock<HashMap<SocketProfile, PooledSocket>>,
    /// TSN backend for socket configuration.
    backend: Arc<dyn TsnBackend>,
    /// Metrics.
    metrics: Arc<TsnMetrics>,
    /// Maximum pool size.
    max_size: usize,
}

/// A pooled socket with its configuration.
struct PooledSocket {
    socket: UdpSocket,
    config: TsnConfig,
    error_drainer: ErrorQueueDrainer,
    send_count: u64,
}

impl TxSocketPool {
    /// Create a new socket pool.
    pub fn new(
        bind_addr: SocketAddr,
        backend: Arc<dyn TsnBackend>,
        metrics: Arc<TsnMetrics>,
    ) -> Self {
        Self {
            bind_addr,
            sockets: RwLock::new(HashMap::new()),
            backend,
            metrics,
            max_size: 16, // Reasonable default
        }
    }

    /// Set maximum pool size.
    pub fn with_max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size;
        self
    }

    /// Get or create a socket for the given config.
    pub fn get_socket(&self, config: &TsnConfig) -> io::Result<PooledSocketGuard<'_>> {
        let profile = SocketProfile::from_config(config);

        // Try read lock first (fast path)
        {
            let sockets = self
                .sockets
                .read()
                .map_err(|_| io::Error::other("socket pool lock poisoned"))?;

            if sockets.contains_key(&profile) {
                return Ok(PooledSocketGuard {
                    pool: self,
                    profile,
                });
            }
        }

        // Need to create a new socket (slow path)
        self.create_socket(config, profile.clone())?;

        Ok(PooledSocketGuard {
            pool: self,
            profile,
        })
    }

    /// Create a new socket for the given profile.
    fn create_socket(&self, config: &TsnConfig, profile: SocketProfile) -> io::Result<()> {
        let mut sockets = self
            .sockets
            .write()
            .map_err(|_| io::Error::other("socket pool lock poisoned"))?;

        // Double-check after acquiring write lock
        if sockets.contains_key(&profile) {
            return Ok(());
        }

        // Check pool size limit
        if sockets.len() >= self.max_size {
            return Err(io::Error::other(format!(
                "socket pool full (max {} sockets)",
                self.max_size
            )));
        }

        // Create and configure socket
        let socket = UdpSocket::bind(self.bind_addr)?;
        self.backend.apply_socket_opts(&socket, config)?;

        let pooled = PooledSocket {
            socket,
            config: config.clone(),
            error_drainer: ErrorQueueDrainer::new(),
            send_count: 0,
        };

        sockets.insert(profile, pooled);
        self.metrics.record_priority_set();

        Ok(())
    }

    /// Send data using the appropriate socket.
    pub fn send_to(
        &self,
        config: &TsnConfig,
        buf: &[u8],
        addr: SocketAddr,
        txtime: Option<u64>,
    ) -> io::Result<usize> {
        let profile = SocketProfile::from_config(config);

        let mut sockets = self
            .sockets
            .write()
            .map_err(|_| io::Error::other("socket pool lock poisoned"))?;

        let pooled = sockets
            .get_mut(&profile)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "socket not found in pool"))?;

        // Drain error queue periodically
        if pooled.send_count % 100 == 0 {
            let stats = pooled.error_drainer.drain(&pooled.socket);
            if stats.dropped_late > 0 {
                self.metrics.record_dropped_late(stats.dropped_late);
            }
            if stats.dropped_other > 0 {
                self.metrics.record_dropped_other(stats.dropped_other);
            }
        }

        pooled.send_count += 1;

        // Send with or without txtime
        self.backend
            .send_with_txtime(&pooled.socket, buf, addr, txtime, config)
    }

    /// Get pool statistics.
    pub fn stats(&self) -> PoolStats {
        let sockets = self.sockets.read().ok();
        let socket_count = sockets.as_ref().map(|s| s.len()).unwrap_or(0);
        let total_sends = sockets
            .as_ref()
            .map(|s| s.values().map(|p| p.send_count).sum())
            .unwrap_or(0);

        PoolStats {
            socket_count,
            max_size: self.max_size,
            total_sends,
        }
    }

    /// Drain all error queues.
    pub fn drain_all_error_queues(&self) {
        if let Ok(mut sockets) = self.sockets.write() {
            for pooled in sockets.values_mut() {
                let stats = pooled.error_drainer.drain(&pooled.socket);
                if stats.dropped_late > 0 {
                    self.metrics.record_dropped_late(stats.dropped_late);
                }
                if stats.dropped_other > 0 {
                    self.metrics.record_dropped_other(stats.dropped_other);
                }
            }
        }
        self.metrics.record_error_queue_drain();
    }

    /// Clear the pool (close all sockets).
    pub fn clear(&self) {
        if let Ok(mut sockets) = self.sockets.write() {
            sockets.clear();
        }
    }
}

/// Guard for accessing a pooled socket.
pub struct PooledSocketGuard<'a> {
    pool: &'a TxSocketPool,
    profile: SocketProfile,
}

impl<'a> PooledSocketGuard<'a> {
    /// Send data through this socket.
    pub fn send_to(&self, buf: &[u8], addr: SocketAddr, txtime: Option<u64>) -> io::Result<usize> {
        let sockets = self
            .pool
            .sockets
            .read()
            .map_err(|_| io::Error::other("socket pool lock poisoned"))?;

        let pooled = sockets
            .get(&self.profile)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "socket removed from pool"))?;

        self.pool
            .backend
            .send_with_txtime(&pooled.socket, buf, addr, txtime, &pooled.config)
    }

    /// Get the socket profile.
    pub fn profile(&self) -> &SocketProfile {
        &self.profile
    }
}

/// Pool statistics.
#[derive(Clone, Debug, Default)]
pub struct PoolStats {
    /// Number of sockets in the pool.
    pub socket_count: usize,
    /// Maximum pool size.
    pub max_size: usize,
    /// Total sends across all sockets.
    pub total_sends: u64,
}

impl PoolStats {
    /// Check if pool is full.
    pub fn is_full(&self) -> bool {
        self.socket_count >= self.max_size
    }

    /// Get utilization ratio.
    pub fn utilization(&self) -> f64 {
        if self.max_size == 0 {
            0.0
        } else {
            self.socket_count as f64 / self.max_size as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::tsn::null::NullTsnBackend;

    fn test_pool() -> TxSocketPool {
        let backend = Arc::new(NullTsnBackend);
        let metrics = Arc::new(TsnMetrics::new());
        TxSocketPool::new("127.0.0.1:0".parse().expect("valid addr"), backend, metrics)
    }

    // Helper to create a config that works with NullTsnBackend (enabled=false)
    // Uses traffic_class to differentiate profiles since so_priority() returns None when disabled
    fn disabled_config_with_traffic_class(tc: u8) -> TsnConfig {
        TsnConfig {
            enabled: false, // NullTsnBackend accepts disabled configs
            traffic_class: Some(tc),
            ..Default::default()
        }
    }

    #[test]
    fn test_pool_new() {
        let pool = test_pool();
        let stats = pool.stats();
        assert_eq!(stats.socket_count, 0);
        assert_eq!(stats.max_size, 16);
    }

    #[test]
    fn test_pool_with_max_size() {
        let backend = Arc::new(NullTsnBackend);
        let metrics = Arc::new(TsnMetrics::new());
        let pool = TxSocketPool::new("127.0.0.1:0".parse().expect("valid addr"), backend, metrics)
            .with_max_size(4);

        assert_eq!(pool.stats().max_size, 4);
    }

    #[test]
    fn test_pool_get_socket_creates() {
        let pool = test_pool();
        let config = TsnConfig::default(); // enabled=false

        let _guard = pool.get_socket(&config).expect("should get socket");
        assert_eq!(pool.stats().socket_count, 1);
    }

    #[test]
    fn test_pool_get_socket_reuses() {
        let pool = test_pool();
        let config = TsnConfig::default();

        let _guard1 = pool.get_socket(&config).expect("should get socket");
        let _guard2 = pool.get_socket(&config).expect("should get socket");

        // Same config should reuse socket
        assert_eq!(pool.stats().socket_count, 1);
    }

    #[test]
    fn test_pool_different_configs() {
        let pool = test_pool();

        // Use disabled configs with different traffic classes for different profiles
        let config1 = disabled_config_with_traffic_class(0);
        let config2 = disabled_config_with_traffic_class(1);

        let _guard1 = pool.get_socket(&config1).expect("should get socket");
        let _guard2 = pool.get_socket(&config2).expect("should get socket");

        // Different traffic_class = different profiles = different sockets
        assert_eq!(pool.stats().socket_count, 2);
    }

    #[test]
    fn test_pool_max_size_limit() {
        let backend = Arc::new(NullTsnBackend);
        let metrics = Arc::new(TsnMetrics::new());
        let pool = TxSocketPool::new("127.0.0.1:0".parse().expect("valid addr"), backend, metrics)
            .with_max_size(2);

        let config1 = disabled_config_with_traffic_class(0);
        let config2 = disabled_config_with_traffic_class(1);
        let config3 = disabled_config_with_traffic_class(2);

        pool.get_socket(&config1).expect("should get socket 1");
        pool.get_socket(&config2).expect("should get socket 2");

        // Third should fail (pool full)
        let result = pool.get_socket(&config3);
        assert!(result.is_err());
    }

    #[test]
    fn test_pool_clear() {
        let pool = test_pool();
        let config = disabled_config_with_traffic_class(0);

        pool.get_socket(&config).expect("should get socket");
        assert_eq!(pool.stats().socket_count, 1);

        pool.clear();
        assert_eq!(pool.stats().socket_count, 0);
    }

    #[test]
    fn test_pool_stats_utilization() {
        let stats = PoolStats {
            socket_count: 4,
            max_size: 16,
            total_sends: 100,
        };

        assert!(!stats.is_full());
        assert!((stats.utilization() - 0.25).abs() < 0.001);
    }

    #[test]
    fn test_pool_stats_full() {
        let stats = PoolStats {
            socket_count: 16,
            max_size: 16,
            total_sends: 0,
        };

        assert!(stats.is_full());
        assert!((stats.utilization() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_pool_drain_all_error_queues() {
        let pool = test_pool();
        let config = disabled_config_with_traffic_class(0);

        pool.get_socket(&config).expect("should get socket");
        pool.drain_all_error_queues(); // Should not panic
    }

    #[test]
    fn test_pooled_socket_guard_profile() {
        let pool = test_pool();
        // Note: with enabled=false, so_priority() returns None
        let config = TsnConfig::default();

        let guard = pool.get_socket(&config).expect("should get socket");
        // Default config has enabled=false, so so_priority is None
        assert!(guard.profile().so_priority.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_pool_with_linux_backend() {
        use crate::transport::tsn::linux::LinuxTsnBackend;

        let backend = Arc::new(LinuxTsnBackend::new());
        let metrics = Arc::new(TsnMetrics::new());
        let pool = TxSocketPool::new("127.0.0.1:0".parse().expect("valid addr"), backend, metrics);

        // With Linux backend, enabled configs should work
        let config = TsnConfig::new().with_priority(5);
        let guard = pool.get_socket(&config).expect("should get socket");
        assert_eq!(guard.profile().so_priority, Some(5));
    }
}
