// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Null TSN backend for unsupported platforms.

use std::io;
use std::net::{SocketAddr, UdpSocket};

use super::backend::{TsnBackend, TsnErrorStats};
use super::config::TsnConfig;
use super::probe::{SupportLevel, TsnCapabilities};

/// Stub TSN backend for platforms without TSN support.
///
/// All operations return `Unsupported` errors or no-op.
/// This allows HDDS to compile on all platforms while gracefully
/// degrading TSN features.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullTsnBackend;

impl TsnBackend for NullTsnBackend {
    fn apply_socket_opts(&self, _sock: &UdpSocket, cfg: &TsnConfig) -> io::Result<()> {
        if cfg.enabled {
            // Log that TSN is requested but not available
            // In production, this increments a metric counter
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TSN not supported on this platform",
            ))
        } else {
            Ok(())
        }
    }

    fn send_with_txtime(
        &self,
        sock: &UdpSocket,
        buf: &[u8],
        addr: SocketAddr,
        txtime: Option<u64>,
        _cfg: &TsnConfig,
    ) -> io::Result<usize> {
        if txtime.is_some() {
            // txtime requested but not supported - fall back to regular send
            // Caller should check supports_txtime() first
        }
        sock.send_to(buf, addr)
    }

    fn probe(&self, _iface: &str) -> io::Result<TsnCapabilities> {
        Ok(TsnCapabilities {
            so_txtime: SupportLevel::Unsupported,
            etf_configured: false,
            taprio_configured: false,
            mqprio_configured: false,
            cbs_configured: false,
            hw_timestamping: SupportLevel::Unsupported,
            phc_device: None,
            kernel_version: None,
            notes: vec!["TSN not supported on this platform".to_string()],
        })
    }

    fn drain_error_queue(&self, _sock: &UdpSocket) -> TsnErrorStats {
        TsnErrorStats::default()
    }

    fn supports_txtime(&self) -> bool {
        false
    }

    fn clock_gettime(&self, _cfg: &TsnConfig) -> io::Result<u64> {
        // Return system time as nanoseconds (best effort)
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?;
        Ok(now.as_nanos() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_backend_probe() {
        let backend = NullTsnBackend;
        let caps = backend.probe("eth0").expect("probe should succeed");
        assert_eq!(caps.so_txtime, SupportLevel::Unsupported);
        assert!(!caps.etf_configured);
        assert!(!caps.notes.is_empty());
    }

    #[test]
    fn test_null_backend_supports_txtime() {
        let backend = NullTsnBackend;
        assert!(!backend.supports_txtime());
    }

    #[test]
    fn test_null_backend_drain_error_queue() {
        let backend = NullTsnBackend;
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind should succeed");
        let stats = backend.drain_error_queue(&sock);
        assert_eq!(stats.total_dropped(), 0);
    }

    #[test]
    fn test_null_backend_clock_gettime() {
        let backend = NullTsnBackend;
        let cfg = TsnConfig::default();
        let time = backend
            .clock_gettime(&cfg)
            .expect("clock_gettime should succeed");
        assert!(time > 0);
    }

    #[test]
    fn test_null_backend_apply_opts_disabled() {
        let backend = NullTsnBackend;
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind should succeed");
        let cfg = TsnConfig::default(); // enabled = false
        assert!(backend.apply_socket_opts(&sock, &cfg).is_ok());
    }

    #[test]
    fn test_null_backend_apply_opts_enabled() {
        let backend = NullTsnBackend;
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind should succeed");
        let cfg = TsnConfig::new().with_priority(6); // enabled = true
        let result = backend.apply_socket_opts(&sock, &cfg);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn test_null_backend_send_fallback() {
        let backend = NullTsnBackend;
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind should succeed");
        let cfg = TsnConfig::default();

        // Should not error, just use regular send
        let result = backend.send_with_txtime(
            &sock,
            b"test",
            "127.0.0.1:9999".parse().expect("valid addr"),
            Some(1_000_000), // txtime ignored
            &cfg,
        );
        // May fail due to no listener, but should not panic
        let _ = result;
    }
}
