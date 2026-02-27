// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Kubernetes DNS-Based Discovery
//!
//! Zero-dependency Kubernetes discovery using standard DNS resolution.
//! Works with Kubernetes Headless Services to discover DDS participants.
//!
//! # How It Works
//!
//! 1. Query DNS for headless service: `{service}.{namespace}.svc.cluster.local`
//! 2. Get list of pod IPs (A/AAAA records)
//! 3. Each pod IP + DDS port = potential DDS participant
//! 4. Register discovered peers with DiscoveryFsm
//!
//! # Kubernetes Setup
//!
//! ```yaml
//! apiVersion: v1
//! kind: Service
//! metadata:
//!   name: hdds-discovery
//!   namespace: default
//! spec:
//!   clusterIP: None  # Headless service
//!   selector:
//!     app: my-dds-app
//!   ports:
//!   - name: dds-user
//!     port: 7411
//!     protocol: UDP
//! ```
//!
//! # Example
//!
//! ```ignore
//! use hdds::{Participant, TransportMode};
//!
//! let participant = Participant::builder("my-app")
//!     .with_transport(TransportMode::UdpMulticast)
//!     .with_k8s_discovery("hdds-discovery", "default")
//!     .build()?;
//! ```
//!
//! # Environment Variables
//!
//! - `HDDS_K8S_SERVICE`: Service name (default: "hdds-discovery")
//! - `HDDS_K8S_NAMESPACE`: Namespace (default: "default")
//! - `HDDS_K8S_PORT`: DDS port (default: 7411)
//! - `HDDS_K8S_POLL_INTERVAL_MS`: Poll interval (default: 5000)

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

/// Configuration for Kubernetes DNS discovery.
#[derive(Debug, Clone)]
pub struct K8sDiscoveryConfig {
    /// Kubernetes service name (headless service)
    pub service_name: String,

    /// Kubernetes namespace
    pub namespace: String,

    /// DDS port to use for discovered peers
    pub dds_port: u16,

    /// DNS poll interval
    pub poll_interval: Duration,

    /// Cluster domain suffix (usually "cluster.local")
    pub cluster_domain: String,
}

impl Default for K8sDiscoveryConfig {
    fn default() -> Self {
        Self {
            service_name: std::env::var("HDDS_K8S_SERVICE")
                .unwrap_or_else(|_| "hdds-discovery".to_string()),
            namespace: std::env::var("HDDS_K8S_NAMESPACE")
                .unwrap_or_else(|_| "default".to_string()),
            dds_port: std::env::var("HDDS_K8S_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(7411),
            poll_interval: Duration::from_millis(
                std::env::var("HDDS_K8S_POLL_INTERVAL_MS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(5000),
            ),
            cluster_domain: "cluster.local".to_string(),
        }
    }
}

impl K8sDiscoveryConfig {
    /// Create a new config with service and namespace.
    pub fn new(service_name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            namespace: namespace.into(),
            ..Default::default()
        }
    }

    /// Set the DDS port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.dds_port = port;
        self
    }

    /// Set the poll interval.
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Get the full DNS name for the headless service.
    pub fn dns_name(&self) -> String {
        format!(
            "{}.{}.svc.{}",
            self.service_name, self.namespace, self.cluster_domain
        )
    }
}

/// Kubernetes DNS discovery handler.
///
/// Periodically resolves a Kubernetes headless service DNS name
/// and registers discovered peers with the DDS discovery system.
pub struct K8sDiscovery {
    config: K8sDiscoveryConfig,
    discovered_peers: Arc<RwLock<HashSet<SocketAddr>>>,
    running: Arc<AtomicBool>,
    /// Callback to register discovered peers
    on_peer_discovered: Option<Arc<dyn Fn(SocketAddr) + Send + Sync>>,
}

impl K8sDiscovery {
    /// Create a new K8s discovery handler.
    pub fn new(config: K8sDiscoveryConfig) -> Self {
        Self {
            config,
            discovered_peers: Arc::new(RwLock::new(HashSet::new())),
            running: Arc::new(AtomicBool::new(false)),
            on_peer_discovered: None,
        }
    }

    /// Create with service name and namespace.
    pub fn with_service(service_name: &str, namespace: &str) -> Self {
        Self::new(K8sDiscoveryConfig::new(service_name, namespace))
    }

    /// Set the callback for when a peer is discovered.
    pub fn on_peer_discovered<F>(mut self, callback: F) -> Self
    where
        F: Fn(SocketAddr) + Send + Sync + 'static,
    {
        self.on_peer_discovered = Some(Arc::new(callback));
        self
    }

    /// Resolve the DNS name and return discovered IPs.
    pub fn resolve_peers(&self) -> Vec<SocketAddr> {
        let dns_name = self.config.dns_name();
        let port = self.config.dds_port;

        // Use std::net DNS resolution
        let lookup = format!("{}:{}", dns_name, port);

        match lookup.to_socket_addrs() {
            Ok(addrs) => {
                let peers: Vec<SocketAddr> = addrs.collect();
                log::debug!(
                    "[K8s-Discovery] Resolved {} -> {} peers",
                    dns_name,
                    peers.len()
                );
                for peer in &peers {
                    log::trace!("[K8s-Discovery] Found peer: {}", peer);
                }
                peers
            }
            Err(e) => {
                log::debug!(
                    "[K8s-Discovery] DNS resolution failed for '{}': {}",
                    dns_name,
                    e
                );
                Vec::new()
            }
        }
    }

    /// Perform one discovery cycle.
    ///
    /// Returns newly discovered peers (not seen before).
    pub fn discover_once(&self) -> Vec<SocketAddr> {
        let current_peers: HashSet<SocketAddr> = self.resolve_peers().into_iter().collect();
        let mut new_peers = Vec::new();

        if let Ok(mut known) = self.discovered_peers.write() {
            for peer in &current_peers {
                if !known.contains(peer) {
                    new_peers.push(*peer);
                    known.insert(*peer);

                    // Notify callback
                    if let Some(ref callback) = self.on_peer_discovered {
                        callback(*peer);
                    }
                }
            }

            // Note: We don't remove peers that disappeared from DNS
            // Let the DDS lease mechanism handle peer removal
        }

        if !new_peers.is_empty() {
            log::info!(
                "[K8s-Discovery] Discovered {} new peers from {}",
                new_peers.len(),
                self.config.dns_name()
            );
        }

        new_peers
    }

    /// Get all currently known peers.
    pub fn known_peers(&self) -> Vec<SocketAddr> {
        self.discovered_peers
            .read()
            .map(|p| p.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Check if discovery is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Start the background discovery thread.
    ///
    /// Returns a handle that can be used to stop the thread.
    pub fn start(&self) -> K8sDiscoveryHandle {
        self.running.store(true, Ordering::SeqCst);

        let config = self.config.clone();
        let discovered = Arc::clone(&self.discovered_peers);
        let running = Arc::clone(&self.running);
        let callback = self.on_peer_discovered.clone();

        #[allow(clippy::expect_used)] // thread spawn failure is unrecoverable
        let handle = thread::Builder::new()
            .name("hdds-k8s-discovery".to_string())
            .spawn(move || {
                log::info!(
                    "[K8s-Discovery] Started polling {} every {:?}",
                    config.dns_name(),
                    config.poll_interval
                );

                while running.load(Ordering::SeqCst) {
                    // Resolve DNS
                    let dns_name = config.dns_name();
                    let lookup = format!("{}:{}", dns_name, config.dds_port);

                    if let Ok(addrs) = lookup.to_socket_addrs() {
                        let current: HashSet<SocketAddr> = addrs.collect();

                        if let Ok(mut known) = discovered.write() {
                            for peer in &current {
                                if !known.contains(peer) {
                                    log::info!("[K8s-Discovery] New peer: {}", peer);
                                    known.insert(*peer);

                                    if let Some(ref cb) = callback {
                                        cb(*peer);
                                    }
                                }
                            }
                        }
                    }

                    thread::sleep(config.poll_interval);
                }

                log::info!("[K8s-Discovery] Stopped");
            })
            .expect("Failed to spawn K8s discovery thread");

        K8sDiscoveryHandle {
            running: Arc::clone(&self.running),
            thread: Some(handle),
        }
    }
}

/// Handle to control the K8s discovery background thread.
pub struct K8sDiscoveryHandle {
    running: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl K8sDiscoveryHandle {
    /// Stop the discovery thread.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for K8sDiscoveryHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Resolve a Kubernetes service to socket addresses.
///
/// This is a convenience function for one-shot DNS resolution.
///
/// # Arguments
///
/// * `service` - Service name
/// * `namespace` - Kubernetes namespace
/// * `port` - Port number
///
/// # Returns
///
/// List of resolved socket addresses.
pub fn resolve_k8s_service(service: &str, namespace: &str, port: u16) -> Vec<SocketAddr> {
    let dns_name = format!("{}.{}.svc.cluster.local:{}", service, namespace, port);

    match dns_name.to_socket_addrs() {
        Ok(addrs) => addrs.collect(),
        Err(e) => {
            log::debug!("[K8s-Discovery] Failed to resolve '{}': {}", dns_name, e);
            Vec::new()
        }
    }
}

/// Get the local pod IP from Kubernetes downward API.
///
/// Reads from `HDDS_POD_IP` environment variable (set via fieldRef).
pub fn get_pod_ip() -> Option<IpAddr> {
    std::env::var("HDDS_POD_IP")
        .ok()
        .and_then(|s| s.parse().ok())
}

/// Get the local pod name from Kubernetes downward API.
pub fn get_pod_name() -> Option<String> {
    std::env::var("HDDS_POD_NAME").ok()
}

/// Get the namespace from Kubernetes downward API.
pub fn get_namespace() -> Option<String> {
    std::env::var("HDDS_K8S_NAMESPACE").ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = K8sDiscoveryConfig::default();
        assert_eq!(config.service_name, "hdds-discovery");
        assert_eq!(config.namespace, "default");
        assert_eq!(config.dds_port, 7411);
    }

    #[test]
    fn test_config_new() {
        let config = K8sDiscoveryConfig::new("my-service", "my-namespace");
        assert_eq!(config.service_name, "my-service");
        assert_eq!(config.namespace, "my-namespace");
    }

    #[test]
    fn test_config_dns_name() {
        let config = K8sDiscoveryConfig::new("hdds", "production");
        assert_eq!(config.dns_name(), "hdds.production.svc.cluster.local");
    }

    #[test]
    fn test_config_builder() {
        let config = K8sDiscoveryConfig::new("svc", "ns")
            .with_port(8080)
            .with_poll_interval(Duration::from_secs(10));

        assert_eq!(config.dds_port, 8080);
        assert_eq!(config.poll_interval, Duration::from_secs(10));
    }

    #[test]
    fn test_discovery_creation() {
        let discovery = K8sDiscovery::with_service("test-svc", "test-ns");
        assert_eq!(discovery.config.service_name, "test-svc");
        assert_eq!(discovery.config.namespace, "test-ns");
        assert!(!discovery.is_running());
    }

    #[test]
    fn test_discovery_resolve_nonexistent() {
        // This will fail DNS resolution (expected in non-K8s environment)
        let discovery = K8sDiscovery::with_service("nonexistent", "default");
        let peers = discovery.resolve_peers();
        // Should return empty, not panic
        assert!(peers.is_empty());
    }

    #[test]
    fn test_known_peers_initially_empty() {
        let discovery = K8sDiscovery::with_service("test", "default");
        assert!(discovery.known_peers().is_empty());
    }

    #[test]
    fn test_resolve_k8s_service_nonexistent() {
        let addrs = resolve_k8s_service("nonexistent-service", "default", 7411);
        assert!(addrs.is_empty());
    }

    #[test]
    fn test_pod_ip_not_set() {
        // In test environment, these won't be set
        // Just verify they don't panic
        let _ = get_pod_ip();
        let _ = get_pod_name();
        let _ = get_namespace();
    }
}
