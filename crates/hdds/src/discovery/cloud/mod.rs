// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Cloud Discovery for DDS
//!
//! Provides discovery mechanisms for cloud environments where UDP multicast
//! is not available (AWS, Azure, GCP, Kubernetes, etc.).
//!
//! # Supported Backends
//!
//! - **AWS Cloud Map** -- Service discovery for AWS ECS/EKS
//! - **Azure Service Discovery** -- Azure DNS-based discovery
//! - **Consul** -- HashiCorp Consul service mesh
//!
//! # Architecture
//!
//! ```text
//! CloudDiscovery Trait
//! +-- AwsCloudMap      (AWS Cloud Map + ECS metadata)
//! +-- AzureDiscovery   (Azure DNS + Service Bus)
//! +-- ConsulDiscovery  (Consul KV + Health checks)
//! ```
//!
//! # Example
//!
//! ```ignore
//! use hdds::discovery::cloud::{CloudDiscovery, ConsulDiscovery};
//!
//! let discovery = ConsulDiscovery::new("http://consul.service.consul:8500")?;
//! discovery.register_participant(participant_guid, &locators).await?;
//!
//! let peers = discovery.discover_participants().await?;
//! ```

pub mod aws;
pub mod azure;
pub mod consul;
pub mod poller_thread;

pub use aws::AwsCloudMap;
pub use azure::AzureDiscovery;
pub use consul::ConsulDiscovery;
pub use poller_thread::{
    CloudCommand, CloudDiscoveryPoller, CloudDiscoveryPollerHandle, CloudEvent, CloudPollerConfig,
    CloudProvider,
};

use crate::dds::Error;
use std::net::SocketAddr;

/// Locator structure (simplified for cloud discovery)
///
/// Represents a DDS RTPS locator (address + port).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Locator {
    /// Locator kind (1 = UDP, 2 = TCP, etc.)
    pub kind: i32,
    /// Port number
    pub port: u32,
    /// IPv4 or IPv6 address (16 bytes)
    pub address: [u8; 16],
}

/// Participant metadata for cloud discovery
#[derive(Debug, Clone)]
pub struct ParticipantInfo {
    /// Participant GUID
    pub guid: [u8; 16],

    /// Participant name
    pub name: String,

    /// Domain ID
    pub domain_id: u32,

    /// Unicast locators
    pub locators: Vec<Locator>,

    /// Custom metadata (key-value pairs)
    pub metadata: std::collections::HashMap<String, String>,
}

/// Cloud discovery trait
///
/// Backend-agnostic interface for service discovery in cloud environments.
pub trait CloudDiscovery: Send + Sync {
    /// Register this participant with the cloud discovery service
    ///
    /// # Arguments
    ///
    /// - `info` -- Participant metadata (GUID, name, locators, etc.)
    fn register_participant(
        &self,
        info: &ParticipantInfo,
    ) -> impl std::future::Future<Output = Result<(), Error>> + Send;

    /// Discover other participants in the same domain
    ///
    /// # Returns
    ///
    /// List of discovered participant metadata
    fn discover_participants(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<ParticipantInfo>, Error>> + Send;

    /// Deregister this participant (cleanup on shutdown)
    fn deregister_participant(
        &self,
        guid: [u8; 16],
    ) -> impl std::future::Future<Output = Result<(), Error>> + Send;

    /// Health check (optional, for service mesh integrations)
    fn health_check(&self) -> impl std::future::Future<Output = Result<bool, Error>> + Send {
        async { Ok(true) }
    }
}

/// Helper: Convert Locator to SocketAddr
#[allow(dead_code)] // Helper for cloud discovery implementations
pub(crate) fn locator_to_socket_addr(locator: &Locator) -> Option<SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let ip = match locator.address {
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, a, b, c, d] => IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
        bytes => IpAddr::V6(Ipv6Addr::from(bytes)),
    };

    Some(SocketAddr::new(ip, locator.port as u16))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locator_to_socket_addr_ipv4() {
        let locator = Locator {
            kind: 1,
            port: 7400,
            address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 100],
        };

        let addr = locator_to_socket_addr(&locator).unwrap();
        assert_eq!(addr.to_string(), "192.168.1.100:7400");
    }

    #[test]
    fn test_participant_info_creation() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("region".to_string(), "us-east-1".to_string());

        let info = ParticipantInfo {
            guid: [0x42; 16],
            name: "test-participant".to_string(),
            domain_id: 0,
            locators: vec![],
            metadata,
        };

        assert_eq!(info.name, "test-participant");
        assert_eq!(info.metadata.get("region").unwrap(), "us-east-1");
    }
}
