// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # DDS Discovery Mechanisms
//!
//! Discovery allows DDS participants to find each other and exchange endpoint
//! information (topics, QoS, types) without manual configuration.
//!
//! ## Discovery Backends
//!
//! HDDS supports multiple discovery mechanisms for different environments:
//!
//! | Backend | Use Case | Module |
//! |---------|----------|--------|
//! | **Multicast SPDP/SEDP** | LAN, same subnet | [`crate::core::discovery`] |
//! | **Discovery Server** | Non-multicast networks | `hdds-discovery-server` crate |
//! | **Cloud Discovery** | AWS, Azure, Consul | `cloud` |
//! | **Static Peers** | Embedded, known endpoints | [`Participant::add_static_peer`](crate::Participant) |
//!
//! ## How Discovery Works
//!
//! ```text
//! +-------------------------------------------------------------+
//! |                    SPDP (Participant Discovery)             |
//! |  Participant A ---- multicast ----> Participant B           |
//! |       |                                    |                |
//! |       v                                    v                |
//! |  "I exist, here's my GUID"          "I exist too!"          |
//! +-------------------------------------------------------------+
//!                          |
//!                          v
//! +-------------------------------------------------------------+
//! |                    SEDP (Endpoint Discovery)                |
//! |  Writer(TopicA) <----- unicast -----> Reader(TopicA)        |
//! |       |                                    |                |
//! |       v                                    v                |
//! |  "I publish TopicA, QoS=reliable"   "I subscribe TopicA"    |
//! |                                                             |
//! |              --> MATCHED! Data can flow <--                 |
//! +-------------------------------------------------------------+
//! ```
//!
//! ## Cloud Discovery
//!
//! When UDP multicast is unavailable (AWS VPC, Azure VNet, Kubernetes), use
//! cloud-native service discovery:
//!
//! ```rust,ignore
//! use hdds::discovery::{CloudDiscovery, ConsulDiscovery, ParticipantInfo};
//!
//! // Register with Consul
//! let discovery = ConsulDiscovery::new("http://consul:8500")?;
//! discovery.register_participant(&participant_info).await?;
//!
//! // Discover peers
//! let peers = discovery.discover_participants().await?;
//! for peer in peers {
//!     println!("Found: {} at {:?}", peer.name, peer.locators);
//! }
//! ```
//!
//! ## See Also
//!
//! - [`crate::core::discovery`] - SPDP/SEDP implementation
//! - `cloud::CloudDiscovery` - Cloud discovery trait
//! - [RTPS Spec Sec.8.5](https://www.omg.org/spec/DDSI-RTPS/2.5/) - Discovery Protocol

#[cfg(feature = "cloud-discovery")]
pub mod cloud;

/// Kubernetes DNS-based discovery (zero dependencies).
///
/// Uses Kubernetes Headless Services for peer discovery without any k8s client libraries.
#[cfg(feature = "k8s")]
pub mod k8s;

#[cfg(feature = "cloud-discovery")]
pub use cloud::{AwsCloudMap, AzureDiscovery, CloudDiscovery, ConsulDiscovery, ParticipantInfo};

#[cfg(feature = "k8s")]
pub use k8s::{
    get_namespace, get_pod_ip, get_pod_name, resolve_k8s_service, K8sDiscovery, K8sDiscoveryConfig,
    K8sDiscoveryHandle,
};
