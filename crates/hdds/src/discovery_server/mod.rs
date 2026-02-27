// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Discovery Server client support.
//!
//! This module provides client-side support for connecting to a Discovery Server
//! instead of using multicast-based discovery.
//!
//! # Use Cases
//!
//! - Cloud/Kubernetes environments without multicast
//! - Corporate networks with multicast disabled
//! - NAT traversal scenarios
//! - WAN deployments
//!
//! # Example
//!
//! ```ignore
//! use hdds::discovery_server::{DiscoveryServerClient, DiscoveryServerConfig};
//!
//! let config = DiscoveryServerConfig::default();
//! let guid_prefix = [1u8; 12];
//! let mut client = DiscoveryServerClient::new(config, guid_prefix)?;
//! client.connect()?;
//! client.announce_participant(0, Some("MyApp".into()), vec![], 0x3f)?;
//! ```

mod client;
mod config;
mod protocol;

pub use client::{ClientError, ClientEvent, DiscoveryServerClient};
pub use config::DiscoveryServerConfig;
pub use protocol::{ClientMessage, ServerMessage};
