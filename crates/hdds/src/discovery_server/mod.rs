// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Discovery Server client support.
//!
//! This module provides the protocol and blocking client for the standalone
//! `hdds-discovery-server` workspace binary. A participant configured through
//! `ParticipantBuilder::with_discovery_server` owns the client lifecycle and
//! uses server-provided locators as unicast SPDP destinations. The raw client
//! remains public for diagnostics and protocol tooling.
//!
//! # Use Cases
//!
//! - Cloud/Kubernetes environments without multicast
//! - Corporate networks with multicast disabled
//! - Routed WAN deployments with mutually reachable UDP locators
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

mod base64;
mod client;
mod config;
mod protocol;

pub use client::{ClientError, ClientEvent, DiscoveryServerClient, SessionWaker};
pub use config::DiscoveryServerConfig;
pub use protocol::{ClientMessage, ServerMessage};
