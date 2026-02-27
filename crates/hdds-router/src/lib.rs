// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS DDS Routing Service
//!
//! Provides domain bridging, topic remapping, and QoS transformation
//! for DDS systems.
//!
//! # Features
//!
//! - **Domain Bridging**: Route messages between DDS domains
//! - **Topic Remapping**: Rename topics during routing
//! - **QoS Transformation**: Modify QoS policies during routing
//! - **Content Filtering**: Filter messages based on content
//!
//! # Quick Start
//!
//! ```bash
//! # Bridge domain 0 to domain 1
//! hdds-router --from-domain 0 --to-domain 1
//!
//! # With topic remapping
//! hdds-router --from-domain 0 --to-domain 1 --remap "Sensor/*:Vehicle/*"
//!
//! # Using config file
//! hdds-router --config router.toml
//! ```
//!
//! # Configuration File
//!
//! ```toml
//! [router]
//! name = "my-router"
//!
//! [[routes]]
//! from_domain = 0
//! to_domain = 1
//! topics = ["Temperature", "Pressure"]
//!
//! [[routes.remaps]]
//! from = "Sensor/Temperature"
//! to = "Vehicle/Engine/Temperature"
//! ```

pub mod config;
pub mod route;
pub mod router;
pub mod transform;

pub use config::{RouteConfig, RouterConfig, TopicRemap};
pub use route::{Route, RouteStats, RouteStatsSnapshot};
pub use router::{Router, RouterError, RouterHandle};
pub use transform::{QosTransform, TopicTransform};
