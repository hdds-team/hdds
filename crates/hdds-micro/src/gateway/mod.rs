// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! LoRa <-> WiFi/UDP Gateway for HDDS Micro
//!
//! Bridges between LoRa (HDDS Micro nodes) and WiFi/UDP (HDDS Standard network).
//!
//! ## Architecture
//!
//! ```text
//!                                    +-----------------+
//!                                    |   HDDS Network  |
//!                                    |   (WiFi/UDP)    |
//!                                    +--------+--------+
//!                                             |
//!                                             v
//! +-----------------+              +---------------------+
//! |  ESP32 + LoRa   |   LoRa 868   |  Gateway            |
//! |  HDDS Micro     | ~~~~~~~~~~~~ |  (Pi Zero W)        |
//! |  (Sensor)       |              |                     |
//! +-----------------+              +---------------------+
//! ```
//!
//! ## Features (requires `std` feature)
//!
//! - Bidirectional message forwarding
//! - Topic-based filtering
//! - Rate limiting
//! - Statistics monitoring

#[cfg(feature = "std")]
mod bridge;
#[cfg(feature = "std")]
mod config;
#[cfg(feature = "std")]
mod routing;
#[cfg(feature = "std")]
mod stats;

#[cfg(feature = "std")]
pub use bridge::{Bridge, BridgeBuilder, LoRaMessage};
#[cfg(feature = "std")]
pub use config::GatewayConfig;
#[cfg(feature = "std")]
pub use routing::{RouteEntry, Router};
#[cfg(feature = "std")]
pub use stats::{GatewayStats, RateLimiter, StatsSnapshot, TopicRateLimiter};
